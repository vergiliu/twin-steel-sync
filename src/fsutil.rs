use crate::model::Hash;
use filetime::FileTime;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BUF: usize = 1 << 20;

thread_local! {
    /// One buffer per thread, reused by every hash and every copy.
    ///
    /// Allocating a megabyte per file is what made hashing a tree slow: the
    /// pages were faulted in and zeroed again for every file, and the bytes
    /// were thrown away right after.
    static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Run `f` with the shared buffer, big enough to hold a whole chunk.
///
/// The buffer belongs to the thread and is handed out for the duration of the
/// call only: nothing inside `f` may ask for it again.
pub fn with_scratch<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
    SCRATCH.with(|cell| {
        let mut buffer = cell.borrow_mut();
        if buffer.len() < BUF {
            buffer.resize(BUF, 0);
        }
        f(&mut buffer)
    })
}

/// How hard a run works to make the bytes durable.
///
/// The default is the strongest barrier the platform offers, because a file
/// that is renamed into place has to survive a power cut. The weaker modes
/// exist because that barrier is expensive: on macOS an `F_FULLFSYNC` costs
/// tens of milliseconds, which is more than the copy of a small file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fsync {
    /// `F_FULLFSYNC` on macOS, `fsync` elsewhere: the bytes are on the disk
    /// when the call returns.
    Full,
    /// `fsync`: the bytes reached the drive, but the drive's own cache may
    /// still be holding them.
    Data,
    /// No barrier at all: the bytes are in the page cache.
    Off,
}

impl Fsync {
    /// The name the command line uses.
    pub fn name(self) -> &'static str {
        match self {
            Fsync::Full => "full",
            Fsync::Data => "data",
            Fsync::Off => "off",
        }
    }

    /// The mode a `--fsync` argument names.
    pub fn parse(text: &str) -> Option<Fsync> {
        match text.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Fsync::Full),
            "data" => Some(Fsync::Data),
            "off" => Some(Fsync::Off),
            _ => None,
        }
    }

    /// The mode the wire protocol carries.
    pub fn code(self) -> u8 {
        match self {
            Fsync::Full => 0,
            Fsync::Data => 1,
            Fsync::Off => 2,
        }
    }

    /// The mode a wire protocol code names.
    pub fn from_code(code: u8) -> Fsync {
        match code {
            1 => Fsync::Data,
            2 => Fsync::Off,
            _ => Fsync::Full,
        }
    }
}

/// The directories a run wrote into, so that each can be flushed once when
/// the run ends instead of once per file.
///
/// A directory fsync is what makes a rename durable. Doing it per file costs a
/// barrier per file; doing it once per directory, at the end of the run, costs
/// one barrier per directory and leaves the same guarantee once the run is
/// over.
#[derive(Debug, Default)]
pub struct DirFlush {
    dirs: std::collections::BTreeSet<PathBuf>,
}

impl DirFlush {
    /// Remember that a file was written into `dir`.
    pub fn note(&mut self, dir: &Path) {
        self.dirs.insert(dir.to_path_buf());
    }

    /// Flush every directory that was written to, once each.
    pub fn flush(&mut self, mode: Fsync) {
        if mode == Fsync::Off {
            self.dirs.clear();
            return;
        }
        for dir in std::mem::take(&mut self.dirs) {
            // A directory that cannot be fsynced is no reason to fail the run:
            // the file itself is already durable.
            let _ = sync_dir(&dir);
        }
    }
}

/// The name of the temporary file that holds a transfer in flight, derived from
/// the destination it will be renamed to.
///
/// The name has to be stable across runs: an interrupted transfer leaves this
/// file behind, and the next run must find it to continue where the last one
/// stopped. A digest of the whole destination path keeps two trees that happen
/// to share a file name apart, and the escaped file name keeps it readable.
pub fn temp_file_name(dst: &Path) -> String {
    let mut escaped = String::new();
    for byte in dst.file_name().unwrap_or_default().as_bytes() {
        let c = *byte;
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' {
            escaped.push(c as char);
        } else {
            escaped.push('_');
            escaped.push_str(&format!("{c:02x}"));
        }
        if escaped.len() >= 96 {
            break;
        }
    }
    let digest = blake3::hash(dst.as_os_str().as_bytes());
    format!(".twin-tmp-{escaped}-{}", &digest.to_hex().to_string()[..8])
}

/// A hash that did not match. The engine retries such a transfer once before
/// it gives up on the file.
#[derive(Debug)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for VerifyError {}

/// An error that means "the bytes did not verify", as opposed to "the disk
/// said no". Only the former is worth retrying.
pub fn verification_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, VerifyError(message.into()))
}

/// Whether an error is a verification failure.
pub fn is_verification_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<VerifyError>())
        .is_some()
}

/// Do a transfer, and do it once more if the content did not verify.
///
/// A hash that does not match is worth another try: the file may have been
/// read while it was being written. Anything else is the disk saying no, and
/// saying no twice is the answer.
pub fn retry_once<T>(what: &str, mut attempt: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    match attempt() {
        Ok(value) => Ok(value),
        Err(error) if is_verification_error(&error) => {
            crate::warn!("{what}: the content did not verify; trying once more");
            attempt()
        }
        Err(error) => Err(error),
    }
}

pub fn hash_file(path: &Path) -> io::Result<Hash> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    with_scratch(|buf| -> io::Result<()> {
        loop {
            let n = file.read(buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(())
    })?;
    Ok(*hasher.finalize().as_bytes())
}

/// Copy `src` to `dst` so that `dst` is never observable in a partial state:
/// write a temp file in the destination directory, fsync it, verify its hash
/// against the bytes actually read from the source, then rename.
///
/// The directory the file was renamed into is not flushed here: the caller
/// collects the directories it wrote into and flushes each of them once, when
/// the run ends.
pub fn copy_atomic(src: &Path, dst: &Path, tmp: &Path, mode: Fsync) -> io::Result<Hash> {
    let parent = dst
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    fs::create_dir_all(parent).ctx(|| format!("creating {}", parent.display()))?;
    // A temporary file left by an earlier run must never stand in the way,
    // not even one that cannot be written to.
    let _ = fs::remove_file(tmp);

    let outcome = copy_via_temp(src, tmp, dst, mode);
    if outcome.is_err() {
        let _ = fs::remove_file(tmp);
    }
    outcome
}

/// Copy `src` to `dst`, continuing from `tmp` when that file already holds the
/// beginning of the source.
///
/// The whole file is verified once it is complete, prefix included: a prefix
/// that does not belong to this source fails the check and the temporary file
/// is thrown away, so the next attempt starts from zero.
pub fn copy_resumable(src: &Path, dst: &Path, tmp: &Path, mode: Fsync) -> io::Result<Hash> {
    let parent = dst
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    fs::create_dir_all(parent).ctx(|| format!("creating {}", parent.display()))?;

    let size = fs::metadata(src)
        .ctx(|| format!("stat {}", src.display()))?
        .len();
    let expected = hash_file(src).ctx(|| format!("hashing {}", src.display()))?;

    // A partial file longer than the source belongs to an older, longer
    // version: it cannot be continued, so it goes.
    let mut offset = 0u64;
    match fs::metadata(tmp) {
        Ok(meta) if meta.len() <= size => offset = meta.len(),
        Ok(_) => {
            let _ = fs::remove_file(tmp);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    if offset < size {
        let mut reader = File::open(src).ctx(|| format!("opening {}", src.display()))?;
        reader
            .seek(SeekFrom::Start(offset))
            .ctx(|| format!("seeking in {}", src.display()))?;
        let mut writer = OpenOptions::new()
            .create(true)
            .append(true)
            .open(tmp)
            .ctx(|| format!("opening {}", tmp.display()))?;
        with_scratch(|buf| -> io::Result<()> {
            loop {
                let n = reader.read(buf)?;
                if n == 0 {
                    break;
                }
                writer.write_all(&buf[..n])?;
            }
            Ok(())
        })?;
        writer.flush()?;
        fsync_file(&writer, mode)?;
    }

    // Verify what landed on disk rather than trusting the write path.
    let got = hash_file(tmp).ctx(|| format!("hashing {}", tmp.display()))?;
    if got != expected {
        let _ = fs::remove_file(tmp);
        return Err(verification_error(
            "verification failed: bytes on disk differ from bytes read",
        ));
    }

    let meta = fs::metadata(src).ctx(|| format!("stat {}", src.display()))?;
    apply_mtime(tmp, mtime_ns(&meta), "copying");
    fs::rename(tmp, dst)
        .ctx(|| format!("moving {} into place at {}", tmp.display(), dst.display()))?;
    Ok(expected)
}

fn copy_via_temp(src: &Path, tmp: &Path, dst: &Path, mode: Fsync) -> io::Result<Hash> {
    let mut reader = File::open(src).ctx(|| format!("opening {}", src.display()))?;
    let mut writer = File::create(tmp).ctx(|| format!("creating {}", tmp.display()))?;
    let mut hasher = blake3::Hasher::new();
    with_scratch(|buf| -> io::Result<()> {
        loop {
            let n = reader.read(buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            writer.write_all(&buf[..n])?;
        }
        Ok(())
    })?;
    let source_hash = *hasher.finalize().as_bytes();
    writer.flush()?;
    fsync_file(&writer, mode)?;
    drop(writer);

    // Verify what landed on disk rather than trusting the write path.
    if hash_file(tmp)? != source_hash {
        return Err(verification_error(
            "verification failed: bytes on disk differ from bytes read",
        ));
    }

    let meta = fs::metadata(src).ctx(|| format!("stat {}", src.display()))?;
    apply_mtime(tmp, mtime_ns(&meta), "copying");
    fs::rename(tmp, dst)
        .ctx(|| format!("moving {} into place at {}", tmp.display(), dst.display()))?;
    Ok(source_hash)
}

/// fsync on macOS can be a lie on power loss; F_FULLFSYNC is the real barrier.
pub fn fsync_hard(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
        if rc == -1 {
            return file.sync_all();
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Make a file's bytes durable, as far as the mode asks for.
pub fn fsync_file(file: &File, mode: Fsync) -> io::Result<()> {
    match mode {
        Fsync::Off => Ok(()),
        Fsync::Data => file.sync_all(),
        Fsync::Full => fsync_hard(file),
    }
}

/// Remove `dir` and its ancestors up to (but never including) `root` while empty.
pub fn prune_empty_dirs(root: &Path, dir: &Path) {
    let mut current = dir.to_path_buf();
    while current.starts_with(root) && current != root {
        match fs::read_dir(&current) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return;
                }
            }
            Err(_) => return,
        }
        if fs::remove_dir(&current).is_err() {
            return;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => return,
        }
    }
}

/// Nanoseconds since the epoch as the pair of values `utimensat` accepts.
///
/// `tv_nsec` must be 0..1e9 or the kernel answers EINVAL, so negative timestamps
/// (pre-1970 dates, or an unset filesystem timestamp) are floored rather than
/// truncated: `-1` second must not become a nanosecond field of 3_794_967_295.
pub fn file_time(ns: i64) -> FileTime {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000) as u32;
    FileTime::from_unix_time(secs, nanos)
}

/// Setting an mtime is a nicety: content hashes decide what syncs, mtime only
/// powers the fast path. Filesystems that refuse outright — exFAT, NTFS-3g,
/// several FUSE, SMB and virtiofs mounts answer EINVAL — must not fail a transfer.
pub fn apply_mtime(path: &Path, ns: i64, what: &str) -> bool {
    match filetime::set_file_mtime(path, file_time(ns)) {
        Ok(()) => true,
        Err(error) => {
            crate::warn!(
                "{what}: cannot set the modification time of {} ({error}); the content is correct, \
                 only later runs lose the size+mtime fast path",
                path.display()
            );
            false
        }
    }
}

/// Attach the operation and path to an io error. A bare "Invalid argument (os
/// error 22)" says nothing about where to look; callers should never see that.
pub trait ErrCtx<T> {
    /// The description is only built when something actually failed.
    fn ctx(self, what: impl FnOnce() -> String) -> io::Result<T>;
}

impl<T> ErrCtx<T> for io::Result<T> {
    fn ctx(self, what: impl FnOnce() -> String) -> io::Result<T> {
        self.map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", what())))
    }
}

/// What a directory can actually do, learned by trying rather than assuming.
#[derive(Debug, Clone)]
pub struct FsProbe {
    pub writable: bool,
    pub rename: bool,
    pub mtime: bool,
    pub mtime_subsecond: bool,
    pub file_sync: bool,
    pub dir_sync: bool,
    pub notes: Vec<String>,
}

impl FsProbe {
    pub fn all_ok(&self) -> bool {
        self.writable && self.rename && self.mtime && self.file_sync
    }
}

/// Try the operations a sync depends on, in the directory itself. This is what
/// turns "Invalid argument (os error 22)" into a named, located cause.
pub fn probe_dir(dir: &Path) -> FsProbe {
    let mut probe = FsProbe {
        writable: false,
        rename: false,
        mtime: false,
        mtime_subsecond: false,
        file_sync: false,
        dir_sync: false,
        notes: Vec::new(),
    };
    let stamp = format!(".twin-probe-{}", std::process::id());
    let first = dir.join(format!("{stamp}-a"));
    let second = dir.join(format!("{stamp}-b"));

    match File::create(&first) {
        Ok(mut file) => {
            probe.writable = true;
            if let Err(error) = file.write_all(b"twin") {
                probe.notes.push(format!("writing failed: {error}"));
            }
            if file.sync_all().is_ok() {
                probe.file_sync = true;
            } else {
                probe.notes.push("file fsync unsupported".to_string());
            }
        }
        Err(error) => {
            probe
                .notes
                .push(format!("cannot create files here: {error}"));
            return probe;
        }
    }

    // Nanosecond precision: a filesystem that stores whole seconds will not
    // round-trip the value, and one that cannot store times at all answers EINVAL.
    let want = 1_700_000_000_123_456_789i64;
    match filetime::set_file_mtime(&first, file_time(want)) {
        Ok(()) => {
            probe.mtime = true;
            match fs::metadata(&first) {
                Ok(meta) => {
                    let got = mtime_ns(&meta);
                    probe.mtime_subsecond = got == want;
                    if got != want {
                        probe.notes.push(format!(
                            "the filesystem stores {got} instead of {want} (second precision only)"
                        ));
                    }
                }
                Err(error) => probe
                    .notes
                    .push(format!("cannot stat the probe file: {error}")),
            }
        }
        Err(error) => probe
            .notes
            .push(format!("cannot set modification times here: {error}")),
    }

    match fs::rename(&first, &second) {
        Ok(()) => probe.rename = true,
        Err(error) => probe
            .notes
            .push(format!("atomic replace (rename) failed: {error}")),
    }
    if probe.file_sync {
        if sync_dir(dir).is_ok() {
            probe.dir_sync = true;
        } else {
            probe.notes.push("directory fsync unsupported".to_string());
        }
    }

    let _ = fs::remove_file(&first);
    let _ = fs::remove_file(&second);
    probe
}

pub fn mtime_ns(meta: &fs::Metadata) -> i64 {
    meta.mtime() * 1_000_000_000 + meta.mtime_nsec()
}

/// `YYYYMMDD-HHMMSS` in UTC, without pulling in a date library.
pub fn timestamp_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_barrier_modes_say_what_they_are() {
        assert_eq!(Fsync::parse("full"), Some(Fsync::Full));
        assert_eq!(Fsync::parse("DATA"), Some(Fsync::Data));
        assert_eq!(Fsync::parse(" off "), Some(Fsync::Off));
        assert_eq!(Fsync::parse("sometimes"), None);
        for mode in [Fsync::Full, Fsync::Data, Fsync::Off] {
            assert_eq!(Fsync::from_code(mode.code()), mode);
            assert_eq!(Fsync::parse(mode.name()), Some(mode));
        }
    }

    #[test]
    fn a_directory_is_flushed_once_however_many_files_went_into_it() {
        let mut flush = DirFlush::default();
        flush.note(Path::new("/tmp/one"));
        flush.note(Path::new("/tmp/one"));
        flush.note(Path::new("/tmp/two"));
        assert_eq!(flush.dirs.len(), 2, "the same directory is one entry");
        flush.flush(Fsync::Off);
        assert!(
            flush.dirs.is_empty(),
            "the set is emptied whether the barrier ran or not"
        );
    }

    #[test]
    fn timestamp_shape_is_stable() {
        let ts = timestamp_utc();
        assert_eq!(ts.len(), 15, "unexpected timestamp {ts}");
        assert_eq!(ts.as_bytes()[8], b'-');
    }

    #[test]
    fn copy_preserves_bytes_and_mtime_and_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dst = dir.path().join("nested/dst.txt");
        fs::write(&src, b"hello twin").unwrap();

        let tmp = dst.parent().unwrap().join(temp_file_name(&dst));
        let hash = copy_atomic(&src, &dst, &tmp, Fsync::Full).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"hello twin");
        assert_eq!(hash, *blake3::hash(b"hello twin").as_bytes());
        let src_m = fs::metadata(&src).unwrap();
        let dst_m = fs::metadata(&dst).unwrap();
        assert_eq!(mtime_ns(&src_m), mtime_ns(&dst_m), "mtime must travel");

        let leftovers: Vec<_> = fs::read_dir(dir.path().join("nested"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with(".twin-tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    #[test]
    fn a_verification_failure_is_tried_once_more_and_nothing_else_is() {
        let mut tries = 0;
        let outcome: io::Result<()> = retry_once("test", || {
            tries += 1;
            Err(verification_error("the bytes do not match"))
        });
        assert!(outcome.is_err());
        assert_eq!(tries, 2, "one more try, and no more");

        let mut tries = 0;
        let outcome: io::Result<()> = retry_once("test", || {
            tries += 1;
            Err(io::Error::other("the disk said no"))
        });
        assert!(outcome.is_err());
        assert_eq!(tries, 1, "a plain failure is not worth a second try");

        let mut tries = 0;
        let outcome: io::Result<()> = retry_once("test", || {
            tries += 1;
            if tries == 1 {
                Err(verification_error("the bytes do not match"))
            } else {
                Ok(())
            }
        });
        assert!(outcome.is_ok(), "the second try succeeded");
        assert_eq!(tries, 2);
    }

    #[test]
    fn a_temp_name_is_stable_and_never_collides_with_a_plain_name() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("sub/doc.txt");
        let first = temp_file_name(&dst);
        let second = temp_file_name(&dst);
        assert_eq!(first, second, "the name must survive a run");
        assert!(first.starts_with(".twin-tmp-"), "{first}");
        assert_ne!(
            first,
            temp_file_name(&dir.path().join("sub/other.txt")),
            "two destinations must not share a temp file"
        );
        // Awkward bytes stay inside one file name.
        let odd = temp_file_name(&dir.path().join("we ird\"name.txt"));
        assert!(!odd.contains('/'), "{odd}");
        assert!(odd.len() < 200, "{odd}");
    }

    #[test]
    fn a_resumed_copy_completes_the_file_and_a_bad_prefix_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dst = dir.path().join("out/dst.bin");
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        fs::write(&src, &payload).unwrap();
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        let tmp = dst.parent().unwrap().join(temp_file_name(&dst));

        // An interrupted run left the first half behind.
        fs::write(&tmp, &payload[..1000]).unwrap();
        let hash = copy_resumable(&src, &dst, &tmp, Fsync::Full).unwrap();
        assert_eq!(hash, *blake3::hash(&payload).as_bytes());
        assert_eq!(fs::read(&dst).unwrap(), payload);
        assert!(!tmp.exists(), "the temp file must be gone");

        // A prefix that belongs to something else must not be trusted.
        let dst2 = dir.path().join("out/dst2.bin");
        let tmp2 = dst2.parent().unwrap().join(temp_file_name(&dst2));
        fs::write(&tmp2, b"not the beginning of this file").unwrap();
        let error = copy_resumable(&src, &dst2, &tmp2, Fsync::Full).unwrap_err();
        assert!(is_verification_error(&error), "{error}");
        assert!(!tmp2.exists(), "a bad prefix must be thrown away");
        assert!(!dst2.exists(), "nothing may be published");
    }

    #[test]
    fn file_times_are_always_legal_for_utimensat() {
        // whatever the input, the nanosecond field stays in range
        for ns in [
            0i64,
            1,
            999_999_999,
            1_000_000_000,
            -1,
            -1_500_000_000,
            -999_999_999_999,
            i64::MAX / 2,
        ] {
            let time = file_time(ns);
            assert!(
                (0..1_000_000_000).contains(&time.nanoseconds()),
                "nanoseconds out of range for {ns}: {}",
                time.nanoseconds()
            );
        }
        assert_eq!(
            file_time(1_700_000_000_123_456_789).seconds(),
            1_700_000_000
        );
        assert_eq!(
            file_time(1_700_000_000_123_456_789).nanoseconds(),
            123_456_789
        );
        // flooring, not truncation: -1ns is the last nanosecond of 1969
        assert_eq!(file_time(-1).seconds(), -1);
        assert_eq!(file_time(-1).nanoseconds(), 999_999_999);
    }

    #[test]
    fn a_healthy_directory_passes_every_probe() {
        let dir = tempfile::tempdir().unwrap();
        let probe = probe_dir(dir.path());
        assert!(probe.writable, "{:?}", probe.notes);
        assert!(probe.rename, "{:?}", probe.notes);
        assert!(probe.mtime, "{:?}", probe.notes);
        assert!(probe.file_sync, "{:?}", probe.notes);
        assert!(probe.all_ok(), "{:?}", probe.notes);
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the probe must clean up after itself"
        );
    }

    #[test]
    fn a_directory_that_cannot_be_written_is_reported_not_guessed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();

        let probe = probe_dir(&locked);
        let outcome = if unsafe { libc::geteuid() } == 0 {
            true // root ignores the mode; nothing to assert
        } else {
            !probe.writable
        };
        assert!(outcome);
        if !probe.writable {
            assert!(
                probe
                    .notes
                    .iter()
                    .any(|n| n.contains("cannot create files here")),
                "the reason must name the operation: {:?}",
                probe.notes
            );
        }
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn prune_stops_at_root_and_keeps_non_empty_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let deep = root.join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(root.join("a/keep.txt"), b"x").unwrap();

        prune_empty_dirs(&root, &deep);
        assert!(!deep.exists(), "empty chain should be removed");
        assert!(root.join("a").exists(), "non-empty dir must survive");
        assert!(root.exists(), "root must never be removed");
    }
}
