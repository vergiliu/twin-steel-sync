use crate::model::Hash;
use filetime::FileTime;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const BUF: usize = 1 << 20;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn hash_file(path: &Path) -> io::Result<Hash> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(BUF, file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; BUF];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Copy `src` to `dst` so that `dst` is never observable in a partial state:
/// write a temp file in the destination directory, fsync it, verify its hash
/// against the bytes actually read from the source, then rename.
pub fn copy_atomic(src: &Path, dst: &Path) -> io::Result<Hash> {
    let parent = dst
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    fs::create_dir_all(parent).ctx(|| format!("creating {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".twin-tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let outcome = copy_via_temp(src, &tmp, dst, parent);
    if outcome.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    outcome
}

fn copy_via_temp(src: &Path, tmp: &Path, dst: &Path, parent: &Path) -> io::Result<Hash> {
    let mut reader = BufReader::with_capacity(
        BUF,
        File::open(src).ctx(|| format!("opening {}", src.display()))?,
    );
    let mut writer = BufWriter::with_capacity(
        BUF,
        File::create(tmp).ctx(|| format!("creating {}", tmp.display()))?,
    );
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; BUF];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n])?;
    }
    let source_hash = *hasher.finalize().as_bytes();
    writer.flush()?;
    fsync_hard(writer.get_ref())?;
    drop(writer);

    // Verify what landed on disk rather than trusting the write path.
    if hash_file(tmp)? != source_hash {
        return Err(io::Error::other(
            "verification failed: bytes on disk differ from bytes read",
        ));
    }

    let meta = fs::metadata(src).ctx(|| format!("stat {}", src.display()))?;
    apply_mtime(tmp, mtime_ns(&meta), "copying");
    fs::rename(tmp, dst)
        .ctx(|| format!("moving {} into place at {}", tmp.display(), dst.display()))?;
    let _ = sync_dir(parent);
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

        let hash = copy_atomic(&src, &dst).unwrap();
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
