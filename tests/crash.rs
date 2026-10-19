//! F-073: SIGKILL in the middle of a transfer.
//!
//! The invariant under test is the one F-062 states: kill the process at any
//! point and nothing partial is ever visible under a real name, the archive
//! stays consistent, and the next run converges.
//!
//! The transfer is interrupted for real: a 256 MiB file is streamed to a real
//! `twin serve` on loopback, the temp file the server writes is watched for,
//! and the client is killed with SIGKILL (`Child::kill`) the moment the
//! transfer is demonstrably in flight. If the file were small the transfer
//! would finish before the kill could land, and the test would be proving
//! nothing; that case fails loudly instead of passing quietly.

mod common;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use twin::archive::Archive;

/// Big enough that the transfer is still running when the kill lands.
const BIG: u64 = 256 * 1024 * 1024;
/// The file that travels.
const NAME: &str = "big.bin";

/// The temp file the far side is writing right now, if there is one.
fn temp_file_in(dir: &Path) -> Option<String> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(".twin-tmp-") {
            return Some(name);
        }
        // The temp file lives next to the file it will become, so the search
        // has to look in the subdirectories too.
        if path.is_dir() {
            if let Some(found) = temp_file_in(&path) {
                return Some(found);
            }
        }
    }
    None
}

/// Every regular file under `root`, relative to it, ignoring temp files.
fn real_files_under(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).unwrap();
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(".twin-tmp-") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .to_string();
            found.insert(relative);
        }
    }
    found
}

/// True when both files hold exactly the same bytes.
fn same_bytes(left: &Path, right: &Path) -> bool {
    let mut left = File::open(left).unwrap();
    let mut right = File::open(right).unwrap();
    let mut left_buffer = [0u8; 64 * 1024];
    let mut right_buffer = [0u8; 64 * 1024];
    loop {
        let left_read = left.read(&mut left_buffer).unwrap();
        let right_read = right.read(&mut right_buffer).unwrap();
        if left_read != right_read {
            return false;
        }
        if left_buffer[..left_read] != right_buffer[..right_read] {
            return false;
        }
        if left_read == 0 {
            return true;
        }
    }
}

/// True when the file is exactly `len` bytes of zero.
fn all_zero(path: &Path, len: u64) -> bool {
    let mut file = File::open(path).unwrap();
    let mut buffer = [0u8; 64 * 1024];
    let mut seen: u64 = 0;
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return false;
        }
        seen += read as u64;
    }
    seen == len
}

/// The one archive file in the archive directory.
fn archive_file(dir: &Path) -> PathBuf {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!(
            "cannot read the archive directory {}: {error}",
            dir.display()
        )
    });
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("db"))
        .collect();
    found.sort();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one archive in {}, found {found:?}",
        dir.display()
    );
    found.remove(0)
}

/// Everything the killed child printed, for the failure messages.
fn drain(child: &mut Child) -> String {
    let mut text = String::new();
    if let Some(mut out) = child.stdout.take() {
        let mut chunk = String::new();
        let _ = out.read_to_string(&mut chunk);
        text.push_str(&chunk);
    }
    if let Some(mut err) = child.stderr.take() {
        let mut chunk = String::new();
        let _ = err.read_to_string(&mut chunk);
        text.push_str(&chunk);
    }
    text
}

#[test]
fn a_killed_transfer_leaves_no_partial_file_and_the_next_run_converges() {
    let (fixture, server) = common::Fixture::new();

    // A big, sparse file: the test costs no memory and no disk until the
    // transfer actually writes it.
    let source = fixture.local.join(NAME);
    let file = File::create(&source).unwrap();
    file.set_len(BIG).unwrap();
    drop(file);
    assert_eq!(
        fs::metadata(&source).unwrap().len(),
        BIG,
        "the source file must be {BIG} bytes"
    );

    let mut child = fixture
        .push_command(&server)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for the transfer to be demonstrably in flight: the far side writes
    // to a temp file in the destination directory until the content is whole.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut in_flight = false;
    while Instant::now() < deadline {
        if temp_file_in(&fixture.remote).is_some() {
            in_flight = true;
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let output = drain(&mut child);
            panic!(
                "the transfer ended ({status}) before it could be interrupted: the \
                 file is too small to interrupt a transfer in flight, or the run \
                 failed outright\n{output}"
            );
        }
        thread::sleep(Duration::from_millis(2));
    }
    assert!(
        in_flight,
        "no transfer was ever in flight in {} within 30s: the file is too small \
         to interrupt a transfer in flight, or the run failed before it started",
        fixture.remote.display()
    );

    if let Some(status) = child.try_wait().unwrap() {
        let output = drain(&mut child);
        panic!(
            "the transfer ended ({status}) before the kill landed: the file is too \
             small to interrupt a transfer in flight\n{output}"
        );
    }

    child.kill().expect("the client must still be running");
    let status = child.wait().unwrap();
    assert!(
        status.code().is_none(),
        "the client must die from a signal, not exit on its own: {status}"
    );

    // Give the server a moment to notice that the connection is gone.
    thread::sleep(Duration::from_millis(300));

    // Nothing partial is ever visible under a real name.
    let delivered = fixture.remote.join(NAME);
    assert!(
        !delivered.exists(),
        "the interrupted file must not exist under its real name in {}",
        fixture.remote.display()
    );
    assert_eq!(
        fs::metadata(&source).unwrap().len(),
        BIG,
        "the source file must not be truncated by the interrupted transfer"
    );
    assert!(
        all_zero(&source, BIG),
        "the source file must be untouched by the interrupted transfer"
    );
    assert_eq!(
        real_files_under(&fixture.local),
        BTreeSet::from([NAME.to_string()]),
        "the client root must hold exactly the file it started with"
    );

    // The archive never recorded the interrupted file as synced.
    {
        let archive = Archive::open(&archive_file(&fixture.archive_dir)).unwrap();
        assert_eq!(
            archive.integrity().unwrap(),
            "ok",
            "the archive must survive the kill unharmed"
        );
        assert!(
            archive.get(Path::new(NAME)).unwrap().is_none(),
            "the archive must not record the interrupted file as synced"
        );
        let mut recorded = Vec::new();
        archive
            .for_each(|path, _row| {
                recorded.push(path.to_string_lossy().to_string());
                Ok(())
            })
            .unwrap();
        assert!(
            recorded.is_empty(),
            "the archive must hold nothing after an interrupted transfer: {recorded:?}"
        );
    }

    // The next run converges: the file travels again and lands whole.
    let mut again = fixture.push_command(&server);
    let (code, output) = common::run(&mut again);
    assert_eq!(code, 0, "the second push must succeed: {output}");
    let counters = common::summary(&output);
    assert_eq!(
        counters.get("failures"),
        Some(&0),
        "the second push must not fail on any file: {output}"
    );
    assert_eq!(
        counters.get("created").copied().unwrap_or(0)
            + counters.get("updated").copied().unwrap_or(0),
        1,
        "the second push must transfer the file exactly once: {output}"
    );

    assert!(
        delivered.exists(),
        "the second push must deliver the file: {output}"
    );
    assert_eq!(
        fs::metadata(&delivered).unwrap().len(),
        BIG,
        "the delivered file must have the same length as the source"
    );
    assert!(
        same_bytes(&source, &delivered),
        "the delivered file must hold the same bytes as the source"
    );

    // A leftover temp file is never synced as if it were content.
    assert_eq!(
        real_files_under(&fixture.remote),
        BTreeSet::from([NAME.to_string()]),
        "the served tree must hold exactly the real file"
    );
    {
        let archive = Archive::open(&archive_file(&fixture.archive_dir)).unwrap();
        assert_eq!(
            archive.integrity().unwrap(),
            "ok",
            "the archive must still be sane after the second push"
        );
        let mut recorded: Vec<String> = Vec::new();
        archive
            .for_each(|path, _row| {
                recorded.push(path.to_string_lossy().to_string());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            recorded,
            vec![NAME.to_string()],
            "the archive must hold the real file and nothing else"
        );
    }
}
