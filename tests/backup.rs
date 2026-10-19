//! `--backup DIR`: the version that is about to be replaced or removed is kept
//! on the client, whichever side the file is on.
//!
//! Real directories, the real binary: what is checked here is what a user would
//! find on disk after a run.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn twin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

struct Sandbox {
    _root: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    archive: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let remote = root.path().join("remote");
        let archive = root.path().join("archive");
        for dir in [&local, &remote, &archive] {
            fs::create_dir_all(dir).unwrap();
        }
        Sandbox {
            _root: root,
            local,
            remote,
            archive,
        }
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let output = Command::new(twin())
            .args(args)
            .arg("--archive-dir")
            .arg(&self.archive)
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.code().unwrap_or(-1), text)
    }

    /// A first run, so both sides know each other.
    fn settle(&self) {
        let (code, output) = self.run(&[
            "sync",
            self.local.to_str().unwrap(),
            self.remote.to_str().unwrap(),
            "--auto",
            "--quiet",
        ]);
        assert_eq!(code, 0, "{output}");
    }

    fn sync_with_backup(&self, backup: &Path) -> (i32, String) {
        self.run(&[
            "sync",
            self.local.to_str().unwrap(),
            self.remote.to_str().unwrap(),
            "--auto",
            "--quiet",
            "--backup",
            backup.to_str().unwrap(),
        ])
    }

    fn write(&self, side: &Path, rel: &str, contents: &str) {
        let path = side.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

/// Every file below `dir`, however deep.
fn files_below(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn a_file_overwritten_on_the_remote_side_is_backed_up() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    sandbox.settle();

    // The local file changes, so the remote one is about to be replaced.
    sandbox.write(&sandbox.local, "doc.txt", "new local");
    let backup = sandbox._root.path().join("backup");
    let (code, output) = sandbox.sync_with_backup(&backup);
    assert_eq!(code, 0, "{output}");

    let backups = files_below(&backup);
    assert_eq!(backups.len(), 1, "one backup expected: {backups:?}");
    assert_eq!(
        fs::read_to_string(&backups[0]).unwrap(),
        "base",
        "the backup must hold the version that was replaced"
    );
    // The path under the backup directory mirrors the path under the root.
    assert!(
        backups[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("doc.txt.bak-"),
        "{:?}",
        backups[0]
    );
    assert_eq!(
        fs::read_to_string(sandbox.remote.join("doc.txt")).unwrap(),
        "new local"
    );
}

#[test]
fn a_file_overwritten_on_the_local_side_is_backed_up() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    sandbox.settle();

    // The remote file changes, so the local one is about to be replaced.
    sandbox.write(&sandbox.remote, "doc.txt", "new remote");
    let backup = sandbox._root.path().join("backup");
    let (code, output) = sandbox.sync_with_backup(&backup);
    assert_eq!(code, 0, "{output}");

    let backups = files_below(&backup);
    assert_eq!(backups.len(), 1, "one backup expected: {backups:?}");
    assert_eq!(
        fs::read_to_string(&backups[0]).unwrap(),
        "base",
        "the backup must hold the version that was replaced"
    );
    assert_eq!(
        fs::read_to_string(sandbox.local.join("doc.txt")).unwrap(),
        "new remote"
    );
}

#[test]
fn a_deleted_file_is_backed_up() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "gone.txt", "still here");
    sandbox.write(&sandbox.local, "kept.txt", "kept");
    sandbox.settle();

    fs::remove_file(sandbox.remote.join("gone.txt")).unwrap();
    let backup = sandbox._root.path().join("backup");
    let (code, output) = sandbox.sync_with_backup(&backup);
    assert_eq!(code, 0, "{output}");

    let backups = files_below(&backup);
    assert_eq!(backups.len(), 1, "one backup expected: {backups:?}");
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), "still here");
    assert!(
        !sandbox.local.join("gone.txt").exists(),
        "the file must still be deleted"
    );
}

#[test]
fn the_backup_keeps_the_path_under_the_backup_directory() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "deep/inside/notes.txt", "base");
    sandbox.settle();

    sandbox.write(&sandbox.local, "deep/inside/notes.txt", "new");
    let backup = sandbox._root.path().join("backup");
    let (code, output) = sandbox.sync_with_backup(&backup);
    assert_eq!(code, 0, "{output}");

    let expected = backup.join("deep/inside/notes.txt.bak-");
    let found = files_below(&backup);
    assert_eq!(found.len(), 1, "{found:?}");
    let name = found[0].to_string_lossy().to_string();
    assert!(
        name.starts_with(&expected.to_string_lossy().to_string()),
        "the backup must keep the path: {name}"
    );
}

#[test]
fn the_backup_directory_is_never_synced() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    sandbox.settle();

    // The backup directory sits inside the synced root: what it holds must
    // not travel to the other side, or the next run would back up the
    // backups.
    let backup = sandbox.local.join("backups");
    sandbox.write(&sandbox.local, "doc.txt", "new");
    let (code, output) = sandbox.sync_with_backup(&backup);
    assert_eq!(code, 0, "{output}");

    assert!(!files_below(&backup).is_empty(), "the backup must exist");
    assert!(
        !sandbox.remote.join("backups").exists(),
        "the backup directory must not travel: {:?}",
        files_below(&sandbox.remote)
    );
    assert_eq!(
        files_below(&sandbox.remote).len(),
        1,
        "only the synced file may be on the other side"
    );
}

#[test]
fn a_dry_run_writes_no_backup() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    sandbox.settle();
    sandbox.write(&sandbox.local, "doc.txt", "new");

    let backup = sandbox._root.path().join("backup");
    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.local.to_str().unwrap(),
        sandbox.remote.to_str().unwrap(),
        "--auto",
        "--dry-run",
        "--backup",
        backup.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{output}");
    assert!(
        !backup.exists(),
        "a dry run writes nothing at all: {:?}",
        files_below(&backup)
    );
    assert_eq!(
        fs::read_to_string(sandbox.remote.join("doc.txt")).unwrap(),
        "base",
        "the dry run must not have replaced anything"
    );
}

#[test]
fn a_backup_is_never_overwritten() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    sandbox.settle();
    let backup = sandbox._root.path().join("backup");

    // Three changes in the same second: the timestamps collide, so the
    // backups need a counter.
    for round in 0..3 {
        sandbox.write(&sandbox.local, "doc.txt", &format!("round {round}"));
        let (code, output) = sandbox.sync_with_backup(&backup);
        assert_eq!(code, 0, "{output}");
    }

    let backups = files_below(&backup);
    assert_eq!(backups.len(), 3, "every version must be kept: {backups:?}");
    let mut contents: Vec<String> = backups
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect();
    contents.sort();
    assert_eq!(contents, vec!["base", "round 0", "round 1"]);
}
