//! CLI-level tests: they cover the wiring between flags, engine options and exit
//! codes, which is exactly where a "verify" that quietly writes was hiding.

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

    fn sync(&self) -> (i32, String) {
        self.run(&[
            "sync",
            self.local.to_str().unwrap(),
            self.remote.to_str().unwrap(),
            "--auto",
            "--quiet",
        ])
    }

    fn verify(&self) -> (i32, String) {
        self.run(&[
            "verify",
            self.local.to_str().unwrap(),
            self.remote.to_str().unwrap(),
        ])
    }

    fn read(&self, side: &Path, rel: &str) -> String {
        fs::read_to_string(side.join(rel)).unwrap()
    }
}

#[test]
fn verify_reports_differences_without_touching_anything() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.local.join("a.txt"), "original").unwrap();
    sandbox.sync();

    fs::write(sandbox.local.join("a.txt"), "changed").unwrap();
    let (code, output) = sandbox.verify();
    assert_eq!(code, 3, "differences must be reported: {output}");

    assert_eq!(
        sandbox.read(&sandbox.remote, "a.txt"),
        "original",
        "verify must not copy anything"
    );

    // and it must still report the same difference afterwards
    let (code, _) = sandbox.verify();
    assert_eq!(code, 3);
}

#[test]
fn dry_run_prints_the_plan_and_changes_nothing() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.local.join("a.txt"), "hello").unwrap();

    let (code, output) = sandbox.run(&[
        "push",
        sandbox.local.to_str().unwrap(),
        sandbox.remote.to_str().unwrap(),
        "--dry-run",
        "--auto",
    ]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("create"), "plan expected: {output}");
    assert!(
        !sandbox.remote.join("a.txt").exists(),
        "dry run must not create files"
    );
}

#[test]
fn conflicts_exit_three_and_leave_both_versions_on_both_sides() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.local.join("doc.txt"), "base").unwrap();
    sandbox.sync();

    fs::write(sandbox.local.join("doc.txt"), "mine").unwrap();
    fs::write(sandbox.remote.join("doc.txt"), "theirs").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.local.to_str().unwrap(),
        sandbox.remote.to_str().unwrap(),
        "--auto",
    ]);
    assert_eq!(code, 3, "{output}");

    let names: Vec<String> = fs::read_dir(&sandbox.local)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n.contains(".conflict-")),
        "a conflict copy must exist: {names:?}"
    );
    let copy = names.iter().find(|n| n.contains(".conflict-")).unwrap();
    assert!(
        sandbox.remote.join(copy).exists(),
        "the conflict copy must exist on both sides"
    );
}

#[test]
fn a_new_pair_without_consent_reports_and_writes_nothing() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.local.join("a.txt"), "hello").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.local.to_str().unwrap(),
        sandbox.remote.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 2,
        "a non-interactive call without --auto must refuse: {output}"
    );
    assert!(!sandbox.remote.join("a.txt").exists());
}
