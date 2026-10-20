//! CLI-level tests: they cover the wiring between flags, engine options and exit
//! codes, and the direction the two arguments decide.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn twin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

struct Sandbox {
    _root: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
    archive: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        let archive = root.path().join("archive");
        for dir in [&source, &destination, &archive] {
            fs::create_dir_all(dir).unwrap();
        }
        Sandbox {
            _root: root,
            source,
            destination,
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

    /// Copy the source to the destination.
    fn sync(&self) -> (i32, String) {
        self.run(&[
            "sync",
            self.source.to_str().unwrap(),
            self.destination.to_str().unwrap(),
            "--auto",
            "--quiet",
        ])
    }

    fn read(&self, side: &Path, rel: &str) -> String {
        fs::read_to_string(side.join(rel)).unwrap()
    }
}

#[test]
fn the_arguments_decide_which_way_the_content_flows() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("a.txt"), "from the source").unwrap();
    fs::write(sandbox.destination.join("a.txt"), "from the destination").unwrap();

    let (code, output) = sandbox.sync();
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        sandbox.read(&sandbox.destination, "a.txt"),
        "from the source",
        "the first argument is the source, the second the destination"
    );

    // The other order copies the other way.
    fs::write(sandbox.destination.join("a.txt"), "from the destination").unwrap();
    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.destination.to_str().unwrap(),
        sandbox.source.to_str().unwrap(),
        "--auto",
        "--quiet",
    ]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        sandbox.read(&sandbox.source, "a.txt"),
        "from the destination",
        "the first argument is the source, so it wins"
    );
}

#[test]
fn dry_run_prints_the_plan_and_changes_nothing() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("a.txt"), "hello").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.source.to_str().unwrap(),
        sandbox.destination.to_str().unwrap(),
        "--dry-run",
        "--auto",
    ]);
    assert_eq!(code, 0, "{output}");
    assert!(output.contains("create"), "plan expected: {output}");
    assert!(
        !sandbox.destination.join("a.txt").exists(),
        "dry run must not create files"
    );
}

#[test]
fn the_source_wins_and_the_destination_keeps_no_version_of_its_own() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("doc.txt"), "base").unwrap();
    sandbox.sync();

    fs::write(sandbox.source.join("doc.txt"), "mine").unwrap();
    fs::write(sandbox.destination.join("doc.txt"), "theirs").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.source.to_str().unwrap(),
        sandbox.destination.to_str().unwrap(),
        "--auto",
    ]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(sandbox.read(&sandbox.destination, "doc.txt"), "mine");
    assert_eq!(sandbox.read(&sandbox.source, "doc.txt"), "mine");

    let names: Vec<String> = fs::read_dir(&sandbox.destination)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        !names.iter().any(|n| n.contains(".conflict-")),
        "a one-way copy keeps no second version: {names:?}"
    );
}

#[test]
fn a_new_pair_without_consent_reports_and_writes_nothing() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("a.txt"), "hello").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.source.to_str().unwrap(),
        sandbox.destination.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 2,
        "a non-interactive call without --auto must refuse: {output}"
    );
    assert!(!sandbox.destination.join("a.txt").exists());
}

/// F-015: a dry run is a report, not a decision. It exits 0 even when the
/// plan holds deletions.
#[test]
fn a_dry_run_exits_zero_even_when_the_plan_holds_deletions() {
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("doc.txt"), "base").unwrap();
    fs::write(sandbox.destination.join("doc.txt"), "theirs").unwrap();
    sandbox.sync();

    fs::write(sandbox.source.join("doc.txt"), "mine").unwrap();
    fs::write(sandbox.destination.join("gone.txt"), "to be removed").unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.source.to_str().unwrap(),
        sandbox.destination.to_str().unwrap(),
        "--auto",
        "--dry-run",
        "--delete",
    ]);
    assert_eq!(code, 0, "a dry run is not a failure: {output}");
    assert!(
        output.contains("delete"),
        "the plan must be shown: {output}"
    );
    assert!(
        sandbox.destination.join("gone.txt").exists(),
        "a dry run removes nothing: {output}"
    );
}

/// F-029: a path that cannot be read fails on its own. The other paths carry
/// on and the run ends with the partial exit code.
#[test]
fn a_file_that_cannot_be_read_fails_alone() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root reads everything: nothing to assert
    }
    let sandbox = Sandbox::new();
    fs::write(sandbox.source.join("bad.txt"), "unreadable").unwrap();
    fs::write(sandbox.source.join("good.txt"), "fine").unwrap();

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        sandbox.source.join("bad.txt"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let (code, output) = sandbox.run(&[
        "sync",
        sandbox.source.to_str().unwrap(),
        sandbox.destination.to_str().unwrap(),
        "--auto",
    ]);
    assert_eq!(code, 4, "one file failed: {output}");
    assert!(
        output.contains("bad.txt"),
        "the failure must name the path: {output}"
    );
    assert!(
        output.contains("failures 1"),
        "the failure must be counted: {output}"
    );
    assert!(
        sandbox.destination.join("good.txt").exists(),
        "the other files must carry on: {output}"
    );
    assert!(!sandbox.destination.join("bad.txt").exists());

    fs::set_permissions(
        sandbox.source.join("bad.txt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}
