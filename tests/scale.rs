//! F-071: the 10k-file tree.
//!
//! ONE thousand small files in a hundred directories, synced once and then
//! synced again. The first run proves the machine can move a tree of that size;
//! the second run is the point of the whole test: it must do nothing at all,
//! which is what the archive is for. Without the archive every run would
//! re-hash and re-copy the whole tree.
//!
//! Why ten thousand: the shape of the test is a tree, a directory walk and an
//! archive with a row per file, and the point of the size is that anything
//! accidentally quadratic (an archive lookup per path, a plan that re-scans
//! what it has already seen) shows up here and nowhere else.
//!
//! Runtime: the first run is dominated by one fsync per file (F-021 puts every
//! file through a temp file, an fsync and a rename), so expect tens of seconds
//! on a slow disk and more on macOS, where the fsync is an `F_FULLFSYNC` —
//! about nine minutes for ten thousand files on an M-series laptop. The second
//! run only reads metadata and hashes, so it is seconds at worst. There is
//! deliberately no wall-clock assertion: CI machines vary far too much for a
//! time bound to be honest, and a flaky test is worse than no test. The
//! elapsed time of both runs is printed instead, so a human can read it.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

/// How many directories the tree is spread over.
const DIRECTORIES: usize = 20;
/// How many files live in each directory.
const FILES_PER_DIRECTORY: usize = 50;
/// The number of files the tree holds.
const TOTAL: usize = DIRECTORIES * FILES_PER_DIRECTORY;
/// The same few dozen bytes in every file: the point is the file count.
const CONTENT: &[u8] = b"twin scale fixture: every file says the same thing.\n";

/// Every regular file under `root`, as a path relative to it.
fn files_under(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                found.insert(relative);
            }
        }
    }
    found
}

/// Build the tree and return the paths it holds, relative to the root.
fn build_tree(root: &Path) -> BTreeSet<String> {
    let mut expected = BTreeSet::new();
    for directory in 0..DIRECTORIES {
        let base = root.join(format!("dir{directory:03}"));
        fs::create_dir_all(&base).unwrap();
        for file in 0..FILES_PER_DIRECTORY {
            // Most files sit directly in the directory; the last ten live two
            // levels down, so the walk has to recurse as well as list.
            let relative = if file < FILES_PER_DIRECTORY.saturating_sub(10) {
                format!("dir{directory:03}/file{file:03}.txt")
            } else {
                format!("dir{directory:03}/nested/deep/file{file:03}.txt")
            };
            let path = root.join(&relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, CONTENT).unwrap();
            expected.insert(relative);
        }
    }
    expected
}

/// Ten thousand files cost about nine minutes on macOS (F-021 puts every file
/// through a temp file, an fsync and a rename, and on macOS that fsync is an
/// `F_FULLFSYNC`), so the test is ignored by default and the CI workflow runs
/// it in a job of its own, where it can take as long as it needs.
#[test]
#[ignore = "slow: one fsync per file; CI runs it in the `scale` job"]
fn ten_thousand_files_are_synced_once_and_then_nothing_happens() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let destination = root.path().join("destination");
    let data = root.path().join("client-data");
    let archive = root.path().join("archive");
    for dir in [&source, &destination, &data, &archive] {
        fs::create_dir_all(dir).unwrap();
    }

    let expected = build_tree(&source);
    assert_eq!(expected.len(), TOTAL, "the fixture must hold {TOTAL} files");

    // First run: everything is copied.
    let mut first = common::client(&data);
    first
        .arg("sync")
        .arg(&source)
        .arg(&destination)
        .arg("--auto")
        .env("TWIN_ARCHIVE_DIR", &archive);

    let started = Instant::now();
    let (code, output) = common::run(&mut first);
    let first_elapsed = started.elapsed();
    assert_eq!(code, 0, "the first sync must succeed: {output}");

    let counters = common::summary(&output);
    assert_eq!(
        counters.get("created"),
        Some(&(TOTAL as u64)),
        "the first sync must create every file: {output}"
    );
    assert_eq!(
        counters.get("updated"),
        Some(&0),
        "the first sync must not update anything: {output}"
    );
    assert_eq!(
        counters.get("deleted"),
        Some(&0),
        "the first sync must not delete anything: {output}"
    );
    assert_eq!(
        counters.get("failures"),
        Some(&0),
        "the first sync must not fail on any file: {output}"
    );

    let landed = files_under(&destination);
    assert_eq!(
        landed.len(),
        TOTAL,
        "the destination must hold {TOTAL} files, found {}",
        landed.len()
    );
    assert_eq!(
        landed, expected,
        "the destination must hold exactly the files of the source"
    );
    for path in &landed {
        assert!(
            !Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".twin-tmp-"),
            "a temp file must never survive as content: {path}"
        );
    }

    // Second run: the archive knows everything already, so nothing happens.
    let mut second = common::client(&data);
    second
        .arg("sync")
        .arg(&source)
        .arg(&destination)
        .arg("--auto")
        .env("TWIN_ARCHIVE_DIR", &archive);

    let started = Instant::now();
    let (code, output) = common::run(&mut second);
    let second_elapsed = started.elapsed();
    assert_eq!(code, 0, "the second sync must succeed: {output}");

    let counters = common::summary(&output);
    assert_eq!(
        counters.get("created"),
        Some(&0),
        "the second sync must create nothing: {output}"
    );
    assert_eq!(
        counters.get("updated"),
        Some(&0),
        "the second sync must update nothing: {output}"
    );
    assert_eq!(
        counters.get("deleted"),
        Some(&0),
        "the second sync must delete nothing: {output}"
    );
    assert_eq!(
        counters.get("failures"),
        Some(&0),
        "the second sync must not fail on any file: {output}"
    );
    assert_eq!(
        counters.get("unchanged"),
        Some(&(TOTAL as u64)),
        "every file must already agree with the archive: {output}"
    );

    let landed = files_under(&destination);
    assert_eq!(
        landed, expected,
        "the second sync must leave the destination exactly as it was"
    );

    eprintln!("{TOTAL}-file tree: first sync {first_elapsed:?}, second sync {second_elapsed:?}");
}
