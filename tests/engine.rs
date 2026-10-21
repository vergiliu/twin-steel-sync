use filetime::FileTime;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use twin::engine::{run, End, RunOptions, Summary};

struct Pair {
    _root: tempfile::TempDir,
    source: PathBuf,
    destination: PathBuf,
    archive: PathBuf,
}

impl Pair {
    fn new() -> Pair {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        let archive = root.path().join("archive");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::create_dir_all(&archive).unwrap();
        Pair {
            _root: root,
            source,
            destination,
            archive,
        }
    }

    fn options(&self) -> RunOptions {
        RunOptions {
            auto: true,
            archive_dir: self.archive.clone(),
            quiet: true,
            ..Default::default()
        }
    }

    fn go(&self, options: &RunOptions) -> (Summary, String) {
        let mut out = Vec::new();
        let summary = run(
            &End::Local(self.source.clone()),
            &End::Local(self.destination.clone()),
            None,
            options,
            &mut out,
        )
        .unwrap();
        (summary, String::from_utf8(out).unwrap())
    }

    /// The same pair, the other way round: the destination becomes the source.
    fn go_backwards(&self, options: &RunOptions) -> (Summary, String) {
        let mut out = Vec::new();
        let summary = run(
            &End::Local(self.destination.clone()),
            &End::Local(self.source.clone()),
            None,
            options,
            &mut out,
        )
        .unwrap();
        (summary, String::from_utf8(out).unwrap())
    }

    fn put(&self, side: Side, rel: &str, contents: &str) {
        let path = self.root(side).join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn get(&self, side: Side, rel: &str) -> String {
        fs::read_to_string(self.root(side).join(rel)).unwrap()
    }

    fn exists(&self, side: Side, rel: &str) -> bool {
        self.root(side).join(rel).exists()
    }

    fn root(&self, side: Side) -> &Path {
        match side {
            Side::Source => &self.source,
            Side::Destination => &self.destination,
        }
    }
}

#[derive(Clone, Copy)]
enum Side {
    Source,
    Destination,
}

fn plan_lines(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|l| l.starts_with("  "))
        .map(|l| l.trim().to_string())
        .collect()
}

#[test]
fn first_run_copies_then_settles() {
    let pair = Pair::new();
    pair.put(Side::Source, "notes/a.txt", "hello");
    pair.put(Side::Source, "b.txt", "world");

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.created, 2, "both files are new");
    assert_eq!(pair.get(Side::Destination, "notes/a.txt"), "hello");
    assert_eq!(pair.get(Side::Destination, "b.txt"), "world");

    let (second, _) = pair.go(&pair.options());
    assert_eq!(
        (second.created, second.updated, second.deleted),
        (0, 0, 0),
        "a settled pair must be a no-op"
    );
    assert_eq!(second.unchanged, 2);
}

#[test]
fn a_file_both_ends_already_hold_is_remembered() {
    let pair = Pair::new();
    pair.put(Side::Source, "same.txt", "same");
    pair.put(Side::Destination, "same.txt", "same");

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.created, 0, "there is nothing to copy");
    assert_eq!(summary.updated, 0);
    assert_eq!(summary.unchanged, 1);

    // The archive must know the path, or the next run would hash both ends
    // again for nothing.
    let archive = twin::archive::Archive::open(&archive_file(&pair.archive)).unwrap();
    let row = archive
        .get(Path::new("same.txt"))
        .unwrap()
        .expect("a path both ends hold must be recorded in the archive");
    assert_eq!(
        row.hash,
        twin::fsutil::hash_file(&pair.source.join("same.txt")).unwrap(),
        "the recorded hash must be the content both ends hold"
    );
    // Each end keeps its own timestamp: the fast path matches them apart.
    assert_eq!(
        row.mtime_source,
        twin::fsutil::mtime_ns(&fs::metadata(pair.source.join("same.txt")).unwrap())
    );
    assert_eq!(
        row.mtime_destination,
        twin::fsutil::mtime_ns(&fs::metadata(pair.destination.join("same.txt")).unwrap())
    );
}

/// The one archive file of a pair.
fn archive_file(dir: &Path) -> PathBuf {
    let mut found: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("db"))
        .collect();
    found.sort();
    assert_eq!(found.len(), 1, "expected exactly one archive: {found:?}");
    found.remove(0)
}

#[test]
fn the_source_always_wins() {
    let pair = Pair::new();
    pair.put(Side::Source, "f.txt", "one");
    pair.go(&pair.options());

    pair.put(Side::Source, "f.txt", "two");
    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Destination, "f.txt"), "two");

    // A version of its own on the destination is not kept: the source decides.
    pair.put(Side::Destination, "f.txt", "three");
    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Destination, "f.txt"), "two");
    assert_eq!(
        pair.get(Side::Source, "f.txt"),
        "two",
        "the source is never written to"
    );
}

#[test]
fn the_arguments_decide_the_direction() {
    let pair = Pair::new();
    pair.put(Side::Source, "doc.txt", "from the source");
    pair.put(Side::Destination, "doc.txt", "from the destination");

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Destination, "doc.txt"), "from the source");

    // The other way round, the other file wins.
    pair.put(Side::Destination, "doc.txt", "from the destination");
    let (summary, _) = pair.go_backwards(&pair.options());
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Source, "doc.txt"), "from the destination");
    assert_eq!(
        pair.get(Side::Destination, "doc.txt"),
        "from the destination",
        "the source is never written to"
    );
}

#[test]
fn a_file_deleted_on_the_source_stays_unless_asked_to_be_removed() {
    let pair = Pair::new();
    pair.put(Side::Source, "gone.txt", "x");
    pair.put(Side::Source, "kept.txt", "y");
    pair.go(&pair.options());

    fs::remove_file(pair.source.join("gone.txt")).unwrap();
    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.deleted, 0, "nothing is removed without --delete");
    assert!(
        pair.exists(Side::Destination, "gone.txt"),
        "the destination keeps what the source no longer has"
    );
    assert!(pair.exists(Side::Destination, "kept.txt"));

    let mut deleting = pair.options();
    deleting.delete = true;
    let (summary, _) = pair.go(&deleting);
    assert_eq!(summary.deleted, 1);
    assert!(!pair.exists(Side::Destination, "gone.txt"));
    assert!(pair.exists(Side::Destination, "kept.txt"));
}

#[test]
fn mass_deletion_is_refused_without_force() {
    let pair = Pair::new();
    for i in 0..200 {
        pair.put(Side::Source, &format!("many/f{i:03}.txt"), "x");
    }
    pair.go(&pair.options());

    for i in 0..150 {
        fs::remove_file(pair.source.join(format!("many/f{i:03}.txt"))).unwrap();
    }

    let mut deleting = pair.options();
    deleting.delete = true;
    let (summary, output) = pair.go(&deleting);
    assert!(summary.aborted, "the guard must stop this: {output}");
    assert!(
        pair.exists(Side::Destination, "many/f000.txt"),
        "nothing may be deleted"
    );
    assert!(pair.exists(Side::Source, "many/f199.txt"));

    let mut forced = pair.options();
    forced.delete = true;
    forced.force = true;
    let (summary, _) = pair.go(&forced);
    assert_eq!(summary.deleted, 150);
    assert!(!pair.exists(Side::Destination, "many/f000.txt"));
}

#[test]
fn dry_run_changes_nothing_and_reports_exactly_what_a_real_run_does() {
    let pair = Pair::new();
    pair.put(Side::Source, "one.txt", "1");
    pair.put(Side::Source, "dir/two.txt", "2");

    let mut preview = pair.options();
    preview.dry_run = true;
    preview.verbose = true;
    let (planned, planned_output) = pair.go(&preview);
    assert_eq!(planned.created, 2);
    assert!(
        !pair.exists(Side::Destination, "one.txt"),
        "dry run must not write"
    );
    assert!(!pair.exists(Side::Destination, "dir/two.txt"));

    let mut real = pair.options();
    real.verbose = true;
    let (performed, performed_output) = pair.go(&real);
    assert_eq!(performed.created, 2);
    assert_eq!(
        plan_lines(&planned_output),
        plan_lines(&performed_output),
        "the plan and the run must agree path for path"
    );
}

#[test]
fn metadata_fast_path_can_miss_edits_unless_asked_to_hash() {
    let pair = Pair::new();
    pair.put(Side::Source, "sneaky.txt", "aaaa");
    pair.go(&pair.options());
    let original = fs::metadata(pair.source.join("sneaky.txt")).unwrap();

    pair.put(Side::Source, "sneaky.txt", "bbbb");
    filetime::set_file_mtime(
        pair.source.join("sneaky.txt"),
        FileTime::from_unix_time(original.mtime(), original.mtime_nsec() as u32),
    )
    .unwrap();

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(
        summary.updated, 0,
        "size and mtime unchanged: nothing looks different"
    );
    assert_eq!(pair.get(Side::Destination, "sneaky.txt"), "aaaa");

    let mut hashing = pair.options();
    hashing.checksum = true;
    let (summary, _) = pair.go(&hashing);
    assert_eq!(summary.updated, 1, "--checksum must find it");
    assert_eq!(pair.get(Side::Destination, "sneaky.txt"), "bbbb");
}

#[test]
fn ignored_paths_stay_put_and_do_not_haunt_later_runs() {
    let pair = Pair::new();
    fs::write(pair.source.join(".twinignore"), "*.log\nbuild/\n").unwrap();
    pair.put(Side::Source, "keep.txt", "keep");
    pair.put(Side::Source, "noise.log", "noise");
    pair.put(Side::Source, "build/artifact", "artifact");

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(
        summary.created, 2,
        "only the ignore file and keep.txt travel"
    );
    assert!(!pair.exists(Side::Destination, "noise.log"));
    assert!(!pair.exists(Side::Destination, "build/artifact"));

    let (second, _) = pair.go(&pair.options());
    assert_eq!(
        second.created + second.updated + second.deleted,
        0,
        "ignores must stay quiet"
    );
}

/// The archive sweep: a path that is gone from both ends is forgotten, and a
/// path that is still there keeps its row. The walk already knows which paths
/// are there, so the sweep only has to look at the ones it did not see.
#[test]
fn a_path_that_is_gone_from_both_ends_is_forgotten_and_one_that_stays_keeps_its_row() {
    let pair = Pair::new();
    pair.put(Side::Source, "gone.txt", "x");
    pair.put(Side::Source, "kept.txt", "y");
    pair.go(&pair.options());

    // The file is removed on both sides: the pair no longer tracks it.
    fs::remove_file(pair.source.join("gone.txt")).unwrap();
    fs::remove_file(pair.destination.join("gone.txt")).unwrap();

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.deleted, 0, "nothing is deleted without --delete");

    let archive = twin::archive::Archive::open(&archive_file(&pair.archive)).unwrap();
    assert!(
        archive.get(Path::new("gone.txt")).unwrap().is_none(),
        "a path that is gone from both ends must not stay in the archive"
    );
    assert!(
        archive.get(Path::new("kept.txt")).unwrap().is_some(),
        "a path that is still there must keep its row"
    );

    // And the row that was kept is still the one the pair agreed on.
    let (again, _) = pair.go(&pair.options());
    assert_eq!(
        again.created + again.updated + again.deleted,
        0,
        "a run with nothing to do must do nothing"
    );
}

/// A file whose time moved on both sides but whose bytes did not: the two
/// ends still agree, so nothing is transferred and only the archive row is
/// refreshed. The plan has to read both sides to know that.
#[test]
fn a_file_that_only_moved_is_not_copied_again() {
    let pair = Pair::new();
    pair.put(Side::Source, "same.txt", "content");
    pair.put(Side::Destination, "same.txt", "content");
    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.created, 0, "both ends already hold the same bytes");

    // The time moves on both sides; the bytes do not.
    let later = FileTime::from_unix_time(1_700_000_000, 0);
    filetime::set_file_mtime(pair.source.join("same.txt"), later).unwrap();
    filetime::set_file_mtime(pair.destination.join("same.txt"), later).unwrap();

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(
        summary.updated, 0,
        "the bytes did not change: nothing is transferred"
    );
    assert_eq!(summary.unchanged, 1, "the two ends still agree");
    assert_eq!(pair.get(Side::Destination, "same.txt"), "content");

    // And the row now knows the new times, so the next run is quiet.
    let (again, _) = pair.go(&pair.options());
    assert_eq!(
        again.created + again.updated + again.deleted,
        0,
        "a run with nothing to do must do nothing"
    );
}

#[test]
fn the_source_is_read_and_the_destination_is_written() {
    let pair = Pair::new();
    pair.put(Side::Source, "a.txt", "local");
    pair.put(Side::Destination, "extra.txt", "only here");

    let (summary, _) = pair.go(&pair.options());
    assert_eq!(summary.created, 1);
    assert_eq!(pair.get(Side::Destination, "a.txt"), "local");
    assert!(
        pair.exists(Side::Destination, "extra.txt"),
        "no deletion without --delete"
    );
    assert!(
        !pair.exists(Side::Source, "extra.txt"),
        "the source is never written to"
    );

    let mut deleting = pair.options();
    deleting.delete = true;
    let (summary, _) = pair.go(&deleting);
    assert_eq!(summary.deleted, 1);
    assert!(!pair.exists(Side::Destination, "extra.txt"));
}

#[test]
fn roots_that_contain_each_other_are_refused() {
    let pair = Pair::new();
    let options = pair.options();
    let mut out = Vec::new();
    let nested = pair.source.join("inside");
    fs::create_dir_all(&nested).unwrap();
    let error = run(
        &End::Local(pair.source.clone()),
        &End::Local(nested),
        None,
        &options,
        &mut out,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("must not contain each other"),
        "got: {error}"
    );
}

#[test]
fn the_same_directory_on_both_sides_is_refused() {
    let pair = Pair::new();
    let options = pair.options();
    let mut out = Vec::new();
    let error = run(
        &End::Local(pair.source.clone()),
        &End::Local(pair.source.clone()),
        None,
        &options,
        &mut out,
    )
    .unwrap_err();
    assert!(error.to_string().contains("same directory"), "got: {error}");
}
