use filetime::FileTime;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use twin::engine::{run, Mode, RunOptions, Summary};

struct Pair {
    _root: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    archive: PathBuf,
}

impl Pair {
    fn new() -> Pair {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let remote = root.path().join("remote");
        let archive = root.path().join("archive");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&remote).unwrap();
        fs::create_dir_all(&archive).unwrap();
        Pair {
            _root: root,
            local,
            remote,
            archive,
        }
    }

    fn options(&self, mode: Mode) -> RunOptions {
        RunOptions {
            mode,
            auto: true,
            archive_dir: self.archive.clone(),
            quiet: true,
            ..Default::default()
        }
    }

    fn go(&self, options: &RunOptions) -> (Summary, String) {
        let mut out = Vec::new();
        let summary = run(&self.local, &self.remote, options, &mut out).unwrap();
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
            Side::Local => &self.local,
            Side::Remote => &self.remote,
        }
    }

    fn names(&self, side: Side) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.root(side))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }
}

#[derive(Clone, Copy)]
enum Side {
    Local,
    Remote,
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
    pair.put(Side::Local, "notes/a.txt", "hello");
    pair.put(Side::Local, "b.txt", "world");

    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(summary.created, 2, "both files are new");
    assert_eq!(pair.get(Side::Remote, "notes/a.txt"), "hello");
    assert_eq!(pair.get(Side::Remote, "b.txt"), "world");

    let (second, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(
        (
            second.created,
            second.updated,
            second.deleted,
            second.conflicts
        ),
        (0, 0, 0, 0),
        "a settled pair must be a no-op"
    );
    assert_eq!(second.unchanged, 2);
}

#[test]
fn edits_propagate_whichever_side_they_happen_on() {
    let pair = Pair::new();
    pair.put(Side::Local, "f.txt", "one");
    pair.go(&pair.options(Mode::Sync));

    pair.put(Side::Local, "f.txt", "two");
    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Remote, "f.txt"), "two");

    pair.put(Side::Remote, "f.txt", "three");
    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(summary.updated, 1);
    assert_eq!(pair.get(Side::Local, "f.txt"), "three");
}

#[test]
fn deletion_propagates_only_when_the_survivor_is_untouched() {
    let pair = Pair::new();
    pair.put(Side::Local, "gone.txt", "x");
    pair.put(Side::Local, "kept.txt", "y");
    pair.go(&pair.options(Mode::Sync));

    fs::remove_file(pair.remote.join("gone.txt")).unwrap();
    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(summary.deleted, 1);
    assert!(
        !pair.exists(Side::Local, "gone.txt"),
        "deletion must propagate"
    );
    assert!(pair.exists(Side::Local, "kept.txt"));
}

#[test]
fn concurrent_edits_keep_both_versions() {
    let pair = Pair::new();
    pair.put(Side::Local, "doc.txt", "original");
    pair.go(&pair.options(Mode::Sync));

    pair.put(Side::Local, "doc.txt", "local version");
    pair.put(Side::Remote, "doc.txt", "remote version");

    let mut loud = pair.options(Mode::Sync);
    loud.quiet = false;
    let (summary, output) = pair.go(&loud);
    assert_eq!(summary.conflicts, 1);
    assert!(
        output.contains("conflict"),
        "the user must be told: {output}"
    );

    let copies: Vec<String> = pair
        .names(Side::Local)
        .into_iter()
        .filter(|n| n.contains(".conflict-"))
        .collect();
    assert_eq!(
        copies.len(),
        1,
        "local keeps its name, the other version is kept beside it"
    );
    assert!(
        pair.exists(Side::Remote, &copies[0]),
        "both sides carry both versions"
    );

    let mut both = vec![
        pair.get(Side::Local, "doc.txt"),
        pair.get(Side::Remote, "doc.txt"),
        pair.get(Side::Local, &copies[0]),
        pair.get(Side::Remote, &copies[0]),
    ];
    both.sort();
    assert_eq!(
        both,
        vec![
            "local version",
            "local version",
            "remote version",
            "remote version"
        ]
    );
}

#[test]
fn an_edited_file_survives_deletion_on_the_other_side() {
    let pair = Pair::new();
    pair.put(Side::Local, "work.txt", "v1");
    pair.go(&pair.options(Mode::Sync));

    fs::remove_file(pair.remote.join("work.txt")).unwrap();
    pair.put(Side::Local, "work.txt", "v2 edited");

    let mut loud = pair.options(Mode::Sync);
    loud.quiet = false;
    let (summary, output) = pair.go(&loud);
    assert_eq!(summary.created, 1, "the edit is restored to the other side");
    assert_eq!(pair.get(Side::Local, "work.txt"), "v2 edited");
    assert_eq!(pair.get(Side::Remote, "work.txt"), "v2 edited");
    assert!(
        output.contains("restore"),
        "resurrections are reported: {output}"
    );
}

#[test]
fn mass_deletion_is_refused_without_force() {
    let pair = Pair::new();
    for i in 0..200 {
        pair.put(Side::Local, &format!("many/f{i:03}.txt"), "x");
    }
    pair.go(&pair.options(Mode::Sync));

    for i in 0..150 {
        fs::remove_file(pair.local.join(format!("many/f{i:03}.txt"))).unwrap();
    }

    let (summary, output) = pair.go(&pair.options(Mode::Sync));
    assert!(summary.aborted, "the guard must stop this: {output}");
    assert!(
        pair.exists(Side::Remote, "many/f000.txt"),
        "nothing may be deleted"
    );
    assert!(pair.exists(Side::Local, "many/f199.txt"));

    let mut forced = pair.options(Mode::Sync);
    forced.force = true;
    let (summary, _) = pair.go(&forced);
    assert_eq!(summary.deleted, 150);
    assert!(!pair.exists(Side::Remote, "many/f000.txt"));
}

#[test]
fn dry_run_changes_nothing_and_reports_exactly_what_a_real_run_does() {
    let pair = Pair::new();
    pair.put(Side::Local, "one.txt", "1");
    pair.put(Side::Local, "dir/two.txt", "2");

    let mut preview = pair.options(Mode::Sync);
    preview.dry_run = true;
    preview.verbose = true;
    let (planned, planned_output) = pair.go(&preview);
    assert_eq!(planned.created, 2);
    assert!(
        !pair.exists(Side::Remote, "one.txt"),
        "dry run must not write"
    );
    assert!(!pair.exists(Side::Remote, "dir/two.txt"));

    let mut real = pair.options(Mode::Sync);
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
    pair.put(Side::Local, "sneaky.txt", "aaaa");
    pair.go(&pair.options(Mode::Sync));
    let original = fs::metadata(pair.local.join("sneaky.txt")).unwrap();

    pair.put(Side::Local, "sneaky.txt", "bbbb");
    filetime::set_file_mtime(
        pair.local.join("sneaky.txt"),
        FileTime::from_unix_time(original.mtime(), original.mtime_nsec() as u32),
    )
    .unwrap();

    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(
        summary.updated, 0,
        "size and mtime unchanged: nothing looks different"
    );
    assert_eq!(pair.get(Side::Remote, "sneaky.txt"), "aaaa");

    let mut hashing = pair.options(Mode::Sync);
    hashing.checksum = true;
    let (summary, _) = pair.go(&hashing);
    assert_eq!(summary.updated, 1, "--checksum must find it");
    assert_eq!(pair.get(Side::Remote, "sneaky.txt"), "bbbb");
}

#[test]
fn ignored_paths_stay_put_and_do_not_haunt_later_runs() {
    let pair = Pair::new();
    fs::write(pair.local.join(".twinignore"), "*.log\nbuild/\n").unwrap();
    pair.put(Side::Local, "keep.txt", "keep");
    pair.put(Side::Local, "noise.log", "noise");
    pair.put(Side::Local, "build/artifact", "artifact");

    let (summary, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(
        summary.created, 2,
        "only the ignore file and keep.txt travel"
    );
    assert!(!pair.exists(Side::Remote, "noise.log"));
    assert!(!pair.exists(Side::Remote, "build/artifact"));

    let (second, _) = pair.go(&pair.options(Mode::Sync));
    assert_eq!(
        second.created + second.updated + second.deleted,
        0,
        "ignores must stay quiet"
    );
}

#[test]
fn push_is_one_way_and_only_deletes_with_the_flag() {
    let pair = Pair::new();
    pair.put(Side::Local, "a.txt", "local");
    pair.put(Side::Remote, "extra.txt", "only here");

    let (summary, _) = pair.go(&pair.options(Mode::Push));
    assert_eq!(summary.created, 1);
    assert_eq!(pair.get(Side::Remote, "a.txt"), "local");
    assert!(
        pair.exists(Side::Remote, "extra.txt"),
        "no deletion without --delete"
    );
    assert!(
        !pair.exists(Side::Local, "extra.txt"),
        "push never writes to the local side"
    );

    let mut deleting = pair.options(Mode::Push);
    deleting.delete = true;
    let (summary, _) = pair.go(&deleting);
    assert_eq!(summary.deleted, 1);
    assert!(!pair.exists(Side::Remote, "extra.txt"));
}

#[test]
fn roots_that_contain_each_other_are_refused() {
    let pair = Pair::new();
    let mut options = pair.options(Mode::Sync);
    options.auto = true;
    let mut out = Vec::new();
    let nested = pair.local.join("inside");
    fs::create_dir_all(&nested).unwrap();
    let error = run(&pair.local, &nested, &options, &mut out).unwrap_err();
    assert!(
        error.to_string().contains("must not contain each other"),
        "got: {error}"
    );
}
