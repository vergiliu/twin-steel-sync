use crate::archive::{archive_path, Archive};
use crate::backup;
use crate::classify::{self, Resolved, Verdict};
use crate::fsutil::{timestamp_utc, ErrCtx};
use crate::model::{
    cmp_path, metadata_matches, Action, BaseRow, Entry, Hash, Kind, PathFailure, Side,
};
use crate::remote::{RemoteBackend, RemoteOptions};
use crate::report::Reporter;
use crate::scan::{absolute, patterns_for, IgnoreRules};
use crate::side::{Backend, LocalBackend};
use crate::tls;
use std::cmp::Ordering;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Sync,
    Push,
    Pull,
}

impl Mode {
    fn one_way_target(self) -> Option<Side> {
        match self {
            Mode::Sync => None,
            Mode::Push => Some(Side::Remote),
            Mode::Pull => Some(Side::Local),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub mode: Mode,
    pub dry_run: bool,
    /// One-way only: remove paths the source does not have.
    pub delete: bool,
    /// Override the mass-delete guard.
    pub force: bool,
    /// Consent for the first run of a new pair.
    pub auto: bool,
    pub checksum: bool,
    pub fast: bool,
    pub default_ignores: bool,
    pub excludes: Vec<String>,
    pub archive_dir: PathBuf,
    /// Where the version that is about to be replaced or removed is kept.
    pub backup_dir: Option<PathBuf>,
    /// Report as one JSON object per line instead of in prose.
    pub json: bool,
    /// Keep an interrupted transfer and continue it on the next run.
    pub partial: bool,
    /// Whether standard error is a terminal: the progress line is then drawn
    /// in place. The progress goes to standard error, so that is the stream
    /// the answer has to come from.
    pub tty: bool,
    pub verbose: bool,
    pub quiet: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            mode: Mode::Sync,
            dry_run: false,
            delete: false,
            force: false,
            auto: false,
            checksum: false,
            fast: false,
            default_ignores: true,
            excludes: Vec::new(),
            archive_dir: default_archive_dir(),
            backup_dir: None,
            json: false,
            partial: false,
            tty: false,
            verbose: false,
            quiet: false,
        }
    }
}

pub fn default_archive_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TWIN_ARCHIVE_DIR") {
        return PathBuf::from(dir);
    }
    tls::data_dir().join("archive")
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub created: u64,
    pub updated: u64,
    pub deleted: u64,
    pub conflicts: u64,
    pub skipped: u64,
    pub failures: u64,
    pub unchanged: u64,
    /// The pair is new and nobody said yes yet; nothing was written.
    pub needs_consent: bool,
    /// The mass-delete guard stopped the run; nothing was written.
    pub aborted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok,
    Failed,
    Conflicts,
    Partial,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::Failed => 1,
            ExitCode::Conflicts => 3,
            ExitCode::Partial => 4,
        }
    }
}

impl Summary {
    pub fn exit_code(&self) -> ExitCode {
        if self.aborted || self.needs_consent {
            ExitCode::Failed
        } else if self.failures > 0 {
            ExitCode::Partial
        } else if self.conflicts > 0 {
            ExitCode::Conflicts
        } else {
            ExitCode::Ok
        }
    }
}

struct Plan {
    actions: Vec<Action>,
    unchanged: u64,
    /// Paths that could not even be planned. They are reported and counted;
    /// the other paths carry on.
    failures: Vec<PathFailure>,
}

/// Converge two local directories.
pub fn run(
    local_root: &Path,
    remote_root: &Path,
    opts: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<Summary> {
    validate_roots(local_root, remote_root)?;
    let excluded = excluded_dirs(opts);
    let rules = IgnoreRules::load(local_root, opts.default_ignores, &opts.excludes)?;
    let mut local = LocalBackend::excluding(local_root, rules.clone(), excluded.clone())?;
    let mut remote = LocalBackend::excluding(remote_root, rules, excluded)?;
    let key = remote_root.display().to_string();
    let label = remote_label(remote_root);
    run_pair(&mut local, &mut remote, local_root, &key, &label, opts, out)
}

/// Converge a local directory with a directory served by `twin serve` on another
/// machine, over mutual TLS. `pin` is the certificate fingerprint that machine
/// must present.
pub fn run_tls(
    local_root: &Path,
    remote: &RemoteOptions,
    pin: &str,
    opts: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<Summary> {
    validate_local_root(local_root)?;
    let patterns = patterns_for(local_root, &opts.excludes)?;
    let rules = IgnoreRules::from_patterns(local_root, opts.default_ignores, &patterns)?;
    let identity = tls::Identity::load_or_create(&tls::data_dir())?;
    let mut far = RemoteBackend::connect(remote, &identity, pin, opts.default_ignores, &patterns)?;
    let mut local = LocalBackend::excluding(local_root, rules, excluded_dirs(opts))?;
    let key = remote.label();
    let label = remote.host.clone();
    let outcome = run_pair(&mut local, &mut far, local_root, &key, &label, opts, out);
    let closed = far.finish();
    outcome.and_then(|summary| closed.map(|()| summary))
}

/// The directories the local tree must never walk into.
///
/// The backup directory holds copies of files that are on their way out; they
/// must not travel back into the pair, and the directory must not be walked at
/// all even when it sits inside the synced root.
fn excluded_dirs(opts: &RunOptions) -> Vec<PathBuf> {
    match &opts.backup_dir {
        Some(dir) => vec![absolute(dir)],
        None => Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pair(
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    local_root: &Path,
    archive_key: &str,
    conflict_label: &str,
    opts: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<Summary> {
    crate::debug!(
        "pair {} <-> {} ({}), archive {}",
        local_root.display(),
        archive_key,
        match opts.mode {
            Mode::Sync => "two-way",
            Mode::Push => "push",
            Mode::Pull => "pull",
        },
        opts.archive_dir.display()
    );
    let archive = Archive::open(&archive_path(&opts.archive_dir, local_root, archive_key))
        .ctx(|| format!("opening the archive in {}", opts.archive_dir.display()))?;
    let first_run = archive.is_empty()?;
    let tracked = if first_run { 0 } else { archive.count()? };
    crate::debug!(
        "archive holds {tracked} tracked paths{}",
        if first_run { " (new pair)" } else { "" }
    );

    let stamp = timestamp_utc();
    let mut reporter = Reporter::new(out, opts);
    let plan = build_plan(local, remote, &archive, opts, conflict_label, &stamp)?;

    // The JSON stream starts with the plan: it is what the run intends to do,
    // before anything is attempted.
    if opts.json {
        reporter.plan(&plan.actions)?;
        reporter.conflict_and_skip_events(&plan.actions)?;
    }

    let mut summary = Summary {
        unchanged: plan.unchanged,
        failures: plan.failures.len() as u64,
        ..Default::default()
    };
    for failure in &plan.failures {
        reporter.path_error(&failure.path, &failure.message)?;
    }

    let planned_deletes = plan
        .actions
        .iter()
        .filter(|a| matches!(a, Action::Delete { .. } | Action::Forget { .. }))
        .count() as u64;
    let limit = std::cmp::max(100, tracked / 4);
    // A dry run is a report, not a decision: never block it, and never let it write.
    if !opts.dry_run && planned_deletes > limit && !opts.force {
        if reporter.is_json() {
            reporter.notice(&format!(
                "refusing to delete {planned_deletes} of {tracked} tracked paths (guard limit {limit}); \
                 re-run with --force if this is what you want"
            ))?;
        } else {
            reporter.notice(&format!(
                "refusing to delete {planned_deletes} of {tracked} tracked paths (guard limit {limit})"
            ))?;
            for action in plan.actions.iter().take(10) {
                writeln!(reporter.out(), "  {}", action.describe())?;
            }
            reporter.notice("re-run with --force if this is what you want")?;
        }
        let aborted = Summary {
            aborted: true,
            ..summary
        };
        reporter.summary(&aborted)?;
        reporter.finish()?;
        return Ok(aborted);
    }

    let consequential = plan
        .actions
        .iter()
        .filter(|a| !matches!(a, Action::Skip { .. }))
        .count();
    if first_run && consequential > 0 && !opts.auto && !opts.dry_run {
        if reporter.is_json() {
            reporter.notice(&format!(
                "this pair has never been synced ({consequential} actions planned); \
                 re-run with --auto to proceed"
            ))?;
        } else {
            reporter.notice(&format!(
                "this pair has never been synced ({consequential} actions planned); \
                 showing what would happen"
            ))?;
            reporter.plan(&plan.actions)?;
            reporter.notice("re-run with --auto to proceed")?;
        }
        let needs_consent = Summary {
            needs_consent: true,
            ..summary
        };
        reporter.summary(&needs_consent)?;
        reporter.finish()?;
        return Ok(needs_consent);
    }

    if opts.dry_run {
        if !opts.json {
            reporter.plan(&plan.actions)?;
        }
        if !opts.quiet {
            reporter.skip_report(&plan.actions)?;
        }
        let summary = summary_of(&plan);
        reporter.summary(&summary)?;
        reporter.finish()?;
        return Ok(summary);
    }

    if opts.verbose && !opts.json {
        reporter.plan(&plan.actions)?;
    }

    reporter.set_total(planned_bytes(&plan.actions));
    for action in &plan.actions {
        crate::debug!("applying: {}", action.describe());
        match apply(
            action,
            local,
            remote,
            local_root,
            &archive,
            &mut summary,
            &mut reporter,
            opts,
            &stamp,
        ) {
            Ok(()) => {
                // A file that reappears because the other side deleted it is rare
                // and consequential; say so even without -v.
                if !opts.quiet && !reporter.is_json() && matches!(action, Action::Resurrect { .. })
                {
                    writeln!(reporter.out(), "  {}", action.describe())?;
                }
            }
            Err(error) => {
                summary.failures += 1;
                reporter.action_error(action, &error.to_string())?;
            }
        }
    }
    // The progress line is closed before the report: the summary must start on
    // a line of its own.
    reporter.finish()?;
    reporter.text_summary(&summary)?;
    if !opts.quiet {
        reporter.skip_report(&plan.actions)?;
    }
    reporter.summary(&summary)?;
    Ok(summary)
}

/// How many bytes the plan intends to move.
fn planned_bytes(actions: &[Action]) -> u64 {
    actions
        .iter()
        .map(|action| match action {
            Action::Copy { size, .. } | Action::Resurrect { size, .. } => *size,
            _ => 0,
        })
        .sum()
}

fn build_plan(
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    archive: &Archive,
    opts: &RunOptions,
    label: &str,
    stamp: &str,
) -> io::Result<Plan> {
    let mut actions = Vec::new();
    let mut unchanged = 0u64;
    let mut failures: Vec<PathFailure> = Vec::new();

    let mut lnext = local.walk()?;
    let mut rnext = remote.walk()?;

    loop {
        let (take_local, take_remote) = match (&lnext, &rnext) {
            (None, None) => break,
            (Some(Ok(l)), Some(Ok(r))) => match cmp_path(&l.path, &r.path) {
                Ordering::Equal => (true, true),
                Ordering::Less => (true, false),
                Ordering::Greater => (false, true),
            },
            (Some(Ok(_)), None) => (true, false),
            (None, Some(Ok(_))) => (false, true),
            // A path that could not be read is reported on its own; the walk
            // carries on with the paths that can be read.
            (Some(Err(_)), _) => (true, false),
            (_, Some(Err(_))) => (false, true),
        };
        let l = if take_local { lnext.take() } else { None };
        let r = if take_remote { rnext.take() } else { None };

        let mut l_entry: Option<Entry> = None;
        let mut r_entry: Option<Entry> = None;
        match l {
            Some(Ok(entry)) => l_entry = Some(entry),
            Some(Err(failure)) => failures.push(failure),
            None => {}
        }
        match r {
            Some(Ok(entry)) => r_entry = Some(entry),
            Some(Err(failure)) => failures.push(failure),
            None => {}
        }

        let path = l_entry
            .as_ref()
            .or(r_entry.as_ref())
            .map(|entry| entry.path.clone());
        if let Some(path) = path {
            // One path that cannot be planned must not stop the others.
            if let Err(error) = handle_path(
                &path,
                l_entry.as_ref(),
                r_entry.as_ref(),
                local,
                remote,
                archive,
                opts,
                label,
                stamp,
                &mut actions,
                &mut unchanged,
            ) {
                failures.push(PathFailure {
                    path,
                    message: error.to_string(),
                });
            }
        }

        if take_local {
            lnext = local.walk()?;
        }
        if take_remote {
            rnext = remote.walk()?;
        }
    }

    // Rows whose path is gone from both sides are dropped. Paths that are merely
    // ignored stay: they still exist on disk, so they must not be treated as
    // deletions.
    let mut forgotten = Vec::new();
    archive.for_each(|path, _row| {
        let here = match local.stat(path) {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(PathFailure {
                    path: path.to_path_buf(),
                    message: format!("checking {}: {error}", path.display()),
                });
                return Ok(());
            }
        };
        let there = match remote.stat(path) {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(PathFailure {
                    path: path.to_path_buf(),
                    message: format!("checking {}: {error}", path.display()),
                });
                return Ok(());
            }
        };
        if here.is_none() && there.is_none() {
            forgotten.push(Action::Forget {
                path: path.to_path_buf(),
            });
        }
        Ok(())
    })?;
    actions.extend(forgotten);

    Ok(Plan {
        actions,
        unchanged,
        failures,
    })
}

#[allow(clippy::too_many_arguments)]
fn handle_path(
    path: &Path,
    l: Option<&Entry>,
    r: Option<&Entry>,
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    archive: &Archive,
    opts: &RunOptions,
    label: &str,
    stamp: &str,
    actions: &mut Vec<Action>,
    unchanged: &mut u64,
) -> io::Result<()> {
    let base = archive.get(path)?;

    // Directories carry no content; they exist implicitly around synced files.
    if matches!(l.map(|e| e.kind), Some(Kind::Dir)) || matches!(r.map(|e| e.kind), Some(Kind::Dir))
    {
        if let (Some(le), Some(re)) = (l, r) {
            if le.kind != re.kind {
                actions.push(Action::Skip {
                    path: path.to_path_buf(),
                    reason: "directory and file with the same name",
                });
            }
        }
        return Ok(());
    }
    for entry in [l, r].into_iter().flatten() {
        if entry.kind != Kind::File {
            let reason = match entry.kind {
                Kind::Symlink => "symlink",
                _ => "special file",
            };
            actions.push(Action::Skip {
                path: path.to_path_buf(),
                reason,
            });
            return Ok(());
        }
    }

    let mut lres = match l {
        Some(entry) => Some(resolve_side(
            entry,
            base.as_ref(),
            Side::Local,
            local,
            opts,
        )?),
        None => None,
    };
    let mut rres = match r {
        Some(entry) => Some(resolve_side(
            entry,
            base.as_ref(),
            Side::Remote,
            remote,
            opts,
        )?),
        None => None,
    };

    // In --fast mode hashes are avoided until a decision genuinely needs them.
    if opts.fast && opts.mode == Mode::Sync {
        let both_changed = matches!(
            (lres.as_ref(), rres.as_ref()),
            (Some(a), Some(b)) if a.changed && b.changed
        );
        if both_changed
            && (lres.as_ref().unwrap().hash.is_none() || rres.as_ref().unwrap().hash.is_none())
        {
            lres.as_mut().unwrap().hash = Some(local.hash(path)?);
            rres.as_mut().unwrap().hash = Some(remote.hash(path)?);
        }
    }

    let verdict = match opts.mode.one_way_target() {
        None => classify::two_way(lres.as_ref(), rres.as_ref(), base.as_ref()),
        Some(target) => {
            let source = target.other();
            let (source_res, target_res) = if source == Side::Local {
                (lres.as_ref(), rres.as_ref())
            } else {
                (rres.as_ref(), lres.as_ref())
            };
            classify::one_way(source_res, target_res, target, opts.delete)
        }
    };

    match verdict {
        Verdict::Noop => {
            *unchanged += 1;
            if let Some(row) = adoptable_row(l, r, base.as_ref()) {
                actions.push(Action::Adopt {
                    path: path.to_path_buf(),
                    row,
                });
            }
        }
        Verdict::Adopt => {
            *unchanged += 1;
            if let Some(row) = adoptable_row(l, r, base.as_ref()) {
                actions.push(Action::Adopt {
                    path: path.to_path_buf(),
                    row,
                });
            }
        }
        Verdict::CopyTo(dest) => {
            let source = dest.other();
            actions.push(Action::Copy {
                from: source,
                to: dest,
                path: path.to_path_buf(),
                size: size_on(l, r, source),
                new_file: base.is_none(),
            });
        }
        Verdict::Resurrect(dest) => {
            let source = dest.other();
            actions.push(Action::Resurrect {
                from: source,
                to: dest,
                path: path.to_path_buf(),
                size: size_on(l, r, source),
            });
        }
        Verdict::Conflict => actions.push(Action::Conflict {
            path: path.to_path_buf(),
            copy: conflict_path(path, label, stamp),
            size: size_on(l, r, Side::Remote),
        }),
        Verdict::DeleteAt(side) => actions.push(Action::Delete {
            side,
            path: path.to_path_buf(),
        }),
        Verdict::Skip(reason) => actions.push(Action::Skip {
            path: path.to_path_buf(),
            reason,
        }),
    }
    Ok(())
}

fn resolve_side(
    entry: &Entry,
    base: Option<&BaseRow>,
    side: Side,
    backend: &mut dyn Backend,
    opts: &RunOptions,
) -> io::Result<Resolved> {
    if !opts.checksum {
        if let Some(row) = base {
            if metadata_matches(entry, row, side) {
                return Ok(Resolved {
                    kind: entry.kind,
                    size: entry.size,
                    mtime_ns: entry.mtime_ns,
                    hash: Some(row.hash),
                    changed: false,
                });
            }
            if opts.fast {
                // Metadata moved; --fast accepts that as "changed" without reading
                // the file. Hash equality is never needed to pick a direction
                // except when both sides moved, which the caller handles.
                return Ok(Resolved {
                    kind: entry.kind,
                    size: entry.size,
                    mtime_ns: entry.mtime_ns,
                    hash: None,
                    changed: true,
                });
            }
        }
    }
    let hash = backend.hash(&entry.path)?;
    let changed = match base {
        None => true,
        Some(row) => row.hash != hash || row.kind != entry.kind,
    };
    Ok(Resolved {
        kind: entry.kind,
        size: entry.size,
        mtime_ns: entry.mtime_ns,
        hash: Some(hash),
        changed,
    })
}

fn adoptable_row(l: Option<&Entry>, r: Option<&Entry>, base: Option<&BaseRow>) -> Option<BaseRow> {
    let mut row = base?.clone();
    let mut drifted = false;
    for (entry, side) in [(l, Side::Local), (r, Side::Remote)] {
        let Some(entry) = entry else { continue };
        if entry.mtime_ns != row.mtime(side) {
            row.set_mtime(side, entry.mtime_ns);
            drifted = true;
        }
    }
    drifted.then_some(row)
}

fn size_on(l: Option<&Entry>, r: Option<&Entry>, side: Side) -> u64 {
    match side {
        Side::Local => l.map(|e| e.size).unwrap_or(0),
        Side::Remote => r.map(|e| e.size).unwrap_or(0),
    }
}

fn conflict_path(path: &Path, label: &str, stamp: &str) -> PathBuf {
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
            (stem.to_string(), format!(".{ext}"))
        }
        _ => (name, String::new()),
    };
    parent.join(format!("{stem}.conflict-{stamp}-{label}{ext}"))
}

fn remote_label(remote_root: &Path) -> String {
    remote_root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .filter(|n| !n.is_empty() && n != "/")
        .unwrap_or_else(|| "remote".to_string())
}

pub fn validate_local_root(root: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(root)
        .map_err(|e| io::Error::new(e.kind(), format!("local root {}: {e}", root.display())))?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("local root {} is not a directory", root.display()),
        ));
    }
    if root == Path::new("/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to sync the filesystem root",
        ));
    }
    Ok(())
}

fn validate_roots(local_root: &Path, remote_root: &Path) -> io::Result<()> {
    validate_local_root(local_root)?;
    validate_local_root(remote_root)?;
    let local = fs::canonicalize(local_root)?;
    let remote = fs::canonicalize(remote_root)?;
    if local == remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the two roots are the same directory",
        ));
    }
    if remote.starts_with(&local) || local.starts_with(&remote) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the two roots must not contain each other",
        ));
    }
    Ok(())
}

fn summary_of(plan: &Plan) -> Summary {
    let mut summary = Summary {
        unchanged: plan.unchanged,
        failures: plan.failures.len() as u64,
        ..Default::default()
    };
    for action in &plan.actions {
        match action {
            Action::Copy { new_file, .. } => {
                if *new_file {
                    summary.created += 1
                } else {
                    summary.updated += 1
                }
            }
            Action::Resurrect { .. } => summary.created += 1,
            Action::Delete { .. } | Action::Forget { .. } => summary.deleted += 1,
            Action::Conflict { .. } => summary.conflicts += 1,
            Action::Skip { .. } => summary.skipped += 1,
            Action::Adopt { .. } => {}
        }
    }
    summary
}

/// Apply one planned action. Nothing here is discovered at run time: the plan is
/// the whole story, which is what makes `--dry-run` trustworthy.
#[allow(clippy::too_many_arguments)]
fn apply(
    action: &Action,
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    local_root: &Path,
    archive: &Archive,
    summary: &mut Summary,
    reporter: &mut Reporter<'_>,
    opts: &RunOptions,
    stamp: &str,
) -> io::Result<()> {
    match action {
        Action::Copy {
            from,
            to,
            path,
            size,
            new_file,
        } => {
            // The old version is kept before it is replaced: if the backup
            // cannot be written, the file is left alone.
            backup_before(*to, path, local, remote, opts, stamp)?;
            reporter.transfer_start(path, *from, *to, *size)?;
            let hash = transfer_with_retry(*from, *to, path, remote, local_root, opts)?;
            reporter.transfer_done(path, *from, *to, *size)?;
            record(local, remote, path, hash, archive)?;
            if *new_file {
                summary.created += 1;
            } else {
                summary.updated += 1;
            }
        }
        Action::Resurrect {
            from,
            to,
            path,
            size,
        } => {
            backup_before(*to, path, local, remote, opts, stamp)?;
            reporter.transfer_start(path, *from, *to, *size)?;
            let hash = transfer_with_retry(*from, *to, path, remote, local_root, opts)?;
            reporter.transfer_done(path, *from, *to, *size)?;
            record(local, remote, path, hash, archive)?;
            summary.created += 1;
        }
        Action::Delete { side, path } => {
            backup_before(*side, path, local, remote, opts, stamp)?;
            match side {
                Side::Local => local.remove(path)?,
                Side::Remote => remote.remove(path)?,
            }
            archive.delete(path)?;
            summary.deleted += 1;
        }
        Action::Conflict { path, copy, .. } => {
            // The remote's file at this name is about to be replaced by the
            // local one; the other version is kept under the conflict name.
            backup_before(Side::Remote, path, local, remote, opts, stamp)?;
            let local_original = local_root.join(path);
            let local_copy = local_root.join(copy);

            // The local version wins the original name; the other side's version
            // is preserved under the conflict name. Both sides end up with both.
            let loser = remote.get(path, &local_copy, false)?;
            let winner = remote.put(path, &local_original, false)?;
            remote.put(copy, &local_copy, false)?;

            record(local, remote, path, winner, archive)?;
            record(local, remote, copy, loser, archive)?;
            summary.conflicts += 1;
        }
        Action::Adopt { path, row } => {
            archive.put(path, row)?;
        }
        Action::Forget { path } => {
            archive.delete(path)?;
            summary.deleted += 1;
        }
        Action::Skip { .. } => {
            summary.skipped += 1;
        }
    }
    Ok(())
}

/// Keep the version that is about to be replaced or removed.
fn backup_before(
    side: Side,
    path: &Path,
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    opts: &RunOptions,
    stamp: &str,
) -> io::Result<()> {
    let Some(dir) = opts.backup_dir.as_ref() else {
        return Ok(());
    };
    backup::take(side, path, local, remote, dir, stamp)?;
    Ok(())
}

fn transfer(
    from: Side,
    to: Side,
    path: &Path,
    remote: &mut dyn Backend,
    local_root: &Path,
    resume: bool,
) -> io::Result<Hash> {
    match (from, to) {
        // The local file is named by its absolute path on this machine.
        (Side::Local, Side::Remote) => remote.put(path, &local_root.join(path), resume),
        (Side::Remote, Side::Local) => remote.get(path, &local_root.join(path), resume),
        (side, _) => Err(io::Error::other(format!(
            "cannot copy from the {} side to itself",
            side.name()
        ))),
    }
}

/// A file whose content does not verify is worth one more try: the transfer
/// starts over from the beginning. A second failure fails the file, and the
/// other files carry on.
fn transfer_with_retry(
    from: Side,
    to: Side,
    path: &Path,
    remote: &mut dyn Backend,
    local_root: &Path,
    opts: &RunOptions,
) -> io::Result<Hash> {
    crate::fsutil::retry_once(&path.display().to_string(), || {
        transfer(from, to, path, remote, local_root, opts.partial)
    })
}

/// Both sides now agree; remember what they agree on. The hash is the one the
/// transfer verified in transit, so nothing is re-read to compute it.
fn record(
    local: &mut dyn Backend,
    remote: &mut dyn Backend,
    path: &Path,
    hash: Hash,
    archive: &Archive,
) -> io::Result<()> {
    let here = local.stat(path)?;
    let there = remote.stat(path)?;
    let (Some(here), Some(there)) = (here, there) else {
        return Err(io::Error::other(
            "a transfer finished but one side does not have the file",
        ));
    };
    if here.size != there.size {
        return Err(io::Error::other(format!(
            "the two sides disagree about the size of {} after transferring it",
            path.display()
        )));
    }
    archive.put(
        path,
        &BaseRow {
            kind: Kind::File,
            size: here.size,
            mtime_local: here.mtime_ns,
            mtime_remote: there.mtime_ns,
            hash,
        },
    )
}
