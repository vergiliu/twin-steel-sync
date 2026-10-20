use crate::archive::{archive_path, Archive};
use crate::backup;
use crate::classify::{self, Resolved, Verdict};
use crate::fsutil::{timestamp_utc, ErrCtx};
use crate::model::{
    cmp_path, metadata_matches, Action, BaseRow, Entry, Hash, Kind, PathFailure, Role,
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

/// One end of a run: a directory on this machine, or a peer on another machine.
#[derive(Debug, Clone)]
pub enum End {
    Local(PathBuf),
    Remote(RemoteOptions),
}

impl End {
    pub fn is_remote(&self) -> bool {
        matches!(self, End::Remote(_))
    }

    pub fn remote(&self) -> Option<&RemoteOptions> {
        match self {
            End::Remote(remote) => Some(remote),
            End::Local(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub dry_run: bool,
    /// Remove the paths the source does not have.
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
    Partial,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Ok => 0,
            ExitCode::Failed => 1,
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

/// Copy the source's content to the destination.
///
/// The content always flows from the source to the destination: the source is
/// read and never written, the destination is written and never read for
/// anything but the comparison. One of the two ends is a directory on this
/// machine; the other may be a peer reached over mutual TLS.
pub fn run(
    source: &End,
    destination: &End,
    pin: Option<&str>,
    opts: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<Summary> {
    match (source, destination) {
        (End::Remote(_), End::Remote(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "one side must be a directory on this machine; both look like addresses",
        )),
        (End::Local(source), End::Local(destination)) => {
            validate_roots(source, destination)?;
            let (rules, _) = rules_for(source, opts)?;
            let mut source_side =
                LocalBackend::excluding(source, rules.clone(), excluded_dirs(opts))?;
            let mut destination_side =
                LocalBackend::excluding(destination, rules, excluded_dirs(opts))?;
            run_pair(&mut source_side, &mut destination_side, opts, out)
        }
        (End::Local(source), End::Remote(remote)) => {
            validate_local_root(source)?;
            let (rules, patterns) = rules_for(source, opts)?;
            let mut remote = connect(remote, pin, opts, &patterns)?;
            let mut source_side = LocalBackend::excluding(source, rules, excluded_dirs(opts))?;
            let outcome = run_pair(&mut source_side, &mut remote, opts, out);
            let closed = remote.finish();
            outcome.and_then(|summary| closed.map(|()| summary))
        }
        (End::Remote(remote), End::Local(destination)) => {
            validate_local_root(destination)?;
            let (rules, patterns) = rules_for(destination, opts)?;
            let mut remote = connect(remote, pin, opts, &patterns)?;
            let mut destination_side =
                LocalBackend::excluding(destination, rules, excluded_dirs(opts))?;
            let outcome = run_pair(&mut remote, &mut destination_side, opts, out);
            let closed = remote.finish();
            outcome.and_then(|summary| closed.map(|()| summary))
        }
    }
}

/// The ignore rules, taken from the end that is on this machine: the same
/// rules then apply to both ends, and the peer is told about them.
fn rules_for(root: &Path, opts: &RunOptions) -> io::Result<(IgnoreRules, Vec<String>)> {
    let patterns = patterns_for(root, &opts.excludes)?;
    let rules = IgnoreRules::from_patterns(root, opts.default_ignores, &patterns)?;
    Ok((rules, patterns))
}

fn connect(
    remote: &RemoteOptions,
    pin: Option<&str>,
    opts: &RunOptions,
    patterns: &[String],
) -> io::Result<RemoteBackend> {
    let pin = pin.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a remote side needs the fingerprint of the certificate it must present",
        )
    })?;
    let identity = tls::Identity::load_or_create(&tls::data_dir())?;
    RemoteBackend::connect(remote, &identity, pin, opts.default_ignores, patterns)
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

fn run_pair(
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    opts: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<Summary> {
    let source_label = source.label().to_string();
    let destination_label = destination.label().to_string();
    crate::debug!(
        "sync {source_label} -> {destination_label}, archive {}",
        opts.archive_dir.display()
    );
    let archive = Archive::open(&archive_path(
        &opts.archive_dir,
        &source_label,
        &destination_label,
    ))
    .ctx(|| format!("opening the archive in {}", opts.archive_dir.display()))?;
    let first_run = archive.is_empty()?;
    let tracked = if first_run { 0 } else { archive.count()? };
    crate::debug!(
        "archive holds {tracked} tracked paths{}",
        if first_run { " (new pair)" } else { "" }
    );

    let stamp = timestamp_utc();
    let mut reporter = Reporter::new(out, opts, &source_label, &destination_label);
    let plan = build_plan(source, destination, &archive, opts)?;

    // The JSON stream starts with the plan: it is what the run intends to do,
    // before anything is attempted.
    if opts.json {
        reporter.plan(&plan.actions)?;
        reporter.skip_events(&plan.actions)?;
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
        .filter(|a| matches!(a, Action::Delete { .. }))
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
        .filter(|a| !matches!(a, Action::Skip { .. } | Action::Adopt { .. }))
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
            source,
            destination,
            &archive,
            &mut summary,
            &mut reporter,
            opts,
            &stamp,
        ) {
            Ok(()) => {}
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
            Action::Copy { size, .. } => *size,
            _ => 0,
        })
        .sum()
}

fn build_plan(
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    archive: &Archive,
    opts: &RunOptions,
) -> io::Result<Plan> {
    let mut actions = Vec::new();
    let mut unchanged = 0u64;
    let mut failures: Vec<PathFailure> = Vec::new();

    let mut snext = source.walk()?;
    let mut dnext = destination.walk()?;

    loop {
        let (take_source, take_destination) = match (&snext, &dnext) {
            (None, None) => break,
            (Some(Ok(s)), Some(Ok(d))) => match cmp_path(&s.path, &d.path) {
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
        let s = if take_source { snext.take() } else { None };
        let d = if take_destination { dnext.take() } else { None };

        let mut s_entry: Option<Entry> = None;
        let mut d_entry: Option<Entry> = None;
        match s {
            Some(Ok(entry)) => s_entry = Some(entry),
            Some(Err(failure)) => failures.push(failure),
            None => {}
        }
        match d {
            Some(Ok(entry)) => d_entry = Some(entry),
            Some(Err(failure)) => failures.push(failure),
            None => {}
        }

        let path = s_entry
            .as_ref()
            .or(d_entry.as_ref())
            .map(|entry| entry.path.clone());
        if let Some(path) = path {
            // One path that cannot be planned must not stop the others.
            if let Err(error) = handle_path(
                &path,
                s_entry.as_ref(),
                d_entry.as_ref(),
                source,
                destination,
                archive,
                opts,
                &mut actions,
                &mut unchanged,
            ) {
                failures.push(PathFailure {
                    path,
                    message: error.to_string(),
                });
            }
        }

        if take_source {
            snext = source.walk()?;
        }
        if take_destination {
            dnext = destination.walk()?;
        }
    }

    // Rows whose path is gone from both ends are dropped. Paths that are merely
    // ignored stay: they still exist on disk, so they must not be treated as
    // deletions.
    let mut forgotten = Vec::new();
    archive.for_each(|path, _row| {
        let here = match source.stat(path) {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(PathFailure {
                    path: path.to_path_buf(),
                    message: format!("checking {}: {error}", path.display()),
                });
                return Ok(());
            }
        };
        // The source still has it: the pair still tracks it.
        if here.is_some() {
            return Ok(());
        }
        let there = match destination.stat(path) {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(PathFailure {
                    path: path.to_path_buf(),
                    message: format!("checking {}: {error}", path.display()),
                });
                return Ok(());
            }
        };
        if there.is_none() {
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
    s: Option<&Entry>,
    d: Option<&Entry>,
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    archive: &Archive,
    opts: &RunOptions,
    actions: &mut Vec<Action>,
    unchanged: &mut u64,
) -> io::Result<()> {
    let base = archive.get(path)?;

    // Directories carry no content; they exist implicitly around synced files.
    if matches!(s.map(|e| e.kind), Some(Kind::Dir)) || matches!(d.map(|e| e.kind), Some(Kind::Dir))
    {
        if let (Some(se), Some(de)) = (s, d) {
            if se.kind != de.kind {
                actions.push(Action::Skip {
                    path: path.to_path_buf(),
                    reason: "directory and file with the same name",
                });
            }
        }
        return Ok(());
    }
    for entry in [s, d].into_iter().flatten() {
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

    let sres = match s {
        Some(entry) => Some(resolve(entry, base.as_ref(), Role::Source, source, opts)?),
        None => None,
    };
    let dres = match d {
        Some(entry) => Some(resolve(
            entry,
            base.as_ref(),
            Role::Destination,
            destination,
            opts,
        )?),
        None => None,
    };

    let verdict = classify::decide(sres.as_ref(), dres.as_ref(), base.as_ref(), opts.delete);

    match verdict {
        Verdict::Noop => {
            *unchanged += 1;
            if let Some(row) = adoptable_row(s, d, base.as_ref()) {
                actions.push(Action::Adopt {
                    path: path.to_path_buf(),
                    row,
                });
            }
        }
        Verdict::Adopt => {
            *unchanged += 1;
            // The verdict is only reached when both ends hold the same content,
            // so the hash is known and the row can be written.
            let (Some(se), Some(de), Some(hash)) = (s, d, sres.as_ref().and_then(|r| r.hash))
            else {
                return Ok(());
            };
            actions.push(Action::Adopt {
                path: path.to_path_buf(),
                row: BaseRow {
                    kind: se.kind,
                    size: se.size,
                    hash,
                    mtime_source: se.mtime_ns,
                    mtime_destination: de.mtime_ns,
                },
            });
        }
        Verdict::Copy => {
            actions.push(Action::Copy {
                path: path.to_path_buf(),
                size: s.map(|e| e.size).unwrap_or(0),
                new_file: d.is_none(),
            });
        }
        Verdict::Delete => actions.push(Action::Delete {
            path: path.to_path_buf(),
        }),
        Verdict::Skip(reason) => actions.push(Action::Skip {
            path: path.to_path_buf(),
            reason,
        }),
    }
    Ok(())
}

/// What this end holds right now, and whether it still holds what the pair
/// agreed on.
fn resolve(
    entry: &Entry,
    base: Option<&BaseRow>,
    role: Role,
    backend: &mut dyn Backend,
    opts: &RunOptions,
) -> io::Result<Resolved> {
    if !opts.checksum {
        if let Some(row) = base {
            if metadata_matches(entry, row, role) {
                return Ok(Resolved {
                    hash: Some(row.hash),
                    changed: false,
                });
            }
            if opts.fast {
                // Metadata moved; --fast accepts that as "changed" without reading
                // the file. Hash equality is never needed to pick a direction:
                // the source always wins.
                return Ok(Resolved {
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
        hash: Some(hash),
        changed,
    })
}

/// The archive row as it should be written when the two ends already agree.
fn adoptable_row(s: Option<&Entry>, d: Option<&Entry>, base: Option<&BaseRow>) -> Option<BaseRow> {
    let mut row = base?.clone();
    let mut drifted = false;
    if let Some(entry) = s {
        if entry.mtime_ns != row.mtime_source {
            row.mtime_source = entry.mtime_ns;
            drifted = true;
        }
    }
    if let Some(entry) = d {
        if entry.mtime_ns != row.mtime_destination {
            row.mtime_destination = entry.mtime_ns;
            drifted = true;
        }
    }
    drifted.then_some(row)
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

fn validate_roots(source: &Path, destination: &Path) -> io::Result<()> {
    validate_local_root(source)?;
    validate_local_root(destination)?;
    let source = fs::canonicalize(source)?;
    let destination = fs::canonicalize(destination)?;
    if source == destination {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the source and the destination are the same directory",
        ));
    }
    if destination.starts_with(&source) || source.starts_with(&destination) {
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
            Action::Delete { .. } => summary.deleted += 1,
            Action::Skip { .. } => summary.skipped += 1,
            Action::Forget { .. } | Action::Adopt { .. } => {}
        }
    }
    summary
}

/// Apply one planned action. Nothing here is discovered at run time: the plan is
/// the whole story, which is what makes `--dry-run` trustworthy.
#[allow(clippy::too_many_arguments)]
fn apply(
    action: &Action,
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    archive: &Archive,
    summary: &mut Summary,
    reporter: &mut Reporter<'_>,
    opts: &RunOptions,
    stamp: &str,
) -> io::Result<()> {
    match action {
        Action::Copy {
            path,
            size,
            new_file,
        } => {
            // The old version is kept before it is replaced: if the backup
            // cannot be written, the file is left alone.
            backup_before(destination, path, opts, stamp)?;
            reporter.transfer_start(path, *size)?;
            let hash = transfer_with_retry(source, destination, path, opts)?;
            reporter.transfer_done(path, *size)?;
            record(source, destination, path, hash, archive)?;
            if *new_file {
                summary.created += 1;
            } else {
                summary.updated += 1;
            }
        }
        Action::Delete { path } => {
            backup_before(destination, path, opts, stamp)?;
            destination.remove(path)?;
            archive.delete(path)?;
            summary.deleted += 1;
        }
        Action::Adopt { path, row } => {
            archive.put(path, row)?;
        }
        Action::Forget { path } => {
            archive.delete(path)?;
        }
        Action::Skip { .. } => {
            summary.skipped += 1;
        }
    }
    Ok(())
}

/// Keep the version that is about to be replaced or removed.
fn backup_before(
    destination: &mut dyn Backend,
    path: &Path,
    opts: &RunOptions,
    stamp: &str,
) -> io::Result<()> {
    let Some(dir) = opts.backup_dir.as_ref() else {
        return Ok(());
    };
    backup::take(destination, path, dir, stamp)?;
    Ok(())
}

/// Move the content of one path from the source to the destination.
///
/// The content always travels through this machine: the source is a directory
/// here, or a peer that is asked for the bytes. The destination is written
/// atomically by the side that owns it.
fn transfer(
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    path: &Path,
    resume: bool,
) -> io::Result<Hash> {
    match source.local_root() {
        Some(root) => destination.put(path, &root.join(path), resume),
        None => {
            let root = destination.local_root().ok_or_else(|| {
                io::Error::other("the source and the destination cannot both be on another machine")
            })?;
            source.get(path, &root.join(path), resume)
        }
    }
}

/// A file whose content does not verify is worth one more try: the transfer
/// starts over from the beginning. A second failure fails the file, and the
/// other files carry on.
fn transfer_with_retry(
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    path: &Path,
    opts: &RunOptions,
) -> io::Result<Hash> {
    crate::fsutil::retry_once(&path.display().to_string(), || {
        transfer(source, destination, path, opts.partial)
    })
}

/// The two ends now agree; remember what they agree on. The hash is the one the
/// transfer verified in transit, so nothing is re-read to compute it.
fn record(
    source: &mut dyn Backend,
    destination: &mut dyn Backend,
    path: &Path,
    hash: Hash,
    archive: &Archive,
) -> io::Result<()> {
    let here = source.stat(path)?;
    let there = destination.stat(path)?;
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
            mtime_source: here.mtime_ns,
            mtime_destination: there.mtime_ns,
            hash,
        },
    )
}
