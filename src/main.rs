use clap::{Args, Parser, Subcommand};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use twin::engine::{run, run_tls, Mode, RunOptions};
use twin::remote::RemoteOptions;
use twin::tls;

#[derive(Parser)]
#[command(
    name = "twin",
    version,
    about = "Make two directories equal. One side is local; the other is a local path, or a host:port served over mutual TLS."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Two-way: both sides converge, conflicts keep both versions
    Sync(PairArgs),
    /// One-way: copy the local directory to the other side
    Push(PairArgs),
    /// One-way: copy the other side into the local directory
    Pull(PairArgs),
    /// Compare by content and report differences; writes nothing.
    /// Exits 0 when the two sides agree and 3 when they differ — unlike
    /// --dry-run, which always exits 0.
    Verify(PairArgs),
    /// Show this machine's fingerprint, creating its key on first use
    Id,
    /// Let a client fingerprint connect to this machine's server
    Authorize {
        /// The 64 hex characters printed by `twin id` on the client
        fingerprint: String,
    },
    /// Serve one directory to authorized clients over mutual TLS
    Serve(ServeArgs),
    /// Check everything a sync depends on here, and report what is wrong
    Doctor(DoctorArgs),
}

#[derive(Args)]
struct DoctorArgs {
    /// Directory to probe as a sync root (defaults to the current directory)
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    /// Also check a server, as host:port
    #[arg(long, value_name = "ADDR")]
    remote: Option<String>,
    /// Certificate fingerprint that server must present
    #[arg(long, value_name = "HEX")]
    pin: Option<String>,
}

#[derive(Args)]
struct ServeArgs {
    /// Directory to serve; nothing outside it is ever touched
    #[arg(long, value_name = "DIR")]
    root: PathBuf,
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:9443")]
    listen: String,
    /// Serve a single connection, then exit
    #[arg(long)]
    once: bool,
}

#[derive(Args)]
struct PairArgs {
    /// Local directory, or the host:port of a `twin serve`
    left: String,
    /// Local directory, or the host:port of a `twin serve`
    right: String,
    #[arg(long)]
    dry_run: bool,
    /// One-way only: remove paths the source does not have
    #[arg(long)]
    delete: bool,
    /// Override the mass-delete guard
    #[arg(long)]
    force: bool,
    /// Consent to the first run of a new pair without asking
    #[arg(long)]
    auto: bool,
    /// Hash every tracked file instead of trusting size and mtime
    #[arg(long)]
    checksum: bool,
    /// Trust size and mtime; never hash unless a decision needs it
    #[arg(long)]
    fast: bool,
    #[arg(long)]
    no_default_ignores: bool,
    /// Extra ignore pattern (repeatable)
    #[arg(long = "exclude", value_name = "PAT")]
    excludes: Vec<String>,
    #[arg(long, value_name = "DIR")]
    archive_dir: Option<PathBuf>,
    /// Keep the version that is about to be replaced or removed in DIR
    #[arg(long, value_name = "DIR")]
    backup: Option<PathBuf>,
    /// Report as one JSON object per line instead of in prose
    #[arg(long)]
    json: bool,
    /// Keep an interrupted transfer and continue it on the next run
    #[arg(long)]
    partial: bool,
    /// Certificate fingerprint the server must present (needed the first time you
    /// talk to a host; it is remembered afterwards)
    #[arg(long, value_name = "HEX")]
    pin: Option<String>,
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
    #[arg(long, short = 'q')]
    quiet: bool,
}

enum Spec {
    Local(PathBuf),
    Remote(RemoteOptions),
}

enum Target {
    Local(PathBuf),
    Remote(RemoteOptions),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    twin::log::set_level_from_env();

    match cli.command {
        Command::Id => return print_id(),
        Command::Authorize { fingerprint } => return authorize(&fingerprint),
        Command::Serve(args) => return serve(&args),
        Command::Doctor(args) => return doctor(&args),
        _ => {}
    }

    let (args, mode, is_verify) = match cli.command {
        Command::Sync(args) => (args, Mode::Sync, false),
        Command::Push(args) => (args, Mode::Push, false),
        Command::Pull(args) => (args, Mode::Pull, false),
        Command::Verify(args) => (args, Mode::Sync, true),
        _ => unreachable!("handled above"),
    };

    if args.verbose > 0 {
        twin::log::set_level(if args.verbose > 1 {
            twin::log::DEBUG
        } else {
            twin::log::INFO
        });
    }

    let mut left = match parse_spec(&args.left) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let mut right = match parse_spec(&args.right) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    // The local side is whatever is not remote. Which argument came first only
    // says which side is which: `push` always means local -> other, `pull` always
    // means other -> local, whatever the order on the command line.
    if matches!(left, Spec::Remote(_)) && matches!(right, Spec::Local(_)) {
        std::mem::swap(&mut left, &mut right);
    }

    let (local_root, target) = match (left, right) {
        (Spec::Local(root), Spec::Local(other)) => (root, Target::Local(other)),
        (Spec::Local(root), Spec::Remote(remote)) => (root, Target::Remote(remote)),
        (Spec::Remote(_), Spec::Remote(_)) => {
            eprintln!("error: one side must be local; both look like addresses");
            return ExitCode::from(2);
        }
        (Spec::Remote(_), Spec::Local(_)) => unreachable!("swapped above"),
    };

    // A remote needs a pinned certificate: explicit on first contact, remembered after.
    let pin = match &target {
        Target::Local(_) => None,
        Target::Remote(remote) => match resolve_pin(remote, args.pin.as_deref()) {
            Ok(pin) => Some(pin),
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        },
    };

    let mut options = RunOptions {
        mode,
        dry_run: args.dry_run || is_verify,
        delete: args.delete,
        force: args.force,
        auto: args.auto,
        checksum: args.checksum || is_verify,
        fast: args.fast,
        default_ignores: !args.no_default_ignores,
        excludes: args.excludes,
        json: args.json,
        partial: args.partial,
        tty: io::stderr().is_terminal(),
        verbose: args.verbose > 0,
        quiet: args.quiet,
        ..Default::default()
    };
    if let Some(dir) = args.archive_dir {
        options.archive_dir = dir;
    }
    options.backup_dir = args.backup.clone();

    let stdout = io::stdout();
    let mut out = stdout.lock();

    let summary = match run_target(&local_root, &target, pin.as_deref(), &options, &mut out) {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };

    // A pin that worked is remembered, so the next run needs no flags.
    if let (Target::Remote(remote), Some(pin)) = (&target, &pin) {
        if let Err(error) = tls::write_pin(&tls::data_dir(), &remote.host, remote.port, pin) {
            eprintln!("warning: could not remember the pin: {error}");
        }
    }

    if summary.needs_consent {
        if !io::stdin().is_terminal() {
            eprintln!("error: refusing to change a new pair without --auto");
            return ExitCode::from(2);
        }
        match ask_to_proceed() {
            Ok(true) => {
                options.auto = true;
                match run_target(&local_root, &target, pin.as_deref(), &options, &mut out) {
                    Ok(summary) => {
                        return exit_for(&summary, is_verify, options.dry_run, options.json)
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        return ExitCode::from(1);
                    }
                }
            }
            Ok(false) => {
                if options.json {
                    eprintln!("nothing done");
                } else {
                    println!("nothing done");
                }
                return ExitCode::from(0);
            }
            Err(error) => {
                eprintln!("error: {error}");
                return ExitCode::from(1);
            }
        }
    }

    exit_for(&summary, is_verify, options.dry_run, options.json)
}

fn run_target(
    local_root: &Path,
    target: &Target,
    pin: Option<&str>,
    options: &RunOptions,
    out: &mut dyn Write,
) -> io::Result<twin::Summary> {
    match target {
        Target::Local(other) => run(local_root, other, options, out),
        Target::Remote(remote) => {
            let pin = pin.expect("a remote target always has a pin by the time it is used");
            run_tls(local_root, remote, pin, options, out)
        }
    }
}

fn resolve_pin(remote: &RemoteOptions, given: Option<&str>) -> Result<String, String> {
    if let Some(pin) = given {
        let normalized = tls::normalize_fingerprint(pin);
        if normalized.len() != 64 {
            return Err(format!(
                "--pin needs the 64 hex characters printed by `twin id` on the server; got {} of them",
                normalized.len()
            ));
        }
        return Ok(normalized);
    }
    match tls::read_pin(&tls::data_dir(), &remote.host, remote.port) {
        Ok(Some(pin)) => Ok(pin),
        Ok(None) => Err(format!(
            "no pinned certificate for {} yet.\n\
             On the server run `twin id` and pass what it prints:\n  \
             twin <verb> {local} {label} --pin <fingerprint>",
            remote.label(),
            local = "<local dir>",
            label = remote.label()
        )),
        Err(error) => Err(format!("cannot read the pinned certificates: {error}")),
    }
}

fn print_id() -> ExitCode {
    match tls::Identity::load_or_create(&tls::data_dir()) {
        Ok(identity) => {
            println!("{}", identity.fingerprint());
            eprintln!("certificate: {}", identity.cert_path().display());
            eprintln!("private key: {}", identity.key_path().display());
            ExitCode::from(0)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn authorize(fingerprint: &str) -> ExitCode {
    match tls::add_authorized(&tls::data_dir(), fingerprint) {
        Ok(list) => {
            println!("authorized ({} total)", list.len());
            for entry in list {
                println!("  {entry}");
            }
            println!("takes effect on the next connection; the server needs no restart");
            ExitCode::from(0)
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn serve(args: &ServeArgs) -> ExitCode {
    if let Err(error) = twin::engine::validate_local_root(&args.root) {
        eprintln!("error: {error}");
        return ExitCode::from(1);
    }
    let data_dir = tls::data_dir();
    let identity = match tls::Identity::load_or_create(&data_dir) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    let list_path = tls::authorized_path(&data_dir);
    let allowed = match tls::read_list(&list_path) {
        Ok(list) => list,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    // The list is shared with the certificate verifier and read back from disk
    // before every connection, so `twin authorize` takes effect right away.
    let allowed = tls::allow_list(allowed);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match tls::serve_forever(
        &args.root,
        &identity,
        &allowed,
        &list_path,
        &args.listen,
        args.once,
        &mut out,
    ) {
        Ok(()) => ExitCode::from(0),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn doctor(args: &DoctorArgs) -> ExitCode {
    let root = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let mut checks = twin::doctor::environment(Some(&root));

    if let Some(spec) = &args.remote {
        let remote = match parse_spec(spec) {
            Ok(Spec::Remote(remote)) => remote,
            Ok(Spec::Local(_)) => {
                eprintln!("error: {spec} is a local path; --remote wants host:port");
                return ExitCode::from(2);
            }
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        };
        match resolve_pin(&remote, args.pin.as_deref()) {
            Ok(pin) => checks.extend(twin::doctor::remote(&remote, &pin)),
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        }
    }

    if let Ok(identity) = tls::Identity::load_or_create(&tls::data_dir()) {
        let _ = identity;
    }
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match twin::doctor::report(&checks, &mut out) {
        Ok(0) => ExitCode::from(0),
        Ok(_) => ExitCode::from(1),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn exit_for(summary: &twin::Summary, is_verify: bool, dry_run: bool, json: bool) -> ExitCode {
    if is_verify {
        // `twin verify` keeps its own contract: 0 when the two sides agree, 3
        // when they differ. A dry run of the other verbs exits 0 instead.
        let differences = summary.created + summary.updated + summary.deleted + summary.conflicts;
        if differences > 0 {
            if !json {
                println!("{differences} paths differ");
            }
            return ExitCode::from(3);
        }
        if !json {
            println!("in sync");
        }
        return ExitCode::from(0);
    }
    if dry_run {
        // A dry run is a report, not a decision: it succeeds even when the
        // plan holds conflicts. Files that failed are still failures.
        return ExitCode::from(if summary.failures > 0 { 4 } else { 0 });
    }
    ExitCode::from(summary.exit_code().code() as u8)
}

fn parse_spec(spec: &str) -> Result<Spec, String> {
    if Path::new(spec).exists() {
        return Ok(Spec::Local(PathBuf::from(spec)));
    }
    if let Some((host, port)) = spec.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if !host.is_empty() {
                return Ok(Spec::Remote(RemoteOptions {
                    host: host.to_string(),
                    port,
                }));
            }
        }
    }
    Err(format!(
        "{spec}: no such directory, and it does not look like host:port"
    ))
}

fn ask_to_proceed() -> io::Result<bool> {
    print!("proceed? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
