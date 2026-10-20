use clap::{Args, Parser, Subcommand};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use twin::engine::{End, RunOptions};
use twin::remote::RemoteOptions;
use twin::tls;

#[derive(Parser)]
#[command(
    name = "twin",
    version,
    about = "Copy a directory to another one: a local path, or a host:port served over mutual TLS."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Copy the source to the destination. The source always wins.
    Sync(PairArgs),
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
    /// Where the content comes from: a directory, or the host:port of a `twin serve`
    source: String,
    /// Where the content goes: a directory, or the host:port of a `twin serve`
    destination: String,
    #[arg(long)]
    dry_run: bool,
    /// Remove the paths the source does not have
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

fn main() -> ExitCode {
    let cli = Cli::parse();

    twin::log::set_level_from_env();

    match cli.command {
        Command::Id => print_id(),
        Command::Authorize { fingerprint } => authorize(&fingerprint),
        Command::Serve(args) => serve(&args),
        Command::Doctor(args) => doctor(&args),
        Command::Sync(args) => sync(args),
    }
}

/// Copy the source to the destination.
///
/// The order of the two arguments is the direction of the copy: the content
/// flows from the first to the second, and only the second is written.
fn sync(args: PairArgs) -> ExitCode {
    if args.verbose > 0 {
        twin::log::set_level(if args.verbose > 1 {
            twin::log::DEBUG
        } else {
            twin::log::INFO
        });
    }

    let source = match parse_spec(&args.source) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let destination = match parse_spec(&args.destination) {
        Ok(spec) => spec,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };

    if source.is_remote() && destination.is_remote() {
        eprintln!("error: one side must be a directory on this machine; both look like addresses");
        return ExitCode::from(2);
    }

    // A remote needs a pinned certificate: explicit on first contact, remembered after.
    let remote = source.remote().or_else(|| destination.remote());
    let pin = match remote {
        None => None,
        Some(remote) => match resolve_pin(remote, args.pin.as_deref()) {
            Ok(pin) => Some(pin),
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        },
    };

    let mut options = RunOptions {
        dry_run: args.dry_run,
        delete: args.delete,
        force: args.force,
        auto: args.auto,
        checksum: args.checksum,
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

    let summary = match twin::engine::run(&source, &destination, pin.as_deref(), &options, &mut out)
    {
        Ok(summary) => summary,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };

    // A pin that worked is remembered, so the next run needs no flags.
    if let (Some(remote), Some(pin)) = (remote, &pin) {
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
                match twin::engine::run(&source, &destination, pin.as_deref(), &options, &mut out) {
                    Ok(summary) => return exit_for(&summary, options.dry_run),
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

    exit_for(&summary, options.dry_run)
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
            "no pinned certificate for {label} yet.\n\
             On the server run `twin id` and pass what it prints:\n  \
             twin sync <source> {label} --pin <fingerprint>",
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
            Ok(End::Remote(remote)) => remote,
            Ok(End::Local(_)) => {
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

fn exit_for(summary: &twin::Summary, dry_run: bool) -> ExitCode {
    if dry_run {
        // A dry run is a report, not a decision: it succeeds even when the
        // plan holds deletions. Files that failed are still failures.
        return ExitCode::from(if summary.failures > 0 { 4 } else { 0 });
    }
    ExitCode::from(summary.exit_code().code() as u8)
}

fn parse_spec(spec: &str) -> Result<End, String> {
    if Path::new(spec).exists() {
        return Ok(End::Local(PathBuf::from(spec)));
    }
    if let Some((host, port)) = spec.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if !host.is_empty() {
                return Ok(End::Remote(RemoteOptions {
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
