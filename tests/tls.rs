//! End-to-end tests for the mutual-TLS transport: a real `twin serve` process on
//! loopback, a real client binary, real certificates. Nothing is mocked.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

/// Run a twin command with its own data directory (identity, pins, archive).
fn client(data: &Path) -> Command {
    let mut command = Command::new(binary());
    command.env("TWIN_DATA_DIR", data);
    command
}

fn run(command: &mut Command) -> (i32, String) {
    let output = command.output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

/// The fingerprint of the identity in this data directory.
fn fingerprint_of(data: &Path) -> String {
    twin::tls::Identity::load_or_create(data)
        .expect("the identity must be creatable")
        .fingerprint()
        .to_string()
}

struct Server {
    child: Child,
    addr: String,
    fingerprint: String,
    _reader: BufReader<std::process::ChildStdout>,
}

impl Server {
    fn start(root: &Path, data: &Path) -> Server {
        let mut child = Command::new(binary())
            .arg("serve")
            .arg("--root")
            .arg(root)
            .args(["--listen", "127.0.0.1:0"])
            .env("TWIN_DATA_DIR", data)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut addr = String::new();
        let mut fingerprint = String::new();
        for _ in 0..4 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if let Some(rest) = line.strip_prefix("listening on ") {
                addr = rest.trim().to_string();
            }
            if let Some(rest) = line.strip_prefix("serving ") {
                if let Some((_, fp)) = rest.rsplit_once(" as ") {
                    fingerprint = fp.trim().to_string();
                }
            }
            if !addr.is_empty() && !fingerprint.is_empty() {
                break;
            }
        }
        Server {
            child,
            addr,
            fingerprint,
            _reader: reader,
        }
    }

    fn spec(&self) -> &str {
        &self.addr
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    client_data: PathBuf,
}

impl Fixture {
    /// A server that authorizes this client, plus a paired client.
    fn new() -> (Fixture, Server) {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let remote = root.path().join("remote");
        let server_data = root.path().join("server-data");
        let client_data = root.path().join("client-data");
        for dir in [&local, &remote, &server_data, &client_data] {
            fs::create_dir_all(dir).unwrap();
        }

        let client_fp = fingerprint_of(&client_data);
        let (code, output) = run(client(&server_data).arg("authorize").arg(&client_fp));
        assert_eq!(code, 0, "authorize must work: {output}");

        let server = Server::start(&remote, &server_data);
        assert!(
            !server.addr.is_empty(),
            "the server must announce where it listens"
        );
        (
            Fixture {
                _root: root,
                local,
                remote,
                client_data,
            },
            server,
        )
    }

    fn write(&self, side: &Path, rel: &str, contents: &str) {
        let path = side.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// Copy the client's directory to the server: the local side is the
    /// source, the server the destination.
    fn local_to_server(&self, server: &Server, extra: &[&str]) -> (i32, String) {
        let spec = server.spec().to_string();
        let mut command = client(&self.client_data);
        command
            .arg("sync")
            .arg(&self.local)
            .arg(&spec)
            .arg("--pin")
            .arg(&server.fingerprint)
            .args(extra);
        run(&mut command)
    }

    /// Copy the server's directory to the client: the server is the source,
    /// the local side the destination.
    fn server_to_local(&self, server: &Server, extra: &[&str]) -> (i32, String) {
        let spec = server.spec().to_string();
        let mut command = client(&self.client_data);
        command
            .arg("sync")
            .arg(&spec)
            .arg(&self.local)
            .arg("--pin")
            .arg(&server.fingerprint)
            .args(extra);
        run(&mut command)
    }
}

#[test]
fn a_tree_travels_over_mutual_tls_and_settles() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "notes/a.txt", "hello");
    fixture.write(&fixture.local, "deep/b.bin", "0123456789");

    let (code, output) = fixture.local_to_server(&server, &["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("notes/a.txt")).unwrap(),
        "hello"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join("deep/b.bin")).unwrap(),
        "0123456789"
    );

    // mtimes travelled, so the second run has nothing left to do
    let local_meta = fs::metadata(fixture.local.join("notes/a.txt")).unwrap();
    let remote_meta = fs::metadata(fixture.remote.join("notes/a.txt")).unwrap();
    assert_eq!(
        local_meta.modified().unwrap(),
        remote_meta.modified().unwrap()
    );

    let (code, output) = fixture.local_to_server(&server, &[]);
    assert_eq!(code, 0, "{output}");
    assert!(
        output.contains("created 0, updated 0, deleted 0"),
        "a settled pair must be a no-op: {output}"
    );
}

#[test]
fn the_pin_is_remembered_after_the_first_contact() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "a.txt", "one");
    let (code, output) = fixture.local_to_server(&server, &["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");

    // Same host:port, no --pin this time.
    let spec = server.spec().to_string();
    let (code, output) =
        run(client(&fixture.client_data).args(["sync", fixture.local.to_str().unwrap(), &spec]));
    assert_eq!(code, 0, "the remembered pin should be enough: {output}");
}

#[test]
fn the_source_always_wins_over_the_wire() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "doc.txt", "v1");
    fixture.local_to_server(&server, &["--auto", "--quiet"]);

    // A change on the source travels to the destination.
    fixture.write(&fixture.local, "doc.txt", "v2 local");
    let (code, output) = fixture.local_to_server(&server, &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "v2 local"
    );

    // A change on the destination alone is not kept: the source still wins.
    fixture.write(&fixture.remote, "doc.txt", "v3 remote");
    let (code, output) = fixture.local_to_server(&server, &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "v2 local",
        "the source's version must be put back in place"
    );

    // With the other direction the roles are exchanged, and the other side
    // wins.
    fixture.write(&fixture.remote, "doc.txt", "v3 remote");
    // The other direction is another pair, so it needs its own consent.
    let (code, output) = fixture.server_to_local(&server, &["--quiet", "--auto"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "v3 remote",
        "the source is the server now, so its version wins"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "v3 remote",
        "the source is never written to"
    );
}

#[test]
fn a_multi_chunk_file_survives_the_wire() {
    let (fixture, server) = Fixture::new();
    let payload: Vec<u8> = (0..1_200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(fixture.local.join("big.bin"), &payload).unwrap();

    let (code, output) = fixture.local_to_server(&server, &["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(fixture.remote.join("big.bin")).unwrap(), payload);
}

#[test]
fn a_file_deleted_on_the_source_stays_unless_asked_to_be_removed() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "keep.txt", "keep");
    fixture.write(&fixture.local, "drop.txt", "drop");
    fixture.local_to_server(&server, &["--auto", "--quiet"]);

    fs::remove_file(fixture.local.join("drop.txt")).unwrap();
    let (code, output) = fixture.local_to_server(&server, &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert!(
        fixture.remote.join("drop.txt").exists(),
        "nothing is removed without --delete: {output}"
    );

    let (code, output) = fixture.local_to_server(&server, &["--quiet", "--delete"]);
    assert_eq!(code, 0, "{output}");
    assert!(
        !fixture.remote.join("drop.txt").exists(),
        "--delete must remove what the source no longer has: {output}"
    );
    assert!(fixture.remote.join("keep.txt").exists());
}

#[test]
fn the_destination_never_keeps_a_version_of_its_own() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "doc.txt", "base");
    fixture.local_to_server(&server, &["--auto", "--quiet"]);

    fixture.write(&fixture.local, "doc.txt", "mine");
    fixture.write(&fixture.remote, "doc.txt", "theirs");

    let (code, output) = fixture.local_to_server(&server, &["--auto"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "mine",
        "the source's version is the one that is kept"
    );
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "mine",
        "the source is never written to"
    );
}

#[test]
fn a_client_that_was_never_authorized_is_refused() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "a.txt", "x");

    // A different machine: its own data dir, so its own unauthorized identity.
    let stranger_data = fixture._root.path().join("stranger-data");
    fs::create_dir_all(&stranger_data).unwrap();
    fingerprint_of(&stranger_data);

    let spec = server.spec().to_string();
    let (code, output) = run(client(&stranger_data)
        .args(["sync", fixture.local.to_str().unwrap(), &spec])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));

    assert_ne!(code, 0, "an unauthorized client must not get in: {output}");
    assert!(
        output.contains("authorize") || output.contains("authorized"),
        "the refusal must say how to fix it: {output}"
    );
    assert!(
        !fixture.remote.join("a.txt").exists(),
        "nothing may be written"
    );
}

#[test]
fn a_wrong_pin_is_refused_with_an_explanation() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "a.txt", "x");

    let spec = server.spec().to_string();
    let (code, output) = run(client(&fixture.client_data)
        .args(["sync", fixture.local.to_str().unwrap(), &spec])
        .arg("--pin")
        .arg("ab".repeat(32))
        .arg("--auto"));

    assert_ne!(code, 0, "a mismatched pin must not connect: {output}");
    assert!(
        output.contains("refused the connection") || output.contains("pinned"),
        "the refusal must be explained: {output}"
    );
    assert!(!fixture.remote.join("a.txt").exists());
}

#[test]
fn a_server_with_no_authorized_clients_refuses_to_start() {
    let root = tempfile::tempdir().unwrap();
    let serve_root = root.path().join("serve-root");
    let data = root.path().join("data");
    fs::create_dir_all(&serve_root).unwrap();
    fs::create_dir_all(&data).unwrap();

    let (code, output) = run(Command::new(binary())
        .arg("serve")
        .arg("--root")
        .arg(&serve_root)
        .args(["--listen", "127.0.0.1:0"])
        .env("TWIN_DATA_DIR", &data));

    assert_ne!(code, 0, "it must fail closed, not serve everyone: {output}");
    assert!(
        output.contains("authorize"),
        "it must say how to authorize a client: {output}"
    );
}

#[test]
fn the_first_contact_needs_a_pin_rather_than_silent_trust() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "a.txt", "x");

    let spec = server.spec().to_string();
    let (code, output) = run(client(&fixture.client_data)
        .args(["sync", fixture.local.to_str().unwrap(), &spec])
        .arg("--auto"));

    assert_eq!(code, 2, "it must ask for a pin: {output}");
    assert!(
        output.contains("no pinned certificate"),
        "the message must say what to do: {output}"
    );
    assert!(!fixture.remote.join("a.txt").exists());
}

/// The order of the arguments is the direction: the content flows from the
/// first to the second, and the other side is left alone.
#[test]
fn the_order_of_the_arguments_decides_the_direction() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.remote, "doc.txt", "from the server");
    fixture.write(&fixture.local, "doc.txt", "from the laptop");

    let spec = server.spec().to_string();
    let (code, output) = run(client(&fixture.client_data)
        .args(["sync", &spec, fixture.local.to_str().unwrap()])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));

    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "from the server",
        "the first argument is the source: its content must arrive"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "from the server",
        "the source must be left alone"
    );

    // The other order copies the other way.
    fixture.write(&fixture.local, "doc.txt", "from the laptop");
    let (code, output) = run(client(&fixture.client_data)
        .args(["sync", fixture.local.to_str().unwrap(), &spec])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));

    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "from the laptop",
        "the local side is the source now, so its content wins"
    );
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "from the laptop",
        "the source is never written to"
    );
}

/// `twin authorize` must take effect on a running server: a client that is
/// authorized while the server runs gets in on its next attempt, and a client
/// that is withdrawn is refused from then on. Neither needs a restart.
#[test]
fn authorizing_a_client_takes_effect_without_restarting_the_server() {
    let (fixture, server) = Fixture::new();

    // A second machine, with its own identity and its own directory.
    let stranger_data = fixture._root.path().join("stranger-data");
    let stranger = stranger_data.join("local");
    fs::create_dir_all(&stranger).unwrap();
    let stranger_fp = fingerprint_of(&stranger_data);
    fs::write(stranger.join("hello.txt"), "from the stranger").unwrap();
    let server_data = fixture._root.path().join("server-data");

    // Not authorized yet: refused.
    let (code, output) = run(client(&stranger_data)
        .args(["sync", stranger.to_str().unwrap(), server.spec()])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));
    assert_ne!(code, 0, "an unauthorized client must be refused: {output}");

    // Authorized while the server runs: let in, without a restart.
    let (code, output) = run(client(&server_data).arg("authorize").arg(&stranger_fp));
    assert_eq!(code, 0, "{output}");
    let (code, output) = run(client(&stranger_data)
        .args(["sync", stranger.to_str().unwrap(), server.spec()])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));
    assert_eq!(code, 0, "the client must be let in now: {output}");
    assert!(
        fixture.remote.join("hello.txt").exists(),
        "the file must have travelled: {output}"
    );

    // Withdrawn: refused again, still without a restart.
    let list = server_data.join("authorized_clients");
    let kept: Vec<String> = fs::read_to_string(&list)
        .unwrap()
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && line != &stranger_fp)
        .collect();
    fs::write(&list, format!("{}\n", kept.join("\n"))).unwrap();
    fs::remove_file(fixture.remote.join("hello.txt")).unwrap();

    let (code, output) = run(client(&stranger_data)
        .args(["sync", stranger.to_str().unwrap(), server.spec()])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));
    assert_ne!(code, 0, "a withdrawn client must be refused: {output}");
    assert!(
        !fixture.remote.join("hello.txt").exists(),
        "nothing may be written by a withdrawn client: {output}"
    );
}

/// A bare "skipped 1" reads like a failure. The reason must be visible without -v.
#[test]
fn skipping_says_what_was_skipped_and_why() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "shared.txt", "same on both sides");
    fixture.write(&fixture.remote, "shared.txt", "same on both sides");
    fixture.write(&fixture.local, "local-only.txt", "never went anywhere");

    let (code, output) = fixture.server_to_local(&server, &["--auto"]);
    assert_eq!(code, 0, "{output}");
    assert!(
        output.contains("absent on the source side"),
        "a bare skip count is not an explanation: {output}"
    );
    assert!(
        output.contains("--delete"),
        "it must say how to make the skipped paths go away: {output}"
    );
    assert!(
        fixture.local.join("local-only.txt").exists(),
        "skipping must not delete anything"
    );
}
