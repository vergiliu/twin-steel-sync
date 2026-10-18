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

fn fingerprint_of(data: &Path) -> String {
    let (code, output) = run(client(data).arg("id"));
    assert_eq!(code, 0, "twin id must work: {output}");
    output
        .lines()
        .next()
        .expect("a fingerprint on the first line")
        .trim()
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

    fn sync(&self, server: &Server, verb: &str, extra: &[&str]) -> (i32, String) {
        let spec = server.spec().to_string();
        let mut command = client(&self.client_data);
        command
            .arg(verb)
            .arg(&self.local)
            .arg(&spec)
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

    let (code, output) = fixture.sync(&server, "push", &["--auto", "--quiet"]);
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

    let (code, output) = fixture.sync(&server, "push", &[]);
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
    let (code, output) = fixture.sync(&server, "push", &["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");

    // Same host:port, no --pin this time.
    let spec = server.spec().to_string();
    let (code, output) =
        run(client(&fixture.client_data).args(["push", fixture.local.to_str().unwrap(), &spec]));
    assert_eq!(code, 0, "the remembered pin should be enough: {output}");
}

#[test]
fn content_changes_travel_both_ways() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "doc.txt", "v1");
    fixture.sync(&server, "sync", &["--auto", "--quiet"]);

    fixture.write(&fixture.local, "doc.txt", "v2 local");
    let (code, output) = fixture.sync(&server, "sync", &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "v2 local"
    );

    fixture.write(&fixture.remote, "doc.txt", "v3 remote");
    let (code, output) = fixture.sync(&server, "sync", &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "v3 remote"
    );
}

#[test]
fn a_multi_chunk_file_survives_the_wire() {
    let (fixture, server) = Fixture::new();
    let payload: Vec<u8> = (0..1_200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(fixture.local.join("big.bin"), &payload).unwrap();

    let (code, output) = fixture.sync(&server, "push", &["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(fixture.remote.join("big.bin")).unwrap(), payload);
}

#[test]
fn deletions_propagate_over_the_wire() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "keep.txt", "keep");
    fixture.write(&fixture.local, "drop.txt", "drop");
    fixture.sync(&server, "sync", &["--auto", "--quiet"]);

    fs::remove_file(fixture.remote.join("drop.txt")).unwrap();
    let (code, output) = fixture.sync(&server, "sync", &["--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert!(
        !fixture.local.join("drop.txt").exists(),
        "the deletion must travel"
    );
}

#[test]
fn conflicts_keep_both_versions_on_both_sides() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "doc.txt", "base");
    fixture.sync(&server, "sync", &["--auto", "--quiet"]);

    fixture.write(&fixture.local, "doc.txt", "mine");
    fixture.write(&fixture.remote, "doc.txt", "theirs");

    let (code, output) = fixture.sync(&server, "sync", &["--auto"]);
    assert_eq!(code, 3, "conflicts are reported, not fatal: {output}");

    let names: Vec<String> = fs::read_dir(&fixture.local)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    let copy = names
        .iter()
        .find(|n| n.contains(".conflict-"))
        .unwrap_or_else(|| panic!("no conflict copy in {names:?}"));

    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "mine"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "mine",
        "the local version wins the name on both sides"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join(copy)).unwrap(),
        "theirs",
        "the losing version is kept on both sides"
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
        .args(["push", fixture.local.to_str().unwrap(), &spec])
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
        .args(["push", fixture.local.to_str().unwrap(), &spec])
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
        .args(["push", fixture.local.to_str().unwrap(), &spec])
        .arg("--auto"));

    assert_eq!(code, 2, "it must ask for a pin: {output}");
    assert!(
        output.contains("no pinned certificate"),
        "the message must say what to do: {output}"
    );
    assert!(!fixture.remote.join("a.txt").exists());
}

/// The verb decides the direction, not the order of the arguments: `pull` must
/// never push, whichever side is written first.
#[test]
fn pull_never_pushes_however_the_arguments_are_ordered() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.remote, "doc.txt", "from the server");
    fixture.write(&fixture.local, "doc.txt", "from the laptop");

    let spec = server.spec().to_string();
    let (code, output) = run(client(&fixture.client_data)
        .args(["pull", &spec, fixture.local.to_str().unwrap()])
        .arg("--pin")
        .arg(&server.fingerprint)
        .arg("--auto"));

    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read_to_string(fixture.local.join("doc.txt")).unwrap(),
        "from the server",
        "pull must bring content down, not send it up"
    );
    assert_eq!(
        fs::read_to_string(fixture.remote.join("doc.txt")).unwrap(),
        "from the server",
        "the other side must be left alone"
    );
}

/// A bare "skipped 1" reads like a failure. The reason must be visible without -v.
#[test]
fn skipping_says_what_was_skipped_and_why() {
    let (fixture, server) = Fixture::new();
    fixture.write(&fixture.local, "shared.txt", "same on both sides");
    fixture.write(&fixture.remote, "shared.txt", "same on both sides");
    fixture.write(&fixture.local, "local-only.txt", "never went anywhere");

    let (code, output) = fixture.sync(&server, "pull", &["--auto"]);
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
