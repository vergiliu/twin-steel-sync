//! Helpers shared by the integration tests that drive the real `twin` binary.
//!
//! Cargo picks up `tests/*.rs` and `tests/*/main.rs` as test targets, so this
//! file is a plain module: it is compiled into every test that says
//! `mod common;` and never becomes a test of its own.
//!
//! What lives here is deliberately a copy of what `tests/tls.rs` does rather
//! than an import from it: that file belongs to somebody else's change and must
//! not be edited, and a private copy cannot be broken by a change to another
//! test.

#![allow(dead_code)] // every test binary uses a different subset of these

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// The binary cargo built for this test run.
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

/// A `twin` command with its own data directory (identity, pins, archive).
pub fn client(data: &Path) -> Command {
    let mut command = Command::new(binary());
    command.env("TWIN_DATA_DIR", data);
    command
}

/// Run a command to completion and return its exit code and everything it
/// printed (stdout first, then stderr).
pub fn run(command: &mut Command) -> (i32, String) {
    let output = command.output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

/// The fingerprint this data directory's own identity prints.
pub fn fingerprint_of(data: &Path) -> String {
    let (code, output) = run(client(data).arg("id"));
    assert_eq!(code, 0, "twin id must work: {output}");
    output
        .lines()
        .next()
        .expect("a fingerprint on the first line")
        .trim()
        .to_string()
}

/// The counters a run prints once it is done:
///
/// ```text
/// created 3, updated 0, deleted 0, conflicts 0, skipped 0, failures 0, unchanged 12
/// ```
///
/// The shape of that line is the CLI's public output, so the tests read it
/// rather than reaching into the program.
pub fn summary(output: &str) -> BTreeMap<String, u64> {
    let line = output
        .lines()
        .rfind(|line| line.trim_start().starts_with("created "))
        .unwrap_or_else(|| panic!("no summary line in the output:\n{output}"));
    let mut counters = BTreeMap::new();
    for part in line.split(',') {
        let (name, value) = part
            .trim()
            .split_once(' ')
            .unwrap_or_else(|| panic!("cannot read the summary line: {line}"));
        let number = value
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("cannot read the summary line: {line}"));
        counters.insert(name.to_string(), number);
    }
    counters
}

/// A real `twin serve` on loopback, with its own data directory.
pub struct Server {
    child: Child,
    addr: String,
    fingerprint: String,
    _reader: BufReader<std::process::ChildStdout>,
}

impl Server {
    /// Start a server for `root` and wait for it to say where it listens and
    /// which fingerprint it serves.
    pub fn start(root: &Path, data: &Path) -> Server {
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

    /// `host:port` of the running server.
    pub fn spec(&self) -> &str {
        &self.addr
    }

    /// The certificate fingerprint the server presents.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A client and a server that trust each other, plus the directories they
/// work in.
pub struct Fixture {
    _root: tempfile::TempDir,
    /// The client's root: what the client syncs.
    pub local: PathBuf,
    /// The server's root: what the server serves.
    pub remote: PathBuf,
    /// The client's data directory: identity, pins, archive.
    pub client_data: PathBuf,
    /// The server's data directory: identity, authorized clients.
    pub server_data: PathBuf,
    /// Where the client's archive lives.
    pub archive_dir: PathBuf,
}

impl Fixture {
    /// Start a server and a client that is allowed to talk to it.
    ///
    /// The client is authorized before the server is launched, so the very
    /// first connection is already allowed. (A server picks up a later change
    /// to the allow-list on the next connection, so the order does not
    /// actually matter — it is done this way because it is the order that
    /// cannot fail.)
    pub fn new() -> (Fixture, Server) {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let remote = root.path().join("remote");
        let server_data = root.path().join("server-data");
        let client_data = root.path().join("client-data");
        let archive_dir = root.path().join("archive");
        for dir in [&local, &remote, &server_data, &client_data, &archive_dir] {
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
        assert!(
            !server.fingerprint.is_empty(),
            "the server must announce which fingerprint it serves"
        );

        (
            Fixture {
                _root: root,
                local,
                remote,
                client_data,
                server_data,
                archive_dir,
            },
            server,
        )
    }

    /// Write a file under one side of the pair.
    pub fn write(&self, side: &Path, rel: &str, contents: &[u8]) {
        let path = side.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    /// The command that copies the client's root to the server.
    pub fn sync_command(&self, server: &Server) -> Command {
        let mut command = client(&self.client_data);
        command
            .arg("sync")
            .arg(&self.local)
            .arg(server.spec())
            .arg("--pin")
            .arg(server.fingerprint())
            .arg("--auto")
            .env("TWIN_ARCHIVE_DIR", &self.archive_dir);
        command
    }
}
