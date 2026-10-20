//! `--partial`: an interrupted transfer keeps what it has, and the next run
//! continues it instead of starting over.
//!
//! The temporary file that holds a transfer in flight has a name derived from
//! the destination, so the next run finds it again. The tests use that rule
//! (`twin::side::temp_for`) to play the part of the interrupted run.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

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

/// The file that holds a transfer in flight for `rel` under `root`.
fn leftover(root: &Path, rel: &str) -> PathBuf {
    twin::side::temp_for(&root.join(rel))
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32 * 31 + seed as u32) % 251) as u8)
        .collect()
}

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
        for dir in [&local, &remote, &archive] {
            fs::create_dir_all(dir).unwrap();
        }
        Pair {
            _root: root,
            local,
            remote,
            archive,
        }
    }

    /// Copy the remote directory to the local one: the remote side is the
    /// source, the local side the destination.
    fn sync(&self, extra: &[&str]) -> (i32, String) {
        let output = Command::new(binary())
            .arg("sync")
            .arg(&self.remote)
            .arg(&self.local)
            .args(extra)
            .arg("--archive-dir")
            .arg(&self.archive)
            .output()
            .unwrap();
        let mut text = String::from_utf8_lossy(&output.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.code().unwrap_or(-1), text)
    }
}

#[test]
fn an_interrupted_transfer_is_finished_by_the_next_run() {
    let pair = Pair::new();
    let content = payload(7, 120_000);
    fs::write(pair.remote.join("big.bin"), &content).unwrap();

    // An interrupted run left the beginning of the file behind.
    let partial = leftover(&pair.local, "big.bin");
    fs::write(&partial, &content[..40_000]).unwrap();

    let (code, output) = pair.sync(&["--auto", "--quiet", "--partial"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read(pair.local.join("big.bin")).unwrap(),
        content,
        "the file must be complete"
    );
    assert!(
        !partial.exists(),
        "the partial file must have become the real file"
    );
}

#[test]
fn a_corrupted_partial_file_is_thrown_away_and_the_file_retransferred() {
    let pair = Pair::new();
    let content = payload(11, 90_000);
    fs::write(pair.remote.join("big.bin"), &content).unwrap();

    // The leftover belongs to something else entirely.
    let partial = leftover(&pair.local, "big.bin");
    fs::write(&partial, b"this is not the beginning of the file").unwrap();

    let (code, output) = pair.sync(&["--auto", "--quiet", "--partial"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read(pair.local.join("big.bin")).unwrap(),
        content,
        "the file must be transferred again from the beginning"
    );
    assert!(!partial.exists(), "the bad prefix must be gone");
}

#[test]
fn without_the_flag_the_leftover_is_replaced_rather_than_continued() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores the mode bits: nothing to assert
    }
    let pair = Pair::new();
    let content = payload(3, 60_000);
    fs::write(pair.remote.join("big.bin"), &content).unwrap();

    // A leftover that cannot be written to: a run that continues it fails,
    // a run that replaces it does not.
    let partial = leftover(&pair.local, "big.bin");
    fs::write(&partial, &content[..20_000]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o400)).unwrap();

    let (code, output) = pair.sync(&["--auto", "--quiet", "--partial"]);
    assert_eq!(
        code, 4,
        "the leftover must be continued, so it cannot be written to: {output}"
    );
    assert!(
        !pair.local.join("big.bin").exists(),
        "nothing may be published from a broken transfer"
    );

    // Without the flag the leftover is thrown away and the file is sent again.
    let (code, output) = pair.sync(&["--auto", "--quiet"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(pair.local.join("big.bin")).unwrap(), content);
}

#[test]
fn a_partial_file_that_is_too_long_is_thrown_away() {
    let pair = Pair::new();
    let content = payload(5, 10_000);
    fs::write(pair.remote.join("small.bin"), &content).unwrap();

    // A leftover from a longer version of the file.
    let partial = leftover(&pair.local, "small.bin");
    fs::write(&partial, vec![0u8; 50_000]).unwrap();

    let (code, output) = pair.sync(&["--auto", "--quiet", "--partial"]);
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(pair.local.join("small.bin")).unwrap(), content);
    assert!(!partial.exists());
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
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn an_interrupted_transfer_over_tls_is_finished_by_the_next_run() {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join("local");
    let remote = root.path().join("remote");
    let server_data = root.path().join("server-data");
    let client_data = root.path().join("client-data");
    for dir in [&local, &remote, &server_data, &client_data] {
        fs::create_dir_all(dir).unwrap();
    }

    // The client has an identity, and the server trusts it.
    let (code, output) = run(client(&client_data).arg("id"));
    assert_eq!(code, 0, "{output}");
    let fingerprint = output.lines().next().unwrap().trim().to_string();
    let (code, output) = run(client(&server_data).arg("authorize").arg(&fingerprint));
    assert_eq!(code, 0, "{output}");

    let content = payload(13, 200_000);
    fs::write(remote.join("big.bin"), &content).unwrap();

    let server = Server::start(&remote, &server_data);
    assert!(
        !server.addr.is_empty(),
        "the server must announce its address"
    );

    // An interrupted run left the beginning of the file behind.
    let partial = leftover(&local, "big.bin");
    fs::write(&partial, &content[..80_000]).unwrap();

    let (code, output) = run(client(&client_data)
        .arg("sync")
        .arg(&server.addr)
        .arg(&local)
        .arg("--pin")
        .arg(&server.fingerprint)
        .args(["--auto", "--quiet", "--partial"]));
    assert_eq!(code, 0, "{output}");
    assert_eq!(
        fs::read(local.join("big.bin")).unwrap(),
        content,
        "the file must be complete"
    );
    assert!(!partial.exists(), "the partial file must be gone");
}

#[test]
fn a_killed_transfer_keeps_its_partial_file_and_the_next_run_resumes_it() {
    const BIG: usize = 32 * 1024 * 1024;

    let root = tempfile::tempdir().unwrap();
    let local = root.path().join("local");
    let remote = root.path().join("remote");
    let server_data = root.path().join("server-data");
    let client_data = root.path().join("client-data");
    for dir in [&local, &remote, &server_data, &client_data] {
        fs::create_dir_all(dir).unwrap();
    }

    let (code, output) = run(client(&client_data).arg("id"));
    assert_eq!(code, 0, "{output}");
    let fingerprint = output.lines().next().unwrap().trim().to_string();
    let (code, output) = run(client(&server_data).arg("authorize").arg(&fingerprint));
    assert_eq!(code, 0, "{output}");

    let content = payload(23, BIG);
    fs::write(remote.join("big.bin"), &content).unwrap();
    let server = Server::start(&remote, &server_data);

    // The client is killed while the file is on its way.
    let mut child = Command::new(binary())
        .env("TWIN_DATA_DIR", &client_data)
        .arg("sync")
        .arg(&server.addr)
        .arg(&local)
        .arg("--pin")
        .arg(&server.fingerprint)
        .args(["--auto", "--quiet", "--partial"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Wait until the transfer is demonstrably in flight: the partial file
    // holds bytes.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut partial: Option<PathBuf> = None;
    while std::time::Instant::now() < deadline {
        if let Some(path) = partial_file_with_bytes(&local) {
            partial = Some(path);
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("the transfer ended ({status}) before it could be interrupted");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let partial = partial.expect("no transfer was ever in flight");
    child.kill().expect("the client must still be running");
    let status = child.wait().unwrap();
    assert!(
        status.code().is_none(),
        "the client must die from a signal, not exit on its own: {status}"
    );

    // The interrupted transfer keeps what it had, and nothing was published
    // under the real name.
    assert!(
        partial.exists(),
        "the partial file must survive the kill: {:?}",
        partial
    );
    assert!(
        !local.join("big.bin").exists(),
        "a partial file must never appear under its real name"
    );

    // The next run finishes the file.
    let (code, output) = run(client(&client_data)
        .arg("sync")
        .arg(&server.addr)
        .arg(&local)
        .arg("--pin")
        .arg(&server.fingerprint)
        .args(["--auto", "--quiet", "--partial"]));
    assert_eq!(code, 0, "{output}");
    let delivered = fs::read(local.join("big.bin")).unwrap();
    assert_eq!(delivered.len(), content.len());
    assert_eq!(delivered, content, "the file must be complete and correct");
}

/// A temporary file in `root` that holds something.
fn partial_file_with_bytes(root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(".twin-tmp-") {
            continue;
        }
        let path = entry.path();
        if fs::metadata(&path)
            .map(|meta| meta.len() > 0)
            .unwrap_or(false)
        {
            return Some(path);
        }
    }
    None
}

#[test]
fn a_corrupted_partial_file_over_tls_is_thrown_away() {
    let root = tempfile::tempdir().unwrap();
    let local = root.path().join("local");
    let remote = root.path().join("remote");
    let server_data = root.path().join("server-data");
    let client_data = root.path().join("client-data");
    for dir in [&local, &remote, &server_data, &client_data] {
        fs::create_dir_all(dir).unwrap();
    }

    let (code, output) = run(client(&client_data).arg("id"));
    assert_eq!(code, 0, "{output}");
    let fingerprint = output.lines().next().unwrap().trim().to_string();
    let (code, output) = run(client(&server_data).arg("authorize").arg(&fingerprint));
    assert_eq!(code, 0, "{output}");

    let content = payload(17, 150_000);
    fs::write(remote.join("big.bin"), &content).unwrap();

    let server = Server::start(&remote, &server_data);

    let partial = leftover(&local, "big.bin");
    fs::write(&partial, b"not the beginning of this file at all").unwrap();

    let (code, output) = run(client(&client_data)
        .arg("sync")
        .arg(&server.addr)
        .arg(&local)
        .arg("--pin")
        .arg(&server.fingerprint)
        .args(["--auto", "--quiet", "--partial"]));
    assert_eq!(code, 0, "{output}");
    assert_eq!(fs::read(local.join("big.bin")).unwrap(), content);
    assert!(!partial.exists(), "the bad prefix must be gone");
}
