//! Tests for the diagnostics added after a Linux client failed with a bare
//! "Invalid argument (os error 22)": doctor must name the failing operation, and
//! the log levels must actually emit a trail.

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

fn run(command: &mut Command) -> (i32, String) {
    let output = command.output().unwrap();
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.code().unwrap_or(-1), text)
}

struct Scrubbed {
    _root: tempfile::TempDir,
    data: PathBuf,
    root: PathBuf,
}

fn scrubbed() -> Scrubbed {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let sync_root = root.path().join("tree");
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&sync_root).unwrap();
    Scrubbed {
        _root: root,
        data,
        root: sync_root,
    }
}

#[test]
fn a_healthy_environment_reports_no_problems() {
    let place = scrubbed();
    let (code, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .env("TWIN_DATA_DIR", &place.data));

    // The host's own network policy is not this test's business: on a machine whose
    // firewall blocks unsigned programs that one check fails, and everything else
    // must still pass. Anything else failing is a real problem.
    let expected = [
        "data directory",
        "identity",
        "private key permissions",
        "certificate and key",
        "temporary directory",
        "archive directory",
        "free space",
        "sync root",
        "sync root can store files",
        "sync root stores timestamps",
        "sync root can flush to disk",
        "binary signature",
        "local network accepts connections",
    ];
    for name in expected {
        let line = output
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("missing check {name:?}: {output}"));
        if name == "local network accepts connections" || name == "binary signature" {
            continue; // host state, asserted separately
        }
        assert!(line.starts_with("ok"), "{name} is not ok: {line}");
    }
    for line in output.lines().filter(|l| l.starts_with("FAIL")) {
        assert!(
            line.contains("local network accepts connections") || line.contains("binary signature"),
            "only host-state checks may fail here: {line}"
        );
    }
    if code == 0 {
        assert!(output.contains("no problems found"), "{output}");
    }
}

/// The analogue of the Linux failure: an environment the sync cannot use must be
/// named ("cannot create files here"), never left as a bare errno.
#[test]
fn a_root_that_cannot_be_written_is_named_not_guessed() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root ignores the permission bits, so there is nothing to assert
    }
    let place = scrubbed();
    let locked = place._root.path().join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();

    let (code, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&locked)
        .env("TWIN_DATA_DIR", &place.data));

    assert_eq!(
        code, 1,
        "a broken environment must not report success: {output}"
    );
    let root_line = output
        .lines()
        .find(|l| l.contains("sync root can store files"))
        .unwrap_or_else(|| panic!("missing the sync-root check: {output}"));
    assert!(root_line.starts_with("FAIL"), "{root_line}");
    assert!(
        root_line.contains("cannot create files here"),
        "the check must name the operation that failed, not the errno: {root_line}"
    );
    assert!(
        !root_line.contains("os error 22"),
        "an unhelpful errno leaked into the sync-root check: {root_line}"
    );

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
}

struct Server {
    child: Child,
    addr: String,
    fingerprint: String,
    _reader: BufReader<std::process::ChildStdout>,
}

impl Server {
    fn start(root: &Path, data: &Path, authorized: &[String]) -> Server {
        for fingerprint in authorized {
            let (code, output) = run(Command::new(binary())
                .arg("authorize")
                .arg(fingerprint)
                .env("TWIN_DATA_DIR", data));
            assert_eq!(code, 0, "{output}");
        }
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
fn doctor_can_check_the_far_end_over_the_wire() {
    let place = scrubbed();
    let server_data = place._root.path().join("server-data");
    fs::create_dir_all(&server_data).unwrap();

    let client_fp = {
        let (code, output) = run(Command::new(binary())
            .arg("id")
            .env("TWIN_DATA_DIR", &place.data));
        assert_eq!(code, 0, "{output}");
        output.lines().next().unwrap().trim().to_string()
    };
    let server = Server::start(&place.root, &server_data, &[client_fp]);
    fs::write(place.root.join("content.txt"), "hello").unwrap();

    let (code, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .args(["--remote", &server.addr, "--pin", &server.fingerprint])
        .env("TWIN_DATA_DIR", &place.data));

    // Only the host's own network policy may fail (see the note above); everything
    // that talks to the far end must be clean.
    let _ = code;
    for line in output.lines().filter(|l| l.starts_with("FAIL")) {
        assert!(
            line.contains("local network accepts connections") || line.contains("binary signature"),
            "the far end must be reachable in this test: {line}"
        );
    }
    assert!(output.contains("remote address"), "{output}");
    assert!(
        output
            .lines()
            .any(|l| l.starts_with("ok") && l.contains("handshake")),
        "the handshake must succeed: {output}"
    );
    assert!(
        output
            .lines()
            .any(|l| l.starts_with("ok") && l.contains("1 entries readable")),
        "it should count what it can read: {output}"
    );
}

#[test]
fn doctor_says_the_handshake_failed_when_the_pin_is_wrong() {
    let place = scrubbed();
    let server_data = place._root.path().join("server-data");
    fs::create_dir_all(&server_data).unwrap();
    let client_fp = {
        let (code, output) = run(Command::new(binary())
            .arg("id")
            .env("TWIN_DATA_DIR", &place.data));
        assert_eq!(code, 0, "{output}");
        output.lines().next().unwrap().trim().to_string()
    };
    let server = Server::start(&place.root, &server_data, &[client_fp]);

    let (code, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .args(["--remote", &server.addr, "--pin", &"ab".repeat(32)])
        .env("TWIN_DATA_DIR", &place.data));

    assert_eq!(code, 1, "{output}");
    assert!(output.contains("FAIL"), "{output}");
    assert!(output.contains("handshake"), "{output}");
    assert!(
        output.contains("pinned") || output.contains("handshake failed"),
        "the failure must be named: {output}"
    );
}

#[test]
fn verbose_runs_leave_a_trail_and_quiet_ones_do_not() {
    let place = scrubbed();
    fs::write(place.root.join("a.txt"), "hello").unwrap();
    let far = place._root.path().join("far");
    fs::create_dir_all(&far).unwrap();

    let (code, _) = run(Command::new(binary())
        .args([
            "push",
            place.root.to_str().unwrap(),
            far.to_str().unwrap(),
            "--auto",
        ])
        .env("TWIN_DATA_DIR", &place.data));
    assert_eq!(code, 0);

    // -vv turns on the diagnostic level
    let (code, output) = run(Command::new(binary())
        .args([
            "push",
            place.root.to_str().unwrap(),
            far.to_str().unwrap(),
            "-vv",
        ])
        .env("TWIN_DATA_DIR", &place.data));
    assert_eq!(code, 0, "{output}");
    assert!(
        output.contains("twin: debug:") || output.contains("twin: info:"),
        "-vv must produce diagnostics: {output}"
    );

    // a plain run stays quiet on stderr
    let (code, output) = run(Command::new(binary())
        .args(["push", place.root.to_str().unwrap(), far.to_str().unwrap()])
        .env("TWIN_DATA_DIR", &place.data));
    assert_eq!(code, 0);
    assert!(
        !output.contains("twin: debug:"),
        "diagnostics must be off by default: {output}"
    );
}

/// The contract that makes the EINVAL class survivable: an mtime that cannot be
/// stored is a warning, never a failed transfer — and a pre-1970 timestamp must
/// be storable rather than turned into an illegal nanosecond field.
#[test]
fn awkward_modification_times_are_not_fatal() {
    let place = scrubbed();

    let missing = place.root.join("does-not-exist.txt");
    assert!(
        !twin::fsutil::apply_mtime(&missing, -1_500_000_000, "testing"),
        "a path that cannot be touched must be reported"
    );

    let file = place.root.join("real.txt");
    fs::write(&file, "content").unwrap();
    assert!(
        twin::fsutil::apply_mtime(&file, -1_500_000_000, "testing"),
        "a pre-1970 timestamp must be storable, not rejected as an invalid argument"
    );
    let meta = fs::metadata(&file).unwrap();
    assert_eq!(
        twin::fsutil::mtime_ns(&meta),
        -1_500_000_000,
        "the timestamp must round-trip exactly"
    );
}

/// The probe that tells "the program is broken" apart from "the system will not
/// let this program receive local-network connections".
#[test]
fn the_local_network_probe_uses_a_connection_it_made_itself() {
    let detail = twin::tls::probe_address("127.0.0.1:0".parse().unwrap())
        .expect("loopback must always work");
    assert!(
        detail.contains("accepted and used a connection"),
        "{detail}"
    );
}

#[test]
fn the_probe_reports_an_unusable_address_instead_of_panicking() {
    // 192.0.2.0/24 is reserved for documentation: never assigned to an interface.
    let problem = twin::tls::probe_address("192.0.2.1:0".parse().unwrap())
        .expect_err("binding to a foreign address must fail");
    assert!(problem.contains("cannot listen on 192.0.2.1"), "{problem}");
}

#[test]
fn doctor_reports_whether_this_machine_can_serve_the_local_network() {
    let place = scrubbed();
    let (code, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .env("TWIN_DATA_DIR", &place.data));

    let line = output
        .lines()
        .find(|l| l.contains("local network accepts connections"))
        .unwrap_or_else(|| panic!("the check is missing: {output}"));

    // Either verdict is legitimate — it describes this host. What matters is that a
    // blocked host is told how to fix it, and that the check itself is present.
    // (The process exit code is not a usable signal here: the signature check can
    // fail on its own, e.g. right after cargo relinks the binary.)
    if line.starts_with("FAIL") {
        assert!(
            output.contains("Firewall") && output.contains("Local Network"),
            "a blocked machine must be told how to fix it: {output}"
        );
    } else {
        assert!(line.starts_with("ok"), "{line}");
    }
    let _ = code;
}

/// When this host blocks local-network serving, the check must hand over the ways
/// out — including the one that needs no password.
#[test]
fn a_blocked_local_network_check_names_the_ways_out() {
    let place = scrubbed();
    let (_, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .env("TWIN_DATA_DIR", &place.data));

    let blocked = output
        .lines()
        .any(|l| l.starts_with("FAIL") && l.contains("local network accepts connections"));
    if !blocked {
        return; // this host allows it; nothing to assert beyond the check existing
    }
    assert!(
        output.contains("codesign -s -"),
        "the no-password fix must be offered: {output}"
    );
    assert!(output.contains("Firewall"), "{output}");
    assert!(
        output.contains("restart"),
        "the note about restarting the process must be there: {output}"
    );
}

/// The build step and the detector have to agree: an unsigned binary is signed
/// by the script, and then it reads as signed.
#[cfg(target_os = "macos")]
#[test]
fn the_signing_script_turns_an_unsigned_binary_into_a_signed_one() {
    use std::path::Path as StdPath;

    let place = scrubbed();
    let copy = place._root.path().join("copy-of-the-test-binary");
    fs::copy(std::env::current_exe().unwrap(), &copy).unwrap();

    // The linker signs what it links on arm64, so the copy may already carry a
    // signature there. Take it off: what this test is about is that the script
    // and the detector agree, not what the linker happens to do.
    let _ = Command::new("/usr/bin/codesign")
        .arg("--remove-signature")
        .arg(&copy)
        .output();

    assert_eq!(
        twin::tls::signature_state(&copy),
        twin::tls::SignatureState::Unsigned,
        "the copy must be unsigned before the script runs"
    );

    let script = StdPath::new(env!("CARGO_MANIFEST_DIR")).join("scripts/codesign-macos.sh");
    let first = Command::new("sh").arg(&script).arg(&copy).output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        String::from_utf8_lossy(&first.stdout).contains("signed"),
        "{}",
        String::from_utf8_lossy(&first.stdout)
    );
    assert_eq!(
        twin::tls::signature_state(&copy),
        twin::tls::SignatureState::Signed,
        "the script must leave a signature behind"
    );

    let second = Command::new("sh").arg(&script).arg(&copy).output().unwrap();
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("already signed"),
        "a second run must not sign twice: {}",
        String::from_utf8_lossy(&second.stdout)
    );
}

/// Where this host blocks, the doctor output must name every way out, including
/// signing the binary, and must point at the binary it is actually running.
#[test]
fn a_blocked_host_is_told_how_to_sign_its_way_out() {
    let place = scrubbed();
    let (_, output) = run(Command::new(binary())
        .arg("doctor")
        .arg(&place.root)
        .env("TWIN_DATA_DIR", &place.data));

    let blocked = output
        .lines()
        .any(|l| l.starts_with("FAIL") && l.contains("local network accepts connections"));
    let unsigned = output
        .lines()
        .any(|l| l.starts_with("FAIL") && l.contains("binary signature"));
    if !blocked && !unsigned {
        return; // this host is fine; nothing to assert
    }
    assert!(
        output.contains("codesign -s - -f --identifier dev.twin.cli"),
        "the signing command must be spelled out: {output}"
    );
    assert!(
        output.contains("twin"),
        "the message must name the binary to sign: {output}"
    );
}
