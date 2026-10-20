//! `twin doctor`: try the things a sync depends on, and say which one fails.
//!
//! This exists because a bare "Invalid argument (os error 22)" names neither the
//! syscall, the path, nor the filesystem that produced it. Every check here runs
//! the real operation and reports the real error.

use crate::archive::Archive;
use crate::fsutil::probe_dir;
use crate::remote::{RemoteBackend, RemoteOptions};
use crate::side::Backend;
use crate::tls;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Check {
    fn pass(name: impl Into<String>, detail: impl Into<String>) -> Check {
        Check {
            name: name.into(),
            ok: true,
            detail: detail.into(),
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>) -> Check {
        Check {
            name: name.into(),
            ok: false,
            detail: detail.into(),
        }
    }
}

fn writable_dir(name: &str, dir: &Path) -> Check {
    match fs::create_dir_all(dir) {
        Ok(()) => {
            let probe = dir.join(format!(".twin-doctor-{}", std::process::id()));
            match fs::write(&probe, b"twin") {
                Ok(()) => {
                    let _ = fs::remove_file(&probe);
                    Check::pass(name, dir.display().to_string())
                }
                Err(error) => Check::fail(
                    name,
                    format!("{} cannot be written to: {error}", dir.display()),
                ),
            }
        }
        Err(error) => Check::fail(name, format!("cannot create {}: {error}", dir.display())),
    }
}

fn free_space(name: &str, dir: &Path) -> Check {
    match free_bytes(dir) {
        Some(bytes) => {
            let gb = bytes as f64 / 1_073_741_824.0;
            let detail = format!("{gb:.1} GiB free at {}", dir.display());
            if bytes < 64 * 1024 * 1024 {
                Check::fail(name, format!("{detail} — that is very little"))
            } else {
                Check::pass(name, detail)
            }
        }
        None => Check::pass(name, format!("could not be measured at {}", dir.display())),
    }
}

#[cfg(unix)]
fn free_bytes(dir: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut stats) };
    if rc != 0 {
        return None;
    }
    Some(stats.f_bavail as u64 * stats.f_frsize as u64)
}

/// Everything that can be checked without a network.
pub fn environment(local_root: Option<&Path>) -> Vec<Check> {
    let mut checks = Vec::new();
    let data = tls::data_dir();

    checks.push(writable_dir("data directory", &data));

    match tls::Identity::load_or_create(&data) {
        Ok(identity) => {
            checks.push(Check::pass(
                "identity",
                format!("fingerprint {}", identity.fingerprint()),
            ));
            match fs::metadata(identity.key_path()) {
                Ok(meta) => {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 == 0 {
                        checks.push(Check::pass(
                            "private key permissions",
                            format!("{mode:o} on {}", identity.key_path().display()),
                        ));
                    } else {
                        checks.push(Check::fail(
                            "private key permissions",
                            format!(
                                "{mode:o} is readable by others; run `chmod 600 {}`",
                                identity.key_path().display()
                            ),
                        ));
                    }
                }
                Err(error) => checks.push(Check::fail(
                    "private key permissions",
                    format!("cannot stat {}: {error}", identity.key_path().display()),
                )),
            }
            // Building a config is the cheapest proof that the key and certificate
            // belong together and that this build can do TLS at all.
            match tls::client_config(&identity, &"0".repeat(64)) {
                Ok(_) => checks.push(Check::pass("certificate and key", "usable together")),
                Err(error) => checks.push(Check::fail("certificate and key", error.to_string())),
            }
        }
        Err(error) => checks.push(Check::fail("identity", error.to_string())),
    }

    let executable = std::env::current_exe().unwrap_or_default();
    checks.push(match tls::signature_state(&executable) {
        tls::SignatureState::Signed => Check::pass(
            "binary signature",
            format!("signed ({})", executable.display()),
        ),
        tls::SignatureState::Unsigned => Check::fail(
            "binary signature",
            format!(
                "not signed, and macOS refuses local-network connections from unsigned programs:\n      {}",
                tls::signing_command(&executable)
            ),
        ),
        tls::SignatureState::Unknown => {
            Check::pass("binary signature", "not required on this platform")
        }
    });

    checks.push(match tls::local_network_probe() {
        Ok(detail) => Check::pass("local network accepts connections", detail),
        Err(problem) => Check::fail("local network accepts connections", problem),
    });

    let temp = std::env::temp_dir();
    checks.push(writable_dir("temporary directory", &temp));

    let archive_dir = crate::engine::default_archive_dir();
    checks.push(writable_dir("archive directory", &archive_dir));
    checks.extend(archive_integrity(&archive_dir));
    checks.push(free_space("free space", &archive_dir));

    match local_root {
        None => {}
        Some(root) => {
            if !root.exists() {
                checks.push(Check::fail(
                    "sync root",
                    format!("{} does not exist", root.display()),
                ));
            } else if !root.is_dir() {
                checks.push(Check::fail(
                    "sync root",
                    format!("{} is not a directory", root.display()),
                ));
            } else {
                checks.push(Check::pass("sync root", root.display().to_string()));
                let probe = probe_dir(root);
                checks.push(fs_probe_check(
                    "sync root can store files",
                    probe.writable,
                    &probe.notes,
                    "files",
                ));
                checks.push(fs_probe_check(
                    "sync root can replace files atomically",
                    probe.rename,
                    &probe.notes,
                    "atomic replace",
                ));
                checks.push(Check {
                    name: "sync root stores timestamps".into(),
                    ok: probe.mtime,
                    detail: if probe.mtime && probe.mtime_subsecond {
                        "nanosecond precision".into()
                    } else if probe.mtime {
                        probe
                            .notes
                            .iter()
                            .find(|n| n.contains("precision"))
                            .cloned()
                            .unwrap_or_else(|| "second precision only".into())
                    } else {
                        probe
                            .notes
                            .iter()
                            .find(|n| n.contains("modification times"))
                            .cloned()
                            .unwrap_or_else(|| "cannot set modification times".into())
                    },
                });
                checks.push(Check {
                    name: "sync root can flush to disk".into(),
                    ok: probe.file_sync,
                    detail: if probe.dir_sync {
                        "file and directory fsync".into()
                    } else {
                        "file fsync only".into()
                    },
                });
            }
        }
    }

    checks
}

fn fs_probe_check(name: &str, ok: bool, notes: &[String], needle: &str) -> Check {
    if ok {
        Check::pass(name, "yes")
    } else {
        let detail = notes
            .iter()
            .find(|note| note.contains(needle))
            .cloned()
            .unwrap_or_else(|| "unsupported".to_string());
        Check::fail(name, detail)
    }
}

fn archive_integrity(archive_dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    let entries = match fs::read_dir(archive_dir) {
        Ok(entries) => entries,
        Err(_) => return checks,
    };
    let mut archives: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "db"))
        .collect();
    archives.sort();
    for path in archives {
        let name = format!(
            "archive {}",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        match Archive::open(&path).and_then(|archive| archive.integrity()) {
            Ok(result) if result.trim() == "ok" => checks.push(Check::pass(name, "consistent")),
            Ok(problem) => checks.push(Check::fail(
                name,
                format!("{problem} — delete this file to rebuild it by rescanning"),
            )),
            Err(error) => checks.push(Check::fail(name, error.to_string())),
        }
    }
    checks
}

/// Everything that needs the other side: TCP, TLS, the pinned certificate, and
/// the protocol handshake.
pub fn remote(remote: &RemoteOptions, pin: &str) -> Vec<Check> {
    let mut checks = Vec::new();
    let data = tls::data_dir();
    checks.push(Check::pass("remote address", remote.label()));

    let identity = match tls::Identity::load_or_create(&data) {
        Ok(identity) => identity,
        Err(error) => {
            checks.push(Check::fail("remote identity", error.to_string()));
            return checks;
        }
    };

    let patterns: Vec<String> = Vec::new();
    let mut backend = match RemoteBackend::connect(remote, &identity, pin, true, &patterns) {
        Ok(backend) => {
            checks.push(Check::pass(
                "handshake",
                format!(
                    "mutual TLS with the pinned certificate on {}",
                    remote.label()
                ),
            ));
            backend
        }
        Err(error) => {
            checks.push(Check::fail("handshake", error.to_string()));
            return checks;
        }
    };

    // Walking proves the far end can actually read the directory it serves.
    let mut count = 0u64;
    let mut walk_error: Option<io::Error> = None;
    let mut unreadable: Vec<String> = Vec::new();
    loop {
        match backend.walk() {
            Ok(Some(Ok(_))) => count += 1,
            // A path that cannot be read is a problem of its own: the rest of
            // the listing is still worth counting.
            Ok(Some(Err(failure))) => {
                unreadable.push(format!("{}: {}", failure.path.display(), failure.message))
            }
            Ok(None) => break,
            Err(error) => {
                walk_error = Some(error);
                break;
            }
        }
    }
    match walk_error {
        None if unreadable.is_empty() => checks.push(Check::pass(
            "remote listing",
            format!("{count} entries readable"),
        )),
        None => checks.push(Check::fail(
            "remote listing",
            format!(
                "{count} entries readable, {} unreadable: {}",
                unreadable.len(),
                unreadable.join("; ")
            ),
        )),
        Some(error) => checks.push(Check::fail("remote listing", error.to_string())),
    }

    if let Err(error) = backend.finish() {
        checks.push(Check::fail("remote shutdown", error.to_string()));
    }
    checks
}

/// Print the checks the way a person can act on them.
pub fn report(checks: &[Check], out: &mut dyn Write) -> io::Result<usize> {
    let mut failures = 0;
    for check in checks {
        let mark = if check.ok { "ok  " } else { "FAIL" };
        if !check.ok {
            failures += 1;
        }
        writeln!(out, "{mark}  {:<34} {}", check.name, check.detail)?;
    }
    writeln!(out)?;
    if failures == 0 {
        writeln!(out, "no problems found")?;
    } else {
        writeln!(out, "{failures} problem(s) found")?;
    }
    Ok(failures)
}
