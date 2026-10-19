//! `--json`: one JSON object per line, so a program can follow a run.
//!
//! The stream is read with a small parser written here: the project has no
//! `serde`, and the test must not depend on one either.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn twin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_twin"))
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Text(String),
    Number(u64),
}

impl Value {
    fn text(&self) -> &str {
        match self {
            Value::Text(text) => text,
            Value::Number(number) => panic!("expected a string, got {number}"),
        }
    }

    fn number(&self) -> u64 {
        match self {
            Value::Number(number) => *number,
            Value::Text(text) => panic!("expected a number, got {text}"),
        }
    }
}

type Object = BTreeMap<String, Value>;

/// Read one flat JSON object. Enough for the event stream, and it fails loudly
/// on anything it does not understand.
fn parse_object(line: &str) -> Result<Object, String> {
    let body = line
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or_else(|| format!("not a JSON object: {line}"))?;
    let mut fields = Object::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped.trim();
        }
        let (key, tail) = read_string(rest)?;
        let tail = tail.trim_start();
        let tail = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("expected a colon after {key:?} in {line}"))?;
        let tail = tail.trim_start();
        let (value, tail) = if tail.starts_with('"') {
            let (text, tail) = read_string(tail)?;
            (Value::Text(text), tail)
        } else {
            let end = tail
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(tail.len());
            let number: u64 = tail[..end]
                .parse()
                .map_err(|_| format!("expected a number in {line}"))?;
            (Value::Number(number), &tail[end..])
        };
        fields.insert(key, value);
        rest = tail.trim();
        if let Some(stripped) = rest.strip_prefix(',') {
            rest = stripped.trim();
        }
    }
    Ok(fields)
}

/// Read a quoted string and unescape it.
fn read_string(text: &str) -> Result<(String, &str), String> {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(format!("expected a quoted string: {text}"));
    }
    let mut out = String::new();
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                index += 1;
                let escaped = *bytes.get(index).ok_or("unterminated escape")?;
                out.push(match escaped {
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'b' => '\u{08}',
                    b'f' => '\u{0c}',
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'u' => {
                        // A \uXXXX escape: the tests do not need the code
                        // point, only a placeholder that is not a quote.
                        index += 4;
                        '\u{fffd}'
                    }
                    other => other as char,
                });
                index += 1;
            }
            b'"' => return Ok((out, &text[index + 1..])),
            _ => {
                let ch = text[index..].chars().next().unwrap_or('\u{fffd}');
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Err(format!("unterminated string: {text}"))
}

struct Sandbox {
    _root: tempfile::TempDir,
    local: PathBuf,
    remote: PathBuf,
    archive: PathBuf,
}

impl Sandbox {
    fn new() -> Sandbox {
        let root = tempfile::tempdir().unwrap();
        let local = root.path().join("local");
        let remote = root.path().join("remote");
        let archive = root.path().join("archive");
        for dir in [&local, &remote, &archive] {
            fs::create_dir_all(dir).unwrap();
        }
        Sandbox {
            _root: root,
            local,
            remote,
            archive,
        }
    }

    fn run(&self, verb: &str, extra: &[&str]) -> (i32, String, String) {
        let output = Command::new(twin())
            .arg(verb)
            .arg(&self.local)
            .arg(&self.remote)
            .args(extra)
            .arg("--archive-dir")
            .arg(&self.archive)
            .output()
            .unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// The event stream: standard output only, one object per line.
    fn json(&self, verb: &str, extra: &[&str]) -> (i32, Vec<Object>) {
        let (code, stdout, stderr) = self.run(verb, &{
            let mut args = vec!["--json"];
            args.extend_from_slice(extra);
            args
        });
        let events: Vec<Object> = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                parse_object(line)
                    .unwrap_or_else(|e| panic!("{e}\nwhole output:\n{stdout}{stderr}"))
            })
            .collect();
        (code, events)
    }

    fn write(&self, side: &Path, rel: &str, contents: &str) {
        let path = side.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

fn kind(event: &Object) -> &str {
    event.get("type").expect("every event has a type").text()
}

#[test]
fn every_line_is_an_object_and_the_last_one_is_the_summary() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "a.txt", "one");
    sandbox.write(&sandbox.local, "dir/b.txt", "two");

    let (code, events) = sandbox.json("sync", &["--auto"]);
    assert_eq!(code, 0);
    assert!(events.len() >= 3, "{events:?}");
    for event in &events {
        assert!(
            event.contains_key("type"),
            "every event needs a type: {event:?}"
        );
    }
    assert_eq!(kind(events.last().unwrap()), "summary");
    assert_eq!(
        events.iter().filter(|event| kind(event) == "plan").count(),
        2,
        "both files are planned"
    );
}

#[test]
fn a_transfer_is_reported_from_start_to_finish() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "a.txt", "one");

    let (code, events) = sandbox.json("sync", &["--auto"]);
    assert_eq!(code, 0);
    let transfers: Vec<&Object> = events
        .iter()
        .filter(|event| kind(event) == "transfer")
        .collect();
    assert_eq!(transfers.len(), 2, "start and done: {events:?}");
    assert_eq!(transfers[0].get("phase").unwrap().text(), "start");
    assert_eq!(transfers[1].get("phase").unwrap().text(), "done");
    assert_eq!(transfers[1].get("path").unwrap().text(), "a.txt");
    assert_eq!(transfers[1].get("from").unwrap().text(), "local");
    assert_eq!(transfers[1].get("to").unwrap().text(), "remote");
    assert_eq!(transfers[1].get("size").unwrap().number(), 3);
}

#[test]
fn a_conflict_emits_a_conflict_event() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "doc.txt", "base");
    let (code, _) = sandbox.json("sync", &["--auto"]);
    assert_eq!(code, 0);

    sandbox.write(&sandbox.local, "doc.txt", "mine");
    sandbox.write(&sandbox.remote, "doc.txt", "theirs");

    let (code, events) = sandbox.json("sync", &["--auto"]);
    assert_eq!(code, 3, "a conflict is not a failure");
    let conflicts: Vec<&Object> = events
        .iter()
        .filter(|event| kind(event) == "conflict")
        .collect();
    assert_eq!(conflicts.len(), 1, "one conflict: {events:?}");
    assert_eq!(conflicts[0].get("path").unwrap().text(), "doc.txt");
    let copy = conflicts[0].get("copy").unwrap().text();
    assert!(
        copy.starts_with("doc.conflict-"),
        "the copy must be named: {copy}"
    );
}

#[test]
fn a_skipped_file_emits_a_skip_event_with_a_reason() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "keep.txt", "same");
    sandbox.write(&sandbox.remote, "keep.txt", "same");
    sandbox.write(&sandbox.local, "extra.txt", "only here");

    // A pull cannot remove what the source does not have.
    let (code, events) = sandbox.json("pull", &["--auto"]);
    assert_eq!(code, 0);
    let skips: Vec<&Object> = events
        .iter()
        .filter(|event| kind(event) == "skip")
        .collect();
    assert_eq!(skips.len(), 1, "one skip: {events:?}");
    assert_eq!(skips[0].get("path").unwrap().text(), "extra.txt");
    let reason = skips[0].get("reason").unwrap().text();
    assert!(reason.contains("source side"), "{reason}");
}

#[test]
fn the_summary_counts_match_the_text_report() {
    // Two identical pairs: one reports in JSON, the other in prose.
    let json_run = Sandbox::new();
    let text_run = Sandbox::new();
    for sandbox in [&json_run, &text_run] {
        sandbox.write(&sandbox.local, "a.txt", "one");
        sandbox.write(&sandbox.local, "b.txt", "two");
    }

    let (code, events) = json_run.json("sync", &["--auto"]);
    assert_eq!(code, 0);
    let summary = events.last().unwrap();
    assert_eq!(summary.get("created").unwrap().number(), 2);
    assert_eq!(summary.get("updated").unwrap().number(), 0);
    assert_eq!(summary.get("deleted").unwrap().number(), 0);
    assert_eq!(summary.get("failures").unwrap().number(), 0);

    let (code, text, _) = text_run.run("sync", &["--auto"]);
    assert_eq!(code, 0);
    let expected = format!(
        "created {}, updated {}, deleted {}, conflicts {}, skipped {}, failures {}",
        summary.get("created").unwrap().number(),
        summary.get("updated").unwrap().number(),
        summary.get("deleted").unwrap().number(),
        summary.get("conflicts").unwrap().number(),
        summary.get("skipped").unwrap().number(),
        summary.get("failures").unwrap().number(),
    );
    assert!(
        text.contains(&expected),
        "the text report must agree with the summary: {text}"
    );
}

#[test]
fn the_json_stream_replaces_the_human_report() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "a.txt", "one");

    let (_, output, _) = sandbox.run("sync", &["--auto", "--json"]);
    assert!(
        !output.contains("created 1, updated 0"),
        "the human summary must not be printed as well: {output}"
    );
    assert!(
        !output.contains("  create local -> remote"),
        "the per-file text lines must not be printed as well: {output}"
    );
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        parse_object(line).unwrap_or_else(|e| panic!("{e}: {line}"));
    }
}

#[test]
fn a_failure_is_reported_as_an_error_event() {
    let sandbox = Sandbox::new();
    sandbox.write(&sandbox.local, "a.txt", "one");

    // A destination that cannot be written to: the file fails, the run does
    // not.
    let locked = sandbox.remote.join("sub");
    fs::create_dir_all(&locked).unwrap();
    sandbox.write(&sandbox.local, "sub/b.txt", "two");
    let mut permissions = fs::metadata(&locked).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o500);
    fs::set_permissions(&locked, permissions).unwrap();

    let (code, events) = sandbox.json("sync", &["--auto"]);
    if unsafe { libc::geteuid() } == 0 {
        // root ignores the mode: nothing to assert.
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    assert_eq!(code, 4, "a failed file is a partial run: {events:?}");
    let errors: Vec<&Object> = events
        .iter()
        .filter(|event| kind(event) == "error")
        .collect();
    assert!(
        !errors.is_empty(),
        "the failure must be reported: {events:?}"
    );
    assert_eq!(
        errors[0].get("path").unwrap().text(),
        "sub/b.txt",
        "the error must name the path: {events:?}"
    );
    let message = errors[0].get("message").unwrap().text();
    assert!(
        message.contains("Permission denied") || message.contains("os error 13"),
        "the error must name the errno: {message}"
    );
    assert_eq!(events.last().unwrap().get("failures").unwrap().number(), 1);

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
}
