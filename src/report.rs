//! How a run talks to the user.
//!
//! Three faces of the same run: the plain text report that has always been
//! there, the JSON event stream (`--json`) that a program can read, and the
//! progress line that tells a human how far along the run is. The text report
//! is the default and does not change; the other two are additions.

use crate::engine::Summary;
use crate::json::Object;
use crate::model::Action;
use std::io::{self, Write};
use std::path::{Component, Path};
use std::time::Instant;

/// A path as the reports show it: relative to the synced root, with `/`
/// separators.
pub fn relative(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        if let Component::Normal(part) = component {
            parts.push(part.to_string_lossy().to_string());
        }
    }
    parts.join("/")
}

/// Writes the report of a run, in text or as JSON events.
pub struct Reporter<'a> {
    out: &'a mut dyn Write,
    json: bool,
    quiet: bool,
    verbose: bool,
    /// Where the content comes from, and where it goes.
    source: String,
    destination: String,
    progress: Progress,
}

impl<'a> Reporter<'a> {
    pub fn new(
        out: &'a mut dyn Write,
        opts: &crate::engine::RunOptions,
        source: &str,
        destination: &str,
    ) -> Reporter<'a> {
        Reporter {
            out,
            json: opts.json,
            quiet: opts.quiet,
            verbose: opts.verbose,
            source: source.to_string(),
            destination: destination.to_string(),
            progress: Progress::new(opts.tty, !opts.json && !opts.quiet),
        }
    }

    pub fn is_json(&self) -> bool {
        self.json
    }

    /// The raw output, for the lines that are not part of the report.
    pub fn out(&mut self) -> &mut dyn Write {
        self.out
    }

    /// How many bytes the run intends to move: the progress needs a total.
    pub fn set_total(&mut self, total: u64) {
        self.progress.set_total(total);
    }

    /// The plan. In text this is the indented list the report has always
    /// shown; in JSON it is one event per action.
    pub fn plan(&mut self, actions: &[Action]) -> io::Result<()> {
        for action in actions {
            if self.json {
                let event = plan_event(action);
                writeln!(self.out, "{event}")?;
                continue;
            }
            if matches!(
                action,
                Action::Adopt { .. } | Action::Forget { .. } | Action::Skip { .. }
            ) && !self.verbose
            {
                continue;
            }
            writeln!(self.out, "  {}", action.describe())?;
        }
        Ok(())
    }

    /// The skips, as events of their own. In text they are part of the plan
    /// and of the closing report.
    pub fn skip_events(&mut self, actions: &[Action]) -> io::Result<()> {
        if !self.json {
            return Ok(());
        }
        for action in actions {
            if let Action::Skip { path, reason } = action {
                let mut object = Object::new("skip");
                object.text("path", &relative(path));
                object.text("reason", reason);
                writeln!(self.out, "{}", object.finish())?;
            }
        }
        Ok(())
    }

    /// The closing report of the skips, in text.
    pub fn skip_report(&mut self, actions: &[Action]) -> io::Result<()> {
        if self.json {
            return Ok(());
        }
        let mut reasons: std::collections::BTreeMap<&'static str, u64> =
            std::collections::BTreeMap::new();
        for action in actions {
            if let Action::Skip { reason, .. } = action {
                *reasons.entry(reason).or_default() += 1;
            }
        }
        for (reason, count) in reasons {
            writeln!(self.out, "{count} skipped: {reason}")?;
        }
        Ok(())
    }

    /// A transfer is about to start.
    pub fn transfer_start(&mut self, path: &Path, size: u64) -> io::Result<()> {
        if self.json {
            let event = transfer_event("start", path, size);
            writeln!(self.out, "{event}")?;
        }
        self.progress.file_start(path);
        Ok(())
    }

    /// A transfer is done.
    pub fn transfer_done(&mut self, path: &Path, size: u64) -> io::Result<()> {
        if self.json {
            let event = transfer_event("done", path, size);
            writeln!(self.out, "{event}")?;
        }
        self.progress.file_done(path, size);
        Ok(())
    }

    /// A file could not be done.
    pub fn action_error(&mut self, action: &Action, message: &str) -> io::Result<()> {
        if self.json {
            let mut object = Object::new("error");
            object.text("path", &relative(action.path()));
            object.text("message", message);
            writeln!(self.out, "{}", object.finish())?;
        } else {
            writeln!(self.out, "error: {} :: {message}", action.describe())?;
        }
        Ok(())
    }

    /// A path could not even be planned.
    pub fn path_error(&mut self, path: &Path, message: &str) -> io::Result<()> {
        if self.json {
            let mut object = Object::new("error");
            object.text("path", &relative(path));
            object.text("message", message);
            writeln!(self.out, "{}", object.finish())?;
        } else {
            writeln!(self.out, "error: {} :: {message}", path.display())?;
        }
        Ok(())
    }

    /// Something worth saying that is not about one path.
    pub fn notice(&mut self, message: &str) -> io::Result<()> {
        if self.json {
            let mut object = Object::new("error");
            object.text("path", "");
            object.text("message", message);
            writeln!(self.out, "{}", object.finish())?;
        } else {
            writeln!(self.out, "{message}")?;
        }
        Ok(())
    }

    /// The closing summary. In JSON it is the last line of the stream.
    pub fn summary(&mut self, summary: &Summary) -> io::Result<()> {
        if !self.json {
            return Ok(());
        }
        let mut object = Object::new("summary");
        object.text("source", &self.source);
        object.text("destination", &self.destination);
        object.number("created", summary.created);
        object.number("updated", summary.updated);
        object.number("deleted", summary.deleted);
        object.number("skipped", summary.skipped);
        object.number("failures", summary.failures);
        object.number("unchanged", summary.unchanged);
        writeln!(self.out, "{}", object.finish())?;
        Ok(())
    }

    /// The human summary line, in text.
    pub fn text_summary(&mut self, summary: &Summary) -> io::Result<()> {
        if self.json || self.quiet {
            return Ok(());
        }
        writeln!(
            self.out,
            "created {}, updated {}, deleted {}, skipped {}, failures {}, unchanged {}",
            summary.created,
            summary.updated,
            summary.deleted,
            summary.skipped,
            summary.failures,
            summary.unchanged
        )?;
        Ok(())
    }

    /// The end of the run: a terminal line that was drawn in place needs its
    /// newline.
    pub fn finish(&mut self) -> io::Result<()> {
        self.progress.finish()
    }
}

fn plan_event(action: &Action) -> String {
    let mut object = Object::new("plan");
    object.text("action", action.kind());
    object.text("path", &relative(action.path()));
    if let Action::Copy { size, .. } = action {
        object.number("size", *size);
    }
    object.finish()
}

fn transfer_event(phase: &str, path: &Path, size: u64) -> String {
    let mut object = Object::new("transfer");
    object.text("phase", phase);
    object.text("path", &relative(path));
    object.number("size", size);
    object.finish()
}

/// How far along the run is.
///
/// On a terminal the line is rewritten in place; everywhere else there is one
/// line per finished file, which is what a log wants. The progress goes to
/// standard error: standard output carries the report, and the two must not
/// be mixed.
pub struct Progress {
    enabled: bool,
    tty: bool,
    total: u64,
    done: u64,
    started: Instant,
    current: Option<String>,
    drawn: bool,
}

impl Progress {
    pub fn new(tty: bool, enabled: bool) -> Progress {
        Progress {
            enabled,
            tty,
            total: 0,
            done: 0,
            started: Instant::now(),
            current: None,
            drawn: false,
        }
    }

    /// How many bytes the run intends to move.
    pub fn set_total(&mut self, total: u64) {
        self.total = total;
    }

    pub fn file_start(&mut self, path: &Path) {
        if !self.enabled {
            return;
        }
        self.current = Some(relative(path));
        self.draw();
    }

    pub fn file_done(&mut self, path: &Path, size: u64) {
        if !self.enabled {
            return;
        }
        self.done += size;
        self.current = None;
        if self.tty {
            self.draw();
        } else {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "copied {} ({})", relative(path), human_bytes(size));
        }
    }

    /// The end of the run: close the line that was drawn in place.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.enabled && self.tty && self.drawn {
            let mut stderr = std::io::stderr();
            writeln!(stderr)?;
        }
        Ok(())
    }

    fn draw(&mut self) {
        if !self.tty {
            return;
        }
        let line = self.line();
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\r{line}");
        let _ = stderr.flush();
        self.drawn = true;
    }

    fn line(&self) -> String {
        let percent = match self.total {
            0 => 100,
            total => self.done.saturating_mul(100) / total,
        };
        let speed = self.speed();
        let remaining = self.total.saturating_sub(self.done);
        // Without a rate there is no honest estimate: say so.
        let eta = if speed > 0.0 {
            human_duration((remaining as f64 / speed).round() as u64)
        } else {
            "-".to_string()
        };
        let speed_text = if speed > 0.0 {
            format!("{}/s", human_bytes(speed as u64))
        } else {
            "-".to_string()
        };
        let current = self.current.clone().unwrap_or_default();
        format!(
            "{percent:3}%  {}/{}  {speed_text}  ETA {eta}  {current}",
            human_bytes(self.done),
            human_bytes(self.total)
        )
    }

    /// The running average, in bytes per second.
    fn speed(&self) -> f64 {
        let seconds = self.started.elapsed().as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        self.done as f64 / seconds
    }
}

/// A number of bytes, in the unit a human reads at a glance.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// A duration, as hours, minutes and seconds.
pub fn human_duration(seconds: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_and_use_slashes() {
        assert_eq!(relative(Path::new("a/b/c.txt")), "a/b/c.txt");
        assert_eq!(relative(Path::new("c.txt")), "c.txt");
    }

    #[test]
    fn bytes_and_durations_read_like_a_person_wrote_them() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MB");
        assert_eq!(human_duration(0), "00:00:00");
        assert_eq!(human_duration(65), "00:01:05");
        assert_eq!(human_duration(3725), "01:02:05");
    }

    #[test]
    fn a_progress_line_without_a_rate_says_it_does_not_know() {
        let progress = Progress::new(true, true);
        let line = progress.line();
        assert!(line.contains("ETA -"), "{line}");
        assert!(line.contains(" - "), "{line}");
    }
}
