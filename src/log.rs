//! Minimal leveled logging. Diagnostics go to stderr; command output stays on
//! stdout so scripts and tests keep parsing what they expect.
//!
//! Level comes from `TWIN_LOG` (error|warn|info|debug) and is raised by `-v`.
//! Default is `warn`: a run prints its summary and nothing else.

use std::sync::atomic::{AtomicU8, Ordering};

pub const ERROR: u8 = 0;
pub const WARN: u8 = 1;
pub const INFO: u8 = 2;
pub const DEBUG: u8 = 3;

static LEVEL: AtomicU8 = AtomicU8::new(WARN);

pub fn set_level(level: u8) {
    LEVEL.store(level, Ordering::Relaxed);
}

pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

pub fn set_level_from_env() {
    if let Ok(value) = std::env::var("TWIN_LOG") {
        set_level(match value.trim().to_ascii_lowercase().as_str() {
            "error" => ERROR,
            "warn" => WARN,
            "info" => INFO,
            "debug" | "trace" => DEBUG,
            _ => WARN,
        });
    }
}

pub fn enabled(level: u8) -> bool {
    level <= self::level()
}

pub fn log(level: u8, message: std::fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }
    let tag = match level {
        ERROR => "error",
        WARN => "warning",
        INFO => "info",
        _ => "debug",
    };
    eprintln!("twin: {tag}: {message}");
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => { $crate::log::log($crate::log::WARN, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => { $crate::log::log($crate::log::INFO, format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => { $crate::log::log($crate::log::DEBUG, format_args!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_gate_output_predicatably() {
        set_level(WARN);
        assert!(enabled(WARN));
        assert!(!enabled(INFO));
        set_level(DEBUG);
        assert!(enabled(DEBUG));
        set_level(WARN);
    }
}
