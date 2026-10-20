//! Keeps the version that is about to be replaced or removed.
//!
//! The backup lands on the client, whatever the transfer runs in: the far side
//! may be another machine, so the old version has to be fetched before it is
//! overwritten. The layout under the backup directory mirrors the path under
//! the synced root, and the file name carries a timestamp, so a backup is
//! never silently overwritten either.

use crate::fsutil::ErrCtx;
use crate::model::Kind;
use crate::side::Backend;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where the backup of `rel` goes: the same path under the backup directory,
/// with a timestamp on the file name.
pub fn backup_path(backup_dir: &Path, rel: &Path, stamp: &str) -> PathBuf {
    let name = rel
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let parent = rel.parent().unwrap_or(Path::new(""));
    backup_dir.join(parent).join(format!("{name}.bak-{stamp}"))
}

/// The same path with a counter on the end, so a backup is never overwritten.
pub fn unique_path(candidate: &Path) -> PathBuf {
    if !candidate.exists() {
        return candidate.to_path_buf();
    }
    let text = candidate.to_string_lossy().to_string();
    for n in 1..1000 {
        let next = PathBuf::from(format!("{text}-{n}"));
        if !next.exists() {
            return next;
        }
    }
    candidate.to_path_buf()
}

/// Copy the version that is about to be replaced into the backup directory.
///
/// Returns the path of the backup, or `None` when there is nothing to keep:
/// a file that does not exist yet, or one the engine skips anyway.
pub fn take(
    backend: &mut dyn Backend,
    rel: &Path,
    backup_dir: &Path,
    stamp: &str,
) -> io::Result<Option<PathBuf>> {
    take_from(backend, rel, backup_dir, stamp)
}

/// Keep the version one side holds at `rel`.
fn take_from(
    backend: &mut dyn Backend,
    rel: &Path,
    backup_dir: &Path,
    stamp: &str,
) -> io::Result<Option<PathBuf>> {
    let Some(entry) = backend.stat(rel)? else {
        return Ok(None);
    };
    // Only regular files are worth keeping; the engine skips the rest anyway.
    if entry.kind != Kind::File {
        return Ok(None);
    }
    let target = unique_path(&backup_path(backup_dir, rel, stamp));
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).ctx(|| format!("creating {}", parent.display()))?;
    }
    backend
        .get(rel, &target, false)
        .ctx(|| format!("backing up {} into {}", rel.display(), target.display()))?;
    Ok(Some(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_keeps_the_path_and_gets_a_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let backup = backup_path(dir.path(), Path::new("a/b/c.txt"), "20260101-120000");
        assert_eq!(backup, dir.path().join("a/b/c.txt.bak-20260101-120000"));
    }

    #[test]
    fn a_second_backup_never_overwrites_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let first = backup_path(dir.path(), Path::new("c.txt"), "20260101-120000");
        fs::write(&first, b"old").unwrap();
        let second = unique_path(&first);
        assert_ne!(second, first);
        assert!(second.to_string_lossy().ends_with("-1"));
        fs::write(&second, b"old too").unwrap();
        let third = unique_path(&first);
        assert!(third.to_string_lossy().ends_with("-2"));
        assert_eq!(fs::read(&first).unwrap(), b"old");
    }
}
