use crate::fsutil::{
    copy_atomic, copy_resumable, hash_file, prune_empty_dirs, temp_file_name, ErrCtx,
};
use crate::model::{Entry, Hash, PathFailure};
use crate::scan::{entry_for, IgnoreRules, Scanner};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One end of a pair. Everything the engine needs from a filesystem goes through
/// this, so a side can be local or a peer on the far end of a TLS connection.
pub trait Backend {
    /// Human-facing identity, used in messages.
    fn label(&self) -> &str;
    /// The directory this end lives in, when it is a directory on this
    /// machine. A peer on the far end of a connection has none: its content
    /// only reaches this machine through a transfer.
    fn local_root(&self) -> Option<&Path>;
    /// Next entry in component order; `None` at the end of the tree. A path
    /// that cannot be read is reported on its own, not as a failure of the
    /// whole walk.
    fn walk(&mut self) -> io::Result<Option<Result<Entry, PathFailure>>>;
    fn hash(&mut self, path: &Path) -> io::Result<Hash>;
    fn stat(&mut self, path: &Path) -> io::Result<Option<Entry>>;
    /// Send the local file at `local_src` to this side at `path`, atomically.
    /// With `resume`, a partial transfer left at the destination is continued
    /// instead of started over.
    fn put(&mut self, path: &Path, local_src: &Path, resume: bool) -> io::Result<Hash>;
    /// Bring this side's `path` to the local path `local_dst`, atomically.
    /// With `resume`, a partial transfer left at the destination is continued
    /// instead of started over.
    fn get(&mut self, path: &Path, local_dst: &Path, resume: bool) -> io::Result<Hash>;
    fn remove(&mut self, path: &Path) -> io::Result<()>;
    /// Release any resources; called once per run.
    fn finish(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub struct LocalBackend {
    label: String,
    root: PathBuf,
    scanner: Option<Scanner>,
}

impl LocalBackend {
    /// A backend that never walks into the given absolute directories.
    pub fn excluding(root: &Path, rules: IgnoreRules, excluded: Vec<PathBuf>) -> io::Result<Self> {
        Ok(LocalBackend {
            label: root.display().to_string(),
            root: root.to_path_buf(),
            scanner: Some(Scanner::with_excluded(root, rules, excluded)?),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// The temporary file that holds a transfer in flight for `dst`. Its name is
/// derived from the destination, so the next run finds what this one left.
pub fn temp_for(dst: &Path) -> PathBuf {
    match dst.parent() {
        Some(parent) => parent.join(temp_file_name(dst)),
        None => PathBuf::from(temp_file_name(dst)),
    }
}

impl Backend for LocalBackend {
    fn label(&self) -> &str {
        &self.label
    }

    fn local_root(&self) -> Option<&Path> {
        Some(&self.root)
    }

    fn walk(&mut self) -> io::Result<Option<Result<Entry, PathFailure>>> {
        match self.scanner.as_mut() {
            None => Ok(None),
            Some(scanner) => Ok(scanner.next_entry()),
        }
    }

    fn hash(&mut self, path: &Path) -> io::Result<Hash> {
        let abs = self.root.join(path);
        hash_file(&abs).ctx(|| format!("hashing {}", abs.display()))
    }

    fn stat(&mut self, path: &Path) -> io::Result<Option<Entry>> {
        match fs::symlink_metadata(self.root.join(path)) {
            Ok(meta) => Ok(Some(entry_for(path.to_path_buf(), &meta))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put(&mut self, path: &Path, local_src: &Path, resume: bool) -> io::Result<Hash> {
        let dst = self.root.join(path);
        let tmp = temp_for(&dst);
        if resume {
            copy_resumable(local_src, &dst, &tmp)
        } else {
            copy_atomic(local_src, &dst, &tmp)
        }
    }

    fn get(&mut self, path: &Path, local_dst: &Path, resume: bool) -> io::Result<Hash> {
        let src = self.root.join(path);
        let tmp = temp_for(local_dst);
        if resume {
            copy_resumable(&src, local_dst, &tmp)
        } else {
            copy_atomic(&src, local_dst, &tmp)
        }
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        let target = self.root.join(path);
        match fs::remove_file(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if let Some(parent) = target.parent() {
            prune_empty_dirs(&self.root, parent);
        }
        Ok(())
    }
}

/// Reject anything that could escape the served root. The far end is untrusted
/// input: a client must not be able to ask for `../../etc/passwd`, an absolute
/// path, or a path that resolves through a symlinked ancestor.
pub fn safe_join(root: &Path, rel: &Path) -> io::Result<PathBuf> {
    if rel.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("absolute path refused: {}", rel.display()),
        ));
    }
    let mut out = root.to_path_buf();
    for component in rel.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("path escapes the synced root: {}", rel.display()),
                ))
            }
        }
    }
    // Every existing ancestor must be a real directory, not a symlink.
    let mut probe = root.to_path_buf();
    if let Some(parent) = rel.parent() {
        for component in parent.components() {
            if let std::path::Component::Normal(part) = component {
                probe.push(part);
                match fs::symlink_metadata(&probe) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!("refusing to write through a symlink: {}", probe.display()),
                        ))
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_that_escape_the_root_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for evil in ["../outside", "a/../../outside", "/etc/passwd", "/"] {
            let err = safe_join(root, Path::new(evil));
            assert!(err.is_err(), "{evil} should be refused");
        }
        // `/./` is normalised away by Path itself, so this stays inside the root,
        // and `~` is only a shell convention — it is a literal directory name here.
        assert!(safe_join(root, Path::new("a/./b")).is_ok());
        assert!(safe_join(root, Path::new("~/x")).is_ok());
        assert_eq!(
            safe_join(root, Path::new("a/b.txt")).unwrap(),
            root.join("a/b.txt")
        );
        assert_eq!(safe_join(root, Path::new("")).unwrap(), root);
    }

    #[test]
    fn symlinked_ancestors_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let err = safe_join(&root, Path::new("link/payload.txt"));
        assert!(err.is_err(), "writing through a symlink must be refused");
        // a plain path under the root still works
        assert!(safe_join(&root, Path::new("plain/payload.txt")).is_ok());
    }
}
