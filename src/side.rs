use crate::fsutil::{copy_atomic, hash_file, prune_empty_dirs};
use crate::model::{Entry, Hash};
use crate::scan::{entry_for, IgnoreRules, Scanner};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// One end of a pair. Everything the engine needs from a filesystem goes through
/// this, so a side can be local or a peer on the far end of a TLS connection.
pub trait Backend {
    /// Human-facing identity, used in messages.
    fn label(&self) -> &str;
    /// Next entry in component order; `None` at the end of the tree.
    fn walk(&mut self) -> io::Result<Option<Entry>>;
    fn hash(&mut self, path: &Path) -> io::Result<Hash>;
    fn stat(&mut self, path: &Path) -> io::Result<Option<Entry>>;
    /// Send the local file at `local_src` to this side at `path`, atomically.
    fn put(&mut self, path: &Path, local_src: &Path) -> io::Result<Hash>;
    /// Bring this side's `path` to the local path `local_dst`, atomically.
    fn get(&mut self, path: &Path, local_dst: &Path) -> io::Result<Hash>;
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
    pub fn new(root: &Path, rules: IgnoreRules) -> io::Result<Self> {
        Ok(LocalBackend {
            label: root.display().to_string(),
            root: root.to_path_buf(),
            scanner: Some(Scanner::new(root, rules)?),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl Backend for LocalBackend {
    fn label(&self) -> &str {
        &self.label
    }

    fn walk(&mut self) -> io::Result<Option<Entry>> {
        match self.scanner.as_mut() {
            None => Ok(None),
            Some(scanner) => match scanner.next_entry() {
                None => Ok(None),
                Some(Ok(entry)) => Ok(Some(entry)),
                Some(Err(e)) => Err(e),
            },
        }
    }

    fn hash(&mut self, path: &Path) -> io::Result<Hash> {
        hash_file(&self.root.join(path))
    }

    fn stat(&mut self, path: &Path) -> io::Result<Option<Entry>> {
        match fs::symlink_metadata(self.root.join(path)) {
            Ok(meta) => Ok(Some(entry_for(path.to_path_buf(), &meta))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn put(&mut self, path: &Path, local_src: &Path) -> io::Result<Hash> {
        copy_atomic(local_src, &self.root.join(path))
    }

    fn get(&mut self, path: &Path, local_dst: &Path) -> io::Result<Hash> {
        copy_atomic(&self.root.join(path), local_dst)
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
