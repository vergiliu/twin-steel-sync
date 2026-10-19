use crate::fsutil::mtime_ns;
use crate::model::{Entry, Kind, PathFailure};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Patterns that are almost never meant to sync, on either platform.
const DEFAULT_IGNORES: &[&str] = &[
    ".DS_Store",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    "lost+found",
    ".twin",
];

#[derive(Clone)]
pub struct IgnoreRules {
    matcher: Option<Gitignore>,
    defaults: bool,
}

/// The `.twinignore` lines plus any command-line patterns, in the order they
/// apply. The far end of a remote pair receives exactly this list.
pub fn patterns_for(root: &Path, extra_excludes: &[String]) -> io::Result<Vec<String>> {
    let mut patterns = Vec::new();
    let ignore_file = root.join(".twinignore");
    if ignore_file.is_file() {
        let text = fs::read_to_string(&ignore_file)
            .map_err(|e| io::Error::other(format!("cannot read {}: {e}", ignore_file.display())))?;
        patterns.extend(text.lines().map(str::to_string));
    }
    patterns.extend(extra_excludes.iter().cloned());
    Ok(patterns)
}

impl IgnoreRules {
    pub fn load(root: &Path, defaults: bool, extra_excludes: &[String]) -> io::Result<Self> {
        let patterns = patterns_for(root, extra_excludes)?;
        Self::from_patterns(root, defaults, &patterns)
    }

    /// Same rules on both sides: the client sends exactly these patterns to the
    /// far end rather than letting each machine read its own `.twinignore`.
    pub fn from_patterns(root: &Path, defaults: bool, patterns: &[String]) -> io::Result<Self> {
        let mut builder = GitignoreBuilder::new(root);
        for pattern in patterns {
            if pattern.trim().is_empty() {
                continue;
            }
            builder
                .add_line(None, pattern)
                .map_err(|e| io::Error::other(format!("bad ignore pattern {pattern:?}: {e}")))?;
        }
        let matcher = match builder.build() {
            Ok(m) => Some(m),
            Err(e) => return Err(io::Error::other(format!("bad ignore rules: {e}"))),
        };
        Ok(IgnoreRules { matcher, defaults })
    }

    pub fn matches(&self, rel: &Path, is_dir: bool) -> bool {
        if self.defaults {
            if let Some(name) = rel.file_name() {
                if is_default_ignored(name) {
                    return true;
                }
            }
        }
        match &self.matcher {
            Some(m) => m.matched(rel, is_dir).is_ignore(),
            None => false,
        }
    }
}

fn is_default_ignored(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    if DEFAULT_IGNORES.iter().any(|d| d.as_bytes() == bytes) {
        return true;
    }
    bytes.starts_with(b".twin-tmp-")
        || bytes.starts_with(b"._")
        || bytes.ends_with(b"~")
        || bytes.ends_with(b".swp")
}

struct Frame {
    dir_rel: PathBuf,
    children: Vec<(OsString, bool)>,
    idx: usize,
}

/// Depth-first walk that yields entries in `cmp_path` order and never keeps more
/// than one directory's worth of names in memory.
pub struct Scanner {
    root: PathBuf,
    /// The root as an absolute path, so the excluded directories can be
    /// compared with it whatever the caller passed in.
    root_abs: PathBuf,
    rules: IgnoreRules,
    /// Directories that are never walked: the backup directory lives here, and
    /// what it holds must not travel back into the pair.
    excluded: Vec<PathBuf>,
    stack: Vec<Frame>,
}

impl Scanner {
    pub fn new(root: &Path, rules: IgnoreRules) -> io::Result<Self> {
        Self::with_excluded(root, rules, Vec::new())
    }

    /// A scanner that never descends into the given absolute directories.
    pub fn with_excluded(
        root: &Path,
        rules: IgnoreRules,
        excluded: Vec<PathBuf>,
    ) -> io::Result<Self> {
        let children = read_children(root)?;
        Ok(Scanner {
            root: root.to_path_buf(),
            root_abs: absolute(root),
            rules,
            excluded,
            stack: vec![Frame {
                dir_rel: PathBuf::new(),
                children,
                idx: 0,
            }],
        })
    }

    /// The next entry, or the failure of the one path that could not be read.
    /// A path that cannot be read is not a reason to abandon the whole walk.
    pub fn next_entry(&mut self) -> Option<Result<Entry, PathFailure>> {
        loop {
            let top = self.stack.len().checked_sub(1)?;
            if self.stack[top].idx >= self.stack[top].children.len() {
                self.stack.pop();
                continue;
            }
            let (name, is_dir) = self.stack[top].children[self.stack[top].idx].clone();
            self.stack[top].idx += 1;
            let rel = self.stack[top].dir_rel.join(&name);
            if self.rules.matches(&rel, is_dir) {
                continue;
            }
            let abs = self.root.join(&rel);
            if self.is_excluded(&rel) {
                continue;
            }
            let meta = match fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(e) => {
                    return Some(Err(PathFailure {
                        path: rel,
                        message: format!("reading {}: {e}", abs.display()),
                    }))
                }
            };
            let kind = kind_of(&meta);

            if kind == Kind::Dir {
                match read_children(&abs) {
                    Ok(children) => self.stack.push(Frame {
                        dir_rel: rel.clone(),
                        children,
                        idx: 0,
                    }),
                    Err(e) => {
                        return Some(Err(PathFailure {
                            path: rel,
                            message: format!("listing {}: {e}", abs.display()),
                        }))
                    }
                }
            }

            return Some(Ok(entry_for(rel, &meta)));
        }
    }

    fn is_excluded(&self, rel: &Path) -> bool {
        if self.excluded.is_empty() {
            return false;
        }
        let abs = self.root_abs.join(rel);
        self.excluded.iter().any(|dir| abs.starts_with(dir))
    }
}

/// An absolute, normalized version of a path, so two paths can be compared.
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    }
}

/// Classify and describe a path the way both sides must agree on.
pub fn entry_for(path: PathBuf, meta: &fs::Metadata) -> Entry {
    let kind = kind_of(meta);
    Entry {
        path,
        kind,
        size: if kind == Kind::File { meta.len() } else { 0 },
        mtime_ns: mtime_ns(meta),
    }
}

fn kind_of(meta: &fs::Metadata) -> Kind {
    let file_type = meta.file_type();
    if file_type.is_dir() {
        Kind::Dir
    } else if file_type.is_file() {
        Kind::File
    } else if file_type.is_symlink() {
        Kind::Symlink
    } else {
        Kind::Other
    }
}

fn read_children(dir: &Path) -> io::Result<Vec<(OsString, bool)>> {
    let mut children: Vec<(OsString, bool)> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        children.push((entry.file_name(), is_dir));
    }
    children.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn scan(root: &Path, defaults: bool, excludes: &[String]) -> Vec<String> {
        let rules = IgnoreRules::load(root, defaults, excludes).unwrap();
        let mut scanner = Scanner::new(root, rules).unwrap();
        let mut out = Vec::new();
        while let Some(entry) = scanner.next_entry() {
            out.push(entry.unwrap().path.display().to_string());
        }
        out
    }

    #[test]
    fn walk_is_deterministic_and_prunes_ignored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("src/deep")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("src/deep/file.rs"), b"x").unwrap();
        fs::write(root.join("target/debug/junk"), b"x").unwrap();
        fs::write(root.join("readme.md"), b"x").unwrap();
        fs::write(root.join("notes~"), b"x").unwrap();
        fs::write(root.join(".DS_Store"), b"x").unwrap();
        fs::write(root.join(".twinignore"), b"target/\n").unwrap();

        let got = scan(root, true, &[]);
        let paths: BTreeSet<&str> = got.iter().map(|s| s.as_str()).collect();
        assert!(paths.contains("src"));
        assert!(paths.contains("src/deep"));
        assert!(paths.contains("src/deep/file.rs"));
        assert!(paths.contains("readme.md"));
        assert!(
            !paths.iter().any(|p| p.starts_with("target")),
            "ignored dir must be pruned: {got:?}"
        );
        assert!(
            !paths.contains(".DS_Store"),
            "default ignore missing: {got:?}"
        );
        assert!(!paths.contains("notes~"), "default ignore missing: {got:?}");
        assert_eq!(
            got,
            vec![
                ".twinignore",
                "readme.md",
                "src",
                "src/deep",
                "src/deep/file.rs",
            ],
            "walk order must be component-wise"
        );
    }

    #[test]
    fn excludes_from_the_command_line_apply() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("a.log"), b"x").unwrap();
        fs::write(root.join("b.txt"), b"x").unwrap();
        let got = scan(root, true, &["*.log".to_string()]);
        assert_eq!(got, vec!["b.txt"]);
    }
}
