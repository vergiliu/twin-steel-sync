use std::cmp::Ordering;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

impl Kind {
    pub fn to_sql(self) -> i64 {
        match self {
            Kind::File => 0,
            Kind::Dir => 1,
            Kind::Symlink => 2,
            Kind::Other => 3,
        }
    }

    pub fn from_sql(v: i64) -> Kind {
        match v {
            0 => Kind::File,
            1 => Kind::Dir,
            2 => Kind::Symlink,
            _ => Kind::Other,
        }
    }
}

/// A path as seen on one side, before any hashing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i64,
}

/// Which end of a run a path belongs to.
///
/// A run has exactly two ends: the source, which is read, and the
/// destination, which is written. The content always flows from the first to
/// the second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Source,
    Destination,
}

/// Last state the two ends agreed on, as stored in the archive.
///
/// Metadata is remembered per end: the same content can carry different mtimes
/// on the two sides, and the fast path must match each end against its own
/// recorded value or every run would rewrite the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRow {
    pub kind: Kind,
    pub size: u64,
    pub hash: Hash,
    pub mtime_source: i64,
    pub mtime_destination: i64,
}

/// A failure that belongs to exactly one path. The run reports it, counts it
/// and carries on with the other paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFailure {
    pub path: PathBuf,
    pub message: String,
}

/// One unit of planned work. A run reports exactly these, dry or real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Put the source's content at the destination.
    Copy {
        path: PathBuf,
        size: u64,
        new_file: bool,
    },
    /// The source does not have it and the destination must not keep it.
    Delete {
        path: PathBuf,
    },
    /// The two ends already agree; only the archive row is stale.
    Adopt {
        path: PathBuf,
        row: BaseRow,
    },
    /// Neither end has it any more: drop the remembered row.
    Forget {
        path: PathBuf,
    },
    Skip {
        path: PathBuf,
        reason: &'static str,
    },
}

impl Action {
    /// The path this action is about.
    pub fn path(&self) -> &Path {
        match self {
            Action::Copy { path, .. }
            | Action::Delete { path }
            | Action::Adopt { path, .. }
            | Action::Forget { path }
            | Action::Skip { path, .. } => path,
        }
    }

    /// The word the report uses for this action. The same words the text
    /// output uses, so both reports can be read side by side.
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Copy { new_file: true, .. } => "create",
            Action::Copy {
                new_file: false, ..
            } => "update",
            Action::Delete { .. } => "delete",
            Action::Skip { .. } => "skip",
            Action::Forget { .. } => "forget",
            Action::Adopt { .. } => "adopt",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Action::Copy {
                path,
                size,
                new_file,
            } => format!(
                "{} {} ({} B)",
                if *new_file { "create" } else { "update" },
                path.display(),
                size
            ),
            Action::Delete { path } => format!("delete {}", path.display()),
            Action::Adopt { path, .. } => format!("archive-only refresh of {}", path.display()),
            Action::Forget { path } => format!("forget {} (gone on both sides)", path.display()),
            Action::Skip { path, reason } => format!("skip {} ({})", path.display(), reason),
        }
    }
}

/// Ordering used for the merge walk: components compared lexicographically,
/// a path that is a prefix of another sorts first. Depth-first traversal with
/// children sorted by name yields exactly this order on both sides.
pub fn cmp_path(a: &Path, b: &Path) -> Ordering {
    let mut ai = a.components();
    let mut bi = b.components();
    loop {
        match (ai.next(), bi.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let xs = x.as_os_str().as_bytes();
                let ys = y.as_os_str().as_bytes();
                match xs.cmp(ys) {
                    Ordering::Equal => continue,
                    other => return other,
                }
            }
        }
    }
}

/// A path is considered unchanged when size and mtime agree with what this end
/// last agreed to. Hash equality is what actually decides; this is only a fast path.
pub fn metadata_matches(entry: &Entry, base: &BaseRow, role: Role) -> bool {
    let mtime = match role {
        Role::Source => base.mtime_source,
        Role::Destination => base.mtime_destination,
    };
    entry.size == base.size && entry.mtime_ns == mtime && entry.kind == base.kind
}

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn path_order_is_component_wise() {
        let mut v: Vec<PathBuf> = ["b/x", "a.txt", "a/b/c", "a-b", "a", "a/b"]
            .iter()
            .map(PathBuf::from)
            .collect();
        v.sort_by(|x, y| cmp_path(x, y));
        let got: Vec<String> = v.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(got, vec!["a", "a/b", "a/b/c", "a-b", "a.txt", "b/x"]);
    }

    #[test]
    fn hash_bytes_round_trip_through_sql_kinds() {
        for k in [Kind::File, Kind::Dir, Kind::Symlink, Kind::Other] {
            assert_eq!(Kind::from_sql(k.to_sql()), k);
        }
    }
}
