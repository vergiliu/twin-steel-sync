use crate::model::{BaseRow, Hash, Kind};
use rusqlite::{params, Connection};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Remembers what the two ends of a run last agreed on for every tracked path.
/// One row per path; every mutation is a single statement, so a crash between
/// two files can never leave a half-updated record.
pub struct Archive {
    conn: Connection,
}

impl Archive {
    pub fn open(path: &Path) -> io::Result<Archive> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path).map_err(to_io)?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(to_io)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS entries (
                 path              BLOB PRIMARY KEY,
                 kind              INTEGER NOT NULL,
                 size              INTEGER NOT NULL,
                 mtime_source      INTEGER NOT NULL,
                 mtime_destination INTEGER NOT NULL,
                 hash              BLOB NOT NULL
             );",
        )
        .map_err(to_io)?;
        Ok(Archive { conn })
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.count()? == 0)
    }

    pub fn count(&self) -> io::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|n| n as u64)
            .map_err(to_io)
    }

    pub fn get(&self, path: &Path) -> io::Result<Option<BaseRow>> {
        let key = path.as_os_str().as_bytes().to_vec();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT kind, size, mtime_source, mtime_destination, hash FROM entries WHERE path = ?1",
            )
            .map_err(to_io)?;
        let mut rows = stmt.query(params![key]).map_err(to_io)?;
        match rows.next().map_err(to_io)? {
            None => Ok(None),
            Some(row) => {
                let kind: i64 = row.get(0).map_err(to_io)?;
                let size: i64 = row.get(1).map_err(to_io)?;
                let mtime_source: i64 = row.get(2).map_err(to_io)?;
                let mtime_destination: i64 = row.get(3).map_err(to_io)?;
                let hash: Vec<u8> = row.get(4).map_err(to_io)?;
                if hash.len() != 32 {
                    return Err(io::Error::other("archive holds a malformed hash"));
                }
                let mut h: Hash = [0u8; 32];
                h.copy_from_slice(&hash);
                Ok(Some(BaseRow {
                    kind: Kind::from_sql(kind),
                    size: size.max(0) as u64,
                    mtime_source,
                    mtime_destination,
                    hash: h,
                }))
            }
        }
    }

    pub fn put(&self, path: &Path, row: &BaseRow) -> io::Result<()> {
        self.conn
            .execute(
                "INSERT INTO entries (path, kind, size, mtime_source, mtime_destination, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(path) DO UPDATE SET
                     kind=?2, size=?3, mtime_source=?4, mtime_destination=?5, hash=?6",
                params![
                    path.as_os_str().as_bytes().to_vec(),
                    row.kind.to_sql(),
                    row.size as i64,
                    row.mtime_source,
                    row.mtime_destination,
                    row.hash.to_vec(),
                ],
            )
            .map(|_| ())
            .map_err(to_io)
    }

    /// `PRAGMA integrity_check`: the one honest answer to "is this file sane?".
    pub fn integrity(&self) -> io::Result<String> {
        self.conn
            .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
            .map_err(to_io)
    }

    pub fn delete(&self, path: &Path) -> io::Result<()> {
        self.conn
            .execute(
                "DELETE FROM entries WHERE path = ?1",
                params![path.as_os_str().as_bytes().to_vec()],
            )
            .map(|_| ())
            .map_err(to_io)
    }

    /// Stream every remembered path without loading the archive into memory.
    pub fn for_each(
        &self,
        mut visit: impl FnMut(&Path, &BaseRow) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, kind, size, mtime_source, mtime_destination, hash FROM entries")
            .map_err(to_io)?;
        let mut rows = stmt.query([]).map_err(to_io)?;
        while let Some(row) = rows.next().map_err(to_io)? {
            let raw: Vec<u8> = row.get(0).map_err(to_io)?;
            let kind: i64 = row.get(1).map_err(to_io)?;
            let size: i64 = row.get(2).map_err(to_io)?;
            let mtime_source: i64 = row.get(3).map_err(to_io)?;
            let mtime_destination: i64 = row.get(4).map_err(to_io)?;
            let hash: Vec<u8> = row.get(5).map_err(to_io)?;
            if hash.len() != 32 {
                return Err(io::Error::other("archive holds a malformed hash"));
            }
            let mut h: Hash = [0u8; 32];
            h.copy_from_slice(&hash);
            let path = PathBuf::from(OsString::from_vec(raw));
            visit(
                &path,
                &BaseRow {
                    kind: Kind::from_sql(kind),
                    size: size.max(0) as u64,
                    mtime_source,
                    mtime_destination,
                    hash: h,
                },
            )?;
        }
        Ok(())
    }
}

fn to_io(err: rusqlite::Error) -> io::Error {
    io::Error::other(format!("archive: {err}"))
}

/// Archive locations live outside any synced tree, keyed by the pair itself.
///
/// A pair is directional: the source and the destination are named in that
/// order, so the same two directories in the other direction are a different
/// pair with a different archive. The version tag keeps archives written by
/// an older layout from being read as if they were current.
pub fn archive_path(archive_dir: &Path, source: &str, destination: &str) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"twin-archive-v2");
    hasher.update(b"\0");
    hasher.update(source.as_bytes());
    hasher.update(b"\0");
    hasher.update(destination.as_bytes());
    let digest = hasher.finalize();
    let id = digest.to_hex().to_string();
    archive_dir.join(format!("{}.db", &id[..16]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_survive_round_trips_and_non_utf8_paths() {
        let dir = tempfile::tempdir().unwrap();
        let archive = Archive::open(&dir.path().join("a.db")).unwrap();
        assert!(archive.is_empty().unwrap());

        let path = PathBuf::from(OsString::from_vec(b"caf\xe9-\xff.bin".to_vec()));
        let row = BaseRow {
            kind: Kind::File,
            size: 7,
            mtime_source: 123,
            mtime_destination: 456,
            hash: [9u8; 32],
        };
        archive.put(&path, &row).unwrap();
        assert_eq!(archive.get(&path).unwrap(), Some(row.clone()));
        assert!(!archive.is_empty().unwrap());

        let mut seen = Vec::new();
        archive
            .for_each(|p, r| {
                seen.push((p.to_path_buf(), r.clone()));
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, vec![(path.clone(), row)]);

        archive.delete(&path).unwrap();
        assert_eq!(archive.get(&path).unwrap(), None);
        assert!(archive.is_empty().unwrap());
    }

    #[test]
    fn pair_id_is_stable_and_distinguishes_the_direction() {
        let dir = tempfile::tempdir().unwrap();
        let a = archive_path(dir.path(), "/x/one", "/y/two");
        let b = archive_path(dir.path(), "/x/one", "/y/two");
        let c = archive_path(dir.path(), "/x/one", "/y/three");
        let reversed = archive_path(dir.path(), "/y/two", "/x/one");
        let remote = archive_path(dir.path(), "/x/one", "mini:9443");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(
            a, reversed,
            "the same two roots in the other direction are another pair"
        );
        assert_ne!(a, remote);
    }
}
