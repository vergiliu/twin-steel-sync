//! Wire protocol between the local `twin` and the `twin --serve` process on the
//! far end of a TLS connection. Frames are length-prefixed, paths travel as raw
//! bytes (Linux allows anything else), and file content flows in bounded chunks.

use crate::fsutil::{hash_file, mtime_ns, DirFlush, ErrCtx, Fsync};
use crate::model::{Entry, Hash, Kind};
use crate::scan::{entry_for, IgnoreRules, Scanner};
use crate::side::safe_join;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: u16 = 3;
pub const AGENT: &str = concat!("twin ", env!("CARGO_PKG_VERSION"));
const CHUNK: usize = 256 * 1024;
const MAX_FRAME: usize = 8 * 1024 * 1024;

const HELLO: u8 = 1;
const RULES: u8 = 2;
const LIST: u8 = 3;
const ENTRY: u8 = 4;
const END_LIST: u8 = 5;
const HASH: u8 = 6;
const GET: u8 = 7;
const DATA_BEGIN: u8 = 8;
const PUSH: u8 = 9;
const DELETE: u8 = 10;
const ACK: u8 = 11;
const BYE: u8 = 12;
const STAT: u8 = 13;
const STAT_REPLY: u8 = 14;
const CHUNK_FRAME: u8 = 15;
const END_FRAME: u8 = 16;
/// A GET that starts at a byte offset, so an interrupted transfer can be
/// continued instead of started over.
const GET_RANGE: u8 = 17;
/// A PUSH that continues a partial transfer at a byte offset.
const PUSH_RANGE: u8 = 18;
/// A question about how much of a file the far end already holds.
const RESUME_QUERY: u8 = 19;
/// The answer to a resume query.
const RESUME_REPLY: u8 = 20;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
pub const STATUS_MISSING: u8 = 2;

/// What the far end says when the file it holds is shorter than the offset a
/// resume asked for: the prefix cannot belong to it, so the transfer has to
/// start over.
pub const RESUME_TOO_LONG: &str = "the file is shorter than the resume offset";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        version: u16,
        agent: String,
    },
    Rules {
        defaults: bool,
        patterns: Vec<String>,
        /// How hard the far end should work to make the bytes durable: the
        /// far end is where the bytes land.
        fsync: u8,
    },
    List,
    Entry(Entry),
    EndList,
    Hash(PathBuf),
    Get(PathBuf),
    /// A GET that starts at `offset` bytes into the file.
    GetRange {
        path: PathBuf,
        offset: u64,
    },
    DataBegin {
        size: u64,
        mtime_ns: i64,
        hash: Hash,
    },
    Push {
        path: PathBuf,
        size: u64,
        mtime_ns: i64,
        hash: Hash,
    },
    /// A PUSH that continues the file at `offset` bytes and carries the hash
    /// of the whole file, prefix included.
    PushRange {
        path: PathBuf,
        size: u64,
        mtime_ns: i64,
        hash: Hash,
        offset: u64,
    },
    /// How much of the file the far end already holds, so a transfer can be
    /// continued where it stopped.
    ResumeQuery(PathBuf),
    ResumeReply {
        size: u64,
    },
    Chunk(Vec<u8>),
    End,
    Ack {
        status: u8,
        hash: Hash,
        message: String,
    },
    Stat(PathBuf),
    StatReply(Option<Entry>),
    Delete(PathBuf),
    Bye,
}

pub fn write_frame<W: Write + ?Sized>(out: &mut W, frame: &Frame) -> io::Result<()> {
    let mut payload = Vec::new();
    match frame {
        Frame::Hello { version, agent } => {
            payload.push(HELLO);
            payload.extend_from_slice(&version.to_le_bytes());
            payload.extend_from_slice(agent.as_bytes());
        }
        Frame::Rules {
            defaults,
            patterns,
            fsync,
        } => {
            payload.push(RULES);
            payload.push(u8::from(*defaults));
            payload.push(*fsync);
            let joined = patterns.join("\n");
            payload.extend_from_slice(&(joined.len() as u32).to_le_bytes());
            payload.extend_from_slice(joined.as_bytes());
        }
        Frame::List => payload.push(LIST),
        Frame::Entry(entry) => {
            payload.push(ENTRY);
            payload.push(entry.kind.to_sql() as u8);
            payload.extend_from_slice(&entry.size.to_le_bytes());
            payload.extend_from_slice(&entry.mtime_ns.to_le_bytes());
            payload.extend_from_slice(entry.path.as_os_str().as_bytes());
        }
        Frame::EndList => payload.push(END_LIST),
        Frame::Hash(path) => {
            payload.push(HASH);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::Get(path) => {
            payload.push(GET);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::GetRange { path, offset } => {
            payload.push(GET_RANGE);
            payload.extend_from_slice(&offset.to_le_bytes());
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::DataBegin {
            size,
            mtime_ns,
            hash,
        } => {
            payload.push(DATA_BEGIN);
            payload.extend_from_slice(&size.to_le_bytes());
            payload.extend_from_slice(&mtime_ns.to_le_bytes());
            payload.extend_from_slice(hash);
        }
        Frame::Push {
            path,
            size,
            mtime_ns,
            hash,
        } => {
            payload.push(PUSH);
            payload.extend_from_slice(&size.to_le_bytes());
            payload.extend_from_slice(&mtime_ns.to_le_bytes());
            payload.extend_from_slice(hash);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::PushRange {
            path,
            size,
            mtime_ns,
            hash,
            offset,
        } => {
            payload.push(PUSH_RANGE);
            payload.extend_from_slice(&size.to_le_bytes());
            payload.extend_from_slice(&mtime_ns.to_le_bytes());
            payload.extend_from_slice(&offset.to_le_bytes());
            payload.extend_from_slice(hash);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::ResumeQuery(path) => {
            payload.push(RESUME_QUERY);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::ResumeReply { size } => {
            payload.push(RESUME_REPLY);
            payload.extend_from_slice(&size.to_le_bytes());
        }
        Frame::Chunk(bytes) => {
            payload.push(CHUNK_FRAME);
            payload.extend_from_slice(bytes);
        }
        Frame::End => payload.push(END_FRAME),
        Frame::Ack {
            status,
            hash,
            message,
        } => {
            payload.push(ACK);
            payload.push(*status);
            payload.extend_from_slice(hash);
            payload.extend_from_slice(message.as_bytes());
        }
        Frame::Stat(path) => {
            payload.push(STAT);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::StatReply(entry) => {
            payload.push(STAT_REPLY);
            match entry {
                None => payload.push(0),
                Some(entry) => {
                    payload.push(1);
                    payload.push(entry.kind.to_sql() as u8);
                    payload.extend_from_slice(&entry.size.to_le_bytes());
                    payload.extend_from_slice(&entry.mtime_ns.to_le_bytes());
                    payload.extend_from_slice(entry.path.as_os_str().as_bytes());
                }
            }
        }
        Frame::Delete(path) => {
            payload.push(DELETE);
            payload.extend_from_slice(path.as_os_str().as_bytes());
        }
        Frame::Bye => payload.push(BYE),
    }
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    out.write_all(&(payload.len() as u32).to_le_bytes())?;
    out.write_all(&payload)
}

pub fn read_frame<R: Read + ?Sized>(input: &mut R) -> io::Result<Frame> {
    let mut len_bytes = [0u8; 4];
    input.read_exact(&mut len_bytes).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::other("the other side closed the connection")
        } else {
            e
        }
    })?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("nonsense frame length {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    input.read_exact(&mut payload)?;
    decode(&payload)
}

fn decode(payload: &[u8]) -> io::Result<Frame> {
    let tag = payload[0];
    let body = &payload[1..];
    let bad = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed {what} frame"),
        )
    };
    match tag {
        HELLO => {
            if body.len() < 2 {
                return Err(bad("hello"));
            }
            let version = u16::from_le_bytes([body[0], body[1]]);
            let agent = String::from_utf8_lossy(&body[2..]).to_string();
            Ok(Frame::Hello { version, agent })
        }
        RULES => {
            if body.len() < 6 {
                return Err(bad("rules"));
            }
            let defaults = body[0] != 0;
            let fsync = body[1];
            let text_len = u32::from_le_bytes([body[2], body[3], body[4], body[5]]) as usize;
            let text = &body[6..];
            if text.len() < text_len {
                return Err(bad("rules"));
            }
            let patterns = String::from_utf8_lossy(&text[..text_len])
                .lines()
                .map(str::to_string)
                .collect();
            Ok(Frame::Rules {
                defaults,
                patterns,
                fsync,
            })
        }
        LIST => Ok(Frame::List),
        ENTRY => {
            if body.len() < 17 {
                return Err(bad("entry"));
            }
            let kind = Kind::from_sql(body[0] as i64);
            let size = u64::from_le_bytes(body[1..9].try_into().unwrap());
            let mtime_ns = i64::from_le_bytes(body[9..17].try_into().unwrap());
            let path = PathBuf::from(std::ffi::OsString::from_vec(body[17..].to_vec()));
            Ok(Frame::Entry(Entry {
                path,
                kind,
                size,
                mtime_ns,
            }))
        }
        END_LIST => Ok(Frame::EndList),
        HASH => Ok(Frame::Hash(path_from(body))),
        GET => Ok(Frame::Get(path_from(body))),
        GET_RANGE => {
            if body.len() < 8 {
                return Err(bad("get range"));
            }
            let offset = u64::from_le_bytes(body[0..8].try_into().unwrap());
            Ok(Frame::GetRange {
                path: path_from(&body[8..]),
                offset,
            })
        }
        DATA_BEGIN => {
            if body.len() < 48 {
                return Err(bad("data"));
            }
            let size = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let mtime_ns = i64::from_le_bytes(body[8..16].try_into().unwrap());
            let mut hash: Hash = [0u8; 32];
            hash.copy_from_slice(&body[16..48]);
            Ok(Frame::DataBegin {
                size,
                mtime_ns,
                hash,
            })
        }
        PUSH => {
            if body.len() < 48 {
                return Err(bad("push"));
            }
            let size = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let mtime_ns = i64::from_le_bytes(body[8..16].try_into().unwrap());
            let mut hash: Hash = [0u8; 32];
            hash.copy_from_slice(&body[16..48]);
            let path = path_from(&body[48..]);
            Ok(Frame::Push {
                path,
                size,
                mtime_ns,
                hash,
            })
        }
        PUSH_RANGE => {
            if body.len() < 56 {
                return Err(bad("push range"));
            }
            let size = u64::from_le_bytes(body[0..8].try_into().unwrap());
            let mtime_ns = i64::from_le_bytes(body[8..16].try_into().unwrap());
            let offset = u64::from_le_bytes(body[16..24].try_into().unwrap());
            let mut hash: Hash = [0u8; 32];
            hash.copy_from_slice(&body[24..56]);
            let path = path_from(&body[56..]);
            Ok(Frame::PushRange {
                path,
                size,
                mtime_ns,
                hash,
                offset,
            })
        }
        RESUME_QUERY => Ok(Frame::ResumeQuery(path_from(body))),
        RESUME_REPLY => {
            if body.len() < 8 {
                return Err(bad("resume reply"));
            }
            Ok(Frame::ResumeReply {
                size: u64::from_le_bytes(body[0..8].try_into().unwrap()),
            })
        }
        CHUNK_FRAME => Ok(Frame::Chunk(body.to_vec())),
        END_FRAME => Ok(Frame::End),
        ACK => {
            if body.len() < 33 {
                return Err(bad("ack"));
            }
            let status = body[0];
            let mut hash: Hash = [0u8; 32];
            hash.copy_from_slice(&body[1..33]);
            let message = String::from_utf8_lossy(&body[33..]).to_string();
            Ok(Frame::Ack {
                status,
                hash,
                message,
            })
        }
        STAT => Ok(Frame::Stat(path_from(body))),
        STAT_REPLY => {
            if body.is_empty() {
                return Err(bad("stat"));
            }
            if body[0] == 0 {
                return Ok(Frame::StatReply(None));
            }
            if body.len() < 18 {
                return Err(bad("stat"));
            }
            let kind = Kind::from_sql(body[1] as i64);
            let size = u64::from_le_bytes(body[2..10].try_into().unwrap());
            let mtime_ns = i64::from_le_bytes(body[10..18].try_into().unwrap());
            let path = PathBuf::from(std::ffi::OsString::from_vec(body[18..].to_vec()));
            Ok(Frame::StatReply(Some(Entry {
                path,
                kind,
                size,
                mtime_ns,
            })))
        }
        DELETE => Ok(Frame::Delete(path_from(body))),
        BYE => Ok(Frame::Bye),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown frame type {other}"),
        )),
    }
}

fn path_from(body: &[u8]) -> PathBuf {
    PathBuf::from(std::ffi::OsString::from_vec(body.to_vec()))
}

/// Stream a reader to the far side as CHUNK frames followed by END.
pub fn write_stream<R: Read + ?Sized, W: Write + ?Sized>(
    input: &mut R,
    out: &mut W,
) -> io::Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    crate::fsutil::with_scratch(|buf| -> io::Result<()> {
        let chunk = &mut buf[..CHUNK];
        loop {
            let read = input.read(chunk)?;
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
            write_frame(out, &Frame::Chunk(chunk[..read].to_vec()))?;
        }
        Ok(())
    })?;
    write_frame(out, &Frame::End)?;
    out.flush()?;
    Ok(*hasher.finalize().as_bytes())
}

/// Read CHUNK frames until END, hashing as they arrive.
pub fn read_stream<R: Read + ?Sized>(input: &mut R, mut sink: impl Write) -> io::Result<Hash> {
    let mut hasher = blake3::Hasher::new();
    loop {
        match read_frame(input)? {
            Frame::Chunk(bytes) => {
                hasher.update(&bytes);
                sink.write_all(&bytes)?;
            }
            Frame::End => break,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected file data, got {other:?}"),
                ))
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn ack(out: &mut (impl Write + ?Sized), status: u8, hash: Hash, message: &str) -> io::Result<()> {
    write_frame(
        out,
        &Frame::Ack {
            status,
            hash,
            message: message.to_string(),
        },
    )?;
    out.flush()
}

/// The far end. Speaks the protocol on the given streams and never touches
/// anything outside `root`.
///
/// The directories that were written into are flushed once, when the
/// connection ends: one barrier per directory instead of one per file.
pub fn serve(root: &Path, input: &mut dyn Read, output: &mut dyn Write) -> io::Result<()> {
    let mut flush = DirFlush::default();
    let mut mode = Fsync::Full;
    let outcome = serve_connection(root, input, output, &mut flush, &mut mode);
    flush.flush(mode);
    outcome
}

fn serve_connection(
    root: &Path,
    input: &mut dyn Read,
    output: &mut dyn Write,
    flush: &mut DirFlush,
    mode: &mut Fsync,
) -> io::Result<()> {
    let banner = *blake3::hash(b"twin").as_bytes();
    match read_frame(input)? {
        Frame::Hello { version, agent } => {
            if version != PROTOCOL_VERSION {
                ack(
                    output,
                    STATUS_ERROR,
                    banner,
                    &format!(
                        "protocol mismatch: this side speaks {PROTOCOL_VERSION}, you speak {version} ({agent}). Install the same twin version on both ends."
                    ),
                )?;
                return Ok(());
            }
        }
        other => {
            ack(
                output,
                STATUS_ERROR,
                banner,
                &format!("expected a hello, got {other:?}"),
            )?;
            return Ok(());
        }
    }
    write_frame(
        output,
        &Frame::Hello {
            version: PROTOCOL_VERSION,
            agent: AGENT.to_string(),
        },
    )?;
    output.flush()?;

    let rules = match read_frame(input)? {
        Frame::Rules {
            defaults,
            patterns,
            fsync,
        } => {
            *mode = Fsync::from_code(fsync);
            IgnoreRules::from_patterns(root, defaults, &patterns)?
        }
        other => {
            ack(
                output,
                STATUS_ERROR,
                banner,
                &format!("expected ignore rules, got {other:?}"),
            )?;
            return Ok(());
        }
    };

    loop {
        let frame = match read_frame(input) {
            Ok(frame) => frame,
            Err(e) if e.kind() == io::ErrorKind::Other => return Ok(()), // peer went away
            Err(e) => return Err(e),
        };
        match frame {
            Frame::List => {
                crate::debug!("listing {}", root.display());
                let mut scanner = Scanner::new(root, rules.clone())?;
                while let Some(entry) = scanner.next_entry() {
                    match entry {
                        Ok(entry) => write_frame(output, &Frame::Entry(entry))?,
                        // One path that cannot be read must not hide the rest
                        // of the tree.
                        Err(failure) => {
                            crate::warn!("{}: {}", failure.path.display(), failure.message);
                        }
                    }
                }
                write_frame(output, &Frame::EndList)?;
                output.flush()?;
            }
            Frame::Hash(path) => match safe_join(root, &path)
                .and_then(|abs| hash_file(&abs).ctx(|| format!("hashing {}", abs.display())))
            {
                Ok(hash) => ack(output, STATUS_OK, hash, "")?,
                Err(e) => ack(output, STATUS_ERROR, banner, &e.to_string())?,
            },
            Frame::Stat(path) => {
                let reply = match safe_join(root, &path) {
                    Ok(abs) => match fs::symlink_metadata(&abs) {
                        Ok(meta) => Some(entry_for(path.clone(), &meta)),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                        Err(e) => {
                            ack(output, STATUS_ERROR, banner, &e.to_string())?;
                            continue;
                        }
                    },
                    Err(e) => {
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                };
                write_frame(output, &Frame::StatReply(reply))?;
                output.flush()?;
            }
            Frame::Get(path) => send_file(output, root, &path, 0)?,
            Frame::GetRange { path, offset } => send_file(output, root, &path, offset)?,
            Frame::ResumeQuery(path) => {
                let reply = match safe_join(root, &path) {
                    Ok(abs) => {
                        let tmp = crate::side::temp_for(&abs);
                        fs::metadata(&tmp).map(|meta| meta.len()).unwrap_or(0)
                    }
                    Err(e) => {
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                };
                write_frame(output, &Frame::ResumeReply { size: reply })?;
                output.flush()?;
            }
            Frame::Push {
                path,
                size,
                mtime_ns: mtime,
                hash,
            } => {
                let abs = match safe_join(root, &path) {
                    Ok(abs) => abs,
                    Err(e) => {
                        // The data still has to be drained to keep the stream in sync.
                        drain_stream(input)?;
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                };
                let tmp = crate::side::temp_for(&abs);
                let outcome = receive_file(input, &abs, &tmp, size, mtime, hash, 0, false, *mode);
                match outcome {
                    Ok(()) => {
                        if let Some(parent) = abs.parent() {
                            flush.note(parent);
                        }
                        ack(output, STATUS_OK, hash, "")?
                    }
                    Err(e) => {
                        // Without a resume the partial file is of no use to anyone.
                        let _ = fs::remove_file(&tmp);
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                }
            }
            Frame::PushRange {
                path,
                size,
                mtime_ns: mtime,
                hash,
                offset,
            } => {
                let abs = match safe_join(root, &path) {
                    Ok(abs) => abs,
                    Err(e) => {
                        drain_stream(input)?;
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                };
                let tmp = crate::side::temp_for(&abs);
                let outcome =
                    receive_file(input, &abs, &tmp, size, mtime, hash, offset, true, *mode);
                match outcome {
                    Ok(()) => {
                        if let Some(parent) = abs.parent() {
                            flush.note(parent);
                        }
                        ack(output, STATUS_OK, hash, "")?
                    }
                    Err(e) => {
                        // A partial transfer is kept so the next run can continue
                        // it; a file that does not verify is thrown away.
                        if is_hash_mismatch(&e.to_string()) {
                            let _ = fs::remove_file(&tmp);
                        }
                        ack(output, STATUS_ERROR, banner, &e.to_string())?;
                        continue;
                    }
                }
            }
            Frame::Delete(path) => match safe_join(root, &path) {
                Ok(abs) => {
                    let removed = match fs::remove_file(&abs) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err(e),
                    };
                    match removed {
                        Ok(()) => {
                            if let Some(parent) = abs.parent() {
                                // never climb above the served root
                                if parent.starts_with(root) {
                                    crate::fsutil::prune_empty_dirs(root, parent);
                                }
                            }
                            ack(output, STATUS_OK, banner, "")?;
                        }
                        Err(e) => ack(output, STATUS_ERROR, banner, &e.to_string())?,
                    }
                }
                Err(e) => ack(output, STATUS_ERROR, banner, &e.to_string())?,
            },
            Frame::Bye => {
                // The run is over: the directories that were written into are
                // flushed now, and the answer says so, so the other side knows
                // the bytes are durable before it reports the run as done.
                flush.flush(*mode);
                ack(output, STATUS_OK, banner, "")?;
                return Ok(());
            }
            other => {
                ack(
                    output,
                    STATUS_ERROR,
                    banner,
                    &format!("unexpected request {other:?}"),
                )?;
            }
        }
    }
}

fn drain_stream(input: &mut dyn Read) -> io::Result<()> {
    loop {
        match read_frame(input)? {
            Frame::Chunk(_) => continue,
            Frame::End => return Ok(()),
            _ => return Ok(()),
        }
    }
}

/// Send a file, optionally starting at an offset so an interrupted transfer
/// can be continued. The announced hash always covers the whole file, so the
/// receiving side can verify the result in one go.
fn send_file(output: &mut dyn Write, root: &Path, path: &Path, offset: u64) -> io::Result<()> {
    let banner = *blake3::hash(b"twin").as_bytes();
    crate::debug!("sending {}", path.display());
    let abs = match safe_join(root, path) {
        Ok(abs) => abs,
        Err(e) => {
            ack(output, STATUS_ERROR, banner, &e.to_string())?;
            return Ok(());
        }
    };
    let meta = match fs::symlink_metadata(&abs) {
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => {
            ack(output, STATUS_ERROR, banner, "not a regular file")?;
            return Ok(());
        }
        Err(e) => {
            ack(output, STATUS_MISSING, banner, &e.to_string())?;
            return Ok(());
        }
    };
    if offset > meta.len() {
        // The file shrank since the last attempt: the prefix cannot be part
        // of it, so the client has to start over.
        ack(output, STATUS_ERROR, banner, RESUME_TOO_LONG)?;
        return Ok(());
    }
    let hash = hash_file(&abs).ctx(|| format!("hashing {}", abs.display()))?;
    write_frame(
        output,
        &Frame::DataBegin {
            size: meta.len(),
            mtime_ns: mtime_ns(&meta),
            hash,
        },
    )?;
    let mut reader = File::open(&abs).ctx(|| format!("opening {}", abs.display()))?;
    if offset > 0 {
        reader
            .seek(SeekFrom::Start(offset))
            .ctx(|| format!("seeking in {}", abs.display()))?;
    }
    write_stream(&mut reader, output).ctx(|| format!("sending {}", abs.display()))?;
    Ok(())
}

/// Whether a message from the far side describes a hash mismatch, which the
/// engine may retry once.
pub fn is_hash_mismatch(message: &str) -> bool {
    message.contains("hash does not match")
        || message.contains("verification failed")
        || message.contains("does not match the hash")
}

/// Receive a file into `tmp` and move it into place.
///
/// With `offset` above zero the transfer continues a partial file: the bytes
/// already there are kept and the whole file is verified once it is complete.
/// A file that does not verify is thrown away, so the next attempt starts
/// from zero.
#[allow(clippy::too_many_arguments)]
fn receive_file(
    input: &mut dyn Read,
    abs: &Path,
    tmp: &Path,
    declared_size: u64,
    mtime: i64,
    expected: Hash,
    offset: u64,
    resumable: bool,
    mode: Fsync,
) -> io::Result<()> {
    let parent = abs
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
    fs::create_dir_all(parent)?;

    if resumable {
        let have = fs::metadata(tmp).map(|meta| meta.len()).unwrap_or(0);
        if have < offset {
            return Err(io::Error::other(
                "the partial file is shorter than the resume offset",
            ));
        }
        // Anything past the agreed offset belongs to an older attempt.
        let file = fs::OpenOptions::new()
            .write(true)
            .open(tmp)
            .ctx(|| format!("opening {}", tmp.display()))?;
        file.set_len(offset)
            .ctx(|| format!("trimming {}", tmp.display()))?;
    } else {
        let _ = fs::remove_file(tmp);
    }

    let mut writer = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(tmp)
        .ctx(|| format!("creating {}", tmp.display()))?;
    let result = (|| -> io::Result<()> {
        read_stream(input, &mut writer)
            .ctx(|| format!("receiving {} into {}", abs.display(), tmp.display()))?;
        writer.flush()?;
        crate::fsutil::fsync_file(&writer, mode).ctx(|| format!("flushing {}", tmp.display()))?;
        drop(writer);
        // The whole file is verified, prefix included.
        let got = hash_file(tmp).ctx(|| format!("hashing {}", tmp.display()))?;
        if got != expected {
            return Err(crate::fsutil::verification_error(
                "content hash does not match what was sent",
            ));
        }
        let written = fs::metadata(tmp)?.len();
        if written != declared_size {
            return Err(io::Error::other(format!(
                "expected {declared_size} bytes, wrote {written}"
            )));
        }
        crate::fsutil::apply_mtime(tmp, mtime, "storing");
        if let Ok(existing) = fs::symlink_metadata(abs) {
            if existing.is_dir() {
                return Err(io::Error::other("destination is a directory"));
            }
        }
        fs::rename(tmp, abs)
            .ctx(|| format!("moving {} into place at {}", tmp.display(), abs.display()))?;
        Ok(())
    })();
    if result.is_err() && !resumable {
        let _ = fs::remove_file(tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufWriter;

    fn frames_round_trip(frame: Frame) {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &frame).unwrap();
        let mut reader = io::Cursor::new(buffer);
        assert_eq!(read_frame(&mut reader).unwrap(), frame);
    }

    #[test]
    fn every_frame_survives_a_round_trip() {
        frames_round_trip(Frame::Hello {
            version: 1,
            agent: "twin 0.1.0".into(),
        });
        frames_round_trip(Frame::Rules {
            defaults: true,
            patterns: vec!["*.log".into(), "build/".into()],
            fsync: 0,
        });
        frames_round_trip(Frame::List);
        frames_round_trip(Frame::Entry(Entry {
            path: PathBuf::from("a/b.txt"),
            kind: Kind::File,
            size: 12,
            mtime_ns: 99,
        }));
        frames_round_trip(Frame::Push {
            path: PathBuf::from("x.bin"),
            size: 3,
            mtime_ns: 7,
            hash: [4u8; 32],
        });
        frames_round_trip(Frame::Ack {
            status: STATUS_OK,
            hash: [1u8; 32],
            message: "fine".into(),
        });
        frames_round_trip(Frame::StatReply(Some(Entry {
            path: PathBuf::from("z"),
            kind: Kind::Symlink,
            size: 0,
            mtime_ns: 1,
        })));
        frames_round_trip(Frame::Delete(PathBuf::from("gone")));
        frames_round_trip(Frame::GetRange {
            path: PathBuf::from("a/b.bin"),
            offset: 4096,
        });
        frames_round_trip(Frame::PushRange {
            path: PathBuf::from("a/b.bin"),
            size: 9000,
            mtime_ns: 11,
            hash: [7u8; 32],
            offset: 4096,
        });
        frames_round_trip(Frame::ResumeQuery(PathBuf::from("a/b.bin")));
        frames_round_trip(Frame::ResumeReply { size: 4096 });
        frames_round_trip(Frame::Bye);
    }

    #[test]
    fn paths_with_arbitrary_bytes_survive() {
        let odd = PathBuf::from(std::ffi::OsString::from_vec(b"caf\xe9-\xff.txt".to_vec()));
        frames_round_trip(Frame::Entry(Entry {
            path: odd.clone(),
            kind: Kind::File,
            size: 1,
            mtime_ns: 2,
        }));
        frames_round_trip(Frame::Get(odd));
    }

    #[test]
    fn a_stream_is_reassembled_and_hashed() {
        let payload = vec![7u8; CHUNK * 2 + 13];
        let mut wire = Vec::new();
        let hash = write_stream(&mut io::Cursor::new(&payload), &mut wire).unwrap();
        assert_eq!(hash, *blake3::hash(&payload).as_bytes());

        let mut reader = io::Cursor::new(wire);
        let mut sink = Vec::new();
        let got = read_stream(&mut reader, &mut sink).unwrap();
        assert_eq!(got, hash);
        assert_eq!(sink, payload);
    }

    #[test]
    fn the_server_serves_a_root_and_refuses_escapes() {
        use std::io::BufWriter;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/hello.txt"), b"hello").unwrap();

        let mut wire = Vec::new();
        {
            let mut out = BufWriter::new(&mut wire);
            write_frame(
                &mut out,
                &Frame::Hello {
                    version: PROTOCOL_VERSION,
                    agent: "test".into(),
                },
            )
            .unwrap();
            write_frame(
                &mut out,
                &Frame::Rules {
                    defaults: true,
                    patterns: vec![],
                    fsync: 0,
                },
            )
            .unwrap();
            write_frame(&mut out, &Frame::List).unwrap();
            write_frame(&mut out, &Frame::Get(PathBuf::from("sub/hello.txt"))).unwrap();
            write_frame(&mut out, &Frame::Get(PathBuf::from("../escape"))).unwrap();
            write_frame(&mut out, &Frame::Hash(PathBuf::from("sub/hello.txt"))).unwrap();
            write_frame(&mut out, &Frame::Stat(PathBuf::from("nope"))).unwrap();
            write_frame(&mut out, &Frame::Bye).unwrap();
            out.flush().unwrap();
        }

        let mut input = io::Cursor::new(wire);
        let mut output = Vec::new();
        serve(&root, &mut input, &mut output).unwrap();

        let mut replies = io::Cursor::new(output);
        assert!(matches!(
            read_frame(&mut replies).unwrap(),
            Frame::Hello { .. }
        ));
        let mut listed = Vec::new();
        loop {
            match read_frame(&mut replies).unwrap() {
                Frame::Entry(entry) => listed.push(entry.path.display().to_string()),
                Frame::EndList => break,
                other => panic!("expected a listing, got {other:?}"),
            }
        }
        assert!(listed.contains(&"sub".to_string()), "{listed:?}");
        assert!(listed.contains(&"sub/hello.txt".to_string()), "{listed:?}");

        match read_frame(&mut replies).unwrap() {
            Frame::DataBegin { size, hash, .. } => {
                assert_eq!(size, 5);
                assert_eq!(hash, *blake3::hash(b"hello").as_bytes());
            }
            other => panic!("expected file data, got {other:?}"),
        }
        let mut body = Vec::new();
        read_stream(&mut replies, &mut body).unwrap();
        assert_eq!(body, b"hello");

        match read_frame(&mut replies).unwrap() {
            Frame::Ack { status, .. } => {
                assert_eq!(status, STATUS_ERROR, "escapes must be refused")
            }
            other => panic!("expected an error ack, got {other:?}"),
        }
        match read_frame(&mut replies).unwrap() {
            Frame::Ack { status, hash, .. } => {
                assert_eq!(status, STATUS_OK);
                assert_eq!(hash, *blake3::hash(b"hello").as_bytes());
            }
            other => panic!("expected an ack, got {other:?}"),
        }
        assert_eq!(read_frame(&mut replies).unwrap(), Frame::StatReply(None));
    }

    #[test]
    fn a_version_mismatch_is_refused_with_a_usable_message() {
        let dir = tempfile::tempdir().unwrap();
        let mut wire = Vec::new();
        {
            let mut out = BufWriter::new(&mut wire);
            write_frame(
                &mut out,
                &Frame::Hello {
                    version: PROTOCOL_VERSION + 1,
                    agent: "twin 9".into(),
                },
            )
            .unwrap();
            out.flush().unwrap();
        }
        let mut input = io::Cursor::new(wire);
        let mut output = Vec::new();
        serve(dir.path(), &mut input, &mut output).unwrap();

        let mut replies = io::Cursor::new(output);
        match read_frame(&mut replies).unwrap() {
            Frame::Ack {
                status, message, ..
            } => {
                assert_eq!(status, STATUS_ERROR);
                assert!(message.contains("protocol mismatch"), "{message}");
                assert!(
                    message.contains("twin 9"),
                    "name the other version: {message}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn pushed_content_lands_atomically_and_keeps_its_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir_all(&root).unwrap();

        let payload = b"pushed payload".to_vec();
        let mtime = 1_700_000_000_123_456_789i64;
        let mut wire = Vec::new();
        {
            let mut out = BufWriter::new(&mut wire);
            write_frame(
                &mut out,
                &Frame::Hello {
                    version: PROTOCOL_VERSION,
                    agent: "t".into(),
                },
            )
            .unwrap();
            write_frame(
                &mut out,
                &Frame::Rules {
                    defaults: true,
                    patterns: vec![],
                    fsync: 0,
                },
            )
            .unwrap();
            write_frame(
                &mut out,
                &Frame::Push {
                    path: PathBuf::from("deep/new.txt"),
                    size: payload.len() as u64,
                    mtime_ns: mtime,
                    hash: *blake3::hash(&payload).as_bytes(),
                },
            )
            .unwrap();
            write_stream(&mut io::Cursor::new(&payload), &mut out).unwrap();
            write_frame(&mut out, &Frame::Bye).unwrap();
            out.flush().unwrap();
        }

        let mut input = io::Cursor::new(wire);
        let mut output = Vec::new();
        serve(&root, &mut input, &mut output).unwrap();

        assert_eq!(fs::read(root.join("deep/new.txt")).unwrap(), payload);
        assert_eq!(
            mtime_ns(&fs::metadata(root.join("deep/new.txt")).unwrap()),
            mtime
        );
        let leftovers = fs::read_dir(root.join("deep"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".twin-tmp-")
            })
            .count();
        assert_eq!(leftovers, 0, "temp files must not survive");
    }
}
