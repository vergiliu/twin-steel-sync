//! The far side of a pair, reached over mutual TLS. It implements the same
//! `Backend` seam the local filesystem does, so the engine does not know or care
//! which it is talking to.

use crate::fsutil::{fsync_hard, hash_file, mtime_ns, sync_dir, ErrCtx};
use crate::model::{Entry, Hash, PathFailure};
use crate::proto::{self, Frame, AGENT, PROTOCOL_VERSION, STATUS_MISSING, STATUS_OK};
use crate::side::Backend;
use crate::tls;
use rustls::{ClientConfig, ClientConnection};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Whether the far end turned us away.
///
/// TLS 1.3 lets the client finish its handshake before the server has looked
/// at the client certificate, so a refusal arrives *after* the handshake: the
/// server sends its alert and closes the connection, and the client finds a
/// closed connection when it writes the first frame. Whether that surfaces as
/// the alert itself or as a broken pipe depends on the platform and on the
/// timing, so both are read as the refusal they are.
fn is_refusal(error: &io::Error) -> bool {
    match error.kind() {
        io::ErrorKind::BrokenPipe
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::UnexpectedEof => return true,
        _ => {}
    }
    let text = error.to_string();
    text.contains("alert") || text.contains("certificate")
}

fn handshake_error(label: &str, error: io::Error) -> io::Error {
    let text = error.to_string();
    let hint = if is_refusal(&error) {
        "this client is not allowed there: run `twin` here to print this machine's \
         fingerprint, then `twin authorize <fingerprint>` on the server — it takes \
         effect on the next connection"
    } else {
        "the other side did not speak the twin protocol"
    };
    io::Error::other(format!("{label}: {text} — {hint}"))
}

#[derive(Debug, Clone)]
pub struct RemoteOptions {
    pub host: String,
    pub port: u16,
}

impl RemoteOptions {
    pub fn label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct RemoteBackend {
    label: String,
    stream: rustls::StreamOwned<ClientConnection, TcpStream>,
    /// The far end streams its listing as one answer to one request, so the whole
    /// answer is read before anything else is asked: replies can never cross.
    /// Entries spill to a temporary file, so memory stays independent of tree size.
    spool_path: PathBuf,
    spool: Option<BufReader<File>>,
    listing_done: bool,
}

impl RemoteBackend {
    pub fn connect(
        options: &RemoteOptions,
        identity: &tls::Identity,
        pinned: &str,
        defaults: bool,
        patterns: &[String],
    ) -> io::Result<RemoteBackend> {
        let config: Arc<ClientConfig> = tls::client_config(identity, pinned)?;
        let stream = tls::connect(&options.host, options.port, config)?;
        crate::info!("connected to {} (mutual TLS)", options.label());
        let mut backend = RemoteBackend {
            label: options.label(),
            stream,
            spool_path: std::env::temp_dir().join(format!(
                "twin-listing-{}-{}",
                std::process::id(),
                SPOOL_COUNTER.fetch_add(1, Ordering::Relaxed)
            )),
            spool: None,
            listing_done: false,
        };
        // Under TLS 1.3 the server's rejection can arrive after the client thinks
        // the handshake is done, so the hint belongs around the first exchange too.
        backend
            .handshake(defaults, patterns)
            .map_err(|error| handshake_error(&backend.label, error))?;
        Ok(backend)
    }

    fn handshake(&mut self, defaults: bool, patterns: &[String]) -> io::Result<()> {
        self.send(&Frame::Hello {
            version: PROTOCOL_VERSION,
            agent: AGENT.to_string(),
        })?;
        match self.receive()? {
            Frame::Hello { version, agent } => {
                if version != PROTOCOL_VERSION {
                    return Err(io::Error::other(format!(
                        "protocol mismatch: local {PROTOCOL_VERSION}, remote {version} ({agent}). \
                         Install the same twin version on both ends."
                    )));
                }
            }
            Frame::Ack { message, .. } => return Err(io::Error::other(message)),
            other => return Err(io::Error::other(format!("unexpected reply {other:?}"))),
        }
        self.send(&Frame::Rules {
            defaults,
            patterns: patterns.to_vec(),
        })
    }

    fn send(&mut self, frame: &Frame) -> io::Result<()> {
        proto::write_frame(&mut self.stream, frame)?;
        self.stream.flush()
    }

    fn receive(&mut self) -> io::Result<Frame> {
        proto::read_frame(&mut self.stream)
    }

    fn request(&mut self, frame: &Frame) -> io::Result<Hash> {
        self.send(frame)?;
        self.expect_ack()
    }

    /// Read the reply to a request that has already been sent.
    fn expect_ack(&mut self) -> io::Result<Hash> {
        match self.receive()? {
            Frame::Ack {
                status,
                hash,
                message,
            } => {
                if status == STATUS_OK {
                    Ok(hash)
                } else if proto::is_hash_mismatch(&message) {
                    // A hash that does not match is worth one more try.
                    Err(crate::fsutil::verification_error(message))
                } else {
                    Err(io::Error::other(if message.is_empty() {
                        "the other side refused the request".to_string()
                    } else {
                        message
                    }))
                }
            }
            other => Err(io::Error::other(format!(
                "expected an acknowledgement, got {other:?}"
            ))),
        }
    }

    /// Ask for the listing and spool every frame of the answer, so that requests
    /// made while the plan is being built cannot interleave with it.
    fn read_listing(&mut self) -> io::Result<()> {
        self.send(&Frame::List)?;
        let mut spool = BufWriter::new(File::create(&self.spool_path)?);
        loop {
            let frame = self.receive()?;
            match &frame {
                Frame::Entry(_) => proto::write_frame(&mut spool, &frame)?,
                Frame::EndList => {
                    proto::write_frame(&mut spool, &frame)?;
                    break;
                }
                Frame::Ack { message, .. } => {
                    let _ = fs::remove_file(&self.spool_path);
                    return Err(io::Error::other(message.clone()));
                }
                other => {
                    let _ = fs::remove_file(&self.spool_path);
                    return Err(io::Error::other(format!(
                        "expected a directory entry, got {other:?}"
                    )));
                }
            }
        }
        spool.flush()?;
        drop(spool);
        self.spool = Some(BufReader::new(
            File::open(&self.spool_path)
                .ctx(|| format!("reading {}", self.spool_path.display()))?,
        ));
        Ok(())
    }

    /// How much of the file the far end already holds. A partial file that is
    /// longer than the source belongs to an older version and cannot be
    /// continued.
    fn remote_offset(&mut self, path: &Path, size: u64) -> io::Result<u64> {
        self.send(&Frame::ResumeQuery(path.to_path_buf()))?;
        let have = match self.receive()? {
            Frame::ResumeReply { size } => size,
            Frame::Ack { message, .. } => {
                return Err(io::Error::other(if message.is_empty() {
                    "the other side refused the request".to_string()
                } else {
                    message
                }))
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected a resume reply, got {other:?}"
                )))
            }
        };
        Ok(if have > size { 0 } else { have })
    }

    /// Ask for the bytes from `offset` on and put the file in place.
    fn fetch(
        &mut self,
        path: &Path,
        offset: u64,
        tmp: &Path,
        local_dst: &Path,
        parent: &Path,
        keep_partial: bool,
    ) -> io::Result<Hash> {
        self.send(&Frame::GetRange {
            path: path.to_path_buf(),
            offset,
        })?;
        let (size, mtime, expected) = match self.receive()? {
            Frame::DataBegin {
                size,
                mtime_ns,
                hash,
            } => (size, mtime_ns, hash),
            Frame::Ack {
                status, message, ..
            } => {
                return Err(io::Error::other(if status == STATUS_MISSING {
                    format!("the other side no longer has {}", path.display())
                } else if message.is_empty() {
                    "the other side refused the request".to_string()
                } else {
                    message
                }))
            }
            other => {
                return Err(io::Error::other(format!(
                    "expected file data, got {other:?}"
                )))
            }
        };

        let outcome = (|| -> io::Result<Hash> {
            let mut writer = BufWriter::with_capacity(
                256 * 1024,
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(tmp)
                    .ctx(|| format!("opening {}", tmp.display()))?,
            );
            proto::read_stream(&mut self.stream, &mut writer)?;
            writer.flush()?;
            fsync_hard(writer.get_ref())?;
            drop(writer);
            // The whole file is verified, the prefix included.
            let got = hash_file(tmp).ctx(|| format!("hashing {}", tmp.display()))?;
            if got != expected {
                return Err(crate::fsutil::verification_error(
                    "received content does not match the hash the other side announced",
                ));
            }
            let total = fs::metadata(tmp)?.len();
            if total != size {
                return Err(crate::fsutil::verification_error(format!(
                    "expected {size} bytes, received {total}"
                )));
            }
            crate::fsutil::apply_mtime(tmp, mtime, "storing");
            fs::rename(tmp, local_dst).ctx(|| {
                format!(
                    "moving {} into place at {}",
                    tmp.display(),
                    local_dst.display()
                )
            })?;
            let _ = sync_dir(parent);
            Ok(expected)
        })();
        match outcome.as_ref().err() {
            // A file that does not verify is of no use to anyone.
            Some(error) if crate::fsutil::is_verification_error(error) => {
                let _ = fs::remove_file(tmp);
            }
            // An interrupted transfer keeps what it has, so the next run can
            // continue it. Without a resume the partial file goes.
            Some(_) if !keep_partial => {
                let _ = fs::remove_file(tmp);
            }
            _ => {}
        }
        outcome
    }
}

impl Drop for RemoteBackend {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.spool_path);
    }
}

impl Backend for RemoteBackend {
    fn label(&self) -> &str {
        &self.label
    }

    fn local_root(&self) -> Option<&Path> {
        None
    }

    fn walk(&mut self) -> io::Result<Option<Result<Entry, PathFailure>>> {
        if !self.listing_done && self.spool.is_none() {
            self.read_listing()?;
        }
        if self.listing_done {
            return Ok(None);
        }
        let spool = self.spool.as_mut().expect("spool is open while listing");
        match proto::read_frame(spool)? {
            Frame::Entry(entry) => Ok(Some(Ok(entry))),
            Frame::EndList => {
                self.listing_done = true;
                Ok(None)
            }
            other => Err(io::Error::other(format!(
                "listing spool holds an unexpected frame {other:?}"
            ))),
        }
    }

    fn hash(&mut self, path: &Path) -> io::Result<Hash> {
        self.request(&Frame::Hash(path.to_path_buf()))
    }

    fn stat(&mut self, path: &Path) -> io::Result<Option<Entry>> {
        self.send(&Frame::Stat(path.to_path_buf()))?;
        match self.receive()? {
            Frame::StatReply(entry) => Ok(entry),
            Frame::Ack { message, .. } => Err(io::Error::other(message)),
            other => Err(io::Error::other(format!(
                "expected a stat reply, got {other:?}"
            ))),
        }
    }

    fn put(&mut self, path: &Path, local_src: &Path, resume: bool) -> io::Result<Hash> {
        crate::debug!("sending {}", path.display());
        let meta = fs::metadata(local_src).ctx(|| format!("stat {}", local_src.display()))?;
        if !meta.is_file() {
            return Err(io::Error::other(format!(
                "{} is not a regular file",
                local_src.display()
            )));
        }
        let size = meta.len();
        // Hash before sending: the far end verifies what it receives against it.
        let expected = hash_file(local_src).ctx(|| format!("hashing {}", local_src.display()))?;

        // How much of the file the far end already holds, if the transfer may
        // be continued.
        let offset = if resume {
            self.remote_offset(path, size)?
        } else {
            0
        };

        if offset > 0 {
            self.send(&Frame::PushRange {
                path: path.to_path_buf(),
                size,
                mtime_ns: mtime_ns(&meta),
                hash: expected,
                offset,
            })?;
        } else {
            self.send(&Frame::Push {
                path: path.to_path_buf(),
                size,
                mtime_ns: mtime_ns(&meta),
                hash: expected,
            })?;
        }
        let mut reader = BufReader::new(File::open(local_src)?);
        if offset > 0 {
            reader
                .seek(SeekFrom::Start(offset))
                .ctx(|| format!("seeking in {}", local_src.display()))?;
        }
        let actual = proto::write_stream(&mut reader, &mut self.stream)?;
        self.stream.flush()?;
        if offset == 0 && actual != expected {
            return Err(io::Error::other(
                "the file changed while it was being sent; nothing was written remotely",
            ));
        }
        self.expect_ack()
    }

    fn get(&mut self, path: &Path, local_dst: &Path, resume: bool) -> io::Result<Hash> {
        crate::debug!("receiving {}", path.display());
        let parent = local_dst.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent")
        })?;
        fs::create_dir_all(parent)?;
        let tmp = crate::side::temp_for(local_dst);
        let mut offset = 0u64;
        if resume {
            offset = fs::metadata(&tmp).map(|meta| meta.len()).unwrap_or(0);
        } else {
            let _ = fs::remove_file(&tmp);
        }

        // A file that shrank on the other side cannot be continued: the
        // partial file is dropped and the transfer starts over.
        let mut restarted = false;
        loop {
            match self.fetch(path, offset, &tmp, local_dst, parent, resume) {
                Ok(hash) => return Ok(hash),
                Err(error) => {
                    let restart = !restarted && error.to_string().contains(proto::RESUME_TOO_LONG);
                    if !restart {
                        return Err(error);
                    }
                    restarted = true;
                    let _ = fs::remove_file(&tmp);
                    offset = 0;
                }
            }
        }
    }

    /// Ask for the bytes from `offset` on and put the file in place.
    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.request(&Frame::Delete(path.to_path_buf())).map(|_| ())
    }

    fn finish(&mut self) -> io::Result<()> {
        let _ = self.send(&Frame::Bye);
        let _ = self.stream.flush();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_refusal;
    use std::io;

    /// A server that refuses the client certificate closes the connection
    /// instead of answering. Depending on the platform and the timing that
    /// arrives as a broken pipe, as a reset, as an unexpected end of file, or
    /// as the TLS alert itself — and all four mean the same thing.
    #[test]
    fn a_closed_connection_during_the_handshake_is_a_refusal() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::UnexpectedEof,
        ] {
            let error = io::Error::from(kind);
            assert!(is_refusal(&error), "{kind:?} must read as a refusal");
        }
        let alert = io::Error::other("received fatal alert: certificate required");
        assert!(is_refusal(&alert), "a TLS alert must read as a refusal");
    }

    /// Anything else is not a refusal: the other side may simply not speak the
    /// twin protocol.
    #[test]
    fn other_failures_are_not_refusals() {
        let error = io::Error::new(io::ErrorKind::InvalidData, "not a twin frame");
        assert!(!is_refusal(&error));
        let error = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        assert!(!is_refusal(&error));
    }

    /// On Linux a refused client finds a broken pipe where on macOS it finds
    /// the alert. Both have to say the same thing, because both mean the same
    /// thing.
    #[test]
    fn a_refusal_always_says_how_to_fix_it() {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::UnexpectedEof,
        ] {
            let message =
                super::handshake_error("127.0.0.1:1234", io::Error::from(kind)).to_string();
            assert!(message.contains("authorize"), "{message}");
            assert!(message.contains("not allowed"), "{message}");
        }
    }
}
