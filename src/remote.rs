//! The far side of a pair, reached over mutual TLS. It implements the same
//! `Backend` seam the local filesystem does, so the engine does not know or care
//! which it is talking to.

use crate::fsutil::{fsync_hard, hash_file, mtime_ns, sync_dir, ErrCtx};
use crate::model::{Entry, Hash};
use crate::proto::{self, Frame, AGENT, PROTOCOL_VERSION, STATUS_MISSING, STATUS_OK};
use crate::side::Backend;
use crate::tls;
use rustls::{ClientConfig, ClientConnection};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static SPOOL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn handshake_error(label: &str, error: io::Error) -> io::Error {
    let text = error.to_string();
    let hint = if text.contains("alert") || text.contains("certificate") {
        "this client is not allowed there: run `twin id` here, then `twin authorize <fingerprint>` on the server"
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

    fn walk(&mut self) -> io::Result<Option<Entry>> {
        if !self.listing_done && self.spool.is_none() {
            self.read_listing()?;
        }
        if self.listing_done {
            return Ok(None);
        }
        let spool = self.spool.as_mut().expect("spool is open while listing");
        match proto::read_frame(spool)? {
            Frame::Entry(entry) => Ok(Some(entry)),
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

    fn put(&mut self, path: &Path, local_src: &Path) -> io::Result<Hash> {
        crate::debug!("sending {}", path.display());
        let meta = fs::metadata(local_src).ctx(|| format!("stat {}", local_src.display()))?;
        if !meta.is_file() {
            return Err(io::Error::other(format!(
                "{} is not a regular file",
                local_src.display()
            )));
        }
        // Hash before sending: the far end verifies what it receives against it.
        let expected = hash_file(local_src)?;
        self.send(&Frame::Push {
            path: path.to_path_buf(),
            size: meta.len(),
            mtime_ns: mtime_ns(&meta),
            hash: expected,
        })?;
        let actual = proto::write_stream(
            &mut BufReader::new(File::open(local_src)?),
            &mut self.stream,
        )?;
        self.stream.flush()?;
        if actual != expected {
            return Err(io::Error::other(
                "the file changed while it was being sent; nothing was written remotely",
            ));
        }
        self.expect_ack()
    }

    fn get(&mut self, path: &Path, local_dst: &Path) -> io::Result<Hash> {
        crate::debug!("receiving {}", path.display());
        self.send(&Frame::Get(path.to_path_buf()))?;
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

        let parent = local_dst.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent")
        })?;
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(".twin-tmp-{}-recv", std::process::id()));
        let outcome = (|| -> io::Result<Hash> {
            let mut writer = BufWriter::with_capacity(256 * 1024, File::create(&tmp)?);
            let written = proto::read_stream(&mut self.stream, &mut writer)?;
            writer.flush()?;
            fsync_hard(writer.get_ref())?;
            drop(writer);
            if written != expected {
                return Err(io::Error::other(
                    "received content does not match the hash the other side announced",
                ));
            }
            let got = fs::metadata(&tmp)?.len();
            if got != size {
                return Err(io::Error::other(format!(
                    "expected {size} bytes, received {got}"
                )));
            }
            crate::fsutil::apply_mtime(&tmp, mtime, "storing");
            fs::rename(&tmp, local_dst).ctx(|| {
                format!(
                    "moving {} into place at {}",
                    tmp.display(),
                    local_dst.display()
                )
            })?;
            let _ = sync_dir(parent);
            Ok(expected)
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        outcome
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.request(&Frame::Delete(path.to_path_buf())).map(|_| ())
    }

    fn finish(&mut self) -> io::Result<()> {
        let _ = self.send(&Frame::Bye);
        let _ = self.stream.flush();
        Ok(())
    }
}
