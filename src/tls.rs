//! Mutual-TLS transport. Both ends hold a self-signed ECDSA P-256 key pair and
//! trust is explicit: each side pins the other's certificate fingerprint. No CA,
//! no accounts, no third party in the middle.

use crate::proto;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, ClientConnection, DistinguishedName, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// Where identity, pins and archives live. One directory per user, never inside a
/// synced tree.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TWIN_DATA_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/twin")
}

pub fn normalize_fingerprint(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// SHA-256 over the certificate DER, lowercase hex without separators. Matches
/// what `openssl x509 -fingerprint -sha256` prints, minus the punctuation.
pub fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Identity {
    pub fingerprint: String,
    cert_pem: String,
    key_pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl Identity {
    pub fn load_or_create(dir: &Path) -> io::Result<Identity> {
        let identity_dir = dir.join("identity");
        let cert_path = identity_dir.join("cert.pem");
        let key_path = identity_dir.join("key.pem");
        if cert_path.is_file() && key_path.is_file() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let fingerprint = fingerprint_of(&parse_cert(&cert_pem)?);
            return Ok(Identity {
                fingerprint,
                cert_pem,
                key_pem,
                cert_path,
                key_path,
            });
        }

        fs::create_dir_all(&identity_dir)?;
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| io::Error::other(format!("cannot generate a key: {e}")))?;
        let mut params = rcgen::CertificateParams::new(vec!["twin".to_string()])
            .map_err(|e| io::Error::other(format!("cannot build a certificate: {e}")))?;
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2044, 1, 1);
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| io::Error::other(format!("cannot self-sign a certificate: {e}")))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        write_private(&key_path, &key_pem)?;
        fs::write(&cert_path, &cert_pem)?;
        Ok(Identity {
            fingerprint: fingerprint_of(&cert.der().clone()),
            cert_pem,
            key_pem,
            cert_path,
            key_path,
        })
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    fn certs(&self) -> io::Result<Vec<CertificateDer<'static>>> {
        Ok(vec![parse_cert(&self.cert_pem)?])
    }

    fn key(&self) -> io::Result<PrivateKeyDer<'static>> {
        rustls_pemfile::private_key(&mut self.key_pem.as_bytes())
            .map_err(|e| io::Error::other(format!("cannot read the private key: {e}")))?
            .ok_or_else(|| io::Error::other("no private key in the identity"))
    }
}

fn write_private(path: &Path, contents: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

fn parse_cert(pem: &str) -> io::Result<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .transpose()
        .map_err(|e| io::Error::other(format!("cannot read the certificate: {e}")))?
        .ok_or_else(|| io::Error::other("no certificate in the identity"))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Trust the far end by fingerprint and nothing else.
#[derive(Debug)]
struct PinnedPeer {
    expected: String,
}

impl ServerCertVerifier for PinnedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if fingerprint_of(end_entity) == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "the server presented {} but {} is pinned",
                fingerprint_of(end_entity),
                self.expected
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The other direction: only clients whose fingerprint was authorized may connect.
///
/// The list is shared and guarded by a lock: `twin authorize` writes the file,
/// the accept loop reads it back before every connection, and the verifier
/// reads the same set. A client that is authorized while the server runs is
/// let in on its next attempt, and a client that is removed is refused from
/// then on — no restart involved.
pub type AllowList = Arc<RwLock<HashSet<String>>>;

/// A shared allow list, ready to be handed to the verifier.
pub fn allow_list(fingerprints: Vec<String>) -> AllowList {
    Arc::new(RwLock::new(fingerprints.into_iter().collect()))
}

/// Read the allow list back from disk and publish it to the verifier.
pub fn refresh_allow_list(list: &AllowList, path: &Path) -> io::Result<()> {
    let fresh = read_list(path)?;
    let mut guard = list
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = fresh.into_iter().collect();
    Ok(())
}

/// The fingerprints the server currently accepts.
pub fn allowed_fingerprints(list: &AllowList) -> Vec<String> {
    let guard = list.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut names: Vec<String> = guard.iter().cloned().collect();
    names.sort();
    names
}

#[derive(Debug)]
struct AuthorizedClients {
    allowed: AllowList,
}

impl ClientCertVerifier for AuthorizedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let presented = fingerprint_of(end_entity);
        let allowed = self
            .allowed
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if allowed.contains(&presented) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "client {presented} is not authorized on this server (run `twin authorize {presented}` \
                 there; it takes effect on the next connection)"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn server_config(identity: &Identity, allowed: &AllowList) -> io::Result<Arc<ServerConfig>> {
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("cannot set up TLS: {e}")))?
        .with_client_cert_verifier(Arc::new(AuthorizedClients {
            allowed: allowed.clone(),
        }))
        .with_single_cert(identity.certs()?, identity.key()?)
        .map_err(|e| io::Error::other(format!("cannot use the identity: {e}")))?;
    Ok(Arc::new(config))
}

pub fn client_config(identity: &Identity, pinned: &str) -> io::Result<Arc<ClientConfig>> {
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::other(format!("cannot set up TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedPeer {
            expected: pinned.to_string(),
        }))
        .with_client_auth_cert(identity.certs()?, identity.key()?)
        .map_err(|e| io::Error::other(format!("cannot use the identity: {e}")))?;
    Ok(Arc::new(config))
}

/// Socket tuning is a convenience; a platform that refuses one of these must not
/// take the whole run down with it. Warn and carry on — but say exactly which
/// descriptor refused: a bare EINVAL here means the fd is not the socket the
/// caller believes it holds.
fn tune(tcp: &TcpStream, what: &str) {
    let mut failures: Vec<String> = Vec::new();
    if let Err(error) = tcp.set_nodelay(true) {
        failures.push(format!("Nagle ({error})"));
    }
    if let Err(error) = tcp.set_read_timeout(Some(IO_TIMEOUT)) {
        failures.push(format!("read timeout ({error})"));
    }
    if let Err(error) = tcp.set_write_timeout(Some(IO_TIMEOUT)) {
        failures.push(format!("write timeout ({error})"));
    }
    if !failures.is_empty() {
        crate::warn!(
            "{what}: could not set {}; continuing without them",
            failures.join(", ")
        );
        crate::warn!("{what}: {}", describe_socket(tcp));
    }
}

/// What the kernel thinks this descriptor is. Diagnosing "Invalid argument" on a
/// socket option without this is guesswork.
pub fn describe_socket(tcp: &TcpStream) -> String {
    use std::os::unix::io::AsRawFd;
    let fd = tcp.as_raw_fd();
    let mut parts = vec![format!("fd {fd}")];
    unsafe {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            parts.push(match value {
                libc::SOCK_STREAM => "SOCK_STREAM".to_string(),
                libc::SOCK_DGRAM => "SOCK_DGRAM".to_string(),
                other => format!("SO_TYPE={other}"),
            });
        } else {
            parts.push(format!("SO_TYPE={}", io::Error::last_os_error()));
        }

        let mut accepting: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            &mut accepting as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            parts.push(format!("SO_ACCEPTCONN={accepting}"));
        }

        let mut pending: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut pending as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            parts.push(format!("SO_ERROR={pending}"));
        }

        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(
            fd,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut peer_len,
        ) == 0
        {
            parts.push("peer=connected".to_string());
        } else {
            parts.push(format!("peer={}", io::Error::last_os_error()));
        }

        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            parts.push(format!("F_GETFL={flags:#x}"));
        }
    }
    parts.join(", ")
}

pub fn connect(
    host: &str,
    port: u16,
    config: Arc<ClientConfig>,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let tcp = TcpStream::connect((host, port))
        .map_err(|e| io::Error::new(e.kind(), format!("cannot reach {host}:{port}: {e}")))?;
    tune(&tcp, &format!("{host}:{port}"));
    crate::debug!("TCP connected to {host}:{port}, starting the handshake");

    let server_name = ServerName::try_from(host.to_string())
        .unwrap_or_else(|_| ServerName::try_from("twin.local").expect("static name"));
    let connection = ClientConnection::new(config, server_name)
        .map_err(|e| io::Error::other(format!("cannot start TLS: {e}")))?;
    let mut stream = StreamOwned::new(connection, tcp);
    // Run the handshake now so authentication failures surface here, with a hint,
    // instead of as a mystifying error on the first frame.
    if let Err(error) = stream.conn.complete_io(&mut stream.sock) {
        return Err(io::Error::other(format!(
            "{host}:{port}: the TLS handshake failed: {error}. Is this client authorized there \
             (`twin id` here, then `twin authorize <fingerprint>` on the server — it takes effect \
             on the next connection), and does the pin match?"
        )));
    }
    crate::debug!("handshake with {host}:{port} done");
    Ok(stream)
}

/// Serve one directory over TLS until interrupted. One connection at a time.
///
/// The allow list is read back from disk before every connection, so
/// `twin authorize` takes effect on the next attempt instead of after a
/// restart.
pub fn serve_forever(
    root: &Path,
    identity: &Identity,
    allowed: &AllowList,
    list_path: &Path,
    listen: &str,
    once: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    if allowed_fingerprints(allowed).is_empty() {
        return Err(io::Error::other(
            "no clients are authorized yet, so every connection would be refused.\n\
             On this machine run `twin id` on the client, then `twin authorize <fingerprint>` here.",
        ));
    }
    let config = server_config(identity, allowed)?;
    let listener = TcpListener::bind(listen)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot listen on {listen}: {e}")))?;
    let probe = crate::fsutil::probe_dir(root);
    if !probe.all_ok() {
        crate::warn!(
            "{} cannot do everything a sync needs: {}",
            root.display(),
            probe.notes.join("; ")
        );
    }
    let bound = listener.local_addr()?;
    crate::debug!("listening socket {bound} (fd {})", {
        use std::os::unix::io::AsRawFd;
        listener.as_raw_fd()
    });
    if !bound.ip().is_loopback() {
        match local_network_probe() {
            Ok(detail) => crate::info!("local network: {detail}"),
            Err(problem) => {
                crate::warn!("{problem}");
                let executable = std::env::current_exe().unwrap_or_default();
                if signature_state(&executable) == SignatureState::Unsigned {
                    crate::warn!(
                        "this binary is not signed, which is the usual reason macOS tears these \
                         connections down. Sign it and restart the server:\n  {}",
                        signing_command(&executable)
                    );
                }
            }
        }
    }
    writeln!(out, "listening on {bound}")?;
    writeln!(
        out,
        "serving {} as {}",
        root.display(),
        identity.fingerprint()
    )?;
    writeln!(
        out,
        "authorized clients: {}",
        allowed_fingerprints(allowed).len()
    )?;
    out.flush()?;

    loop {
        let (tcp, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) => {
                writeln!(out, "accept failed: {e}")?;
                continue;
            }
        };
        // The allow list is read back from disk for every connection: a client
        // authorized (or withdrawn) while the server runs is refused (or let
        // in) on its next attempt.
        if let Err(error) = refresh_allow_list(allowed, list_path) {
            crate::warn!("cannot read the authorized clients: {error}");
        }
        crate::debug!("accepted {peer}: {}", describe_socket(&tcp));
        tune(&tcp, &peer.to_string());
        crate::debug!("connection from {peer}, starting the handshake");
        let connection = match ServerConnection::new(config.clone()) {
            Ok(connection) => connection,
            Err(e) => {
                writeln!(out, "{peer}: cannot start TLS: {e}")?;
                continue;
            }
        };
        // One object, two borrows: the protocol is strictly request/response.
        let duplex = Duplex(RefCell::new(StreamOwned::new(connection, tcp)));
        match proto::serve(root, &mut &duplex, &mut &duplex) {
            Ok(()) => {}
            Err(error) => {
                writeln!(out, "{peer}: {error}")?;
                if error.kind() == io::ErrorKind::NotConnected {
                    writeln!(out, "{peer}: {LOCAL_NETWORK_HINT}")?;
                }
                out.flush()?;
            }
        }
        if once {
            return Ok(());
        }
    }
}

struct Duplex<S>(RefCell<S>);

impl<S: Read> Read for &Duplex<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}

impl<S: Write> Write for &Duplex<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// What macOS says when it refuses to let an unsigned program serve the local
/// network. The connection completes at the TCP level and is then torn down, so
/// the failure surfaces as EINVAL from setsockopt, EINVAL from getpeername and
/// ENOTCONN from read — all of which look like bugs in the program.
/// What macOS says when it refuses to let an unsigned program serve the local
/// network: the connection completes at the TCP level and is then torn down, so
/// the failure looks like EINVAL from setsockopt and ENOTCONN from reads.
pub const LOCAL_NETWORK_REMEDY: &str = "\n  • quickest, no password needed — ad-hoc sign this binary, then restart it:\n      codesign -s - -f --identifier dev.twin.cli <path to twin>\n  • or allow it: System Settings → Network → Firewall → Options… → allow the twin binary\n  • or grant the permission: System Settings → Privacy & Security → Local Network → enable the app that launched twin\n  A running process keeps the decision it started with, so restart the server afterwards.\n  Rebuilding invalidates an ad-hoc signature: sign after each build, or install to a stable\n  path (`cargo install --path .`) and sign once.";

/// One short line for the per-connection log.
pub const LOCAL_NETWORK_HINT: &str =
    "if this repeats for every connection, the system is refusing to let this program serve the \
     local network (an ad-hoc `codesign -s - -f --identifier dev.twin.cli <binary>` is usually \
     enough, then restart it); `twin doctor` shows the details";

/// What macOS thinks of this program's code signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureState {
    Signed,
    Unsigned,
    /// Not macOS, or codesign is unavailable: nothing to say.
    Unknown,
}

/// Signed programs may serve the local network by default; unsigned ones are torn
/// down. Reading it from `codesign` is exact, and the marker it prints for a
/// missing signature is stable.
pub fn signature_state(executable: &Path) -> SignatureState {
    if !cfg!(target_os = "macos") {
        return SignatureState::Unknown;
    }
    let output = match std::process::Command::new("/usr/bin/codesign")
        .arg("-dvvv")
        .arg(executable)
        .output()
    {
        Ok(output) => output,
        Err(_) => return SignatureState::Unknown,
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("not signed at all") {
        SignatureState::Unsigned
    } else if text.contains("CodeDirectory") {
        SignatureState::Signed
    } else {
        SignatureState::Unknown
    }
}

/// The command that fixes an unsigned binary, for messages.
pub fn signing_command(executable: &Path) -> String {
    format!(
        "codesign -s - -f --identifier dev.twin.cli {}",
        executable.display()
    )
}

fn peer_known(fd: i32) -> io::Result<()> {
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        if libc::getpeername(fd, &mut storage as *mut _ as *mut libc::sockaddr, &mut len) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Listen on `addr`, connect to ourselves, and see whether the accepted socket is
/// usable. This is the cheapest way to tell "the program is broken" apart from
/// "the system will not let this program receive connections here".
pub fn probe_address(addr: SocketAddr) -> Result<String, String> {
    use std::os::unix::io::AsRawFd;
    let listener = match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(error) => return Err(format!("cannot listen on {addr}: {error}")),
    };
    let bound = match listener.local_addr() {
        Ok(bound) => bound,
        Err(error) => return Err(format!("cannot inspect the listener on {addr}: {error}")),
    };
    let client = match TcpStream::connect(bound) {
        Ok(client) => client,
        Err(error) => {
            return Err(format!(
                "cannot connect to our own listener on {bound}: {error}"
            ))
        }
    };
    let accepted = match listener.accept() {
        Ok((accepted, _)) => accepted,
        Err(error) => return Err(format!("accept failed on {bound}: {error}")),
    };
    let verdict = match peer_known(accepted.as_raw_fd()) {
        Ok(()) => Ok(format!("accepted and used a connection on {bound}")),
        Err(error) => Err(format!(
            "a connection to {bound} completed and was torn down before this program could use it \
             ({error}). On macOS that is what an Application Firewall block, or a local-network \
             permission that was never granted, looks like.{LOCAL_NETWORK_REMEDY}"
        )),
    };
    drop(accepted);
    drop(client);
    verdict
}

/// The address this machine would be reached on from the local network.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // A UDP "connect" sends nothing; it only asks the routing table.
    socket.connect("1.1.1.1:53").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) if !addr.ip().is_loopback() && !addr.ip().is_unspecified() => {
            Some(*addr.ip())
        }
        _ => None,
    }
}

pub fn local_network_probe() -> Result<String, String> {
    match primary_ipv4() {
        None => Ok("this machine has no local-network address".to_string()),
        Some(ip) => probe_address(SocketAddr::new(IpAddr::V4(ip), 0)),
    }
}

pub fn authorized_path(dir: &Path) -> PathBuf {
    dir.join("authorized_clients")
}

pub fn read_list(path: &Path) -> io::Result<Vec<String>> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    Ok(fs::read_to_string(path)?
        .lines()
        .map(normalize_fingerprint)
        .filter(|line| !line.is_empty())
        .collect())
}

pub fn add_authorized(dir: &Path, fingerprint: &str) -> io::Result<Vec<String>> {
    let path = authorized_path(dir);
    let fingerprint = normalize_fingerprint(fingerprint);
    if fingerprint.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "a fingerprint is 64 hex characters; got {} of them",
                fingerprint.len()
            ),
        ));
    }
    let mut list = read_list(&path)?;
    if !list.contains(&fingerprint) {
        list.push(fingerprint);
        fs::create_dir_all(dir)?;
        fs::write(&path, format!("{}\n", list.join("\n")))?;
    }
    Ok(list)
}

pub fn read_pin(dir: &Path, host: &str, port: u16) -> io::Result<Option<String>> {
    let path = dir.join("known_hosts");
    if !path.is_file() {
        return Ok(None);
    }
    let key = format!("{host}:{port}");
    for line in fs::read_to_string(path)?.lines() {
        if let Some((name, value)) = line.split_once(char::is_whitespace) {
            if name == key {
                return Ok(Some(normalize_fingerprint(value)));
            }
        }
    }
    Ok(None)
}

pub fn write_pin(dir: &Path, host: &str, port: u16, fingerprint: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join("known_hosts");
    let key = format!("{host}:{port}");
    let value = normalize_fingerprint(fingerprint);
    let mut lines: Vec<String> = Vec::new();
    if path.is_file() {
        for line in fs::read_to_string(&path)?.lines() {
            if let Some((name, _)) = line.split_once(char::is_whitespace) {
                if name != key {
                    lines.push(line.to_string());
                }
            }
        }
    }
    lines.push(format!("{key} {value}"));
    fs::write(&path, format!("{}\n", lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_is_created_once_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = Identity::load_or_create(dir.path()).unwrap();
        let second = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 64, "sha-256 hex");

        let mode = fs::metadata(first.key_path()).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            mode.mode() & 0o777,
            0o600,
            "the private key must not be world readable"
        );
    }

    #[test]
    fn fingerprints_survive_the_shapes_people_paste() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path()).unwrap();
        let fp = identity.fingerprint().to_string();
        let spaced: String = fp
            .as_bytes()
            .chunks(2)
            .map(|pair| String::from_utf8_lossy(pair).to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(normalize_fingerprint(&spaced), fp);
        assert_eq!(normalize_fingerprint(&format!("  {fp} ")), fp);
    }

    #[test]
    fn pins_round_trip_per_host_and_port() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_pin(dir.path(), "mini", 9443).unwrap(), None);
        write_pin(dir.path(), "mini", 9443, "aa:bb:cc").unwrap();
        assert_eq!(
            read_pin(dir.path(), "mini", 9443).unwrap(),
            Some(normalize_fingerprint("aabbcc"))
        );
        assert_eq!(
            read_pin(dir.path(), "mini", 9444).unwrap(),
            None,
            "port matters"
        );
        // re-pinning the same host replaces rather than duplicates
        write_pin(dir.path(), "mini", 9443, "dd").unwrap();
        assert_eq!(
            read_pin(dir.path(), "mini", 9443).unwrap(),
            Some("dd".to_string())
        );
    }

    #[test]
    fn authorization_lists_reject_nonsense() {
        let dir = tempfile::tempdir().unwrap();
        let err = add_authorized(dir.path(), "too-short").unwrap_err();
        assert!(err.to_string().contains("64 hex"), "{err}");
        let fp = "ab".repeat(32);
        assert_eq!(add_authorized(dir.path(), &fp).unwrap().len(), 1);
        assert_eq!(
            add_authorized(dir.path(), &fp).unwrap().len(),
            1,
            "no duplicates"
        );
    }
}
