//! Shared fixtures: a throwaway CA, server and client certificates, config
//! files, and a minimal HTTP/1.1-over-TLS client.

#![allow(dead_code, missing_docs, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

pub mod x509;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, SupportedProtocolVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509::{Ca, Usage};

pub struct Pki {
    pub dir: PathBuf,
    pub ca_pem: String,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub agent_ca: PathBuf,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub other_client_cert_pem: String,
    pub other_client_key_pem: String,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh directory under the system temp dir.
pub fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "palisade-server-it-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn write_secret(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// A CA, a server certificate for `server_sans`, an agent CA with one
/// client certificate, and a client certificate from an unrelated CA.
pub fn pki(tag: &str, server_sans: &[&str]) -> Pki {
    let dir = temp_dir(tag);
    let server_ca = Ca::new("test server CA");
    let (server_cert, server_key) = server_ca.issue(server_sans, Usage::Server);
    let agent_ca = Ca::new("test agent CA");
    let (client_cert, client_key) = agent_ca.issue(&["agent-1"], Usage::Client);
    let rogue_ca = Ca::new("unrelated CA");
    let (other_cert, other_key) = rogue_ca.issue(&["agent-x"], Usage::Client);

    let server_cert_path = dir.join("server.crt");
    std::fs::write(&server_cert_path, &server_cert).unwrap();
    let server_key_path = dir.join("server.key");
    write_secret(&server_key_path, &server_key);
    let agent_ca_path = dir.join("agent-ca.crt");
    std::fs::write(&agent_ca_path, agent_ca.pem()).unwrap();
    Pki {
        ca_pem: server_ca.pem(),
        dir,
        server_cert: server_cert_path,
        server_key: server_key_path,
        agent_ca: agent_ca_path,
        client_cert_pem: client_cert,
        client_key_pem: client_key,
        other_client_cert_pem: other_cert,
        other_client_key_pem: other_key,
    }
}

/// A free TCP port on loopback (racy, but good enough for tests).
///
/// For more than one port, use [`free_ports`]: separate calls can return
/// the same number, because each probe socket is closed before the next
/// one asks the OS for a port.
pub fn free_port() -> u16 {
    let [port] = free_ports::<1>();
    port
}

/// `N` distinct free TCP ports on loopback. Every probe socket stays open
/// until all `N` have been chosen, so the OS cannot hand the same port out
/// twice. (The ports can still be taken by another process before the test
/// binds them, as with [`free_port`].)
pub fn free_ports<const N: usize>() -> [u16; N] {
    let held: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut ports = [0u16; N];
    for (slot, listener) in ports.iter_mut().zip(&held) {
        *slot = listener.local_addr().unwrap().port();
    }
    ports
}

/// Builds a client config trusting the test server CA.
pub fn client_config(
    pki: &Pki,
    versions: &[&'static SupportedProtocolVersion],
    client_cert: Option<(&str, &str)>,
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(pki.ca_pem.as_bytes()).unwrap())
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots);
    let mut cfg = match client_cert {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()],
                PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
            )
            .unwrap(),
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

pub async fn connect(
    cfg: Arc<ClientConfig>,
    addr: SocketAddr,
    name: &str,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from(name.to_owned()).unwrap();
    TlsConnector::from(cfg).connect(name, tcp).await
}

pub struct HttpResponse {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Sends one raw HTTP/1.1 request (with `Connection: close`) and reads the
/// whole response. Handles `Content-Length` bodies only.
pub async fn http1(stream: &mut TlsStream<TcpStream>, request: &[u8]) -> HttpResponse {
    stream.write_all(request).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    parse_response(&buf)
}

pub fn parse_response(buf: &[u8]) -> HttpResponse {
    let text = String::from_utf8_lossy(buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    HttpResponse {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

pub fn get_request(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Writes a config file and returns its path.
pub fn write_config(pki: &Pki, body: &str) -> PathBuf {
    let text = format!(
        "[tls]\ncert_file = {:?}\nkey_file = {:?}\n{body}",
        pki.server_cert.display().to_string(),
        pki.server_key.display().to_string()
    );
    let path = pki.dir.join("server.toml");
    std::fs::write(&path, text).unwrap();
    path
}

#[cfg(test)]
mod port_tests {
    /// Regression test: two listeners in one test must never get the same
    /// port. Separate `free_port` calls could, and the server then refused
    /// to start ("listen.admin and listen.agent both use 127.0.0.1 port …").
    #[test]
    fn free_ports_are_distinct() {
        for _ in 0..200 {
            let [a, b, c] = super::free_ports::<3>();
            assert!(a != b && b != c && a != c, "{a} {b} {c}");
        }
    }
}
