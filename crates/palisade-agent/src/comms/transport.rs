//! One HTTPS request per connection, directly or through an explicit HTTP
//! proxy (#62).
//!
//! The agent opens a TCP connection (to the server, or to the proxy and
//! then a `CONNECT` tunnel), runs TLS with [`super::tls`], sends one
//! HTTP/1.1 request with `Connection: close`, and reads one response whose
//! head is parsed by [`palisade_proto::comms::http`] and whose body is
//! bounded by the caller. Every step has a deadline. Nothing here falls back
//! to plaintext or to weaker TLS: a failure is reported, classified, and
//! retried by the caller with backoff.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use palisade_proto::comms::http::{self, HeadError};
use palisade_proto::comms::proxy;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::tls::PIN_MISMATCH;

/// The deadline for each request, from connect to the last body byte (#62:
/// 30 s by default).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An `https://host[:port]` endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The host name or IP literal, without brackets.
    pub host: String,
    /// The port.
    pub port: u16,
}

impl Endpoint {
    /// Parses `https://host[:port][/]`. Paths, queries, credentials and other
    /// schemes are refused, so a URL cannot smuggle anything into a request.
    ///
    /// # Errors
    ///
    /// A message naming the problem.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("`{url}` is not an https:// URL"))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty()
            || rest.contains(['/', '?', '#', '@'])
            || rest.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!(
                "`{url}` must be https://host[:port] with nothing after it"
            ));
        }
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, after) = v6
                .split_once(']')
                .ok_or_else(|| format!("`{url}` has an unclosed IPv6 literal"))?;
            let port = match after {
                "" => 443,
                p => p
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .ok_or_else(|| format!("`{url}` has an invalid port"))?,
            };
            (host.to_owned(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_owned(),
                    p.parse()
                        .map_err(|_| format!("`{url}` has an invalid port"))?,
                ),
                None => (rest.to_owned(), 443),
            }
        };
        if host.is_empty() || port == 0 {
            return Err(format!("`{url}` has no host or port"));
        }
        ServerName::try_from(host.clone())
            .map_err(|_| format!("`{url}` has an invalid host name"))?;
        Ok(Self { host, port })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}", self.authority())
    }
}

/// An explicit HTTP proxy: `http://host:port`, with optional Basic
/// credentials. Proxy credentials are secrets: `Debug` never prints them,
/// and storing them DPAPI-protected is #62's remaining work.
#[derive(Clone, PartialEq, Eq)]
pub struct Proxy {
    /// The proxy host.
    pub host: String,
    /// The proxy port.
    pub port: u16,
    /// `Proxy-Authorization` value, such as `Basic <base64>`.
    pub authorization: Option<String>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("host", &self.host)
            .field("port", &self.port)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Proxy {
    /// Parses `http://host:port[/]`.
    ///
    /// # Errors
    ///
    /// A message naming the problem.
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("proxy `{url}` is not an http:// URL"))?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| format!("proxy `{url}` needs a port"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| format!("proxy `{url}` has an invalid port"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || port == 0 || host.contains(['/', '@', '?', '#']) {
            return Err(format!("proxy `{url}` must be http://host:port"));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            authorization: None,
        })
    }
}

/// Whether `host` is in a `NO_PROXY`-style list: comma-separated names, a
/// leading `.` or `*.` for a domain and its subdomains, `*` for all.
#[must_use]
pub fn bypasses(no_proxy: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    no_proxy.iter().any(|entry| {
        let entry = entry.trim().to_ascii_lowercase();
        if entry == "*" {
            return true;
        }
        let domain = entry.trim_start_matches("*.").trim_start_matches('.');
        !domain.is_empty() && (host == domain || host.ends_with(&format!(".{domain}")))
    })
}

/// How a request failed. The caller backs off on every kind; the kinds
/// differ in what they are logged and reported as.
#[derive(Debug)]
pub enum TransportError {
    /// TCP connect, the proxy tunnel or the TLS handshake failed (an ADR
    /// 0015 handshake failure).
    Connect(String),
    /// The server's chain did not end in a pinned root
    /// (`transport.pin_mismatch`: possible interception).
    PinMismatch,
    /// The response was not well-formed HTTP, or was too large.
    Protocol(String),
    /// The deadline passed.
    Timeout,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "cannot connect: {e}"),
            Self::PinMismatch => f.write_str(
                "the server's certificate chain does not end in a pinned CA (transport.pin_mismatch)",
            ),
            Self::Protocol(e) => write!(f, "malformed response: {e}"),
            Self::Timeout => f.write_str("the request timed out"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A response: status, `Retry-After` and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// `Retry-After` in seconds, if the server sent one.
    pub retry_after: Option<u32>,
    /// The body.
    pub body: Vec<u8>,
}

/// Where requests go and how.
#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    tls: Arc<ClientConfig>,
    proxy: Option<Proxy>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("proxy", &self.proxy)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client for `endpoint`, with TLS configuration `tls` and an
    /// optional proxy.
    #[must_use]
    pub fn new(endpoint: Endpoint, tls: Arc<ClientConfig>, proxy: Option<Proxy>) -> Self {
        Self {
            endpoint,
            tls,
            proxy,
        }
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Sends `method path` with `body` (JSON when given) and reads a
    /// response of at most `max_body` bytes, within [`REQUEST_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`TransportError`].
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Response, TransportError> {
        tokio::time::timeout(
            REQUEST_TIMEOUT,
            self.request_inner(method, path, body, max_body),
        )
        .await
        .map_err(|_| TransportError::Timeout)?
    }

    async fn request_inner(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        max_body: usize,
    ) -> Result<Response, TransportError> {
        let tcp = match &self.proxy {
            None => TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
                .await
                .map_err(|e| TransportError::Connect(e.to_string()))?,
            Some(proxy) => self.tunnel(proxy).await?,
        };
        let name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let mut tls = TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| {
                if e.to_string().contains(PIN_MISMATCH) {
                    TransportError::PinMismatch
                } else {
                    TransportError::Connect(e.to_string())
                }
            })?;
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: palisade-agent/{}\r\n",
            self.endpoint.authority(),
            env!("CARGO_PKG_VERSION")
        )
        .into_bytes();
        match body {
            Some(b) => {
                request.extend_from_slice(
                    format!(
                        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        b.len()
                    )
                    .as_bytes(),
                );
                request.extend_from_slice(b);
            }
            None => request.extend_from_slice(b"\r\n"),
        }
        tls.write_all(&request)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        tls.flush()
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        read_response(&mut tls, max_body).await
    }

    async fn tunnel(&self, proxy: &Proxy) -> Result<TcpStream, TransportError> {
        let mut tcp = TcpStream::connect((proxy.host.as_str(), proxy.port))
            .await
            .map_err(|e| TransportError::Connect(format!("proxy: {e}")))?;
        let request = proxy::connect_request(
            &self.endpoint.host,
            self.endpoint.port,
            proxy.authorization.as_deref(),
        )
        .map_err(|e| TransportError::Connect(e.to_string()))?;
        tcp.write_all(&request)
            .await
            .map_err(|e| TransportError::Connect(format!("proxy: {e}")))?;
        // Read one byte at a time until the head ends, so no tunnel byte is
        // consumed: the TLS handshake starts right after it.
        let mut head = Vec::with_capacity(256);
        loop {
            let mut byte = [0u8; 1];
            let n = tcp
                .read(&mut byte)
                .await
                .map_err(|e| TransportError::Connect(format!("proxy: {e}")))?;
            if n == 0 {
                return Err(TransportError::Connect(
                    "the proxy closed the connection".to_owned(),
                ));
            }
            head.extend_from_slice(&byte);
            match proxy::parse_reply(&head) {
                Ok(reply) if reply.is_open() => return Ok(tcp),
                Ok(reply) => {
                    return Err(TransportError::Connect(format!(
                        "the proxy refused the tunnel with status {}",
                        reply.status
                    )));
                }
                Err(proxy::ProxyError::Incomplete) => {}
                Err(e) => return Err(TransportError::Connect(format!("proxy: {e}"))),
            }
        }
    }
}

/// Reads a response: the head, then a body framed by `Content-Length` or by
/// the connection closing, at most `max_body` bytes.
async fn read_response<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    max_body: usize,
) -> Result<Response, TransportError> {
    let limit = http::MAX_HEAD.saturating_add(max_body);
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let head = loop {
        match http::parse_head(&buf) {
            Ok(h) => break h,
            Err(HeadError::Incomplete) => {}
            Err(e) => return Err(TransportError::Protocol(e.to_string())),
        }
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            return Err(TransportError::Protocol(
                "the connection closed before the response head".to_owned(),
            ));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    if head.transfer_encoding {
        return Err(TransportError::Protocol(
            "Transfer-Encoding is not accepted".to_owned(),
        ));
    }
    let want = match head.content_length {
        Some(len) => {
            let len = usize::try_from(len).unwrap_or(usize::MAX);
            if len > max_body {
                return Err(TransportError::Protocol(format!(
                    "the body is larger than {max_body} bytes"
                )));
            }
            Some(head.head_len + len)
        }
        None => None,
    };
    loop {
        if want.is_some_and(|w| buf.len() >= w) {
            break;
        }
        if buf.len() > limit {
            return Err(TransportError::Protocol(format!(
                "the body is larger than {max_body} bytes"
            )));
        }
        let n = read_some(stream, &mut chunk).await?;
        if n == 0 {
            if want.is_some() {
                return Err(TransportError::Protocol(
                    "the connection closed before the body ended".to_owned(),
                ));
            }
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    let end = want.unwrap_or(buf.len());
    let body = buf.get(head.head_len..end).unwrap_or_default().to_vec();
    if body.len() > max_body {
        return Err(TransportError::Protocol(format!(
            "the body is larger than {max_body} bytes"
        )));
    }
    Ok(Response {
        status: head.status,
        retry_after: head.retry_after,
        body,
    })
}

/// Reads, treating a TLS close without `close_notify` as the end of the
/// stream: the body is framed by `Content-Length` where it matters.
async fn read_some<S: AsyncRead + Unpin>(
    stream: &mut S,
    chunk: &mut [u8],
) -> Result<usize, TransportError> {
    match stream.read(chunk).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(TransportError::Protocol(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse_strictly() {
        assert_eq!(
            Endpoint::parse("https://palisade.example").unwrap(),
            Endpoint {
                host: "palisade.example".to_owned(),
                port: 443
            }
        );
        let e = Endpoint::parse("https://localhost:8444/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("localhost", 8444));
        assert_eq!(e.to_string(), "https://localhost:8444");
        let v6 = Endpoint::parse("https://[2001:db8::1]:9443").unwrap();
        assert_eq!(v6.host, "2001:db8::1");
        assert_eq!(v6.to_string(), "https://[2001:db8::1]:9443");
        assert_eq!(Endpoint::parse("https://[::1]").unwrap().port, 443);
        for bad in [
            "http://x",
            "https://",
            "https://x/path",
            "https://u@x",
            "https://x:0",
            "https://x:port",
            "https://x?q",
            "https://[::1",
            "https://[::1]x",
            "https://a b",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn proxies_parse_and_hide_credentials() {
        let mut p = Proxy::parse("http://proxy.corp:3128/").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.corp", 3128));
        p.authorization = Some("Basic c2VjcmV0".to_owned());
        assert!(!format!("{p:?}").contains("c2VjcmV0"));
        for bad in [
            "https://p:1",
            "http://p",
            "http://p:x",
            "http://:1",
            "http://u@p:1",
        ] {
            assert!(Proxy::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn no_proxy_matches_names_and_domains() {
        let list = vec![".corp.example".to_owned(), "palisade".to_owned()];
        assert!(bypasses(&list, "srv.corp.example"));
        assert!(bypasses(&list, "corp.example"));
        assert!(bypasses(&list, "PALISADE"));
        assert!(!bypasses(&list, "notcorp.example"));
        assert!(!bypasses(&list, "palisade.other"));
        assert!(bypasses(&["*".to_owned()], "anything"));
        assert!(!bypasses(&[String::new()], "anything"));
        assert!(bypasses(&["*.corp.example".to_owned()], "a.corp.example"));
    }

    #[tokio::test]
    async fn responses_are_framed_and_bounded() {
        async fn read(bytes: &[u8], max: usize) -> Result<Response, TransportError> {
            let (mut a, mut b) = tokio::io::duplex(64 * 1024);
            a.write_all(bytes).await.unwrap();
            drop(a);
            read_response(&mut b, max).await
        }
        let r = read(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}extra", 10)
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        let r = read(
            b"HTTP/1.1 429 Slow\r\nRetry-After: 7\r\n\r\nuntil close",
            64,
        )
        .await
        .unwrap();
        assert_eq!(r.retry_after, Some(7));
        assert_eq!(r.body, b"until close");
        for (bytes, max) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort"[..],
                64,
            ),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n", 10),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 10),
            (b"HTTP/1.1 200 OK\r\n\r\n0123456789abc", 10),
            (b"garbage\r\n\r\n", 10),
            (b"HTTP/1.1 200", 10),
        ] {
            assert!(
                matches!(read(bytes, max).await, Err(TransportError::Protocol(_))),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn errors_display() {
        for e in [
            TransportError::Connect("x".to_owned()),
            TransportError::PinMismatch,
            TransportError::Protocol("x".to_owned()),
            TransportError::Timeout,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
