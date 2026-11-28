//! HTTP `CONNECT` tunnels through an explicit proxy (#62): the request the
//! agent sends and the parser for the proxy's reply.
//!
//! The agent opens the tunnel in plaintext, then runs TLS end to end with
//! the server through it, so the proxy never sees the mTLS session and the
//! server's pinning still applies (ADR 0015). The proxy is not trusted: its
//! reply is parsed strictly and bounded, and only a `2xx` status opens the
//! tunnel. A proxy that inspects TLS breaks the session at the pinning
//! check, never silently.
//!
//! The parser reads the status line and headers only. Nothing after the
//! blank line is consumed: those bytes belong to the tunnel.

use std::fmt;

use super::http::{HeadError, parse_head};
pub use super::http::{MAX_HEAD, MAX_HEADERS};

/// The `CONNECT` request for `host:port`, with an optional
/// `Proxy-Authorization` value (for example `Basic <base64>`).
///
/// # Errors
///
/// [`ProxyError::BadTarget`] if `host` or the authorisation contains a
/// control character, space or anything else that could end the line.
pub fn connect_request(
    host: &str,
    port: u16,
    authorization: Option<&str>,
) -> Result<Vec<u8>, ProxyError> {
    let clean = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
    if !clean(host) || host.contains('/') || host.contains('@') {
        return Err(ProxyError::BadTarget);
    }
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut out = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = authorization {
        if !auth.bytes().all(|b| b.is_ascii_graphic() || b == b' ') || auth.is_empty() {
            return Err(ProxyError::BadTarget);
        }
        out.push_str("Proxy-Authorization: ");
        out.push_str(auth);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    Ok(out.into_bytes())
}

/// What the proxy answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectReply {
    /// The HTTP status code.
    pub status: u16,
    /// How many bytes of the input the head took, including the blank line.
    /// Bytes after it belong to the tunnel.
    pub head_len: usize,
}

impl ConnectReply {
    /// Whether the tunnel is open: a `2xx` status.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// A reply that is not a well-formed HTTP/1.x response head, or a request
/// that cannot be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// More input is needed: the blank line has not arrived yet.
    Incomplete,
    /// The head is longer than [`MAX_HEAD`] or has more than
    /// [`MAX_HEADERS`] lines.
    TooLarge,
    /// The status line or a header line is malformed.
    Malformed,
    /// The target host or authorisation cannot be written into a request.
    BadTarget,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "the proxy reply is incomplete",
            Self::TooLarge => "the proxy reply head is too large",
            Self::Malformed => "the proxy reply is not an HTTP/1.x response",
            Self::BadTarget => "the proxy target cannot be written into a request",
        })
    }
}

impl std::error::Error for ProxyError {}

/// Parses the reply head at the start of `input` with
/// [`super::http::parse_head`]. Call again with more bytes while it returns
/// [`ProxyError::Incomplete`].
///
/// # Errors
///
/// As [`super::http::parse_head`].
pub fn parse_reply(input: &[u8]) -> Result<ConnectReply, ProxyError> {
    match parse_head(input) {
        Ok(head) => Ok(ConnectReply {
            status: head.status,
            head_len: head.head_len,
        }),
        Err(HeadError::Incomplete) => Err(ProxyError::Incomplete),
        Err(HeadError::TooLarge) => Err(ProxyError::TooLarge),
        Err(HeadError::Malformed) => Err(ProxyError::Malformed),
    }
}
