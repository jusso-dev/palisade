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

/// The longest reply head accepted, in bytes.
pub const MAX_HEAD: usize = 8 * 1024;
/// Most header lines accepted.
pub const MAX_HEADERS: usize = 64;

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

/// Parses the reply head at the start of `input`. Call again with more
/// bytes while it returns [`ProxyError::Incomplete`].
///
/// # Errors
///
/// [`ProxyError::Incomplete`] until a full head is present,
/// [`ProxyError::TooLarge`] past the limits, and [`ProxyError::Malformed`]
/// for anything that is not `HTTP/1.0` or `HTTP/1.1`, a three-digit status
/// and well-formed header lines, each ending in CRLF.
pub fn parse_reply(input: &[u8]) -> Result<ConnectReply, ProxyError> {
    let window = input.get(..input.len().min(MAX_HEAD)).unwrap_or_default();
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(if input.len() >= MAX_HEAD {
            ProxyError::TooLarge
        } else {
            ProxyError::Incomplete
        });
    };
    let head = window.get(..end).ok_or(ProxyError::Malformed)?;
    let mut lines = CrlfLines(Some(head));
    let status_line = lines.next().ok_or(ProxyError::Malformed)?;
    let status = parse_status_line(status_line)?;
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(ProxyError::TooLarge);
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(ProxyError::Malformed)?;
        let name = line.get(..colon).ok_or(ProxyError::Malformed)?;
        if name.is_empty() || !name.iter().all(|&b| is_token(b)) {
            return Err(ProxyError::Malformed);
        }
        let value = line.get(colon + 1..).unwrap_or_default();
        if value.iter().any(|&b| b.is_ascii_control() && b != b'\t') {
            return Err(ProxyError::Malformed);
        }
    }
    Ok(ConnectReply {
        status,
        head_len: end + 4,
    })
}

/// The lines of a head, split on CRLF. A bare CR or LF inside a line is
/// left in it, and the line checks then refuse it as a control character.
struct CrlfLines<'a>(Option<&'a [u8]>);

impl<'a> Iterator for CrlfLines<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.0?;
        match rest.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                self.0 = rest.get(i + 2..);
                rest.get(..i)
            }
            None => {
                self.0 = None;
                Some(rest)
            }
        }
    }
}

fn parse_status_line(line: &[u8]) -> Result<u16, ProxyError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or(ProxyError::Malformed)?;
    let (digits, reason) = rest.split_at_checked(3).ok_or(ProxyError::Malformed)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(ProxyError::Malformed);
    }
    if !(reason.is_empty() || reason.first() == Some(&b' ')) {
        return Err(ProxyError::Malformed);
    }
    if reason.iter().any(|&b| b.is_ascii_control() && b != b'\t') {
        return Err(ProxyError::Malformed);
    }
    let status = digits
        .iter()
        .fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(ProxyError::Malformed);
    }
    Ok(status)
}

/// An RFC 9110 `tchar`.
const fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}
