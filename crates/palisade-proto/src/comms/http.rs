//! The HTTP/1.1 response head, as the agent reads it from the server and
//! from a proxy (#62).
//!
//! The agent talks HTTP/1.1 with `Connection: close`, one request per
//! connection, so it only ever needs a response head and a body of known
//! length. Keeping its own strict parser keeps a general HTTP client stack
//! out of the privileged service (ADR 0003). Everything here is bounded and
//! nothing indexes: the head is at most [`MAX_HEAD`] bytes and
//! [`MAX_HEADERS`] lines, each line must end in CRLF, header names must be
//! tokens, and values may not hold control characters.
//!
//! Only what the agent acts on is extracted: the status, `Content-Length`,
//! `Retry-After` (seconds) and whether `Transfer-Encoding` is present. The
//! agent refuses a body with `Transfer-Encoding` or more than one
//! `Content-Length`, so a response cannot be framed two ways.

use std::fmt;

/// The longest response head accepted, in bytes.
pub const MAX_HEAD: usize = 8 * 1024;
/// Most header lines accepted.
pub const MAX_HEADERS: usize = 64;

/// A parsed response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    /// The status code, 100 to 599.
    pub status: u16,
    /// How many bytes the head took, including the blank line. The body
    /// starts here.
    pub head_len: usize,
    /// `Content-Length`, if present.
    pub content_length: Option<u64>,
    /// `Retry-After` in seconds, if present in that form.
    pub retry_after: Option<u32>,
    /// Whether a `Transfer-Encoding` header is present.
    pub transfer_encoding: bool,
}

/// A head that is not a well-formed HTTP/1.x response head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// More input is needed: the blank line has not arrived yet.
    Incomplete,
    /// The head is longer than [`MAX_HEAD`] or has more than
    /// [`MAX_HEADERS`] lines.
    TooLarge,
    /// The status line or a header line is malformed, or the framing
    /// headers are ambiguous.
    Malformed,
}

impl fmt::Display for HeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "the response head is incomplete",
            Self::TooLarge => "the response head is too large",
            Self::Malformed => "the response is not a well-formed HTTP/1.x response",
        })
    }
}

impl std::error::Error for HeadError {}

/// Parses the response head at the start of `input`. Call again with more
/// bytes while it returns [`HeadError::Incomplete`].
///
/// # Errors
///
/// [`HeadError::Incomplete`] until a full head is present,
/// [`HeadError::TooLarge`] past the limits, and [`HeadError::Malformed`]
/// for anything that is not `HTTP/1.0` or `HTTP/1.1`, a three-digit status
/// and well-formed header lines, or for two `Content-Length` headers or one
/// that is not a decimal number.
pub fn parse_head(input: &[u8]) -> Result<Head, HeadError> {
    let window = input.get(..input.len().min(MAX_HEAD)).unwrap_or_default();
    let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(if input.len() >= MAX_HEAD {
            HeadError::TooLarge
        } else {
            HeadError::Incomplete
        });
    };
    let head = window.get(..end).ok_or(HeadError::Malformed)?;
    let mut lines = CrlfLines(Some(head));
    let status_line = lines.next().ok_or(HeadError::Malformed)?;
    let status = parse_status_line(status_line)?;
    let mut out = Head {
        status,
        head_len: end + 4,
        content_length: None,
        retry_after: None,
        transfer_encoding: false,
    };
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(HeadError::TooLarge);
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or(HeadError::Malformed)?;
        let name = line.get(..colon).ok_or(HeadError::Malformed)?;
        if name.is_empty() || !name.iter().all(|&b| is_token(b)) {
            return Err(HeadError::Malformed);
        }
        let value = line.get(colon + 1..).unwrap_or_default();
        if value.iter().any(|&b| b.is_ascii_control() && b != b'\t') {
            return Err(HeadError::Malformed);
        }
        let value = trim(value);
        if name.eq_ignore_ascii_case(b"content-length") {
            if out.content_length.is_some() {
                return Err(HeadError::Malformed);
            }
            out.content_length = Some(decimal(value).ok_or(HeadError::Malformed)?);
        } else if name.eq_ignore_ascii_case(b"retry-after") {
            out.retry_after = decimal(value).and_then(|v| u32::try_from(v).ok());
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            out.transfer_encoding = true;
        }
    }
    Ok(out)
}

/// A decimal number of 1 to 19 digits.
fn decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 19 || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    value.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })
}

fn trim(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    value.get(start..end).unwrap_or_default()
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

fn parse_status_line(line: &[u8]) -> Result<u16, HeadError> {
    let rest = line
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| line.strip_prefix(b"HTTP/1.0 "))
        .ok_or(HeadError::Malformed)?;
    let (digits, reason) = rest.split_at_checked(3).ok_or(HeadError::Malformed)?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return Err(HeadError::Malformed);
    }
    if !(reason.is_empty() || reason.first() == Some(&b' ')) {
        return Err(HeadError::Malformed);
    }
    if reason.iter().any(|&b| b.is_ascii_control() && b != b'\t') {
        return Err(HeadError::Malformed);
    }
    let status = digits
        .iter()
        .fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    if !(100..=599).contains(&status) {
        return Err(HeadError::Malformed);
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
