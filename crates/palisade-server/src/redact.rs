//! Log redaction (#227): a second line of defence behind "never pass a
//! secret to a log macro".
//!
//! [`RedactingMakeWriter`] wraps the log writer. Every complete line it is
//! given goes through [`redact_line`] before it is written:
//!
//! - **Sensitive field names.** In a JSON line, any object member whose
//!   name has a segment (split on `_`, `-` and `.`, compared without case)
//!   in [`SENSITIVE_SEGMENTS`] has its value replaced by `"[REDACTED]"`,
//!   whatever its type. This covers event fields and the fields of every
//!   span on the line. A name whose last segment is `file` or `path` is
//!   exempt: secrets are configured by path (`tls.key_file`,
//!   `database.password_file`) and the path is what an operator needs to
//!   fix a problem.
//! - **Secret-looking values**, in every string of a JSON line and in any
//!   line that is not JSON: admin API tokens (`pal_<env>_<id>_<secret>`,
//!   #227) keep their non-secret `pal_<env>_<id>_` prefix and lose the
//!   rest, an HTTP `Bearer` or `Basic` credential loses its value, and a PEM
//!   `PRIVATE KEY` block loses its body.
//!
//! Redaction never fails open by dropping a line: a line it cannot parse as
//! JSON is still scanned for secret-looking values and then written.

use std::io::{self, Write};

use serde_json::Value;
use tracing_subscriber::fmt::MakeWriter;

/// What a redacted value becomes.
pub const REDACTED: &str = crate::secret::REDACTED;

/// Field-name segments that mark a value as secret.
pub const SENSITIVE_SEGMENTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "key",
    "authorization",
    "cookie",
    "code",
    "credential",
    "credentials",
];

/// Last segments that mark a name as a path to a secret, not the secret.
const PATH_SEGMENTS: &[&str] = &["file", "path"];

/// Whether a field named `name` holds a secret.
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    let segments: Vec<String> = name
        .split(['_', '-', '.'])
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if segments
        .last()
        .is_some_and(|last| PATH_SEGMENTS.contains(&last.as_str()))
    {
        return false;
    }
    segments
        .iter()
        .any(|s| SENSITIVE_SEGMENTS.contains(&s.as_str()))
}

/// Redacts one log line (without its line ending).
#[must_use]
pub fn redact_line(line: &str) -> String {
    match serde_json::from_str::<Value>(line) {
        Ok(mut value @ (Value::Object(_) | Value::Array(_))) => {
            redact_value(&mut value);
            serde_json::to_string(&value).unwrap_or_else(|_| redact_text(line))
        }
        _ => redact_text(line),
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (name, v) in map.iter_mut() {
                if is_sensitive_name(name) {
                    *v = Value::String(REDACTED.to_owned());
                } else {
                    redact_value(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::String(s) => {
            let redacted = redact_text(s);
            if redacted != *s {
                *s = redacted;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Masks secret-looking values in free text.
#[must_use]
pub fn redact_text(text: &str) -> String {
    let text = redact_pem_private_keys(text);
    let text = redact_auth_schemes(&text);
    redact_api_tokens(&text)
}

/// Replaces the body of every PEM `PRIVATE KEY` block (`PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`): every
/// character between the begin marker and the next `-----END `. A block
/// with no end marker loses everything after its begin marker.
fn redact_pem_private_keys(text: &str) -> String {
    const MARKER: &str = "PRIVATE KEY-----";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(MARKER) {
        let header_end = at + MARKER.len();
        // Only a begin marker: the text before it on the line has `BEGIN`.
        let line_start = rest[..at].rfind('\n').map_or(0, |i| i + 1);
        let is_begin = rest[line_start..at].contains("-----BEGIN ");
        out.push_str(&rest[..header_end]);
        rest = &rest[header_end..];
        if !is_begin {
            continue;
        }
        out.push_str(REDACTED);
        match rest.find("-----END ") {
            Some(end) => rest = &rest[end..],
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

/// Replaces the credential after `Bearer ` or `Basic ` (any case).
fn redact_auth_schemes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        let matched = ["bearer ", "basic "].iter().find(|scheme| {
            text.get(i..i + scheme.len())
                .is_some_and(|w| w.eq_ignore_ascii_case(scheme))
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        });
        if let Some(scheme) = matched {
            let value_start = i + scheme.len();
            let value_end = text[value_start..]
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | ',' | ';' | '\''))
                .map_or(text.len(), |e| value_start + e);
            if value_end > value_start {
                out.push_str(&text[i..value_start]);
                out.push_str(REDACTED);
                i = value_end;
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Masks the secret part of admin API tokens: `pal_<env>_<id>_<secret>`,
/// with `env` lowercase letters and digits, `id` 8 letters and digits and
/// the secret 20 or more letters and digits. The prefix up to the last
/// `_` stays, so a token can still be identified.
fn redact_api_tokens(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        if let Some(prefix_len) = token_at(text, i) {
            out.push_str(&text[i..i + prefix_len]);
            out.push_str(REDACTED);
            let secret_len = text[i + prefix_len..]
                .find(|c: char| !c.is_ascii_alphanumeric())
                .unwrap_or(text.len() - i - prefix_len);
            i += prefix_len + secret_len;
            continue;
        }
        let ch = text[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// If a token starts at byte `i`, the length of its non-secret prefix.
fn token_at(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if i > 0 && bytes.get(i - 1).is_some_and(u8::is_ascii_alphanumeric) {
        return None;
    }
    let rest = text.get(i..)?.strip_prefix("pal_")?;
    let (env, rest) = rest.split_once('_')?;
    if env.is_empty()
        || !env
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return None;
    }
    let id = rest.get(..8)?;
    if !id.bytes().all(|b| b.is_ascii_alphanumeric()) || rest.as_bytes().get(8) != Some(&b'_') {
        return None;
    }
    let secret = &rest[9..];
    let secret_len = secret
        .find(|c: char| !c.is_ascii_alphanumeric())
        .unwrap_or(secret.len());
    (secret_len >= 20).then_some("pal_".len() + env.len() + 1 + 9)
}

/// A [`MakeWriter`] whose writers redact each line before passing it to
/// the inner writer.
#[derive(Debug, Clone)]
pub struct RedactingMakeWriter<M>(pub M);

impl<'a, M: MakeWriter<'a>> MakeWriter<'a> for RedactingMakeWriter<M> {
    type Writer = RedactingWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.0.make_writer(),
            pending: Vec::new(),
        }
    }
}

/// Buffers until a line is complete, then writes it redacted. A partial
/// line left at drop is redacted and written then.
#[derive(Debug)]
pub struct RedactingWriter<W: Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: Write> RedactingWriter<W> {
    fn emit(&mut self, line: &[u8], newline: bool) -> io::Result<()> {
        let text = String::from_utf8_lossy(line);
        let mut out = redact_line(&text);
        if newline {
            out.push('\n');
        }
        self.inner.write_all(out.as_bytes())
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        while let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            let body = line.strip_suffix(b"\n").unwrap_or(&line);
            let body = body.strip_suffix(b"\r").unwrap_or(body);
            self.emit(body, true)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            // Nowhere to report a failed log write.
            let _ = self.emit(&rest, false);
        }
        let _ = self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TOKEN: &str = "pal_prod_AbCd1234_Q9w8E7r6T5y4U3i2O1p0AsDfGhJkL";

    #[test]
    fn sensitive_names() {
        for name in [
            "password",
            "db.password",
            "Authorization",
            "api_key",
            "access-token",
            "session.cookie",
            "stop_code",
            "client_secret",
            "PASSPHRASE",
            "credentials",
        ] {
            assert!(is_sensitive_name(name), "{name}");
        }
        for name in [
            "password_file",
            "tls.key_file",
            "db.password_file",
            "key_path",
            "listener",
            "keyring_status",
            "monkey",
            "status",
            "message",
            "",
        ] {
            assert!(!is_sensitive_name(name), "{name}");
        }
    }

    #[test]
    fn json_fields_are_redacted_at_any_depth() {
        let line = json!({
            "timestamp": "t",
            "level": "INFO",
            "fields": {"message": "login", "password": "hunter2", "user": "admin", "attempts": 3},
            "span": {"name": "request", "authorization": "Bearer abc"},
            "spans": [{"name": "outer", "api_key": 12345, "nested": {"token": {"a": 1}}}],
            "key_file": "/etc/palisade/server.key"
        })
        .to_string();
        let out: Value = serde_json::from_str(&redact_line(&line)).unwrap();
        assert_eq!(out["fields"]["password"], REDACTED);
        assert_eq!(out["fields"]["user"], "admin");
        assert_eq!(out["fields"]["attempts"], 3);
        assert_eq!(out["span"]["authorization"], REDACTED);
        assert_eq!(out["spans"][0]["api_key"], REDACTED);
        assert_eq!(out["spans"][0]["nested"]["token"], REDACTED);
        assert_eq!(out["key_file"], "/etc/palisade/server.key");
        assert!(!redact_line(&line).contains("hunter2"));
    }

    #[test]
    fn values_that_look_secret_are_masked_anywhere() {
        let msg = format!("rejected {TOKEN}, retry with {TOKEN}.");
        let out = redact_text(&msg);
        assert_eq!(
            out,
            "rejected pal_prod_AbCd1234_[REDACTED], retry with pal_prod_AbCd1234_[REDACTED]."
        );
        let line = json!({"fields": {"message": msg}}).to_string();
        assert!(!redact_line(&line).contains("Q9w8E7r6"));
        // Not tokens: too short a secret, a word before `pal_`, bad id.
        for text in [
            "pal_prod_AbCd1234_short",
            "xpal_prod_AbCd1234_Q9w8E7r6T5y4U3i2O1p0",
            "pal_PROD_AbCd1234_Q9w8E7r6T5y4U3i2O1p0",
            "pal_prod_AbCd123_Q9w8E7r6T5y4U3i2O1p0AA",
            "pal_prod_AbCd12-4_Q9w8E7r6T5y4U3i2O1p0",
            "pal__AbCd1234_Q9w8E7r6T5y4U3i2O1p0",
            "pal_",
        ] {
            assert_eq!(redact_text(text), text);
        }
        assert_eq!(
            redact_text("Authorization: Bearer eyJhbGciOi.x.y; next"),
            "Authorization: Bearer [REDACTED]; next"
        );
        assert_eq!(redact_text("basic dXNlcjpwYXNz"), "basic [REDACTED]");
        assert_eq!(redact_text("a bearer "), "a bearer ");
        assert_eq!(redact_text("debearer x"), "debearer x");
        assert_eq!(redact_text("naïve bearer ü"), "naïve bearer [REDACTED]");
    }

    #[test]
    fn pem_private_keys_lose_their_body() {
        let pem = "a -----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMG\n-----END PRIVATE KEY----- b";
        assert_eq!(
            redact_text(pem),
            "a -----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY----- b"
        );
        let ec = "-----BEGIN EC PRIVATE KEY-----MHcCAQEE";
        assert_eq!(redact_text(ec), "-----BEGIN EC PRIVATE KEY-----[REDACTED]");
        let cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(redact_text(cert), cert);
        assert_eq!(redact_text("-----BEGIN "), "-----BEGIN ");
    }

    #[test]
    fn non_json_lines_are_scanned_not_dropped() {
        assert_eq!(redact_line("plain text"), "plain text");
        assert_eq!(redact_line("\"a string\""), "\"a string\"");
        assert_eq!(
            redact_line(&format!("{{broken {TOKEN}")),
            "{broken pal_prod_AbCd1234_[REDACTED]"
        );
        assert_eq!(redact_line("[1, 2]"), "[1,2]");
    }

    #[test]
    fn writer_redacts_per_line_and_flushes_partial_lines() {
        let mut out = Vec::new();
        {
            let mut w = RedactingWriter {
                inner: &mut out,
                pending: Vec::new(),
            };
            let line1 = json!({"fields": {"password": "hunter2"}}).to_string();
            // Split across writes, with a CRLF line ending.
            w.write_all(&line1.as_bytes()[..10]).unwrap();
            w.write_all(format!("{}\r\n", &line1[10..]).as_bytes())
                .unwrap();
            w.write_all(format!("partial {TOKEN}").as_bytes()).unwrap();
            w.flush().unwrap();
        }
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "{\"fields\":{\"password\":\"[REDACTED]\"}}\npartial pal_prod_AbCd1234_[REDACTED]"
        );
    }

    #[test]
    fn make_writer_wraps_the_inner_writer() {
        let make = RedactingMakeWriter(io::sink);
        let mut w = make.make_writer();
        w.write_all(b"{\"token\":\"x\"}\n").unwrap();
    }
}
