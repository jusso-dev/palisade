//! Registration codes (#223): what proves an install may join a tenant and
//! group.
//!
//! A code is 12 to 24 characters from [`ALPHABET`], 30 characters with
//! nothing a reader can confuse (no `0`/`O`, `1`/`I`/`L`, or `U`). The
//! server generates it from the OS secure random source ([`generate`]), so a
//! 20-character code carries about 98 bits. It is shown to the
//! administrator once and stored only as its peppered hash
//! ([`Pepper::hash`]): HMAC-SHA-256 under a server-side secret, so a leaked
//! database does not reveal codes and cannot be brute-forced offline without
//! the pepper.
//!
//! People type codes, so [`normalise`] accepts lower case and ignores
//! spaces and hyphens before hashing: `abcd-efgh-jkmn` and `ABCDEFGHJKMN`
//! are the same code.

use std::fmt;

use crate::events::Sha256Hex;
use crate::pki::crypto::{self, MacKey};

/// The characters a code is made of.
pub const ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The shortest code.
pub const MIN_LEN: usize = 12;
/// The longest code.
pub const MAX_LEN: usize = 24;
/// The length [`generate`] uses by default.
pub const DEFAULT_LEN: usize = 20;

/// A registration code in normal form. `Debug` never prints it.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    /// The code, to show the administrator once or to send at enrolment.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code([REDACTED])")
    }
}

/// Why a string is not a registration code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeError {
    /// Shorter than [`MIN_LEN`] or longer than [`MAX_LEN`] characters.
    Length,
    /// A character outside [`ALPHABET`].
    Character,
    /// The secure random source failed.
    Random,
}

impl fmt::Display for CodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "a registration code is 12 to 24 characters",
            Self::Character => "a registration code has a character outside its alphabet",
            Self::Random => "the secure random source failed",
        })
    }
}

impl std::error::Error for CodeError {}

/// Reads a typed or installed code: ASCII letters in either case, with any
/// spaces and hyphens ignored.
///
/// # Errors
///
/// [`CodeError::Character`] for any other character, and
/// [`CodeError::Length`] unless 12 to 24 characters remain.
pub fn normalise(text: &str) -> Result<Code, CodeError> {
    let mut out = String::with_capacity(text.len().min(MAX_LEN));
    for c in text.chars() {
        if c == ' ' || c == '-' {
            continue;
        }
        let upper = c.to_ascii_uppercase();
        if !upper.is_ascii() || !ALPHABET.contains(&(upper as u8)) {
            return Err(CodeError::Character);
        }
        if out.len() == MAX_LEN {
            return Err(CodeError::Length);
        }
        out.push(upper);
    }
    if out.len() < MIN_LEN {
        return Err(CodeError::Length);
    }
    Ok(Code(out))
}

/// A new code of `len` characters, drawn uniformly from [`ALPHABET`] with
/// the OS secure random source.
///
/// # Errors
///
/// [`CodeError::Length`] unless `len` is 12 to 24, and
/// [`CodeError::Random`] if the random source fails.
pub fn generate(len: usize) -> Result<Code, CodeError> {
    if !(MIN_LEN..=MAX_LEN).contains(&len) {
        return Err(CodeError::Length);
    }
    // Rejection sampling: 30 * 8 = 240 is the largest multiple of 30 not
    // above 256, so bytes 240 and up are dropped and every character is
    // equally likely.
    const LIMIT: u8 = 240;
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 32];
    while out.len() < len {
        crypto::random(&mut buf).map_err(|_| CodeError::Random)?;
        for b in buf {
            if out.len() == len {
                break;
            }
            if b < LIMIT {
                let index = usize::from(b % 30);
                if let Some(&c) = ALPHABET.get(index) {
                    out.push(char::from(c));
                }
            }
        }
    }
    Ok(Code(out))
}

/// The server-side secret codes are hashed under. `Debug` never prints it.
pub struct Pepper(MacKey);

impl Pepper {
    /// A pepper from its 32 bytes, read from the server's secret store.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        Self(MacKey::new(key))
    }

    /// The stored form of `code`: HMAC-SHA-256 of its normal form.
    #[must_use]
    pub fn hash(&self, code: &Code) -> Sha256Hex {
        Sha256Hex::from_bytes(self.0.tag(code.0.as_bytes()))
    }
}

impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pepper([REDACTED])")
    }
}
