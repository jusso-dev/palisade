//! The one place the hash cache calls a MAC library.
//!
//! ADR 0008 picks HMAC-SHA-256 for MACs, provided by `ring`, behind a thin
//! module so the provider can be swapped in one place. Signature
//! verification has its own such module (`authenticode/crypto.rs`).

#![forbid(unsafe_code)]

use std::fmt;

use ring::hmac;

/// Length of a hash cache record MAC: an HMAC-SHA-256 tag.
pub const MAC_LEN: usize = 32;

/// The shortest key accepted, in bytes. HMAC-SHA-256 keys shorter than the
/// output length weaken the MAC.
pub const MIN_KEY_LEN: usize = 32;

/// The key that authenticates hash cache records.
///
/// It is held by the agent and never written next to the cache (#18 owns
/// its lifecycle). `Debug` does not print it.
#[derive(Clone)]
pub struct MacKey(hmac::Key);

impl MacKey {
    /// A key from raw bytes, at least [`MIN_KEY_LEN`] long.
    pub fn new(bytes: &[u8]) -> Result<Self, MacKeyTooShort> {
        if bytes.len() < MIN_KEY_LEN {
            return Err(MacKeyTooShort { len: bytes.len() });
        }
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, bytes)))
    }

    pub(crate) fn tag(&self, data: &[u8]) -> [u8; MAC_LEN] {
        let tag = hmac::sign(&self.0, data);
        let mut out = [0_u8; MAC_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Checks `tag` over `data`, in constant time.
    pub(crate) fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        hmac::verify(&self.0, data, tag).is_ok()
    }
}

impl fmt::Debug for MacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MacKey(..)")
    }
}

/// A MAC key shorter than [`MIN_KEY_LEN`] was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacKeyTooShort {
    /// The length given.
    pub len: usize,
}

impl fmt::Display for MacKeyTooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a hash cache MAC key must be at least {MIN_KEY_LEN} bytes, got {}",
            self.len
        )
    }
}

impl std::error::Error for MacKeyTooShort {}
