//! Protecting the policy cache's secrets at rest (#326): the data keyring
//! and the anti-rollback record copies.
//!
//! A [`Protector`] wraps small blobs so only this machine can read them.
//! On Windows it is machine-scope DPAPI (`Dpapi`, through the agent's
//! `ffi` module). [`MemoryProtector`] is the portable backend for tests and
//! non-Windows development builds: it seals under a key that lives only in
//! the process, so nothing it protects survives a restart.
//!
//! Each use passes a distinct `purpose`, bound into the protection
//! (DPAPI's optional entropy), so a blob protected for one use never
//! unprotects for another.

use std::{fmt, io, sync::Mutex};

use palisade_proto::policy_bundle::at_rest::KeyRing;

/// The `purpose` of the data keyring.
pub const KEYRING_PURPOSE: &[u8] = b"palisade-policy-keyring-v1";
/// The `purpose` of an anti-rollback record copy.
pub const RECORD_PURPOSE: &[u8] = b"palisade-policy-record-v1";

/// Wraps blobs so only this machine can read them.
pub trait Protector: Send + Sync + fmt::Debug {
    /// Protects `data` for `purpose`.
    ///
    /// # Errors
    ///
    /// The OS error.
    fn protect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>>;

    /// Unprotects a blob [`Self::protect`] made for the same `purpose`.
    ///
    /// # Errors
    ///
    /// Any blob that was changed, made for another purpose or on another
    /// machine.
    fn unprotect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>>;
}

/// Machine-scope DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`). Any account on the
/// machine that can read a protected blob can unprotect it, so the blobs
/// are kept in SYSTEM-only storage (#220).
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Dpapi;

#[cfg(windows)]
impl Protector for Dpapi {
    fn protect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>> {
        crate::ffi::dpapi_protect(data, purpose)
    }

    fn unprotect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>> {
        crate::ffi::dpapi_unprotect(data, purpose)
    }
}

/// The protector the agent uses on this platform: [`Dpapi`] on Windows.
#[cfg(windows)]
pub fn platform() -> Box<dyn Protector> {
    Box::new(Dpapi)
}

/// Seals under an AES-256-GCM key that lives only in this process. For
/// tests and non-Windows development builds; see the module docs.
#[derive(Debug)]
pub struct MemoryProtector(Mutex<KeyRing>);

impl MemoryProtector {
    /// A protector with a fresh key.
    ///
    /// # Errors
    ///
    /// If the secure random source fails.
    pub fn new() -> io::Result<Self> {
        KeyRing::generate()
            .map(|r| Self(Mutex::new(r)))
            .map_err(io::Error::other)
    }

    fn ring(&self) -> std::sync::MutexGuard<'_, KeyRing> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `purpose`, its length, then `data`: the purpose is bound into what is
/// sealed, and cannot be confused with the data.
fn framed(data: &[u8], purpose: &[u8]) -> Vec<u8> {
    let len = u32::try_from(purpose.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + purpose.len() + data.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(purpose);
    out.extend_from_slice(data);
    out
}

impl Protector for MemoryProtector {
    fn protect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>> {
        let mut ring = self.ring();
        ring.reserve().map_err(io::Error::other)?;
        ring.seal(&framed(data, purpose)).map_err(io::Error::other)
    }

    fn unprotect(&self, data: &[u8], purpose: &[u8]) -> io::Result<Vec<u8>> {
        let opened = self
            .ring()
            .open(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let prefix = framed(&[], purpose);
        opened
            .strip_prefix(prefix.as_slice())
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "protected for another purpose")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_protector_binds_the_purpose_and_the_process_key() {
        let p = MemoryProtector::new().unwrap();
        let blob = p.protect(b"secret", RECORD_PURPOSE).unwrap();
        assert!(!blob.windows(6).any(|w| w == b"secret"));
        assert_eq!(p.unprotect(&blob, RECORD_PURPOSE).unwrap(), b"secret");
        assert!(p.unprotect(&blob, KEYRING_PURPOSE).is_err());
        assert!(p.unprotect(b"garbage", RECORD_PURPOSE).is_err());
        // Another process key: nothing opens.
        let other = MemoryProtector::new().unwrap();
        assert!(other.unprotect(&blob, RECORD_PURPOSE).is_err());
        // A purpose that is a prefix of another is still distinct.
        let short = p.protect(b"x", b"ab").unwrap();
        assert!(p.unprotect(&short, b"a").is_err());
    }
}
