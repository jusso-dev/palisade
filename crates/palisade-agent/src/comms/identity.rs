//! The device identity the agent keeps after enrolment (#223): device,
//! tenant and group IDs, the certificate chain, the pinned root key, the
//! last accepted trust set, the check-in URL, and the device key.
//!
//! It is stored as one file, sealed by a [`Protector`] (machine-scope DPAPI
//! on Windows) under its own purpose, in the agent's SYSTEM-only data
//! directory. The device key's PKCS#8 document is inside the sealed blob
//! and is wiped from memory after loading. A TPM-backed key (#220) would
//! keep only a key handle here.
//!
//! A file that is missing means "not enrolled". A file that is present but
//! cannot be unsealed or parsed is an error, never a reason to enrol again
//! silently: re-enrolment needs a registration code, which an attacker who
//! can corrupt the file must not be able to make the agent ask for.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use palisade_proto::comms::Base64;
use palisade_proto::events::{HostId, TenantId, Uuid7};
use palisade_proto::pki::leaf_key::{LeafKey, Pkcs8};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::policy_cache::Protector;

/// The protection purpose of the identity file.
pub const IDENTITY_PURPOSE: &[u8] = b"palisade-device-identity-v1";
/// The identity file's name.
pub const IDENTITY_FILE: &str = "identity.bin";
/// The largest identity file read, in bytes.
const MAX_IDENTITY: u64 = 512 * 1024;

/// What enrolment produced.
pub struct Identity {
    /// The device ID.
    pub device: HostId,
    /// The tenant.
    pub tenant: TenantId,
    /// The group.
    pub group: Uuid7,
    /// The device certificate first, then the issuing CA, DER.
    pub chain: Vec<Vec<u8>>,
    /// The root key's DER `SubjectPublicKeyInfo`, pinned for trust sets.
    pub root_key: Vec<u8>,
    /// The last accepted signed trust set.
    pub trust_set: Vec<u8>,
    /// Where to check in.
    pub checkin_url: String,
    /// The device key.
    pub key: Arc<LeafKey>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("device", &self.device)
            .field("tenant", &self.tenant)
            .field("group", &self.group)
            .field("checkin_url", &self.checkin_url)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    device: HostId,
    tenant: TenantId,
    group: Uuid7,
    chain: Vec<Base64<{ palisade_proto::comms::MAX_CERT_DER }>>,
    root_key: Base64<{ palisade_proto::pki::key::MAX_SPKI_LEN }>,
    trust_set: Base64<{ palisade_proto::pki::trust_set::MAX_ENVELOPE_LEN }>,
    checkin_url: String,
    key: Base64<4096>,
}

/// Reads and writes the sealed identity file.
pub struct IdentityStore {
    path: PathBuf,
    protector: Box<dyn Protector>,
}

impl fmt::Debug for IdentityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_owned())
}

impl IdentityStore {
    /// The store for `dir`/[`IDENTITY_FILE`].
    #[must_use]
    pub fn new(dir: &Path, protector: Box<dyn Protector>) -> Self {
        Self {
            path: dir.join(IDENTITY_FILE),
            protector,
        }
    }

    /// The identity, or `None` if the device is not enrolled.
    ///
    /// # Errors
    ///
    /// A file that cannot be read, unsealed or parsed.
    pub fn load(&self) -> io::Result<Option<Identity>> {
        let sealed = match std::fs::metadata(&self.path) {
            Ok(m) if m.len() > MAX_IDENTITY => {
                return Err(invalid("the identity file is too large"));
            }
            Ok(_) => std::fs::read(&self.path)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let plain = Zeroizing::new(self.protector.unprotect(&sealed, IDENTITY_PURPOSE)?);
        let stored: Stored = serde_json::from_slice(&plain)
            .map_err(|_| invalid("the identity file is malformed"))?;
        if stored.version != 1 {
            return Err(invalid("the identity file has an unknown version"));
        }
        let key = LeafKey::from_pkcs8(&Pkcs8::new(stored.key.into_bytes()))
            .map_err(|_| invalid("the identity file holds no usable device key"))?;
        Ok(Some(Identity {
            device: stored.device,
            tenant: stored.tenant,
            group: stored.group,
            chain: stored.chain.into_iter().map(Base64::into_bytes).collect(),
            root_key: stored.root_key.into_bytes(),
            trust_set: stored.trust_set.into_bytes(),
            checkin_url: stored.checkin_url,
            key: Arc::new(key),
        }))
    }

    /// Writes the identity with `pkcs8` as its key: to a temporary file,
    /// then renamed over the old one.
    ///
    /// # Errors
    ///
    /// The I/O or protection error.
    pub fn save(&self, identity: &Identity, pkcs8: &Pkcs8) -> io::Result<()> {
        fn b64<const N: usize>(v: &[u8]) -> io::Result<Base64<N>> {
            Base64::new(v.to_vec()).map_err(|_| invalid("a value is too large"))
        }
        let stored = Stored {
            version: 1,
            device: identity.device,
            tenant: identity.tenant,
            group: identity.group,
            chain: identity
                .chain
                .iter()
                .map(|c| b64(c))
                .collect::<io::Result<_>>()?,
            root_key: b64(&identity.root_key)?,
            trust_set: b64(&identity.trust_set)?,
            checkin_url: identity.checkin_url.clone(),
            key: b64(pkcs8.expose())?,
        };
        let plain = Zeroizing::new(serde_json::to_vec(&stored).map_err(io::Error::other)?);
        let sealed = self.protector.protect(&plain, IDENTITY_PURPOSE)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &self.path)
    }

    /// Updates the stored trust set after the agent accepted a newer one.
    ///
    /// # Errors
    ///
    /// As [`Self::load`] and [`Self::save`].
    pub fn update_trust_set(&self, trust_set: &[u8]) -> io::Result<()> {
        let sealed = std::fs::read(&self.path)?;
        let plain = Zeroizing::new(self.protector.unprotect(&sealed, IDENTITY_PURPOSE)?);
        let mut stored: Stored = serde_json::from_slice(&plain)
            .map_err(|_| invalid("the identity file is malformed"))?;
        stored.trust_set =
            Base64::new(trust_set.to_vec()).map_err(|_| invalid("the trust set is too large"))?;
        let plain = Zeroizing::new(serde_json::to_vec(&stored).map_err(io::Error::other)?);
        let sealed = self.protector.protect(&plain, IDENTITY_PURPOSE)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_cache::MemoryProtector;
    use std::str::FromStr;

    fn dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("palisade-identity-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn identity(key: Arc<LeafKey>) -> Identity {
        let id = Uuid7::from_str("019a0000-0000-7000-8000-000000000001").unwrap();
        Identity {
            device: HostId(id),
            tenant: TenantId(id),
            group: id,
            chain: vec![vec![1, 2, 3]],
            root_key: key.public_key().spki_der().to_vec(),
            trust_set: vec![9],
            checkin_url: "https://localhost:8444".to_owned(),
            key,
        }
    }

    #[test]
    fn the_identity_round_trips_sealed_and_never_holds_the_key_in_clear() {
        let d = dir("roundtrip");
        let store = IdentityStore::new(&d, Box::new(MemoryProtector::new().unwrap()));
        assert!(store.load().unwrap().is_none());
        let (key, pkcs8) = LeafKey::generate().unwrap();
        let key = Arc::new(key);
        store.save(&identity(key.clone()), &pkcs8).unwrap();
        let raw = std::fs::read(d.join(IDENTITY_FILE)).unwrap();
        assert!(
            !raw.windows(pkcs8.expose().len())
                .any(|w| w == pkcs8.expose())
        );
        let back = store.load().unwrap().unwrap();
        assert_eq!(back.key.public_key(), key.public_key());
        assert_eq!(back.chain, vec![vec![1, 2, 3]]);
        store.update_trust_set(&[7, 7]).unwrap();
        assert_eq!(store.load().unwrap().unwrap().trust_set, vec![7, 7]);
        assert!(!format!("{back:?}").contains("PRIVATE"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_corrupt_or_foreign_identity_is_an_error_not_unenrolled() {
        let d = dir("corrupt");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(IDENTITY_FILE), b"garbage").unwrap();
        let store = IdentityStore::new(&d, Box::new(MemoryProtector::new().unwrap()));
        assert!(store.load().is_err());
        // Sealed by another machine's key: also an error.
        let (key, pkcs8) = LeafKey::generate().unwrap();
        let other = IdentityStore::new(&d, Box::new(MemoryProtector::new().unwrap()));
        other.save(&identity(Arc::new(key)), &pkcs8).unwrap();
        assert!(store.load().is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
