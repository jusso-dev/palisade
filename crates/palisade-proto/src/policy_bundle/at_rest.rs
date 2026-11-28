//! Policy cache files at rest (#326): AES-256-GCM sealing under a data key,
//! with the nonce and seal-count rules of ADR 0017.
//!
//! The agent seals each cache file (a signed bundle envelope, #325) before
//! writing it, and opens it after reading. Sealing adds confidentiality and
//! an integrity check, but it never replaces signature verification: the
//! opened bytes are the signed envelope, which the agent verifies as if it
//! had never been sealed. A file that does not open is unreadable, never
//! trusted.
//!
//! # Formats
//!
//! All integers are big-endian.
//!
//! ```text
//! sealed  = "PLCS" version:u8 (= 1) key_id:[u8;16] nonce:[u8;12] ciphertext tag:[u8;16]
//! keyring = "PLKR" version:u8 (= 1) seals:u64 key_id:[u8;16] key:[u8;32]
//!           retired:u8 (0 or 1) [key_id:[u8;16] key:[u8;32]]
//! ```
//!
//! A sealed file's additional authenticated data is
//! `"palisade-policy-cache-v1\0"` followed by its first 21 bytes (magic,
//! version and key ID), so the key ID cannot be changed without failing the
//! tag.
//!
//! # Keys and nonces (ADR 0017)
//!
//! [`KeyRing`] holds the current data key and, after a rotation, the one
//! before it (to open files sealed before the rotation). Every nonce is
//! drawn from the OS secure random source inside [`KeyRing::seal`]; no
//! caller can pass one. A key seals at most [`KeyRing::SEAL_LIMIT`] (2^32)
//! messages, which keeps the chance of any repeated nonce under one key at
//! or below 2^-33. The count is persisted **before** a seal is used:
//! [`KeyRing::reserve`] raises it (rotating first if the key is used up),
//! the caller persists [`KeyRing::encode`], and only then does
//! [`KeyRing::seal`] use the reservation. A keyring that is missing or does
//! not decode is never repaired: the caller generates a new one, which
//! "rotates now".
//!
//! The keyring holds raw keys, so the agent protects it before writing it
//! (machine-scope DPAPI on Windows). `ring` does not wipe key memory on
//! drop; the agent process is trusted with the keys for its life.

#![forbid(unsafe_code)]

use std::fmt;

use crate::pki::crypto::{self, AeadKey, NONCE_LEN, TAG_LEN};

/// The sealed file magic.
pub const SEALED_MAGIC: [u8; 4] = *b"PLCS";
/// The keyring magic.
pub const KEYRING_MAGIC: [u8; 4] = *b"PLKR";
/// The format version both formats use.
pub const FORMAT_VERSION: u8 = 1;

const DOMAIN: &[u8] = b"palisade-policy-cache-v1\0";
const KEY_ID_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Magic, version and key ID.
const HEADER_LEN: usize = 4 + 1 + KEY_ID_LEN;
/// The bytes sealing adds to a plaintext.
pub const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;
const KEYRING_ONE: usize = 4 + 1 + 8 + KEY_ID_LEN + KEY_LEN + 1;
const KEYRING_TWO: usize = KEYRING_ONE + KEY_ID_LEN + KEY_LEN;

/// Why sealing or opening failed. Every failure means the file is not
/// used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtRestError {
    /// The bytes are not in the format (wrong magic, version or length).
    Malformed,
    /// The file names a key this keyring does not hold.
    UnknownKey,
    /// The tag does not verify: the file or its header was changed.
    Authentication,
    /// [`KeyRing::seal`] was called without a reservation.
    NotReserved,
    /// The OS secure random source failed.
    Random,
}

impl fmt::Display for AtRestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a sealed policy cache file or keyring",
            Self::UnknownKey => "sealed with a data key this keyring does not hold",
            Self::Authentication => "the sealed file does not authenticate",
            Self::NotReserved => "no seal was reserved",
            Self::Random => "the secure random source failed",
        })
    }
}

impl std::error::Error for AtRestError {}

/// One data key.
struct DataKey {
    id: [u8; KEY_ID_LEN],
    raw: [u8; KEY_LEN],
    key: AeadKey,
}

impl DataKey {
    fn new(id: [u8; KEY_ID_LEN], raw: [u8; KEY_LEN]) -> Result<Self, AtRestError> {
        let key = AeadKey::new(&raw).map_err(|_| AtRestError::Malformed)?;
        Ok(Self { id, raw, key })
    }

    fn generate() -> Result<Self, AtRestError> {
        let mut id = [0u8; KEY_ID_LEN];
        let mut raw = [0u8; KEY_LEN];
        crypto::random(&mut id).map_err(|_| AtRestError::Random)?;
        crypto::random(&mut raw).map_err(|_| AtRestError::Random)?;
        Self::new(id, raw)
    }
}

/// The data keys and the current key's persisted seal count. `Debug` never
/// prints a key.
pub struct KeyRing {
    current: DataKey,
    retired: Option<DataKey>,
    /// Seals reserved under `current`, persisted or about to be.
    seals: u64,
    /// Reservations not used yet, in this process only.
    reserved: u64,
    limit: u64,
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyRing")
            .field("seals", &self.seals)
            .field("retired", &self.retired.is_some())
            .finish_non_exhaustive()
    }
}

impl KeyRing {
    /// The most messages one data key seals (ADR 0017).
    pub const SEAL_LIMIT: u64 = 1 << 32;

    /// A new keyring with one fresh key and no seals.
    ///
    /// # Errors
    ///
    /// [`AtRestError::Random`] if the secure random source fails.
    pub fn generate() -> Result<Self, AtRestError> {
        Ok(Self {
            current: DataKey::generate()?,
            retired: None,
            seals: 0,
            reserved: 0,
            limit: Self::SEAL_LIMIT,
        })
    }

    /// The same keyring, rotating once `limit` seals were reserved. For
    /// tests of rotation; values above [`Self::SEAL_LIMIT`] are lowered to
    /// it.
    #[must_use]
    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = limit.min(Self::SEAL_LIMIT);
        self
    }

    /// Seals reserved under the current key.
    #[must_use]
    pub const fn seals(&self) -> u64 {
        self.seals
    }

    /// Reserves one seal. If the current key is used up, it is retired
    /// first and a new key becomes current; the key retired before is then
    /// dropped, so files sealed under it no longer open. Returns whether it
    /// rotated. Persist [`Self::encode`] before calling [`Self::seal`].
    ///
    /// # Errors
    ///
    /// [`AtRestError::Random`] if a rotation needs a key and the secure
    /// random source fails.
    pub fn reserve(&mut self) -> Result<bool, AtRestError> {
        let rotate = self.seals >= self.limit;
        if rotate {
            let next = DataKey::generate()?;
            self.retired = Some(std::mem::replace(&mut self.current, next));
            self.seals = 0;
            self.reserved = 0;
        }
        self.seals = self.seals.saturating_add(1);
        self.reserved = self.reserved.saturating_add(1);
        Ok(rotate)
    }

    /// Seals `plaintext` under the current key with a fresh random nonce,
    /// using one reservation.
    ///
    /// # Errors
    ///
    /// [`AtRestError::NotReserved`] without a reservation, and
    /// [`AtRestError::Random`] if the secure random source fails.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AtRestError> {
        if self.reserved == 0 {
            return Err(AtRestError::NotReserved);
        }
        self.reserved -= 1;
        let header = header(&self.current.id);
        let body = self
            .current
            .key
            .seal(&aad(&header), plaintext)
            .map_err(|_| AtRestError::Random)?;
        let mut out = Vec::with_capacity(header.len().saturating_add(body.len()));
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Opens a sealed file under whichever key it names.
    ///
    /// # Errors
    ///
    /// [`AtRestError::Malformed`], [`AtRestError::UnknownKey`] or
    /// [`AtRestError::Authentication`].
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, AtRestError> {
        let (head, body) = sealed
            .split_at_checked(HEADER_LEN)
            .ok_or(AtRestError::Malformed)?;
        let id = sealed_key_id(head).ok_or(AtRestError::Malformed)?;
        let key = [Some(&self.current), self.retired.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| k.id == id)
            .ok_or(AtRestError::UnknownKey)?;
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err(AtRestError::Malformed);
        }
        key.key
            .open(&aad(head), body)
            .ok_or(AtRestError::Authentication)
    }

    /// The keyring bytes, to protect and persist.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEYRING_TWO);
        out.extend_from_slice(&KEYRING_MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.seals.to_be_bytes());
        out.extend_from_slice(&self.current.id);
        out.extend_from_slice(&self.current.raw);
        match &self.retired {
            None => out.push(0),
            Some(k) => {
                out.push(1);
                out.extend_from_slice(&k.id);
                out.extend_from_slice(&k.raw);
            }
        }
        out
    }

    /// Decodes keyring bytes, strictly.
    ///
    /// # Errors
    ///
    /// [`AtRestError::Malformed`] for anything [`Self::encode`] would not
    /// write.
    pub fn decode(bytes: &[u8]) -> Result<Self, AtRestError> {
        const M: AtRestError = AtRestError::Malformed;
        if bytes.len() != KEYRING_ONE && bytes.len() != KEYRING_TWO {
            return Err(M);
        }
        let mut r = Reader(bytes);
        if r.array::<4>()? != KEYRING_MAGIC || r.array::<1>()? != [FORMAT_VERSION] {
            return Err(M);
        }
        let seals = u64::from_be_bytes(r.array()?);
        let current = DataKey::new(r.array()?, r.array()?)?;
        let retired = match (r.array::<1>()?, bytes.len()) {
            ([0], KEYRING_ONE) => None,
            ([1], KEYRING_TWO) => Some(DataKey::new(r.array()?, r.array()?)?),
            _ => return Err(M),
        };
        if retired.as_ref().is_some_and(|k| k.id == current.id) {
            return Err(M);
        }
        Ok(Self {
            current,
            retired,
            seals,
            reserved: 0,
            limit: Self::SEAL_LIMIT,
        })
    }
}

fn header(id: &[u8; KEY_ID_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    for (o, b) in h
        .iter_mut()
        .zip(SEALED_MAGIC.iter().chain([FORMAT_VERSION].iter()).chain(id))
    {
        *o = *b;
    }
    h
}

fn aad(header: &[u8]) -> Vec<u8> {
    let mut a = DOMAIN.to_vec();
    a.extend_from_slice(header);
    a
}

/// The key ID of a sealed file's header, if the magic and version match.
fn sealed_key_id(head: &[u8]) -> Option<[u8; KEY_ID_LEN]> {
    let rest = head.strip_prefix(&SEALED_MAGIC)?;
    let id = rest.strip_prefix(&[FORMAT_VERSION])?;
    id.try_into().ok()
}

/// Whether `bytes` start like a sealed file. Says nothing about whether it
/// opens.
#[must_use]
pub fn looks_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(&SEALED_MAGIC)
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], AtRestError> {
        let (head, rest) = self.0.split_at_checked(N).ok_or(AtRestError::Malformed)?;
        self.0 = rest;
        head.try_into().map_err(|_| AtRestError::Malformed)
    }
}

#[cfg(test)]
mod tests;
