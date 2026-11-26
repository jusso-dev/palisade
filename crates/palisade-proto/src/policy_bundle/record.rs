//! The anti-rollback record and its copies.
//!
//! The record holds, for this device's target (ADR 0007, which is still
//! `proposed`):
//!
//! - the **floor**: the highest `policy_version` the agent has made
//!   `active`. It never exceeds the version of the bundle in `active`;
//! - the **fallback**: the version of the `previous` bundle that the current
//!   `active` directly replaced, or none. Only that bundle may load under the
//!   one-step N-1 exception, and it is always below the floor.
//!
//! The agent keeps several copies (#225: a DPAPI-protected file and a
//! registry mirror, later a TPM-sealed blob). Each copy is sealed on its own
//! with HMAC-SHA-256 under a device key that the agent holds in protected
//! storage (#220), so a copy cannot be edited without the key. A copy can
//! still be deleted or replaced by an older sealed copy, which is why
//! [`RecordCopies`] compares them.
//!
//! # Encoding
//!
//! ```text
//! copy     = format:u8 (= 1)
//!            tenant:[u8;16] scope:u8 (1 group | 2 device) scope_id:[u8;16]
//!            floor:u64
//!            has_fallback:u8 (0 | 1) [fallback:u64]   if has_fallback = 1
//!            tag:[u8;32]
//! tag      = HMAC-SHA-256(key, "palisade-policy-record-v1\0" ‖ every byte before the tag)
//! ```
//!
//! Integers are big-endian, IDs are UUIDv7 bytes. The tag is checked before
//! any field is read, and a copy for another target is refused, so a sealed
//! copy cannot be moved between targets.

use std::fmt;

use palisade_core::Uuid7;

use super::{Scope, Target};
use crate::events::{HostId, TenantId};
use crate::pki::crypto::MacKey;

/// The record format version this module reads and writes.
pub const FORMAT_VERSION: u8 = 1;

/// The MAC domain-separation prefix, including its NUL.
const MAC_DOMAIN: &[u8] = b"palisade-policy-record-v1\0";

const TAG_LEN: usize = 32;
const BODY_LEN: usize = 1 + 16 + 1 + 16 + 8 + 1;
/// Length of a sealed copy with no fallback.
pub const SEALED_LEN: usize = BODY_LEN + TAG_LEN;
/// Length of a sealed copy with a fallback.
pub const SEALED_LEN_WITH_FALLBACK: usize = BODY_LEN + 8 + TAG_LEN;

/// The device's record key: 32 bytes that the agent keeps in protected
/// storage (#220). `Debug` never prints it.
pub struct RecordKey(MacKey);

impl RecordKey {
    /// A key from its 32 bytes.
    #[must_use]
    pub fn from_bytes(key: &[u8; 32]) -> Self {
        Self(MacKey::new(key))
    }
}

impl fmt::Debug for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordKey(..)")
    }
}

/// The anti-rollback record for one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Record {
    target: Target,
    floor: u64,
    fallback: Option<u64>,
}

impl Record {
    /// The record before any bundle was activated: floor 0, no fallback.
    #[must_use]
    pub const fn empty(target: Target) -> Self {
        Self {
            target,
            floor: 0,
            fallback: None,
        }
    }

    /// A record.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidFallback`] unless the fallback, if any, is
    /// from 1 to below the floor.
    pub const fn new(
        target: Target,
        floor: u64,
        fallback: Option<u64>,
    ) -> Result<Self, RecordError> {
        if let Some(f) = fallback {
            if f == 0 || f >= floor {
                return Err(RecordError::InvalidFallback);
            }
        }
        Ok(Self {
            target,
            floor,
            fallback,
        })
    }

    /// The target.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// The highest version made `active`.
    #[must_use]
    pub const fn floor(&self) -> u64 {
        self.floor
    }

    /// The `previous` version the current `active` directly replaced.
    #[must_use]
    pub const fn fallback(&self) -> Option<u64> {
        self.fallback
    }

    /// The same record without its fallback.
    #[must_use]
    pub const fn without_fallback(self) -> Self {
        Self {
            fallback: None,
            ..self
        }
    }

    /// One sealed copy.
    #[must_use]
    pub fn seal(&self, key: &RecordKey) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEALED_LEN_WITH_FALLBACK);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(self.target.tenant.0.as_bytes());
        let (code, id) = match self.target.scope {
            Scope::Group(id) => (1u8, id),
            Scope::Device(host) => (2u8, host.0),
        };
        out.push(code);
        out.extend_from_slice(id.as_bytes());
        out.extend_from_slice(&self.floor.to_be_bytes());
        match self.fallback {
            None => out.push(0),
            Some(f) => {
                out.push(1);
                out.extend_from_slice(&f.to_be_bytes());
            }
        }
        let tag = key.0.tag(&mac_input(&out));
        out.extend_from_slice(&tag);
        out
    }

    /// Reads one sealed copy, checking its tag first.
    ///
    /// # Errors
    ///
    /// [`RecordError::Malformed`] for a wrong length or layout,
    /// [`RecordError::BadTag`] if the tag does not verify, and
    /// [`RecordError::WrongTarget`] for a copy sealed for another target.
    pub fn unseal(bytes: &[u8], key: &RecordKey, expected: Target) -> Result<Self, RecordError> {
        if bytes.len() != SEALED_LEN && bytes.len() != SEALED_LEN_WITH_FALLBACK {
            return Err(RecordError::Malformed);
        }
        let (body, tag) = bytes
            .split_at_checked(bytes.len() - TAG_LEN)
            .ok_or(RecordError::Malformed)?;
        if !key.0.verify(&mac_input(body), tag) {
            return Err(RecordError::BadTag);
        }
        let record = decode(body)?;
        if record.target != expected {
            return Err(RecordError::WrongTarget);
        }
        Ok(record)
    }
}

fn mac_input(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAC_DOMAIN.len() + body.len());
    m.extend_from_slice(MAC_DOMAIN);
    m.extend_from_slice(body);
    m
}

fn decode(body: &[u8]) -> Result<Record, RecordError> {
    const M: RecordError = RecordError::Malformed;
    let (&format, rest) = body.split_first().ok_or(M)?;
    if format != FORMAT_VERSION {
        return Err(M);
    }
    let (tenant, rest) = rest.split_first_chunk::<16>().ok_or(M)?;
    let (&scope, rest) = rest.split_first().ok_or(M)?;
    let (scope_id, rest) = rest.split_first_chunk::<16>().ok_or(M)?;
    let (floor, rest) = rest.split_first_chunk::<8>().ok_or(M)?;
    let (&has_fallback, rest) = rest.split_first().ok_or(M)?;
    let (fallback, rest) = match has_fallback {
        0 => (None, rest),
        1 => {
            let (f, rest) = rest.split_first_chunk::<8>().ok_or(M)?;
            (Some(u64::from_be_bytes(*f)), rest)
        }
        _ => return Err(M),
    };
    if !rest.is_empty() {
        return Err(M);
    }
    let tenant = TenantId(Uuid7::from_bytes(*tenant).ok_or(M)?);
    let id = Uuid7::from_bytes(*scope_id).ok_or(M)?;
    let scope = match scope {
        1 => Scope::Group(id),
        2 => Scope::Device(HostId(id)),
        _ => return Err(M),
    };
    Record::new(
        Target { tenant, scope },
        u64::from_be_bytes(*floor),
        fallback,
    )
    .map_err(|_| M)
}

/// The state of one copy as read from storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyState {
    /// The copy does not exist.
    Missing,
    /// The copy exists but does not unseal.
    Corrupt(RecordError),
    /// The copy unsealed.
    Intact(Record),
}

/// Every copy of the record, read and compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordCopies {
    target: Target,
    copies: Vec<CopyState>,
}

impl RecordCopies {
    /// Unseals each copy (`None` for a copy that does not exist).
    #[must_use]
    pub fn read(copies: &[Option<&[u8]>], key: &RecordKey, target: Target) -> Self {
        let copies = copies
            .iter()
            .map(|c| match c {
                None => CopyState::Missing,
                Some(bytes) => match Record::unseal(bytes, key, target) {
                    Ok(r) => CopyState::Intact(r),
                    Err(e) => CopyState::Corrupt(e),
                },
            })
            .collect();
        Self { target, copies }
    }

    /// The target the copies were read for.
    #[must_use]
    pub const fn target(&self) -> Target {
        self.target
    }

    /// Each copy's state, in the order given.
    #[must_use]
    pub fn states(&self) -> &[CopyState] {
        &self.copies
    }

    fn intact(&self) -> impl Iterator<Item = &Record> {
        self.copies.iter().filter_map(|c| match c {
            CopyState::Intact(r) => Some(r),
            _ => None,
        })
    }

    /// The highest floor among intact copies, or 0.
    #[must_use]
    pub fn floor(&self) -> u64 {
        self.intact().map(|r| r.floor).max().unwrap_or(0)
    }

    /// The fallback, only if every intact copy records the same one.
    #[must_use]
    pub fn fallback(&self) -> Option<u64> {
        let mut intact = self.intact();
        let first = intact.next()?.fallback;
        intact
            .all(|r| r.fallback == first)
            .then_some(first)
            .flatten()
    }

    /// The record as read: [`Self::floor`] and [`Self::fallback`].
    #[must_use]
    pub fn record(&self) -> Record {
        // The fallback agrees across copies, so it is below that copy's
        // floor and so below the highest floor.
        Record::new(self.target, self.floor(), self.fallback())
            .unwrap_or_else(|_| Record::empty(self.target))
    }

    /// Whether any copy is missing.
    #[must_use]
    pub fn any_missing(&self) -> bool {
        self.copies.iter().any(|c| matches!(c, CopyState::Missing))
    }

    /// Whether any copy exists but does not unseal.
    #[must_use]
    pub fn any_corrupt(&self) -> bool {
        self.copies
            .iter()
            .any(|c| matches!(c, CopyState::Corrupt(_)))
    }

    /// Whether the intact copies hold different values.
    #[must_use]
    pub fn disagree(&self) -> bool {
        let mut intact = self.intact();
        intact
            .next()
            .is_some_and(|first| intact.any(|r| r != first))
    }

    /// Whether a disagreement is exactly what an interrupted activation
    /// leaves (ADR 0007): every copy intact, the highest floor equal to the
    /// version of the verified `active` bundle that loaded, and exactly two
    /// distinct values, `older` and `newer`, where `older` has no fallback
    /// and either
    ///
    /// - step 3 was interrupted: the same floor, and only `newer` (the
    ///   value before step 3) has a fallback; or
    /// - step 5 was interrupted: `older` has the lower floor, and `newer`'s
    ///   fallback is none or `older`'s floor (the bundle step 2 copied).
    ///
    /// The second condition is stricter than ADR 0007's wording, so that an
    /// old sealed copy restored into one store does not pass as an
    /// interrupted activation.
    #[must_use]
    pub fn interrupted_activation(&self, active_version: Option<u64>) -> bool {
        if self.any_missing() || self.any_corrupt() || active_version != Some(self.floor()) {
            return false;
        }
        let mut distinct: Vec<&Record> = Vec::new();
        for r in self.intact() {
            if !distinct.contains(&r) {
                distinct.push(r);
            }
        }
        match distinct.as_slice() {
            [a, b] => {
                let key = |r: &Record| (r.floor, r.fallback.is_some());
                let (older, newer) = if key(a) <= key(b) { (a, b) } else { (b, a) };
                older.fallback.is_none()
                    && (older.floor == newer.floor
                        || newer.fallback.is_none_or(|f| f == older.floor))
            }
            _ => false,
        }
    }
}

/// A record or copy is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The fallback is 0 or not below the floor.
    InvalidFallback,
    /// The copy has the wrong length, format version or layout.
    Malformed,
    /// The copy's tag does not verify under this device's key.
    BadTag,
    /// The copy was sealed for another target.
    WrongTarget,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFallback => "the fallback must be from 1 to below the floor",
            Self::Malformed => "the record copy is malformed",
            Self::BadTag => "the record copy's MAC does not verify",
            Self::WrongTarget => "the record copy is for another target",
        })
    }
}

impl std::error::Error for RecordError {}
