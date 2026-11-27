//! The signed trust-set manifest and the agent's acceptance rule.
//!
//! A trust set tells an agent which keys it trusts: the keys that may sign
//! the next trust set, the server CA public-key pins, the policy-signing and
//! unlock-token keys, the signature algorithms it accepts, and a pointer to
//! the update-signing root metadata (#226). It is signed by the offline root
//! or by a trust-set key that an earlier trust set endorsed.
//!
//! # Acceptance rule
//!
//! [`TrustAnchor::accept`] takes a new signed trust set only if all of these
//! hold (threats: T-signer-06, T-ca-01):
//!
//! 1. The envelope and manifest decode under the strict rules below.
//! 2. At least one signature verifies under a key the agent **already**
//!    trusts: the pinned root, or a `root-ca` or `trust-set` key in the
//!    *current* trust set. A key listed only in the new set never counts,
//!    so a set cannot endorse itself.
//! 3. A current-set key only counts if its validity window contains `now`,
//!    allowing for clock skew. The pinned root has no window: it is trusted
//!    until the device is re-enrolled (R-11).
//! 4. Every signature by a key the agent knows (the pinned root or a current
//!    trust key) must name that key's own algorithm, an algorithm the
//!    current set accepts, and must verify, whether or not the key is inside
//!    its validity window. A bad or mislabelled signature from a known key is
//!    tampering, not noise, and rejects the whole set. Signatures from
//!    unknown keys are ignored, which lets a set carry signatures for agents
//!    on different trust versions during a rotation.
//! 5. `trust_version` is strictly greater than the current one, so an
//!    older or replayed set is refused (rollback), and at most
//!    [`MAX_VERSION_STEP`] greater. Without the cap, a stolen trust-set key
//!    could publish version `u64::MAX` and no later set, not even one signed
//!    by the root, could ever be newer (fast-forward). The cap applies to
//!    root-signed sets too, so recovering agents that a stolen key moved
//!    far ahead of the rest may need intermediate sets.
//! 6. `issued_at` is not earlier than the current set's, and not later than
//!    `now` plus the skew tolerance.
//!
//! `now` must be trusted time on the agent (#220). Storing the accepted set
//! and the last two versions in the protected data directory is also #220.
//!
//! # Canonical encoding
//!
//! The signed payload is a fixed-layout binary encoding with one valid
//! encoding per trust set. The decoder enforces that: every list is sorted
//! strictly ascending (so duplicates are refused), every count and length is
//! bounded, every code is known, and no bytes may follow the last field.
//! `encode(decode(bytes)) == bytes` for every accepted input.
//!
//! All integers are big-endian. Timestamps are signed 64-bit microseconds
//! since 1970-01-01T00:00:00Z, within years 0001 to 9999.
//!
//! ```text
//! payload    = version:u8 (= 1)
//!              trust_version:u64 (>= 1)
//!              issued_at:i64
//!              n_algs:u8 (1..=2)   alg:u8 * n_algs          ascending
//!              n_trust:u8 (1..=64) key * n_trust            ascending kid
//!              n_pins:u8 (0..=64)  sha256:[u8;32] * n_pins  ascending
//!              n_policy:u8 (0..=64) key * n_policy          ascending kid
//!              n_unlock:u8 (0..=64) key * n_unlock          ascending kid
//!              update_root:u8 (0 | 1)
//!                [version:u64 sha256:[u8;32]]               if update_root = 1
//! key        = purpose:u8 status:u8 alg:u8
//!              not_before:i64 not_after:i64
//!              spki_len:u8 spki:[u8; spki_len]
//!
//! envelope   = version:u8 (= 1)
//!              payload_len:u32 (1..=65536) payload
//!              n_sigs:u8 (1..=8) sig * n_sigs               ascending kid
//! sig        = kid:[u8;16] alg:u8 bytes:[u8; length fixed by alg]
//! ```
//!
//! Codes are [`KeyPurpose::code`], [`KeyStatus::code`] and
//! [`SignatureAlgorithm::code`]. A key ID appears at most once across all
//! three key lists, so no key serves two purposes. Each list holds only its
//! own purposes: `root-ca` or `trust-set`, then `policy-signing`, then
//! `unlock-token`. Listed keys are `active` or `retiring`: a retired or
//! compromised key is revoked by leaving it out of the next trust set.
//!
//! The issue suggests reusing the policy bundle's canonical CBOR (#225).
//! That encoder does not exist yet. This format is versioned, so a later
//! version can move to it without breaking agents on version 1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::events::{Sha256Hex, Timestamp};

use super::Domain;
use super::key::{
    KeyError, KeyPurpose, KeyStatus, KeyType, Kid, MAX_SPKI_LEN, PublicKey, SignatureAlgorithm,
};
use super::signer::{Signature, Signer, SignerError};
use super::time::{SkewTolerance, TimeError, Validity};

/// The payload and envelope format version this module reads and writes.
pub const FORMAT_VERSION: u8 = 1;
/// The most `trust_version` may grow in one accepted update. Servers
/// increment it by one per publication, so an agent can miss up to a million
/// publications and still catch up in one step.
pub const MAX_VERSION_STEP: u64 = 1_000_000;
/// Largest envelope accepted, in bytes: the largest payload, its header
/// and the most signatures.
pub const MAX_ENVELOPE_LEN: usize = 1 + 4 + MAX_PAYLOAD_LEN + 1 + MAX_SIGNATURES * (16 + 1 + 96);
/// Most keys in each key list.
pub const MAX_KEYS: usize = 64;
/// Most server CA pins.
pub const MAX_PINS: usize = 64;
/// Most signatures on one trust set.
pub const MAX_SIGNATURES: usize = 8;
/// Largest payload accepted, in bytes. A manifest with every list full is about 29 KiB.
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// A key listed in a trust set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    public_key: PublicKey,
    purpose: KeyPurpose,
    algorithm: SignatureAlgorithm,
    status: KeyStatus,
    validity: Validity,
}

impl TrustedKey {
    /// A listed key.
    ///
    /// # Errors
    ///
    /// [`TrustSetError::Key`] if the purpose does not allow the algorithm or
    /// the public key is of the wrong type, and
    /// [`TrustSetError::StatusNotTrusted`] unless the status is `active` or
    /// `retiring`.
    pub fn new(
        public_key: PublicKey,
        purpose: KeyPurpose,
        algorithm: SignatureAlgorithm,
        status: KeyStatus,
        validity: Validity,
    ) -> Result<Self, TrustSetError> {
        let key_alg = algorithm.key_algorithm();
        if !purpose.allows(key_alg) {
            return Err(TrustSetError::Key(KeyError::AlgorithmNotAllowed {
                purpose,
                algorithm: key_alg,
            }));
        }
        if key_alg.key_type() != public_key.key_type() {
            return Err(TrustSetError::Key(KeyError::KeyTypeMismatch));
        }
        if !status.verifies() {
            return Err(TrustSetError::StatusNotTrusted(status));
        }
        Ok(Self {
            public_key,
            purpose,
            algorithm,
            status,
            validity,
        })
    }

    /// The key ID.
    #[must_use]
    pub fn kid(&self) -> Kid {
        self.public_key.kid()
    }

    /// The public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The purpose.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// `active` or `retiring`.
    #[must_use]
    pub const fn status(&self) -> KeyStatus {
        self.status
    }

    /// The validity window.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

/// Where the agent finds the update-signing root metadata (#226): its
/// version and SHA-256. The metadata format itself belongs to #226.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateRootPointer {
    /// The root metadata version.
    pub version: u64,
    /// The SHA-256 of the root metadata file.
    pub sha256: Sha256Hex,
}

/// Which key list a key belongs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum List {
    Trust,
    Policy,
    Unlock,
}

impl List {
    const fn holds(self, purpose: KeyPurpose) -> bool {
        matches!(
            (self, purpose),
            (Self::Trust, KeyPurpose::RootCa | KeyPurpose::TrustSet)
                | (Self::Policy, KeyPurpose::PolicySigning)
                | (Self::Unlock, KeyPurpose::UnlockToken)
        )
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Trust => "trust keys",
            Self::Policy => "policy keys",
            Self::Unlock => "unlock keys",
        }
    }

    const fn for_domain(domain: Domain) -> Self {
        match domain {
            Domain::TrustSet => Self::Trust,
            Domain::Policy => Self::Policy,
            Domain::Unlock => Self::Unlock,
        }
    }
}

/// A trust-set manifest. The constructors check every rule the decoder
/// checks, so every value has exactly one encoding, except that a set
/// without trust keys is refused by [`Self::encode`] and by
/// [`TrustAnchor::with_current`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustSet {
    trust_version: u64,
    issued_at: Timestamp,
    algorithms: BTreeSet<SignatureAlgorithm>,
    trust_keys: BTreeMap<Kid, TrustedKey>,
    server_pins: BTreeSet<Sha256Hex>,
    policy_keys: BTreeMap<Kid, TrustedKey>,
    unlock_keys: BTreeMap<Kid, TrustedKey>,
    update_root: Option<UpdateRootPointer>,
}

impl TrustSet {
    /// An empty trust set. Add at least one trust key before encoding.
    ///
    /// # Errors
    ///
    /// [`TrustSetError::ZeroVersion`] if `trust_version` is 0 (the version an
    /// agent holds before its first trust set), and
    /// [`TrustSetError::NoAlgorithms`] if `algorithms` is empty.
    pub fn new(
        trust_version: u64,
        issued_at: Timestamp,
        algorithms: &[SignatureAlgorithm],
    ) -> Result<Self, TrustSetError> {
        if trust_version == 0 {
            return Err(TrustSetError::ZeroVersion);
        }
        if algorithms.is_empty() {
            return Err(TrustSetError::NoAlgorithms);
        }
        Ok(Self {
            trust_version,
            issued_at,
            algorithms: algorithms.iter().copied().collect(),
            trust_keys: BTreeMap::new(),
            server_pins: BTreeSet::new(),
            policy_keys: BTreeMap::new(),
            unlock_keys: BTreeMap::new(),
            update_root: None,
        })
    }

    /// Adds a `root-ca` or `trust-set` key, which may sign the next trust set.
    ///
    /// # Errors
    ///
    /// See [`TrustSetError`].
    pub fn add_trust_key(&mut self, key: TrustedKey) -> Result<(), TrustSetError> {
        self.add_key(List::Trust, key)
    }

    /// Adds a `policy-signing` key (#225).
    ///
    /// # Errors
    ///
    /// See [`TrustSetError`].
    pub fn add_policy_key(&mut self, key: TrustedKey) -> Result<(), TrustSetError> {
        self.add_key(List::Policy, key)
    }

    /// Adds an `unlock-token` key (#222).
    ///
    /// # Errors
    ///
    /// See [`TrustSetError`].
    pub fn add_unlock_key(&mut self, key: TrustedKey) -> Result<(), TrustSetError> {
        self.add_key(List::Unlock, key)
    }

    /// Adds a server CA pin: the SHA-256 of an accepted CA's
    /// `SubjectPublicKeyInfo` (#223).
    ///
    /// # Errors
    ///
    /// [`TrustSetError::TooMany`] or [`TrustSetError::DuplicatePin`].
    pub fn add_server_pin(&mut self, pin: Sha256Hex) -> Result<(), TrustSetError> {
        if self.server_pins.len() >= MAX_PINS {
            return Err(TrustSetError::TooMany("server pins"));
        }
        if !self.server_pins.insert(pin) {
            return Err(TrustSetError::DuplicatePin(pin));
        }
        Ok(())
    }

    /// Sets the update-signing root metadata pointer.
    pub fn set_update_root(&mut self, pointer: UpdateRootPointer) {
        self.update_root = Some(pointer);
    }

    fn add_key(&mut self, list: List, key: TrustedKey) -> Result<(), TrustSetError> {
        if !list.holds(key.purpose) {
            return Err(TrustSetError::WrongList {
                list: list.name(),
                purpose: key.purpose,
            });
        }
        if !self.algorithms.contains(&key.algorithm) {
            return Err(TrustSetError::AlgorithmNotListed(key.algorithm));
        }
        let kid = key.kid();
        if self.trust_keys.contains_key(&kid)
            || self.policy_keys.contains_key(&kid)
            || self.unlock_keys.contains_key(&kid)
        {
            return Err(TrustSetError::DuplicateKey(kid));
        }
        let map = match list {
            List::Trust => &mut self.trust_keys,
            List::Policy => &mut self.policy_keys,
            List::Unlock => &mut self.unlock_keys,
        };
        if map.len() >= MAX_KEYS {
            return Err(TrustSetError::TooMany(list.name()));
        }
        map.insert(kid, key);
        Ok(())
    }

    /// The monotonic version.
    #[must_use]
    pub const fn trust_version(&self) -> u64 {
        self.trust_version
    }

    /// When the server issued this set.
    #[must_use]
    pub const fn issued_at(&self) -> Timestamp {
        self.issued_at
    }

    /// The accepted signature algorithms, ascending.
    pub fn algorithms(&self) -> impl Iterator<Item = SignatureAlgorithm> + '_ {
        self.algorithms.iter().copied()
    }

    /// The keys that may sign the next trust set.
    pub fn trust_keys(&self) -> impl Iterator<Item = &TrustedKey> {
        self.trust_keys.values()
    }

    /// The policy-signing keys.
    pub fn policy_keys(&self) -> impl Iterator<Item = &TrustedKey> {
        self.policy_keys.values()
    }

    /// The unlock-token keys.
    pub fn unlock_keys(&self) -> impl Iterator<Item = &TrustedKey> {
        self.unlock_keys.values()
    }

    /// The server CA pins, ascending.
    pub fn server_pins(&self) -> impl Iterator<Item = &Sha256Hex> {
        self.server_pins.iter()
    }

    /// The update-signing root metadata pointer, if set.
    #[must_use]
    pub const fn update_root(&self) -> Option<UpdateRootPointer> {
        self.update_root
    }

    /// Whether a CA public key (its DER `SubjectPublicKeyInfo`) is pinned.
    #[must_use]
    pub fn pins(&self, ca_spki_der: &[u8]) -> bool {
        self.server_pins
            .contains(&super::key::spki_sha256(ca_spki_der))
    }

    /// Verifies a signature for `domain` against this set: the signing key
    /// must be listed for that domain, its algorithm must be accepted, and
    /// its validity window must contain `now`, allowing for `skew`.
    ///
    /// This is the check that policy bundles (#225) and unlock tokens (#222)
    /// will use. For trust sets, use [`TrustAnchor::accept`] instead, which
    /// also trusts the pinned root and enforces the version rules.
    ///
    /// # Errors
    ///
    /// See [`VerifyError`].
    pub fn verify(
        &self,
        domain: Domain,
        payload: &[u8],
        signature: &Signature,
        now: Timestamp,
        skew: SkewTolerance,
    ) -> Result<&TrustedKey, VerifyError> {
        let key = self.listed(domain, &signature.kid())?;
        if !self.algorithms.contains(&signature.algorithm()) {
            return Err(VerifyError::AlgorithmNotAccepted(signature.algorithm()));
        }
        if signature.algorithm() != key.algorithm {
            return Err(VerifyError::AlgorithmMismatch);
        }
        key.validity.check(now, skew).map_err(VerifyError::Time)?;
        if key
            .public_key
            .verify(signature.algorithm(), domain, payload, signature.bytes())
        {
            Ok(key)
        } else {
            Err(VerifyError::BadSignature)
        }
    }

    fn listed(&self, domain: Domain, kid: &Kid) -> Result<&TrustedKey, VerifyError> {
        let map = match List::for_domain(domain) {
            List::Trust => &self.trust_keys,
            List::Policy => &self.policy_keys,
            List::Unlock => &self.unlock_keys,
        };
        map.get(kid).ok_or(VerifyError::UnknownKey(*kid))
    }

    /// The canonical payload bytes, the input to signing.
    ///
    /// # Errors
    ///
    /// [`TrustSetError::NoTrustKeys`] if no trust key is listed. The pinned
    /// root is outside the set, so a set without trust keys could still be
    /// followed by a root-signed one, but an empty list is almost always a
    /// mistake, so the format refuses it.
    pub fn encode(&self) -> Result<Vec<u8>, TrustSetError> {
        if self.trust_keys.is_empty() {
            return Err(TrustSetError::NoTrustKeys);
        }
        let mut out = Vec::with_capacity(1024);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.trust_version.to_be_bytes());
        out.extend_from_slice(&self.issued_at.unix_micros().to_be_bytes());
        push_count(&mut out, self.algorithms.len());
        for alg in &self.algorithms {
            out.push(alg.code());
        }
        encode_keys(&mut out, &self.trust_keys);
        push_count(&mut out, self.server_pins.len());
        for pin in &self.server_pins {
            out.extend_from_slice(pin.as_bytes());
        }
        encode_keys(&mut out, &self.policy_keys);
        encode_keys(&mut out, &self.unlock_keys);
        match self.update_root {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.version.to_be_bytes());
                out.extend_from_slice(p.sha256.as_bytes());
            }
        }
        Ok(out)
    }

    /// Decodes canonical payload bytes. Signatures are not checked here.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for any input that is not the canonical encoding of a
    /// valid trust set.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_PAYLOAD_LEN {
            return Err(DecodeError::TooLong);
        }
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let trust_version = r.u64()?;
        let issued_at = r.timestamp()?;

        let n_algs = r.count(1, SignatureAlgorithm::ALL.len(), "algorithms")?;
        let mut algorithms = Vec::with_capacity(n_algs);
        for _ in 0..n_algs {
            let code = r.u8()?;
            let alg = SignatureAlgorithm::from_code(code)
                .ok_or(DecodeError::UnknownCode("signature algorithm"))?;
            if algorithms.last().is_some_and(|prev| *prev >= alg) {
                return Err(DecodeError::NotAscending("algorithms"));
            }
            algorithms.push(alg);
        }
        let mut set = Self::new(trust_version, issued_at, &algorithms).map_err(DecodeError::Set)?;

        decode_keys(&mut r, &mut set, List::Trust)?;

        let n_pins = r.count(0, MAX_PINS, "server pins")?;
        let mut last: Option<Sha256Hex> = None;
        for _ in 0..n_pins {
            let pin = Sha256Hex::from_bytes(r.array()?);
            if last.is_some_and(|prev| prev >= pin) {
                return Err(DecodeError::NotAscending("server pins"));
            }
            set.add_server_pin(pin).map_err(DecodeError::Set)?;
            last = Some(pin);
        }

        decode_keys(&mut r, &mut set, List::Policy)?;
        decode_keys(&mut r, &mut set, List::Unlock)?;

        match r.u8()? {
            0 => {}
            1 => {
                let version = r.u64()?;
                let sha256 = Sha256Hex::from_bytes(r.array()?);
                set.set_update_root(UpdateRootPointer { version, sha256 });
            }
            _ => return Err(DecodeError::UnknownCode("update root presence")),
        }
        r.finish()?;
        Ok(set)
    }
}

fn push_count(out: &mut Vec<u8>, n: usize) {
    // Every list is capped at 64 entries, so the count fits a byte.
    out.push(u8::try_from(n).unwrap_or(u8::MAX));
}

fn encode_keys(out: &mut Vec<u8>, keys: &BTreeMap<Kid, TrustedKey>) {
    push_count(out, keys.len());
    for key in keys.values() {
        out.push(key.purpose.code());
        out.push(key.status.code());
        out.push(key.algorithm.code());
        out.extend_from_slice(&key.validity.not_before().unix_micros().to_be_bytes());
        out.extend_from_slice(&key.validity.not_after().unix_micros().to_be_bytes());
        let spki = key.public_key.spki_der();
        push_count(out, spki.len());
        out.extend_from_slice(spki);
    }
}

fn decode_keys(r: &mut Reader<'_>, set: &mut TrustSet, list: List) -> Result<(), DecodeError> {
    let min = usize::from(list == List::Trust);
    let n = r.count(min, MAX_KEYS, list.name())?;
    let mut last: Option<Kid> = None;
    for _ in 0..n {
        let purpose =
            KeyPurpose::from_code(r.u8()?).ok_or(DecodeError::UnknownCode("key purpose"))?;
        let status = KeyStatus::from_code(r.u8()?).ok_or(DecodeError::UnknownCode("key status"))?;
        let algorithm = SignatureAlgorithm::from_code(r.u8()?)
            .ok_or(DecodeError::UnknownCode("signature algorithm"))?;
        let not_before = r.timestamp()?;
        let not_after = r.timestamp()?;
        let validity = Validity::new(not_before, not_after).map_err(DecodeError::Time)?;
        let spki_len = usize::from(r.u8()?);
        if spki_len > MAX_SPKI_LEN {
            return Err(DecodeError::TooLong);
        }
        let public_key = PublicKey::from_spki_der(r.take(spki_len)?)
            .map_err(|e| DecodeError::Set(TrustSetError::Key(e)))?;
        let key = TrustedKey::new(public_key, purpose, algorithm, status, validity)
            .map_err(DecodeError::Set)?;
        let kid = key.kid();
        if last.is_some_and(|prev| prev >= kid) {
            return Err(DecodeError::NotAscending(list.name()));
        }
        set.add_key(list, key).map_err(DecodeError::Set)?;
        last = Some(kid);
    }
    Ok(())
}

/// A trust set with its signatures: the unit delivered to agents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTrustSet {
    payload: Vec<u8>,
    signatures: Vec<Signature>,
}

impl SignedTrustSet {
    /// Encodes `set` and signs it with each key in `kids`, in the
    /// [`Domain::TrustSet`] domain.
    ///
    /// During a trust-key rotation, sign with both the old and the new key,
    /// so agents on either side of the rotation accept the set.
    ///
    /// # Errors
    ///
    /// [`TrustSetError::Signer`] if signing fails (including a key whose
    /// purpose may not sign trust sets), [`TrustSetError::SignatureCount`]
    /// for no keys or more than [`MAX_SIGNATURES`], and
    /// [`TrustSetError::DuplicateKey`] if a key is given twice.
    pub fn sign<S: Signer + ?Sized>(
        set: &TrustSet,
        signer: &S,
        kids: &[Kid],
    ) -> Result<Self, TrustSetError> {
        if kids.is_empty() || kids.len() > MAX_SIGNATURES {
            return Err(TrustSetError::SignatureCount);
        }
        let payload = set.encode()?;
        let mut signatures: BTreeMap<Kid, Signature> = BTreeMap::new();
        for kid in kids {
            let sig = signer
                .sign(kid, Domain::TrustSet, &payload)
                .map_err(TrustSetError::Signer)?;
            if signatures.insert(*kid, sig).is_some() {
                return Err(TrustSetError::DuplicateKey(*kid));
            }
        }
        Ok(Self {
            payload,
            signatures: signatures.into_values().collect(),
        })
    }

    /// Joins a payload and signatures made elsewhere, for example by an
    /// offline root ceremony.
    ///
    /// # Errors
    ///
    /// As [`Self::decode`] would report for the joined envelope.
    pub fn from_parts(payload: Vec<u8>, signatures: Vec<Signature>) -> Result<Self, DecodeError> {
        let mut sigs = signatures;
        sigs.sort_by_key(Signature::kid);
        let joined = Self {
            payload,
            signatures: sigs,
        };
        Self::decode(&joined.encode())
    }

    /// The signed payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The signatures, ascending by key ID.
    #[must_use]
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// The envelope bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload.len().saturating_add(256));
        out.push(FORMAT_VERSION);
        // The payload is at most 64 KiB, so its length fits a u32.
        let len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        push_count(&mut out, self.signatures.len());
        for sig in &self.signatures {
            out.extend_from_slice(sig.kid().as_bytes());
            out.push(sig.algorithm().code());
            out.extend_from_slice(sig.bytes());
        }
        out
    }

    /// Decodes envelope bytes. The payload is checked to be canonical, but
    /// signatures are not verified: use [`TrustAnchor::accept`].
    ///
    /// # Errors
    ///
    /// [`DecodeError`] for anything but a canonical envelope around a
    /// canonical payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_parts(bytes).map(|(signed, _)| signed)
    }

    /// Decodes envelope bytes and returns the decoded payload too, so it is
    /// parsed once.
    fn decode_parts(bytes: &[u8]) -> Result<(Self, TrustSet), DecodeError> {
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(DecodeError::TooLong);
        }
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let len = usize::try_from(r.u32()?).map_err(|_| DecodeError::TooLong)?;
        if len == 0 {
            return Err(DecodeError::Truncated);
        }
        if len > MAX_PAYLOAD_LEN {
            return Err(DecodeError::TooLong);
        }
        let payload = r.take(len)?.to_vec();
        // The payload must be canonical before anyone looks at signatures.
        let set = TrustSet::decode(&payload)?;
        let n = r.count(1, MAX_SIGNATURES, "signatures")?;
        let mut signatures: Vec<Signature> = Vec::with_capacity(n);
        for _ in 0..n {
            let kid = Kid::from_bytes(r.array()?);
            let alg = SignatureAlgorithm::from_code(r.u8()?)
                .ok_or(DecodeError::UnknownCode("signature algorithm"))?;
            let sig_bytes = r.take(alg.signature_len())?.to_vec();
            if signatures.last().is_some_and(|prev| prev.kid() >= kid) {
                return Err(DecodeError::NotAscending("signatures"));
            }
            let sig = Signature::new(kid, alg, sig_bytes)
                .map_err(|e| DecodeError::Set(TrustSetError::Signer(e)))?;
            signatures.push(sig);
        }
        r.finish()?;
        Ok((
            Self {
                payload,
                signatures,
            },
            set,
        ))
    }
}

/// What an agent trusts: the root pinned at enrolment, and the trust set it
/// last accepted.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pinned_root: PublicKey,
    current: Option<TrustSet>,
    skew: SkewTolerance,
}

impl TrustAnchor {
    /// An anchor with only the pinned root, as at enrolment.
    ///
    /// # Errors
    ///
    /// [`TrustSetError::Key`] unless the root is a P-384 key, the only
    /// algorithm a `root-ca` key may use.
    pub fn new(pinned_root: PublicKey, skew: SkewTolerance) -> Result<Self, TrustSetError> {
        if pinned_root.key_type() != KeyType::P384 {
            return Err(TrustSetError::Key(KeyError::KeyTypeMismatch));
        }
        Ok(Self {
            pinned_root,
            current: None,
            skew,
        })
    }

    /// An anchor restored from storage: the pinned root and the last
    /// accepted trust set.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], plus [`TrustSetError::NoTrustKeys`] if `current`
    /// lists no trust key, which no decoded trust set can.
    pub fn with_current(
        pinned_root: PublicKey,
        current: TrustSet,
        skew: SkewTolerance,
    ) -> Result<Self, TrustSetError> {
        if current.trust_keys.is_empty() {
            return Err(TrustSetError::NoTrustKeys);
        }
        let mut anchor = Self::new(pinned_root, skew)?;
        anchor.current = Some(current);
        Ok(anchor)
    }

    /// The pinned root key.
    #[must_use]
    pub const fn pinned_root(&self) -> &PublicKey {
        &self.pinned_root
    }

    /// The last accepted trust set.
    #[must_use]
    pub const fn current(&self) -> Option<&TrustSet> {
        self.current.as_ref()
    }

    /// The current trust version, 0 before the first trust set.
    #[must_use]
    pub fn trust_version(&self) -> u64 {
        self.current.as_ref().map_or(0, TrustSet::trust_version)
    }

    /// Checks a signed trust set against the rule in the [module
    /// docs](self), without changing the anchor.
    ///
    /// # Errors
    ///
    /// The first [`Rejection`] that applies.
    pub fn check(&self, envelope: &[u8], now: Timestamp) -> Result<TrustSet, Rejection> {
        let (signed, offered) =
            SignedTrustSet::decode_parts(envelope).map_err(Rejection::Malformed)?;

        let mut trusted_signature = false;
        let mut out_of_window: Option<Rejection> = None;
        for sig in &signed.signatures {
            let Some((key, window)) = self.known_signer(sig)? else {
                continue;
            };
            if !key.verify(
                sig.algorithm(),
                Domain::TrustSet,
                &signed.payload,
                sig.bytes(),
            ) {
                return Err(Rejection::BadSignature(sig.kid()));
            }
            match window.map(|w| w.check(now, self.skew)) {
                None | Some(Ok(())) => trusted_signature = true,
                Some(Err(e)) => {
                    out_of_window.get_or_insert(Rejection::SignerNotValid(sig.kid(), e));
                }
            }
        }
        if !trusted_signature {
            return Err(out_of_window.unwrap_or(Rejection::NoTrustedSignature));
        }

        let current_version = self.trust_version();
        if offered.trust_version <= current_version {
            return Err(Rejection::NotNewer {
                current: current_version,
                offered: offered.trust_version,
            });
        }
        if offered.trust_version - current_version > MAX_VERSION_STEP {
            return Err(Rejection::VersionJump {
                current: current_version,
                offered: offered.trust_version,
            });
        }
        if let Some(current) = &self.current
            && offered.issued_at < current.issued_at
        {
            return Err(Rejection::IssuedBeforeCurrent);
        }
        if !Validity::not_in_future(offered.issued_at, now, self.skew) {
            return Err(Rejection::IssuedInFuture);
        }
        Ok(offered)
    }

    /// Checks a signed trust set and, if it passes, makes it current.
    /// On rejection the anchor is unchanged.
    ///
    /// # Errors
    ///
    /// As [`Self::check`].
    pub fn accept(&mut self, envelope: &[u8], now: Timestamp) -> Result<&TrustSet, Rejection> {
        let accepted = self.check(envelope, now)?;
        Ok(self.current.insert(accepted))
    }

    /// The key behind `sig` if the agent knows it, with its validity window
    /// (`None` for the pinned root, which has none). `Ok(None)` for a key
    /// the agent does not know.
    ///
    /// # Errors
    ///
    /// [`Rejection::AlgorithmNotAccepted`] if a known key's signature names
    /// an algorithm that is not the key's own or that the current set does
    /// not accept.
    fn known_signer(
        &self,
        sig: &Signature,
    ) -> Result<Option<(&PublicKey, Option<Validity>)>, Rejection> {
        let kid = sig.kid();
        if kid == self.pinned_root.kid() {
            // A root-ca key uses ECDSA P-384 only.
            return if sig.algorithm() == SignatureAlgorithm::EcdsaP384Sha384 {
                Ok(Some((&self.pinned_root, None)))
            } else {
                Err(Rejection::AlgorithmNotAccepted(sig.algorithm()))
            };
        }
        let Some(current) = &self.current else {
            return Ok(None);
        };
        let Some(key) = current.trust_keys.get(&kid) else {
            return Ok(None);
        };
        if !current.algorithms.contains(&sig.algorithm()) || sig.algorithm() != key.algorithm {
            return Err(Rejection::AlgorithmNotAccepted(sig.algorithm()));
        }
        Ok(Some((&key.public_key, Some(key.validity))))
    }
}

/// Why an agent refused a trust set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The envelope or payload is not canonical.
    Malformed(DecodeError),
    /// No signature is by a key the agent already trusts.
    NoTrustedSignature,
    /// A trusted key's signature does not verify.
    BadSignature(Kid),
    /// A trusted key signed with an algorithm the current set does not
    /// accept, or one that is not the key's own.
    AlgorithmNotAccepted(SignatureAlgorithm),
    /// A trusted key's validity window does not contain `now`, even
    /// allowing for skew.
    SignerNotValid(Kid, TimeError),
    /// `trust_version` is not greater than the current one (rollback or
    /// replay).
    NotNewer {
        /// The agent's current version.
        current: u64,
        /// The offered version.
        offered: u64,
    },
    /// `trust_version` is more than [`MAX_VERSION_STEP`] above the current
    /// one (fast-forward).
    VersionJump {
        /// The agent's current version.
        current: u64,
        /// The offered version.
        offered: u64,
    },
    /// `issued_at` is earlier than the current set's.
    IssuedBeforeCurrent,
    /// `issued_at` is later than `now` plus the skew tolerance.
    IssuedInFuture,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed trust set: {e}"),
            Self::NoTrustedSignature => f.write_str("no signature by a trusted key"),
            Self::BadSignature(kid) => write!(f, "the signature by {kid} does not verify"),
            Self::AlgorithmNotAccepted(alg) => write!(f, "{alg} is not accepted for this key"),
            Self::SignerNotValid(kid, e) => write!(f, "signing key {kid}: {e}"),
            Self::NotNewer { current, offered } => write!(
                f,
                "trust version {offered} is not newer than the current {current}"
            ),
            Self::VersionJump { current, offered } => write!(
                f,
                "trust version {offered} is more than {MAX_VERSION_STEP} above the current {current}"
            ),
            Self::IssuedBeforeCurrent => f.write_str("issued before the current trust set"),
            Self::IssuedInFuture => f.write_str("issued in the future"),
        }
    }
}

impl std::error::Error for Rejection {}

/// A signature check against a trust set failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The key is not listed for this domain.
    UnknownKey(Kid),
    /// The trust set does not accept the algorithm.
    AlgorithmNotAccepted(SignatureAlgorithm),
    /// The signature's algorithm is not the key's.
    AlgorithmMismatch,
    /// The key is outside its validity window.
    Time(TimeError),
    /// The signature does not verify.
    BadSignature,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(kid) => write!(f, "key {kid} is not trusted for this purpose"),
            Self::AlgorithmNotAccepted(alg) => write!(f, "{alg} is not accepted"),
            Self::AlgorithmMismatch => f.write_str("the algorithm is not the key's"),
            Self::Time(e) => e.fmt(f),
            Self::BadSignature => f.write_str("the signature does not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A trust set could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustSetError {
    /// `trust_version` 0 is reserved for "no trust set yet".
    ZeroVersion,
    /// The algorithm list is empty.
    NoAlgorithms,
    /// No trust key is listed.
    NoTrustKeys,
    /// A key uses an algorithm the set does not list.
    AlgorithmNotListed(SignatureAlgorithm),
    /// A key's status is not `active` or `retiring`.
    StatusNotTrusted(KeyStatus),
    /// A key's purpose does not belong in this list.
    WrongList {
        /// The list.
        list: &'static str,
        /// The key's purpose.
        purpose: KeyPurpose,
    },
    /// A key is listed twice, in the same list or in two lists.
    DuplicateKey(Kid),
    /// A pin is listed twice.
    DuplicatePin(Sha256Hex),
    /// A list is full; names the list.
    TooMany(&'static str),
    /// No signing keys, or more than [`MAX_SIGNATURES`].
    SignatureCount,
    /// A key rule was broken.
    Key(KeyError),
    /// The signer failed.
    Signer(SignerError),
}

impl fmt::Display for TrustSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroVersion => f.write_str("trust version 0 is reserved"),
            Self::NoAlgorithms => f.write_str("a trust set lists at least one algorithm"),
            Self::NoTrustKeys => f.write_str("a trust set lists at least one trust key"),
            Self::AlgorithmNotListed(alg) => write!(f, "{alg} is not in the algorithm list"),
            Self::StatusNotTrusted(status) => {
                write!(f, "a {status} key cannot be listed in a trust set")
            }
            Self::WrongList { list, purpose } => {
                write!(f, "a {purpose} key does not belong in {list}")
            }
            Self::DuplicateKey(kid) => write!(f, "key {kid} is listed twice"),
            Self::DuplicatePin(pin) => write!(f, "pin {pin} is listed twice"),
            Self::TooMany(what) => write!(f, "too many {what}"),
            Self::SignatureCount => write!(f, "a trust set has 1 to {MAX_SIGNATURES} signatures"),
            Self::Key(e) => e.fmt(f),
            Self::Signer(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for TrustSetError {}

/// Bytes are not a canonical trust set or envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ends early.
    Truncated,
    /// Bytes follow the last field.
    TrailingBytes,
    /// The format version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u8),
    /// A length is over its limit.
    TooLong,
    /// A count is over its limit (or zero where one is required); names the
    /// list.
    BadCount(&'static str),
    /// A list is not strictly ascending; names the list.
    NotAscending(&'static str),
    /// A code is not known; names the field.
    UnknownCode(&'static str),
    /// A timestamp is outside years 0001 to 9999.
    InvalidTimestamp,
    /// A validity window is invalid.
    Time(TimeError),
    /// The content breaks a trust-set rule.
    Set(TrustSetError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the input ends early"),
            Self::TrailingBytes => f.write_str("bytes follow the last field"),
            Self::UnsupportedVersion(v) => write!(f, "format version {v} is not supported"),
            Self::TooLong => f.write_str("a length is over its limit"),
            Self::BadCount(what) => write!(f, "the number of {what} is out of range"),
            Self::NotAscending(what) => write!(f, "{what} are not strictly ascending"),
            Self::UnknownCode(what) => write!(f, "unknown {what}"),
            Self::InvalidTimestamp => f.write_str("a timestamp is out of range"),
            Self::Time(e) => e.fmt(f),
            Self::Set(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A bounds-checked reader over untrusted bytes. Every read either returns
/// the bytes or fails; nothing indexes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(DecodeError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn timestamp(&mut self) -> Result<Timestamp, DecodeError> {
        Timestamp::from_unix_micros(i64::from_be_bytes(self.array()?))
            .ok_or(DecodeError::InvalidTimestamp)
    }

    /// A one-byte count from `min` to `max`.
    fn count(&mut self, min: usize, max: usize, what: &'static str) -> Result<usize, DecodeError> {
        let n = usize::from(self.u8()?);
        if n < min || n > max {
            return Err(DecodeError::BadCount(what));
        }
        Ok(n)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}
