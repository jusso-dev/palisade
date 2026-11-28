//! The signed policy bundle envelope (#325): signing on the server, and the
//! agent's verification, which produces the [`Examined`] that
//! [`select`](super::select) decides on.
//!
//! # Format
//!
//! One canonical, strict, versioned binary encoding, in the style of the
//! trust-set envelope ([`crate::pki::trust_set`]). All integers are
//! big-endian.
//!
//! ```text
//! envelope = version:u8 (= 1)
//!            kind:u8 (1 = bundle, 2 = delta)
//!            payload_len:u32 (1..=limit) payload
//!            n_sigs:u8 (1..=8) sig * n_sigs        ascending kid, no repeats
//! sig      = kid:[u8;16] alg:u8 bytes:[u8; length fixed by alg]
//! ```
//!
//! `alg` is [`SignatureAlgorithm::code`]: `ecdsa-p384-sha384` (the default)
//! or `ed25519` (ADR 0008, ADR 0017). More than one signature lets a bundle
//! carry signatures from an old and a new key during a rotation (#224).
//! Nothing may follow the last signature, and the decoder refuses anything
//! [`Envelope::encode`] would not write, so `encode(decode(b)) == b`.
//!
//! # What is signed
//!
//! Every signature covers [`Domain::Policy`]'s prefix followed by the
//! canonical **bundle** bytes: `"palisade-policy-v1\0" ‖ bundle_bytes`.
//!
//! - For `kind = 1`, the payload is that bundle.
//! - For `kind = 2`, the payload is a [`BundleDelta`], and the signatures
//!   cover the **result** bundle the delta produces, not the delta. The
//!   agent rebuilds the full bundle from its verified base with
//!   [`rebuild`], which yields an ordinary bundle envelope, and verifies
//!   that. A delta is never trusted on its own, so an unsigned or forged
//!   delta can at most produce bytes that fail verification. The rebuilt
//!   envelope is what the policy cache stores (#326), so the stored bundle
//!   always carries its own signatures.
//!
//! Only bundle bytes are ever signed in the policy domain, and every bundle
//! starts with the CBOR array byte `0x82`, so one signed message can never
//! be read as another kind of thing.
//!
//! # Header fields are not repeated
//!
//! The envelope does not repeat the tenant, target, `policy_version` or any
//! other header field. The agent reads them only from the signed bundle
//! bytes, with [`decode_header`], so there is no unsigned copy that could
//! disagree with the signed one.
//!
//! # Verification order
//!
//! [`verify`] runs #225's checks in order, and fails closed on every error:
//!
//! 1. the envelope size limit (64 MiB of bundle by default), before any
//!    byte is read, then the strict envelope decoding;
//! 2. at least one valid signature from a key the trust set lists for
//!    policy signing, inside its validity window. Signatures from keys the
//!    trust set does not list are ignored, so a bundle can be signed for
//!    agents on both sides of a rotation; a signature from a listed key
//!    that names an algorithm the trust set does not accept or that is not
//!    the key's, or that does not verify, is tampering and fails the
//!    bundle even if another signature verifies;
//! 3. tenant and target, and 4. the version: these depend on the device's
//!    enrolment and anti-rollback record, so [`select::pending`] and
//!    [`select::startup`] apply them to the [`Examined`] this returns, in
//!    this order (`policy_bundle::check`);
//! 5. `min_agent_version`;
//! 6. the schema: the header's format and schema version, and, for a bundle
//!    whose signature verified, the strict [`PolicyBundle::decode`] of the
//!    body.
//!
//! The header is read with [`decode_header`], which reads nothing past the
//! header. The body is decoded only after a signature verifies, or when the
//! effective signature mode (`audit` or `warn`) loads bundles whose
//! signature fails anyway. In `enforce` mode a bundle without a valid
//! signature is never decoded, and its schema is reported as unsupported:
//! a check that did not run never counts as passed (ADR 0018). The
//! signature check refuses it first in any case.
//!
//! [`select::pending`]: super::select::pending
//! [`select::startup`]: super::select::startup

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use palisade_policy::bundle::{
    AgentVersion, BundleDelta, BundleError, BundleLimits, DeltaError, Header, PolicyBundle,
    TargetScope, apply, bundle_hash, decode_header,
};

use super::{BundleMeta, EffectiveMode, Examined, Scope, Target, content_hash};
use crate::events::{HostId, TenantId, Timestamp};
use crate::pki::{
    Domain, Kid, Signature, SignatureAlgorithm, Signer, SignerError, SkewTolerance, TimeError,
    TrustSet, TrustedKey,
};

/// The envelope format this crate writes and reads.
pub const FORMAT_VERSION: u8 = 1;

/// Most signatures on one envelope.
pub const MAX_SIGNATURES: usize = 8;

/// The longest signature entry: key ID, algorithm code and an ECDSA P-384
/// signature.
const MAX_SIG_ENTRY: usize = 16 + 1 + 96;

/// The bytes around the payload at most: version, kind, length, count and
/// [`MAX_SIGNATURES`] signature entries.
pub const MAX_OVERHEAD: usize = 1 + 1 + 4 + 1 + MAX_SIGNATURES * MAX_SIG_ENTRY;

/// The largest payload the format can carry.
const MAX_ENCODABLE: usize = u32::MAX as usize;

/// The largest envelope accepted for a payload limit of `max_payload`
/// bytes.
#[must_use]
pub const fn max_envelope_len(max_payload: usize) -> usize {
    max_payload.saturating_add(MAX_OVERHEAD)
}

/// What an envelope carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A full bundle, signed.
    Bundle,
    /// A delta, with the signatures of the bundle it produces.
    Delta,
}

impl Kind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Bundle => 1,
            Self::Delta => 2,
        }
    }

    /// The kind with this wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Bundle),
            2 => Some(Self::Delta),
            _ => None,
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bundle => "bundle",
            Self::Delta => "delta",
        })
    }
}

/// A decoded envelope: what it carries, the payload and the signatures.
/// Decoding checks the encoding only; nothing here is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    kind: Kind,
    payload: Vec<u8>,
    signatures: Vec<Signature>,
}

impl Envelope {
    /// Signs `bundle` with each key in `kids`, in the [`Domain::Policy`]
    /// domain. This is the server's signing step.
    ///
    /// During a policy-key rotation, sign with both keys, so agents that
    /// trust either accept the bundle.
    ///
    /// # Errors
    ///
    /// [`SignError::NotABundle`] unless `bundle` starts with a bundle
    /// header (only the header is read), [`SignError::TooLarge`] if it is
    /// longer than the format can carry, and the errors of
    /// signing: [`SignError::SignatureCount`],
    /// [`SignError::DuplicateKey`] and [`SignError::Signer`].
    pub fn sign_bundle<S: Signer + ?Sized>(
        bundle: &[u8],
        signer: &S,
        kids: &[Kid],
    ) -> Result<Self, SignError> {
        check_bundle(bundle)?;
        Self::sign_kind(Kind::Bundle, bundle.to_vec(), bundle, signer, kids)
    }

    /// Wraps `delta` with the signatures of `result`, the bundle it
    /// produces. The agent rebuilds `result` with [`rebuild`] and verifies
    /// those signatures over it.
    ///
    /// # Errors
    ///
    /// [`SignError::ResultMismatch`] unless `result` hashes to the delta's
    /// `result_bundle_hash`, [`SignError::Delta`] if the delta does not
    /// encode, and the errors of [`sign_bundle`](Self::sign_bundle).
    pub fn sign_delta<S: Signer + ?Sized>(
        delta: &BundleDelta,
        result: &[u8],
        signer: &S,
        kids: &[Kid],
    ) -> Result<Self, SignError> {
        check_bundle(result)?;
        if bundle_hash(result) != delta.result_bundle_hash {
            return Err(SignError::ResultMismatch);
        }
        let payload = delta.to_bytes().map_err(SignError::Delta)?;
        if payload.len() > MAX_ENCODABLE {
            return Err(SignError::TooLarge);
        }
        Self::sign_kind(Kind::Delta, payload, result, signer, kids)
    }

    fn sign_kind<S: Signer + ?Sized>(
        kind: Kind,
        payload: Vec<u8>,
        signed: &[u8],
        signer: &S,
        kids: &[Kid],
    ) -> Result<Self, SignError> {
        if kids.is_empty() || kids.len() > MAX_SIGNATURES {
            return Err(SignError::SignatureCount);
        }
        let mut seen = BTreeSet::new();
        let mut signatures = Vec::with_capacity(kids.len());
        for kid in kids {
            if !seen.insert(*kid) {
                return Err(SignError::DuplicateKey(*kid));
            }
            signatures.push(
                signer
                    .sign(kid, Domain::Policy, signed)
                    .map_err(SignError::Signer)?,
            );
        }
        signatures.sort_by_key(Signature::kid);
        Ok(Self {
            kind,
            payload,
            signatures,
        })
    }

    /// Joins a payload and signatures made elsewhere, for example by an
    /// offline signing step or a hardware key.
    ///
    /// # Errors
    ///
    /// As [`Self::decode`] would report for the joined envelope.
    pub fn from_parts(
        kind: Kind,
        payload: Vec<u8>,
        mut signatures: Vec<Signature>,
        limits: &BundleLimits,
    ) -> Result<Self, EnvelopeError> {
        if payload.len() > MAX_ENCODABLE {
            return Err(EnvelopeError::TooLarge {
                size: payload.len(),
                limit: limits.max_bytes.min(MAX_ENCODABLE),
            });
        }
        signatures.sort_by_key(Signature::kid);
        let joined = Self {
            kind,
            payload,
            signatures,
        };
        Self::decode(&joined.encode(), limits)
    }

    /// What the envelope carries.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The payload: the bundle, or the delta.
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
        let mut out = Vec::with_capacity(
            self.payload
                .len()
                .saturating_add(7 + self.signatures.len() * MAX_SIG_ENTRY),
        );
        out.push(FORMAT_VERSION);
        out.push(self.kind.code());
        // Every constructor bounds the payload to `u32::MAX` bytes.
        let len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        // At most `MAX_SIGNATURES`, so it fits a byte.
        out.push(u8::try_from(self.signatures.len()).unwrap_or(u8::MAX));
        for sig in &self.signatures {
            out.extend_from_slice(sig.kid().as_bytes());
            out.push(sig.algorithm().code());
            out.extend_from_slice(sig.bytes());
        }
        out
    }

    /// Decodes envelope bytes, strictly. The payload is not read and no
    /// signature is checked: use [`verify`].
    ///
    /// # Errors
    ///
    /// [`EnvelopeError`] for anything but a canonical envelope whose
    /// payload is within `limits.max_bytes`.
    pub fn decode(bytes: &[u8], limits: &BundleLimits) -> Result<Self, EnvelopeError> {
        let max_payload = limits.max_bytes.min(MAX_ENCODABLE);
        let limit = max_envelope_len(max_payload);
        if bytes.len() > limit {
            return Err(EnvelopeError::TooLarge {
                size: bytes.len(),
                limit,
            });
        }
        let mut r = Reader(bytes);
        let version = r.u8()?;
        if version != FORMAT_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let code = r.u8()?;
        let kind = Kind::from_code(code).ok_or(EnvelopeError::UnknownKind(code))?;
        let len = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        if len == 0 {
            return Err(EnvelopeError::EmptyPayload);
        }
        if len > max_payload {
            return Err(EnvelopeError::TooLarge {
                size: len,
                limit: max_payload,
            });
        }
        let payload = r.take(len)?.to_vec();
        let n = usize::from(r.u8()?);
        if n == 0 || n > MAX_SIGNATURES {
            return Err(EnvelopeError::SignatureCount(n));
        }
        let mut signatures: Vec<Signature> = Vec::with_capacity(n);
        for _ in 0..n {
            let kid = Kid::from_bytes(r.array()?);
            let code = r.u8()?;
            let alg =
                SignatureAlgorithm::from_code(code).ok_or(EnvelopeError::UnknownAlgorithm(code))?;
            let sig_bytes = r.take(alg.signature_len())?.to_vec();
            if signatures.last().is_some_and(|prev| prev.kid() >= kid) {
                return Err(EnvelopeError::NotAscending);
            }
            // The length was taken from the algorithm, so this cannot fail.
            let sig = Signature::new(kid, alg, sig_bytes).map_err(|_| EnvelopeError::Truncated)?;
            signatures.push(sig);
        }
        r.finish()?;
        Ok(Self {
            kind,
            payload,
            signatures,
        })
    }
}

/// Signing needs a bundle: the header must read, and the length must fit
/// the format.
fn check_bundle(bundle: &[u8]) -> Result<(), SignError> {
    if bundle.len() > MAX_ENCODABLE {
        return Err(SignError::TooLarge);
    }
    let limits = BundleLimits {
        max_bytes: MAX_ENCODABLE,
        ..BundleLimits::DEFAULT
    };
    decode_header(bundle, &limits)
        .map(|_| ())
        .map_err(SignError::NotABundle)
}

/// Rebuilds the full bundle from a delta envelope and the agent's current
/// bundle, and returns it as a bundle envelope with the delta envelope's
/// signatures, ready for [`verify`].
///
/// `base` must be the bytes of the bundle the agent has verified and runs.
/// The delta is decoded and applied before any signature is checked, because
/// the signatures cover the result; the delta decoder is strict and bounded
/// by `limits`, and [`apply`] refuses any other base and any result that
/// does not hash to the delta's result hash. Nothing the delta produces is
/// trusted until [`verify`] accepts the returned envelope.
///
/// # Errors
///
/// [`RebuildError::Envelope`] if the envelope does not decode or is not a
/// delta, and [`RebuildError::Delta`] if the delta does not decode or apply.
pub fn rebuild(
    delta_envelope: &[u8],
    base: &[u8],
    limits: &BundleLimits,
) -> Result<Envelope, RebuildError> {
    let envelope = Envelope::decode(delta_envelope, limits).map_err(RebuildError::Envelope)?;
    if envelope.kind != Kind::Delta {
        return Err(RebuildError::Envelope(EnvelopeError::WrongKind {
            expected: Kind::Delta,
            found: envelope.kind,
        }));
    }
    let delta = BundleDelta::from_bytes(&envelope.payload, limits).map_err(RebuildError::Delta)?;
    let (_, bytes) = apply(base, &delta, limits).map_err(RebuildError::Delta)?;
    Ok(Envelope {
        kind: Kind::Bundle,
        payload: bytes,
        signatures: envelope.signatures,
    })
}

/// Why the signatures do not make a bundle trusted (#225 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// No signature is from a key the trust set lists for policy signing.
    NoTrustedSignature,
    /// A listed key's signature names an algorithm the trust set does not
    /// accept.
    AlgorithmNotAccepted(Kid, SignatureAlgorithm),
    /// A listed key's signature names an algorithm that is not the key's.
    AlgorithmMismatch(Kid),
    /// A listed key's signature does not verify: the bundle or the
    /// signature was changed, or it was made for another domain.
    BadSignature(Kid),
    /// Every listed key that signed is outside its validity window; the
    /// error is the first key's.
    KeyNotValid(Kid, TimeError),
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTrustedSignature => {
                f.write_str("no signature is from a trusted policy-signing key")
            }
            Self::AlgorithmNotAccepted(kid, alg) => {
                write!(f, "key {kid} signed with {alg}, which is not accepted")
            }
            Self::AlgorithmMismatch(kid) => {
                write!(f, "key {kid} signed with an algorithm that is not its own")
            }
            Self::BadSignature(kid) => write!(f, "the signature of key {kid} does not verify"),
            Self::KeyNotValid(kid, e) => write!(f, "key {kid}: {e}"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// The result of [`verify`]: the [`Examined`] that [`select`](super::select)
/// decides on, and the details behind it.
#[derive(Clone, Debug)]
pub struct Verified {
    examined: Examined,
    detail: Detail,
}

#[derive(Clone, Debug)]
enum Detail {
    Unreadable(EnvelopeError),
    Parsed {
        header: Header,
        signature: Result<Kid, SignatureError>,
        body: Option<Result<Box<PolicyBundle>, BundleError>>,
    },
}

impl Verified {
    /// The checks' results, for [`select::pending`](super::select::pending)
    /// and [`select::startup`](super::select::startup).
    #[must_use]
    pub const fn examined(&self) -> Examined {
        self.examined
    }

    /// Why the envelope could not be read, if it could not.
    #[must_use]
    pub const fn unreadable(&self) -> Option<&EnvelopeError> {
        match &self.detail {
            Detail::Unreadable(e) => Some(e),
            Detail::Parsed { .. } => None,
        }
    }

    /// The bundle header. Only trustworthy when [`Self::signer`] is set.
    #[must_use]
    pub const fn header(&self) -> Option<&Header> {
        match &self.detail {
            Detail::Parsed { header, .. } => Some(header),
            Detail::Unreadable(_) => None,
        }
    }

    /// The key whose signature made the bundle trusted (the lowest key ID,
    /// if several did), for `policy.applied`. `None` unless a signature
    /// verified.
    #[must_use]
    pub fn signer(&self) -> Option<Kid> {
        match &self.detail {
            Detail::Parsed { signature, .. } => signature.ok(),
            Detail::Unreadable(_) => None,
        }
    }

    /// Why no signature made the bundle trusted, if none did.
    #[must_use]
    pub fn signature_error(&self) -> Option<SignatureError> {
        match &self.detail {
            Detail::Parsed { signature, .. } => signature.err(),
            Detail::Unreadable(_) => None,
        }
    }

    /// Why the body does not decode, if it was decoded.
    #[must_use]
    pub fn body_error(&self) -> Option<&BundleError> {
        match &self.detail {
            Detail::Parsed {
                body: Some(Err(e)), ..
            } => Some(e),
            _ => None,
        }
    }

    /// The decoded bundle: present when the body was decoded (a signature
    /// verified, or the mode tolerates an invalid one) and it decoded.
    #[must_use]
    pub fn into_bundle(self) -> Option<PolicyBundle> {
        match self.detail {
            Detail::Parsed {
                body: Some(Ok(b)), ..
            } => Some(*b),
            _ => None,
        }
    }
}

/// What [`verify`] needs to know about the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Agent {
    /// This agent's version, for `min_agent_version` (step 5).
    pub version: AgentVersion,
    /// The bundle limits; [`BundleLimits::DEFAULT`] is 64 MiB.
    pub limits: BundleLimits,
    /// The clock-skew tolerance for key validity windows.
    pub skew: SkewTolerance,
    /// The signature mode in force. It decides only whether the body of a
    /// bundle whose signature fails is decoded; [`select`](super::select)
    /// applies the mode itself.
    pub mode: EffectiveMode,
}

/// Verifies a bundle envelope for this agent (#225 steps 1, 2, 5 and 6; the
/// module documentation has the order). `trust` is the agent's current
/// trust set and `now` trusted time (#220).
///
/// Every failure is reported in the result, never as an allow: an
/// unreadable envelope is [`Examined::Unreadable`], and anything else that
/// fails, or was not checked, sets the matching flag of
/// [`Examined::Parsed`] to `false`.
#[must_use]
pub fn verify(envelope: &[u8], trust: &TrustSet, agent: &Agent, now: Timestamp) -> Verified {
    let limits = &agent.limits;
    let unreadable = |e| Verified {
        examined: Examined::Unreadable,
        detail: Detail::Unreadable(e),
    };
    // Step 1: the size limit, then the strict envelope.
    let env = match Envelope::decode(envelope, limits) {
        Ok(env) => env,
        Err(e) => return unreadable(e),
    };
    if env.kind != Kind::Bundle {
        return unreadable(EnvelopeError::WrongKind {
            expected: Kind::Bundle,
            found: env.kind,
        });
    }
    // Step 2, before anything reads the payload.
    let signature = check_signatures(&env, trust, agent.skew, now);
    // The header only: nothing past it is read yet.
    let header = match decode_header(&env.payload, limits) {
        Ok(h) => h,
        Err(e) => return unreadable(EnvelopeError::Header(e)),
    };
    let meta = BundleMeta {
        target: target_of(header.target),
        version: header.policy_version,
        sha256: content_hash(&env.payload),
    };
    // Step 6: the body is decoded only once a signature has verified, or
    // when the mode loads unsigned bundles anyway. A body not decoded is
    // not a supported schema.
    let body = (signature.is_ok() || agent.mode.tolerates_invalid_signature())
        .then(|| PolicyBundle::decode(&env.payload, limits).map(Box::new));
    let body_ok = matches!(body, Some(Ok(_)));
    Verified {
        examined: Examined::Parsed {
            meta,
            signature_valid: signature.is_ok(),
            agent_supported: header.supports_agent(agent.version),
            schema_supported: header.schema_supported() && body_ok,
        },
        detail: Detail::Parsed {
            header,
            signature,
            body,
        },
    }
}

/// #225 step 2, with the trust anchor's rule for known keys: every
/// signature by a listed policy key must be well formed and verify, and at
/// least one such key must be inside its validity window.
fn check_signatures(
    env: &Envelope,
    trust: &TrustSet,
    skew: SkewTolerance,
    now: Timestamp,
) -> Result<Kid, SignatureError> {
    let mut trusted = None;
    let mut out_of_window = None;
    for sig in &env.signatures {
        let Some(key) = policy_key(trust, sig.kid()) else {
            // Unknown keys are ignored, for rotations.
            continue;
        };
        let alg = sig.algorithm();
        if !trust.algorithms().any(|a| a == alg) {
            return Err(SignatureError::AlgorithmNotAccepted(sig.kid(), alg));
        }
        if alg != key.algorithm() {
            return Err(SignatureError::AlgorithmMismatch(sig.kid()));
        }
        if !key
            .public_key()
            .verify(alg, Domain::Policy, &env.payload, sig.bytes())
        {
            return Err(SignatureError::BadSignature(sig.kid()));
        }
        match key.validity().check(now, skew) {
            Ok(()) => {
                trusted.get_or_insert(sig.kid());
            }
            Err(e) => {
                out_of_window.get_or_insert(SignatureError::KeyNotValid(sig.kid(), e));
            }
        }
    }
    trusted.ok_or(out_of_window.unwrap_or(SignatureError::NoTrustedSignature))
}

fn policy_key(trust: &TrustSet, kid: Kid) -> Option<&TrustedKey> {
    trust.policy_keys().find(|k| k.kid() == kid)
}

/// The bundle header's target in the event types' terms.
#[must_use]
pub const fn target_of(target: palisade_policy::bundle::Target) -> Target {
    Target {
        tenant: TenantId(target.tenant),
        scope: match target.scope {
            TargetScope::Group(id) => Scope::Group(id),
            TargetScope::Device(id) => Scope::Device(HostId(id)),
        },
    }
}

/// Bytes are not a canonical envelope this agent reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope or its payload is over the size limit.
    TooLarge {
        /// The size, in bytes.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The input ends early.
    Truncated,
    /// Bytes follow the last signature.
    TrailingBytes,
    /// The format version is not [`FORMAT_VERSION`].
    UnsupportedVersion(u8),
    /// The kind code is not known.
    UnknownKind(u8),
    /// The envelope carries another kind than the one expected.
    WrongKind {
        /// The kind expected.
        expected: Kind,
        /// The kind found.
        found: Kind,
    },
    /// The payload is empty.
    EmptyPayload,
    /// No signatures, or more than [`MAX_SIGNATURES`].
    SignatureCount(usize),
    /// The signatures are not strictly ascending by key ID.
    NotAscending,
    /// A signature algorithm code is not known.
    UnknownAlgorithm(u8),
    /// The bundle header does not read.
    Header(BundleError),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, limit } => {
                write!(f, "the envelope is {size} bytes, over the limit of {limit}")
            }
            Self::Truncated => f.write_str("the envelope ends early"),
            Self::TrailingBytes => f.write_str("bytes follow the last signature"),
            Self::UnsupportedVersion(v) => {
                write!(f, "envelope format {v} is not supported")
            }
            Self::UnknownKind(k) => write!(f, "unknown envelope kind {k}"),
            Self::WrongKind { expected, found } => {
                write!(f, "the envelope holds a {found}, not a {expected}")
            }
            Self::EmptyPayload => f.write_str("the envelope payload is empty"),
            Self::SignatureCount(n) => write!(
                f,
                "the envelope has {n} signatures; it must have 1 to {MAX_SIGNATURES}"
            ),
            Self::NotAscending => f.write_str("the signatures are not ascending by key ID"),
            Self::UnknownAlgorithm(code) => write!(f, "unknown signature algorithm {code}"),
            Self::Header(e) => write!(f, "the bundle header does not read: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Signing failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The bytes do not start with a bundle header.
    NotABundle(BundleError),
    /// The payload is longer than the format can carry.
    TooLarge,
    /// The result bundle does not hash to the delta's result hash.
    ResultMismatch,
    /// The delta does not encode.
    Delta(DeltaError),
    /// No keys, or more than [`MAX_SIGNATURES`].
    SignatureCount,
    /// A key was given twice.
    DuplicateKey(Kid),
    /// The signer failed, including for a key whose purpose may not sign
    /// policy bundles.
    Signer(SignerError),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotABundle(e) => write!(f, "not a policy bundle: {e}"),
            Self::TooLarge => f.write_str("the payload is too large for the envelope"),
            Self::ResultMismatch => {
                f.write_str("the result bundle does not match the delta's result hash")
            }
            Self::Delta(e) => e.fmt(f),
            Self::SignatureCount => write!(f, "sign with 1 to {MAX_SIGNATURES} keys"),
            Self::DuplicateKey(kid) => write!(f, "key {kid} is given twice"),
            Self::Signer(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SignError {}

/// A delta envelope could not be turned into a bundle envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RebuildError {
    /// The envelope does not decode, or is not a delta.
    Envelope(EnvelopeError),
    /// The delta does not decode, or does not apply to the base.
    Delta(DeltaError),
}

impl fmt::Display for RebuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Envelope(e) => e.fmt(f),
            Self::Delta(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RebuildError {}

/// A bounds-checked reader over untrusted bytes. Every read either returns
/// the bytes or fails; nothing indexes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvelopeError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(EnvelopeError::Truncated)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, EnvelopeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), EnvelopeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(EnvelopeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests;
