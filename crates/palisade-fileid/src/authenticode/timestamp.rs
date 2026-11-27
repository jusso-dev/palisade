//! Timestamps on Authenticode signatures (#50).
//!
//! A signature's unauthenticated attributes can carry timestamps that say
//! when it was made. [`verify_timestamps`] parses and verifies every one
//! that [`super::verify_certificate_table`] collected
//! ([`SignatureInfo::timestamp_tokens`]):
//!
//! - **Legacy Authenticode timestamps**: a PKCS #9 countersignature
//!   (1.2.840.113549.1.9.6), a SignerInfo whose `messageDigest` attribute is
//!   the hash of the primary signature value and whose `signingTime`
//!   attribute is the time. Its signer certificate is one of the primary
//!   signature's embedded certificates.
//! - **RFC 3161 timestamp tokens** (1.3.6.1.4.1.311.3.3.1, or the standard
//!   `id-aa-timeStampToken` 1.2.840.113549.1.9.16.2.14): a SignedData over a
//!   `TSTInfo`, whose `messageImprint` must be the hash of the primary
//!   signature value and whose `genTime` is the time. Its signer
//!   certificate is in the token, or else among the primary signature's
//!   certificates.
//!
//! A timestamp is [`TimestampStatus::Valid`] only when all of these hold:
//! it parses as strict DER; it covers this signature's value; its own
//! signature verifies with its signer certificate's key (and that
//! certificate matches the ESS `signingCertificate` attribute, when there is
//! one); no digest is MD2 or MD5; the signer certificate chains to an
//! anchor of the **TSA** [`TrustConfig`] the caller supplies; the chain is in
//! force for the Time Stamping EKU (the TSA certificate lists it, and no
//! issuer restricts it away); the TSA key usage, if restricted, allows
//! digital signatures; and the timestamp's time, widened by its stated
//! accuracy, lies inside every chain certificate's validity period.
//!
//! What a valid timestamp means for the signature (expiry, revocation,
//! policy constraints) is decided by [`super::evaluate_validity`].
//!
//! # Untrusted input
//!
//! Every byte goes through the strict DER reader in `asn1.rs`, and
//! cryptography through `crypto.rs` (ADR 0008). At most
//! [`super::MAX_TIMESTAMPS`] timestamps are kept per signature,
//! [`MAX_FILE_TIMESTAMPS`] are verified per file, and chain checks that use
//! keys a file supplies share one budget of
//! [`super::MAX_FILE_SIGNATURE_CHECKS`] per file, so a hostile file cannot
//! make verification expensive. Nothing panics.

#![forbid(unsafe_code)]

use std::fmt;

use serde::Serialize;

use super::asn1::{self, Asn1Error, ObjectId, Tlv, oid, read_oid, read_small_uint, tag};
use super::chain::{ChainReport, MAX_FILE_SIGNATURE_CHECKS, TrustConfig, build_chain_within};
use super::crypto::{self, PublicKey, Verified};
use super::eku;
use super::pkcs7::{self, CertKey, DigestId};
use super::signature::{
    DigestAlgorithm, SignatureAlgorithm, SignatureError, SignatureInfo, SignerIdentifier,
    TimestampKind, Unsupported,
};
use super::verify;
use super::x509::{self, Budget, CertSummary, CertificateError, KeyUsage};
use crate::hash::{AlgorithmSet, hash_bytes};

/// The most timestamps verified for one file, across all its signatures.
/// Later ones are reported as [`TimestampStatus::NotChecked`].
pub const MAX_FILE_TIMESTAMPS: usize = 32;
/// The most certificates kept from one RFC 3161 token.
pub const MAX_TOKEN_CERTIFICATES: usize = super::MAX_CERTIFICATES;
/// The most warnings kept for one timestamp.
pub const MAX_TIMESTAMP_WARNINGS: usize = 16;

/// Why a timestamp could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimestampError {
    /// The DER encoding is invalid.
    Asn1(Asn1Error),
    /// A part shared with signature parsing (an algorithm identifier, an
    /// attribute) is invalid.
    Signature(SignatureError),
    /// The RFC 3161 token is not a `signedData` ContentInfo.
    NotSignedData(ObjectId),
    /// The token's content type is not `id-ct-TSTInfo`.
    NotTstInfo(ObjectId),
    /// The token has no encapsulated content.
    MissingContent,
    /// The token does not have exactly one SignerInfo.
    SignerCount(usize),
    /// The timestamp's SignerInfo has no authenticated attributes.
    MissingAuthenticatedAttributes,
    /// A required authenticated attribute is missing (`contentType` and
    /// `messageDigest` for a token, `messageDigest` and `signingTime` for a
    /// countersignature).
    MissingAttribute(ObjectId),
    /// An authenticated attribute appears more than once.
    DuplicateAttribute(ObjectId),
    /// A `TSTInfo` extension appears more than once.
    DuplicateExtension(ObjectId),
    /// The `contentType` attribute names the wrong type.
    ContentTypeMismatch(ObjectId),
    /// The `TSTInfo` version is not 1.
    UnsupportedVersion(u32),
    /// `genTime` is not a GeneralizedTime.
    NotGeneralizedTime,
    /// The `accuracy` field is out of range (millis or micros outside 1 to
    /// 999).
    BadAccuracy,
    /// The message imprint is not as long as its algorithm's output.
    DigestLength,
    /// `TSTInfo` has a critical extension, which nothing here processes.
    CriticalExtension(ObjectId),
    /// The `tsa` name could not be parsed.
    TsaName(CertificateError),
    /// The signer certificate could not be parsed into a chain.
    SignerCertificate(CertificateError),
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::Signature(e) => write!(f, "{e}"),
            Self::NotSignedData(o) => write!(f, "token content type {o} is not signedData"),
            Self::NotTstInfo(o) => write!(f, "token content type {o} is not TSTInfo"),
            Self::MissingContent => f.write_str("the token has no content"),
            Self::SignerCount(n) => write!(f, "{n} SignerInfos; a token has exactly one"),
            Self::MissingAuthenticatedAttributes => f.write_str("no authenticated attributes"),
            Self::MissingAttribute(o) => write!(f, "missing authenticated attribute {o}"),
            Self::DuplicateAttribute(o) => write!(f, "authenticated attribute {o} appears twice"),
            Self::DuplicateExtension(o) => write!(f, "TSTInfo extension {o} appears twice"),
            Self::ContentTypeMismatch(o) => write!(f, "unexpected contentType attribute {o}"),
            Self::UnsupportedVersion(v) => write!(f, "TSTInfo version {v} is not 1"),
            Self::NotGeneralizedTime => f.write_str("genTime is not a GeneralizedTime"),
            Self::BadAccuracy => f.write_str("accuracy millis or micros out of range"),
            Self::DigestLength => f.write_str("the message imprint has the wrong length"),
            Self::CriticalExtension(o) => write!(f, "unprocessed critical TSTInfo extension {o}"),
            Self::TsaName(e) => write!(f, "invalid tsa name: {e}"),
            Self::SignerCertificate(e) => write!(f, "invalid TSA certificate: {e}"),
        }
    }
}

impl std::error::Error for TimestampError {}

impl From<Asn1Error> for TimestampError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

impl From<SignatureError> for TimestampError {
    fn from(e: SignatureError) -> Self {
        match e {
            SignatureError::Asn1(e) => Self::Asn1(e),
            other => Self::Signature(other),
        }
    }
}

type Result<T> = std::result::Result<T, TimestampError>;

/// The verdict on one timestamp. Anything but [`TimestampStatus::Valid`]
/// means the timestamp is not used.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimestampStatus {
    /// Every check passed (see the module documentation).
    Valid,
    /// The timestamp could not be parsed.
    Malformed(TimestampError),
    /// The timestamp does not cover this signature: the RFC 3161
    /// `messageImprint`, or the countersignature's `messageDigest`
    /// attribute, is not the hash of the primary signature value. A
    /// timestamp copied from another signature, or forged, ends here.
    ImprintMismatch,
    /// The RFC 3161 token's `messageDigest` attribute is not the hash of
    /// its `TSTInfo`: the content was changed after signing.
    ContentDigestMismatch,
    /// No certificate matches the timestamp's signer identifier.
    SignerCertificateNotFound,
    /// The timestamp's signature does not verify with its signer
    /// certificate's key.
    SignatureInvalid,
    /// The signer certificate is not the one the ESS `signingCertificate`
    /// attribute names.
    SigningCertificateMismatch,
    /// A digest is MD2 or MD5.
    WeakAlgorithm(DigestAlgorithm),
    /// The timestamp could not be verified.
    Unsupported(Unsupported),
    /// The TSA certificate chains to no anchor of the TSA trust
    /// configuration.
    UntrustedTsa,
    /// The TSA chain could be built only by relaxing an issuer's basic
    /// constraints ([`super::TrustConfig::ignore_basic_constraints`]). Those
    /// relaxations are for code signers' chains; a TSA chain that needs one
    /// is never trusted, even when the TSA trust configuration is shared
    /// with code signing.
    TsaBasicConstraintsRelaxed,
    /// The TSA chain is not in force for the Time Stamping EKU.
    MissingTimeStampingEku,
    /// The TSA certificate's key usage does not include
    /// `digitalSignature`.
    TsaKeyUsage,
    /// The timestamp's time (widened by its accuracy) is outside the
    /// validity period of a certificate in the TSA chain.
    TsaNotValidAtTime,
    /// A certificate in the TSA chain is revoked (set by
    /// [`super::evaluate_validity`]).
    TsaRevoked,
    /// The revocation state of a certificate in the TSA chain could not be
    /// obtained, and policy fails closed (set by
    /// [`super::evaluate_validity`]).
    TsaRevocationUnknown,
    /// The timestamp uses SHA-1 and its time is after the configured SHA-1
    /// cutoff (set by [`super::evaluate_validity`]).
    Sha1PastCutoff,
    /// Not verified: [`MAX_FILE_TIMESTAMPS`] were already verified for this
    /// file.
    NotChecked,
}

impl TimestampStatus {
    /// Whether the status is [`TimestampStatus::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Something unusual about a timestamp that does not change its status.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TimestampWarning {
    /// The token has no ESS `signingCertificate` attribute (RFC 3161
    /// requires one), so the signer certificate is bound only by its key.
    NoSigningCertificateAttribute,
    /// An authenticated attribute of an unknown type was ignored.
    UnknownAttribute(ObjectId),
    /// The SignerInfo version does not match its signer identifier form.
    SignerVersionMismatch(u32),
    /// The TSA certificate lists more extended key usages than Time
    /// Stamping (RFC 3161 asks for exactly one).
    TsaEkuNotSole,
    /// The `tsa` field is not a directory name, so it is not reported.
    TsaNameNotDirectory,
    /// The token holds more than [`MAX_TOKEN_CERTIFICATES`] certificates;
    /// the rest were ignored.
    TooManyCertificates,
    /// A `CertificateChoices` entry that is not an X.509 certificate was
    /// skipped.
    NonX509Certificate,
    /// The timestamp's digests (imprint or signer) use SHA-1.
    Sha1Digest,
    /// More than [`MAX_TIMESTAMP_WARNINGS`] warnings; the rest were dropped.
    WarningsTruncated,
}

/// One verified timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimestampInfo {
    /// Its position in [`SignatureInfo::timestamp_tokens`].
    pub index: usize,
    /// Legacy countersignature or RFC 3161 token.
    pub kind: TimestampKind,
    /// The time it states, in seconds since the Unix epoch (UTC): the
    /// countersignature's `signingTime`, or the token's `genTime` (any
    /// fraction of a second dropped). `None` if it did not parse.
    pub time: Option<i64>,
    /// The stated accuracy, rounded up to whole seconds, plus one second
    /// when `genTime` had a fraction. 0 for a countersignature or a token
    /// without `accuracy`.
    pub accuracy_secs: u64,
    /// The digest over the primary signature value: the RFC 3161 imprint
    /// algorithm, or the countersigner's digest algorithm.
    pub digest_alg: Option<DigestAlgorithm>,
    /// The digest the timestamp's SignerInfo uses.
    pub signer_digest_alg: Option<DigestAlgorithm>,
    /// The RFC 3161 TSA policy.
    pub policy: Option<ObjectId>,
    /// The RFC 3161 serial number, lowercase hex as encoded.
    pub serial_number: Option<String>,
    /// The RFC 3161 `tsa` field, when it is a directory name: its canonical
    /// DN string. Informational: it is not checked against the certificate.
    pub tsa_name: Option<String>,
    /// The TSA (signer) certificate, if it was found and parsed.
    pub tsa_cert: Option<CertSummary>,
    /// The TSA certificate's chains, built against the TSA trust
    /// configuration.
    pub tsa_chain: Option<ChainReport>,
    /// The verdict.
    pub status: TimestampStatus,
    /// Whether [`Self::status`] is [`TimestampStatus::Valid`].
    pub valid: bool,
    /// Anything unusual.
    pub warnings: Vec<TimestampWarning>,
}

impl TimestampInfo {
    /// The earliest time the timestamp allows: its time less its accuracy.
    #[must_use]
    pub fn earliest(&self) -> Option<i64> {
        self.time
            .map(|t| t.saturating_sub(accuracy_i64(self.accuracy_secs)))
    }

    /// The latest time the timestamp allows: its time plus its accuracy.
    #[must_use]
    pub fn latest(&self) -> Option<i64> {
        self.time
            .map(|t| t.saturating_add(accuracy_i64(self.accuracy_secs)))
    }

    /// Whether the imprint or the signer digest is SHA-1.
    #[must_use]
    pub fn uses_sha1(&self) -> bool {
        self.digest_alg == Some(DigestAlgorithm::Sha1)
            || self.signer_digest_alg == Some(DigestAlgorithm::Sha1)
    }

    /// Sets the status, keeping [`Self::valid`] in step.
    pub(crate) fn set_status(&mut self, status: TimestampStatus) {
        self.valid = status.is_valid();
        self.status = status;
    }
}

fn accuracy_i64(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Collects warnings up to [`MAX_TIMESTAMP_WARNINGS`].
#[derive(Debug, Default)]
struct Warnings(Vec<TimestampWarning>);

impl Warnings {
    fn push(&mut self, warning: TimestampWarning) {
        if self.0.contains(&warning) {
            return;
        }
        if self.0.len() < MAX_TIMESTAMP_WARNINGS {
            self.0.push(warning);
        } else if !self.0.contains(&TimestampWarning::WarningsTruncated) {
            self.0.push(TimestampWarning::WarningsTruncated);
        }
    }
}

/// The work one file may cause: timestamps verified, and chain checks with
/// keys the file supplies.
#[derive(Debug)]
pub(crate) struct TimestampBudget {
    tokens_left: usize,
    pub(crate) checks: Budget,
}

impl TimestampBudget {
    /// The budget for one file.
    pub(crate) const fn for_file() -> Self {
        Self {
            tokens_left: MAX_FILE_TIMESTAMPS,
            checks: Budget::new(MAX_FILE_SIGNATURE_CHECKS),
        }
    }

    fn take_token(&mut self) -> bool {
        if self.tokens_left == 0 {
            false
        } else {
            self.tokens_left -= 1;
            true
        }
    }
}

/// Parses and verifies every timestamp of `sig` against `tsa`, the trust
/// configuration for timestamping authorities (which may be the same as the
/// code signing one). Returns one [`TimestampInfo`] per entry of
/// [`SignatureInfo::timestamp_tokens`], in order. A signature that did not
/// parse has no timestamps.
#[must_use]
pub fn verify_timestamps(sig: &SignatureInfo, tsa: &TrustConfig) -> Vec<TimestampInfo> {
    verify_timestamps_within(sig, tsa, &mut TimestampBudget::for_file())
}

/// [`verify_timestamps`] with a file-wide budget.
pub(crate) fn verify_timestamps_within(
    sig: &SignatureInfo,
    tsa: &TrustConfig,
    budget: &mut TimestampBudget,
) -> Vec<TimestampInfo> {
    sig.timestamp_tokens
        .iter()
        .enumerate()
        .map(|(index, token)| {
            let mut info = blank(index, token.kind);
            if budget.take_token() {
                verify_one(
                    &mut info,
                    &token.der,
                    &sig.signature_value,
                    &sig.certs_in_blob,
                    tsa,
                    &mut budget.checks,
                );
            } else {
                info.set_status(TimestampStatus::NotChecked);
            }
            info
        })
        .collect()
}

fn blank(index: usize, kind: TimestampKind) -> TimestampInfo {
    TimestampInfo {
        index,
        kind,
        time: None,
        accuracy_secs: 0,
        digest_alg: None,
        signer_digest_alg: None,
        policy: None,
        serial_number: None,
        tsa_name: None,
        tsa_cert: None,
        tsa_chain: None,
        status: TimestampStatus::NotChecked,
        valid: false,
        warnings: Vec::new(),
    }
}

/// The parts of a timestamp's SignerInfo that verification needs.
struct TsSigner<'a> {
    sid: SignerIdentifier,
    digest_alg: DigestId,
    /// The authenticated attributes with the SET tag: what the signature
    /// covers.
    signed_attrs: Vec<u8>,
    content_type: Option<&'a [u8]>,
    message_digest: Option<&'a [u8]>,
    signing_time: Option<i64>,
    /// Every ESS certificate binding: `signingCertificate` and
    /// `signingCertificateV2`, at most one of each. All must match.
    signing_certs: Vec<EssCertId<'a>>,
    sig_alg: SignatureAlgorithm,
    signature: &'a [u8],
}

/// The first `ESSCertID` (or `ESSCertIDv2`) of a `signingCertificate`
/// attribute: the hash of the signer certificate.
struct EssCertId<'a> {
    alg: DigestId,
    hash: &'a [u8],
}

/// A parsed RFC 3161 token.
struct Token<'a> {
    tst: TstInfo<'a>,
    /// The DER `TSTInfo`: what the `messageDigest` attribute hashes.
    tst_der: &'a [u8],
    certificates: Vec<&'a [u8]>,
    signer: TsSigner<'a>,
}

struct TstInfo<'a> {
    policy: &'a [u8],
    imprint_alg: DigestId,
    imprint: &'a [u8],
    serial: &'a [u8],
    time: i64,
    accuracy_secs: u64,
    tsa_name: Option<String>,
}

fn verify_one(
    info: &mut TimestampInfo,
    der: &[u8],
    signature_value: &[u8],
    outer_certs: &[Vec<u8>],
    tsa: &TrustConfig,
    checks: &mut Budget,
) {
    let mut warnings = Warnings::default();
    let status = match info.kind {
        TimestampKind::Rfc3161 => verify_rfc3161(
            info,
            der,
            signature_value,
            outer_certs,
            tsa,
            checks,
            &mut warnings,
        ),
        TimestampKind::CounterSignature => verify_legacy(
            info,
            der,
            signature_value,
            outer_certs,
            tsa,
            checks,
            &mut warnings,
        ),
    };
    if info.uses_sha1() {
        warnings.push(TimestampWarning::Sha1Digest);
    }
    info.warnings = warnings.0;
    info.set_status(status);
}

fn verify_rfc3161(
    info: &mut TimestampInfo,
    der: &[u8],
    signature_value: &[u8],
    outer_certs: &[Vec<u8>],
    tsa: &TrustConfig,
    checks: &mut Budget,
    warnings: &mut Warnings,
) -> TimestampStatus {
    let token = match parse_token(der, warnings) {
        Ok(token) => token,
        Err(e) => return TimestampStatus::Malformed(e),
    };
    info.time = Some(token.tst.time);
    info.accuracy_secs = token.tst.accuracy_secs;
    info.digest_alg = token.tst.imprint_alg.as_ref().ok().copied();
    info.signer_digest_alg = token.signer.digest_alg.as_ref().ok().copied();
    info.policy = Some(ObjectId::from_der(token.tst.policy));
    info.serial_number = Some(x509::hex(token.tst.serial));
    info.tsa_name.clone_from(&token.tst.tsa_name);

    if let Err(status) = check_digest(&token.tst.imprint_alg, token.tst.imprint, signature_value) {
        return status;
    }
    match token.signer.content_type {
        Some(oid::TST_INFO) => {}
        Some(other) => {
            return TimestampStatus::Malformed(TimestampError::ContentTypeMismatch(
                ObjectId::from_der(other),
            ));
        }
        None => {
            return TimestampStatus::Malformed(TimestampError::MissingAttribute(
                ObjectId::from_der(oid::CONTENT_TYPE),
            ));
        }
    }
    let Some(message_digest) = token.signer.message_digest else {
        return TimestampStatus::Malformed(TimestampError::MissingAttribute(ObjectId::from_der(
            oid::MESSAGE_DIGEST,
        )));
    };
    if let Err(status) = check_digest(&token.signer.digest_alg, message_digest, token.tst_der) {
        return match status {
            TimestampStatus::ImprintMismatch => TimestampStatus::ContentDigestMismatch,
            other => other,
        };
    }
    if token.signer.signing_certs.is_empty() {
        warnings.push(TimestampWarning::NoSigningCertificateAttribute);
    }
    // The token's own certificates first, then the signature's.
    let certs: Vec<Vec<u8>> = token
        .certificates
        .iter()
        .map(|c| c.to_vec())
        .chain(outer_certs.iter().cloned())
        .collect();
    verify_signer_and_tsa(info, &token.signer, &certs, tsa, checks, warnings)
}

fn verify_legacy(
    info: &mut TimestampInfo,
    der: &[u8],
    signature_value: &[u8],
    outer_certs: &[Vec<u8>],
    tsa: &TrustConfig,
    checks: &mut Budget,
    warnings: &mut Warnings,
) -> TimestampStatus {
    let signer = match asn1::single(der, 0, tag::SEQUENCE)
        .map_err(TimestampError::from)
        .and_then(|info| parse_ts_signer(&info, warnings))
    {
        Ok(signer) => signer,
        Err(e) => return TimestampStatus::Malformed(e),
    };
    info.digest_alg = signer.digest_alg.as_ref().ok().copied();
    info.signer_digest_alg = info.digest_alg;
    info.time = signer.signing_time;
    // RFC 5652 leaves `contentType` out of countersignatures; Authenticode
    // signers put `data` there. Anything else is not a countersignature.
    if let Some(ct) = signer.content_type.filter(|ct| *ct != oid::DATA) {
        return TimestampStatus::Malformed(TimestampError::ContentTypeMismatch(
            ObjectId::from_der(ct),
        ));
    }
    let Some(message_digest) = signer.message_digest else {
        return TimestampStatus::Malformed(TimestampError::MissingAttribute(ObjectId::from_der(
            oid::MESSAGE_DIGEST,
        )));
    };
    if signer.signing_time.is_none() {
        return TimestampStatus::Malformed(TimestampError::MissingAttribute(ObjectId::from_der(
            oid::SIGNING_TIME,
        )));
    }
    if let Err(status) = check_digest(&signer.digest_alg, message_digest, signature_value) {
        return status;
    }
    verify_signer_and_tsa(info, &signer, outer_certs, tsa, checks, warnings)
}

/// Checks that `digest` is the hash of `data` under `alg`. A broken or
/// unknown algorithm fails first.
fn check_digest(
    alg: &DigestId,
    digest: &[u8],
    data: &[u8],
) -> std::result::Result<(), TimestampStatus> {
    let alg = match alg {
        Ok(alg) => *alg,
        Err(oid) => {
            return Err(TimestampStatus::Unsupported(Unsupported::UnknownDigest(
                oid.clone(),
            )));
        }
    };
    if alg.is_broken() {
        return Err(TimestampStatus::WeakAlgorithm(alg));
    }
    let Some(hash_alg) = alg.hash_algorithm() else {
        return Err(TimestampStatus::WeakAlgorithm(alg));
    };
    let computed = hash_bytes(data, AlgorithmSet::from(hash_alg));
    if computed
        .get(hash_alg)
        .is_some_and(|d| d.as_bytes() == digest)
    {
        Ok(())
    } else {
        Err(TimestampStatus::ImprintMismatch)
    }
}

/// Finds the signer certificate, verifies the timestamp's signature, and
/// judges the TSA chain.
fn verify_signer_and_tsa(
    info: &mut TimestampInfo,
    signer: &TsSigner<'_>,
    certs: &[Vec<u8>],
    tsa: &TrustConfig,
    checks: &mut Budget,
    warnings: &mut Warnings,
) -> TimestampStatus {
    let signer_alg = match &signer.digest_alg {
        Ok(alg) if alg.is_broken() => return TimestampStatus::WeakAlgorithm(*alg),
        Ok(alg) => *alg,
        Err(oid) => {
            return TimestampStatus::Unsupported(Unsupported::UnknownDigest(oid.clone()));
        }
    };
    let found = certs.iter().enumerate().find_map(|(i, der)| {
        pkcs7::parse_certificate(der)
            .ok()
            .filter(|c| pkcs7::matches(c, &signer.sid))
            .map(|c| (i, c))
    });
    let Some((cert_index, cert)) = found else {
        return TimestampStatus::SignerCertificateNotFound;
    };
    let scheme = match verify::scheme(&signer.sig_alg, signer_alg) {
        Ok(scheme) => scheme,
        Err(why) => return TimestampStatus::Unsupported(why),
    };
    let key = match cert.key {
        Some(CertKey::Rsa { der, bits }) => PublicKey::Rsa { der, bits },
        Some(CertKey::Ec { curve, point }) => PublicKey::Ec { curve, point },
        None => {
            return TimestampStatus::Unsupported(Unsupported::KeyAlgorithm(cert.key_alg.clone()));
        }
    };
    match crypto::verify(scheme, key, &signer.signed_attrs, signer.signature) {
        Verified::Valid => {}
        Verified::Invalid => return TimestampStatus::SignatureInvalid,
        Verified::Unsupported(why) => return TimestampStatus::Unsupported(why),
    }
    let cert_der = certs.get(cert_index).map(Vec::as_slice).unwrap_or_default();
    for ess in &signer.signing_certs {
        if let Err(status) = check_digest(&ess.alg, ess.hash, cert_der) {
            return match status {
                TimestampStatus::ImprintMismatch => TimestampStatus::SigningCertificateMismatch,
                other => other,
            };
        }
    }

    let chain = match build_chain_within(certs, cert_index, tsa, checks) {
        Ok(chain) => chain,
        Err(e) => return TimestampStatus::Malformed(TimestampError::SignerCertificate(e)),
    };
    info.tsa_cert = chain.leaf_cert().cloned();
    let status = judge_tsa(info, &chain, warnings);
    info.tsa_chain = Some(chain);
    status
}

/// The TSA chain checks: anchored with no basic-constraint relaxation, Time
/// Stamping EKU, key usage, and the time inside every certificate's
/// validity.
fn judge_tsa(
    info: &TimestampInfo,
    chain: &ChainReport,
    warnings: &mut Warnings,
) -> TimestampStatus {
    if !chain.full_chain.anchored {
        return TimestampStatus::UntrustedTsa;
    }
    if !chain.basic_constraints_ignored.is_empty() {
        return TimestampStatus::TsaBasicConstraintsRelaxed;
    }
    let time_stamping = eku::TIME_STAMPING.id();
    if !chain.chain_has_eku(&time_stamping) {
        return TimestampStatus::MissingTimeStampingEku;
    }
    let leaf = chain.leaf_cert();
    if leaf
        .and_then(|c| c.extended_key_usage.as_ref())
        .is_some_and(|list| list.len() > 1)
    {
        warnings.push(TimestampWarning::TsaEkuNotSole);
    }
    if leaf
        .and_then(|c| c.key_usage)
        .is_some_and(|ku| !ku.contains(KeyUsage::DIGITAL_SIGNATURE))
    {
        return TimestampStatus::TsaKeyUsage;
    }
    let (Some(earliest), Some(latest)) = (info.earliest(), info.latest()) else {
        return TimestampStatus::TsaNotValidAtTime;
    };
    if chain
        .full_chain_certs()
        .any(|c| earliest < c.not_before || latest > c.not_after)
    {
        return TimestampStatus::TsaNotValidAtTime;
    }
    TimestampStatus::Valid
}

/// Parses an RFC 3161 token: a `ContentInfo` holding a SignedData over a
/// `TSTInfo`.
fn parse_token<'a>(der: &'a [u8], warnings: &mut Warnings) -> Result<Token<'a>> {
    let content_info = asn1::single(der, 0, tag::SEQUENCE)?;
    let mut ci = content_info.reader();
    let content_type = read_oid(&mut ci)?;
    if content_type != oid::SIGNED_DATA {
        return Err(TimestampError::NotSignedData(ObjectId::from_der(
            content_type,
        )));
    }
    let explicit = ci.read(tag::context_cons(0))?;
    ci.finish()?;
    let sd = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
    let mut r = sd.reader();
    read_small_uint(&mut r)?;
    let digest_algorithms = r.read(tag::SET)?;
    let mut d = digest_algorithms.reader();
    while !d.is_empty() {
        // Each identifier must be well formed; which ones are listed does
        // not matter, because the SignerInfo names its own digest.
        let _listed = pkcs7::parse_digest_alg(&d.read(tag::SEQUENCE)?)?;
    }

    let encap = r.read(tag::SEQUENCE)?;
    let mut e = encap.reader();
    let econtent_type = read_oid(&mut e)?;
    if econtent_type != oid::TST_INFO {
        return Err(TimestampError::NotTstInfo(ObjectId::from_der(
            econtent_type,
        )));
    }
    let content = e
        .read_optional(tag::context_cons(0))?
        .ok_or(TimestampError::MissingContent)?;
    e.finish()?;
    let octets = asn1::single(content.content, content.content_offset, tag::OCTET_STRING)?;
    let tst = parse_tst_info(octets.content, octets.content_offset, warnings)?;

    let mut certificates = Vec::new();
    if let Some(set) = r.read_optional(tag::context_cons(0))? {
        let mut certs = set.reader();
        while !certs.is_empty() {
            let choice = certs.read_any()?;
            asn1::validate(&choice)?;
            if choice.tag != tag::SEQUENCE {
                warnings.push(TimestampWarning::NonX509Certificate);
            } else if certificates.len() < MAX_TOKEN_CERTIFICATES {
                certificates.push(choice.raw);
            } else {
                warnings.push(TimestampWarning::TooManyCertificates);
            }
        }
    }
    if let Some(crls) = r.read_optional(tag::context_cons(1))? {
        asn1::validate(&crls)?;
    }
    let signer_infos = r.read(tag::SET)?;
    r.finish()?;
    let mut infos = signer_infos.reader();
    let mut count = 0_usize;
    let mut first = None;
    while !infos.is_empty() {
        let info = infos.read_any()?;
        count = count.saturating_add(1);
        if first.is_none() {
            first = Some(info);
        }
    }
    let signer = match (count, first) {
        (1, Some(info)) => parse_ts_signer(&info, warnings)?,
        _ => return Err(TimestampError::SignerCount(count)),
    };
    Ok(Token {
        tst,
        tst_der: octets.content,
        certificates,
        signer,
    })
}

/// `TSTInfo` (RFC 3161, 2.4.2).
fn parse_tst_info<'a>(der: &'a [u8], base: usize, warnings: &mut Warnings) -> Result<TstInfo<'a>> {
    let seq = asn1::single(der, base, tag::SEQUENCE)?;
    let mut r = seq.reader();
    let version = read_small_uint(&mut r)?;
    if version != 1 {
        return Err(TimestampError::UnsupportedVersion(version));
    }
    let policy = read_oid(&mut r)?;
    let imprint = r.read(tag::SEQUENCE)?;
    let mut m = imprint.reader();
    let imprint_alg = pkcs7::parse_digest_alg(&m.read(tag::SEQUENCE)?)?;
    let hashed = m.read(tag::OCTET_STRING)?.content;
    m.finish()?;
    if let Ok(alg) = imprint_alg
        && hashed.len() != alg.digest_len()
    {
        return Err(TimestampError::DigestLength);
    }
    let serial = asn1::integer_bytes(&r.read(tag::INTEGER)?)?;
    let gen_time = match r.read_any()? {
        t if t.tag == tag::GENERALIZED_TIME => t,
        _ => return Err(TimestampError::NotGeneralizedTime),
    };
    let time = asn1::time(&gen_time)?;
    let fraction = u64::from(gen_time.content.contains(&b'.'));
    let mut accuracy_secs = 0_u64;
    if let Some(accuracy) = r.read_optional(tag::SEQUENCE)? {
        accuracy_secs = parse_accuracy(&accuracy)?;
    }
    accuracy_secs = accuracy_secs.saturating_add(fraction);
    if let Some(ordering) = r.read_optional(tag::BOOLEAN)? {
        // `ordering BOOLEAN DEFAULT FALSE`: DER omits FALSE.
        if !asn1::boolean(&ordering)? {
            return Err(ordering.error(asn1::Asn1ErrorKind::InvalidValue).into());
        }
    }
    if let Some(nonce) = r.read_optional(tag::INTEGER)? {
        asn1::integer_bytes(&nonce)?;
    }
    let mut tsa_name = None;
    if let Some(tsa) = r.read_optional(tag::context_cons(0))? {
        let mut t = tsa.reader();
        let name = t.read_any()?;
        t.finish()?;
        asn1::validate(&name)?;
        if name.tag == tag::context_cons(4) {
            let dn = asn1::single(name.content, name.content_offset, tag::SEQUENCE)?;
            let parsed = x509::parse_name(&dn).map_err(TimestampError::TsaName)?;
            tsa_name = Some(parsed.canonical);
        } else if name.tag & 0xc0 == 0x80
            && name.tag & 0x1f <= 8
            && name.tag != tag::context_prim(4)
        {
            // Another GeneralName choice ([0] to [8], but never a primitive
            // [4]: directoryName is explicitly tagged): valid, not reported.
            warnings.push(TimestampWarning::TsaNameNotDirectory);
        } else {
            return Err(name
                .error(asn1::Asn1ErrorKind::UnexpectedTag {
                    expected: tag::context_cons(4),
                    found: name.tag,
                })
                .into());
        }
    }
    if let Some(extensions) = r.read_optional(tag::context_cons(1))? {
        let mut l = extensions.reader();
        if l.is_empty() {
            return Err(extensions.error(asn1::Asn1ErrorKind::InvalidValue).into());
        }
        let mut seen = std::collections::HashSet::new();
        while !l.is_empty() {
            let ext = l.read(tag::SEQUENCE)?;
            let mut x = ext.reader();
            let id = read_oid(&mut x)?;
            let critical = match x.read_optional(tag::BOOLEAN)? {
                Some(flag) if asn1::boolean(&flag)? => true,
                Some(flag) => return Err(flag.error(asn1::Asn1ErrorKind::InvalidValue).into()),
                None => false,
            };
            asn1::validate(&x.read(tag::OCTET_STRING)?)?;
            x.finish()?;
            if !seen.insert(id) {
                return Err(TimestampError::DuplicateExtension(ObjectId::from_der(id)));
            }
            if critical {
                return Err(TimestampError::CriticalExtension(ObjectId::from_der(id)));
            }
        }
    }
    r.finish()?;
    Ok(TstInfo {
        policy,
        imprint_alg,
        imprint: hashed,
        serial,
        time,
        accuracy_secs,
        tsa_name,
    })
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER
/// (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`, rounded up
/// to whole seconds.
fn parse_accuracy(accuracy: &Tlv<'_>) -> Result<u64> {
    let mut r = accuracy.reader();
    let seconds = match r.read_optional(tag::INTEGER)? {
        Some(s) => u64::from(asn1::small_uint(&s)?),
        None => 0,
    };
    let mut fraction = false;
    for field in [tag::context_prim(0), tag::context_prim(1)] {
        if let Some(part) = r.read_optional(field)? {
            if !(1..=999).contains(&asn1::small_uint(&part)?) {
                return Err(TimestampError::BadAccuracy);
            }
            fraction = true;
        }
    }
    r.finish()?;
    Ok(seconds.saturating_add(u64::from(fraction)))
}

/// A timestamp's SignerInfo: the countersignature itself, or the token's
/// only SignerInfo.
fn parse_ts_signer<'a>(info: &Tlv<'a>, warnings: &mut Warnings) -> Result<TsSigner<'a>> {
    let mut r = info.expect(tag::SEQUENCE)?.reader();
    let version = read_small_uint(&mut r)?;
    let sid = pkcs7::parse_sid(&mut r)?;
    if version != pkcs7::sid_version(&sid) {
        warnings.push(TimestampWarning::SignerVersionMismatch(version));
    }
    let digest_alg = pkcs7::parse_digest_alg(&r.read(tag::SEQUENCE)?)?;
    let attrs = r
        .read_optional(tag::context_cons(0))?
        .ok_or(TimestampError::MissingAuthenticatedAttributes)?;
    let sig_alg_id = r.read(tag::SEQUENCE)?;
    let signature = r.read(tag::OCTET_STRING)?.content;
    if let Some(unsigned) = r.read_optional(tag::context_cons(1))? {
        asn1::validate(&unsigned)?;
    }
    r.finish()?;
    let sig_alg = pkcs7::parse_signature_alg(&sig_alg_id, &digest_alg)?;

    let mut signed_attrs = attrs.raw.to_vec();
    if let Some(first) = signed_attrs.first_mut() {
        *first = tag::SET;
    }
    let mut content_type = None;
    let mut message_digest = None;
    let mut signing_time = None;
    let mut ess_v1 = None;
    let mut ess_v2 = None;
    let mut a = attrs.reader();
    while !a.is_empty() {
        let (attr_type, values) = pkcs7::read_attribute(&mut a)?;
        let duplicate = || TimestampError::DuplicateAttribute(ObjectId::from_der(attr_type));
        match attr_type {
            oid::CONTENT_TYPE => {
                let value = pkcs7::single_value(attr_type, &values)?;
                if content_type.replace(asn1::oid_bytes(&value)?).is_some() {
                    return Err(duplicate());
                }
            }
            oid::MESSAGE_DIGEST => {
                let value = pkcs7::single_value(attr_type, &values)?.expect(tag::OCTET_STRING)?;
                if message_digest.replace(value.content).is_some() {
                    return Err(duplicate());
                }
            }
            oid::SIGNING_TIME => {
                let value = pkcs7::single_value(attr_type, &values)?;
                if signing_time.replace(asn1::time(&value)?).is_some() {
                    return Err(duplicate());
                }
            }
            oid::SIGNING_CERTIFICATE | oid::SIGNING_CERTIFICATE_V2 => {
                let value = pkcs7::single_value(attr_type, &values)?;
                let v2 = attr_type == oid::SIGNING_CERTIFICATE_V2;
                // A token may carry both forms (RFC 5816); each binds the
                // certificate, so both are checked.
                let parsed = parse_signing_certificate(&value, v2)?;
                let slot = if v2 { &mut ess_v2 } else { &mut ess_v1 };
                if slot.replace(parsed).is_some() {
                    return Err(duplicate());
                }
            }
            other => {
                asn1::validate(&values)?;
                warnings.push(TimestampWarning::UnknownAttribute(ObjectId::from_der(
                    other,
                )));
            }
        }
    }
    Ok(TsSigner {
        sid,
        digest_alg,
        signed_attrs,
        content_type,
        message_digest,
        signing_time,
        signing_certs: ess_v1.into_iter().chain(ess_v2).collect(),
        sig_alg,
        signature,
    })
}

/// `SigningCertificate ::= SEQUENCE { certs SEQUENCE OF ESSCertID,
/// policies OPTIONAL }` (RFC 2634), or `SigningCertificateV2` (RFC 5035)
/// with `ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash,
/// issuerSerial OPTIONAL }`. Returns the first entry.
fn parse_signing_certificate<'a>(value: &Tlv<'a>, v2: bool) -> Result<EssCertId<'a>> {
    let mut r = value.expect(tag::SEQUENCE)?.reader();
    let certs = r.read(tag::SEQUENCE)?;
    if let Some(policies) = r.read_optional(tag::SEQUENCE)? {
        asn1::validate(&policies)?;
    }
    r.finish()?;
    let mut c = certs.reader();
    let first = c.read(tag::SEQUENCE)?;
    while !c.is_empty() {
        asn1::validate(&c.read(tag::SEQUENCE)?)?;
    }
    let mut f = first.reader();
    let alg = if v2 {
        match f.read_optional(tag::SEQUENCE)? {
            Some(id) => pkcs7::parse_digest_alg(&id)?,
            None => Ok(DigestAlgorithm::Sha256),
        }
    } else {
        Ok(DigestAlgorithm::Sha1)
    };
    let hash = f.read(tag::OCTET_STRING)?.content;
    if let Some(issuer_serial) = f.read_optional(tag::SEQUENCE)? {
        asn1::validate(&issuer_serial)?;
    }
    f.finish()?;
    Ok(EssCertId { alg, hash })
}

/// Parses one timestamp attribute value without verifying it, for the fuzz
/// target and tests: returns the stated time.
#[doc(hidden)]
pub fn parse_timestamp_time(kind: TimestampKind, der: &[u8]) -> Option<i64> {
    let mut warnings = Warnings::default();
    match kind {
        TimestampKind::Rfc3161 => parse_token(der, &mut warnings).ok().map(|t| t.tst.time),
        TimestampKind::CounterSignature => asn1::single(der, 0, tag::SEQUENCE)
            .ok()
            .and_then(|info| parse_ts_signer(&info, &mut warnings).ok())
            .and_then(|s| s.signing_time),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = asn1::header(tag, content.len());
        out.extend_from_slice(content);
        out
    }

    fn accuracy(content: &[u8]) -> Result<u64> {
        let der = tlv(tag::SEQUENCE, content);
        let seq = asn1::single(&der, 0, tag::SEQUENCE)?;
        parse_accuracy(&seq)
    }

    #[test]
    fn accuracy_rounds_up_and_checks_ranges() {
        assert_eq!(accuracy(&[]).unwrap(), 0);
        assert_eq!(accuracy(&[0x02, 0x01, 0x05]).unwrap(), 5);
        assert_eq!(
            accuracy(&[0x02, 0x01, 0x01, 0x80, 0x02, 0x01, 0xf4]).unwrap(),
            2
        );
        assert_eq!(accuracy(&[0x81, 0x01, 0x64]).unwrap(), 1);
        assert_eq!(
            accuracy(&[0x80, 0x02, 0x03, 0xe8]).unwrap_err(),
            TimestampError::BadAccuracy
        );
        assert_eq!(
            accuracy(&[0x81, 0x01, 0x00]).unwrap_err(),
            TimestampError::BadAccuracy
        );
        assert!(accuracy(&[0x80, 0x00]).is_err());
        // Out of order.
        assert!(accuracy(&[0x80, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err());
    }

    /// A `TSTInfo` with `tail` after `genTime`.
    fn tst(tail: &[u8]) -> Vec<u8> {
        let sha256 = tlv(
            tag::SEQUENCE,
            &tlv(
                tag::OID,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            ),
        );
        let imprint = tlv(
            tag::SEQUENCE,
            &[sha256, tlv(tag::OCTET_STRING, &[0; 32])].concat(),
        );
        let body = [
            tlv(tag::INTEGER, &[1]),
            tlv(tag::OID, &[0x2a, 0x03]),
            imprint,
            tlv(tag::INTEGER, &[7]),
            tlv(tag::GENERALIZED_TIME, b"20210101000000Z"),
            tail.to_vec(),
        ]
        .concat();
        tlv(tag::SEQUENCE, &body)
    }

    fn parse_tst(tail: &[u8]) -> (Result<i64>, Vec<TimestampWarning>) {
        let der = tst(tail);
        let mut warnings = Warnings::default();
        let r = parse_tst_info(&der, 0, &mut warnings).map(|t| t.time);
        (r, warnings.0)
    }

    #[test]
    fn tst_info_tsa_names_and_extensions() {
        let (r, w) = parse_tst(&[]);
        assert_eq!(r.unwrap(), 1_609_459_200);
        assert!(w.is_empty());
        // A directory name is reported; a DNS name only warns.
        let dn = tlv(
            tag::SEQUENCE,
            &tlv(
                tag::SET,
                &tlv(
                    tag::SEQUENCE,
                    &[tlv(tag::OID, &[0x55, 0x04, 0x03]), tlv(0x0c, b"TSA")].concat(),
                ),
            ),
        );
        let der = tst(&tlv(tag::context_cons(0), &tlv(tag::context_cons(4), &dn)));
        let mut warnings = Warnings::default();
        assert_eq!(
            parse_tst_info(&der, 0, &mut warnings)
                .unwrap()
                .tsa_name
                .as_deref(),
            Some("CN=TSA")
        );
        let (r, w) = parse_tst(&tlv(
            tag::context_cons(0),
            &tlv(tag::context_prim(2), b"tsa.test"),
        ));
        assert!(r.is_ok());
        assert_eq!(w, vec![TimestampWarning::TsaNameNotDirectory]);
        // Not a GeneralName at all, or a primitive directoryName.
        let (r, _) = parse_tst(&tlv(tag::context_cons(0), &tlv(tag::OCTET_STRING, b"x")));
        assert!(r.is_err());
        let (r, _) = parse_tst(&tlv(tag::context_cons(0), &tlv(tag::context_prim(4), b"x")));
        assert!(r.is_err());
        // Extensions: empty, duplicate, critical.
        let ext = |critical: bool| {
            let mut body = tlv(tag::OID, &[0x2a, 0x04]);
            if critical {
                body.extend(tlv(tag::BOOLEAN, &[0xff]));
            }
            body.extend(tlv(tag::OCTET_STRING, &[0x05, 0x00]));
            tlv(tag::SEQUENCE, &body)
        };
        assert!(parse_tst(&tlv(tag::context_cons(1), &ext(false))).0.is_ok());
        assert!(parse_tst(&tlv(tag::context_cons(1), &[])).0.is_err());
        assert_eq!(
            parse_tst(&tlv(
                tag::context_cons(1),
                &[ext(false), ext(false)].concat()
            ))
            .0
            .unwrap_err(),
            TimestampError::DuplicateExtension(ObjectId::from_der(&[0x2a, 0x04]))
        );
        assert!(matches!(
            parse_tst(&tlv(tag::context_cons(1), &ext(true)))
                .0
                .unwrap_err(),
            TimestampError::CriticalExtension(_)
        ));
    }

    fn ess_attr(oid: &[u8], hash: &[u8]) -> Vec<u8> {
        let ess_id = tlv(tag::SEQUENCE, &tlv(tag::OCTET_STRING, hash));
        let value = tlv(tag::SEQUENCE, &tlv(tag::SEQUENCE, &ess_id));
        tlv(
            tag::SEQUENCE,
            &[tlv(tag::OID, oid), tlv(tag::SET, &value)].concat(),
        )
    }

    /// A SignerInfo (not validly signed) with these authenticated
    /// attributes.
    fn signer_info(attrs: &[Vec<u8>]) -> Vec<u8> {
        let sha256 = tlv(
            tag::SEQUENCE,
            &tlv(
                tag::OID,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            ),
        );
        let rsa = tlv(
            tag::SEQUENCE,
            &[
                tlv(
                    tag::OID,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                ),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let body = [
            tlv(tag::INTEGER, &[3]),
            tlv(tag::context_prim(0), &[1, 2, 3]),
            sha256,
            tlv(tag::context_cons(0), &attrs.concat()),
            rsa,
            tlv(tag::OCTET_STRING, &[0; 4]),
        ]
        .concat();
        tlv(tag::SEQUENCE, &body)
    }

    fn signer(attrs: &[Vec<u8>]) -> Result<usize> {
        let der = signer_info(attrs);
        let info = asn1::single(&der, 0, tag::SEQUENCE)?;
        parse_ts_signer(&info, &mut Warnings::default()).map(|s| s.signing_certs.len())
    }

    #[test]
    fn both_ess_attributes_are_kept_and_duplicates_rejected() {
        let v1 = ess_attr(oid::SIGNING_CERTIFICATE, &[1; 20]);
        let v2 = ess_attr(oid::SIGNING_CERTIFICATE_V2, &[2; 32]);
        assert_eq!(signer(std::slice::from_ref(&v1)).unwrap(), 1);
        assert_eq!(signer(&[v1.clone(), v2.clone()]).unwrap(), 2);
        assert_eq!(
            signer(&[v1.clone(), v1]).unwrap_err(),
            TimestampError::DuplicateAttribute(ObjectId::from_der(oid::SIGNING_CERTIFICATE))
        );
        assert!(signer(&[v2.clone(), v2]).is_err());
    }

    #[test]
    fn a_tsa_chain_that_needs_a_relaxed_issuer_is_never_trusted() {
        use super::super::chain::{CertificatePin, TrustConfig, build_chain};
        let fixture = |n: &str| {
            std::fs::read(format!(
                "{}/tests/fixtures/chain/{n}.der",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        };
        let certs = vec![
            fixture("leaf-under-not-ca"),
            fixture("inter-not-ca"),
            fixture("root"),
        ];
        let mut config = TrustConfig::new();
        config.add_anchor("root", &fixture("root")).unwrap();
        // A configuration relaxed for code signing, shared with TSAs.
        let inter = super::super::x509::CertSummary::from_der(&certs[1]).unwrap();
        config.ignore_basic_constraints(CertificatePin::Sha256Thumbprint(inter.sha256_thumbprint));
        let chain = build_chain(&certs, 0, &config).unwrap();
        assert!(chain.full_chain.anchored);
        assert_eq!(chain.basic_constraints_ignored, [1]);
        let mut info = blank(0, TimestampKind::Rfc3161);
        info.time = Some(1_900_000_000);
        let mut warnings = Warnings::default();
        assert_eq!(
            judge_tsa(&info, &chain, &mut warnings),
            TimestampStatus::TsaBasicConstraintsRelaxed
        );
    }

    #[test]
    fn earliest_and_latest_saturate() {
        let mut info = blank(0, TimestampKind::Rfc3161);
        assert_eq!((info.earliest(), info.latest()), (None, None));
        info.time = Some(100);
        info.accuracy_secs = 5;
        assert_eq!((info.earliest(), info.latest()), (Some(95), Some(105)));
        info.time = Some(i64::MAX);
        info.accuracy_secs = u64::MAX;
        assert_eq!(info.latest(), Some(i64::MAX));
        assert_eq!(info.earliest(), Some(0));
    }

    #[test]
    fn digest_checks_fail_closed() {
        assert_eq!(
            check_digest(&Ok(DigestAlgorithm::Md5), &[0; 16], b"x"),
            Err(TimestampStatus::WeakAlgorithm(DigestAlgorithm::Md5))
        );
        assert_eq!(
            check_digest(&Ok(DigestAlgorithm::Md2), &[0; 16], b"x"),
            Err(TimestampStatus::WeakAlgorithm(DigestAlgorithm::Md2))
        );
        assert_eq!(
            check_digest(&Ok(DigestAlgorithm::Sha256), &[0; 32], b"x"),
            Err(TimestampStatus::ImprintMismatch)
        );
        let unknown = ObjectId::from_der(&[0x2a, 0x03]);
        assert_eq!(
            check_digest(&Err(unknown.clone()), &[0; 32], b"x"),
            Err(TimestampStatus::Unsupported(Unsupported::UnknownDigest(
                unknown
            )))
        );
    }

    #[test]
    fn budget_counts_tokens() {
        let mut budget = TimestampBudget::for_file();
        for _ in 0..MAX_FILE_TIMESTAMPS {
            assert!(budget.take_token());
        }
        assert!(!budget.take_token());
    }
}
