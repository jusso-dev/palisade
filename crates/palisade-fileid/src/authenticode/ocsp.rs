//! OCSP responses as revocation data (#50).
//!
//! Like CRLs, OCSP responses are **data the caller supplies**: the agent or
//! server fetches them (#4, #126), and this module parses and checks them,
//! with no I/O. [`OcspResponse::from_der`] reads an `OCSPResponse` (RFC
//! 6960) strictly, and [`super::RevocationSet::add_ocsp`] adds it to the
//! revocation data [`super::evaluate_validity`] judges with.
//!
//! A response counts for a certificate only when all of these hold:
//!
//! - its status is `successful` and its type is `id-pkix-ocsp-basic`;
//! - a `SingleResponse` names the certificate: its `CertID` hashes (SHA-1
//!   or SHA-256) of the issuer's name and key match the certificate's
//!   issuer on the chain being checked, and its serial is the certificate's;
//! - the response is signed by the issuer itself, or by a **delegated
//!   responder**: a certificate in the response that the issuer issued
//!   (its signature verifies with the issuer's key), whose extended key
//!   usage lists OCSP Signing and whose key usage, if restricted, allows
//!   digital signatures. The responder ID (by name or by key hash) must
//!   name the key that signed.
//!
//! What it shows:
//!
//! - `revoked`: the certificate is revoked from `revocationTime`, with the
//!   reason if given. Like a CRL entry, this counts however old the
//!   response is.
//! - `good`: only while the response is current (`thisUpdate <= now <=
//!   nextUpdate`, with `nextUpdate` present). A stale `good` vouches for
//!   nothing.
//! - `unknown`: nothing; the certificate's coverage is judged as if there
//!   were no response.
//!
//! A response with a critical extension this module does not process, a
//! nonce it cannot check (the caller asked without one, as background
//! fetching does), or more than [`MAX_OCSP_RESPONSES_PER_RESPONSE`]
//! `SingleResponse`s is rejected. At most [`MAX_OCSP_SIZE`] bytes are read.

#![forbid(unsafe_code)]

use std::fmt;

use serde::Serialize;

use super::asn1::{self, Asn1Error, Asn1ErrorKind, ObjectId, Tlv, oid, read_oid, tag};
use super::crypto::Verified;
use super::eku;
use super::revocation::RevocationReason;
use super::signature::{DigestAlgorithm, SignatureAlgorithm};
use super::x509::{self, CertSummary, KeyUsage};
use crate::hash::{AlgorithmSet, HashAlgorithm, hash_bytes};

/// The largest OCSP response [`OcspResponse::from_der`] reads: 1 MiB.
pub const MAX_OCSP_SIZE: usize = 1024 * 1024;
/// The most `SingleResponse`s kept from one response.
pub const MAX_OCSP_RESPONSES_PER_RESPONSE: usize = 256;
/// The most certificates a response may carry for its responder.
pub const MAX_OCSP_CERTIFICATES: usize = 8;

/// 1.3.6.1.5.5.7.48.1.1 `id-pkix-ocsp-basic`.
const OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

/// Why an OCSP response was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OcspError {
    /// The DER encoding is invalid.
    Asn1(Asn1Error),
    /// The response is larger than [`MAX_OCSP_SIZE`].
    TooLarge(usize),
    /// `responseStatus` is not `successful` (0): the responder sent an
    /// error (malformed request, internal error, try later, unauthorised).
    Unsuccessful(u32),
    /// The response type is not `id-pkix-ocsp-basic`.
    UnsupportedType(ObjectId),
    /// The `ResponseData` version is not v1.
    UnsupportedVersion(u32),
    /// An algorithm identifier is invalid.
    AlgorithmParameters,
    /// A `CertID` hash algorithm other than SHA-1 or SHA-256.
    UnsupportedCertIdHash(ObjectId),
    /// A `CertID` hash is not as long as its algorithm's output.
    CertIdHashLength,
    /// The responder's name could not be read.
    BadName,
    /// A `revocationReason` that is not a defined reason.
    BadReason(u32),
    /// More than [`MAX_OCSP_RESPONSES_PER_RESPONSE`] `SingleResponse`s, or
    /// more than [`MAX_OCSP_CERTIFICATES`] certificates.
    TooMany,
    /// A certificate in the response does not parse.
    Certificate,
    /// An extension appears twice.
    DuplicateExtension(ObjectId),
    /// A critical extension this module does not process (a nonce
    /// included: no request nonce is checked here).
    UnhandledCriticalExtension(ObjectId),
}

impl fmt::Display for OcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::TooLarge(n) => write!(
                f,
                "OCSP response of {n} bytes is larger than {MAX_OCSP_SIZE}"
            ),
            Self::Unsuccessful(s) => write!(f, "OCSP response status {s} is not successful"),
            Self::UnsupportedType(o) => write!(f, "OCSP response type {o} is not basic"),
            Self::UnsupportedVersion(v) => write!(f, "OCSP response version {v} is not v1"),
            Self::AlgorithmParameters => f.write_str("invalid algorithm parameters"),
            Self::UnsupportedCertIdHash(o) => {
                write!(f, "CertID hash algorithm {o} is not supported")
            }
            Self::CertIdHashLength => f.write_str("a CertID hash has the wrong length"),
            Self::BadName => f.write_str("invalid responder name"),
            Self::BadReason(r) => write!(f, "undefined revocation reason {r}"),
            Self::TooMany => f.write_str("too many responses or certificates"),
            Self::Certificate => f.write_str("a responder certificate does not parse"),
            Self::DuplicateExtension(o) => write!(f, "extension {o} appears twice"),
            Self::UnhandledCriticalExtension(o) => {
                write!(f, "unprocessed critical OCSP extension {o}")
            }
        }
    }
}

impl std::error::Error for OcspError {}

impl From<Asn1Error> for OcspError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

/// How the response names its signer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponderId {
    /// `byName`: the responder's subject `Name`, DER.
    #[serde(serialize_with = "serialize_hex")]
    ByName(Vec<u8>),
    /// `byKey`: the SHA-1 of the responder's public key (the BIT STRING
    /// contents of its `subjectPublicKey`), hex.
    ByKey(String),
}

fn serialize_hex<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&x509::hex(bytes))
}

/// A certificate's status in one `SingleResponse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OcspCertStatus {
    /// `good`.
    Good,
    /// `revoked`.
    Revoked {
        /// `revocationTime`, in seconds since the Unix epoch.
        at: i64,
        /// `revocationReason`, or `Unspecified`.
        reason: RevocationReason,
    },
    /// `unknown`.
    Unknown,
}

/// One `SingleResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SingleResponse {
    /// The `CertID` hash algorithm: SHA-1 or SHA-256.
    pub hash_alg: DigestAlgorithm,
    /// `issuerNameHash`, hex.
    pub issuer_name_hash: String,
    /// `issuerKeyHash`, hex.
    pub issuer_key_hash: String,
    /// `serialNumber`: lowercase hex of the INTEGER content octets, as
    /// [`CertSummary::serial`] gives it.
    pub serial: String,
    /// The status.
    pub status: OcspCertStatus,
    /// `thisUpdate`.
    pub this_update: i64,
    /// `nextUpdate`, if present.
    pub next_update: Option<i64>,
}

impl SingleResponse {
    /// Whether this names `cert`, issued by `issuer`.
    #[must_use]
    pub fn names(&self, cert: &CertSummary, issuer: &CertSummary) -> bool {
        if !self.serial.eq_ignore_ascii_case(&cert.serial) {
            return false;
        }
        let Some((name, key)) = self
            .hash_alg
            .hash_algorithm()
            .and_then(|alg| cert_id_hashes(issuer, alg))
        else {
            return false;
        };
        name.eq_ignore_ascii_case(&self.issuer_name_hash)
            && key.eq_ignore_ascii_case(&self.issuer_key_hash)
    }

    /// Whether this response is current at `now`: `thisUpdate <= now <=
    /// nextUpdate`. Without `nextUpdate` it is never current, so it can
    /// revoke but never vouch.
    #[must_use]
    pub fn is_current(&self, now: i64) -> bool {
        self.this_update <= now && self.next_update.is_some_and(|next| now <= next)
    }
}

/// The `CertID` hashes of `issuer`: of its subject `Name` (DER) and of its
/// public key (the `subjectPublicKey` BIT STRING contents), under `alg`.
fn cert_id_hashes(issuer: &CertSummary, alg: HashAlgorithm) -> Option<(String, String)> {
    let key = subject_public_key(issuer)?;
    let set = AlgorithmSet::from(alg);
    let name = hash_bytes(&issuer.subject.der, set).get(alg)?.to_string();
    let key = hash_bytes(key, set).get(alg)?.to_string();
    Some((name, key))
}

/// The contents of a certificate's `subjectPublicKey` BIT STRING.
fn subject_public_key(cert: &CertSummary) -> Option<&[u8]> {
    let c = asn1::single(&cert.der, 0, tag::SEQUENCE).ok()?;
    let tbs = c.reader().read(tag::SEQUENCE).ok()?;
    let mut t = tbs.reader();
    if t.peek_tag() == Some(tag::context_cons(0)) {
        t.read_any().ok()?;
    }
    // serial, signature, issuer, validity, subject, then the SPKI.
    for _ in 0..5 {
        t.read_any().ok()?;
    }
    let spki = t.read(tag::SEQUENCE).ok()?;
    let mut s = spki.reader();
    s.read(tag::SEQUENCE).ok()?;
    asn1::bit_string_octets(&s.read(tag::BIT_STRING).ok()?).ok()
}

/// A parsed OCSP response. Its signature is checked only when it is used
/// against an issuer ([`Self::verified_by`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OcspResponse {
    /// Who signed it.
    pub responder: ResponderId,
    /// `producedAt`.
    pub produced_at: i64,
    /// The `SingleResponse`s, in order.
    pub responses: Vec<SingleResponse>,
    /// The signature algorithm.
    pub sig_alg: SignatureAlgorithm,
    /// The certificates the response carries (a delegated responder and
    /// perhaps its chain).
    pub certificates: Vec<CertSummary>,
    #[serde(skip)]
    tbs: Vec<u8>,
    #[serde(skip)]
    signature: Vec<u8>,
}

impl OcspResponse {
    /// Parses a DER `OCSPResponse`.
    pub fn from_der(der: &[u8]) -> Result<Self, OcspError> {
        if der.len() > MAX_OCSP_SIZE {
            return Err(OcspError::TooLarge(der.len()));
        }
        let outer = asn1::single(der, 0, tag::SEQUENCE)?;
        let mut o = outer.reader();
        let status = asn1::small_uint(&o.read(tag::ENUMERATED)?)?;
        if status != 0 {
            return Err(OcspError::Unsuccessful(status));
        }
        let explicit = o
            .read(tag::context_cons(0))
            .map_err(|_| OcspError::Unsuccessful(status))?;
        o.finish()?;
        let bytes = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
        let mut b = bytes.reader();
        let kind = read_oid(&mut b)?;
        if kind != OCSP_BASIC {
            return Err(OcspError::UnsupportedType(ObjectId::from_der(kind)));
        }
        let basic_octets = b.read(tag::OCTET_STRING)?;
        b.finish()?;
        let basic = asn1::single(
            basic_octets.content,
            basic_octets.content_offset,
            tag::SEQUENCE,
        )?;
        parse_basic(&basic)
    }

    /// Whether `issuer`, or a responder `issuer` delegated to, signed the
    /// response. This alone does not say the response is about a
    /// certificate `issuer` issued: [`Self::answers_for`] checks both, and
    /// is what revocation uses. Costs at most [`Self::max_checks`]
    /// signature verifications.
    #[must_use]
    pub fn verified_by(&self, issuer: &CertSummary) -> bool {
        // The issuer signed it.
        if self.names_responder(issuer) && self.signature_valid(issuer) {
            return true;
        }
        // A delegated responder, issued by the issuer.
        self.certificates.iter().any(|r| {
            self.names_responder(r)
                && r.issuer.der == issuer.subject.der
                && r.has_eku(&eku::OCSP_SIGNING.id())
                && r.key_usage
                    .is_none_or(|ku| ku.contains(KeyUsage::DIGITAL_SIGNATURE))
                && r.unhandled_critical_extensions.is_empty()
                && issued_by(r, issuer)
                && self.signature_valid(r)
        })
    }

    /// The most signature verifications [`Self::verified_by`] makes: one
    /// for the issuer, and two (the responder's certificate, then the
    /// response) for each certificate the response carries.
    #[must_use]
    pub fn max_checks(&self) -> usize {
        1 + 2 * self.certificates.len()
    }

    fn names_responder(&self, cert: &CertSummary) -> bool {
        match &self.responder {
            ResponderId::ByName(name) => cert.subject.der == *name,
            ResponderId::ByKey(hash) => subject_public_key(cert)
                .and_then(|k| {
                    hash_bytes(k, AlgorithmSet::SHA1)
                        .get(HashAlgorithm::Sha1)
                        .map(ToString::to_string)
                })
                .is_some_and(|h| h.eq_ignore_ascii_case(hash)),
        }
    }

    fn signature_valid(&self, signer: &CertSummary) -> bool {
        if x509::signature_digest(&self.sig_alg).is_some_and(DigestAlgorithm::is_broken) {
            return false;
        }
        let Ok(signer_raw) = x509::split(&signer.der) else {
            return false;
        };
        let child = x509::Raw {
            tbs: &self.tbs,
            signature: &self.signature,
            key: None,
        };
        x509::check_signed_by(&child, &self.sig_alg, &signer_raw, &signer.public_key_alg)
            == Verified::Valid
    }

    /// The answers this response gives about `cert`, issued by `issuer`:
    /// the `SingleResponse`s whose `CertID` names `cert` under `issuer`,
    /// and only if `issuer` (or a responder it delegated to) signed the
    /// response. Empty otherwise.
    #[must_use]
    pub fn answers_for<'a>(
        &'a self,
        cert: &'a CertSummary,
        issuer: &'a CertSummary,
    ) -> Vec<&'a SingleResponse> {
        let answers: Vec<&SingleResponse> = self.responses_for(cert, issuer).collect();
        if answers.is_empty() || !self.verified_by(issuer) {
            return Vec::new();
        }
        answers
    }

    /// The `SingleResponse`s for `cert`, issued by `issuer`, in order,
    /// whoever signed the response.
    pub fn responses_for<'a>(
        &'a self,
        cert: &'a CertSummary,
        issuer: &'a CertSummary,
    ) -> impl Iterator<Item = &'a SingleResponse> + 'a {
        self.responses.iter().filter(move |r| r.names(cert, issuer))
    }
}

/// Whether `child`'s signature verifies with `issuer`'s key.
fn issued_by(child: &CertSummary, issuer: &CertSummary) -> bool {
    if x509::signature_digest(&child.sig_alg).is_some_and(DigestAlgorithm::is_broken) {
        return false;
    }
    let (Ok(c), Ok(i)) = (x509::split(&child.der), x509::split(&issuer.der)) else {
        return false;
    };
    x509::check_signed_by(&c, &child.sig_alg, &i, &issuer.public_key_alg) == Verified::Valid
}

/// `BasicOCSPResponse ::= SEQUENCE { tbsResponseData, signatureAlgorithm,
/// signature BIT STRING, certs [0] EXPLICIT SEQUENCE OF Certificate
/// OPTIONAL }`.
fn parse_basic(basic: &Tlv<'_>) -> Result<OcspResponse, OcspError> {
    let mut r = basic.reader();
    let tbs = r.read(tag::SEQUENCE)?;
    let sig_alg_tlv = r.read(tag::SEQUENCE)?;
    let sig_alg =
        x509::signature_algorithm(&sig_alg_tlv).map_err(|_| OcspError::AlgorithmParameters)?;
    let signature = asn1::bit_string_octets(&r.read(tag::BIT_STRING)?)?;
    let mut certificates = Vec::new();
    if let Some(explicit) = r.read_optional(tag::context_cons(0))? {
        let list = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
        let mut l = list.reader();
        while !l.is_empty() {
            let cert = l.read(tag::SEQUENCE)?;
            if certificates.len() >= MAX_OCSP_CERTIFICATES {
                return Err(OcspError::TooMany);
            }
            certificates.push(CertSummary::from_der(cert.raw).map_err(|_| OcspError::Certificate)?);
        }
    }
    r.finish()?;

    let mut t = tbs.reader();
    if let Some(version) = t.read_optional(tag::context_cons(0))? {
        // DEFAULT v1: DER omits it, so any explicit version is either not
        // DER (v1) or unknown.
        let v = asn1::single(version.content, version.content_offset, tag::INTEGER)?;
        let n = asn1::small_uint(&v)?;
        if n == 0 {
            return Err(version.error(Asn1ErrorKind::InvalidValue).into());
        }
        return Err(OcspError::UnsupportedVersion(n.saturating_add(1)));
    }
    let responder = match t.peek_tag() {
        Some(t1) if t1 == tag::context_cons(1) => {
            let name_tlv = t.read_any()?;
            let name = asn1::single(name_tlv.content, name_tlv.content_offset, tag::SEQUENCE)?;
            x509::parse_name(&name).map_err(|_| OcspError::BadName)?;
            ResponderId::ByName(name.raw.to_vec())
        }
        Some(t2) if t2 == tag::context_cons(2) => {
            let key_tlv = t.read_any()?;
            let hash = asn1::single(key_tlv.content, key_tlv.content_offset, tag::OCTET_STRING)?;
            if hash.content.len() != 20 {
                return Err(hash.error(Asn1ErrorKind::InvalidValue).into());
            }
            ResponderId::ByKey(x509::hex(hash.content))
        }
        _ => {
            return Err(asn1::err(
                Asn1ErrorKind::Missing {
                    expected: tag::context_cons(1),
                },
                t.offset(),
            )
            .into());
        }
    };
    let produced_at = generalized_time(&t.read(tag::GENERALIZED_TIME)?)?;
    let list = t.read(tag::SEQUENCE)?;
    let mut responses = Vec::new();
    let mut l = list.reader();
    while !l.is_empty() {
        if responses.len() >= MAX_OCSP_RESPONSES_PER_RESPONSE {
            return Err(OcspError::TooMany);
        }
        responses.push(parse_single(&l.read(tag::SEQUENCE)?)?);
    }
    if let Some(explicit) = t.read_optional(tag::context_cons(1))? {
        let exts = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
        check_extensions(&exts)?;
    }
    t.finish()?;
    Ok(OcspResponse {
        responder,
        produced_at,
        responses,
        sig_alg,
        certificates,
        tbs: tbs.raw.to_vec(),
        signature: signature.to_vec(),
    })
}

/// `SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate
/// GeneralizedTime, nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL,
/// singleExtensions [1] EXPLICIT Extensions OPTIONAL }`.
fn parse_single(single: &Tlv<'_>) -> Result<SingleResponse, OcspError> {
    let mut s = single.reader();
    let cert_id = s.read(tag::SEQUENCE)?;
    let mut c = cert_id.reader();
    let alg = c.read(tag::SEQUENCE)?;
    let mut a = alg.reader();
    let alg_oid = read_oid(&mut a)?;
    if !a.is_empty() {
        let p = a.read_any()?;
        if p.tag != tag::NULL || !p.content.is_empty() {
            return Err(OcspError::AlgorithmParameters);
        }
    }
    a.finish()?;
    let hash_alg = match alg_oid {
        oid::SHA1 => DigestAlgorithm::Sha1,
        oid::SHA256 => DigestAlgorithm::Sha256,
        other => return Err(OcspError::UnsupportedCertIdHash(ObjectId::from_der(other))),
    };
    let name_hash = c.read(tag::OCTET_STRING)?.content;
    let key_hash = c.read(tag::OCTET_STRING)?.content;
    let serial = asn1::integer_bytes(&c.read(tag::INTEGER)?)?;
    c.finish()?;
    let len = hash_alg.digest_len();
    if name_hash.len() != len || key_hash.len() != len {
        return Err(OcspError::CertIdHashLength);
    }

    let status_tlv = s.read_any()?;
    let status = match status_tlv.tag {
        t if t == tag::context_prim(0) && status_tlv.content.is_empty() => OcspCertStatus::Good,
        t if t == tag::context_cons(1) => {
            let mut ri = status_tlv.reader();
            let at = generalized_time(&ri.read(tag::GENERALIZED_TIME)?)?;
            let mut reason = RevocationReason::Unspecified;
            if let Some(explicit) = ri.read_optional(tag::context_cons(0))? {
                let code =
                    asn1::single(explicit.content, explicit.content_offset, tag::ENUMERATED)?;
                let n = asn1::small_uint(&code)?;
                reason = RevocationReason::from_code(n).ok_or(OcspError::BadReason(n))?;
            }
            ri.finish()?;
            OcspCertStatus::Revoked { at, reason }
        }
        t if t == tag::context_prim(2) && status_tlv.content.is_empty() => OcspCertStatus::Unknown,
        _ => return Err(status_tlv.error(Asn1ErrorKind::InvalidValue).into()),
    };
    let this_update = generalized_time(&s.read(tag::GENERALIZED_TIME)?)?;
    let next_update = match s.read_optional(tag::context_cons(0))? {
        Some(explicit) => Some(generalized_time(&asn1::single(
            explicit.content,
            explicit.content_offset,
            tag::GENERALIZED_TIME,
        )?)?),
        None => None,
    };
    if let Some(explicit) = s.read_optional(tag::context_cons(1))? {
        let exts = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
        check_extensions(&exts)?;
    }
    s.finish()?;
    Ok(SingleResponse {
        hash_alg,
        issuer_name_hash: x509::hex(name_hash),
        issuer_key_hash: x509::hex(key_hash),
        serial: x509::hex(serial),
        status,
        this_update,
        next_update,
    })
}

/// A GeneralizedTime, which OCSP uses for every time.
fn generalized_time(tlv: &Tlv<'_>) -> Result<i64, OcspError> {
    let tlv = *tlv;
    Ok(asn1::time(&tlv.expect(tag::GENERALIZED_TIME)?)?)
}

/// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`: non-empty, no
/// duplicates, DER, and no critical extension (none is processed). A
/// non-critical nonce (`id-pkix-ocsp-nonce`) is ignored: it binds a
/// response to a request, and background fetching sends none to bind.
fn check_extensions(list: &Tlv<'_>) -> Result<(), OcspError> {
    let mut l = list.reader();
    if l.is_empty() {
        return Err(list.error(Asn1ErrorKind::InvalidValue).into());
    }
    let mut seen = std::collections::HashSet::new();
    while !l.is_empty() {
        let ext = l.read(tag::SEQUENCE)?;
        let mut x = ext.reader();
        let id = read_oid(&mut x)?;
        let critical = match x.read_optional(tag::BOOLEAN)? {
            Some(flag) if asn1::boolean(&flag)? => true,
            Some(flag) => return Err(flag.error(Asn1ErrorKind::InvalidValue).into()),
            None => false,
        };
        let value = x.read(tag::OCTET_STRING)?;
        x.finish()?;
        asn1::validate(&value)?;
        if !seen.insert(id) {
            return Err(OcspError::DuplicateExtension(ObjectId::from_der(id)));
        }
        if critical {
            return Err(OcspError::UnhandledCriticalExtension(ObjectId::from_der(
                id,
            )));
        }
    }
    Ok(())
}
