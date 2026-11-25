//! Revocation data for signature validity (#50).
//!
//! This crate does no I/O. Revocation information is **data the caller
//! supplies** in a [`RevocationSet`]:
//!
//! - **offline entries shipped in policy** (#6): revoked certificates by
//!   SHA-256 thumbprint, by TBS hash or by issuer and serial number, revoked
//!   file hashes, and the OS vendor's disallowed-certificate list when an
//!   administrator imports it (as thumbprint entries);
//! - **CRLs** the agent or server has fetched or cached (#4, #126), parsed
//!   here by [`Crl::from_der`] and checked against the certificates of each
//!   chain. A CRL is used only when its signature verifies with the key of
//!   the certificate it claims to come from (the issuer of the certificate
//!   being checked, found by name and key identifier on that chain), and
//!   only for the certificates that issuer issued.
//! - **OCSP responses** fetched or cached the same way, parsed by
//!   [`OcspResponse::from_der`] (`ocsp.rs`). A response is used only for a
//!   certificate its `CertID` names under that certificate's issuer on the
//!   chain, and only when the issuer, or a responder the issuer delegated
//!   to, signed it.
//!
//! [`super::evaluate_validity`] decides what an entry means for a
//! signature, including the timestamp rule: a certificate revoked after a
//! signature's trusted signing time is still good for that signature
//! (unless the reason is `keyCompromise` and policy says to be strict).
//!
//! Fetching CRLs and OCSP responses, the response cache and the
//! `revocation_mode` network settings are the agent's and server's job;
//! this module only records which mode the caller ran in, so a missing
//! answer can be judged (`revocation_failure`), and judges what they
//! fetched.
//!
//! # Untrusted input
//!
//! A CRL is attacker-reachable (it is fetched from a URL a certificate
//! names), so [`Crl::from_der`] reads it with the strict DER reader, keeps
//! at most [`MAX_CRL_ENTRIES`] entries, rejects a CRL larger than
//! [`MAX_CRL_SIZE`] and never panics. A fuzz target covers it.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::Serialize;

use super::asn1::{self, Asn1Error, Asn1ErrorKind, ObjectId, oid, read_oid, tag};
use super::crypto::Verified;
use super::ocsp::{OcspCertStatus, OcspResponse, Signer};
use super::signature::SignatureAlgorithm;
use super::x509::{self, CertSummary, DistinguishedName, KeyUsage};
use crate::hash::Digest;

/// The largest CRL [`Crl::from_der`] reads: 8 MiB.
pub const MAX_CRL_SIZE: usize = 8 * 1024 * 1024;
/// The most revoked-certificate entries kept from one CRL. A CRL with more
/// is rejected rather than read in part, so a truncated list can never
/// make a revoked certificate look good.
pub const MAX_CRL_ENTRIES: usize = 100_000;
/// The most CRLs a [`RevocationSet`] holds.
pub const MAX_CRLS: usize = 256;
/// The most CRL and OCSP signatures verified for one file by
/// [`super::evaluate_validity`]. Each CRL check hashes a whole CRL (up to
/// [`MAX_CRL_SIZE`]), so it is bounded like every other check; an OCSP
/// response costs the checks it needs, at most
/// [`OcspResponse::max_checks`]. A certificate whose
/// CRLs or OCSP responses could not all be checked has the state
/// [`CertRevocation::NotChecked`], which fails closed.
pub const MAX_CRL_CHECKS: usize = 32;
/// The most OCSP responses a [`RevocationSet`] holds.
pub const MAX_OCSP_RESPONSES: usize = 256;

/// Why a CRL was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CrlError {
    /// The DER encoding is invalid.
    Asn1(Asn1Error),
    /// The CRL is larger than [`MAX_CRL_SIZE`].
    TooLarge(usize),
    /// The CRL has more than [`MAX_CRL_ENTRIES`] entries.
    TooManyEntries,
    /// The version is not v1 or v2.
    UnsupportedVersion(u32),
    /// The outer `signatureAlgorithm` differs from the one in `tbsCertList`.
    SignatureAlgorithmMismatch,
    /// An algorithm identifier is invalid.
    AlgorithmParameters,
    /// A field the CRL's version does not allow (extensions in a v1 CRL).
    FieldNotAllowed,
    /// The issuer name could not be read.
    BadName,
    /// The `reasonCode` value is not a defined reason.
    BadReason(u32),
    /// A CRL or entry extension appears twice.
    DuplicateExtension(ObjectId),
    /// A critical CRL or entry extension that this module does not process
    /// (an issuing distribution point, a delta indicator, a certificate
    /// issuer, and so on). Such a CRL is not used at all (RFC 5280, 5.2,
    /// 5.3).
    UnhandledCriticalExtension(ObjectId),
}

impl fmt::Display for CrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(e) => write!(f, "invalid DER: {e}"),
            Self::TooLarge(n) => write!(f, "CRL of {n} bytes is larger than {MAX_CRL_SIZE}"),
            Self::TooManyEntries => write!(f, "more than {MAX_CRL_ENTRIES} CRL entries"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported CRL version {v}"),
            Self::SignatureAlgorithmMismatch => {
                f.write_str("signatureAlgorithm differs from the tbsCertList signature field")
            }
            Self::AlgorithmParameters => f.write_str("invalid algorithm parameters"),
            Self::FieldNotAllowed => f.write_str("extensions in a v1 CRL"),
            Self::BadName => f.write_str("invalid issuer name"),
            Self::BadReason(r) => write!(f, "undefined revocation reason {r}"),
            Self::DuplicateExtension(o) => write!(f, "extension {o} appears twice"),
            Self::UnhandledCriticalExtension(o) => {
                write!(f, "unprocessed critical CRL extension {o}")
            }
        }
    }
}

impl std::error::Error for CrlError {}

impl From<Asn1Error> for CrlError {
    fn from(e: Asn1Error) -> Self {
        Self::Asn1(e)
    }
}

/// A revocation reason (RFC 5280, 5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// 0, or no reason given.
    Unspecified,
    /// 1: the private key was compromised. A signature made before the
    /// revocation date can still be forged, so policy may treat it as bad
    /// whatever the timestamp says (`strict_key_compromise`).
    KeyCompromise,
    /// 2: a CA key was compromised.
    CaCompromise,
    /// 3: the subject's affiliation changed.
    AffiliationChanged,
    /// 4: the certificate was superseded.
    Superseded,
    /// 5: the subject ceased operation.
    CessationOfOperation,
    /// 6: the certificate is on hold.
    CertificateHold,
    /// 8: removed from a CRL (delta CRLs only).
    RemoveFromCrl,
    /// 9: a privilege was withdrawn.
    PrivilegeWithdrawn,
    /// 10: an attribute authority was compromised.
    AaCompromise,
}

impl RevocationReason {
    /// The reason for `code`, if it is a defined one (7 is unused).
    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        Some(match code {
            0 => Self::Unspecified,
            1 => Self::KeyCompromise,
            2 => Self::CaCompromise,
            3 => Self::AffiliationChanged,
            4 => Self::Superseded,
            5 => Self::CessationOfOperation,
            6 => Self::CertificateHold,
            8 => Self::RemoveFromCrl,
            9 => Self::PrivilegeWithdrawn,
            10 => Self::AaCompromise,
            _ => return None,
        })
    }

    /// Whether a signature made before the revocation date may have been
    /// forged with the compromised key: `keyCompromise`, or a CA or
    /// attribute authority compromise.
    #[must_use]
    pub const fn is_compromise(self) -> bool {
        matches!(
            self,
            Self::KeyCompromise | Self::CaCompromise | Self::AaCompromise
        )
    }
}

/// How an offline entry names a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateMatch {
    /// The SHA-256 thumbprint of the whole certificate, lowercase hex.
    Sha256Thumbprint(String),
    /// A TBS hash, lowercase hex: under the certificate's own signature
    /// digest ([`CertSummary::tbs_hash`]) or SHA-256
    /// ([`CertSummary::tbs_hash_sha256`]). This is the form OS-native
    /// policies use, and it covers every certificate re-issued from the
    /// same TBS.
    TbsHash(String),
    /// The issuer name (DER) and the serial number (lowercase hex of the
    /// INTEGER content octets, as [`CertSummary::serial`] gives it).
    IssuerSerial {
        /// The issuer `Name`, DER-encoded.
        #[serde(serialize_with = "serialize_hex")]
        issuer: Vec<u8>,
        /// The serial, lowercase hex.
        serial: String,
    },
}

fn serialize_hex<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&x509::hex(bytes))
}

impl CertificateMatch {
    /// Whether this names `cert`. Hex is compared ignoring case, since OS
    /// tooling often prints it in uppercase.
    #[must_use]
    pub fn matches(&self, cert: &CertSummary) -> bool {
        match self {
            Self::Sha256Thumbprint(t) => cert.sha256_thumbprint.eq_ignore_ascii_case(t),
            Self::TbsHash(h) => tbs_matches(cert, h),
            Self::IssuerSerial { issuer, serial } => {
                cert.issuer.der == *issuer && cert.serial.eq_ignore_ascii_case(serial)
            }
        }
    }
}

/// Whether `hash` (hex, any case) is `cert`'s TBS hash under its own
/// digest or SHA-256.
pub(crate) fn tbs_matches(cert: &CertSummary, hash: &str) -> bool {
    cert.tbs_hash
        .as_deref()
        .is_some_and(|own| own.eq_ignore_ascii_case(hash))
        || cert.tbs_hash_sha256.eq_ignore_ascii_case(hash)
}

/// Where a revocation entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RevocationSource {
    /// An offline entry shipped in policy content.
    Policy,
    /// The OS vendor's disallowed-certificate list, imported by an
    /// administrator.
    OsDisallowedList,
    /// A CRL, by its index in [`RevocationSet::crls`].
    Crl(usize),
    /// An OCSP response, by its index in [`RevocationSet::ocsp_responses`].
    Ocsp(usize),
}

/// An offline certificate revocation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevokedCertificate {
    /// Which certificate.
    pub cert: CertificateMatch,
    /// When it was revoked, in seconds since the Unix epoch. `None` means
    /// "always": no signature by it is good, whatever its time.
    pub revoked_at: Option<i64>,
    /// Why.
    pub reason: RevocationReason,
    /// Where the entry came from.
    pub source: RevocationSource,
}

/// How the caller obtained revocation information: the
/// `revocation_mode` setting it ran under. Fetching is not done here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMode {
    /// Nothing was fetched: only offline policy entries (and any CRLs
    /// shipped with them) are consulted. The agent default.
    #[default]
    Off,
    /// The caller supplied CRLs from its cache, without fetching.
    CacheOnly,
    /// The caller fetched CRLs online where it could.
    Online,
    /// As `Online`, and an answer is required for every certificate that
    /// names a CRL distribution point or OCSP responder.
    OnlineRequired,
}

/// What happens when a revocation answer that was looked for could not be
/// obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFailure {
    /// The signature is judged without the answer, and a warning is
    /// recorded (the default).
    #[default]
    FailOpen,
    /// The signature fails with
    /// [`palisade_core::VerificationError::RevocationUnavailable`].
    FailClosed,
}

/// Every piece of revocation information the caller has: offline entries
/// from policy, revoked file hashes, and parsed CRLs.
#[derive(Debug, Clone, Default)]
pub struct RevocationSet {
    certificates: Vec<RevokedCertificate>,
    file_hashes: Vec<Digest>,
    crls: Vec<Crl>,
    ocsp: Vec<OcspResponse>,
    /// The mode the caller fetched under.
    pub mode: RevocationMode,
    /// What to do when an answer is missing.
    pub failure: RevocationFailure,
    /// CRL distribution point and OCSP URLs whose fetch the caller
    /// attempted and could not complete. A certificate that names one of
    /// these has an unknown status.
    pub unavailable_urls: Vec<String>,
}

/// What revocation data says about a certificate apart from any entry that
/// names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Nothing more was needed, or a current CRL from its issuer, or a
    /// current `good` OCSP response its issuer authorised, covers it.
    Good,
    /// An answer was looked for and is missing.
    Unknown,
    /// A CRL or OCSP response that may cover it was not checked
    /// ([`MAX_CRL_CHECKS`]).
    NotChecked,
}

impl CertRevocation {
    /// The matching entries (empty unless revoked) and the coverage.
    #[must_use]
    pub fn parts(&self) -> (&[RevokedCertificate], Coverage) {
        match self {
            Self::Good => (&[], Coverage::Good),
            Self::Unknown => (&[], Coverage::Unknown),
            Self::NotChecked => (&[], Coverage::NotChecked),
            Self::Revoked { entries, coverage } => (entries, *coverage),
        }
    }
}

/// A certificate's revocation state, as the set knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertRevocation {
    /// No entry names it, and either nothing more was needed or a current
    /// CRL from its issuer covers it.
    Good,
    /// Entries name it: every matching offline and CRL entry, so policy can
    /// judge each (a later `keyCompromise` must not hide behind an earlier
    /// `superseded`). `coverage` is what the state would be without them:
    /// when policy excuses every entry (all dated after the trusted signing
    /// time), the certificate is still judged on it, so an excused entry can
    /// never hide a CRL that was not checked or an answer that is missing.
    Revoked {
        /// The matching entries.
        entries: Vec<RevokedCertificate>,
        /// The state apart from these entries.
        coverage: Coverage,
    },
    /// The caller looked for an answer and could not get one, or
    /// [`RevocationMode::OnlineRequired`] needs one and there is none.
    Unknown,
    /// A CRL that may cover it was not checked, because
    /// [`MAX_CRL_CHECKS`] CRL signatures were already verified for this
    /// file. Always a failure (fails closed).
    NotChecked,
}

impl RevocationSet {
    /// An empty set: nothing is revoked, and no online answers were sought.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an offline certificate entry.
    pub fn add_certificate(&mut self, entry: RevokedCertificate) {
        self.certificates.push(entry);
    }

    /// Adds a revoked file hash.
    pub fn add_file_hash(&mut self, digest: Digest) {
        self.file_hashes.push(digest);
    }

    /// Adds a CRL. Returns its index, or `None` if the set already holds
    /// [`MAX_CRLS`].
    pub fn add_crl(&mut self, crl: Crl) -> Option<usize> {
        if self.crls.len() >= MAX_CRLS {
            return None;
        }
        self.crls.push(crl);
        Some(self.crls.len() - 1)
    }

    /// The offline certificate entries.
    #[must_use]
    pub fn certificates(&self) -> &[RevokedCertificate] {
        &self.certificates
    }

    /// The revoked file hashes.
    #[must_use]
    pub fn file_hashes(&self) -> &[Digest] {
        &self.file_hashes
    }

    /// The CRLs.
    #[must_use]
    pub fn crls(&self) -> &[Crl] {
        &self.crls
    }

    /// Adds an OCSP response. Returns its index, or `None` if the set
    /// already holds [`MAX_OCSP_RESPONSES`].
    pub fn add_ocsp(&mut self, response: OcspResponse) -> Option<usize> {
        if self.ocsp.len() >= MAX_OCSP_RESPONSES {
            return None;
        }
        self.ocsp.push(response);
        Some(self.ocsp.len() - 1)
    }

    /// The OCSP responses.
    #[must_use]
    pub fn ocsp_responses(&self) -> &[OcspResponse] {
        &self.ocsp
    }

    /// Whether a file with these digests is revoked by hash. Each listed
    /// digest is compared with the file's digest of the same algorithm.
    #[must_use]
    pub fn file_revoked(&self, digests: &[Digest]) -> Option<&Digest> {
        self.file_hashes.iter().find(|revoked| {
            digests
                .iter()
                .any(|d| d.algorithm() == revoked.algorithm() && d.as_bytes() == revoked.as_bytes())
        })
    }

    /// The revocation state of `chain[index]` at time `now`, where `chain`
    /// is a full chain leaf first, each certificate issued by the next (as
    /// [`super::ChainReport::full_chain_certs`] gives it). Offline entries
    /// are checked first, then CRLs whose signature verifies with the key of
    /// `chain[index + 1]`, then OCSP responses that name the certificate
    /// under that issuer and that it, or a responder it delegated to,
    /// signed. A delegated responder must have been valid at `producedAt`
    /// and must not be named by an offline entry; its `good` answers count
    /// only while it is still valid. An entry in any such CRL, or a
    /// `revoked` OCSP answer, counts, however old; but only a CRL or an
    /// OCSP answer (`good` or `revoked`) current at `now` (`thisUpdate <=
    /// now <= nextUpdate`, with `nextUpdate` present) is an answer that
    /// covers the certificate. At most
    /// [`MAX_CRL_CHECKS`] CRL and OCSP signatures are verified per call.
    #[must_use]
    pub fn state_of(&self, chain: &[&CertSummary], index: usize, now: i64) -> CertRevocation {
        self.check(chain, index, now, &mut CrlCache::new())
    }

    /// [`Self::state_of`], sharing CRL signature checks across calls.
    pub(crate) fn check(
        &self,
        chain: &[&CertSummary],
        index: usize,
        now: i64,
        crl_cache: &mut CrlCache,
    ) -> CertRevocation {
        let Some(cert) = chain.get(index) else {
            return CertRevocation::Good;
        };
        let mut found: Vec<RevokedCertificate> = self
            .certificates
            .iter()
            .filter(|e| e.cert.matches(cert))
            .cloned()
            .collect();
        let mut covered = false;
        let mut not_checked = false;
        if let Some(issuer) = chain.get(index + 1).copied() {
            for (crl_index, crl) in self.crls.iter().enumerate() {
                match crl_cache.issued_by(crl_index, crl, issuer) {
                    Issued::No => continue,
                    Issued::NotChecked => {
                        not_checked = true;
                        continue;
                    }
                    Issued::Yes => {}
                }
                covered |= crl.is_current(now);
                for entry in crl.entries_for(&cert.serial) {
                    found.push(RevokedCertificate {
                        cert: CertificateMatch::IssuerSerial {
                            issuer: cert.issuer.der.clone(),
                            serial: cert.serial.clone(),
                        },
                        revoked_at: Some(entry.effective_date()),
                        reason: entry.reason,
                        source: RevocationSource::Crl(crl_index),
                    });
                }
            }
            for (index, response) in self.ocsp.iter().enumerate() {
                // Only a response that names this certificate is worth a
                // signature check.
                let mut singles = response.responses_for(cert, issuer).peekable();
                if singles.peek().is_none() {
                    continue;
                }
                // A responder that offline entries revoke vouches for
                // nothing.
                let revoked = |r: &CertSummary| self.certificates.iter().any(|e| e.cert.matches(r));
                let signer = match crl_cache.ocsp_by(index, response, issuer, &revoked) {
                    Signer::None => continue,
                    Signer::NotChecked => {
                        not_checked = true;
                        continue;
                    }
                    signer => signer,
                };
                for single in singles.filter(|a| signer.vouches(a, now)) {
                    // A current answer, `good` or `revoked`, is an answer:
                    // coverage, like a current CRL. Only a stale one, or
                    // `unknown`, leaves the question open.
                    if single.status != OcspCertStatus::Unknown {
                        covered |= single.is_current(now);
                    }
                    match single.status {
                        OcspCertStatus::Good => {}
                        OcspCertStatus::Revoked { at, reason } => found.push(RevokedCertificate {
                            cert: CertificateMatch::IssuerSerial {
                                issuer: cert.issuer.der.clone(),
                                serial: cert.serial.clone(),
                            },
                            revoked_at: Some(at),
                            reason,
                            source: RevocationSource::Ocsp(index),
                        }),
                        OcspCertStatus::Unknown => {}
                    }
                }
            }
        }
        let names_unavailable = cert
            .crl_distribution_points
            .iter()
            .chain(cert.ocsp_urls.iter())
            .any(|url| self.unavailable_urls.iter().any(|u| u == url));
        let needs_answer = self.mode == RevocationMode::OnlineRequired
            && (!cert.crl_distribution_points.is_empty() || !cert.ocsp_urls.is_empty());
        let coverage = if not_checked {
            Coverage::NotChecked
        } else if covered || !(names_unavailable || needs_answer) {
            Coverage::Good
        } else {
            Coverage::Unknown
        };
        match (found.is_empty(), coverage) {
            (false, coverage) => CertRevocation::Revoked {
                entries: found,
                coverage,
            },
            (true, Coverage::Good) => CertRevocation::Good,
            (true, Coverage::Unknown) => CertRevocation::Unknown,
            (true, Coverage::NotChecked) => CertRevocation::NotChecked,
        }
    }
}

/// Whether a CRL was issued by a certificate.
enum Issued {
    Yes,
    No,
    /// It might have been, but the check budget ran out.
    NotChecked,
}

/// Which CRLs verify with which issuer key, so each CRL signature is
/// checked at most once per issuer key, and at most [`MAX_CRL_CHECKS`]
/// times in all.
#[derive(Debug)]
pub(crate) struct CrlCache {
    verified: HashMap<(usize, String), bool>,
    ocsp_verified: HashMap<(usize, String), Signer>,
    checks_left: usize,
}

impl CrlCache {
    /// A cache with the full budget.
    pub(crate) fn new() -> Self {
        Self {
            verified: HashMap::new(),
            ocsp_verified: HashMap::new(),
            checks_left: MAX_CRL_CHECKS,
        }
    }

    /// Whether `crl` was issued by `issuer`: its issuer name matches the
    /// issuer's subject, its authority key identifier (if any) matches the
    /// issuer's subject key identifier (if any), the issuer may sign CRLs,
    /// and the CRL's signature verifies with the issuer's key.
    fn issued_by(&mut self, index: usize, crl: &Crl, issuer: &CertSummary) -> Issued {
        if crl.issuer.der != issuer.subject.der {
            return Issued::No;
        }
        if let (Some(aki), Some(ski)) = (&crl.authority_key_id, &issuer.subject_key_id) {
            if aki != ski {
                return Issued::No;
            }
        }
        if issuer
            .key_usage
            .is_some_and(|ku| !ku.contains(KeyUsage::CRL_SIGN))
        {
            return Issued::No;
        }
        let key = (index, issuer.spki_sha256.clone());
        let verified = match self.verified.get(&key) {
            Some(v) => *v,
            None if self.checks_left == 0 => return Issued::NotChecked,
            None => {
                self.checks_left -= 1;
                let v = crl.verify_with(issuer) == Verified::Valid;
                self.verified.insert(key, v);
                v
            }
        };
        if verified { Issued::Yes } else { Issued::No }
    }

    /// Who signed `response`, for `issuer` ([`OcspResponse::signer_for`]),
    /// cached per issuer certificate (its SHA-256 thumbprint: the answer
    /// depends on its name as well as its key), and charged the signature
    /// checks actually made from the same budget as CRLs. A check cut short
    /// by the budget is not cached.
    fn ocsp_by(
        &mut self,
        index: usize,
        response: &OcspResponse,
        issuer: &CertSummary,
        revoked: &dyn Fn(&CertSummary) -> bool,
    ) -> Signer {
        let key = (index, issuer.sha256_thumbprint.clone());
        if let Some(signer) = self.ocsp_verified.get(&key) {
            return *signer;
        }
        let signer = response.signer_for(issuer, revoked, &mut self.checks_left);
        if signer != Signer::NotChecked {
            self.ocsp_verified.insert(key, signer);
        }
        signer
    }
}

/// One revoked certificate in a CRL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrlEntry {
    /// The serial number, lowercase hex of the INTEGER content octets.
    pub serial: String,
    /// `revocationDate`, in seconds since the Unix epoch.
    pub revocation_date: i64,
    /// `reasonCode`, or `Unspecified` when absent. Every reason revokes,
    /// including `certificateHold` and `removeFromCRL` (which only a delta
    /// CRL may use, and delta CRLs are rejected): failing closed.
    pub reason: RevocationReason,
    /// `invalidityDate`, when given: when the key is known or suspected to
    /// have become unusable. Earlier than the revocation date, it is the
    /// date used.
    pub invalidity_date: Option<i64>,
}

impl CrlEntry {
    /// The date that counts: the revocation date, or an earlier invalidity
    /// date, which is when the key stopped being trustworthy.
    #[must_use]
    pub fn effective_date(&self) -> i64 {
        self.invalidity_date
            .map_or(self.revocation_date, |d| d.min(self.revocation_date))
    }
}

/// A parsed X.509 CRL (RFC 5280, 5). Its signature is not checked when it
/// is parsed, only when it is used against an issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Crl {
    /// 1 or 2.
    pub version: u8,
    /// The issuer.
    pub issuer: DistinguishedName,
    /// `thisUpdate`.
    pub this_update: i64,
    /// `nextUpdate`, if present.
    pub next_update: Option<i64>,
    /// The signature algorithm.
    pub sig_alg: SignatureAlgorithm,
    /// The `authorityKeyIdentifier` key ID, lowercase hex.
    pub authority_key_id: Option<String>,
    /// The `cRLNumber`, lowercase hex.
    pub crl_number: Option<String>,
    /// The revoked certificates, in CRL order (see [`Self::entries`]).
    entries: Vec<CrlEntry>,
    /// Serial to entry indices, for lookups.
    #[serde(skip)]
    by_serial: HashMap<String, Vec<usize>>,
    #[serde(skip)]
    tbs: Vec<u8>,
    #[serde(skip)]
    signature: Vec<u8>,
}

impl Crl {
    /// Parses a DER CRL.
    pub fn from_der(der: &[u8]) -> Result<Self, CrlError> {
        if der.len() > MAX_CRL_SIZE {
            return Err(CrlError::TooLarge(der.len()));
        }
        let list = asn1::single(der, 0, tag::SEQUENCE)?;
        let mut c = list.reader();
        let tbs = c.read(tag::SEQUENCE)?;
        let outer_alg = c.read(tag::SEQUENCE)?;
        let signature = asn1::bit_string_octets(&c.read(tag::BIT_STRING)?)?;
        c.finish()?;

        let mut t = tbs.reader();
        let version = if t.peek_tag() == Some(tag::INTEGER) {
            let v = asn1::read_small_uint(&mut t)?;
            // v2 is 1; v1 omits the field (DER never encodes v1 as 0 here
            // because the field is OPTIONAL, not DEFAULT, but RFC 5280
            // requires it absent for v1).
            if v != 1 {
                return Err(CrlError::UnsupportedVersion(v.saturating_add(1)));
            }
            2
        } else {
            1
        };
        let inner_alg = t.read(tag::SEQUENCE)?;
        if inner_alg.raw != outer_alg.raw {
            return Err(CrlError::SignatureAlgorithmMismatch);
        }
        let sig_alg =
            x509::signature_algorithm(&inner_alg).map_err(|_| CrlError::AlgorithmParameters)?;
        let issuer_tlv = t.read(tag::SEQUENCE)?;
        let issuer = x509::parse_name(&issuer_tlv).map_err(|_| CrlError::BadName)?;
        let this_update = asn1::time(&t.read_any()?)?;
        let next_update = match t.peek_tag() {
            Some(tag::UTC_TIME | tag::GENERALIZED_TIME) => Some(asn1::time(&t.read_any()?)?),
            _ => None,
        };
        let mut entries = Vec::new();
        if let Some(revoked) = t.read_optional(tag::SEQUENCE)? {
            let mut r = revoked.reader();
            while !r.is_empty() {
                if entries.len() >= MAX_CRL_ENTRIES {
                    return Err(CrlError::TooManyEntries);
                }
                entries.push(parse_entry(&r.read(tag::SEQUENCE)?, version)?);
            }
        }
        let mut authority_key_id = None;
        let mut crl_number = None;
        if let Some(explicit) = t.read_optional(tag::context_cons(0))? {
            if version != 2 {
                return Err(CrlError::FieldNotAllowed);
            }
            let list = asn1::single(explicit.content, explicit.content_offset, tag::SEQUENCE)?;
            for (id, critical, value) in extensions(&list)? {
                match id {
                    oid::AUTHORITY_KEY_IDENTIFIER => {
                        let seq = asn1::single(value.content, value.content_offset, tag::SEQUENCE)?;
                        let mut a = seq.reader();
                        if let Some(key_id) = a.read_optional(tag::context_prim(0))? {
                            authority_key_id = Some(x509::hex(key_id.content));
                        }
                        while !a.is_empty() {
                            asn1::validate(&a.read_any()?)?;
                        }
                    }
                    oid::CRL_NUMBER => {
                        let n = asn1::single(value.content, value.content_offset, tag::INTEGER)?;
                        crl_number = Some(x509::hex(asn1::integer_bytes(&n)?));
                    }
                    other if critical => {
                        return Err(CrlError::UnhandledCriticalExtension(ObjectId::from_der(
                            other,
                        )));
                    }
                    _ => {}
                }
            }
        }
        t.finish()?;
        let mut by_serial: HashMap<String, Vec<usize>> = HashMap::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            by_serial.entry(entry.serial.clone()).or_default().push(i);
        }
        Ok(Self {
            by_serial,
            version,
            issuer,
            this_update,
            next_update,
            sig_alg,
            authority_key_id,
            crl_number,
            entries,
            tbs: tbs.raw.to_vec(),
            signature: signature.to_vec(),
        })
    }

    /// The revoked certificates, in CRL order. Read-only, so the serial
    /// index cannot drift from them.
    #[must_use]
    pub fn entries(&self) -> &[CrlEntry] {
        &self.entries
    }

    /// Every entry for a certificate serial (hex, any case), in CRL order.
    /// A serial may be listed more than once, with different reasons.
    pub fn entries_for(&self, serial: &str) -> impl Iterator<Item = &CrlEntry> {
        self.by_serial
            .get(&serial.to_ascii_lowercase())
            .into_iter()
            .flatten()
            .filter_map(|i| self.entries.get(*i))
    }

    /// Whether the CRL is current at `now`: `thisUpdate <= now <=
    /// nextUpdate`. A CRL without `nextUpdate` (which RFC 5280, 5.1.2.5,
    /// requires) is never current, so it can revoke but never vouch.
    #[must_use]
    pub fn is_current(&self, now: i64) -> bool {
        self.this_update <= now && self.next_update.is_some_and(|next| now <= next)
    }

    /// Verifies the CRL's signature with `issuer`'s key. Weak digests are
    /// never accepted.
    pub(crate) fn verify_with(&self, issuer: &CertSummary) -> Verified {
        if let Some(d) = x509::signature_digest(&self.sig_alg).filter(|d| d.is_broken()) {
            return Verified::Unsupported(super::signature::Unsupported::WeakAlgorithm(d));
        }
        let Ok(issuer_raw) = x509::split(&issuer.der) else {
            return Verified::Invalid;
        };
        let child = x509::Raw {
            tbs: &self.tbs,
            signature: &self.signature,
            key: None,
        };
        x509::check_signed_by(&child, &self.sig_alg, &issuer_raw, &issuer.public_key_alg)
    }
}

/// One `revokedCertificates` entry.
fn parse_entry(entry: &asn1::Tlv<'_>, version: u8) -> Result<CrlEntry, CrlError> {
    let mut e = entry.reader();
    let serial = x509::hex(asn1::integer_bytes(&e.read(tag::INTEGER)?)?);
    let revocation_date = asn1::time(&e.read_any()?)?;
    let mut reason = RevocationReason::Unspecified;
    let mut invalidity_date = None;
    if let Some(list) = e.read_optional(tag::SEQUENCE)? {
        if version != 2 {
            return Err(CrlError::FieldNotAllowed);
        }
        for (id, critical, value) in extensions(&list)? {
            match id {
                oid::REASON_CODE => {
                    let code = asn1::single(value.content, value.content_offset, tag::ENUMERATED)?;
                    let n = asn1::small_uint(&code)?;
                    reason = RevocationReason::from_code(n).ok_or(CrlError::BadReason(n))?;
                }
                oid::INVALIDITY_DATE => {
                    let t =
                        asn1::single(value.content, value.content_offset, tag::GENERALIZED_TIME)?;
                    invalidity_date = Some(asn1::time(&t)?);
                }
                other if critical => {
                    return Err(CrlError::UnhandledCriticalExtension(ObjectId::from_der(
                        other,
                    )));
                }
                _ => {}
            }
        }
    }
    e.finish()?;
    Ok(CrlEntry {
        serial,
        revocation_date,
        reason,
        invalidity_date,
    })
}

/// One extension: its OID, whether it is critical, and its value.
type Extension<'a> = (&'a [u8], bool, asn1::Tlv<'a>);

/// `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`: each `(id,
/// critical, value OCTET STRING)`, checked for duplicates and DER.
fn extensions<'a>(list: &asn1::Tlv<'a>) -> Result<Vec<Extension<'a>>, CrlError> {
    let mut l = list.reader();
    if l.is_empty() {
        return Err(list.error(Asn1ErrorKind::InvalidValue).into());
    }
    let mut out: Vec<Extension<'a>> = Vec::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
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
            return Err(CrlError::DuplicateExtension(ObjectId::from_der(id)));
        }
        out.push((id, critical, value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_round_trip_and_seven_is_unused() {
        for code in 0..=10 {
            match RevocationReason::from_code(code) {
                Some(_) => assert_ne!(code, 7),
                None => assert_eq!(code, 7),
            }
        }
        assert!(RevocationReason::from_code(11).is_none());
        assert!(RevocationReason::KeyCompromise.is_compromise());
        assert!(!RevocationReason::Superseded.is_compromise());
    }

    #[test]
    fn oversized_crls_are_rejected_before_parsing() {
        let big = vec![0_u8; MAX_CRL_SIZE + 1];
        assert_eq!(
            Crl::from_der(&big).unwrap_err(),
            CrlError::TooLarge(MAX_CRL_SIZE + 1)
        );
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = asn1::header(tag, content.len());
        out.extend_from_slice(content);
        out
    }

    /// A v2 CRL (not validly signed) with these CRL extensions, or, when
    /// `in_entry` is set, with one entry carrying them.
    fn crl_with(extensions: &[Vec<u8>], in_entry: bool) -> Vec<u8> {
        let alg = tlv(
            tag::SEQUENCE,
            &[
                tlv(
                    tag::OID,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
                ),
                vec![0x05, 0x00],
            ]
            .concat(),
        );
        let name = tlv(
            tag::SEQUENCE,
            &tlv(
                tag::SET,
                &tlv(
                    tag::SEQUENCE,
                    &[tlv(tag::OID, &[0x55, 0x04, 0x03]), tlv(0x0c, b"x")].concat(),
                ),
            ),
        );
        let time = tlv(tag::UTC_TIME, b"240101000000Z");
        let list = tlv(tag::SEQUENCE, &extensions.concat());
        let mut tbs = [
            tlv(tag::INTEGER, &[1]),
            alg.clone(),
            name,
            time.clone(),
            time.clone(),
        ]
        .concat();
        if in_entry {
            let entry = tlv(
                tag::SEQUENCE,
                &[tlv(tag::INTEGER, &[0x10]), time, list].concat(),
            );
            tbs.extend(tlv(tag::SEQUENCE, &entry));
        } else {
            tbs.extend(tlv(tag::context_cons(0), &list));
        }
        let tbs = tlv(tag::SEQUENCE, &tbs);
        tlv(
            tag::SEQUENCE,
            &[tbs, alg, tlv(tag::BIT_STRING, &[0, 1, 2])].concat(),
        )
    }

    fn ext(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut body = tlv(tag::OID, id);
        if critical {
            body.extend(tlv(tag::BOOLEAN, &[0xff]));
        }
        body.extend(tlv(tag::OCTET_STRING, value));
        tlv(tag::SEQUENCE, &body)
    }

    #[test]
    fn crl_extension_rules() {
        let number = ext(oid::CRL_NUMBER, false, &tlv(tag::INTEGER, &[1]));
        assert!(Crl::from_der(&crl_with(std::slice::from_ref(&number), false)).is_ok());
        assert_eq!(
            Crl::from_der(&crl_with(&[number.clone(), number], false)).unwrap_err(),
            CrlError::DuplicateExtension(ObjectId::from_der(oid::CRL_NUMBER))
        );
        // A critical issuing distribution point (2.5.29.28): not processed.
        let idp = ext(&[0x55, 0x1d, 0x1c], true, &tlv(tag::SEQUENCE, &[]));
        assert_eq!(
            Crl::from_der(&crl_with(std::slice::from_ref(&idp), false)).unwrap_err(),
            CrlError::UnhandledCriticalExtension(ObjectId::from_der(&[0x55, 0x1d, 0x1c]))
        );
        // Not critical: ignored.
        let idp = ext(&[0x55, 0x1d, 0x1c], false, &tlv(tag::SEQUENCE, &[]));
        assert!(Crl::from_der(&crl_with(&[idp], false)).is_ok());
        // Entry extensions: reason codes, and a critical unknown one.
        let reason = |r: u8| ext(oid::REASON_CODE, false, &tlv(tag::ENUMERATED, &[r]));
        let c = Crl::from_der(&crl_with(&[reason(1)], true)).unwrap();
        assert_eq!(c.entries[0].reason, RevocationReason::KeyCompromise);
        assert_eq!(
            Crl::from_der(&crl_with(&[reason(7)], true)).unwrap_err(),
            CrlError::BadReason(7)
        );
        let cert_issuer = ext(&[0x55, 0x1d, 0x1d], true, &tlv(tag::SEQUENCE, &[]));
        assert!(matches!(
            Crl::from_der(&crl_with(&[cert_issuer], true)).unwrap_err(),
            CrlError::UnhandledCriticalExtension(_)
        ));
        // An explicit FALSE `critical` is not DER.
        let mut body = tlv(tag::OID, oid::CRL_NUMBER);
        body.extend(tlv(tag::BOOLEAN, &[0x00]));
        body.extend(tlv(tag::OCTET_STRING, &tlv(tag::INTEGER, &[1])));
        assert!(Crl::from_der(&crl_with(&[tlv(tag::SEQUENCE, &body)], false)).is_err());
    }

    #[test]
    fn many_extensions_parse_in_linear_time() {
        // 50,000 distinct extension OIDs: a quadratic duplicate scan would
        // take billions of comparisons.
        let many: Vec<Vec<u8>> = (0_u32..50_000)
            .map(|i| {
                let id = [
                    0x2a,
                    0x83,
                    0x80 | ((i >> 14) & 0x7f).to_le_bytes()[0],
                    0x80 | ((i >> 7) & 0x7f).to_le_bytes()[0],
                    (i & 0x7f).to_le_bytes()[0],
                ];
                ext(&id, false, &[0x05, 0x00])
            })
            .collect();
        let start = std::time::Instant::now();
        assert!(Crl::from_der(&crl_with(&many, false)).is_ok());
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_crl_without_next_update_is_never_current() {
        let number = ext(oid::CRL_NUMBER, false, &tlv(tag::INTEGER, &[1]));
        let mut c = Crl::from_der(&crl_with(&[number], false)).unwrap();
        assert!(c.is_current(c.this_update));
        c.next_update = None;
        assert!(!c.is_current(c.this_update));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for data in [
            &[][..],
            &[0x30],
            &[0x30, 0x80],
            &[0x30, 0x00],
            &[0x04, 0x01, 0x00],
        ] {
            assert!(Crl::from_der(data).is_err());
        }
    }
}
