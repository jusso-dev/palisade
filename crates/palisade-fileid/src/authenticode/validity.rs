//! Signature validity: timestamps, expiry, revocation and the
//! verification-error taxonomy (#50).
//!
//! [`evaluate_validity`] takes a file's verified signatures
//! ([`SignatureReport`], #48) and their chains and trust verdicts
//! ([`TrustReport`], #49), and decides for each signature whether it is
//! **valid as of when it was made**. The answer for each is one
//! [`VerificationError`] code from the shared table in `palisade-core`,
//! whose codes 0 to 28 are the OS code integrity ones, plus the evidence
//! behind it.
//!
//! # Signing time
//!
//! Every timestamp is verified ([`super::verify_timestamps`]) against the
//! TSA trust configuration. A timestamp is also not used when it is SHA-1
//! and its time is after [`ValidityPolicy::sha1_timestamp_cutoff`], or
//! when a certificate of its TSA chain is revoked (by the same timing rule
//! as below). The **trusted signing time** is the earliest remaining valid
//! timestamp. Nothing else is: the `signingTime` authenticated attribute is
//! the signer's own claim and never counts.
//!
//! # Expiry
//!
//! The validity periods checked are those of every certificate in the full
//! chain except a configured anchor at its top (an anchor's lifetime is
//! policy's business, #224). "Now" is the later of the caller's clock and
//! its clock floor ([`ValidityContext::clock_floor`]), so setting the clock
//! back can never revive an expired certificate.
//!
//! - With a trusted signing time whose accuracy window lies inside every
//!   period: [`TimeValidity::ValidTimestamped`], even if a certificate has
//!   expired since. A trusted time outside a period is
//!   [`TimeValidity::SignedOutsideValidity`].
//! - Without one: [`TimeValidity::Valid`] while now is inside every period,
//!   otherwise [`TimeValidity::Expired`] or [`TimeValidity::NotYetValid`].
//! - A leaf with the Lifetime Signing EKU is [`TimeValidity::Expired`] once
//!   it has expired, whatever the timestamp says.
//! - [`ExpiryPolicy`] decides what fails: `TimestampAware` (the default)
//!   fails anything but `Valid` and `ValidTimestamped`; `Strict` also fails
//!   a certificate that has expired by now, timestamp or not; `Ignore` never
//!   fails on expiry (the state is still reported).
//! - When the clock is suspect (before the floor), "not yet valid" alone is
//!   not a failure; it is reported as a warning.
//!
//! # Revocation
//!
//! Revocation data comes from the caller ([`RevocationSet`]); nothing here
//! does I/O. Every certificate of the full chain, and of each TSA chain, is
//! checked. A revoked certificate still counts as good for a signature whose
//! trusted signing time (its latest bound) is before the revocation date,
//! when [`ValidityPolicy::revocation_honours_timestamp`] is on, unless the
//! reason is a key, CA or attribute authority compromise and
//! [`ValidityPolicy::strict_key_compromise`] is on. With no trusted signing
//! time, any matching entry revokes: the wall clock is never used to judge a
//! revocation date. A file whose hash is listed is
//! [`VerificationError::RevokedByHash`].
//!
//! # Per-certificate relaxations
//!
//! [`CertificateOptions`] carry an [`ErrorIgnoreFlags`] mask for one
//! certificate, pinned by SHA-256 thumbprint or TBS hash (forms that bind
//! the key; issuer and serial do not, so they cannot pin). When a pinned
//! certificate is on a signature's full chain, the flags relax the matching
//! checks for that signature, and every relaxation actually used is
//! recorded in [`SignatureValidity::relaxed`] for the decision trace (#41).

#![forbid(unsafe_code)]

use palisade_core::VerificationError;
use serde::Serialize;

use super::chain::{CertificatePin, ChainReport, TrustConfig};
use super::eku;
use super::revocation::{
    CertRevocation, Coverage, CrlCache, RevocationFailure, RevocationSet, RevokedCertificate,
};
use super::signature::{
    BadSignature, KeyAlgorithm, SignatureInfo, SignatureReport, SignatureStatus, SigningState,
    Unsupported,
};
use super::timestamp::{TimestampBudget, TimestampInfo, TimestampStatus, verify_timestamps_within};
use super::trust::{
    SignerIdentity, SignerTrust, TrustReport, UntrustedReason, digest_rank, identity,
};
use super::x509::CertSummary;
use crate::hash::Digest;
use crate::pe::version::VersionInfo;

/// What certificate expiry does to a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryPolicy {
    /// Expiry never fails a signature (compatibility mode). The state is
    /// still reported.
    Ignore,
    /// A signature is good while its chain is valid now, or when a trusted
    /// timestamp proves it was made while the chain was valid (the default).
    #[default]
    TimestampAware,
    /// As `TimestampAware`, and a certificate that has expired by now
    /// always fails, timestamp or not.
    Strict,
}

/// A per-certificate relaxation mask, carried on trusted-publisher rules.
///
/// Only flags this module can honour exist. Relaxing basic constraints and
/// time nesting needs chain building to change (#49), so those are not
/// offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize)]
pub struct ErrorIgnoreFlags(pub u8);

impl ErrorIgnoreFlags {
    /// Expiry does not fail the signature.
    pub const IGNORE_EXPIRY: u8 = 0x01;
    /// A revocation state that could not be obtained does not fail the
    /// signature, even when [`RevocationFailure::FailClosed`] is set.
    pub const IGNORE_REVOCATION_UNKNOWN: u8 = 0x02;
    /// A chain that restricts its extended key usage away from code signing,
    /// or a leaf whose key usage lacks `digitalSignature`, does not fail the
    /// signature.
    pub const IGNORE_INVALID_USAGE: u8 = 0x04;
    /// A **complete** chain (one that ends at a self-signed root) that
    /// reaches no configured anchor does not fail the signature. The pinned
    /// certificate must be on the chain, every link of which is still
    /// verified. An incomplete chain still fails: the embedded certificates
    /// are unsigned, so anyone could strip the issuers above the pin to
    /// escape their revocation, usage, expiry and key-size checks.
    pub const ALLOW_UNTRUSTED_ROOT: u8 = 0x08;
    /// Every flag.
    pub const ALL: u8 = 0x0f;

    /// Whether every bit of `flag` is set.
    #[must_use]
    pub const fn contains(self, flag: u8) -> bool {
        self.0 & flag == flag
    }
}

/// One relaxation flag, as recorded in the decision trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IgnoreFlag {
    /// [`ErrorIgnoreFlags::IGNORE_EXPIRY`].
    IgnoreExpiry,
    /// [`ErrorIgnoreFlags::IGNORE_REVOCATION_UNKNOWN`].
    IgnoreRevocationUnknown,
    /// [`ErrorIgnoreFlags::IGNORE_INVALID_USAGE`].
    IgnoreInvalidUsage,
    /// [`ErrorIgnoreFlags::ALLOW_UNTRUSTED_ROOT`].
    AllowUntrustedRoot,
}

impl IgnoreFlag {
    const fn bit(self) -> u8 {
        match self {
            Self::IgnoreExpiry => ErrorIgnoreFlags::IGNORE_EXPIRY,
            Self::IgnoreRevocationUnknown => ErrorIgnoreFlags::IGNORE_REVOCATION_UNKNOWN,
            Self::IgnoreInvalidUsage => ErrorIgnoreFlags::IGNORE_INVALID_USAGE,
            Self::AllowUntrustedRoot => ErrorIgnoreFlags::ALLOW_UNTRUSTED_ROOT,
        }
    }
}

/// Relaxations for one trusted certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificateOptions {
    /// A name for reports and console warnings.
    pub label: String,
    /// Which certificate.
    pub pin: CertificatePin,
    /// What to relax.
    pub flags: ErrorIgnoreFlags,
}

/// The validity settings, from policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidityPolicy {
    /// What expiry does. Default [`ExpiryPolicy::TimestampAware`].
    pub expiry_policy: ExpiryPolicy,
    /// SHA-1 timestamps whose time (latest bound) is after this, in seconds
    /// since the Unix epoch, are not used. `None` (the default) sets no
    /// cutoff.
    pub sha1_timestamp_cutoff: Option<i64>,
    /// The rule-level minimum signing time: a signature passes only if its
    /// trusted signing time (earliest bound) is at or after this. With no
    /// trusted signing time it fails. Default `None`.
    pub sign_time_after: Option<i64>,
    /// A trusted timestamp is required. Default `false`.
    pub requires_countersignature: bool,
    /// A certificate revoked after the trusted signing time is still good
    /// for that signature. Default `true`.
    pub revocation_honours_timestamp: bool,
    /// A key, CA or attribute authority compromise revokes whatever the
    /// timestamp says. Default `true`.
    pub strict_key_compromise: bool,
    /// The smallest RSA key allowed anywhere on the full chain, in bits.
    /// Default `None` (no minimum).
    pub min_rsa_bits: Option<u32>,
    /// The smallest elliptic-curve key allowed, in bits. Default `None`.
    pub min_ec_bits: Option<u32>,
    /// Per-certificate relaxations.
    pub certificate_options: Vec<CertificateOptions>,
}

impl Default for ValidityPolicy {
    fn default() -> Self {
        Self {
            expiry_policy: ExpiryPolicy::TimestampAware,
            sha1_timestamp_cutoff: None,
            sign_time_after: None,
            requires_countersignature: false,
            revocation_honours_timestamp: true,
            strict_key_compromise: true,
            min_rsa_bits: None,
            min_ec_bits: None,
            certificate_options: Vec::new(),
        }
    }
}

/// Everything [`evaluate_validity`] judges against.
#[derive(Debug, Clone, Copy)]
pub struct ValidityContext<'a> {
    /// The current time, in seconds since the Unix epoch, from the caller's
    /// clock (anchored time where the agent has it, ADR 0012).
    pub now: i64,
    /// A lower bound on real time: the latest of the build time of the
    /// policy content, the agent's build time and the stored clock floor.
    /// When `now` is before it the clock is suspect.
    pub clock_floor: Option<i64>,
    /// The validity settings.
    pub policy: &'a ValidityPolicy,
    /// Revocation data.
    pub revocation: &'a RevocationSet,
    /// Anchors for timestamping authorities.
    pub tsa_trust: &'a TrustConfig,
    /// Digests of the file (flat and Authenticode, any algorithms), for
    /// revoked-hash entries.
    pub file_digests: &'a [Digest],
    /// The file's version resource, for the primary signer's identity.
    pub version: Option<&'a VersionInfo>,
}

/// When a signature's chain is valid, as far as time goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeValidity {
    /// No trusted signing time, and every certificate is valid now.
    Valid,
    /// A trusted signing time lies inside every certificate's validity.
    ValidTimestamped,
    /// The trusted signing time lies outside a certificate's validity.
    SignedOutsideValidity,
    /// No trusted signing time, and a certificate has expired; or the leaf
    /// has the Lifetime Signing EKU and has expired; or, under
    /// [`ExpiryPolicy::Strict`], a certificate has expired by now.
    Expired,
    /// No trusted signing time, and a certificate is not valid yet.
    NotYetValid,
}

/// A suppressed failure, for the decision trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelaxedCheck {
    /// The flag used.
    pub flag: IgnoreFlag,
    /// The option it came from: an index into
    /// [`ValidityPolicy::certificate_options`].
    pub option: usize,
    /// The failure it suppressed.
    pub suppressed: VerificationError,
}

/// One certificate's revocation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainRevocation {
    /// Its position on the full chain, leaf first.
    pub position: usize,
    /// Its SHA-256 thumbprint.
    pub sha256_thumbprint: String,
    /// The state.
    pub state: CertRevocation,
    /// Whether the entry counts against this signature, after the
    /// timestamp rule.
    pub effective: bool,
}

/// Something about a signature's validity that does not fail it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidityWarning {
    /// A certificate was revoked, but after the trusted signing time.
    RevokedAfterSigning {
        /// Its position on the full chain.
        position: usize,
    },
    /// A certificate's revocation state could not be obtained, and policy
    /// fails open.
    RevocationUnknown {
        /// Its position on the full chain.
        position: usize,
    },
    /// The chain is not yet valid, but the clock is suspect, so that alone
    /// does not fail the signature.
    NotYetValidClockSuspect,
    /// Expiry did not fail the signature because the expiry policy is
    /// [`ExpiryPolicy::Ignore`].
    ExpiryIgnored,
    /// A timestamp was dropped because it is SHA-1 and after the cutoff.
    Sha1TimestampPastCutoff {
        /// Its index in [`SignatureValidity::timestamps`].
        timestamp: usize,
    },
    /// A TSA certificate's revocation state could not be obtained, and
    /// policy fails open.
    TsaRevocationUnknown {
        /// The timestamp's index.
        timestamp: usize,
    },
}

/// One signature's validity verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureValidity {
    /// The signature: an index into [`SignatureReport::signatures`].
    pub signature: usize,
    /// Every timestamp, verified.
    pub timestamps: Vec<TimestampInfo>,
    /// The timestamp that gives the trusted signing time: an index into
    /// [`Self::timestamps`].
    pub trusted_timestamp: Option<usize>,
    /// The trusted signing time.
    pub signing_time: Option<i64>,
    /// The chain's time validity. `None` when there is no chain (the
    /// signature is not valid, or its signer certificate did not parse).
    pub validity: Option<TimeValidity>,
    /// The leaf has the Lifetime Signing EKU.
    pub lifetime_signing: bool,
    /// The revocation state of every full-chain certificate an entry names
    /// or that has an unknown state.
    pub revocation: Vec<ChainRevocation>,
    /// Failures suppressed by per-certificate options.
    pub relaxed: Vec<RelaxedCheck>,
    /// Every failure, in check order.
    pub failures: Vec<VerificationError>,
    /// The verdict: the first failure, or [`VerificationError::Ok`].
    pub error: VerificationError,
    /// Anything that did not fail the signature.
    pub warnings: Vec<ValidityWarning>,
}

impl SignatureValidity {
    /// Whether the signature passed every check.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.error.is_ok()
    }
}

/// The validity verdict on a file's signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidityReport {
    /// One entry per signature, in [`SignatureReport::signatures`] order.
    pub signatures: Vec<SignatureValidity>,
    /// The primary signature after validity: the first signature that
    /// passed every check, with the strongest digest (SHA-2 beats SHA-1),
    /// as #48 and #49 rank them.
    pub primary: Option<usize>,
    /// The primary signer's identity. It equals
    /// [`TrustReport::identity`] when the trust primary is also valid.
    pub identity: Option<SignerIdentity>,
    /// The file's verdict: `Ok` with a primary; otherwise the first
    /// signature's error; with no signature, `RevokedByHash` for a revoked
    /// hash, `MalformedSignature` when the certificate table could not be
    /// read, and `NotSigned` otherwise.
    pub error: VerificationError,
    /// The time judged against: the later of the clock and the floor.
    pub effective_now: i64,
    /// The clock is before the floor. The agent raises a health event
    /// (#67).
    pub clock_suspect: bool,
    /// The file's hash is on the revoked list.
    pub file_revoked: bool,
}

impl ValidityReport {
    /// The primary signature's entry.
    #[must_use]
    pub fn primary_signature(&self) -> Option<&SignatureValidity> {
        self.primary.and_then(|i| self.signatures.get(i))
    }
}

/// Judges every signature of a file. `report` and `trust` must come from
/// the same file ([`super::verify_pe`] and [`super::evaluate_trust`]).
#[must_use]
pub fn evaluate_validity(
    report: &SignatureReport,
    trust: &TrustReport,
    ctx: &ValidityContext<'_>,
) -> ValidityReport {
    let effective_now = ctx.clock_floor.map_or(ctx.now, |f| f.max(ctx.now));
    let clock_suspect = ctx.clock_floor.is_some_and(|f| ctx.now < f);
    let file_revoked = ctx.revocation.file_revoked(ctx.file_digests).is_some();
    let mut budget = TimestampBudget::for_file();
    let mut crl_cache = CrlCache::new();
    let mut judge = Judge {
        ctx,
        effective_now,
        clock_suspect,
        file_revoked,
        crl_cache: &mut crl_cache,
    };
    let signatures: Vec<SignatureValidity> = report
        .signatures
        .iter()
        .map(|sig| {
            let signer = trust.signers.iter().find(|s| s.signature == sig.index);
            judge.signature(sig, signer, &mut budget)
        })
        .collect();

    let mut best: Option<(usize, u8)> = None;
    for v in signatures.iter().filter(|v| v.is_ok()) {
        let Some(sig) = report.signatures.get(v.signature) else {
            continue;
        };
        let rank = digest_rank(sig.digest_alg).min(digest_rank(sig.signer_digest_alg));
        if best.is_none_or(|(_, b)| rank > b) {
            best = Some((v.signature, rank));
        }
    }
    let primary = best.map(|(i, _)| i);
    let identity = primary.and_then(|p| {
        let signer = trust.signers.iter().find(|s| s.signature == p)?;
        let mut id = identity(
            p,
            signer.chain.as_ref()?,
            signer.os_ci_compatible,
            ctx.version,
        );
        // A package publisher name already checked against this signer
        // (#53) carries over.
        if let Some(t) = trust.identity.as_ref().filter(|t| t.signature == p) {
            id.package_display_name.clone_from(&t.package_display_name);
        }
        Some(id)
    });
    let error = match (primary, signatures.first(), &report.signing_state) {
        (Some(_), _, _) => VerificationError::Ok,
        (None, Some(first), _) => first.error,
        (None, None, _) if file_revoked => VerificationError::RevokedByHash,
        (None, None, SigningState::Invalid(_)) => VerificationError::MalformedSignature,
        (None, None, _) => VerificationError::NotSigned,
    };
    ValidityReport {
        signatures,
        primary,
        identity,
        error,
        effective_now,
        clock_suspect,
        file_revoked,
    }
}

struct Judge<'c, 'a> {
    ctx: &'c ValidityContext<'a>,
    effective_now: i64,
    clock_suspect: bool,
    file_revoked: bool,
    crl_cache: &'c mut CrlCache,
}

/// Collects failures and relaxations for one signature.
struct Verdict<'p> {
    options: &'p [CertificateOptions],
    /// Which options pin a certificate on the full chain.
    pinned: Vec<usize>,
    failures: Vec<VerificationError>,
    relaxed: Vec<RelaxedCheck>,
    warnings: Vec<ValidityWarning>,
}

impl Verdict<'_> {
    fn fail(&mut self, error: VerificationError) {
        if !self.failures.contains(&error) {
            self.failures.push(error);
        }
    }

    /// Fails with `error` unless a pinned option carries `flag`, in which
    /// case the relaxation is recorded instead.
    fn fail_unless(&mut self, error: VerificationError, flag: IgnoreFlag) {
        let option = self.pinned.iter().copied().find(|i| {
            self.options
                .get(*i)
                .is_some_and(|o| o.flags.contains(flag.bit()))
        });
        match option {
            Some(option) => {
                let relaxed = RelaxedCheck {
                    flag,
                    option,
                    suppressed: error,
                };
                if !self.relaxed.contains(&relaxed) {
                    self.relaxed.push(relaxed);
                }
            }
            None => self.fail(error),
        }
    }

    fn warn(&mut self, warning: ValidityWarning) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
}

impl Judge<'_, '_> {
    fn signature(
        &mut self,
        sig: &SignatureInfo,
        signer: Option<&SignerTrust>,
        budget: &mut TimestampBudget,
    ) -> SignatureValidity {
        let policy = self.ctx.policy;
        let chain = signer.and_then(|s| s.chain.as_ref());
        let chain_certs: Vec<&CertSummary> = chain
            .map(|c| c.full_chain_certs().collect())
            .unwrap_or_default();
        let pinned = policy
            .certificate_options
            .iter()
            .enumerate()
            .filter(|(_, o)| chain_certs.iter().any(|c| o.pin.matches(c)))
            .map(|(i, _)| i)
            .collect();
        let mut v = Verdict {
            options: &policy.certificate_options,
            pinned,
            failures: Vec::new(),
            relaxed: Vec::new(),
            warnings: Vec::new(),
        };

        // 1. The file's hash is revoked.
        if self.file_revoked {
            v.fail(VerificationError::RevokedByHash);
        }
        // 2. The signature itself.
        if let Some(e) = status_error(&sig.status) {
            v.fail(e);
        }
        // 3. Trust.
        match signer {
            Some(signer) => self.trust_failures(signer, chain, &mut v),
            // No trust verdict for this signature: `trust` is not this
            // file's. Never valid.
            None => v.fail(VerificationError::Generic),
        }
        if sig.status.is_valid() && chain.is_none() && v.failures.is_empty() {
            // A valid signature with no chain must have a reason on record;
            // fail closed if it does not.
            v.fail(VerificationError::ChainIncomplete);
        }

        // Timestamps, and the trusted signing time.
        let mut timestamps = if sig.status.is_valid() {
            verify_timestamps_within(sig, self.ctx.tsa_trust, budget)
        } else {
            Vec::new()
        };
        let mut sha1_dropped = false;
        for ts in &mut timestamps {
            self.post_check_timestamp(ts, &mut v, &mut sha1_dropped);
        }
        let trusted = timestamps
            .iter()
            .filter(|t| t.valid)
            .min_by_key(|t| t.time.unwrap_or(i64::MAX))
            .map(|t| t.index);
        let trusted_ts = trusted.and_then(|i| timestamps.get(i));
        let signing_time = trusted_ts.and_then(|t| t.time);
        let any_timestamp = !timestamps.is_empty();
        // The code for "needed a trusted time and had none".
        let no_time_code = if sha1_dropped {
            VerificationError::Sha1TimestampPastCutoff
        } else {
            VerificationError::SigningTimeUntrusted
        };

        let mut revocation = Vec::new();
        let mut validity = None;
        let mut lifetime_signing = false;
        if let Some(chain) = chain {
            // 4. Revocation, for chains that can pass: anchored, or with an
            // untrusted root that policy allows. Anything else has already
            // failed, and checking CRLs against keys only the file vouches
            // for would spend the file's CRL budget for nothing.
            let can_pass = chain.full_chain.anchored
                || v.relaxed
                    .iter()
                    .any(|r| r.flag == IgnoreFlag::AllowUntrustedRoot);
            if can_pass {
                let window = trusted_ts.and_then(|t| t.latest());
                self.revocation(&chain_certs, window, &mut revocation, &mut v);
            }
            // 5. Key sizes.
            if policy.min_rsa_bits.is_some() || policy.min_ec_bits.is_some() {
                let ok = chain_certs
                    .iter()
                    .all(|c| match (&c.public_key_alg, c.key_bits) {
                        (KeyAlgorithm::Rsa, Some(bits)) => bits >= policy.min_rsa_bits.unwrap_or(0),
                        (KeyAlgorithm::Ec(_), Some(bits)) => {
                            bits >= policy.min_ec_bits.unwrap_or(0)
                        }
                        _ => false,
                    });
                if !ok {
                    v.fail(VerificationError::KeyTooSmall);
                }
            }
            // 6. Expiry.
            let checked = periods(chain, &chain_certs);
            lifetime_signing = chain.leaf_has_eku(&eku::LIFETIME_SIGNING.id());
            let state = self.time_validity(&checked, trusted_ts, lifetime_signing, chain);
            validity = Some(state);
            self.expiry_failures(state, signing_time, any_timestamp, no_time_code, &mut v);
        }

        // 7. Signing-time constraints, for a signature that verified (any
        // other has already failed, and has no timestamps checked).
        if sig.status.is_valid() {
            if let Some(after) = policy.sign_time_after {
                match trusted_ts.and_then(TimestampInfo::earliest) {
                    Some(earliest) if earliest >= after => {}
                    Some(_) => v.fail(VerificationError::SigningTimeUntrusted),
                    None => v.fail(no_time_code),
                }
            }
            if policy.requires_countersignature && trusted.is_none() {
                v.fail(VerificationError::CountersignatureRequired);
            }
        }

        let error = v.failures.first().copied().unwrap_or(VerificationError::Ok);
        SignatureValidity {
            signature: sig.index,
            timestamps,
            trusted_timestamp: trusted,
            signing_time,
            validity,
            lifetime_signing,
            revocation,
            relaxed: v.relaxed,
            failures: v.failures,
            error,
            warnings: v.warnings,
        }
    }

    fn trust_failures(
        &self,
        signer: &SignerTrust,
        chain: Option<&ChainReport>,
        v: &mut Verdict<'_>,
    ) {
        for reason in &signer.untrusted {
            match reason {
                // Already reported from the signature status.
                UntrustedReason::NotValid => {}
                UntrustedReason::SignerCertificate(_) => {
                    v.fail(VerificationError::MalformedSignature);
                }
                UntrustedReason::NoTrustAnchor => {
                    if chain.is_some_and(|c| c.chain_complete) {
                        v.fail_unless(
                            VerificationError::UntrustedRoot,
                            IgnoreFlag::AllowUntrustedRoot,
                        );
                    } else {
                        // Never relaxed: see `ALLOW_UNTRUSTED_ROOT`.
                        v.fail(VerificationError::ChainIncomplete);
                    }
                }
                UntrustedReason::CodeSigningNotPermitted | UntrustedReason::SignerKeyUsage => {
                    v.fail_unless(
                        VerificationError::MissingRequiredEku,
                        IgnoreFlag::IgnoreInvalidUsage,
                    );
                }
            }
        }
    }

    /// The SHA-1 cutoff and TSA revocation, after a timestamp verified.
    fn post_check_timestamp(
        &mut self,
        ts: &mut TimestampInfo,
        v: &mut Verdict<'_>,
        sha1_dropped: &mut bool,
    ) {
        if !ts.valid {
            return;
        }
        let policy = self.ctx.policy;
        if let (Some(cutoff), Some(latest)) = (policy.sha1_timestamp_cutoff, ts.latest()) {
            if ts.uses_sha1() && latest > cutoff {
                ts.set_status(TimestampStatus::Sha1PastCutoff);
                *sha1_dropped = true;
                v.warn(ValidityWarning::Sha1TimestampPastCutoff {
                    timestamp: ts.index,
                });
                return;
            }
        }
        let Some(chain) = ts.tsa_chain.as_ref() else {
            return;
        };
        let certs: Vec<&CertSummary> = chain.full_chain_certs().collect();
        let latest = ts.latest();
        let mut unknown = false;
        let mut not_checked = false;
        let mut revoked = false;
        for position in 0..certs.len() {
            let state =
                self.ctx
                    .revocation
                    .check(&certs, position, self.effective_now, self.crl_cache);
            let (entries, coverage) = state.parts();
            if self.any_counts(entries, latest) {
                revoked = true;
            }
            match coverage {
                Coverage::Good => {}
                Coverage::Unknown => unknown = true,
                Coverage::NotChecked => not_checked = true,
            }
        }
        if revoked {
            ts.set_status(TimestampStatus::TsaRevoked);
        } else if not_checked {
            // The CRL budget ran out: the timestamp is not used, whatever
            // `revocation_failure` says.
            ts.set_status(TimestampStatus::TsaRevocationUnknown);
        } else if unknown {
            if self.ctx.revocation.failure == RevocationFailure::FailClosed {
                ts.set_status(TimestampStatus::TsaRevocationUnknown);
            } else {
                v.warn(ValidityWarning::TsaRevocationUnknown {
                    timestamp: ts.index,
                });
            }
        }
    }

    /// Whether any of `entries` counts against the signature: each is
    /// judged on its own date and reason, so a compromise entry cannot hide
    /// behind an earlier, milder one.
    fn any_counts(&self, entries: &[RevokedCertificate], latest: Option<i64>) -> bool {
        entries.iter().any(|e| self.counts_against(e, latest))
    }

    /// Whether a revocation entry counts against a signature whose trusted
    /// signing time has `latest` as its latest bound.
    fn counts_against(&self, entry: &RevokedCertificate, latest: Option<i64>) -> bool {
        let policy = self.ctx.policy;
        match (entry.revoked_at, latest) {
            (Some(revoked_at), Some(latest)) => {
                let before = latest < revoked_at;
                let strict = policy.strict_key_compromise && entry.reason.is_compromise();
                !(policy.revocation_honours_timestamp && before && !strict)
            }
            // No date, or no trusted signing time: the entry revokes.
            _ => true,
        }
    }

    fn revocation(
        &mut self,
        certs: &[&CertSummary],
        latest: Option<i64>,
        out: &mut Vec<ChainRevocation>,
        v: &mut Verdict<'_>,
    ) {
        for (position, cert) in certs.iter().enumerate() {
            let state =
                self.ctx
                    .revocation
                    .check(certs, position, self.effective_now, self.crl_cache);
            let (entries, coverage) = state.parts();
            if entries.is_empty() && coverage == Coverage::Good {
                continue;
            }
            // Every entry is judged; if none counts, the certificate is
            // still judged on its coverage.
            let effective = if self.any_counts(entries, latest) {
                v.fail(VerificationError::Revoked);
                true
            } else {
                if !entries.is_empty() {
                    v.warn(ValidityWarning::RevokedAfterSigning { position });
                }
                match coverage {
                    Coverage::Good => false,
                    // The CRL budget ran out: fail closed, never relaxed.
                    Coverage::NotChecked => {
                        v.fail(VerificationError::RevocationUnavailable);
                        true
                    }
                    Coverage::Unknown
                        if self.ctx.revocation.failure == RevocationFailure::FailClosed =>
                    {
                        v.fail_unless(
                            VerificationError::RevocationUnavailable,
                            IgnoreFlag::IgnoreRevocationUnknown,
                        );
                        true
                    }
                    Coverage::Unknown => {
                        v.warn(ValidityWarning::RevocationUnknown { position });
                        false
                    }
                }
            };
            out.push(ChainRevocation {
                position,
                sha256_thumbprint: cert.sha256_thumbprint.clone(),
                state,
                effective,
            });
        }
    }

    fn time_validity(
        &self,
        checked: &[&CertSummary],
        trusted: Option<&TimestampInfo>,
        lifetime_signing: bool,
        chain: &ChainReport,
    ) -> TimeValidity {
        let now = self.effective_now;
        let now_state = now_state(checked, now);
        let mut state = match trusted.and_then(|t| t.earliest().zip(t.latest())) {
            Some((earliest, latest)) => {
                if checked
                    .iter()
                    .all(|c| earliest >= c.not_before && latest <= c.not_after)
                {
                    TimeValidity::ValidTimestamped
                } else {
                    TimeValidity::SignedOutsideValidity
                }
            }
            None => now_state,
        };
        if lifetime_signing && chain.leaf_cert().is_some_and(|leaf| now > leaf.not_after) {
            state = TimeValidity::Expired;
        }
        if self.ctx.policy.expiry_policy == ExpiryPolicy::Strict
            && now_state == TimeValidity::Expired
        {
            state = TimeValidity::Expired;
        }
        state
    }

    fn expiry_failures(
        &self,
        state: TimeValidity,
        signing_time: Option<i64>,
        any_timestamp: bool,
        no_time_code: VerificationError,
        v: &mut Verdict<'_>,
    ) {
        let error = match state {
            TimeValidity::Valid | TimeValidity::ValidTimestamped => return,
            TimeValidity::NotYetValid if self.clock_suspect => {
                v.warn(ValidityWarning::NotYetValidClockSuspect);
                return;
            }
            // The chain needed a trusted time, and the file carries
            // timestamps but none could be used: say why.
            TimeValidity::Expired | TimeValidity::NotYetValid
                if signing_time.is_none() && any_timestamp =>
            {
                no_time_code
            }
            _ => VerificationError::Expired,
        };
        if self.ctx.policy.expiry_policy == ExpiryPolicy::Ignore {
            v.warn(ValidityWarning::ExpiryIgnored);
            return;
        }
        v.fail_unless(error, IgnoreFlag::IgnoreExpiry);
    }
}

/// The certificates whose validity periods are checked: the full chain,
/// without a configured anchor at its top. A leaf is always checked, even
/// when it is itself the anchor (a pinned signer).
fn periods<'c>(chain: &ChainReport, certs: &[&'c CertSummary]) -> Vec<&'c CertSummary> {
    let take = if chain.full_chain.anchored && certs.len() > 1 {
        certs.len().saturating_sub(1)
    } else {
        certs.len()
    };
    certs.iter().take(take).copied().collect()
}

fn now_state(checked: &[&CertSummary], now: i64) -> TimeValidity {
    if checked.iter().any(|c| now > c.not_after) {
        TimeValidity::Expired
    } else if checked.iter().any(|c| now < c.not_before) {
        TimeValidity::NotYetValid
    } else {
        TimeValidity::Valid
    }
}

/// The code for a signature that is not [`SignatureStatus::Valid`].
#[must_use]
pub fn status_error(status: &SignatureStatus) -> Option<VerificationError> {
    Some(match status {
        SignatureStatus::Valid => return None,
        SignatureStatus::DigestMismatch | SignatureStatus::NonConformantImage => {
            VerificationError::InvalidHash
        }
        SignatureStatus::BadSignature(BadSignature::MessageDigestMismatch) => {
            VerificationError::DigestMismatch
        }
        SignatureStatus::BadSignature(BadSignature::SignerCertificateNotFound) => {
            VerificationError::ChainIncomplete
        }
        SignatureStatus::WeakAlgorithm(_)
        | SignatureStatus::Unsupported(Unsupported::WeakAlgorithm(_)) => {
            VerificationError::WeakHashAlgorithm
        }
        SignatureStatus::Unsupported(
            Unsupported::KeyAlgorithm(_)
            | Unsupported::Curve(_)
            | Unsupported::CurveDigest { .. }
            | Unsupported::KeyAlgorithmMismatch
            | Unsupported::RsaKeySize(_),
        ) => VerificationError::UnsupportedKeyAlgorithm,
        SignatureStatus::Malformed(_) => VerificationError::MalformedSignature,
        // A bad signature value, and anything else that could not be
        // verified.
        _ => VerificationError::Generic,
    })
}
