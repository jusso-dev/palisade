//! Comparing this crate's signature results with the OS trust-verification
//! API (#48).
//!
//! The Windows backend (`palisade_fileid::win::trust`, behind the `os-trust`
//! feature) asks the OS to verify a file's embedded signatures, one call
//! per signature, and records each result code as an [`OsSignatureResult`].
//! [`cross_check`] then pairs every OS result with the signature in a
//! [`SignatureReport`] that the OS looked at, and records whether the two
//! agree. Everything here is pure, so it is tested on every OS.
//!
//! # Never an override
//!
//! The comparison is a **diagnostic**. [`cross_check`] takes the report by
//! shared reference and returns a separate [`CrossCheck`]; nothing in this
//! crate reads a [`CrossCheck`] to change a verdict. Policy decides from the
//! Rust result, and a disagreement is something to log and investigate.
//!
//! # What is compared
//!
//! [`SignatureStatus::Valid`] means the signature is cryptographically
//! sound and signs this file. It does not mean the signer is trusted. The
//! OS result folds chain trust in, so an OS result is reduced to the same
//! question before comparing ([`OsVerdict`]):
//!
//! - success, or a certificate chain or policy failure that the OS reports
//!   only after the file digest and the signature have verified (an
//!   untrusted root, an expired or revoked certificate, a wrong usage), is
//!   **accepted**: the signature is intact;
//! - a digest or signature failure, a missing signer certificate or a
//!   malformed message is **rejected**, and so is "no signature";
//! - any other code is **unclassified**, and its comparison is
//!   [`Outcome::NotComparable`].
//!
//! The OS reads only the first embedded signature (index 0) and the
//! signatures nested directly in it (indexes 1 and up, its "secondary"
//! signatures). Signatures in a later certificate table entry, or nested
//! more deeply, are not compared.
//!
//! This crate is stricter than the OS in places, by design: an image whose
//! layout departs from the Authenticode specification is
//! [`SignatureStatus::NonConformantImage`], and MD5 and MD2 are never
//! valid. Those show up as [`Outcome::OsAcceptsRustRejects`]. The opposite,
//! [`Outcome::RustAcceptsOsRejects`], is the one that could hide a
//! verification bug, and [`CrossCheck::rust_accepts_os_rejects`] picks it
//! out.

#![forbid(unsafe_code)]

use super::signature::{SignatureKind, SignatureReport, SignatureStatus};

/// The most signatures the OS backend asks about for one file: the primary
/// and up to this many minus one secondary signatures. The same bound as
/// [`super::MAX_SIGNATURES`].
pub const MAX_OS_SIGNATURES: u32 = 32;

/// OS result codes ([`OsSignatureResult::code`]) that [`classify`] knows.
/// Each is the 32-bit `HRESULT` the OS trust API returns, as unsigned bits.
pub mod code {
    /// Success: the signature verified and its chain is trusted.
    pub const S_OK: u32 = 0;
    /// `TRUST_E_NOSIGNATURE`: no signature was found.
    pub const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
    /// `TRUST_E_BAD_DIGEST`: the file's digest does not match the one the
    /// signature signs.
    pub const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
    /// `TRUST_E_NO_SIGNER_CERT`: the signer certificate is missing.
    pub const TRUST_E_NO_SIGNER_CERT: u32 = 0x8009_6002;
    /// `TRUST_E_MALFORMED_SIGNATURE`: the signature is malformed.
    pub const TRUST_E_MALFORMED_SIGNATURE: u32 = 0x8009_6011;
    /// `CRYPT_E_HASH_VALUE`: the `messageDigest` attribute does not match.
    pub const CRYPT_E_HASH_VALUE: u32 = 0x8009_1007;
    /// `NTE_BAD_SIGNATURE`: the signature value does not verify.
    pub const NTE_BAD_SIGNATURE: u32 = 0x8009_0006;
    /// `CRYPT_E_BAD_MSG`: the message cannot be decoded.
    pub const CRYPT_E_BAD_MSG: u32 = 0x8009_200D;
    /// The first `CRYPT_E_ASN1_*` code: ASN.1 decoding errors.
    pub const CRYPT_E_ASN1_FIRST: u32 = 0x8009_3100;
    /// The last `CRYPT_E_ASN1_*` code.
    pub const CRYPT_E_ASN1_LAST: u32 = 0x8009_31FF;
    /// `CERT_E_EXPIRED`.
    pub const CERT_E_EXPIRED: u32 = 0x800B_0101;
    /// `CERT_E_VALIDITYPERIODNESTING`.
    pub const CERT_E_VALIDITYPERIODNESTING: u32 = 0x800B_0102;
    /// `CERT_E_PURPOSE`.
    pub const CERT_E_PURPOSE: u32 = 0x800B_0106;
    /// `CERT_E_UNTRUSTEDROOT`: the chain ends in an untrusted root.
    pub const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
    /// `CERT_E_CHAINING`: no chain could be built to a root.
    pub const CERT_E_CHAINING: u32 = 0x800B_010A;
    /// `CERT_E_REVOKED`.
    pub const CERT_E_REVOKED: u32 = 0x800B_010C;
    /// `CERT_E_UNTRUSTEDTESTROOT`.
    pub const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
    /// `CERT_E_REVOCATION_FAILURE`.
    pub const CERT_E_REVOCATION_FAILURE: u32 = 0x800B_010E;
    /// `CERT_E_WRONG_USAGE`.
    pub const CERT_E_WRONG_USAGE: u32 = 0x800B_0110;
    /// `TRUST_E_EXPLICIT_DISTRUST`.
    pub const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
    /// `CERT_E_UNTRUSTEDCA`.
    pub const CERT_E_UNTRUSTEDCA: u32 = 0x800B_0112;
    /// `TRUST_E_CERT_SIGNATURE`: a certificate's signature in the chain does
    /// not verify.
    pub const TRUST_E_CERT_SIGNATURE: u32 = 0x8009_6004;
    /// `TRUST_E_BASIC_CONSTRAINTS`.
    pub const TRUST_E_BASIC_CONSTRAINTS: u32 = 0x8009_6019;
    /// `CRYPT_E_REVOKED`.
    pub const CRYPT_E_REVOKED: u32 = 0x8009_2010;
    /// `CRYPT_E_NO_REVOCATION_CHECK`.
    pub const CRYPT_E_NO_REVOCATION_CHECK: u32 = 0x8009_2012;
    /// `CRYPT_E_REVOCATION_OFFLINE`.
    pub const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
}

/// What an OS result code says about the signature itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsVerdict {
    /// The signature verified and the OS trusts its chain.
    Trusted,
    /// The signature verified, but the OS does not trust its certificate
    /// chain or rejected it on policy (an untrusted root, an expired or
    /// revoked certificate, a wrong usage). The OS checks the file digest
    /// and the signature before the chain, and reports their failures
    /// first, so the signature itself is intact.
    ChainNotTrusted,
    /// The file digest, the `messageDigest` attribute or the signature
    /// value does not verify, the signer certificate is missing, or the
    /// message is malformed.
    Broken,
    /// The OS found no signature.
    NoSignature,
    /// A code this module does not classify.
    Unclassified,
}

impl OsVerdict {
    /// Whether the OS found the signature intact (`Some(true)`), not intact
    /// or absent (`Some(false)`), or the code says neither (`None`).
    #[must_use]
    pub const fn accepts(self) -> Option<bool> {
        match self {
            Self::Trusted | Self::ChainNotTrusted => Some(true),
            Self::Broken | Self::NoSignature => Some(false),
            Self::Unclassified => None,
        }
    }
}

/// Classifies an OS trust-verification result code.
#[must_use]
pub const fn classify(code: u32) -> OsVerdict {
    match code {
        code::S_OK => OsVerdict::Trusted,
        code::TRUST_E_NOSIGNATURE => OsVerdict::NoSignature,
        code::TRUST_E_BAD_DIGEST
        | code::TRUST_E_NO_SIGNER_CERT
        | code::TRUST_E_MALFORMED_SIGNATURE
        | code::CRYPT_E_HASH_VALUE
        | code::NTE_BAD_SIGNATURE
        | code::CRYPT_E_BAD_MSG
        | code::CRYPT_E_ASN1_FIRST..=code::CRYPT_E_ASN1_LAST => OsVerdict::Broken,
        code::CERT_E_EXPIRED
        | code::CERT_E_VALIDITYPERIODNESTING
        | code::CERT_E_PURPOSE
        | code::CERT_E_UNTRUSTEDROOT
        | code::CERT_E_CHAINING
        | code::CERT_E_REVOKED
        | code::CERT_E_UNTRUSTEDTESTROOT
        | code::CERT_E_REVOCATION_FAILURE
        | code::CERT_E_WRONG_USAGE
        | code::TRUST_E_EXPLICIT_DISTRUST
        | code::CERT_E_UNTRUSTEDCA
        | code::TRUST_E_CERT_SIGNATURE
        | code::TRUST_E_BASIC_CONSTRAINTS
        | code::CRYPT_E_REVOKED
        | code::CRYPT_E_NO_REVOCATION_CHECK
        | code::CRYPT_E_REVOCATION_OFFLINE => OsVerdict::ChainNotTrusted,
        _ => OsVerdict::Unclassified,
    }
}

/// The OS result for one signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OsSignatureResult {
    /// The OS signature index: 0 for the primary signature, 1 and up for
    /// the signatures nested directly in it.
    pub index: u32,
    /// The result code, as the unsigned bits of the `HRESULT`.
    pub code: u32,
}

impl OsSignatureResult {
    /// [`classify`] of [`Self::code`].
    #[must_use]
    pub const fn verdict(&self) -> OsVerdict {
        classify(self.code)
    }
}

/// What the OS reported for one file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OsTrustResult {
    /// One result per signature the OS was asked about, by index. Index 0
    /// is always present when the OS was asked at all.
    pub signatures: Vec<OsSignatureResult>,
    /// How many secondary (nested) signatures the OS said the primary has.
    pub secondary_count: u32,
    /// The OS reported more secondary signatures than
    /// [`MAX_OS_SIGNATURES`] allows, so the rest were not asked about.
    pub truncated: bool,
}

/// How one OS result compares with the Rust result for the same signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Both accept the signature, or both reject it (or both find none).
    Agree,
    /// The OS finds the signature intact and this crate does not: expected
    /// for the stricter checks described in the module documentation, and
    /// otherwise worth investigating.
    OsAcceptsRustRejects,
    /// This crate finds the signature valid and the OS does not. This could
    /// hide a verification bug.
    RustAcceptsOsRejects,
    /// The OS reported a signature that has no counterpart in the report.
    OnlyOs,
    /// The report has a signature the OS should have seen, at an index the
    /// OS did not report.
    OnlyRust,
    /// The OS code is unclassified, so nothing can be said.
    NotComparable,
}

/// One compared pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// The OS signature index.
    pub os_index: u32,
    /// The index of the matching signature in
    /// [`SignatureReport::signatures`], if there is one.
    pub signature: Option<usize>,
    /// The Rust status of that signature.
    pub rust_status: Option<SignatureStatus>,
    /// The OS result, if the OS reported this index.
    pub os: Option<OsSignatureResult>,
    /// The outcome.
    pub outcome: Outcome,
}

/// The result of [`cross_check`]. It is a diagnostic only; see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CrossCheck {
    /// One entry per OS signature index that either side has, in index
    /// order.
    pub comparisons: Vec<Comparison>,
    /// The number of secondary signatures in the report (signatures nested
    /// directly in the primary), to compare with
    /// [`OsTrustResult::secondary_count`].
    pub rust_secondary_count: usize,
    /// The OS and the report disagree on how many secondary signatures
    /// there are.
    pub secondary_count_differs: bool,
}

impl CrossCheck {
    /// Whether every comparison agrees (or is not comparable) and the
    /// secondary counts match.
    #[must_use]
    pub fn agrees(&self) -> bool {
        !self.secondary_count_differs
            && self
                .comparisons
                .iter()
                .all(|c| matches!(c.outcome, Outcome::Agree | Outcome::NotComparable))
    }

    /// The comparisons that disagree.
    pub fn disagreements(&self) -> impl Iterator<Item = &Comparison> {
        self.comparisons
            .iter()
            .filter(|c| !matches!(c.outcome, Outcome::Agree | Outcome::NotComparable))
    }

    /// The comparisons where this crate accepts a signature the OS rejects.
    pub fn rust_accepts_os_rejects(&self) -> impl Iterator<Item = &Comparison> {
        self.comparisons
            .iter()
            .filter(|c| c.outcome == Outcome::RustAcceptsOsRejects)
    }
}

/// The signatures of `report` the OS reads, by OS index: the first
/// embedded signature, then the signatures nested directly in it, in
/// order.
fn os_view(report: &SignatureReport) -> Vec<usize> {
    let Some(primary) = report
        .signatures
        .iter()
        .position(|s| s.kind == SignatureKind::Embedded)
    else {
        return Vec::new();
    };
    let mut view = vec![primary];
    view.extend(
        report
            .signatures
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == SignatureKind::Nested && s.parent == Some(primary))
            .map(|(i, _)| i),
    );
    view
}

/// Compares the OS results for a file with the report this crate produced
/// for the same file. The report is not changed.
///
/// OS indexes 0 to [`MAX_OS_SIGNATURES`] minus one are compared; a result
/// at a larger index (which the Windows backend never asks for) is
/// ignored, so a crafted result cannot make the loop long.
#[must_use]
pub fn cross_check(report: &SignatureReport, os: &OsTrustResult) -> CrossCheck {
    let view = os_view(report);
    let rust_secondary_count = view.len().saturating_sub(1);
    let mut out = CrossCheck {
        comparisons: Vec::new(),
        rust_secondary_count,
        secondary_count_differs: false,
    };
    let os_primary = os.signatures.iter().find(|r| r.index == 0);
    // The OS reports "no signature" at index 0 for an unsigned file. Its
    // secondary count is then meaningless.
    let os_unsigned = os_primary.is_some_and(|r| r.verdict() == OsVerdict::NoSignature);
    out.secondary_count_differs = !os_unsigned
        && !os.truncated
        && usize::try_from(os.secondary_count).ok() != Some(rust_secondary_count);

    let os_max = os.signatures.iter().map(|r| r.index).max();
    let rust_max = u32::try_from(view.len())
        .ok()
        .and_then(|n| n.checked_sub(1));
    let Some(last) = os_max.max(rust_max) else {
        return out;
    };
    for os_index in 0..=last.min(MAX_OS_SIGNATURES - 1) {
        let os_result = os.signatures.iter().find(|r| r.index == os_index).copied();
        let signature = usize::try_from(os_index)
            .ok()
            .and_then(|i| view.get(i))
            .copied();
        let rust_status = signature
            .and_then(|i| report.signatures.get(i))
            .map(|s| s.status.clone());
        let outcome = match (&rust_status, os_result) {
            (None, None) => continue,
            (Some(_), None) => Outcome::OnlyRust,
            (None, Some(r)) => match r.verdict().accepts() {
                // An unsigned file, as both see it.
                Some(false) => Outcome::Agree,
                Some(true) => Outcome::OnlyOs,
                None => Outcome::NotComparable,
            },
            (Some(status), Some(r)) => match r.verdict().accepts() {
                None => Outcome::NotComparable,
                Some(os_ok) => match (status.is_valid(), os_ok) {
                    (true, true) | (false, false) => Outcome::Agree,
                    (false, true) => Outcome::OsAcceptsRustRejects,
                    (true, false) => Outcome::RustAcceptsOsRejects,
                },
            },
        };
        out.comparisons.push(Comparison {
            os_index,
            signature,
            rust_status,
            os: os_result,
            outcome,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticode::{
        AuthenticodeStatus, BadSignature, DigestAlgorithm, SignatureCheck, SignatureInfo,
        SigningState,
    };

    fn sig(kind: SignatureKind, parent: Option<usize>, status: SignatureStatus) -> SignatureInfo {
        SignatureInfo {
            index: 0,
            total: 0,
            kind,
            entry: 0,
            parent,
            depth: u8::from(parent.is_some()),
            digest_alg: None,
            signed_image_digest: None,
            signer_digest_alg: None,
            sig_alg: None,
            key_alg: None,
            key_bits: None,
            digest_match: None,
            signature_valid: SignatureCheck::NotChecked,
            status,
            signer: None,
            untrusted_signer_attrs: false,
            signer_id: None,
            certs_in_blob: Vec::new(),
            pe_image_flags: None,
            page_hashes: None,
            timestamp_tokens: Vec::new(),
            signature_value: Vec::new(),
            os_ci_issues: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn report(signatures: Vec<SignatureInfo>) -> SignatureReport {
        SignatureReport {
            entries: Vec::new(),
            signatures,
            primary: None,
            signing_state: SigningState::Unsigned,
            tolerate_digest_mismatch: false,
            image_status: AuthenticodeStatus::Conformant,
            warnings: Vec::new(),
        }
    }

    fn os(codes: &[u32], secondary_count: u32) -> OsTrustResult {
        OsTrustResult {
            signatures: codes
                .iter()
                .zip(0..)
                .map(|(&code, index)| OsSignatureResult { index, code })
                .collect(),
            secondary_count,
            truncated: false,
        }
    }

    fn outcomes(check: &CrossCheck) -> Vec<Outcome> {
        check.comparisons.iter().map(|c| c.outcome).collect()
    }

    #[test]
    fn classification() {
        assert_eq!(classify(code::S_OK), OsVerdict::Trusted);
        assert_eq!(
            classify(code::CERT_E_UNTRUSTEDROOT),
            OsVerdict::ChainNotTrusted
        );
        assert_eq!(classify(code::CERT_E_EXPIRED), OsVerdict::ChainNotTrusted);
        assert_eq!(classify(code::TRUST_E_BAD_DIGEST), OsVerdict::Broken);
        assert_eq!(classify(code::NTE_BAD_SIGNATURE), OsVerdict::Broken);
        assert_eq!(classify(0x8009_3102), OsVerdict::Broken);
        assert_eq!(classify(code::TRUST_E_NOSIGNATURE), OsVerdict::NoSignature);
        // TRUST_E_TIME_STAMP and anything unknown are not classified.
        assert_eq!(classify(0x8009_6005), OsVerdict::Unclassified);
        assert_eq!(classify(0x8000_4005), OsVerdict::Unclassified);
        assert_eq!(OsVerdict::Trusted.accepts(), Some(true));
        assert_eq!(OsVerdict::ChainNotTrusted.accepts(), Some(true));
        assert_eq!(OsVerdict::Broken.accepts(), Some(false));
        assert_eq!(OsVerdict::NoSignature.accepts(), Some(false));
        assert_eq!(OsVerdict::Unclassified.accepts(), None);
    }

    #[test]
    fn unsigned_file_agrees() {
        let r = report(Vec::new());
        let check = cross_check(&r, &os(&[code::TRUST_E_NOSIGNATURE], 0));
        assert_eq!(outcomes(&check), [Outcome::Agree]);
        assert!(check.agrees());
        // The OS sees a signature the report does not have.
        let check = cross_check(&r, &os(&[code::CERT_E_UNTRUSTEDROOT], 0));
        assert_eq!(outcomes(&check), [Outcome::OnlyOs]);
        assert!(!check.agrees());
        // Nothing asked, nothing compared.
        let check = cross_check(&r, &OsTrustResult::default());
        assert!(check.comparisons.is_empty());
        assert!(check.agrees());
    }

    #[test]
    fn dual_signed_agreement_and_disagreements() {
        let r = report(vec![
            sig(SignatureKind::Embedded, None, SignatureStatus::Valid),
            sig(SignatureKind::Nested, Some(0), SignatureStatus::Valid),
        ]);
        let check = cross_check(
            &r,
            &os(&[code::CERT_E_UNTRUSTEDROOT, code::CERT_E_UNTRUSTEDROOT], 1),
        );
        assert_eq!(outcomes(&check), [Outcome::Agree, Outcome::Agree]);
        assert_eq!(check.comparisons[1].signature, Some(1));
        assert!(check.agrees());

        // The OS says the nested one is broken: a dangerous disagreement.
        let check = cross_check(&r, &os(&[code::S_OK, code::TRUST_E_BAD_DIGEST], 1));
        assert_eq!(
            outcomes(&check),
            [Outcome::Agree, Outcome::RustAcceptsOsRejects]
        );
        assert_eq!(check.rust_accepts_os_rejects().count(), 1);
        assert!(!check.agrees());

        // The OS counts no secondary signature.
        let check = cross_check(&r, &os(&[code::S_OK], 0));
        assert!(check.secondary_count_differs);
        assert_eq!(outcomes(&check), [Outcome::Agree, Outcome::OnlyRust]);
    }

    #[test]
    fn rust_stricter_and_unclassified() {
        let r = report(vec![sig(
            SignatureKind::Embedded,
            None,
            SignatureStatus::NonConformantImage,
        )]);
        let check = cross_check(&r, &os(&[code::S_OK], 0));
        assert_eq!(outcomes(&check), [Outcome::OsAcceptsRustRejects]);
        assert_eq!(check.disagreements().count(), 1);
        assert_eq!(check.rust_accepts_os_rejects().count(), 0);

        let r = report(vec![sig(
            SignatureKind::Embedded,
            None,
            SignatureStatus::BadSignature(BadSignature::SignatureInvalid),
        )]);
        let check = cross_check(&r, &os(&[code::NTE_BAD_SIGNATURE], 0));
        assert_eq!(outcomes(&check), [Outcome::Agree]);
        let check = cross_check(&r, &os(&[0x8009_6005], 0));
        assert_eq!(outcomes(&check), [Outcome::NotComparable]);
        assert!(check.agrees());

        let r = report(vec![sig(
            SignatureKind::Embedded,
            None,
            SignatureStatus::WeakAlgorithm(DigestAlgorithm::Md5),
        )]);
        let check = cross_check(&r, &os(&[code::TRUST_E_BAD_DIGEST], 0));
        assert_eq!(outcomes(&check), [Outcome::Agree]);
    }

    #[test]
    fn only_the_signatures_the_os_reads_are_compared() {
        // A second table entry and a doubly nested signature are invisible
        // to the OS; the secondary count covers only direct children.
        let mut second = sig(SignatureKind::Embedded, None, SignatureStatus::Valid);
        second.entry = 1;
        let r = report(vec![
            sig(SignatureKind::Embedded, None, SignatureStatus::Valid),
            sig(SignatureKind::Nested, Some(0), SignatureStatus::Valid),
            sig(SignatureKind::Nested, Some(1), SignatureStatus::Valid),
            second,
        ]);
        let check = cross_check(&r, &os(&[code::S_OK, code::S_OK], 1));
        assert_eq!(check.rust_secondary_count, 1);
        assert!(!check.secondary_count_differs);
        assert_eq!(outcomes(&check), [Outcome::Agree, Outcome::Agree]);
        assert!(check.agrees());
    }

    #[test]
    fn truncated_os_results_do_not_flag_the_count() {
        let r = report(vec![sig(
            SignatureKind::Embedded,
            None,
            SignatureStatus::Valid,
        )]);
        let mut result = os(&[code::S_OK], 100);
        result.truncated = true;
        let check = cross_check(&r, &result);
        assert!(!check.secondary_count_differs);
        // A huge OS index is never iterated past the bound.
        let result = OsTrustResult {
            signatures: vec![
                OsSignatureResult {
                    index: 0,
                    code: code::S_OK,
                },
                OsSignatureResult {
                    index: u32::MAX,
                    code: code::S_OK,
                },
            ],
            secondary_count: 0,
            truncated: false,
        };
        let check = cross_check(&r, &result);
        assert_eq!(
            check.comparisons.len(),
            1,
            "indexes past the bound are not compared"
        );
    }
}
