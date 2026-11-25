//! The signature verification-error taxonomy (#50).
//!
//! One table of stable numeric codes, shared by everything that reports why
//! a signature did or did not verify: the file identity crate (#50), and the
//! decoder for OS code integrity events (#58). Codes 0 to 28 are the values
//! the OS writes in the `VerificationError` field of its per-signature
//! code integrity events, with the same meaning, so a Palisade event and an
//! OS event for the same file can be compared code for code. Codes from
//! 1000 up are Palisade's own, for conditions the OS has no code for.
//!
//! The numbers are part of the event format: a code is never renumbered or
//! reused, and new codes are only ever added.

use core::fmt;
use core::str::FromStr;

use crate::ParseError;

/// Why a signature failed verification, or [`VerificationError::Ok`].
///
/// [`VerificationError::code`] is the stable number. The `snake_case` text
/// form ([`VerificationError::as_str`]) is the serde form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum VerificationError {
    /// 0: the signature verified.
    Ok,
    /// 1: the file's hash does not match the hash the signature signs.
    InvalidHash,
    /// 2: the file has shared writable sections.
    SharedWritableSections,
    /// 3: the file is not signed.
    NotSigned,
    /// 4: a certificate in the chain is revoked.
    Revoked,
    /// 5: the signature has expired: a certificate's validity period does
    /// not cover the signing time (or the current time, when the signing
    /// time is not trusted).
    Expired,
    /// 6: the signature uses a hash algorithm weaker than policy allows.
    WeakHashAlgorithm,
    /// 7: the chain does not end at a trusted root.
    UntrustedRoot,
    /// 8: the signature could not be validated, for no more specific
    /// reason.
    Generic,
    /// 9: the signing time is not trusted: no trusted timestamp, where one
    /// is needed.
    SigningTimeUntrusted,
    /// 10: the file must carry page hashes for this scenario.
    PageHashesRequired,
    /// 11: a page hash does not match.
    PageHashMismatch,
    /// 12: the signature is not valid for a protected process light.
    NotValidForProtectedProcessLight,
    /// 13: the signature is not valid for a protected process.
    NotValidForProtectedProcess,
    /// 14: the signature lacks the EKU required for ARM processors.
    MissingArmEku,
    /// 15: the hardware certification (certified driver) check failed.
    CertifiedDriverCheckFailed,
    /// 16: the default policy signing level is not met.
    DefaultPolicySigningLevelNotMet,
    /// 17: a custom policy signing level is not met.
    CustomPolicySigningLevelNotMet,
    /// 18: the signature does not match the policy's code integrity
    /// signers.
    CustomSignersNotMet,
    /// 19: the file is revoked by its hash.
    RevokedByHash,
    /// 20: a SHA-1 timestamp is missing or later than the configured cutoff.
    Sha1TimestampPastCutoff,
    /// 21: the file does not pass the OS-native code integrity policy.
    PolicyFailed,
    /// 22: the file is not signed for isolated user mode.
    NotIsolatedUserModeSigned,
    /// 23: the signer's key algorithm cannot be used (the OS reports
    /// elliptic-curve signers with this code).
    UnsupportedKeyAlgorithm,
    /// 24: a pre-release root is not allowed.
    PreReleaseRootNotAllowed,
    /// 25: the anti-cheat policy is violated.
    AntiCheatPolicyViolation,
    /// 26: the file is explicitly denied by policy.
    ExplicitlyDenied,
    /// 27: the signing chain appears to be tampered with.
    ChainTampered,
    /// 28: a resource page hash does not match.
    ResourcePageHashMismatch,
    /// 1000: a digest inside the signature does not match what it covers:
    /// the `messageDigest` attribute, or a timestamp's message imprint.
    DigestMismatch,
    /// 1001: the signature or certificate table could not be parsed.
    MalformedSignature,
    /// 1002: the chain could not be built up to a self-signed root or an
    /// anchor, or the signer certificate is missing.
    ChainIncomplete,
    /// 1003: a certificate lacks a required extended key usage, or key
    /// usage.
    MissingRequiredEku,
    /// 1004: a key is smaller than policy allows.
    KeyTooSmall,
    /// 1005: policy requires a trusted timestamp (countersignature) and the
    /// signature has none.
    CountersignatureRequired,
    /// 1006: a required revocation check could not be completed.
    RevocationUnavailable,
    /// 1007: a certificate's validity period is not inside its issuer's
    /// ("time nesting"), and policy requires it to be.
    TimeNotNested,
    /// 1008: the chain uses an issuer that is not a CA, or whose path
    /// length constraint is exceeded, without a per-certificate relaxation
    /// that allows it.
    BasicConstraintsViolated,
}

impl VerificationError {
    /// Every code, in numeric order.
    pub const ALL: [Self; 38] = [
        Self::Ok,
        Self::InvalidHash,
        Self::SharedWritableSections,
        Self::NotSigned,
        Self::Revoked,
        Self::Expired,
        Self::WeakHashAlgorithm,
        Self::UntrustedRoot,
        Self::Generic,
        Self::SigningTimeUntrusted,
        Self::PageHashesRequired,
        Self::PageHashMismatch,
        Self::NotValidForProtectedProcessLight,
        Self::NotValidForProtectedProcess,
        Self::MissingArmEku,
        Self::CertifiedDriverCheckFailed,
        Self::DefaultPolicySigningLevelNotMet,
        Self::CustomPolicySigningLevelNotMet,
        Self::CustomSignersNotMet,
        Self::RevokedByHash,
        Self::Sha1TimestampPastCutoff,
        Self::PolicyFailed,
        Self::NotIsolatedUserModeSigned,
        Self::UnsupportedKeyAlgorithm,
        Self::PreReleaseRootNotAllowed,
        Self::AntiCheatPolicyViolation,
        Self::ExplicitlyDenied,
        Self::ChainTampered,
        Self::ResourcePageHashMismatch,
        Self::DigestMismatch,
        Self::MalformedSignature,
        Self::ChainIncomplete,
        Self::MissingRequiredEku,
        Self::KeyTooSmall,
        Self::CountersignatureRequired,
        Self::RevocationUnavailable,
        Self::TimeNotNested,
        Self::BasicConstraintsViolated,
    ];

    /// The first Palisade-specific code. Codes below it are OS codes.
    pub const FIRST_PALISADE_CODE: u16 = 1000;

    /// The stable numeric code.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::Ok => 0,
            Self::InvalidHash => 1,
            Self::SharedWritableSections => 2,
            Self::NotSigned => 3,
            Self::Revoked => 4,
            Self::Expired => 5,
            Self::WeakHashAlgorithm => 6,
            Self::UntrustedRoot => 7,
            Self::Generic => 8,
            Self::SigningTimeUntrusted => 9,
            Self::PageHashesRequired => 10,
            Self::PageHashMismatch => 11,
            Self::NotValidForProtectedProcessLight => 12,
            Self::NotValidForProtectedProcess => 13,
            Self::MissingArmEku => 14,
            Self::CertifiedDriverCheckFailed => 15,
            Self::DefaultPolicySigningLevelNotMet => 16,
            Self::CustomPolicySigningLevelNotMet => 17,
            Self::CustomSignersNotMet => 18,
            Self::RevokedByHash => 19,
            Self::Sha1TimestampPastCutoff => 20,
            Self::PolicyFailed => 21,
            Self::NotIsolatedUserModeSigned => 22,
            Self::UnsupportedKeyAlgorithm => 23,
            Self::PreReleaseRootNotAllowed => 24,
            Self::AntiCheatPolicyViolation => 25,
            Self::ExplicitlyDenied => 26,
            Self::ChainTampered => 27,
            Self::ResourcePageHashMismatch => 28,
            Self::DigestMismatch => 1000,
            Self::MalformedSignature => 1001,
            Self::ChainIncomplete => 1002,
            Self::MissingRequiredEku => 1003,
            Self::KeyTooSmall => 1004,
            Self::CountersignatureRequired => 1005,
            Self::RevocationUnavailable => 1006,
            Self::TimeNotNested => 1007,
            Self::BasicConstraintsViolated => 1008,
        }
    }

    /// The error with numeric code `code`, if there is one. An OS event can
    /// carry a code this table does not know yet; that is `None`, never a
    /// guess.
    #[must_use]
    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.code() == code)
    }

    /// Whether this is one of the OS's codes (0 to 28), rather than a
    /// Palisade-specific one.
    #[must_use]
    pub const fn is_os_code(self) -> bool {
        self.code() < Self::FIRST_PALISADE_CODE
    }

    /// Whether this is [`VerificationError::Ok`].
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidHash => "invalid_hash",
            Self::SharedWritableSections => "shared_writable_sections",
            Self::NotSigned => "not_signed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::WeakHashAlgorithm => "weak_hash_algorithm",
            Self::UntrustedRoot => "untrusted_root",
            Self::Generic => "generic",
            Self::SigningTimeUntrusted => "signing_time_untrusted",
            Self::PageHashesRequired => "page_hashes_required",
            Self::PageHashMismatch => "page_hash_mismatch",
            Self::NotValidForProtectedProcessLight => "not_valid_for_protected_process_light",
            Self::NotValidForProtectedProcess => "not_valid_for_protected_process",
            Self::MissingArmEku => "missing_arm_eku",
            Self::CertifiedDriverCheckFailed => "certified_driver_check_failed",
            Self::DefaultPolicySigningLevelNotMet => "default_policy_signing_level_not_met",
            Self::CustomPolicySigningLevelNotMet => "custom_policy_signing_level_not_met",
            Self::CustomSignersNotMet => "custom_signers_not_met",
            Self::RevokedByHash => "revoked_by_hash",
            Self::Sha1TimestampPastCutoff => "sha1_timestamp_past_cutoff",
            Self::PolicyFailed => "policy_failed",
            Self::NotIsolatedUserModeSigned => "not_isolated_user_mode_signed",
            Self::UnsupportedKeyAlgorithm => "unsupported_key_algorithm",
            Self::PreReleaseRootNotAllowed => "pre_release_root_not_allowed",
            Self::AntiCheatPolicyViolation => "anti_cheat_policy_violation",
            Self::ExplicitlyDenied => "explicitly_denied",
            Self::ChainTampered => "chain_tampered",
            Self::ResourcePageHashMismatch => "resource_page_hash_mismatch",
            Self::DigestMismatch => "digest_mismatch",
            Self::MalformedSignature => "malformed_signature",
            Self::ChainIncomplete => "chain_incomplete",
            Self::MissingRequiredEku => "missing_required_eku",
            Self::KeyTooSmall => "key_too_small",
            Self::CountersignatureRequired => "countersignature_required",
            Self::RevocationUnavailable => "revocation_unavailable",
            Self::TimeNotNested => "time_not_nested",
            Self::BasicConstraintsViolated => "basic_constraints_violated",
        }
    }
}

impl fmt::Display for VerificationError {
    /// The `snake_case` name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for VerificationError {
    type Err = ParseError;

    /// Parses the `snake_case` name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|e| e.as_str() == s)
            .ok_or(ParseError("a verification error name"))
    }
}
