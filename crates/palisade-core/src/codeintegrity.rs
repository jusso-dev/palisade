//! Decoder tables for OS code integrity events (#58).
//!
//! The OS code integrity log writes signing levels, signature types,
//! policy option bits and status codes as numbers. These tables give each
//! number its meaning, as data, next to the verification-error codes of
//! #50 ([`VerificationError`](crate::VerificationError), which also decodes
//! the per-signature `VerificationError` field).
//!
//! A number the tables do not list is reported as unknown (`None`), never
//! guessed: an OS update can add values, and a reader that mislabelled one
//! would misreport what the OS enforced.

use core::fmt;

/// A signing level, as the OS reports it in `RequestedSigningLevel`,
/// `ValidatedSigningLevel` and the per-signature `SignatureLevel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningLevel {
    /// 0: not checked.
    Unchecked,
    /// 1: unsigned.
    Unsigned,
    /// 2: signed by a policy-trusted signer (an enterprise signer).
    PolicySigned,
    /// 3: a developer or test signature.
    Developer,
    /// 4: an Authenticode signature that chains to a trusted root.
    Authenticode,
    /// 5: a store signature valid for a protected process light.
    StorePpl,
    /// 6: a store signature.
    Store,
    /// 7: an antimalware signature valid for a protected process light.
    AntimalwarePpl,
    /// 8: signed by the OS vendor's code-signing hierarchy.
    OsVendor,
    /// 11: a native image generated on the device.
    Ngen,
    /// 12: an OS component.
    Windows,
    /// 14: an OS component in the trusted computing base.
    WindowsTcb,
}

impl SigningLevel {
    /// Every level, in code order.
    pub const ALL: [Self; 12] = [
        Self::Unchecked,
        Self::Unsigned,
        Self::PolicySigned,
        Self::Developer,
        Self::Authenticode,
        Self::StorePpl,
        Self::Store,
        Self::AntimalwarePpl,
        Self::OsVendor,
        Self::Ngen,
        Self::Windows,
        Self::WindowsTcb,
    ];

    /// The OS code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unchecked => 0,
            Self::Unsigned => 1,
            Self::PolicySigned => 2,
            Self::Developer => 3,
            Self::Authenticode => 4,
            Self::StorePpl => 5,
            Self::Store => 6,
            Self::AntimalwarePpl => 7,
            Self::OsVendor => 8,
            Self::Ngen => 11,
            Self::Windows => 12,
            Self::WindowsTcb => 14,
        }
    }

    /// The level with code `code`, or `None` for a code this table does
    /// not know (9, 10, 13 and anything above 14).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.code() == code)
    }

    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchecked => "unchecked",
            Self::Unsigned => "unsigned",
            Self::PolicySigned => "policy_signed",
            Self::Developer => "developer",
            Self::Authenticode => "authenticode",
            Self::StorePpl => "store_ppl",
            Self::Store => "store",
            Self::AntimalwarePpl => "antimalware_ppl",
            Self::OsVendor => "os_vendor",
            Self::Ngen => "ngen",
            Self::Windows => "windows",
            Self::WindowsTcb => "windows_tcb",
        }
    }
}

impl fmt::Display for SigningLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a signature was found, from the per-signature `SignatureType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureType {
    /// 0: no signature.
    Unsigned,
    /// 1: embedded in the file.
    Embedded,
    /// 2: a cached result.
    Cached,
    /// 3: a cached catalog result.
    CachedCatalog,
    /// 4: a catalog, not cached.
    UncachedCatalog,
    /// 5: a catalog found through a hint.
    CatalogHint,
    /// 6: a package catalog.
    PackageCatalog,
    /// 7: the file was verified directly.
    FileVerified,
}

impl SignatureType {
    /// Every type, in code order.
    pub const ALL: [Self; 8] = [
        Self::Unsigned,
        Self::Embedded,
        Self::Cached,
        Self::CachedCatalog,
        Self::UncachedCatalog,
        Self::CatalogHint,
        Self::PackageCatalog,
        Self::FileVerified,
    ];

    /// The OS code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unsigned => 0,
            Self::Embedded => 1,
            Self::Cached => 2,
            Self::CachedCatalog => 3,
            Self::UncachedCatalog => 4,
            Self::CatalogHint => 5,
            Self::PackageCatalog => 6,
            Self::FileVerified => 7,
        }
    }

    /// The type with code `code`, or `None` for an unknown code.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.code() == code)
    }

    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Embedded => "embedded",
            Self::Cached => "cached",
            Self::CachedCatalog => "cached_catalog",
            Self::UncachedCatalog => "uncached_catalog",
            Self::CatalogHint => "catalog_hint",
            Self::PackageCatalog => "package_catalog",
            Self::FileVerified => "file_verified",
        }
    }
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The policy option bits a policy activation event (3099) reports, by bit
/// number, with their names.
pub const POLICY_OPTIONS: &[(u8, &str)] = &[
    (2, "UMCI"),
    (3, "BootMenuProtection"),
    (4, "Reputation"),
    (5, "InvalidateEAs"),
    (7, "RequireCertifiedDrivers"),
    (10, "AllowSupplemental"),
    (11, "DisabledRuntimeFilePath"),
    (13, "RevokedExpiredAsUnsigned"),
    (16, "Audit"),
    (17, "DisabledFlightSigning"),
    (18, "InheritDefault"),
    (19, "UnsignedSIP"),
    (20, "DynamicCodeSecurity"),
    (21, "RequiredEV"),
    (22, "BootAuditOnFailure"),
    (23, "AdvancedBootMenu"),
    (24, "DisabledScriptEnforcement"),
    (25, "EnforceStoreApps"),
    (27, "ManagedInstaller"),
    (28, "UpdatePolicyNoReboot"),
];

/// The policy option bits, split into names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyOptions(pub u32);

impl PolicyOptions {
    /// The bit `bit` of the options.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        bit < 32 && self.0 & (1 << bit) != 0
    }

    /// The names of the set bits that [`POLICY_OPTIONS`] lists, in bit
    /// order.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        POLICY_OPTIONS
            .iter()
            .filter(move |(bit, _)| self.has(*bit))
            .map(|(_, name)| *name)
    }

    /// The set bits that [`POLICY_OPTIONS`] does not list: reported as
    /// unknown, not dropped.
    #[must_use]
    pub fn unknown_bits(self) -> u32 {
        let known = POLICY_OPTIONS
            .iter()
            .fold(0_u32, |acc, (bit, _)| acc | (1 << bit));
        self.0 & !known
    }

    /// Whether the policy is in audit mode (bit 16).
    #[must_use]
    pub const fn is_audit(self) -> bool {
        self.has(16)
    }

    /// Whether the policy covers user-mode code (bit 2).
    #[must_use]
    pub const fn is_user_mode(self) -> bool {
        self.has(2)
    }
}

/// The names of the status codes (NTSTATUS values) code integrity events
/// carry most often. The table is for display; an unlisted status is shown
/// as its hex value.
pub const NTSTATUS_NAMES: &[(u32, &str)] = &[
    (0x0000_0000, "STATUS_SUCCESS"),
    (0x4000_0003, "STATUS_IMAGE_NOT_AT_BASE"),
    (0xC000_0001, "STATUS_UNSUCCESSFUL"),
    (0xC000_000D, "STATUS_INVALID_PARAMETER"),
    (0xC000_000F, "STATUS_NO_SUCH_FILE"),
    (0xC000_0022, "STATUS_ACCESS_DENIED"),
    (0xC000_0034, "STATUS_OBJECT_NAME_NOT_FOUND"),
    (0xC000_007B, "STATUS_INVALID_IMAGE_FORMAT"),
    (0xC000_00BB, "STATUS_NOT_SUPPORTED"),
    (0xC000_011B, "STATUS_INVALID_IMAGE_NE_FORMAT"),
    (0xC000_012F, "STATUS_INVALID_IMAGE_NOT_MZ"),
    (0xC000_0130, "STATUS_INVALID_IMAGE_PROTECT"),
    (0xC000_0225, "STATUS_NOT_FOUND"),
    (0xC000_0249, "STATUS_IMAGE_MP_UP_MISMATCH"),
    (0xC000_026C, "STATUS_DRIVER_UNABLE_TO_LOAD"),
    (0xC000_035A, "STATUS_INVALID_IMAGE_WIN_64"),
    (0xC000_036B, "STATUS_DRIVER_BLOCKED_CRITICAL"),
    (0xC000_036C, "STATUS_DRIVER_BLOCKED"),
    (0xC000_0428, "STATUS_INVALID_IMAGE_HASH"),
    (0xC000_0603, "STATUS_IMAGE_CERT_REVOKED"),
    (0xC000_0605, "STATUS_IMAGE_CERT_EXPIRED"),
    (0xC000_A000, "STATUS_INVALID_SIGNATURE"),
    (0xC0E9_0001, "STATUS_SYSTEM_INTEGRITY_ROLLBACK_DETECTED"),
    (0xC0E9_0002, "STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION"),
    (0xC0E9_0003, "STATUS_SYSTEM_INTEGRITY_INVALID_POLICY"),
    (0xC0E9_0004, "STATUS_SYSTEM_INTEGRITY_POLICY_NOT_SIGNED"),
    (0xC0E9_0005, "STATUS_SYSTEM_INTEGRITY_TOO_MANY_POLICIES"),
    (
        0xC0E9_0006,
        "STATUS_SYSTEM_INTEGRITY_SUPPLEMENTAL_POLICY_NOT_AUTHORIZED",
    ),
    (0xC0E9_0007, "STATUS_SYSTEM_INTEGRITY_REPUTATION_MALICIOUS"),
    (0xC0E9_0008, "STATUS_SYSTEM_INTEGRITY_REPUTATION_PUA"),
    (
        0xC0E9_0009,
        "STATUS_SYSTEM_INTEGRITY_REPUTATION_DANGEROUS_EXT",
    ),
    (0xC0E9_000A, "STATUS_SYSTEM_INTEGRITY_REPUTATION_OFFLINE"),
    (
        0xC0E9_000B,
        "STATUS_SYSTEM_INTEGRITY_REPUTATION_UNFRIENDLY_FILE",
    ),
    (
        0xC0E9_000C,
        "STATUS_SYSTEM_INTEGRITY_REPUTATION_UNATTAINABLE",
    ),
    (
        0xC0E9_000D,
        "STATUS_SYSTEM_INTEGRITY_REPUTATION_EXPLICIT_DENY_FILE",
    ),
];

/// The name of status code `status`, if [`NTSTATUS_NAMES`] lists it.
#[must_use]
pub fn ntstatus_name(status: u32) -> Option<&'static str> {
    NTSTATUS_NAMES
        .binary_search_by_key(&status, |(code, _)| *code)
        .ok()
        .and_then(|i| NTSTATUS_NAMES.get(i))
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn signing_levels_round_trip_and_gaps_are_unknown() {
        for level in SigningLevel::ALL {
            assert_eq!(SigningLevel::from_code(level.code()), Some(level));
            assert_eq!(level.to_string(), level.as_str());
        }
        for gap in [9, 10, 13, 15, 255] {
            assert_eq!(SigningLevel::from_code(gap), None);
        }
        assert!(SigningLevel::Unsigned < SigningLevel::WindowsTcb);
    }

    #[test]
    fn signature_types_round_trip() {
        for t in SignatureType::ALL {
            assert_eq!(SignatureType::from_code(t.code()), Some(t));
            assert_eq!(t.to_string(), t.as_str());
        }
        assert_eq!(SignatureType::from_code(8), None);
    }

    #[test]
    fn policy_options_decode_by_name() {
        let bits = (1 << 2) | (1 << 16) | (1 << 27) | (1 << 31) | (1 << 0);
        let o = PolicyOptions(bits);
        assert_eq!(
            o.names().collect::<Vec<_>>(),
            ["UMCI", "Audit", "ManagedInstaller"]
        );
        assert_eq!(o.unknown_bits(), (1 << 31) | 1);
        assert!(o.is_audit() && o.is_user_mode());
        assert!(!PolicyOptions(0).is_audit());
        assert!(!o.has(40));
        // The table is sorted and has no repeats.
        assert!(POLICY_OPTIONS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn status_names_are_sorted_and_found() {
        assert!(NTSTATUS_NAMES.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            ntstatus_name(0xC0E9_0002),
            Some("STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION")
        );
        assert_eq!(ntstatus_name(0), Some("STATUS_SUCCESS"));
        assert_eq!(ntstatus_name(0xDEAD_BEEF), None);
    }
}
