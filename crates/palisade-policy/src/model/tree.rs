//! Match trees and identity criteria.
//!
//! This module defines the shape of a match tree (#30, #33), the identity
//! fields a criterion can test with their strength (#31), the context fields
//! that describe the user, device and session (#33), and the operators with
//! their compatibility table (#32). How a criterion is matched against facts
//! is in [`crate::ops`], and how a whole tree is evaluated is in
//! [`crate::condition`]. New fields and operators are added as enum variants.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A condition tree (#33).
///
/// Each node is an object with exactly one key: `all`, `any`, `not`,
/// `criterion` or `ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Match {
    /// Matches when every child matches. Needs at least one child.
    All(#[schemars(length(min = 1))] Vec<Match>),
    /// Matches when any child matches. Needs at least one child.
    Any(#[schemars(length(min = 1))] Vec<Match>),
    /// Matches when the child does not.
    Not(Box<Match>),
    /// One test of one fact.
    Criterion(Criterion),
    /// A reference to a reusable match fragment or application definition
    /// in a library (#37), by ID and an optional version pin. A policy
    /// document that is evaluated never holds one: the hierarchy replaces
    /// every reference with the tree it names when it builds the effective
    /// policy, and validation rejects one that is left (`unresolved_ref`).
    Ref(crate::library::LibraryRef),
}

impl Match {
    /// The nesting depth: a single criterion has depth 1.
    ///
    /// Iterative, so a hostile, very deep tree cannot overflow the stack.
    #[must_use]
    pub fn depth(&self) -> usize {
        let mut deepest = 0;
        let mut stack = vec![(self, 1usize)];
        while let Some((node, depth)) = stack.pop() {
            deepest = deepest.max(depth);
            for child in node.children() {
                stack.push((child, depth.saturating_add(1)));
            }
        }
        deepest
    }

    /// The direct children of this node.
    #[must_use]
    pub fn children(&self) -> &[Match] {
        match self {
            Self::All(children) | Self::Any(children) => children,
            Self::Not(child) => core::slice::from_ref(child),
            Self::Criterion(_) | Self::Ref(_) => &[],
        }
    }
}

// The derived `Drop` would recurse through `Box` and `Vec`. JSON input is
// bounded by serde_json's recursion limit, but trees built in code or by
// other deserialisers are not, so drop iteratively.
impl Drop for Match {
    fn drop(&mut self) {
        let mut stack = Vec::new();
        take_children(self, &mut stack);
        while let Some(mut node) = stack.pop() {
            take_children(&mut node, &mut stack);
        }
    }
}

/// Moves a node's children onto `stack`, leaving the node childless.
fn take_children(node: &mut Match, stack: &mut Vec<Match>) {
    match node {
        Match::All(children) | Match::Any(children) => stack.append(children),
        Match::Not(child) => stack.push(core::mem::replace(child.as_mut(), Match::All(Vec::new()))),
        Match::Criterion(_) | Match::Ref(_) => {}
    }
}

/// A test of one fact about the object or its context: `field operator
/// values`.
///
/// Values are combined with OR for positive operators and with AND for
/// negative ones (#32): `not_contains [a, b]` means neither `a` nor `b`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = values_by_operator)]
pub struct Criterion {
    /// The fact being tested.
    pub field: Field,
    /// How it is compared.
    pub operator: Operator,
    /// 1 to 25 values. Each is at most 2048 bytes of UTF-8; the schema can
    /// only bound the length in characters, so validation checks the bytes.
    /// `is_true` and `is_false` take no values, and the key may be left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 25), inner(length(min = 1, max = 2048)))]
    pub values: Vec<String>,
    /// Compare strings case-sensitively. Unset means the field's default
    /// (#32), which is case-insensitive for every field defined so far.
    /// Only text, paths, file names, account names and tags have a case;
    /// other fields (hashes, versions, SIDs, group sets, yes-or-no facts and
    /// session types) reject this option.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
}

/// The identity facts a criterion can test (#31).
///
/// This is the part of the #31 catalogue that has a matcher: hashes, the
/// signer, the path and the version resource. The other families (signer
/// constraints such as EKU and TBS hashes, packaged apps, installers,
/// ownership, origin and process relationships) arrive in later minor
/// versions, each with its facts and matcher.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum Field {
    /// SHA-256 of the whole file. The primary identity (ADR 0008).
    #[serde(rename = "hash.sha256")]
    HashSha256,
    /// SHA-384 of the whole file.
    #[serde(rename = "hash.sha384")]
    HashSha384,
    /// SHA-512 of the whole file.
    #[serde(rename = "hash.sha512")]
    HashSha512,
    /// SHA-256 Authenticode image hash: the PE image without its checksum,
    /// security directory entry and certificate table.
    #[serde(rename = "hash.authenticode_sha256")]
    HashAuthenticodeSha256,
    /// SHA-1 Authenticode image hash. Compatibility only (ADR 0008).
    #[serde(rename = "hash.authenticode_sha1")]
    HashAuthenticodeSha1,
    /// SHA-256 hash of the first page of the image, for OS-native policy
    /// formats. It covers only that page, so it is a weak identity alone.
    #[serde(rename = "hash.page_sha256")]
    HashPageSha256,
    /// SHA-1 hash of the first page of the image. Compatibility only
    /// (ADR 0008).
    #[serde(rename = "hash.page_sha1")]
    HashPageSha1,
    /// SHA-256 of an installer package with its timestamps left out, so
    /// rebuilds of the same content share one value (#3).
    #[serde(rename = "hash.msi_fuzzy_sha256")]
    HashMsiFuzzySha256,
    /// SHA-1 of the whole file. Compatibility only (ADR 0008).
    #[serde(rename = "hash.sha1")]
    HashSha1,
    /// MD5 of the whole file. Compatibility only (ADR 0008).
    #[serde(rename = "hash.md5")]
    HashMd5,
    /// The leaf signer's subject common name.
    #[serde(rename = "signer.publisher")]
    SignerPublisher,
    /// The common name of the leaf certificate's issuer.
    #[serde(rename = "signer.issuer")]
    SignerIssuer,
    /// The SHA-256 thumbprint of the leaf certificate.
    #[serde(rename = "signer.leaf_thumbprint")]
    SignerLeafThumbprint,
    /// The normalised full path.
    #[serde(rename = "path.full")]
    PathFull,
    /// The parent directory.
    #[serde(rename = "path.directory")]
    PathDirectory,
    /// The on-disk file name.
    #[serde(rename = "path.file_name")]
    PathFileName,
    /// The file extension, without its leading dot.
    #[serde(rename = "path.extension")]
    PathExtension,
    /// The original file name from the version resource.
    #[serde(rename = "meta.original_filename")]
    MetaOriginalFilename,
    /// The internal name from the version resource.
    #[serde(rename = "meta.internal_name")]
    MetaInternalName,
    /// The file description from the version resource.
    #[serde(rename = "meta.file_description")]
    MetaFileDescription,
    /// The product name from the version resource.
    #[serde(rename = "meta.product_name")]
    MetaProductName,
    /// The company name from the version resource.
    #[serde(rename = "meta.company_name")]
    MetaCompanyName,
    /// The file version from the version resource.
    #[serde(rename = "meta.file_version")]
    MetaFileVersion,
    /// The product version from the version resource.
    #[serde(rename = "meta.product_version")]
    MetaProductVersion,
    /// Context (#33): the SID of the user the process runs as.
    #[serde(rename = "user.sid")]
    UserSid,
    /// Context (#33): the user's account name, as `DOMAIN\user` or as a
    /// user principal name (`user@example.org`). Either form can match.
    /// Regular expressions are not allowed: match principals by SID where
    /// you can (#32).
    #[serde(rename = "user.name")]
    UserName,
    /// Context (#33): the groups in the user's token, as SIDs, and the
    /// user's cloud-directory groups, as object IDs.
    #[serde(rename = "user.groups")]
    UserGroups,
    /// Context (#33): the SID of the user's primary group.
    #[serde(rename = "user.primary_group")]
    UserPrimaryGroup,
    /// Context (#33): the token holds the local Administrators group,
    /// enabled or filtered by UAC.
    #[serde(rename = "user.is_admin")]
    UserIsAdmin,
    /// Context (#33): the token is elevated.
    #[serde(rename = "user.is_elevated")]
    UserIsElevated,
    /// Context (#33): the user is a service account.
    #[serde(rename = "user.is_service_account")]
    UserIsServiceAccount,
    /// Context (#33): the user is the local system account.
    #[serde(rename = "user.is_system")]
    UserIsSystem,
    /// Context (#33): the device's host name.
    #[serde(rename = "device.hostname")]
    DeviceHostname,
    /// Context (#33): the device's fully qualified domain name.
    #[serde(rename = "device.fqdn")]
    DeviceFqdn,
    /// Context (#33): the DNS name of the device's domain.
    #[serde(rename = "device.domain")]
    DeviceDomain,
    /// Context (#33): the device's NetBIOS name.
    #[serde(rename = "device.netbios")]
    DeviceNetbios,
    /// Context (#33): the directory site the device is in.
    #[serde(rename = "device.ad_site")]
    DeviceAdSite,
    /// Context (#33): the device's computer groups, as SIDs, and its
    /// cloud-directory device groups, as object IDs.
    #[serde(rename = "device.groups")]
    DeviceGroups,
    /// Context (#33): the Palisade tags assigned to the device.
    #[serde(rename = "device.tags")]
    DeviceTags,
    /// Context (#33): the operating system version.
    #[serde(rename = "device.os_version")]
    DeviceOsVersion,
    /// Context (#33): the operating system edition.
    #[serde(rename = "device.os_edition")]
    DeviceOsEdition,
    /// Context (#33): the processor architecture, such as `x64` or `arm64`.
    #[serde(rename = "device.arch")]
    DeviceArch,
    /// Context (#33): the device runs a server edition.
    #[serde(rename = "device.is_server")]
    DeviceIsServer,
    /// Context (#33): the device is a domain controller.
    #[serde(rename = "device.is_domain_controller")]
    DeviceIsDomainController,
    /// Context (#33): the device is a laptop.
    #[serde(rename = "device.is_laptop")]
    DeviceIsLaptop,
    /// Context (#33): the device is a virtual desktop.
    #[serde(rename = "device.is_vdi")]
    DeviceIsVdi,
    /// Context (#33): the device is a multi-session terminal server.
    #[serde(rename = "device.is_terminal_server")]
    DeviceIsTerminalServer,
    /// Context (#33): how the session was started: `console`, `rdp`,
    /// `remote_shell`, `service`, `batch` or `network`.
    #[serde(rename = "session.type")]
    SessionType,
    /// Context (#33): the host name of the client connected to the session,
    /// on a multi-session host.
    #[serde(rename = "session.client_hostname")]
    SessionClientHostname,
    /// Context (#33): the session is remote.
    #[serde(rename = "session.is_remote")]
    SessionIsRemote,
}

/// The type of a field's value, which decides the operators it accepts and
/// how values are compared (#32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldClass {
    /// A hexadecimal digest of a fixed length.
    Hash {
        /// The number of hex digits.
        hex_len: usize,
    },
    /// A full path or a directory: normalised before comparison, and the
    /// only class with path variables and the recursive `**` wildcard.
    Path,
    /// One path component, such as a file name or an extension.
    FileName,
    /// Free text, such as a signer name.
    Text,
    /// A dotted version number.
    Version,
    /// A principal's account name (#33): text, without regular
    /// expressions (#32).
    PrincipalName,
    /// One security identifier, such as `S-1-5-32-544` (#33).
    Sid,
    /// A set of principals: SIDs, and cloud-directory object IDs (#33).
    PrincipalSet,
    /// A set of tags (#33).
    TagSet,
    /// A yes-or-no fact (#33).
    Bool,
    /// The type of a session (#33).
    SessionType,
}

impl FieldClass {
    /// Whether text of this class has a case, so `case_sensitive` applies.
    #[must_use]
    pub const fn has_case(self) -> bool {
        matches!(
            self,
            Self::Path | Self::FileName | Self::Text | Self::PrincipalName | Self::TagSet
        )
    }
}

/// How firmly a criterion identifies an object (#31). Ordered from weakest
/// to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Strength {
    /// Attributes anyone can set or copy: file names, extensions, version
    /// resource strings, a first-page hash, or an issuer alone.
    Weak,
    /// Identities that rest on a trust decision: a publisher, or a path,
    /// which an allow rule only trusts where users cannot write (#32).
    Medium,
    /// Collision-resistant hashes of the content or the signing
    /// certificate.
    Strong,
}

impl Field {
    /// Every field, in declaration order.
    pub const ALL: [Self; 50] = [
        Self::HashSha256,
        Self::HashSha384,
        Self::HashSha512,
        Self::HashAuthenticodeSha256,
        Self::HashAuthenticodeSha1,
        Self::HashPageSha256,
        Self::HashPageSha1,
        Self::HashMsiFuzzySha256,
        Self::HashSha1,
        Self::HashMd5,
        Self::SignerPublisher,
        Self::SignerIssuer,
        Self::SignerLeafThumbprint,
        Self::PathFull,
        Self::PathDirectory,
        Self::PathFileName,
        Self::PathExtension,
        Self::MetaOriginalFilename,
        Self::MetaInternalName,
        Self::MetaFileDescription,
        Self::MetaProductName,
        Self::MetaCompanyName,
        Self::MetaFileVersion,
        Self::MetaProductVersion,
        Self::UserSid,
        Self::UserName,
        Self::UserGroups,
        Self::UserPrimaryGroup,
        Self::UserIsAdmin,
        Self::UserIsElevated,
        Self::UserIsServiceAccount,
        Self::UserIsSystem,
        Self::DeviceHostname,
        Self::DeviceFqdn,
        Self::DeviceDomain,
        Self::DeviceNetbios,
        Self::DeviceAdSite,
        Self::DeviceGroups,
        Self::DeviceTags,
        Self::DeviceOsVersion,
        Self::DeviceOsEdition,
        Self::DeviceArch,
        Self::DeviceIsServer,
        Self::DeviceIsDomainController,
        Self::DeviceIsLaptop,
        Self::DeviceIsVdi,
        Self::DeviceIsTerminalServer,
        Self::SessionType,
        Self::SessionClientHostname,
        Self::SessionIsRemote,
    ];

    /// Whether the field describes the context of an evaluation (the user,
    /// device or session) rather than the object (#33). A context field
    /// never identifies an object.
    #[must_use]
    pub const fn is_context(self) -> bool {
        self.strength().is_none()
    }

    /// The type of this field's value.
    #[must_use]
    pub const fn class(self) -> FieldClass {
        match self {
            Self::HashSha256
            | Self::HashAuthenticodeSha256
            | Self::HashPageSha256
            | Self::HashMsiFuzzySha256
            | Self::SignerLeafThumbprint => FieldClass::Hash { hex_len: 64 },
            Self::HashSha384 => FieldClass::Hash { hex_len: 96 },
            Self::HashSha512 => FieldClass::Hash { hex_len: 128 },
            Self::HashAuthenticodeSha1 | Self::HashPageSha1 | Self::HashSha1 => {
                FieldClass::Hash { hex_len: 40 }
            }
            Self::HashMd5 => FieldClass::Hash { hex_len: 32 },
            Self::PathFull | Self::PathDirectory => FieldClass::Path,
            Self::PathFileName | Self::PathExtension => FieldClass::FileName,
            Self::SignerPublisher
            | Self::SignerIssuer
            | Self::MetaOriginalFilename
            | Self::MetaInternalName
            | Self::MetaFileDescription
            | Self::MetaProductName
            | Self::MetaCompanyName
            | Self::DeviceHostname
            | Self::DeviceFqdn
            | Self::DeviceDomain
            | Self::DeviceNetbios
            | Self::DeviceAdSite
            | Self::DeviceOsEdition
            | Self::DeviceArch
            | Self::SessionClientHostname => FieldClass::Text,
            Self::MetaFileVersion | Self::MetaProductVersion | Self::DeviceOsVersion => {
                FieldClass::Version
            }
            Self::UserName => FieldClass::PrincipalName,
            Self::UserSid | Self::UserPrimaryGroup => FieldClass::Sid,
            Self::UserGroups | Self::DeviceGroups => FieldClass::PrincipalSet,
            Self::DeviceTags => FieldClass::TagSet,
            Self::UserIsAdmin
            | Self::UserIsElevated
            | Self::UserIsServiceAccount
            | Self::UserIsSystem
            | Self::DeviceIsServer
            | Self::DeviceIsDomainController
            | Self::DeviceIsLaptop
            | Self::DeviceIsVdi
            | Self::DeviceIsTerminalServer
            | Self::SessionIsRemote => FieldClass::Bool,
            Self::SessionType => FieldClass::SessionType,
        }
    }

    /// Whether this is a collision-prone hash that must never be the only
    /// identity of an allow rule (ADR 0008).
    #[must_use]
    pub const fn is_weak_hash(self) -> bool {
        matches!(
            self,
            Self::HashSha1 | Self::HashMd5 | Self::HashAuthenticodeSha1 | Self::HashPageSha1
        )
    }

    /// How firmly a positive test of this field identifies an object (#31).
    /// `None` for a context field (#33), which identifies no object.
    #[must_use]
    pub const fn strength(self) -> Option<Strength> {
        Some(match self {
            Self::HashSha256
            | Self::HashSha384
            | Self::HashSha512
            | Self::HashAuthenticodeSha256
            | Self::HashMsiFuzzySha256
            | Self::SignerLeafThumbprint => Strength::Strong,
            Self::SignerPublisher | Self::PathFull | Self::PathDirectory => Strength::Medium,
            Self::HashAuthenticodeSha1
            | Self::HashPageSha256
            | Self::HashPageSha1
            | Self::HashSha1
            | Self::HashMd5
            | Self::SignerIssuer
            | Self::PathFileName
            | Self::PathExtension
            | Self::MetaOriginalFilename
            | Self::MetaInternalName
            | Self::MetaFileDescription
            | Self::MetaProductName
            | Self::MetaCompanyName
            | Self::MetaFileVersion
            | Self::MetaProductVersion => Strength::Weak,
            Self::UserSid
            | Self::UserName
            | Self::UserGroups
            | Self::UserPrimaryGroup
            | Self::UserIsAdmin
            | Self::UserIsElevated
            | Self::UserIsServiceAccount
            | Self::UserIsSystem
            | Self::DeviceHostname
            | Self::DeviceFqdn
            | Self::DeviceDomain
            | Self::DeviceNetbios
            | Self::DeviceAdSite
            | Self::DeviceGroups
            | Self::DeviceTags
            | Self::DeviceOsVersion
            | Self::DeviceOsEdition
            | Self::DeviceArch
            | Self::DeviceIsServer
            | Self::DeviceIsDomainController
            | Self::DeviceIsLaptop
            | Self::DeviceIsVdi
            | Self::DeviceIsTerminalServer
            | Self::SessionType
            | Self::SessionClientHostname
            | Self::SessionIsRemote => return None,
        })
    }
}

/// How a criterion compares the fact with its values (#32). Positive
/// operators match if any value matches; negative operators (`not_*`)
/// match if no value does, and never match a fact that is unknown.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal to any value.
    Equals,
    /// Equal to none of the values.
    NotEquals,
    /// Starts with any value. On paths, the value must end at a component
    /// boundary: `C:\Tools` does not match `C:\ToolsX`.
    StartsWith,
    /// Ends with any value.
    EndsWith,
    /// Contains any value.
    Contains,
    /// Contains none of the values.
    NotContains,
    /// Matches any wildcard pattern.
    Wildcard,
    /// Matches none of the wildcard patterns.
    NotWildcard,
    /// Matches any regular expression. Anchored at both ends, and run by a
    /// linear-time engine without look-around or backreferences.
    Regex,
    /// Matches none of the regular expressions.
    NotRegex,
    /// Version equal to any value.
    VersionEq,
    /// Version greater than the value.
    VersionGt,
    /// Version greater than or equal to the value.
    VersionGe,
    /// Version less than the value.
    VersionLt,
    /// Version less than or equal to the value.
    VersionLe,
    /// Version within `[min, max]`, both inclusive. Takes exactly two
    /// values, the minimum first.
    VersionBetween,
    /// The set holds any of the values (#33).
    MemberOf,
    /// The set holds none of the values (#33).
    NotMemberOf,
    /// The fact is true. Takes no values (#33).
    IsTrue,
    /// The fact is false. Takes no values (#33). On an unknown fact it is
    /// unknown, like every other test.
    IsFalse,
}

impl Operator {
    /// Whether a match means the fact equals or resembles a value, as opposed
    /// to a negative test such as `not_equals`. Only positive tests identify
    /// an object.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        !matches!(
            self,
            Self::NotEquals
                | Self::NotContains
                | Self::NotWildcard
                | Self::NotRegex
                | Self::NotMemberOf
        )
    }

    /// The positive operator that this one negates, or the operator itself
    /// if it is positive. `not_contains` gives `contains`.
    #[must_use]
    pub const fn positive(self) -> Self {
        match self {
            Self::NotEquals => Self::Equals,
            Self::NotContains => Self::Contains,
            Self::NotWildcard => Self::Wildcard,
            Self::NotRegex => Self::Regex,
            Self::NotMemberOf => Self::MemberOf,
            other => other,
        }
    }

    /// Whether the operator compares versions.
    #[must_use]
    pub const fn is_version(self) -> bool {
        matches!(
            self,
            Self::VersionEq
                | Self::VersionGt
                | Self::VersionGe
                | Self::VersionLt
                | Self::VersionLe
                | Self::VersionBetween
        )
    }

    /// Whether the operator compares text: the operators of path, file
    /// name and text fields.
    #[must_use]
    pub const fn is_text(self) -> bool {
        matches!(
            self,
            Self::Equals
                | Self::NotEquals
                | Self::StartsWith
                | Self::EndsWith
                | Self::Contains
                | Self::NotContains
                | Self::Wildcard
                | Self::NotWildcard
                | Self::Regex
                | Self::NotRegex
        )
    }

    /// Whether the operator takes regular expressions.
    #[must_use]
    pub const fn is_regex(self) -> bool {
        matches!(self, Self::Regex | Self::NotRegex)
    }

    /// The smallest and largest number of values the operator takes.
    #[must_use]
    pub const fn value_count(self) -> (usize, usize) {
        match self {
            Self::VersionGt | Self::VersionGe | Self::VersionLt | Self::VersionLe => (1, 1),
            Self::VersionBetween => (2, 2),
            Self::IsTrue | Self::IsFalse => (0, 0),
            _ => (1, super::limits::MAX_VALUES_PER_CRITERION),
        }
    }

    /// Whether the operator is valid on a field of this class: the static
    /// compatibility table of #32.
    #[must_use]
    pub const fn applies_to(self, class: FieldClass) -> bool {
        match class {
            FieldClass::Hash { .. } | FieldClass::Sid | FieldClass::SessionType => {
                matches!(self, Self::Equals | Self::NotEquals)
            }
            FieldClass::Path | FieldClass::FileName | FieldClass::Text => self.is_text(),
            FieldClass::PrincipalName => self.is_text() && !self.is_regex(),
            FieldClass::Version => {
                self.is_version() || matches!(self, Self::Equals | Self::NotEquals)
            }
            FieldClass::PrincipalSet | FieldClass::TagSet => {
                matches!(self, Self::MemberOf | Self::NotMemberOf)
            }
            FieldClass::Bool => matches!(self, Self::IsTrue | Self::IsFalse),
        }
    }

    /// Every operator, in declaration order.
    pub const ALL: [Self; 20] = [
        Self::Equals,
        Self::NotEquals,
        Self::StartsWith,
        Self::EndsWith,
        Self::Contains,
        Self::NotContains,
        Self::Wildcard,
        Self::NotWildcard,
        Self::Regex,
        Self::NotRegex,
        Self::VersionEq,
        Self::VersionGt,
        Self::VersionGe,
        Self::VersionLt,
        Self::VersionLe,
        Self::VersionBetween,
        Self::MemberOf,
        Self::NotMemberOf,
        Self::IsTrue,
        Self::IsFalse,
    ];
}

/// Adds to the generated schema of [`Criterion`] what the derive cannot
/// say: `is_true` and `is_false` take no values, and every other operator
/// needs at least one. Validation checks the exact count per operator.
fn values_by_operator(schema: &mut schemars::Schema) {
    let rule = serde_json::json!({
        "if": {
            "properties": { "operator": { "enum": ["is_true", "is_false"] } },
            "required": ["operator"]
        },
        "then": { "properties": { "values": { "maxItems": 0 } } },
        "else": {
            "properties": { "values": { "minItems": 1 } },
            "required": ["values"]
        }
    });
    schema.insert("allOf".to_owned(), serde_json::Value::Array(vec![rule]));
}
