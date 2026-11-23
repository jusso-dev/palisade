//! Match trees and identity criteria.
//!
//! This module defines only the shape of a match tree, which #30 needs. The
//! full catalogue of identity criteria is #31, the operator semantics are #32,
//! and context criteria and the identity-anchor rule are #33. New fields and
//! operators are added as enum variants in a minor schema version.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A condition tree (#33).
///
/// Each node is an object with exactly one key: `all`, `any`, `not` or
/// `criterion`.
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
            Self::Criterion(_) => &[],
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
        Match::Criterion(_) => {}
    }
}

/// A test of one fact about the object: `field operator values`.
///
/// Values are combined with OR for positive operators and with AND for
/// negative ones (#32): `not_in [a, b]` means neither `a` nor `b`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Criterion {
    /// The fact being tested.
    pub field: Field,
    /// How it is compared.
    pub operator: Operator,
    /// 1 to 25 values. Each is at most 2048 bytes of UTF-8; the schema can
    /// only bound the length in characters, so validation checks the bytes.
    #[schemars(length(min = 1, max = 25), inner(length(min = 1, max = 2048)))]
    pub values: Vec<String>,
    /// Compare strings case-sensitively. Unset means the field's default
    /// (#32), which is case-insensitive for every field defined so far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_sensitive: Option<bool>,
}

/// The identity facts a criterion can test. This is the subset of #31
/// needed to express hash, publisher and path rules (ISM-0955); #31 adds the
/// rest.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum Field {
    /// SHA-256 of the whole file. The primary identity (ADR 0008).
    #[serde(rename = "hash.sha256")]
    HashSha256,
    /// SHA-256 Authenticode image hash.
    #[serde(rename = "hash.authenticode_sha256")]
    HashAuthenticodeSha256,
    /// SHA-1 of the whole file. Compatibility only (ADR 0008).
    #[serde(rename = "hash.sha1")]
    HashSha1,
    /// MD5 of the whole file. Compatibility only (ADR 0008).
    #[serde(rename = "hash.md5")]
    HashMd5,
    /// The leaf signer's subject.
    #[serde(rename = "signer.publisher")]
    SignerPublisher,
    /// The leaf signer's issuer.
    #[serde(rename = "signer.issuer")]
    SignerIssuer,
    /// The normalised full path.
    #[serde(rename = "path.full")]
    PathFull,
    /// The parent directory.
    #[serde(rename = "path.directory")]
    PathDirectory,
    /// The on-disk file name.
    #[serde(rename = "path.file_name")]
    PathFileName,
    /// The file extension.
    #[serde(rename = "path.extension")]
    PathExtension,
    /// The original file name from the version resource.
    #[serde(rename = "meta.original_filename")]
    MetaOriginalFilename,
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
}

/// The type of a field's value, which decides the operators it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldClass {
    /// A hexadecimal digest of a fixed length.
    Hash {
        /// The number of hex digits.
        hex_len: usize,
    },
    /// A file-system path or path component.
    Path,
    /// Free text, such as a signer name.
    Text,
    /// A dotted version number.
    Version,
}

impl Field {
    /// Every field, in declaration order.
    pub const ALL: [Self; 15] = [
        Self::HashSha256,
        Self::HashAuthenticodeSha256,
        Self::HashSha1,
        Self::HashMd5,
        Self::SignerPublisher,
        Self::SignerIssuer,
        Self::PathFull,
        Self::PathDirectory,
        Self::PathFileName,
        Self::PathExtension,
        Self::MetaOriginalFilename,
        Self::MetaProductName,
        Self::MetaCompanyName,
        Self::MetaFileVersion,
        Self::MetaProductVersion,
    ];

    /// The type of this field's value.
    #[must_use]
    pub const fn class(self) -> FieldClass {
        match self {
            Self::HashSha256 | Self::HashAuthenticodeSha256 => FieldClass::Hash { hex_len: 64 },
            Self::HashSha1 => FieldClass::Hash { hex_len: 40 },
            Self::HashMd5 => FieldClass::Hash { hex_len: 32 },
            Self::PathFull | Self::PathDirectory | Self::PathFileName | Self::PathExtension => {
                FieldClass::Path
            }
            Self::SignerPublisher
            | Self::SignerIssuer
            | Self::MetaOriginalFilename
            | Self::MetaProductName
            | Self::MetaCompanyName => FieldClass::Text,
            Self::MetaFileVersion | Self::MetaProductVersion => FieldClass::Version,
        }
    }

    /// Whether this is a collision-prone hash that must never be the only
    /// identity of an allow rule (ADR 0008).
    #[must_use]
    pub const fn is_weak_hash(self) -> bool {
        matches!(self, Self::HashSha1 | Self::HashMd5)
    }
}

/// How a criterion compares the fact with its values (#32). Regular
/// expressions arrive with #32, together with their size limits.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    /// Equal to any value.
    Equals,
    /// Equal to none of the values.
    NotEquals,
    /// Starts with any value.
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
}

impl Operator {
    /// Whether a match means the fact equals or resembles a value, as opposed
    /// to a negative test such as `not_equals`. Only positive tests identify
    /// an object.
    #[must_use]
    pub const fn is_positive(self) -> bool {
        !matches!(
            self,
            Self::NotEquals | Self::NotContains | Self::NotWildcard
        )
    }

    /// Whether the operator compares versions.
    #[must_use]
    pub const fn is_version(self) -> bool {
        matches!(
            self,
            Self::VersionEq | Self::VersionGt | Self::VersionGe | Self::VersionLt | Self::VersionLe
        )
    }

    /// Whether the operator takes exactly one value.
    #[must_use]
    pub const fn is_single_valued(self) -> bool {
        matches!(
            self,
            Self::VersionGt | Self::VersionGe | Self::VersionLt | Self::VersionLe
        )
    }

    /// Whether the operator is valid on a field of this class: the static
    /// compatibility table of #32, for the fields defined so far.
    #[must_use]
    pub const fn applies_to(self, class: FieldClass) -> bool {
        match class {
            FieldClass::Hash { .. } => matches!(self, Self::Equals | Self::NotEquals),
            FieldClass::Path | FieldClass::Text => !self.is_version(),
            FieldClass::Version => {
                self.is_version() || matches!(self, Self::Equals | Self::NotEquals)
            }
        }
    }
}
