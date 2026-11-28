//! Reusable libraries: objects that policies reference instead of copying
//! (#37).
//!
//! A [`Library`] is one version of a named object: a rule set, an
//! application definition, a match fragment, or a set of hashes,
//! publishers, paths, principals, devices, networks or schedules, or a
//! message template. Each version is immutable; editing makes a new
//! version with the same [`LibraryId`].
//!
//! # References
//!
//! A match tree refers to a library with a `ref` node ([`LibraryRef`]): an
//! ID and a pin. `pin: latest` (the default) tracks the newest version;
//! `pin: 3` stays on version 3 until the reference is changed. A reference
//! is resolved when the effective policy is built ([`crate::hierarchy`]),
//! and the resolved version of every library used is recorded, so the same
//! inputs always give the same policy. A policy document that is evaluated
//! never holds a reference: validation rejects one (`unresolved_ref`).
//!
//! Only these kinds can be referenced from a match tree. Each is replaced
//! by a tree:
//!
//! | Kind | Replaced by |
//! |---|---|
//! | `match_fragment` | its tree |
//! | `application_definition` | its one tree, or `any` of its trees |
//! | `hash_set`, `publisher_set`, `path_set` | one criterion on the set's field, or `any` of criteria of at most 25 values each |
//! | a `hash_set` of more than 800 SHA-256 hashes | one `member_of` criterion that names the set at its resolved version (#368) |
//!
//! Rule set libraries are assigned to a hierarchy node, not referenced from
//! a tree. Principal, device, network and schedule sets are read by scopes
//! (#38), and message templates by notifications (#147): they are looked up
//! with [`Catalogue::resolve`] and cannot appear in a tree
//! (`ref_kind_not_allowed`).
//!
//! # Cycles and limits
//!
//! A library may reference other libraries: a rule set's rules, a fragment
//! and an application definition may hold `ref` nodes. The reference graph
//! is over library versions, with each pin resolved. [`Catalogue::new`]
//! rejects every cycle in it (`library_cycle`), naming the path, such as
//! `` `Script hosts` v2 -> `Document editors` v1 -> `Script hosts` v2 ``. References
//! nest at most [`limits::MAX_REF_DEPTH`] deep, and expanding one rule's
//! tree produces at most [`limits::MAX_EXPANDED_NODES`] nodes, so a chain of
//! fragments that each use the next twice cannot grow without bound.
//! Validation of the expanded rule then applies the usual tree limits.
//!
//! # Scope, ownership and copies
//!
//! A library is `global` (installation-wide, read-only to tenants) or
//! belongs to one tenant. A tenant's trees may use global libraries and its
//! own; a global library may use only global libraries. Only an
//! installation administrator edits a global library. A tenant library is
//! edited by its `owner` or a tenant administrator; anyone in the tenant
//! may view, duplicate and attach it ([`Library::can_edit`],
//! [`Library::can_use`]). A read-only (curated) library is never edited in
//! place: [`Library::duplicate`] makes an editable copy that records
//! `derived_from`.
//!
//! # Deleting
//!
//! [`crate::hierarchy::ValidatedHierarchy::check_delete`] refuses to delete
//! a library that anything references, and lists every referrer. The
//! 30-day soft delete is the server's (#10).

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::hierarchy::NodeId;
use crate::model::limits::{MAX_TREE_DEPTH, MAX_VALUES_PER_CRITERION};
use crate::model::{
    Criterion, Field, FieldClass, Match, Metadata, Operator, RuleId, RuleSet, RuleSetId,
};
use crate::ops::{self, CompiledCriterion};
use palisade_core::Uuid7;

/// Hard limits on libraries and references.
pub mod limits {
    /// Most entries in a hash set.
    pub const MAX_HASH_SET_ENTRIES: usize = 1_000_000;
    /// Most entries in any other set.
    pub const MAX_SET_ENTRIES: usize = 100_000;
    /// Most trees in an application definition.
    pub const MAX_APPLICATION_MATCHES: usize = 32;
    /// How deeply references may nest: a tree that refers to a fragment
    /// that refers to another fragment has depth 2.
    pub const MAX_REF_DEPTH: usize = 8;
    /// Most nodes one rule's tree may have after every reference in it is
    /// replaced.
    pub const MAX_EXPANDED_NODES: usize = 1_024;
    /// Most library versions in one catalogue.
    pub const MAX_LIBRARY_VERSIONS: usize = 100_000;
    /// Longest message template, in Unicode scalar values.
    pub const MAX_TEMPLATE_CHARS: usize = 4096;
}

use limits::{
    MAX_APPLICATION_MATCHES, MAX_EXPANDED_NODES, MAX_HASH_SET_ENTRIES, MAX_LIBRARY_VERSIONS,
    MAX_REF_DEPTH, MAX_SET_ENTRIES, MAX_TEMPLATE_CHARS,
};

/// The stable ID of a library. Every version of a library has the same ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LibraryId(pub Uuid7);

impl JsonSchema for LibraryId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "LibraryId".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Uuid7::json_schema(generator)
    }
}

impl fmt::Display for LibraryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Which version of a library a reference uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pin {
    /// The newest version. Written `latest`. The default.
    #[default]
    Latest,
    /// One version, from 1. Written as the number.
    Version(u32),
}

impl Pin {
    const fn is_latest(&self) -> bool {
        matches!(self, Self::Latest)
    }
}

impl Serialize for Pin {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Latest => s.serialize_str("latest"),
            Self::Version(v) => s.serialize_u32(*v),
        }
    }
}

impl<'de> Deserialize<'de> for Pin {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Pin;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`latest` or a version number from 1")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Pin, E> {
                if v == "latest" {
                    Ok(Pin::Latest)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(v), &self))
                }
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Pin, E> {
                match u32::try_from(v) {
                    Ok(n) if n >= 1 => Ok(Pin::Version(n)),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Unsigned(v), &self)),
                }
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Pin, E> {
                match u64::try_from(v) {
                    Ok(v) => self.visit_u64(v),
                    Err(_) => Err(E::invalid_value(serde::de::Unexpected::Signed(v), &self)),
                }
            }
        }
        d.deserialize_any(Visitor)
    }
}

impl JsonSchema for Pin {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Pin".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "`latest` (the newest version) or one version number.",
            "oneOf": [
                { "const": "latest" },
                { "type": "integer", "minimum": 1, "maximum": u32::MAX }
            ]
        })
    }
}

impl fmt::Display for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => f.write_str("latest"),
            Self::Version(v) => write!(f, "{v}"),
        }
    }
}

/// A reference to a library from a match tree or a hierarchy assignment.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct LibraryRef {
    /// The library.
    pub id: LibraryId,
    /// The version: `latest` (the default) or a version number.
    #[serde(default, skip_serializing_if = "Pin::is_latest")]
    pub pin: Pin,
}

/// Where a library lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Realm {
    /// Installation-wide, read-only to tenants.
    Global,
    /// One tenant's, by the tenant's node ID.
    Tenant(NodeId),
}

/// Who wants to change or use a library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    /// The principal: a SID or directory object ID, as the server knows it.
    pub principal: String,
    /// The tenant the actor works in, or `None` for the installation.
    pub tenant: Option<NodeId>,
    /// An administrator of that tenant.
    pub tenant_admin: bool,
    /// An installation administrator.
    pub installation_admin: bool,
}

/// What a copy was made from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derivation {
    /// The original library.
    pub id: LibraryId,
    /// The version that was copied.
    pub version: u32,
}

/// One version of a library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    /// The stable ID, shared by every version.
    pub id: LibraryId,
    /// The version, from 1. Each version is immutable.
    pub version: u32,
    /// Display name, with the same rules as a policy name.
    pub name: String,
    /// Free-text description, at most 4096 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Global or one tenant's.
    pub realm: Realm,
    /// Curated: never edited in place, only duplicated.
    #[serde(default)]
    pub read_only: bool,
    /// The principal who owns it, if any: a SID or a directory object ID,
    /// compared in canonical form. Only the owner or a tenant administrator
    /// edits a tenant library.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The library and version this one was duplicated from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<Derivation>,
    /// The content.
    pub content: LibraryContent,
    /// Governance metadata (#40).
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

/// What a library holds. The `kind` key names the variant.
// A rule set's governance metadata (#40) makes the `RuleSet` variant the
// largest. Libraries are few and held in a catalogue, not copied on a hot
// path, so boxing it would only complicate the API.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LibraryContent {
    /// A rule set, assigned to hierarchy nodes. Its `id` must be the
    /// library's ID.
    RuleSet {
        /// The rule set.
        rule_set: RuleSet,
    },
    /// An application: the trees that identify it, any of which matches.
    ApplicationDefinition {
        /// The vendor, for display.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vendor: Option<String>,
        /// The product, for display.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        product: Option<String>,
        /// The lowest version label it covers, for display.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_version: Option<String>,
        /// The highest version label it covers, for display.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_version: Option<String>,
        /// Where the definition came from.
        source: ApplicationSource,
        /// 1 to 32 trees, any of which identifies the application.
        matches: Vec<Match>,
    },
    /// A named sub-tree (#33), such as "script hosts".
    MatchFragment {
        /// The tree.
        tree: Match,
    },
    /// Hashes of one algorithm.
    HashSet {
        /// A hash field, such as `hash.sha256`.
        field: Field,
        /// Up to 1,000,000 hashes.
        hashes: Vec<String>,
    },
    /// Publishers (`signer.publisher`).
    PublisherSet {
        /// Up to 100,000 publisher names.
        publishers: Vec<String>,
    },
    /// Paths.
    PathSet {
        /// `path.full` or `path.directory`.
        field: Field,
        /// `equals`, `starts_with` or `wildcard`.
        operator: Operator,
        /// Up to 100,000 paths.
        paths: Vec<String>,
    },
    /// Users and groups, by SID or object ID, for scopes (#38).
    PrincipalSet {
        /// Up to 100,000 SIDs or object IDs.
        principals: Vec<String>,
    },
    /// Devices, for scopes (#38).
    DeviceSet {
        /// Up to 100,000 device identifiers.
        devices: Vec<String>,
    },
    /// Networks, for scopes (#38): address blocks (`10.0.0.0/8`), ranges
    /// (`10.0.0.1-10.0.0.9`) and DNS suffixes (`corp.example.org`).
    NetworkSet {
        /// Up to 100,000 entries.
        entries: Vec<String>,
    },
    /// A schedule, for scopes (#38): exactly one entry, the schedule
    /// written as JSON, the same object as a scope's inline `schedule`
    /// (whitespace and line breaks allowed), at most 1 MiB.
    ScheduleSet {
        /// One entry.
        entries: Vec<String>,
    },
    /// A notification or block message (#147).
    MessageTemplate {
        /// 1 to 4096 characters.
        text: String,
    },
}

/// Where an application definition came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationSource {
    /// Written by hand.
    Manual,
    /// Learned on devices (#5).
    Learned,
    /// From the curated catalogue (#78).
    Catalogue,
    /// Imported (#194).
    Imported,
    /// Through the API (#185).
    Api,
    /// From a recommendation (#74).
    Recommendation,
}

/// The kind of a library, without its content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LibraryKind {
    /// `rule_set`.
    RuleSet,
    /// `application_definition`.
    ApplicationDefinition,
    /// `match_fragment`.
    MatchFragment,
    /// `hash_set`.
    HashSet,
    /// `publisher_set`.
    PublisherSet,
    /// `path_set`.
    PathSet,
    /// `principal_set`.
    PrincipalSet,
    /// `device_set`.
    DeviceSet,
    /// `network_set`.
    NetworkSet,
    /// `schedule_set`.
    ScheduleSet,
    /// `message_template`.
    MessageTemplate,
}

impl LibraryKind {
    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuleSet => "rule_set",
            Self::ApplicationDefinition => "application_definition",
            Self::MatchFragment => "match_fragment",
            Self::HashSet => "hash_set",
            Self::PublisherSet => "publisher_set",
            Self::PathSet => "path_set",
            Self::PrincipalSet => "principal_set",
            Self::DeviceSet => "device_set",
            Self::NetworkSet => "network_set",
            Self::ScheduleSet => "schedule_set",
            Self::MessageTemplate => "message_template",
        }
    }

    /// Whether a match tree may refer to a library of this kind.
    #[must_use]
    pub const fn in_trees(self) -> bool {
        matches!(
            self,
            Self::ApplicationDefinition
                | Self::MatchFragment
                | Self::HashSet
                | Self::PublisherSet
                | Self::PathSet
        )
    }
}

impl fmt::Display for LibraryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl LibraryContent {
    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> LibraryKind {
        match self {
            Self::RuleSet { .. } => LibraryKind::RuleSet,
            Self::ApplicationDefinition { .. } => LibraryKind::ApplicationDefinition,
            Self::MatchFragment { .. } => LibraryKind::MatchFragment,
            Self::HashSet { .. } => LibraryKind::HashSet,
            Self::PublisherSet { .. } => LibraryKind::PublisherSet,
            Self::PathSet { .. } => LibraryKind::PathSet,
            Self::PrincipalSet { .. } => LibraryKind::PrincipalSet,
            Self::DeviceSet { .. } => LibraryKind::DeviceSet,
            Self::NetworkSet { .. } => LibraryKind::NetworkSet,
            Self::ScheduleSet { .. } => LibraryKind::ScheduleSet,
            Self::MessageTemplate { .. } => LibraryKind::MessageTemplate,
        }
    }

    /// The match trees it holds, with their JSON Pointers relative to the
    /// library.
    #[must_use]
    pub fn trees(&self) -> Vec<(String, &Match)> {
        match self {
            Self::RuleSet { rule_set } => rule_set
                .rules
                .iter()
                .enumerate()
                .map(|(i, r)| (format!("/content/rule_set/rules/{i}/match"), &r.match_))
                .collect(),
            Self::ApplicationDefinition { matches, .. } => matches
                .iter()
                .enumerate()
                .map(|(i, m)| (format!("/content/matches/{i}"), m))
                .collect(),
            Self::MatchFragment { tree } => vec![("/content/tree".to_owned(), tree)],
            _ => Vec::new(),
        }
    }

    /// The entries of a set, in canonical form: hashes in lowercase hex,
    /// SIDs and object IDs in canonical form, sorted, without repeats.
    /// Empty for a kind that is not a set. Entries that are not valid are
    /// kept as written; validation rejects them.
    #[must_use]
    pub fn canonical_entries(&self) -> Vec<String> {
        let mut out: Vec<String> = match self {
            Self::HashSet { hashes, .. } => hashes
                .iter()
                .map(|h| ops::normalize_hex(h).unwrap_or_else(|| h.clone()))
                .collect(),
            Self::PrincipalSet { principals } => principals
                .iter()
                .map(|p| crate::context::normalize_principal(p).unwrap_or_else(|| p.clone()))
                .collect(),
            Self::PublisherSet { publishers: v }
            | Self::PathSet { paths: v, .. }
            | Self::DeviceSet { devices: v }
            | Self::NetworkSet { entries: v }
            | Self::ScheduleSet { entries: v } => v.clone(),
            _ => Vec::new(),
        };
        out.sort();
        out.dedup();
        out
    }
}

/// A hash set's entries, sorted, for membership tests in `O(log n)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashSetIndex {
    field: Field,
    hashes: Vec<String>,
}

impl HashSetIndex {
    /// The hash field.
    #[must_use]
    pub const fn field(&self) -> Field {
        self.field
    }

    /// The number of distinct hashes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Whether the set holds `hash`, in any case and with or without `0x`.
    #[must_use]
    pub fn contains(&self, hash: &str) -> bool {
        ops::normalize_hex(hash).is_some_and(|h| self.hashes.binary_search(&h).is_ok())
    }
}

impl Library {
    /// The digests of a SHA-256 hash set on `field` (#368), or `None` for
    /// another kind, another field, or an entry that is not a SHA-256
    /// (which validation rejects).
    #[must_use]
    pub fn hash_digests(&self, field: Field) -> Option<crate::hashset::Digests> {
        match &self.content {
            LibraryContent::HashSet { field: f, hashes }
                if *f == field && crate::hashset::field_allowed(field) =>
            {
                crate::hashset::Digests::from_hex(hashes).ok()
            }
            _ => None,
        }
    }

    /// A sorted index of a hash set, or `None` for another kind.
    #[must_use]
    pub fn hash_index(&self) -> Option<HashSetIndex> {
        match &self.content {
            LibraryContent::HashSet { field, .. } => Some(HashSetIndex {
                field: *field,
                hashes: self.content.canonical_entries(),
            }),
            _ => None,
        }
    }

    /// Whether `actor` may edit this library. A read-only (curated) or
    /// global library is edited only by an installation administrator; a
    /// tenant library by its owner or an administrator of its tenant.
    #[must_use]
    pub fn can_edit(&self, actor: &Actor) -> bool {
        match self.realm {
            Realm::Global => actor.installation_admin,
            Realm::Tenant(_) if self.read_only => actor.installation_admin,
            Realm::Tenant(tenant) => {
                actor.installation_admin
                    || (actor.tenant == Some(tenant)
                        && (actor.tenant_admin || self.is_owner(actor)))
            }
        }
    }

    /// Whether `actor` is the owner: both principals are SIDs or object
    /// IDs and are equal in canonical form. An empty or malformed principal
    /// is never an owner.
    fn is_owner(&self, actor: &Actor) -> bool {
        let canonical = crate::context::normalize_principal;
        match (
            self.owner.as_deref().and_then(canonical),
            canonical(&actor.principal),
        ) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Whether `actor` may view, duplicate and attach this library: a
    /// global one from anywhere, a tenant one from inside its tenant.
    #[must_use]
    pub fn can_use(&self, actor: &Actor) -> bool {
        match self.realm {
            Realm::Global => true,
            Realm::Tenant(tenant) => actor.installation_admin || actor.tenant == Some(tenant),
        }
    }

    /// An editable copy in `tenant`, owned by `owner`, as version 1 of the
    /// new library `id`, recording what it was copied from. A rule set
    /// gets `id` as its rule set ID, and each of its rules a new ID from
    /// `new_rule_id`, because a rule ID is never reused. Nothing else
    /// changes; references inside keep their pins.
    #[must_use]
    pub fn duplicate(
        &self,
        id: LibraryId,
        tenant: NodeId,
        owner: String,
        mut new_rule_id: impl FnMut() -> RuleId,
    ) -> Self {
        let mut content = self.content.clone();
        if let LibraryContent::RuleSet { rule_set } = &mut content {
            rule_set.id = RuleSetId(id.0);
            rule_set.read_only = false;
            for rule in &mut rule_set.rules {
                rule.id = new_rule_id();
            }
        }
        Self {
            id,
            version: 1,
            name: self.name.clone(),
            description: self.description.clone(),
            realm: Realm::Tenant(tenant),
            read_only: false,
            owner: Some(owner),
            derived_from: Some(Derivation {
                id: self.id,
                version: self.version,
            }),
            content,
            metadata: self.metadata.clone(),
        }
    }

    fn label(&self) -> String {
        format!("`{}` v{}", self.name, self.version)
    }
}

/// The stable code of a library finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LibraryCode {
    /// A name, description or text is not valid.
    InvalidText,
    /// Two libraries share an ID and version, or a version is 0.
    InvalidVersion,
    /// Versions of one library have different kinds or realms.
    KindChanged,
    /// A rule set library's rule set ID is not the library's ID.
    IdMismatch,
    /// A set has no entries, too many, or an entry that is not valid.
    InvalidEntry,
    /// A tree is too deep, or an application definition has no trees or
    /// too many.
    InvalidTree,
    /// A reference names a library or version that does not exist.
    UnknownLibrary,
    /// A reference names a library that is not visible from where it is
    /// used: another tenant's, or a tenant's from a global object.
    NotVisible,
    /// A tree refers to a kind that cannot be used in a tree.
    RefKindNotAllowed,
    /// References form a cycle.
    LibraryCycle,
    /// References nest too deeply, or a tree expands to too many nodes.
    RefTooDeep,
    /// A set is too large to test inline in one rule.
    SetTooLarge,
    /// The catalogue holds too many versions.
    TooManyLibraries,
    /// A rule set library's content does not validate as a policy.
    InvalidRuleSet,
    /// The owner is not a SID or a directory object ID.
    InvalidOwner,
    /// A rule set library's `read_only` differs from its rule set's.
    ReadOnlyMismatch,
}

impl LibraryCode {
    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidText => "invalid_text",
            Self::InvalidVersion => "invalid_version",
            Self::KindChanged => "kind_changed",
            Self::IdMismatch => "id_mismatch",
            Self::InvalidEntry => "invalid_entry",
            Self::InvalidTree => "invalid_tree",
            Self::UnknownLibrary => "unknown_library",
            Self::NotVisible => "library_not_visible",
            Self::RefKindNotAllowed => "ref_kind_not_allowed",
            Self::LibraryCycle => "library_cycle",
            Self::RefTooDeep => "ref_too_deep",
            Self::SetTooLarge => "set_too_large",
            Self::TooManyLibraries => "too_many_libraries",
            Self::InvalidRuleSet => "invalid_rule_set",
            Self::InvalidOwner => "invalid_owner",
            Self::ReadOnlyMismatch => "read_only_mismatch",
        }
    }
}

impl fmt::Display for LibraryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One library finding: a code, the JSON Pointer of the offending value
/// (relative to the catalogue, as `/libraries/3/content/tree`, or to the
/// tree being expanded), and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryError {
    /// The stable code.
    pub code: LibraryCode,
    /// Where.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for LibraryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}] {}: {}", self.code, self.path, self.message)
    }
}

impl std::error::Error for LibraryError {}

fn err(code: LibraryCode, path: impl Into<String>, message: impl Into<String>) -> LibraryError {
    LibraryError {
        code,
        path: path.into(),
        message: message.into(),
    }
}

/// From where a reference is resolved: the installation (for global
/// objects) or one tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Visibility {
    /// Only global libraries.
    Global,
    /// Global libraries and this tenant's.
    Tenant(NodeId),
}

impl Visibility {
    fn sees(self, scope: Realm) -> bool {
        match (self, scope) {
            (_, Realm::Global) => true,
            (Self::Tenant(a), Realm::Tenant(b)) => a.0 == b.0,
            (Self::Global, Realm::Tenant(_)) => false,
        }
    }

    /// The visibility of a library's own references.
    const fn of(scope: Realm) -> Self {
        match scope {
            Realm::Global => Self::Global,
            Realm::Tenant(t) => Self::Tenant(t),
        }
    }
}

/// One library version, as `(id, version)`.
pub type Version = (LibraryId, u32);

/// Every library version, checked: unique versions, one kind and realm per
/// library, valid content, every reference resolvable and visible, and no
/// cycles.
#[derive(Clone, Debug, Default)]
pub struct Catalogue {
    by_id: BTreeMap<LibraryId, BTreeMap<u32, Library>>,
    /// For each hash, publisher and path set version: its canonical entries
    /// if they fit inline in one rule, or their count if not. Computed once
    /// here, so expanding a reference costs O(min(entries, 800)) however
    /// often a set is referenced.
    sets: BTreeMap<Version, Inline>,
}

/// A set as a tree uses it.
#[derive(Clone, Debug)]
enum Inline {
    /// The canonical entries, at most [`inline_limit`].
    Entries(Vec<String>),
    /// More distinct entries than fit inline: how many.
    TooLarge(usize),
}

/// Most entries a set may have to be inlined: 32 criteria of 25 values.
const fn inline_limit() -> usize {
    MAX_VALUES_PER_CRITERION * crate::model::limits::MAX_CRITERIA_PER_RULE
}

impl Catalogue {
    /// Checks `libraries` and indexes them. `index` maps each library to
    /// its position in the input, for error paths, which are
    /// `/libraries/<i>/...`.
    ///
    /// # Errors
    ///
    /// Every finding, in a stable order.
    pub fn new(libraries: Vec<Library>) -> Result<Self, Vec<LibraryError>> {
        let mut errors = Vec::new();
        if libraries.len() > MAX_LIBRARY_VERSIONS {
            errors.push(err(
                LibraryCode::TooManyLibraries,
                "/libraries",
                format!(
                    "{} library versions; at most {MAX_LIBRARY_VERSIONS} are allowed",
                    libraries.len()
                ),
            ));
            return Err(errors);
        }
        let mut by_id: BTreeMap<LibraryId, BTreeMap<u32, Library>> = BTreeMap::new();
        let mut paths: BTreeMap<Version, String> = BTreeMap::new();
        for (i, lib) in libraries.into_iter().enumerate() {
            let base = format!("/libraries/{i}");
            check_library(&base, &lib, &mut errors);
            if lib.version == 0 {
                continue;
            }
            let versions = by_id.entry(lib.id).or_default();
            if let Some(first) = versions.values().next()
                && (first.content.kind() != lib.content.kind() || first.realm != lib.realm)
            {
                errors.push(err(
                    LibraryCode::KindChanged,
                    format!("{base}/content"),
                    format!(
                        "every version of library {} must have the same kind and realm as {}",
                        lib.id,
                        first.label()
                    ),
                ));
            }
            if versions.contains_key(&lib.version) {
                errors.push(err(
                    LibraryCode::InvalidVersion,
                    format!("{base}/version"),
                    format!(
                        "library {} version {} is already defined by {}",
                        lib.id,
                        lib.version,
                        paths
                            .get(&(lib.id, lib.version))
                            .map_or("?", String::as_str)
                    ),
                ));
                continue;
            }
            paths.insert((lib.id, lib.version), base);
            versions.insert(lib.version, lib);
        }
        let sets = by_id
            .iter()
            .flat_map(|(id, vs)| vs.iter().map(move |(v, lib)| ((*id, *v), lib)))
            .filter(|(_, lib)| {
                matches!(
                    lib.content,
                    LibraryContent::HashSet { .. }
                        | LibraryContent::PublisherSet { .. }
                        | LibraryContent::PathSet { .. }
                )
            })
            .map(|(version, lib)| {
                let entries = lib.content.canonical_entries();
                let inline = if entries.len() > inline_limit() {
                    Inline::TooLarge(entries.len())
                } else {
                    Inline::Entries(entries)
                };
                (version, inline)
            })
            .collect();
        let catalogue = Self { by_id, sets };
        // References: each must resolve, be visible and be of a kind a tree
        // may use. Only then is the graph checked for cycles.
        let mut edges: BTreeMap<Version, Vec<Version>> = BTreeMap::new();
        for (version, lib) in catalogue.versions() {
            let base = paths.get(&version).cloned().unwrap_or_default();
            let mut targets = BTreeSet::new();
            for (pointer, tree) in lib.content.trees() {
                for (at, r) in refs_in(tree) {
                    let path = format!("{base}{pointer}{at}");
                    match catalogue.resolve_tree_ref(&r, Visibility::of(lib.realm)) {
                        Ok(target) => {
                            targets.insert((target.id, target.version));
                        }
                        Err(mut e) => {
                            e.path = path;
                            errors.push(e);
                        }
                    }
                }
            }
            edges.insert(version, targets.into_iter().collect());
        }
        errors.extend(cycles(&catalogue, &edges, &paths));
        if errors.is_empty() {
            Ok(catalogue)
        } else {
            Err(errors)
        }
    }

    /// Every version, by `(id, version)`.
    pub fn versions(&self) -> impl Iterator<Item = (Version, &Library)> {
        self.by_id
            .iter()
            .flat_map(|(id, vs)| vs.iter().map(move |(v, lib)| ((*id, *v), lib)))
    }

    /// One version.
    #[must_use]
    pub fn get(&self, id: LibraryId, version: u32) -> Option<&Library> {
        self.by_id.get(&id)?.get(&version)
    }

    /// Resolves a reference: `latest` is the highest version.
    ///
    /// # Errors
    ///
    /// `unknown_library` if the library or version does not exist, and
    /// `library_not_visible` if it is another tenant's, or a tenant's seen
    /// from a global object.
    pub fn resolve(&self, r: &LibraryRef, from: Visibility) -> Result<&Library, LibraryError> {
        let versions = self.by_id.get(&r.id).ok_or_else(|| {
            err(
                LibraryCode::UnknownLibrary,
                "",
                format!("library {} does not exist", r.id),
            )
        })?;
        let lib = match r.pin {
            Pin::Latest => versions.values().next_back(),
            Pin::Version(v) => versions.get(&v),
        }
        .ok_or_else(|| {
            err(
                LibraryCode::UnknownLibrary,
                "",
                format!("library {} has no version {}", r.id, r.pin),
            )
        })?;
        if !from.sees(lib.realm) {
            return Err(err(
                LibraryCode::NotVisible,
                "",
                format!(
                    "library {} belongs to another tenant, and is not visible here",
                    lib.label()
                ),
            ));
        }
        Ok(lib)
    }

    fn resolve_tree_ref(&self, r: &LibraryRef, from: Visibility) -> Result<&Library, LibraryError> {
        let lib = self.resolve(r, from)?;
        let kind = lib.content.kind();
        if kind.in_trees() {
            Ok(lib)
        } else {
            Err(err(
                LibraryCode::RefKindNotAllowed,
                "",
                format!(
                    "library {} is a `{kind}`, which a match tree cannot use; only match fragments, application definitions and hash, publisher and path sets can",
                    lib.label()
                ),
            ))
        }
    }

    /// The rule set libraries whose `category_path` is `category` or below
    /// it (`Tools` includes `Tools/Build`), visible from `from`, at their
    /// latest versions, sorted by ID.
    #[must_use]
    pub fn in_category(&self, category: &str, from: Visibility) -> Vec<&Library> {
        self.by_id
            .values()
            .filter_map(|vs| vs.values().next_back())
            .filter(|lib| from.sees(lib.realm))
            .filter(|lib| match &lib.content {
                LibraryContent::RuleSet { rule_set } => {
                    rule_set.category_path.as_deref().is_some_and(|c| {
                        c == category
                            || c.strip_prefix(category)
                                .is_some_and(|rest| rest.starts_with('/'))
                    })
                }
                _ => false,
            })
            .collect()
    }

    /// `tree` with every reference replaced by the tree it names, resolved
    /// from `from`. Every version used is added to `used`.
    ///
    /// # Errors
    ///
    /// A reference that does not resolve, a kind a tree cannot use, a
    /// cycle, nesting deeper than [`limits::MAX_REF_DEPTH`], a result
    /// larger than [`limits::MAX_EXPANDED_NODES`] nodes, or a set too large
    /// to test inline. Paths are relative to `tree`.
    pub fn expand(
        &self,
        tree: &Match,
        from: Visibility,
        used: &mut BTreeSet<Version>,
    ) -> Result<Match, LibraryError> {
        if tree.depth() > MAX_TREE_DEPTH {
            return Err(err(
                LibraryCode::InvalidTree,
                "",
                format!("the tree is nested more than {MAX_TREE_DEPTH} deep"),
            ));
        }
        let mut budget = MAX_EXPANDED_NODES;
        let mut stack = Vec::new();
        self.expand_node(tree, "", from, &mut stack, &mut budget, used)
    }

    fn expand_node<'c>(
        &'c self,
        node: &Match,
        pointer: &str,
        from: Visibility,
        stack: &mut Vec<&'c Library>,
        budget: &mut usize,
        used: &mut BTreeSet<Version>,
    ) -> Result<Match, LibraryError> {
        *budget = budget.checked_sub(1).ok_or_else(|| {
            err(
                LibraryCode::RefTooDeep,
                pointer,
                format!(
                    "the tree has more than {MAX_EXPANDED_NODES} nodes once its references are replaced"
                ),
            )
        })?;
        Ok(match node {
            Match::All(children) | Match::Any(children) => {
                let key = if matches!(node, Match::All(_)) {
                    "all"
                } else {
                    "any"
                };
                let mut out = Vec::with_capacity(children.len());
                for (i, child) in children.iter().enumerate() {
                    out.push(self.expand_node(
                        child,
                        &format!("{pointer}/{key}/{i}"),
                        from,
                        stack,
                        budget,
                        used,
                    )?);
                }
                if key == "all" {
                    Match::All(out)
                } else {
                    Match::Any(out)
                }
            }
            Match::Not(child) => Match::Not(Box::new(self.expand_node(
                child,
                &format!("{pointer}/not"),
                from,
                stack,
                budget,
                used,
            )?)),
            Match::Criterion(c) => {
                let mut c = c.clone();
                // A hash set test (#368) is pinned to the version its
                // reference resolves to, like a scope's set.
                if let Some(r) = c.set {
                    let at = format!("{pointer}/criterion/set");
                    let lib = self.resolve(&r, from).map_err(|mut e| {
                        e.path.clone_from(&at);
                        e
                    })?;
                    let fits = matches!(&lib.content, LibraryContent::HashSet { field, .. } if *field == c.field)
                        && crate::hashset::field_allowed(c.field);
                    if !fits {
                        return Err(err(
                            LibraryCode::RefKindNotAllowed,
                            at,
                            format!(
                                "library {} is not a SHA-256 hash set on the criterion's field",
                                lib.label()
                            ),
                        ));
                    }
                    used.insert((lib.id, lib.version));
                    c.set = Some(LibraryRef {
                        id: lib.id,
                        pin: Pin::Version(lib.version),
                    });
                }
                Match::Criterion(c)
            }
            Match::Ref(r) => {
                let at = format!("{pointer}/ref");
                let lib = self.resolve_tree_ref(r, from).map_err(|mut e| {
                    e.path.clone_from(&at);
                    e
                })?;
                if let Some(start) = stack
                    .iter()
                    .position(|l| l.id == lib.id && l.version == lib.version)
                {
                    let mut names: Vec<String> = stack[start..].iter().map(|l| l.label()).collect();
                    names.push(lib.label());
                    return Err(err(
                        LibraryCode::LibraryCycle,
                        at,
                        format!("references form a cycle: {}", names.join(" -> ")),
                    ));
                }
                if stack.len() >= MAX_REF_DEPTH {
                    return Err(err(
                        LibraryCode::RefTooDeep,
                        at,
                        format!("references nest more than {MAX_REF_DEPTH} deep"),
                    ));
                }
                used.insert((lib.id, lib.version));
                stack.push(lib);
                // Each library's own references are seen from its realm.
                let inner = Visibility::of(lib.realm);
                let result = self.library_tree(lib, &at, inner, stack, budget, used);
                stack.pop();
                result?
            }
        })
    }

    fn library_tree<'c>(
        &'c self,
        lib: &'c Library,
        at: &str,
        from: Visibility,
        stack: &mut Vec<&'c Library>,
        budget: &mut usize,
        used: &mut BTreeSet<Version>,
    ) -> Result<Match, LibraryError> {
        match &lib.content {
            LibraryContent::MatchFragment { tree } => {
                self.expand_node(tree, at, from, stack, budget, used)
            }
            LibraryContent::ApplicationDefinition { matches, .. } => {
                let mut out = Vec::with_capacity(matches.len());
                for m in matches {
                    out.push(self.expand_node(m, at, from, stack, budget, used)?);
                }
                Ok(if out.len() == 1 {
                    out.remove(0)
                } else {
                    Match::Any(out)
                })
            }
            LibraryContent::HashSet { field, .. } => {
                self.set_tree(lib, *field, Operator::Equals, at, budget)
            }
            LibraryContent::PublisherSet { .. } => {
                self.set_tree(lib, Field::SignerPublisher, Operator::Equals, at, budget)
            }
            LibraryContent::PathSet {
                field, operator, ..
            } => self.set_tree(lib, *field, *operator, at, budget),
            _ => Err(err(
                LibraryCode::RefKindNotAllowed,
                at,
                format!("library {} cannot be used in a tree", lib.label()),
            )),
        }
    }
}

impl Catalogue {
    /// A set as criteria of at most 25 values each, under `any` if there
    /// are several. A rule tests at most 32 criteria, so at most 800
    /// entries fit. A larger SHA-256 hash set becomes one criterion that
    /// names the set (#368); any other larger set is refused. The entries
    /// were made canonical once, in [`Catalogue::new`].
    fn set_tree(
        &self,
        lib: &Library,
        field: Field,
        operator: Operator,
        at: &str,
        budget: &mut usize,
    ) -> Result<Match, LibraryError> {
        let entries = match self.sets.get(&(lib.id, lib.version)) {
            Some(Inline::Entries(entries)) => entries,
            // A large SHA-256 hash set is first-class (#368): one criterion
            // that names the set at this version, matched through the set
            // the bundle carries.
            Some(Inline::TooLarge(_))
                if matches!(lib.content, LibraryContent::HashSet { .. })
                    && crate::hashset::field_allowed(field) =>
            {
                *budget = budget.checked_sub(1).ok_or_else(|| {
                    err(
                        LibraryCode::RefTooDeep,
                        at,
                        format!(
                            "the tree has more than {MAX_EXPANDED_NODES} nodes once its references are replaced"
                        ),
                    )
                })?;
                return Ok(Match::Criterion(Criterion::in_hash_set(
                    field,
                    LibraryRef {
                        id: lib.id,
                        pin: Pin::Version(lib.version),
                    },
                    false,
                )));
            }
            Some(Inline::TooLarge(count)) => {
                return Err(err(
                    LibraryCode::SetTooLarge,
                    at,
                    format!(
                        "set {} has {count} entries; a rule tests at most {} values inline (32 criteria of 25 values), and larger sets are matched through the compiled index (#42)",
                        lib.label(),
                        inline_limit()
                    ),
                ));
            }
            None => {
                return Err(err(
                    LibraryCode::RefKindNotAllowed,
                    at,
                    format!("library {} is not a set", lib.label()),
                ));
            }
        };
        let chunks = entries.len().div_ceil(MAX_VALUES_PER_CRITERION).max(1);
        *budget = budget.checked_sub(chunks).ok_or_else(|| {
            err(
                LibraryCode::RefTooDeep,
                at,
                format!(
                    "the tree has more than {MAX_EXPANDED_NODES} nodes once its references are replaced"
                ),
            )
        })?;
        let mut criteria: Vec<Match> = entries
            .chunks(MAX_VALUES_PER_CRITERION)
            .map(|chunk| Match::Criterion(Criterion::new(field, operator, chunk.iter().cloned())))
            .collect();
        Ok(if criteria.len() == 1 {
            criteria.remove(0)
        } else {
            Match::Any(criteria)
        })
    }
}

/// Every `ref` node in a tree, and every hash set a criterion names
/// (#368), with its pointer relative to the tree, in document order.
#[must_use]
pub fn refs_in(tree: &Match) -> Vec<(String, LibraryRef)> {
    let mut out = Vec::new();
    let mut stack = vec![(tree, String::new())];
    while let Some((node, path)) = stack.pop() {
        match node {
            Match::All(children) | Match::Any(children) => {
                let key = if matches!(node, Match::All(_)) {
                    "all"
                } else {
                    "any"
                };
                for (i, child) in children.iter().enumerate().rev() {
                    stack.push((child, format!("{path}/{key}/{i}")));
                }
            }
            Match::Not(child) => stack.push((child, format!("{path}/not"))),
            Match::Ref(r) => out.push((format!("{path}/ref"), *r)),
            Match::Criterion(c) => {
                if let Some(r) = c.set {
                    out.push((format!("{path}/criterion/set"), r));
                }
            }
        }
    }
    out
}

/// Every cycle in the reference graph, once each, starting from its
/// smallest version, and every chain longer than the nesting limit.
fn cycles(
    catalogue: &Catalogue,
    edges: &BTreeMap<Version, Vec<Version>>,
    paths: &BTreeMap<Version, String>,
) -> Vec<LibraryError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Colour {
        White,
        Grey,
        Black,
    }
    let mut colour: BTreeMap<Version, Colour> = edges.keys().map(|v| (*v, Colour::White)).collect();
    // The longest chain of references below each version, once known.
    let mut height: BTreeMap<Version, usize> = BTreeMap::new();
    let mut found: BTreeSet<Vec<Version>> = BTreeSet::new();
    let mut errors = Vec::new();
    let label = |v: &Version| {
        catalogue
            .get(v.0, v.1)
            .map_or_else(|| format!("{} v{}", v.0, v.1), Library::label)
    };
    for &root in edges.keys() {
        if colour.get(&root) != Some(&Colour::White) {
            continue;
        }
        // Explicit stack of (version, next edge index): no recursion. Each
        // version's position on it, so a back edge finds its cycle's start
        // in O(log n).
        let mut stack: Vec<(Version, usize)> = vec![(root, 0)];
        let mut position: BTreeMap<Version, usize> = BTreeMap::from([(root, 0)]);
        colour.insert(root, Colour::Grey);
        while let Some(&mut (v, ref mut next)) = stack.last_mut() {
            let targets = edges.get(&v).map_or(&[][..], Vec::as_slice);
            if let Some(&t) = targets.get(*next) {
                *next += 1;
                match colour.get(&t).copied().unwrap_or(Colour::Black) {
                    Colour::White => {
                        colour.insert(t, Colour::Grey);
                        position.insert(t, stack.len());
                        stack.push((t, 0));
                    }
                    Colour::Grey => {
                        let start = position.get(&t).copied().unwrap_or(0);
                        let mut cycle: Vec<Version> =
                            stack[start..].iter().map(|(s, _)| *s).collect();
                        let min = cycle
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, v)| **v)
                            .map_or(0, |(i, _)| i);
                        cycle.rotate_left(min);
                        if found.insert(cycle.clone()) {
                            let mut names: Vec<String> = cycle.iter().map(label).collect();
                            names.push(label(&cycle[0]));
                            errors.push(err(
                                LibraryCode::LibraryCycle,
                                paths.get(&cycle[0]).cloned().unwrap_or_default(),
                                format!("references form a cycle: {}", names.join(" -> ")),
                            ));
                        }
                    }
                    Colour::Black => {}
                }
            } else {
                let h = targets
                    .iter()
                    .filter_map(|t| height.get(t))
                    .map(|h| h + 1)
                    .max()
                    .unwrap_or(0);
                height.insert(v, h);
                colour.insert(v, Colour::Black);
                position.remove(&v);
                stack.pop();
            }
        }
    }
    if errors.is_empty() {
        for (v, h) in &height {
            if *h > MAX_REF_DEPTH {
                errors.push(err(
                    LibraryCode::RefTooDeep,
                    paths.get(v).cloned().unwrap_or_default(),
                    format!(
                        "library {} starts a chain of {h} nested references; at most {MAX_REF_DEPTH} are allowed",
                        label(v)
                    ),
                ));
            }
        }
    }
    errors
}

fn check_library(base: &str, lib: &Library, errors: &mut Vec<LibraryError>) {
    if lib.version == 0 {
        errors.push(err(
            LibraryCode::InvalidVersion,
            format!("{base}/version"),
            "versions start at 1",
        ));
    }
    if let Some(problem) = name_problem(&lib.name) {
        errors.push(err(
            LibraryCode::InvalidText,
            format!("{base}/name"),
            problem,
        ));
    }
    if let Some(problem) = lib
        .description
        .as_deref()
        .and_then(|t| crate::validate::text_problem(t, crate::model::limits::MAX_TEXT_CHARS))
    {
        errors.push(err(
            LibraryCode::InvalidText,
            format!("{base}/description"),
            problem,
        ));
    }
    if let Some(owner) = &lib.owner
        && crate::context::normalize_principal(owner).is_none()
    {
        errors.push(err(
            LibraryCode::InvalidOwner,
            format!("{base}/owner"),
            "the owner is a SID or a directory object ID",
        ));
    }
    if lib.derived_from.is_some_and(|d| d.version == 0) {
        errors.push(err(
            LibraryCode::InvalidVersion,
            format!("{base}/derived_from/version"),
            "versions start at 1",
        ));
    }
    for f in crate::validate::metadata_findings(&format!("{base}/metadata"), &lib.metadata) {
        errors.push(err(LibraryCode::InvalidText, f.path, f.message));
    }
    let c = format!("{base}/content");
    match &lib.content {
        LibraryContent::RuleSet { rule_set } => {
            if rule_set.read_only != lib.read_only {
                errors.push(err(
                    LibraryCode::ReadOnlyMismatch,
                    format!("{c}/rule_set/read_only"),
                    format!(
                        "the rule set's `read_only` must match the library's ({}): it decides `curated_first` and the reserved `order` ranges, and only a curated library is curated",
                        lib.read_only
                    ),
                ));
            }
            if rule_set.id.0 != lib.id.0 {
                errors.push(err(
                    LibraryCode::IdMismatch,
                    format!("{c}/rule_set/id"),
                    format!(
                        "a rule set library's rule set must have the library's ID, {}",
                        lib.id
                    ),
                ));
            }
        }
        LibraryContent::ApplicationDefinition {
            vendor,
            product,
            min_version,
            max_version,
            matches,
            ..
        } => {
            for (key, v) in [
                ("vendor", vendor),
                ("product", product),
                ("min_version", min_version),
                ("max_version", max_version),
            ] {
                if let Some(problem) = v.as_deref().and_then(name_problem) {
                    errors.push(err(LibraryCode::InvalidText, format!("{c}/{key}"), problem));
                }
            }
            if matches.is_empty() || matches.len() > MAX_APPLICATION_MATCHES {
                errors.push(err(
                    LibraryCode::InvalidTree,
                    format!("{c}/matches"),
                    format!(
                        "{} trees; 1 to {MAX_APPLICATION_MATCHES} are allowed",
                        matches.len()
                    ),
                ));
            }
            for (i, m) in matches.iter().enumerate() {
                check_depth(&format!("{c}/matches/{i}"), m, errors);
            }
        }
        LibraryContent::MatchFragment { tree } => check_depth(&format!("{c}/tree"), tree, errors),
        LibraryContent::HashSet { field, hashes } => {
            if !matches!(field.class(), FieldClass::Hash { .. }) || field.is_signer() {
                errors.push(err(
                    LibraryCode::InvalidEntry,
                    format!("{c}/field"),
                    "a hash set's field must be a `hash.*` field",
                ));
            } else {
                check_entries(&c, "hashes", hashes, MAX_HASH_SET_ENTRIES, errors, |h| {
                    criterion_problem(*field, Operator::Equals, h)
                });
            }
        }
        LibraryContent::PublisherSet { publishers } => {
            check_entries(&c, "publishers", publishers, MAX_SET_ENTRIES, errors, |p| {
                criterion_problem(Field::SignerPublisher, Operator::Equals, p)
            });
        }
        LibraryContent::PathSet {
            field,
            operator,
            paths,
        } => {
            let field_ok = matches!(field, Field::PathFull | Field::PathDirectory);
            let op_ok = matches!(
                operator,
                Operator::Equals | Operator::StartsWith | Operator::Wildcard
            );
            if !field_ok || !op_ok {
                errors.push(err(
                    LibraryCode::InvalidEntry,
                    c.clone(),
                    "a path set tests `path.full` or `path.directory` with `equals`, `starts_with` or `wildcard`",
                ));
            } else {
                check_entries(&c, "paths", paths, MAX_SET_ENTRIES, errors, |p| {
                    criterion_problem(*field, *operator, p)
                });
            }
        }
        LibraryContent::PrincipalSet { principals } => {
            check_entries(&c, "principals", principals, MAX_SET_ENTRIES, errors, |p| {
                crate::context::normalize_principal(p)
                    .is_none()
                    .then(|| "not a SID or an object ID".to_owned())
            });
        }
        LibraryContent::DeviceSet { devices: v } => {
            check_entries(&c, "devices", v, MAX_SET_ENTRIES, errors, plain_problem);
        }
        LibraryContent::NetworkSet { entries: v } => {
            check_entries(&c, "entries", v, MAX_SET_ENTRIES, errors, |e| {
                plain_problem(e).or_else(|| crate::scope::network_entry_problem(e))
            });
        }
        LibraryContent::ScheduleSet { entries: v } => {
            // One schedule per set. It is JSON, so it may hold line breaks,
            // and it is measured on its own limit, not a set entry's.
            check_entries(
                &c,
                "entries",
                v,
                1,
                errors,
                crate::scope::schedule_entry_problem,
            );
        }
        LibraryContent::MessageTemplate { text } => {
            let problem = if text.trim().is_empty() {
                Some("must not be empty".to_owned())
            } else {
                crate::validate::text_problem(text, MAX_TEMPLATE_CHARS)
            };
            if let Some(problem) = problem {
                errors.push(err(LibraryCode::InvalidText, format!("{c}/text"), problem));
            }
        }
    }
}

fn check_depth(path: &str, tree: &Match, errors: &mut Vec<LibraryError>) {
    let depth = tree.depth();
    if depth > MAX_TREE_DEPTH {
        errors.push(err(
            LibraryCode::InvalidTree,
            path,
            format!("depth {depth}; at most {MAX_TREE_DEPTH} is allowed"),
        ));
    }
}

fn check_entries(
    base: &str,
    key: &str,
    entries: &[String],
    max: usize,
    errors: &mut Vec<LibraryError>,
    problem: impl Fn(&str) -> Option<String>,
) {
    if entries.is_empty() || entries.len() > max {
        errors.push(err(
            LibraryCode::InvalidEntry,
            format!("{base}/{key}"),
            format!("{} entries; 1 to {max} are allowed", entries.len()),
        ));
        return;
    }
    // Every bad entry would be one finding each; a million bad hashes
    // should not make a million findings.
    let mut reported = 0;
    for (i, entry) in entries.iter().enumerate() {
        if let Some(why) = problem(entry) {
            errors.push(err(
                LibraryCode::InvalidEntry,
                format!("{base}/{key}/{i}"),
                why,
            ));
            reported += 1;
            if reported == 25 {
                break;
            }
        }
    }
}

fn criterion_problem(field: Field, operator: Operator, value: &str) -> Option<String> {
    if let Some(why) = plain_problem(value) {
        return Some(why);
    }
    let c = Criterion::new(field, operator, [value]);
    CompiledCriterion::check_value(&c, value)
        .err()
        .map(|k| k.to_string())
}

fn plain_problem(value: &str) -> Option<String> {
    if value.trim().is_empty() {
        Some("entries must not be empty".to_owned())
    } else if let Some(why) = ops::value_too_long(value) {
        Some(why)
    } else if value.chars().any(char::is_control) {
        Some("entries must not contain control characters".to_owned())
    } else {
        None
    }
}

/// The policy-name rule: 1 to 128 characters, trimmed, no control or
/// bidirectional formatting characters.
pub(crate) fn name_problem(name: &str) -> Option<String> {
    let max = crate::model::limits::MAX_NAME_CHARS;
    if name.trim().is_empty() {
        Some("must not be empty or only whitespace".to_owned())
    } else if name.chars().count() > max {
        Some(format!("at most {max} characters"))
    } else if name.trim() != name {
        Some("must not start or end with whitespace".to_owned())
    } else if name
        .chars()
        .any(|c| c.is_control() || crate::validate::is_bidi_control(c))
    {
        Some("must not contain control or bidirectional formatting characters".to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests;
