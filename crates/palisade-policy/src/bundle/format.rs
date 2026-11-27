//! The bundle's byte format (#43): a header that decodes on its own, then
//! the body.
//!
//! A bundle is one canonical CBOR array of two items, `[header, body]`:
//!
//! - the **header** names what the bundle is for and when it may run:
//!   format and schema version, tenant, target, `policy_version`,
//!   `min_agent_version`, `generated_at` and an optional `expires_at`.
//!   [`decode_header`] reads it without reading the body, so the signature
//!   envelope (#225, in `palisade-proto`) can check the target and version
//!   cheaply. It is safe on untrusted input;
//! - the **body** is the effective policy, the library sets its scopes
//!   use, the source revisions and the digest of the governance metadata
//!   that stays on the server.
//!
//! Every map key is a [registry](super::keys) ID. The encoding is
//! canonical at two levels: the CBOR is deterministic ([`super::cbor`]),
//! and the body is in canonical order ([`Body::new`]: rule sets, rules,
//! assignments and profiles sorted by ID or name, governance metadata
//! removed). [`PolicyBundle::decode`] refuses input that is not in that
//! form, so one content has exactly one byte string, and
//! [`bundle_hash`] identifies it.
//!
//! [`PolicyBundle::decision_hash`] covers only what decisions depend on,
//! for the decision cache (#42): it leaves out the header, the source
//! revisions, the metadata digest, the policy revision, and every name,
//! description and display-only field.

use core::fmt;

use palisade_core::{SchemaVersion, Uuid7};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::cbor::{self, DecodeError, Limits, Map, Value};
use super::keys;
use super::serial;
use crate::library::{LibraryContent, LibraryId};
use crate::model::{Metadata, PolicyDocument, PolicyId};

/// The bundle format this crate writes and reads.
pub const FORMAT_VERSION: u16 = 1;

/// The default size limit of one bundle, 64 MiB (#43).
pub const DEFAULT_MAX_BYTES: usize = 64 << 20;

/// A SHA-256 digest.
pub type Sha256Digest = [u8; 32];

/// SHA-256 over a bundle's bytes: the `bundle_hash` that identifies the
/// artefact, which #225 signs and events carry (#16).
#[must_use]
pub fn bundle_hash(bytes: &[u8]) -> Sha256Digest {
    Sha256::digest(bytes).into()
}

/// Lowercase hex of a digest, as decision traces and events show it.
#[must_use]
pub fn hex(digest: &Sha256Digest) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// What a bundle is for: a group or one device, in a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Target {
    /// The tenant.
    pub tenant: Uuid7,
    /// The group or device.
    pub scope: TargetScope,
}

/// The group or device a bundle targets (`group:<id>` or `device:<id>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetScope {
    /// Every device in a group.
    Group(Uuid7),
    /// One device.
    Device(Uuid7),
}

/// An agent version, compared as an integer tuple.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentVersion {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
}

impl AgentVersion {
    /// Builds a version from its parts.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for AgentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The header: everything the envelope checks need before the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Header {
    /// The bundle format, [`FORMAT_VERSION`].
    pub format_version: u16,
    /// The policy schema version of the body.
    pub schema_version: SchemaVersion,
    /// The tenant and target.
    pub target: Target,
    /// Monotonic per target, from 1, assigned by the server.
    pub policy_version: u64,
    /// The oldest agent that may load the bundle.
    pub min_agent_version: AgentVersion,
    /// When the server compiled it, in microseconds since the Unix epoch.
    /// Informational: not in the decision hash.
    pub generated_at: i64,
    /// When it stops being current, in microseconds since the Unix epoch,
    /// if ever (#225 staleness). Not in the decision hash.
    pub expires_at: Option<i64>,
}

impl Header {
    /// A header for the current format and schema version.
    #[must_use]
    pub const fn new(target: Target, policy_version: u64, generated_at: i64) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            schema_version: crate::schema::CURRENT,
            target,
            policy_version,
            min_agent_version: AgentVersion::new(0, 0, 0),
            generated_at,
            expires_at: None,
        }
    }

    /// Whether an agent at `agent` may load the bundle (#225 check step 5).
    #[must_use]
    pub fn supports_agent(&self, agent: AgentVersion) -> bool {
        self.min_agent_version <= agent
    }

    /// Whether this crate reads the bundle's format and schema (#225 check
    /// step 6).
    #[must_use]
    pub const fn schema_supported(&self) -> bool {
        self.format_version == FORMAT_VERSION
            && self.schema_version.is_readable_by(crate::schema::CURRENT)
    }
}

/// The policy revisions and library versions a bundle was compiled from,
/// as evidence of what was in force (ISM-1582). Not in the decision hash.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisions {
    /// Each source policy and its revision, sorted, unique.
    pub policies: Vec<(PolicyId, u64)>,
    /// Each library and the version used, sorted, unique.
    pub libraries: Vec<(LibraryId, u32)>,
}

impl SourceRevisions {
    fn normalise(&mut self) {
        self.policies.sort_unstable();
        self.policies.dedup();
        self.libraries.sort_unstable();
        self.libraries.dedup();
    }
}

/// One library version inlined in a bundle, for the sets that scopes read
/// (#37, #38). Match-tree references are already expanded in an effective
/// policy, so only principal, device, network and schedule sets appear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineLibrary {
    /// The library.
    pub id: LibraryId,
    /// The version the reference was resolved to.
    pub resolved_version: u32,
    /// Its entries.
    pub content: SetContent,
}

/// The entries of an inlined library set, as the library holds them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetContent {
    /// SIDs and directory object IDs.
    PrincipalSet(Vec<String>),
    /// Device entries.
    DeviceSet(Vec<String>),
    /// Address blocks, ranges and DNS suffixes.
    NetworkSet(Vec<String>),
    /// One schedule, as JSON.
    ScheduleSet(Vec<String>),
}

impl SetContent {
    /// The set held by a library's content, if it is one a scope reads.
    #[must_use]
    pub fn of(content: &LibraryContent) -> Option<Self> {
        Some(match content {
            LibraryContent::PrincipalSet { principals } => Self::PrincipalSet(principals.clone()),
            LibraryContent::DeviceSet { devices } => Self::DeviceSet(devices.clone()),
            LibraryContent::NetworkSet { entries } => Self::NetworkSet(entries.clone()),
            LibraryContent::ScheduleSet { entries } => Self::ScheduleSet(entries.clone()),
            _ => return None,
        })
    }
}

/// A 32-byte digest, written as a CBOR byte string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bytes32(Sha256Digest);

impl Serialize for Bytes32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Bytes32;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Bytes32, E> {
                v.try_into()
                    .map(Bytes32)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }
        d.deserialize_bytes(V)
    }
}

/// The body as it is written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyRepr {
    document: PolicyDocument,
    libraries: Vec<InlineLibrary>,
    source_revisions: SourceRevisions,
    metadata_digest: Bytes32,
}

/// The body: the policy and what it needs, in canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    document: PolicyDocument,
    libraries: Vec<InlineLibrary>,
    source_revisions: SourceRevisions,
    metadata_digest: Sha256Digest,
}

impl Body {
    /// The canonical body of `document`: its governance metadata is
    /// replaced by [`Body::metadata_digest`], and rule sets, rules, rule set
    /// assignments, location profiles, libraries and sources are sorted.
    ///
    /// Evaluation does not depend on any of these orders (the precedence
    /// models are property-tested to be order-independent), so sorting
    /// changes no decision and makes two servers write the same bytes.
    /// Text is put in NFC, as the bytes hold it, so a body equals the body
    /// decoded from its bytes.
    ///
    /// # Errors
    ///
    /// [`serial::Error`] if the document holds a name with no registered
    /// key.
    pub fn new(
        mut document: PolicyDocument,
        mut libraries: Vec<InlineLibrary>,
        mut source_revisions: SourceRevisions,
    ) -> Result<Self, serial::Error> {
        let metadata_digest = take_metadata(&mut document);
        sort_document(&mut document);
        sort_libraries(&mut libraries);
        source_revisions.normalise();
        let body = Self {
            document,
            libraries,
            source_revisions,
            metadata_digest,
        };
        Self::from_value(body.to_value()?)
    }

    /// The policy, without governance metadata.
    #[must_use]
    pub const fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// The inlined library sets, sorted by ID and version.
    #[must_use]
    pub fn libraries(&self) -> &[InlineLibrary] {
        &self.libraries
    }

    /// Where it came from.
    #[must_use]
    pub const fn source_revisions(&self) -> &SourceRevisions {
        &self.source_revisions
    }

    /// SHA-256 of the governance metadata the server kept: the policy's,
    /// and every rule set's and rule's by ID ([`metadata_digest`]).
    #[must_use]
    pub const fn metadata_digest(&self) -> &Sha256Digest {
        &self.metadata_digest
    }

    fn to_value(&self) -> Result<Value, serial::Error> {
        serial::to_value(&BodyRepr {
            document: self.document.clone(),
            libraries: self.libraries.clone(),
            source_revisions: self.source_revisions.clone(),
            metadata_digest: Bytes32(self.metadata_digest),
        })
    }

    fn from_value(value: Value) -> Result<Self, serial::Error> {
        let r: BodyRepr = serial::from_value(value)?;
        Ok(Self {
            document: r.document,
            libraries: r.libraries,
            source_revisions: r.source_revisions,
            metadata_digest: r.metadata_digest.0,
        })
    }

    /// The same body in canonical order, without recomputing the digest.
    fn sorted(&self) -> Self {
        let mut out = self.clone();
        sort_document(&mut out.document);
        sort_libraries(&mut out.libraries);
        out.source_revisions.normalise();
        out
    }
}

/// SHA-256 over the governance metadata of `doc`: a JSON object with the
/// policy's metadata, and every non-empty rule set's and rule's by ID.
/// Field and key order is fixed, so the digest is deterministic.
#[must_use]
pub fn metadata_digest(doc: &PolicyDocument) -> Sha256Digest {
    use std::collections::BTreeMap;
    #[derive(Serialize)]
    struct All<'a> {
        policy: &'a Metadata,
        rule_sets: BTreeMap<String, &'a Metadata>,
        rules: BTreeMap<String, &'a Metadata>,
    }
    let all = All {
        policy: &doc.policy.metadata,
        rule_sets: doc
            .rule_sets
            .iter()
            .filter(|s| !s.metadata.is_empty())
            .map(|s| (s.id.to_string(), &s.metadata))
            .collect(),
        rules: doc
            .rule_sets
            .iter()
            .flat_map(|s| &s.rules)
            .filter(|r| !r.metadata.is_empty())
            .map(|r| (r.id.to_string(), &*r.metadata))
            .collect(),
    };
    let json = serde_json::to_vec(&all).unwrap_or_default();
    Sha256::digest(&json).into()
}

fn take_metadata(doc: &mut PolicyDocument) -> Sha256Digest {
    let digest = metadata_digest(doc);
    doc.policy.metadata = Metadata::default();
    for set in &mut doc.rule_sets {
        set.metadata = Metadata::default();
        for rule in &mut set.rules {
            rule.metadata = crate::model::RuleMetadata::default();
        }
    }
    digest
}

fn sort_document(doc: &mut PolicyDocument) {
    doc.policy.rule_sets.sort_unstable();
    doc.policy.rule_set_scopes.sort_by_key(|a| a.rule_set);
    doc.policy
        .location_profiles
        .sort_by(|a, b| a.name.cmp(&b.name));
    doc.rule_sets.sort_by_key(|s| s.id);
    for set in &mut doc.rule_sets {
        set.rules.sort_by_key(|r| r.id);
    }
}

fn sort_libraries(libraries: &mut Vec<InlineLibrary>) {
    libraries.sort_by_key(|l| (l.id, l.resolved_version));
    libraries.dedup_by_key(|l| (l.id, l.resolved_version));
}

/// The part of a document that decisions depend on: every name,
/// description and display-only field cleared, and the revision 0.
fn decision_view(doc: &PolicyDocument) -> PolicyDocument {
    let mut doc = doc.clone();
    let p = &mut doc.policy;
    p.name.clear();
    p.description = None;
    p.revision = 0;
    for set in &mut doc.rule_sets {
        set.name.clear();
        set.description = None;
        set.version = None;
        set.hidden = false;
        set.category_path = None;
        set.allow_child_suppress = None;
        for rule in &mut set.rules {
            rule.name.clear();
            rule.description = None;
        }
    }
    doc
}

/// A bundle: header and body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBundle {
    /// The header.
    pub header: Header,
    /// The body.
    pub body: Body,
}

/// Bounds on what [`PolicyBundle::decode`] and [`decode_header`] read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleLimits {
    /// The largest bundle, in bytes. [`DEFAULT_MAX_BYTES`] by default.
    pub max_bytes: usize,
    /// The most CBOR data items in one bundle.
    pub max_items: usize,
}

impl BundleLimits {
    /// 64 MiB and 4 Mi items.
    pub const DEFAULT: Self = Self {
        max_bytes: DEFAULT_MAX_BYTES,
        max_items: Limits::DEFAULT.max_items,
    };
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why bytes are not a bundle this crate reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// Larger than the limit.
    TooLarge {
        /// The size, in bytes.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// Not canonical CBOR, or over a CBOR limit.
    Cbor(DecodeError),
    /// The CBOR does not have a bundle's shape.
    Shape(&'static str),
    /// A required header field is missing.
    Missing(&'static str),
    /// An integer does not fit its field.
    Overflow(&'static str),
    /// An ID is not a UUIDv7.
    InvalidId(&'static str),
    /// A key this reader does not know, and that it must not skip.
    UnknownCriticalKey(i64),
    /// A bundle format this reader does not implement.
    UnsupportedFormat(u64),
    /// A schema major version this reader does not implement.
    UnsupportedSchema(SchemaVersion),
    /// The body does not read as a policy.
    Body(serial::Error),
    /// The body is not in canonical form: for example, its rules are not
    /// sorted, or a field holds a default the writer leaves out.
    NonCanonical,
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { size, limit } => write!(
                f,
                "the bundle is {size} bytes, over the limit of {limit}; split it into a group bundle and a device bundle, or replace hash rules with signer rules"
            ),
            Self::Cbor(e) => write!(f, "not canonical CBOR: {e}"),
            Self::Shape(what) => write!(f, "not a bundle: {what}"),
            Self::Missing(field) => write!(f, "the header has no `{field}`"),
            Self::Overflow(field) => write!(f, "`{field}` is out of range"),
            Self::InvalidId(field) => write!(f, "`{field}` is not a UUIDv7"),
            Self::UnknownCriticalKey(id) => write!(f, "unknown critical key {id}"),
            Self::UnsupportedFormat(v) => write!(
                f,
                "bundle format {v} is not supported: this reader implements {FORMAT_VERSION}"
            ),
            Self::UnsupportedSchema(v) => write!(
                f,
                "schema version {v} is not supported: this reader implements {}",
                crate::schema::CURRENT
            ),
            Self::Body(e) => write!(f, "invalid bundle body: {e}"),
            Self::NonCanonical => f.write_str("the bundle body is not in canonical form"),
        }
    }
}

impl std::error::Error for BundleError {}

fn k(name: &'static str) -> Value {
    // Every name used here is registered; `keys` tests that.
    Value::int(keys::id(name).unwrap_or(i64::MIN))
}

fn uuid(id: Uuid7) -> Value {
    Value::Bytes(id.as_bytes().to_vec())
}

fn triple(a: u64, b: u64, c: u64) -> Value {
    Value::Array(vec![Value::Uint(a), Value::Uint(b), Value::Uint(c)])
}

fn map(entries: Vec<(Value, Value)>) -> Result<Value, serial::Error> {
    Map::new(entries)
        .map(Value::Map)
        .map_err(serial::Error::Encode)
}

impl Header {
    fn to_value(self) -> Result<Value, serial::Error> {
        let (scope_key, scope_id) = match self.target.scope {
            TargetScope::Group(id) => ("group", id),
            TargetScope::Device(id) => ("device", id),
        };
        let s = self.schema_version;
        let a = self.min_agent_version;
        let mut entries = vec![
            (k("format_version"), Value::Uint(self.format_version.into())),
            (k("schema_version"), triple(s.major, s.minor, s.patch)),
            (k("tenant"), uuid(self.target.tenant)),
            (k("target"), map(vec![(k(scope_key), uuid(scope_id))])?),
            (k("policy_version"), Value::Uint(self.policy_version)),
            (
                k("min_agent_version"),
                triple(a.major.into(), a.minor.into(), a.patch.into()),
            ),
            (k("generated_at"), Value::int(self.generated_at)),
        ];
        if let Some(t) = self.expires_at {
            entries.push((k("expires_at"), Value::int(t)));
        }
        map(entries)
    }

    fn from_value(value: Value) -> Result<Self, BundleError> {
        let Value::Map(m) = value else {
            return Err(BundleError::Shape("the header is not a map"));
        };
        // The format version is read first, so a newer format is reported
        // as such rather than as an unknown key.
        let format = match m.get(&k("format_version")) {
            Some(Value::Uint(v)) => *v,
            Some(_) => return Err(BundleError::Shape("`format_version` is not an integer")),
            None => return Err(BundleError::Missing("format_version")),
        };
        if format != u64::from(FORMAT_VERSION) {
            return Err(BundleError::UnsupportedFormat(format));
        }
        let mut h = HeaderFields::default();
        for (key, v) in m.into_entries() {
            let Some(id) = key.as_i64() else {
                return Err(BundleError::Shape("a header key is not an integer"));
            };
            match keys::name(id) {
                Some("format_version") => {}
                Some("schema_version") => {
                    let [a, b, c] = ints(v, "schema_version")?;
                    h.schema_version = Some(SchemaVersion::new(a, b, c));
                }
                Some("tenant") => h.tenant = Some(read_uuid(v, "tenant")?),
                Some("target") => h.target = Some(read_target(v)?),
                Some("policy_version") => h.policy_version = Some(uint(v, "policy_version")?),
                Some("min_agent_version") => {
                    let [a, b, c] = ints(v, "min_agent_version")?;
                    let n = |x: u64| {
                        u32::try_from(x).map_err(|_| BundleError::Overflow("min_agent_version"))
                    };
                    h.min_agent_version = Some(AgentVersion::new(n(a)?, n(b)?, n(c)?));
                }
                Some("generated_at") => h.generated_at = Some(int(&v, "generated_at")?),
                Some("expires_at") => h.expires_at = Some(int(&v, "expires_at")?),
                _ if id < 0 => {}
                _ => return Err(BundleError::UnknownCriticalKey(id)),
            }
        }
        Ok(Self {
            format_version: FORMAT_VERSION,
            schema_version: h
                .schema_version
                .ok_or(BundleError::Missing("schema_version"))?,
            target: Target {
                tenant: h.tenant.ok_or(BundleError::Missing("tenant"))?,
                scope: h.target.ok_or(BundleError::Missing("target"))?,
            },
            policy_version: h
                .policy_version
                .ok_or(BundleError::Missing("policy_version"))?,
            min_agent_version: h
                .min_agent_version
                .ok_or(BundleError::Missing("min_agent_version"))?,
            generated_at: h.generated_at.ok_or(BundleError::Missing("generated_at"))?,
            expires_at: h.expires_at,
        })
    }
}

#[derive(Default)]
struct HeaderFields {
    schema_version: Option<SchemaVersion>,
    tenant: Option<Uuid7>,
    target: Option<TargetScope>,
    policy_version: Option<u64>,
    min_agent_version: Option<AgentVersion>,
    generated_at: Option<i64>,
    expires_at: Option<i64>,
}

fn uint(v: Value, field: &'static str) -> Result<u64, BundleError> {
    match v {
        Value::Uint(n) => Ok(n),
        Value::Nint(_) => Err(BundleError::Overflow(field)),
        _ => Err(BundleError::Shape("an integer field holds something else")),
    }
}

fn int(v: &Value, field: &'static str) -> Result<i64, BundleError> {
    match v {
        Value::Uint(_) | Value::Nint(_) => v.as_i64().ok_or(BundleError::Overflow(field)),
        _ => Err(BundleError::Shape("an integer field holds something else")),
    }
}

fn ints(v: Value, field: &'static str) -> Result<[u64; 3], BundleError> {
    let Value::Array(items) = v else {
        return Err(BundleError::Shape("a version is not an array"));
    };
    let parts: Vec<u64> = items
        .into_iter()
        .map(|x| uint(x, field))
        .collect::<Result<_, _>>()?;
    parts
        .try_into()
        .map_err(|_| BundleError::Shape("a version is not three integers"))
}

fn read_uuid(v: Value, field: &'static str) -> Result<Uuid7, BundleError> {
    let Value::Bytes(b) = v else {
        return Err(BundleError::Shape("an ID is not a byte string"));
    };
    let bytes: [u8; 16] = b.try_into().map_err(|_| BundleError::InvalidId(field))?;
    Uuid7::from_bytes(bytes).ok_or(BundleError::InvalidId(field))
}

fn read_target(v: Value) -> Result<TargetScope, BundleError> {
    let Value::Map(m) = v else {
        return Err(BundleError::Shape("the target is not a map"));
    };
    let mut entries = m.into_entries();
    if entries.len() != 1 {
        return Err(BundleError::Shape("the target names more than one scope"));
    }
    let (key, id) = entries.remove(0);
    match key.as_i64().and_then(keys::name) {
        Some("group") => Ok(TargetScope::Group(read_uuid(id, "target")?)),
        Some("device") => Ok(TargetScope::Device(read_uuid(id, "target")?)),
        _ => match key.as_i64() {
            Some(id) if id >= 0 => Err(BundleError::UnknownCriticalKey(id)),
            _ => Err(BundleError::Shape(
                "the target is neither a group nor a device",
            )),
        },
    }
}

/// Whether `written` is `read` with only ignorable map entries (negative
/// keys) removed: what a reader that drops fields it does not know gives
/// back. Everything else must be identical.
fn same_but_dropped(read: &Value, written: &Value) -> bool {
    match (read, written) {
        (Value::Map(r), Value::Map(w)) => {
            let mut w = w.entries().iter().peekable();
            for (key, value) in r.entries() {
                match w.peek() {
                    Some((wk, wv)) if wk == key => {
                        if !same_but_dropped(value, wv) {
                            return false;
                        }
                        w.next();
                    }
                    _ if key.as_i64().is_some_and(|id| id < 0) => {}
                    _ => return false,
                }
            }
            w.next().is_none()
        }
        (Value::Array(r), Value::Array(w)) => {
            r.len() == w.len() && r.iter().zip(w).all(|(a, b)| same_but_dropped(a, b))
        }
        _ => read == written,
    }
}

/// Splits `bytes` into the header item and the rest, checking only the
/// outer array and the size.
fn split(bytes: &[u8], limits: &BundleLimits) -> Result<(), BundleError> {
    if bytes.len() > limits.max_bytes {
        return Err(BundleError::TooLarge {
            size: bytes.len(),
            limit: limits.max_bytes,
        });
    }
    // `[header, body]`: an array of two items, 0x82.
    match bytes.first() {
        Some(0x82) => Ok(()),
        _ => Err(BundleError::Shape("not an array of a header and a body")),
    }
}

/// The most data items a header can have, with room for ignorable fields.
const HEADER_ITEMS: usize = 256;

/// Reads only the header of a bundle. The body is not read or checked, so
/// this is cheap on a large bundle, and safe on untrusted input: the
/// header is canonical CBOR and bounded to a few hundred items.
///
/// `palisade-proto` calls this for the envelope checks (#225), and
/// [`PolicyBundle::decode`] after the signature verifies.
///
/// # Errors
///
/// [`BundleError`] if the bytes are over the size limit, do not start with
/// a canonical header, or the header is for another format.
pub fn decode_header(bytes: &[u8], limits: &BundleLimits) -> Result<Header, BundleError> {
    split(bytes, limits)?;
    let cbor_limits = Limits {
        max_bytes: limits.max_bytes,
        max_items: HEADER_ITEMS,
        ..Limits::DEFAULT
    };
    let (value, _) = cbor::decode_prefix(&bytes[1..], &cbor_limits).map_err(|mut e| {
        e.offset += 1;
        BundleError::Cbor(e)
    })?;
    Header::from_value(value)
}

impl PolicyBundle {
    /// Builds a bundle.
    #[must_use]
    pub const fn new(header: Header, body: Body) -> Self {
        Self { header, body }
    }

    /// The canonical bytes.
    ///
    /// # Errors
    ///
    /// [`serial::Error`] if the body holds a name with no registered key,
    /// which the key registry tests rule out.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serial::Error> {
        let value = Value::Array(vec![self.header.to_value()?, self.body.to_value()?]);
        cbor::encode(&value).map_err(serial::Error::Encode)
    }

    /// Reads a bundle, strictly: the CBOR must be canonical, the format
    /// and schema supported, every critical key known, and the body in
    /// canonical form, so that the bytes are exactly what
    /// [`to_bytes`](Self::to_bytes) writes for the result (apart from
    /// ignorable fields this reader does not know, which it drops).
    ///
    /// This does not check `min_agent_version`, and it does not verify a
    /// signature: verification comes first (#225).
    ///
    /// # Errors
    ///
    /// [`BundleError`] for anything else.
    pub fn decode(bytes: &[u8], limits: &BundleLimits) -> Result<Self, BundleError> {
        split(bytes, limits)?;
        let cbor_limits = Limits {
            max_bytes: limits.max_bytes,
            max_items: limits.max_items,
            ..Limits::DEFAULT
        };
        let value = cbor::decode_with_limits(bytes, &cbor_limits).map_err(BundleError::Cbor)?;
        let Value::Array(mut items) = value else {
            return Err(BundleError::Shape("not an array"));
        };
        let body_value = items
            .pop()
            .ok_or(BundleError::Shape("not an array of a header and a body"))?;
        let header_value = items
            .pop()
            .ok_or(BundleError::Shape("not an array of a header and a body"))?;
        let header = Header::from_value(header_value.clone())?;
        if !header.schema_version.is_readable_by(crate::schema::CURRENT) {
            return Err(BundleError::UnsupportedSchema(header.schema_version));
        }
        let body = Body::from_value(body_value.clone()).map_err(|e| match e {
            serial::Error::UnknownCriticalKey(id) => BundleError::UnknownCriticalKey(id),
            e => BundleError::Body(e),
        })?;
        // The canonical form of what was read must be what was read, apart
        // from unknown ignorable entries.
        let again = body.sorted().to_value().map_err(BundleError::Body)?;
        let header_again = header.to_value().map_err(BundleError::Body)?;
        if !same_but_dropped(&body_value, &again) || !same_but_dropped(&header_value, &header_again)
        {
            return Err(BundleError::NonCanonical);
        }
        Ok(Self { header, body })
    }

    /// Validates the body as a policy (#30): decoding checks the encoding
    /// and the model's shape, not the rules validation applies. A loader
    /// calls this after [`decode`](Self::decode) and before it evaluates
    /// anything.
    ///
    /// # Errors
    ///
    /// Every finding of [`PolicyDocument::validate`].
    pub fn validate(
        &self,
    ) -> Result<crate::validate::ValidatedPolicy, Vec<crate::validate::ValidationError>> {
        self.body.document.clone().validate()
    }

    /// SHA-256 of the canonical bytes ([`bundle_hash`]).
    ///
    /// # Errors
    ///
    /// As [`to_bytes`](Self::to_bytes).
    pub fn bundle_hash(&self) -> Result<Sha256Digest, serial::Error> {
        self.to_bytes().map(|b| bundle_hash(&b))
    }

    /// SHA-256 over the decision-relevant part of the body: the policy
    /// without its names, descriptions, display-only rule set fields and
    /// revision, and the inlined libraries. The header, the source
    /// revisions and the metadata digest are left out, so a text-only
    /// edit, a new `policy_version` or a new `generated_at` keeps it. It is
    /// meant as the policy part of the decision cache key (#42).
    ///
    /// A cache keyed by it must not hand back a stored [`Decision`] as is:
    /// a decision names the policy revision it was made under
    /// ([`RuleRef::policy_revision`]), and rule names and display IDs, which
    /// this hash leaves out. Re-stamp the revision (and anything else taken
    /// from the current policy) when serving a cached decision, or key the
    /// cache by the bundle hash instead. The engine's cache (#293) keys by
    /// the snapshot generation today, which changes on every swap, so it is
    /// not affected.
    ///
    /// [`Decision`]: crate::decision::Decision
    /// [`RuleRef::policy_revision`]: crate::decision::RuleRef::policy_revision
    ///
    /// # Errors
    ///
    /// As [`to_bytes`](Self::to_bytes).
    pub fn decision_hash(&self) -> Result<Sha256Digest, serial::Error> {
        let doc = serial::to_value(&decision_view(&self.body.document))?;
        let libraries = serial::to_value(&self.body.libraries)?;
        let value = map(vec![(k("document"), doc), (k("libraries"), libraries)])?;
        let bytes = cbor::encode(&value).map_err(serial::Error::Encode)?;
        Ok(Sha256::digest(&bytes).into())
    }
}

#[cfg(test)]
mod tests;
