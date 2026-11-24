//! Data-driven mapping of OS-native log records to canonical events (#196).
//!
//! A mapping file says, for one source log, which canonical [`EventType`] each
//! source event ID becomes, with which `action`, `outcome` and `mode`, and
//! which source field fills which canonical field. The shipped files are in
//! `crates/palisade-proto/mappings/` and load with [`MappingSet::builtin`].
//!
//! The input is a decoded [`Record`]: the source event ID, the record's system
//! values, and its event data as a flat map from field name to text. Decoding
//! raw log records into that form, and grouping a decision record with its
//! per-signature records by correlation activity ID, belong to the collector
//! (#58, #90). This module only translates.
//!
//! # File format
//!
//! ```yaml
//! schema_version: 1.0.0          # the event schema major version it targets
//! source: os_code_integrity      # a `source.kind` value
//! entries:
//!   - source_event_id: 3077
//!     when:                      # optional: the entry applies only if this holds
//!       field: SISigningScenario
//!       equals: ["0"]            # or `ends_with: [".sys"]`; case-insensitive
//!     canonical_type: driver.decision
//!     action: load
//!     outcome: blocked
//!     mode: enforce              # optional
//!     severity: 7                # optional; default from the registry
//!     description: The OS code integrity policy blocked a kernel driver.
//!     field_map:                 # source field: canonical JSON Pointer (or a list)
//!       FileName: /file/path
//!     signatures:                # optional: correlated per-signature records
//!       source_event_id: 3089
//!       count_field: TotalSignatureCount
//!       index_field: Signature
//!       field_map:
//!         PublisherName: publisher
//! ```
//!
//! Entries for the same source event ID are tried in file order, and the
//! first whose `when` holds is used. Only the last entry for an ID may omit
//! `when`, and it is then the fallback.
//!
//! # Checks when a file is loaded
//!
//! [`MappingSet::from_yaml`] rejects a file, with the entry and field named,
//! when:
//!
//! - it is not strict YAML, has unknown keys, or targets another schema
//!   major version;
//! - a `canonical_type` is not registered;
//! - a target is not a writable canonical field (the table in `targets.rs`); this is how a
//!   mapping that references a field that does not exist fails CI;
//! - an entry cannot fill a field set its type requires from its
//!   `field_map` (signer records do not count: an unsigned file has none);
//! - a `*.decision` entry maps none of the subject fields or none of the
//!   object-name fields that [`Event::ism_0585_gaps`] accepts (ISM-0585);
//! - a `when` has an empty or repeated value, or a value that an earlier
//!   entry for the same event ID and field already matches (so the entry
//!   could never apply to it), or an entry follows the fallback.
//!
//! Every shipped file is loaded by the tests, so these checks run in CI.

mod targets;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::events::{
    CURRENT, Description, Event, EventError, EventMode, EventType, FieldSet, Guid, Host, Labels,
    Outcome, SchemaVersion, Severity, Sha256Hex, SourceKind, TenantId, Timestamp, Token, Uuid7,
};
use targets::{Kind, SIGNERS_POINTER};

/// The shipped mapping files, by name.
pub const BUILTIN: &[(&str, &str)] = &[
    (
        "os_code_integrity.yaml",
        include_str!("../../mappings/os_code_integrity.yaml"),
    ),
    (
        "os_legacy_rule_collection.yaml",
        include_str!("../../mappings/os_legacy_rule_collection.yaml"),
    ),
];

/// Most entries in one mapping file.
pub const MAX_ENTRIES: usize = 1024;
/// Most fields in one record.
pub const MAX_RECORD_FIELDS: usize = 256;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// One decoded source log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The source's event ID.
    pub event_id: u32,
    /// When the source recorded it.
    pub time_created: Timestamp,
    /// The source's record number.
    pub record_id: Option<u64>,
    /// The log channel the record was read from.
    pub channel: Option<String>,
    /// The correlation activity ID.
    pub activity_id: Option<Guid>,
    /// The event data, by field name, as text. Binary fields are hex.
    /// The record's system user and process are included as
    /// `System.UserID` and `System.ProcessID` when the record has them.
    /// An empty value counts as absent.
    pub fields: BTreeMap<String, String>,
}

/// The envelope values that the producing agent owns. A source log never
/// supplies these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// The new event's ID.
    pub event_id: Uuid7,
    /// The tenant.
    pub tenant_id: TenantId,
    /// The device.
    pub host: Host,
    /// The producer's next sequence number.
    pub seq: u64,
    /// The chain value of the producer's previous event.
    pub prev_hash: Option<Sha256Hex>,
    /// Whether the producer's clock is synchronised.
    pub clock_synced: bool,
    /// The producer's monotonic clock, in microseconds.
    pub ts_agent_monotonic: Option<u64>,
    /// The producer's measured clock offset.
    pub clock_skew_ms: Option<i64>,
    /// Labels from policy tags.
    pub labels: Labels,
}

/// A source field that was present but could not be used. The event is still
/// produced without it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dropped {
    /// The source field, or `<field>[<index>]` for the signature record with
    /// that (0-based) index.
    pub field: String,
    /// Why it was dropped.
    pub reason: &'static str,
}

/// A mapped event, with any source fields that had to be dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapped {
    /// The canonical event. It has passed [`Event::validate`].
    pub event: Event,
    /// Source fields that were present but unusable.
    pub dropped: Vec<Dropped>,
    /// Signature records that the record announced but that did not arrive,
    /// as `(received, announced)`. `None` when complete or not applicable.
    pub signatures_incomplete: Option<(usize, u64)>,
}

/// A record could not be mapped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    /// No mapping for this source event ID.
    Unmapped {
        /// The source.
        source: SourceKind,
        /// The source event ID.
        event_id: u32,
    },
    /// The record has too many fields.
    TooManyFields,
    /// A signature record is not the kind the entry expects, or the records
    /// disagree (activity ID, duplicate index, more than announced).
    BadSignatures(String),
    /// The mapped event breaks a schema rule, usually because a required
    /// field set had no usable source field.
    Invalid(Vec<EventError>),
    /// The mapped event does not deserialise. This indicates a bug in the
    /// mapping engine or an envelope value out of range.
    Build(String),
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmapped { source, event_id } => {
                write!(f, "no mapping for {} event {event_id}", source.as_str())
            }
            Self::TooManyFields => write!(f, "the record has more than {MAX_RECORD_FIELDS} fields"),
            Self::BadSignatures(why) => write!(f, "signature records: {why}"),
            Self::Invalid(errors) => {
                f.write_str("the mapped event is invalid:")?;
                for e in errors {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            Self::Build(why) => write!(f, "the mapped event could not be built: {why}"),
        }
    }
}

impl std::error::Error for MapError {}

// ---------------------------------------------------------------------------
// File model
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    schema_version: SchemaVersion,
    source: SourceKind,
    entries: Vec<EntryDoc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryDoc {
    source_event_id: u32,
    #[serde(default)]
    when: Option<When>,
    canonical_type: EventType,
    action: Token,
    outcome: Outcome,
    #[serde(default)]
    mode: Option<EventMode>,
    #[serde(default)]
    severity: Option<Severity>,
    description: Description,
    #[serde(default)]
    field_map: BTreeMap<String, Targets>,
    #[serde(default)]
    signatures: Option<SignaturesDoc>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Targets {
    One(String),
    Many(Vec<String>),
}

impl Targets {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(t) => vec![t],
            Self::Many(t) => t,
        }
    }
}

/// A condition on one source field. Comparison is ASCII case-insensitive.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct When {
    field: String,
    #[serde(default)]
    equals: Vec<String>,
    #[serde(default)]
    ends_with: Vec<String>,
}

impl When {
    /// Whether the condition holds. An empty field value counts as absent,
    /// so it never matches. Values are lowercased when the file is loaded.
    fn holds(&self, record: &Record) -> bool {
        let Some(value) = record.fields.get(&self.field).filter(|v| !v.is_empty()) else {
            return false;
        };
        let value = value.to_ascii_lowercase();
        self.equals.contains(&value) || self.ends_with.iter().any(|v| value.ends_with(v.as_str()))
    }

    /// Lowercases the values and rejects empty or repeated ones.
    fn normalise(&mut self) -> Result<(), String> {
        if self.field.is_empty() || (self.equals.is_empty() && self.ends_with.is_empty()) {
            return Err(
                "needs a `field` and at least one `equals` or `ends_with` value".to_owned(),
            );
        }
        for list in [&mut self.equals, &mut self.ends_with] {
            let mut seen = BTreeSet::new();
            for v in list.iter_mut() {
                if v.is_empty() {
                    return Err(
                        "an empty value matches nothing, because empty fields count as absent"
                            .to_owned(),
                    );
                }
                *v = v.to_ascii_lowercase();
                if !seen.insert(v.clone()) {
                    return Err(format!("`{v}` is listed twice"));
                }
            }
        }
        Ok(())
    }

    /// A value of `self` that an earlier condition `before` already
    /// matches, so the entry with `self` would never see it. Conditions on
    /// different fields cannot be compared, and file order decides.
    fn shadowed_by(&self, before: &Self) -> Option<String> {
        if self.field != before.field {
            return None;
        }
        let matched_before = |v: &str| {
            before.equals.iter().any(|b| b == v)
                || before.ends_with.iter().any(|b| v.ends_with(b.as_str()))
        };
        // Any text that ends with `v` also ends with every suffix of `v`.
        let suffix_before = |v: &str| before.ends_with.iter().any(|b| v.ends_with(b.as_str()));
        self.equals
            .iter()
            .find(|v| matched_before(v))
            .map(|v| format!("equals `{v}`"))
            .or_else(|| {
                self.ends_with
                    .iter()
                    .find(|v| suffix_before(v))
                    .map(|v| format!("ends_with `{v}`"))
            })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignaturesDoc {
    source_event_id: u32,
    count_field: String,
    index_field: String,
    field_map: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Loaded model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Entry {
    when: Option<When>,
    event_type: EventType,
    action: Token,
    outcome: Outcome,
    mode: Option<EventMode>,
    severity: Severity,
    description: Description,
    /// Source field, target pointer, kind.
    fields: Vec<(String, String, Kind)>,
    signatures: Option<Signatures>,
}

#[derive(Clone, Debug)]
struct Signatures {
    event_id: u32,
    count_field: String,
    index_field: String,
    /// Source field, signer field, kind.
    fields: Vec<(String, String, Kind)>,
}

/// A loaded, checked set of mappings.
#[derive(Clone, Debug, Default)]
pub struct MappingSet {
    entries: BTreeMap<(SourceKind, u32), Vec<Entry>>,
}

/// A mapping file was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadError {
    /// The file name.
    pub file: String,
    /// Where in the file, for example `entries[3].field_map.FileName`.
    pub location: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.location.is_empty() {
            write!(f, "{}: {}", self.file, self.message)
        } else {
            write!(f, "{}: {}: {}", self.file, self.location, self.message)
        }
    }
}

impl std::error::Error for LoadError {}

/// The pointer prefix of a field set.
const fn set_prefix(set: FieldSet) -> &'static str {
    match set {
        FieldSet::User => "/user/",
        FieldSet::Policy => "/policy/",
        FieldSet::Process => "/process/",
        FieldSet::File => "/file/",
        FieldSet::Script => "/script/",
        FieldSet::Native => "/native/",
        FieldSet::Agent => "/agent/",
    }
}

/// Targets that identify the subject of a decision, for ISM-0585. These are
/// the fields [`Event::ism_0585_gaps`] accepts.
const SUBJECT_TARGETS: &[&str] = &[
    "/user/sid",
    "/user/name",
    "/process/pid",
    "/process/image_path",
];

/// Targets that name the object of a decision, for ISM-0585. These are the
/// fields [`Event::ism_0585_gaps`] accepts.
const OBJECT_NAME_TARGETS: &[&str] = &[
    "/file/path",
    "/file/package_name",
    "/script/path",
    "/native/clsid",
];

impl MappingSet {
    /// The shipped mappings.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] if a shipped file is invalid. The tests load
    /// every shipped file, so this does not happen in a released build.
    pub fn builtin() -> Result<Self, LoadError> {
        let mut set = Self::default();
        for (name, text) in BUILTIN {
            set.add_yaml(name, text)?;
        }
        Ok(set)
    }

    /// Loads one mapping file.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] if the file breaks any rule in the
    /// [module documentation](self).
    pub fn from_yaml(name: &str, text: &str) -> Result<Self, LoadError> {
        let mut set = Self::default();
        set.add_yaml(name, text)?;
        Ok(set)
    }

    /// Adds one mapping file to the set.
    ///
    /// # Errors
    ///
    /// As [`MappingSet::from_yaml`], and also if the file maps a source event
    /// ID that another file in the set already maps.
    pub fn add_yaml(&mut self, name: &str, text: &str) -> Result<(), LoadError> {
        let err = |location: String, message: String| LoadError {
            file: name.to_owned(),
            location,
            message,
        };
        let value =
            palisade_policy::dsl::to_json_value(text, &palisade_policy::dsl::Limits::DEFAULT)
                .map_err(|e| err(String::new(), e.to_string()))?;
        let doc: FileDoc =
            serde_json::from_value(value).map_err(|e| err(String::new(), e.to_string()))?;
        if doc.schema_version.major != CURRENT.major || doc.schema_version.minor > CURRENT.minor {
            return Err(err(
                "schema_version".to_owned(),
                format!(
                    "targets event schema {}, but this crate implements {CURRENT}",
                    doc.schema_version
                ),
            ));
        }
        if doc.entries.len() > MAX_ENTRIES {
            return Err(err(
                "entries".to_owned(),
                format!("more than {MAX_ENTRIES} entries"),
            ));
        }
        let mut loaded: BTreeMap<u32, Vec<Entry>> = BTreeMap::new();
        for (i, entry) in doc.entries.into_iter().enumerate() {
            let at = |field: &str| format!("entries[{i}]{field}");
            let id = entry.source_event_id;
            let list = loaded.entry(id).or_default();
            if list.last().is_some_and(|e| e.when.is_none()) {
                return Err(err(
                    at(""),
                    format!(
                        "event {id} already has a fallback entry (one without `when`), so this entry is unreachable"
                    ),
                ));
            }
            let built = build_entry(entry).map_err(|(field, message)| err(at(&field), message))?;
            if let Some(when) = &built.when {
                for earlier in list.iter().filter_map(|e| e.when.as_ref()) {
                    if let Some(value) = when.shadowed_by(earlier) {
                        return Err(err(
                            at(".when"),
                            format!(
                                "{value} is already matched by an earlier entry for event {id}, so it can never apply here"
                            ),
                        ));
                    }
                }
            }
            list.push(built);
        }
        // Check every key before inserting any, so a rejected file leaves
        // the set unchanged.
        if let Some(id) = loaded
            .keys()
            .find(|id| self.entries.contains_key(&(doc.source, **id)))
        {
            return Err(err(
                "entries".to_owned(),
                format!(
                    "{} event {id} is already mapped by another file",
                    doc.source.as_str()
                ),
            ));
        }
        for (id, list) in loaded {
            self.entries.insert((doc.source, id), list);
        }
        Ok(())
    }

    /// The source event IDs mapped for a source, in order.
    #[must_use]
    pub fn event_ids(&self, source: SourceKind) -> Vec<u32> {
        self.entries
            .keys()
            .filter(|(s, _)| *s == source)
            .map(|(_, id)| *id)
            .collect()
    }

    /// The canonical types a source event ID can map to, in entry order.
    #[must_use]
    pub fn canonical_types(&self, source: SourceKind, event_id: u32) -> Vec<EventType> {
        self.entries
            .get(&(source, event_id))
            .map(|list| list.iter().map(|e| e.event_type).collect())
            .unwrap_or_default()
    }

    /// Maps one record, with its correlated signature records, to an event.
    ///
    /// `signatures` are the per-signature records with the same correlation
    /// activity ID, in any order. They are ignored for entries that do not
    /// take signatures.
    ///
    /// # Errors
    ///
    /// Returns [`MapError`] if no entry applies, the signature records do
    /// not fit the record, or the result is not a valid event.
    pub fn map(
        &self,
        source: SourceKind,
        record: &Record,
        signatures: &[Record],
        envelope: &Envelope,
    ) -> Result<Mapped, MapError> {
        if record.fields.len() > MAX_RECORD_FIELDS {
            return Err(MapError::TooManyFields);
        }
        let entry = self
            .entries
            .get(&(source, record.event_id))
            .and_then(|list| {
                list.iter()
                    .find(|e| e.when.as_ref().is_none_or(|w| w.holds(record)))
            })
            .ok_or(MapError::Unmapped {
                source,
                event_id: record.event_id,
            })?;
        let mut dropped = Vec::new();
        let mut event = envelope_value(envelope)?;
        let put = |event: &mut Map<String, Value>, key: &str, value: Value| {
            event.insert(key.to_owned(), value);
        };
        put(
            &mut event,
            "schema_version",
            Value::String(CURRENT.to_string()),
        );
        put(
            &mut event,
            "event_type",
            Value::String(entry.event_type.as_str().to_owned()),
        );
        put(
            &mut event,
            "category",
            to_value(&entry.event_type.category())?,
        );
        put(
            &mut event,
            "action",
            Value::String(entry.action.as_str().to_owned()),
        );
        put(&mut event, "outcome", to_value(&entry.outcome)?);
        if let Some(mode) = entry.mode {
            put(&mut event, "mode", to_value(&mode)?);
        }
        put(&mut event, "severity", Value::from(entry.severity.get()));
        put(
            &mut event,
            "description",
            Value::String(entry.description.as_str().to_owned()),
        );
        put(
            &mut event,
            "ts",
            Value::String(record.time_created.to_string()),
        );
        put(&mut event, "source", source_value(source, record)?);

        for (field, pointer, kind) in &entry.fields {
            let Some(raw) = record.fields.get(field) else {
                continue;
            };
            match kind.read(raw) {
                Ok(Some(value)) => insert_at(&mut event, pointer, value),
                Ok(None) => {}
                Err(reason) => dropped.push(Dropped {
                    field: field.clone(),
                    reason,
                }),
            }
        }

        let mut signatures_incomplete = None;
        if let Some(spec) = &entry.signatures {
            let (signers, incomplete) = map_signers(spec, record, signatures, &mut dropped)?;
            if !signers.is_empty() {
                insert_at(&mut event, SIGNERS_POINTER, Value::Array(signers));
            }
            signatures_incomplete = incomplete;
        }

        let event: Event = serde_json::from_value(Value::Object(event))
            .map_err(|e| MapError::Build(e.to_string()))?;
        event.validate().map_err(MapError::Invalid)?;
        Ok(Mapped {
            event,
            dropped,
            signatures_incomplete,
        })
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, MapError> {
    serde_json::to_value(value).map_err(|e| MapError::Build(e.to_string()))
}

fn envelope_value(envelope: &Envelope) -> Result<Map<String, Value>, MapError> {
    let mut map = Map::new();
    map.insert("event_id".to_owned(), to_value(&envelope.event_id)?);
    map.insert("tenant_id".to_owned(), to_value(&envelope.tenant_id)?);
    map.insert("host".to_owned(), to_value(&envelope.host)?);
    map.insert("seq".to_owned(), Value::from(envelope.seq));
    if let Some(prev) = &envelope.prev_hash {
        map.insert("prev_hash".to_owned(), to_value(prev)?);
    }
    map.insert(
        "clock_synced".to_owned(),
        Value::Bool(envelope.clock_synced),
    );
    if let Some(m) = envelope.ts_agent_monotonic {
        map.insert("ts_agent_monotonic".to_owned(), Value::from(m));
    }
    if let Some(skew) = envelope.clock_skew_ms {
        map.insert("clock_skew_ms".to_owned(), Value::from(skew));
    }
    if !envelope.labels.is_empty() {
        map.insert("labels".to_owned(), to_value(&envelope.labels)?);
    }
    Ok(map)
}

fn source_value(source: SourceKind, record: &Record) -> Result<Value, MapError> {
    let mut map = Map::new();
    map.insert("kind".to_owned(), to_value(&source)?);
    map.insert("event_id".to_owned(), Value::from(record.event_id));
    if let Some(id) = record.record_id {
        map.insert("record_id".to_owned(), Value::from(id));
    }
    if let Some(channel) = record.channel.as_deref().filter(|c| !c.is_empty()) {
        // An over-long channel name is a decoder bug; leave it out rather than
        // lose the event.
        if channel.chars().count() <= 256 {
            map.insert("channel".to_owned(), Value::String(channel.to_owned()));
        }
    }
    if let Some(activity) = record.activity_id {
        map.insert("activity_id".to_owned(), to_value(&activity)?);
    }
    Ok(Value::Object(map))
}

/// Inserts `value` at a JSON Pointer of plain object keys, creating objects
/// on the way.
fn insert_at(root: &mut Map<String, Value>, pointer: &str, value: Value) {
    let mut keys = pointer.trim_start_matches('/').split('/').peekable();
    let mut node = root;
    while let Some(key) = keys.next() {
        if keys.peek().is_none() {
            node.insert(key.to_owned(), value);
            return;
        }
        let child = node
            .entry(key.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        if !child.is_object() {
            *child = Value::Object(Map::new());
        }
        let Value::Object(next) = child else { return };
        node = next;
    }
}

type Incomplete = Option<(usize, u64)>;

/// Reads the signature records of one record.
///
/// The OS reports each signature as one record carrying the total count and
/// a 0-based index (`0 .. count`). An unsigned file is reported as exactly
/// one record with a count of 0.
fn map_signers(
    spec: &Signatures,
    record: &Record,
    children: &[Record],
    dropped: &mut Vec<Dropped>,
) -> Result<(Vec<Value>, Incomplete), MapError> {
    let bad = |why: String| MapError::BadSignatures(why);
    let max = u64::try_from(crate::events::MAX_SIGNERS).unwrap_or(u64::MAX);
    // Bound the work before looking at any record.
    if children.len() > crate::events::MAX_SIGNERS {
        return Err(bad(format!(
            "{} records, more than the {max} signatures an event can hold",
            children.len()
        )));
    }
    let mut indexed: BTreeMap<u64, &Record> = BTreeMap::new();
    let mut announced: Option<u64> = None;
    for child in children {
        if child.fields.len() > MAX_RECORD_FIELDS {
            return Err(bad(format!(
                "a record has more than {MAX_RECORD_FIELDS} fields"
            )));
        }
        if child.event_id != spec.event_id {
            return Err(bad(format!(
                "expected event {}, got event {}",
                spec.event_id, child.event_id
            )));
        }
        if child.activity_id != record.activity_id || record.activity_id.is_none() {
            return Err(bad("the activity ID does not match the record's".to_owned()));
        }
        let number = |field: &str| -> Result<u64, MapError> {
            let raw = child.fields.get(field).map_or("", String::as_str);
            match Kind::Unsigned(u64::from(u32::MAX)).read(raw) {
                Ok(Some(Value::Number(n))) => n
                    .as_u64()
                    .ok_or_else(|| bad(format!("`{field}` is not a number"))),
                _ => Err(bad(format!("`{field}` is missing or not a number"))),
            }
        };
        let count = number(&spec.count_field)?;
        if announced.is_some_and(|a| a != count) {
            return Err(bad("the records disagree on the signature count".to_owned()));
        }
        announced = Some(count);
        if count > max {
            return Err(bad(format!(
                "{count} announced signatures, more than {max}"
            )));
        }
        if count == 0 {
            if children.len() > 1 {
                return Err(bad(
                    "an unsigned file is reported by exactly one record".to_owned()
                ));
            }
            continue;
        }
        let index = number(&spec.index_field)?;
        if index >= count {
            return Err(bad(format!(
                "signature index {index} is not below the count {count}"
            )));
        }
        if indexed.insert(index, child).is_some() {
            return Err(bad(format!("signature index {index} appears twice")));
        }
    }
    let announced = announced.unwrap_or(0);
    let mut signers = Vec::new();
    for (&index, child) in &indexed {
        let mut signer = Map::new();
        for (field, target, kind) in &spec.fields {
            let Some(raw) = child.fields.get(field) else {
                continue;
            };
            match kind.read(raw) {
                Ok(Some(value)) => {
                    signer.insert(target.clone(), value);
                }
                Ok(None) => {}
                Err(reason) => dropped.push(Dropped {
                    field: format!("{field}[{index}]"),
                    reason,
                }),
            }
        }
        if !signer.is_empty() {
            signers.push(Value::Object(signer));
        }
    }
    let received = indexed.len();
    let incomplete =
        (u64::try_from(received).unwrap_or(u64::MAX) < announced).then_some((received, announced));
    Ok((signers, incomplete))
}

/// Checks one entry and resolves its targets. On error, returns the field
/// path within the entry and a message.
fn build_entry(mut doc: EntryDoc) -> Result<Entry, (String, String)> {
    if let Some(when) = &mut doc.when {
        when.normalise().map_err(|m| (".when".to_owned(), m))?;
    }
    let mut fields = Vec::new();
    let mut targets_seen = BTreeSet::new();
    for (source, targets) in doc.field_map {
        if source.is_empty() {
            return Err((
                ".field_map".to_owned(),
                "a source field name is empty".to_owned(),
            ));
        }
        let targets = targets.into_vec();
        if targets.is_empty() {
            return Err((format!(".field_map.{source}"), "names no target".to_owned()));
        }
        for target in targets {
            let kind = targets::event_target(&target).ok_or_else(|| {
                (
                    format!(".field_map.{source}"),
                    format!("`{target}` is not a writable canonical field"),
                )
            })?;
            if !targets_seen.insert(target.clone()) {
                return Err((
                    format!(".field_map.{source}"),
                    format!("`{target}` is filled by more than one source field"),
                ));
            }
            fields.push((source.clone(), target, kind));
        }
    }
    let signatures = match doc.signatures {
        None => None,
        Some(sig) => {
            if sig.count_field.is_empty() || sig.index_field.is_empty() {
                return Err((
                    ".signatures".to_owned(),
                    "needs `count_field` and `index_field`".to_owned(),
                ));
            }
            let mut sig_fields = Vec::new();
            let mut seen = BTreeSet::new();
            for (source, target) in sig.field_map {
                let kind = targets::signer_target(&target).ok_or_else(|| {
                    (
                        format!(".signatures.field_map.{source}"),
                        format!("`{target}` is not a writable signer field"),
                    )
                })?;
                if !seen.insert(target.clone()) {
                    return Err((
                        format!(".signatures.field_map.{source}"),
                        format!("`{target}` is filled by more than one source field"),
                    ));
                }
                sig_fields.push((source, target, kind));
            }
            if sig_fields.is_empty() {
                return Err((
                    ".signatures.field_map".to_owned(),
                    "maps no field".to_owned(),
                ));
            }
            Some(Signatures {
                event_id: sig.source_event_id,
                count_field: sig.count_field,
                index_field: sig.index_field,
                fields: sig_fields,
            })
        }
    };
    // Signer records do not fill a field set: an unsigned file has none.
    let fills = |prefix: &str| targets_seen.iter().any(|t| t.starts_with(prefix));
    for &set in doc.canonical_type.required() {
        if !fills(set_prefix(set)) {
            return Err((
                ".field_map".to_owned(),
                format!(
                    "`{}` requires the `{}` field set, and no target fills it",
                    doc.canonical_type.as_str(),
                    set.as_str()
                ),
            ));
        }
    }
    if doc.canonical_type.as_str().ends_with(".decision") {
        if !SUBJECT_TARGETS.iter().any(|t| targets_seen.contains(*t)) {
            return Err((
                ".field_map".to_owned(),
                "a decision must map its subject: a user SID or name, or a process ID or image path (ISM-0585)".to_owned(),
            ));
        }
        if !OBJECT_NAME_TARGETS
            .iter()
            .any(|t| targets_seen.contains(*t))
        {
            return Err((
                ".field_map".to_owned(),
                "a decision must map the name of its object: a file path, package name, script path or class ID (ISM-0585)".to_owned(),
            ));
        }
    }
    let severity = doc
        .severity
        .unwrap_or_else(|| doc.canonical_type.default_severity());
    Ok(Entry {
        when: doc.when,
        event_type: doc.canonical_type,
        action: doc.action,
        outcome: doc.outcome,
        mode: doc.mode,
        severity,
        description: doc.description,
        fields,
        signatures,
    })
}
