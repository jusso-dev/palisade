//! Migrations between major versions of the policy schema (#30, #330).
//!
//! A minor version only adds optional fields, so any reader of a major
//! reads every minor of it ([`SchemaVersion::is_readable_by`]). A major
//! version is a breaking change, and a document written for an older major
//! is brought up to [`CURRENT`](crate::schema::CURRENT) by migrations.
//!
//! Each [`Step`] migrates a document from one major version to the next:
//! `migrate(vN) -> vN+1`. Steps are pure functions from a JSON object to a
//! JSON object; they read no clock, file or setting, so a document always
//! migrates to the same result. [`migrate`] applies every step from the
//! document's major to the current one, in order, and returns a document of
//! the current major unchanged, so migrating twice gives the same result as
//! migrating once.
//!
//! A migration only rewrites the shape of a document. It never decides
//! what an unknown field means: a field the steps do not know is left in
//! place, and the strict reader then rejects the migrated document, as it
//! rejects any other document with an unknown field. A migrated document
//! is therefore never more permissive than its author wrote (ADR 0018).
//!
//! # Versions
//!
//! - **v0** (`0.y.z`) is the draft model of #30, from before the first
//!   release. It differs from v1 in two ways, which [`v0_to_v1`] rewrites:
//!   - `schema_version` is a field of `policy`, not of the document;
//!   - a rule's effect flags are called `flags`; v1 calls them `effects`,
//!     with the same fields.
//! - **v1** is the current version, described by `schemas/policy/v1.json`.
//!
//! # Reading
//!
//! [`read_json`] reads a document of any supported major version: it reads
//! the JSON, rejecting repeated object keys as the strict reader does,
//! migrates it, and then reads the result with the strict model. Use
//! [`PolicyDocument::from_json`] where only the current major is
//! acceptable.
//!
//! # Tests
//!
//! `tests/fixtures/migrate/v{N}/` holds documents written for major `N`.
//! For every document in `v{N}/`, the step from `N` gives the document of
//! the same name in `v{N+1}/`, and [`migrate`] gives the one in the
//! current version's directory, which the strict reader accepts and which
//! validates. `tests/fixtures/migrate/rejected/` holds documents that
//! [`read_json`] refuses, with the error each one gives.

use core::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::model::{PolicyDocument, SchemaVersion};
use crate::schema::CURRENT;

/// A JSON object: the form a document has while it is migrated.
pub type Object = Map<String, Value>;

/// One migration, from major version `from` to `from + 1`.
#[derive(Clone, Copy, Debug)]
pub struct Step {
    /// The major version the step reads.
    pub from: u64,
    /// Rewrites a document of major `from` as a document of major
    /// `from + 1`, including its `schema_version`.
    pub apply: fn(Object) -> Result<Object, StepError>,
}

/// Every migration, in order: entry `i` migrates from major `i`.
pub const STEPS: &[Step] = &[Step {
    from: 0,
    apply: v0_to_v1,
}];

/// Why a step could not migrate a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepError {
    /// JSON Pointer (RFC 6901) to the value the step could not rewrite.
    pub pointer: String,
    /// A human-readable explanation.
    pub message: String,
}

impl fmt::Display for StepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.pointer, self.message)
    }
}

impl std::error::Error for StepError {}

/// A document could not be migrated or read.
#[derive(Debug)]
pub enum MigrateError {
    /// The input is not JSON, repeats an object key, or the migrated
    /// document does not match the current model.
    Json(serde_json::Error),
    /// `schema_version` is missing or not a version string.
    MissingSchemaVersion,
    /// The document's major version is newer than this reader, or no step
    /// migrates from it.
    UnsupportedSchemaVersion(SchemaVersion),
    /// A step could not rewrite the document.
    Step {
        /// The major version the step migrates from.
        from: u64,
        /// What went wrong.
        error: StepError,
    },
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid policy document: {e}"),
            Self::MissingSchemaVersion => {
                f.write_str("invalid policy document: missing or invalid `schema_version`")
            }
            Self::UnsupportedSchemaVersion(v) => write!(
                f,
                "unsupported schema version {v}: this reader migrates versions up to {CURRENT}"
            ),
            Self::Step { from, error } => {
                write!(f, "cannot migrate from version {from}: {error}")
            }
        }
    }
}

impl std::error::Error for MigrateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Step { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// A document read by [`read_json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Migrated {
    /// The document, in the current version.
    pub document: PolicyDocument,
    /// The version it was written for.
    pub from: SchemaVersion,
}

impl Migrated {
    /// Whether the document needed a migration.
    #[must_use]
    pub const fn was_migrated(&self) -> bool {
        self.from.major != CURRENT.major
    }
}

/// The version a document was written for.
///
/// That is the document's `schema_version`. A v0 document has none, and
/// keeps its version in `policy.schema_version` instead; that place is only
/// read for a major version of 0.
///
/// # Errors
///
/// [`MigrateError::MissingSchemaVersion`] if neither place holds a version
/// string.
pub fn schema_version(document: &Value) -> Result<SchemaVersion, MigrateError> {
    let parse = |v: &Value| v.as_str().and_then(|s| s.parse::<SchemaVersion>().ok());
    if let Some(v) = document.get("schema_version") {
        return parse(v).ok_or(MigrateError::MissingSchemaVersion);
    }
    document
        .get("policy")
        .and_then(|p| p.get("schema_version"))
        .and_then(parse)
        .filter(|v| v.major == 0)
        .ok_or(MigrateError::MissingSchemaVersion)
}

/// Migrates a document to the current major version.
///
/// A document of the current major is returned unchanged.
///
/// # Errors
///
/// Returns [`MigrateError`] if the document has no version, is newer than
/// this reader, or a step cannot rewrite it.
pub fn migrate(document: Value) -> Result<Value, MigrateError> {
    let version = schema_version(&document)?;
    if version.major > CURRENT.major {
        return Err(MigrateError::UnsupportedSchemaVersion(version));
    }
    // `schema_version` only finds a version in an object.
    let Value::Object(mut object) = document else {
        return Err(MigrateError::MissingSchemaVersion);
    };
    for major in version.major..CURRENT.major {
        let step = STEPS
            .iter()
            .find(|s| s.from == major)
            .ok_or(MigrateError::UnsupportedSchemaVersion(version))?;
        object = (step.apply)(object).map_err(|error| MigrateError::Step { from: major, error })?;
    }
    Ok(Value::Object(object))
}

/// Reads a policy document of any supported major version from JSON, and
/// migrates it to the current one.
///
/// Repeated object keys are rejected, as [`PolicyDocument::from_json`]
/// rejects them. The migrated document is read in strict mode, so an
/// unknown field is an error.
///
/// # Errors
///
/// Returns [`MigrateError`] if the input is not JSON, cannot be migrated,
/// or does not match the model once migrated.
pub fn read_json(input: &str) -> Result<Migrated, MigrateError> {
    let UniqueValue(value) = serde_json::from_str(input).map_err(MigrateError::Json)?;
    let from = schema_version(&value)?;
    let value = migrate(value)?;
    let document = PolicyDocument::deserialize(value).map_err(MigrateError::Json)?;
    Ok(Migrated { document, from })
}

/// v0 to v1.
///
/// - `policy.schema_version` is removed, and the document's
///   `schema_version` is set to `1.0.0`.
/// - Each rule's `flags` is renamed `effects`. A rule with both is
///   refused, because which one the author meant is unknown.
///
/// Anything else is left as it is.
///
/// # Errors
///
/// Returns [`StepError`] if a rule has both `flags` and `effects`.
pub fn v0_to_v1(mut document: Object) -> Result<Object, StepError> {
    if let Some(Value::Object(policy)) = document.get_mut("policy") {
        policy.remove("schema_version");
    }
    if let Some(Value::Array(sets)) = document.get_mut("rule_sets") {
        for (s, set) in sets.iter_mut().enumerate() {
            let Some(Value::Array(rules)) = set.get_mut("rules") else {
                continue;
            };
            for (r, rule) in rules.iter_mut().enumerate() {
                let Value::Object(rule) = rule else {
                    continue;
                };
                let Some(flags) = rule.remove("flags") else {
                    continue;
                };
                if rule.contains_key("effects") {
                    return Err(StepError {
                        pointer: format!("/rule_sets/{s}/rules/{r}/flags"),
                        message: "a rule has `flags` (v0) and `effects` (v1); keep one".to_owned(),
                    });
                }
                rule.insert("effects".to_owned(), flags);
            }
        }
    }
    document.insert(
        "schema_version".to_owned(),
        SchemaVersion::new(1, 0, 0).to_string().into(),
    );
    Ok(document)
}

/// A JSON value read with every object key unique. `serde_json::Value`
/// keeps the last of repeated keys, which would let two readers disagree
/// about one document.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor).map(Self)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(UniqueValue(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom(format_args!("duplicate key `{key}`")));
            }
            let UniqueValue(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests;
