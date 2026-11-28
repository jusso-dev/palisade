//! The versioned JSON Schema (2020-12) of [`PolicyDocument`].
//!
//! The schema is generated from the Rust types, so it cannot drift from
//! them. The generated text is committed at `schemas/policy/v{major}.json`,
//! and the test `committed_schema_is_current` fails when the committed file
//! differs from what [`generate`] produces. Regenerate it with:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-policy --test schema
//! ```
//!
//! # Versioning
//!
//! [`CURRENT`] is the version this crate writes and the major version it
//! reads. A minor bump adds optional fields; a major bump is a breaking
//! change, gets a new file (`v2.json`) and a migration step
//! ([`crate::migrate`]). The schema's `$id` names the major version only, because every
//! minor version of a major is a valid instance of the latest schema for
//! that major.

use crate::model::{PolicyDocument, SchemaVersion};

/// The schema version this crate implements.
pub const CURRENT: SchemaVersion = SchemaVersion::new(1, 0, 0);

/// The schema's `$id`.
pub const SCHEMA_ID: &str = "https://github.com/jusso-dev/palisade/schemas/policy/v1.json";

/// Generates the JSON Schema of a policy document.
#[must_use]
pub fn generate() -> serde_json::Value {
    let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let mut schema = generator.into_root_schema_for::<PolicyDocument>();
    let object = schema.ensure_object();
    object.insert("$id".to_owned(), SCHEMA_ID.into());
    object.insert("title".to_owned(), "Palisade policy document".into());
    object.insert("x-schema-version".to_owned(), CURRENT.to_string().into());
    sort_keys(schema.to_value())
}

/// Rebuilds every object with its keys in sorted order, so the committed
/// text does not depend on whether `serde_json`'s `preserve_order` feature
/// happens to be enabled elsewhere in the build.
pub(crate) fn sort_keys(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries
                .into_iter()
                .map(|(k, v)| (k, sort_keys(v)))
                .collect::<serde_json::Map<_, _>>()
                .into()
        }
        serde_json::Value::Array(items) => items.into_iter().map(sort_keys).collect(),
        other => other,
    }
}

/// The generated schema as the exact text that is committed: pretty-printed
/// JSON with a trailing newline.
///
/// # Errors
///
/// Only fails if serialising a JSON value fails, which does not happen.
pub fn generate_pretty() -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&generate())?;
    text.push('\n');
    Ok(text)
}
