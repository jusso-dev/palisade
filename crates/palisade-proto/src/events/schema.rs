//! The versioned JSON Schema (2020-12) of [`Event`].
//!
//! The schema is generated from the Rust types and the registry, so it cannot
//! drift from them. The generated text is committed at
//! `schemas/events/v{major}.json`, and the test `committed_schema_is_current`
//! fails when the committed file differs from what [`generate`] produces.
//! Regenerate it with:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-proto --test events_schema
//! ```
//!
//! Besides the shape of every field, the schema states the cross-field rules
//! that [`Event::validate`] checks, so a consumer that only has the schema
//! enforces them too:
//!
//! - each `event_type` fixes its `category` and the field sets it requires;
//! - `prev_hash` is present exactly when `seq` is not 0;
//! - a script is a file or inline, not both.
//!
//! The `$id` names the major version only: every minor version of a major is
//! a valid instance of the newest schema for that major (see the
//! compatibility rules in [`crate::events`]).

use serde_json::{Map, Value, json};

use super::{CURRENT, Event, EventType};

/// The schema's `$id`.
pub const SCHEMA_ID: &str = "https://github.com/jusso-dev/palisade/schemas/events/v1.json";

/// Generates the JSON Schema of an event.
#[must_use]
pub fn generate() -> Value {
    let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let mut schema = generator.into_root_schema_for::<Event>();
    let object = schema.ensure_object();
    object.insert("$id".to_owned(), SCHEMA_ID.into());
    object.insert("title".to_owned(), "Palisade canonical event".into());
    object.insert("x-schema-version".to_owned(), CURRENT.to_string().into());
    object.insert("allOf".to_owned(), Value::Array(cross_field_rules()));
    sort_keys(schema.to_value())
}

/// The rules between fields, as `if`/`then` clauses.
fn cross_field_rules() -> Vec<Value> {
    let mut rules: Vec<Value> = EventType::ALL
        .iter()
        .map(|t| {
            let required: Vec<&str> = t.required().iter().map(|s| s.as_str()).collect();
            let category = serde_json::to_value(t.category()).unwrap_or(Value::Null);
            json!({
                "if": {
                    "properties": { "event_type": { "const": t.as_str() } },
                    "required": ["event_type"]
                },
                "then": {
                    "properties": { "category": { "const": category } },
                    "required": required
                }
            })
        })
        .collect();
    rules.push(json!({
        "if": {
            "properties": { "seq": { "const": 0 } },
            "required": ["seq"]
        },
        "then": { "not": { "required": ["prev_hash"] } },
        "else": { "required": ["prev_hash"] }
    }));
    rules.push(json!({
        "properties": {
            "script": {
                "not": {
                    "properties": { "inline": { "const": true } },
                    "required": ["path", "inline"]
                }
            }
        }
    }));
    rules
}

/// Rebuilds every object with its keys in sorted order, so the committed
/// text does not depend on whether `serde_json`'s `preserve_order` feature
/// happens to be enabled elsewhere in the build.
fn sort_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries
                .into_iter()
                .map(|(k, v)| (k, sort_keys(v)))
                .collect::<Map<_, _>>()
                .into()
        }
        Value::Array(items) => items.into_iter().map(sort_keys).collect(),
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
