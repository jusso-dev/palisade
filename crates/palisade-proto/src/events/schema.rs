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
//! - a script is either a file (`path`) or `inline`: exactly one;
//! - no field may be `null`: unset optional fields are left out;
//! - an event labelled with an older minor version than a field set, field,
//!   event type or source kind it uses is invalid (the `since` versions);
//! - `source.format` is present exactly when `source.kind` is `third_party`;
//! - `network.resolution` needs `network.remote_hostname`;
//! - a registry value has a `value_name` or is the `default_value`, not
//!   both, and `truncated` data has a `preview`;
//! - an admin change has exactly the `old` and `new` values its `op` needs.
//!
//! The `$id` names the major version only: every minor version of a major is
//! a valid instance of the newest schema for that major (see the
//! compatibility rules in [`crate::events`]).

use serde_json::{Map, Value, json};

use super::{ADDED, CURRENT, Event, EventType, SchemaVersion, SourceKind};

/// The schema's `$id`.
pub const SCHEMA_ID: &str = "https://github.com/jusso-dev/palisade/schemas/events/v1.json";

/// Generates the JSON Schema of an event.
#[must_use]
pub fn generate() -> Value {
    let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
    let mut schema = generator.into_root_schema_for::<Event>();
    // No field of the model is nullable: an unset optional field is left
    // out, and readers reject `null`. So the `null` alternatives that the
    // generator adds for `Option` fields are removed, and `required` then
    // means "present with a value" in the schema as it does in the reader.
    let mut no_null = schemars::transform::RecursiveTransform(drop_null);
    schemars::transform::Transform::transform(&mut no_null, &mut schema);
    let object = schema.ensure_object();
    object.insert("$id".to_owned(), SCHEMA_ID.into());
    object.insert("title".to_owned(), "Palisade canonical event".into());
    object.insert("x-schema-version".to_owned(), CURRENT.to_string().into());
    object.insert("allOf".to_owned(), Value::Array(cross_field_rules()));
    if let Some(Value::Object(defs)) = object.get_mut("$defs") {
        for (name, def) in rule_defs() {
            defs.insert(name.to_owned(), def);
        }
    }
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
    let inline = json!({
        "properties": { "inline": { "const": true } },
        "required": ["inline"]
    });
    rules.push(json!({
        "properties": {
            "script": {
                "if": { "required": ["path"] },
                "then": { "not": inline },
                "else": inline
            }
        }
    }));
    rules.extend(version_rules());
    rules.push(json!({
        "properties": {
            "source": {
                "if": {
                    "properties": { "kind": { "const": "third_party" } },
                    "required": ["kind"]
                },
                "then": { "required": ["format"] },
                "else": { "not": { "required": ["format"] } }
            },
            "network": {
                "if": { "required": ["resolution"] },
                "then": { "required": ["remote_hostname"] }
            },
            "registry": {
                "not": { "required": ["value_name", "default_value"] },
                "properties": {
                    "old": { "$ref": "#/$defs/RegistryDataRule" },
                    "new": { "$ref": "#/$defs/RegistryDataRule" }
                }
            },
            "admin": {
                "properties": {
                    "changes": { "items": { "$ref": "#/$defs/ChangeRule" } }
                }
            }
        }
    }));
    rules
}

/// Extra definitions the cross-field rules refer to.
fn rule_defs() -> Vec<(&'static str, Value)> {
    vec![
        (
            "RegistryDataRule",
            json!({
                "description": "`truncated` data has a `preview`.",
                "if": { "required": ["truncated"] },
                "then": { "required": ["preview"] }
            }),
        ),
        (
            "ChangeRule",
            json!({
                "description": "`add` has `new` only, `remove` `old` only, `replace` both.",
                "oneOf": [
                    {
                        "properties": { "op": { "const": "add" } },
                        "required": ["new"],
                        "not": { "required": ["old"] }
                    },
                    {
                        "properties": { "op": { "const": "remove" } },
                        "required": ["old"],
                        "not": { "required": ["new"] }
                    },
                    {
                        "properties": { "op": { "const": "replace" } },
                        "required": ["old", "new"]
                    }
                ]
            }),
        ),
    ]
}

/// A pattern for every `schema_version` of the current major older than
/// `version`. Minor versions are compared as numbers.
fn older_than(version: SchemaVersion) -> String {
    let minors: Vec<String> = (0..version.minor).map(|m| m.to_string()).collect();
    format!(
        "^{}\\.({})\\.(0|[1-9][0-9]*)$",
        version.major,
        minors.join("|")
    )
}

/// The `since` rules: an event that uses a part added in a minor version
/// may not be labelled with an older one.
fn version_rules() -> Vec<Value> {
    let mut rules = Vec::new();
    let label_older = |v: SchemaVersion| {
        json!({
            "properties": { "schema_version": { "pattern": older_than(v) } },
            "required": ["schema_version"]
        })
    };
    // Fields and field sets, by pointer: forbidden under an older label.
    for (pointer, since) in ADDED {
        if since.minor == 0 {
            continue;
        }
        let mut keys: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
        let Some(leaf) = keys.pop() else { continue };
        let mut forbid = json!({ "not": { "required": [leaf] } });
        while let Some(key) = keys.pop() {
            forbid = json!({ "properties": { key: forbid } });
        }
        rules.push(json!({ "if": label_older(*since), "then": forbid }));
    }
    // Event types and source kinds added in a minor version.
    let mut by_version: std::collections::BTreeMap<SchemaVersion, Vec<&str>> =
        std::collections::BTreeMap::new();
    for t in EventType::ALL.iter().filter(|t| t.since().minor > 0) {
        by_version.entry(t.since()).or_default().push(t.as_str());
    }
    for (since, names) in by_version {
        rules.push(json!({
            "if": label_older(since),
            "then": { "properties": { "event_type": { "not": { "enum": names } } } }
        }));
    }
    let mut kinds: std::collections::BTreeMap<SchemaVersion, Vec<&str>> =
        std::collections::BTreeMap::new();
    for k in SourceKind::ALL.iter().filter(|k| k.since().minor > 0) {
        kinds.entry(k.since()).or_default().push(k.as_str());
    }
    for (since, names) in kinds {
        rules.push(json!({
            "if": label_older(since),
            "then": {
                "properties": {
                    "source": { "properties": { "kind": { "not": { "enum": names } } } }
                }
            }
        }));
    }
    rules
}

/// Removes the `null` alternative from one schema object: `"type": [T,
/// "null"]` becomes `"type": T`, and `"anyOf": [S, {"type": "null"}]`
/// becomes `S`.
fn drop_null(schema: &mut schemars::Schema) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(Value::Array(types)) = object.get_mut("type") {
        types.retain(|t| t != "null");
        if let [only] = types.as_slice() {
            let only = only.clone();
            object.insert("type".to_owned(), only);
        }
    }
    let single = match object.get_mut("anyOf") {
        Some(Value::Array(options)) => {
            options.retain(|o| o.get("type").is_none_or(|t| t != "null"));
            match options.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            }
        }
        _ => None,
    };
    if let Some(Value::Object(only)) = single {
        object.remove("anyOf");
        for (k, v) in only {
            object.entry(k).or_insert(v);
        }
    }
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
