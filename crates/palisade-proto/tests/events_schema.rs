//! The committed event JSON Schema.
//!
//! - `committed_schema_is_current` fails if `schemas/events/v1.json` differs
//!   from the schema generated from the Rust types. Regenerate it with
//!   `PALISADE_BLESS=1 cargo test -p palisade-proto --test events_schema`.
//! - The schema itself states the cross-field rules, and rejects the same
//!   broken events that `Event::validate` rejects.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

use palisade_proto::events::{CURRENT, Event, schema};

const SCHEMA_PATH: &str = "../../schemas/events/v1.json";

#[test]
fn committed_schema_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(SCHEMA_PATH);
    let generated = schema::generate_pretty().unwrap();
    if std::env::var_os("PALISADE_BLESS").is_some() {
        fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "{} is stale. Regenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-proto --test events_schema",
        path.display()
    );
}

#[test]
fn schema_declares_its_draft_id_and_version() {
    let value = schema::generate();
    assert_eq!(
        value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(value["$id"], schema::SCHEMA_ID);
    assert_eq!(value["x-schema-version"], CURRENT.to_string());
    assert!(schema::SCHEMA_ID.ends_with(&format!("/v{}.json", CURRENT.major)));
}

fn compiled() -> (boon::Schemas, boon::SchemaIndex) {
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler.enable_format_assertions();
    compiler
        .add_resource(schema::SCHEMA_ID, schema::generate())
        .unwrap();
    let index = compiler.compile(schema::SCHEMA_ID, &mut schemas).unwrap();
    (schemas, index)
}

fn base() -> serde_json::Value {
    let id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";
    serde_json::json!({
        "schema_version": "1.0.0",
        "event_id": id,
        "event_type": "exec.decision",
        "category": "execution",
        "action": "execute",
        "outcome": "blocked",
        "severity": 6,
        "description": "Blocked.",
        "ts": "2026-11-24T03:15:22.123456Z",
        "clock_synced": true,
        "tenant_id": id,
        "host": { "id": id },
        "seq": 1,
        "prev_hash": "00".repeat(32),
        "file": { "path": "C:\\a.exe" }
    })
}

#[test]
fn schema_and_validate_agree_on_cross_field_rules() {
    let (schemas, index) = compiled();
    let check = |value: &serde_json::Value| {
        let by_schema = schemas.validate(value, index).is_ok();
        let by_rust = serde_json::from_value::<Event>(value.clone())
            .map(|e| e.validate().is_ok())
            .unwrap_or(false);
        (by_schema, by_rust)
    };
    assert_eq!(check(&base()), (true, true));
    for script in [
        serde_json::json!({ "path": "a.ps1" }),
        serde_json::json!({ "inline": true }),
    ] {
        let mut v = base();
        v["script"] = script.clone();
        assert_eq!(check(&v), (true, true), "{script}");
    }
    let mut v = base();
    v["user"] = serde_json::json!({ "sid": "S-1-0x000100000000-1" });
    assert_eq!(check(&v), (true, true), "hex authority sid");
    let mut cases = Vec::new();
    let mut v = base();
    v["category"] = "script".into();
    cases.push(("category mismatch", v));
    let mut v = base();
    v.as_object_mut().unwrap().remove("file");
    cases.push(("missing required field set", v));
    let mut v = base();
    v.as_object_mut().unwrap().remove("prev_hash");
    cases.push(("seq 1 without prev_hash", v));
    let mut v = base();
    v["seq"] = 0.into();
    cases.push(("seq 0 with prev_hash", v));
    let mut v = base();
    v["script"] = serde_json::json!({ "path": "a.ps1", "inline": true });
    cases.push(("script path and inline", v));
    let mut v = base();
    v["event_type"] = "exec.nope".into();
    cases.push(("unknown type", v));
    let mut v = base();
    v["severity"] = 11.into();
    cases.push(("severity 11", v));
    let mut v = base();
    v["ts"] = "2026-11-24T03:15:22Z".into();
    cases.push(("timestamp without micros", v));
    let mut v = base();
    v["file"]["hashes"] = serde_json::json!({ "sha256": "AB".repeat(32) });
    cases.push(("uppercase hash", v));
    let mut v = base();
    v["extra"] = 1.into();
    cases.push(("unknown field", v));
    let mut v = base();
    v["prev_hash"] = serde_json::Value::Null;
    cases.push(("seq 1 with null prev_hash", v));
    let mut v = base();
    v["file"] = serde_json::Value::Null;
    cases.push(("required field set null", v));
    let mut v = base();
    v["mode"] = serde_json::Value::Null;
    cases.push(("optional field null", v));
    let mut v = base();
    v["script"] = serde_json::json!({});
    cases.push(("script with neither path nor inline", v));
    let mut v = base();
    v["script"] = serde_json::json!({ "path": null, "inline": true });
    cases.push(("script with null path", v));
    let mut v = base();
    v["ts"] = "2026-11-24T23:59:60.000000Z".into();
    cases.push(("leap second", v));
    let mut v = base();
    v["user"] = serde_json::json!({ "sid": "s-1-5-18" });
    cases.push(("lowercase sid", v));
    for (name, value) in cases {
        assert_eq!(check(&value), (false, false), "{name}");
    }
}
