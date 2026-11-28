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
    for version in ["0.9.0", "1.4.0", "2.0.0"] {
        let mut v = base();
        v["schema_version"] = version.into();
        cases.push(("unreadable version", v));
    }
    for (name, value) in cases {
        assert_eq!(check(&value), (false, false), "{name}");
    }
}

/// `policy.kid` (1.3): both sides need a 1.3 label for it, and refuse a
/// key ID that is not 32 lowercase hex digits.
#[test]
fn schema_and_validate_agree_on_policy_kid() {
    let (schemas, index) = compiled();
    let check = |value: &serde_json::Value| {
        let by_schema = schemas.validate(value, index).is_ok();
        let by_rust = serde_json::from_value::<Event>(value.clone())
            .map(|e| e.validate().is_ok())
            .unwrap_or(false);
        (by_schema, by_rust)
    };
    let with = |label: &str, kid: &str| {
        let mut v = base();
        v["schema_version"] = label.into();
        v["policy"] = serde_json::json!({ "version": 3, "kid": kid });
        v
    };
    let kid = "06e3fd8fda29bb60ab59557de61edb0a";
    for label in ["1.3.0", "1.3.4"] {
        assert_eq!(check(&with(label, kid)), (true, true), "{label}");
    }
    for label in ["1.0.0", "1.1.0", "1.2.0", "1.2.9"] {
        assert_eq!(check(&with(label, kid)), (false, false), "{label}");
    }
    for bad in [
        "",
        "06E3FD8FDA29BB60AB59557DE61EDB0A",
        "06e3fd8fda29bb60ab59557de61edb0",
        "06e3fd8fda29bb60ab59557de61edb0a00",
        "06e3fd8fda29bb60ab59557de61edb0g",
    ] {
        assert_eq!(check(&with("1.3.0", bad)), (false, false), "{bad:?}");
    }
    // Without `kid`, a policy is fine under any readable label.
    let mut v = base();
    v["policy"] = serde_json::json!({ "version": 3 });
    assert_eq!(check(&v), (true, true));
}

fn base_11() -> serde_json::Value {
    let mut v = base();
    v["schema_version"] = "1.1.0".into();
    v
}

/// The 1.1 rules, checked by both sides: version labels, the third-party
/// source format, and the rules inside the new field sets.
#[test]
fn schema_and_validate_agree_on_the_1_1_rules() {
    let (schemas, index) = compiled();
    let check = |value: &serde_json::Value| {
        let by_schema = schemas.validate(value, index).is_ok();
        let by_rust = serde_json::from_value::<Event>(value.clone())
            .map(|e| e.validate().is_ok())
            .unwrap_or(false);
        (by_schema, by_rust)
    };
    let with = |label: &str, key: &str, val: serde_json::Value| {
        let mut v = base_11();
        v["schema_version"] = label.into();
        v[key] = val;
        v
    };
    let mut good = Vec::new();
    let mut bad = Vec::new();
    // A 1.0 event is valid under either label.
    good.push(("1.0 event, 1.0 label", base()));
    good.push(("1.0 event, 1.1 label", base_11()));
    // Each 1.1 part needs a 1.1 label.
    for (key, val) in [
        ("network", serde_json::json!({ "remote_port": 1 })),
        ("device", serde_json::json!({})),
        ("registry", serde_json::json!({})),
        ("elevation", serde_json::json!({})),
        ("approval", serde_json::json!({})),
        ("admin", serde_json::json!({})),
        ("identity", serde_json::json!({})),
        ("audit_policy", serde_json::json!({})),
        ("restriction", serde_json::json!({})),
        ("probe", serde_json::json!({})),
        ("fim", serde_json::json!({})),
        (
            "source",
            serde_json::json!({ "kind": "third_party", "format": "generic" }),
        ),
        (
            "source",
            serde_json::json!({ "kind": "os_security", "rule_name": "R" }),
        ),
        ("script", serde_json::json!({ "inline": true, "text": "x" })),
    ] {
        good.push((key, with("1.1.0", key, val.clone())));
        good.push((key, with("1.1.3", key, val.clone())));
        bad.push((key, with("1.0.0", key, val.clone())));
        bad.push((key, with("1.0.9", key, val)));
    }
    let mut v = with("1.0.0", "process", serde_json::json!({}));
    v["event_type"] = "process.created".into();
    v.as_object_mut().unwrap().remove("file");
    bad.push(("1.1 type with 1.0 label", v.clone()));
    v["schema_version"] = "1.1.0".into();
    good.push(("1.1 type with 1.1 label", v));
    // Rules inside the 1.1 sets.
    for (name, key, val) in [
        (
            "third_party without format",
            "source",
            serde_json::json!({ "kind": "third_party" }),
        ),
        (
            "format on another kind",
            "source",
            serde_json::json!({ "kind": "os_security", "format": "generic" }),
        ),
        (
            "resolution without hostname",
            "network",
            serde_json::json!({ "resolution": "dns" }),
        ),
        (
            "value name and default",
            "registry",
            serde_json::json!({ "value_name": "a", "default_value": true }),
        ),
        (
            "default_value false",
            "registry",
            serde_json::json!({ "default_value": false }),
        ),
        (
            "truncated without preview",
            "registry",
            serde_json::json!({ "new": { "truncated": true } }),
        ),
        (
            "add with old",
            "admin",
            serde_json::json!({ "changes": [{ "op": "add", "path": "/a", "old": 1, "new": 1 }] }),
        ),
        (
            "replace without new",
            "admin",
            serde_json::json!({ "changes": [{ "op": "replace", "path": "/a", "old": 1 }] }),
        ),
        (
            "null in a JSON value",
            "admin",
            serde_json::json!({ "before": { "a": null } }),
        ),
        (
            "float in a JSON value",
            "admin",
            serde_json::json!({ "before": 1.5 }),
        ),
        (
            "bad pointer",
            "admin",
            serde_json::json!({ "changes": [{ "op": "add", "path": "a", "new": 1 }] }),
        ),
        (
            "short root name",
            "registry",
            serde_json::json!({ "key": "HKLM\\SOFTWARE" }),
        ),
        (
            "uppercase host",
            "network",
            serde_json::json!({ "remote_hostname": "A.example" }),
        ),
        (
            "port out of range",
            "network",
            serde_json::json!({ "remote_port": 65536 }),
        ),
        (
            "repeated set member",
            "audit_policy",
            serde_json::json!({ "changes": ["success_added", "success_added"] }),
        ),
    ] {
        bad.push((name, with("1.1.0", key, val)));
    }
    for (name, key, val) in [
        (
            "hostname and resolution",
            "network",
            serde_json::json!({ "remote_hostname": "a.example", "resolution": "dns" }),
        ),
        (
            "default value",
            "registry",
            serde_json::json!({ "key": "HKEY_USERS\\S-1-5-18", "default_value": true }),
        ),
        (
            "truncated with preview",
            "registry",
            serde_json::json!({ "old": { "preview": "x", "truncated": true } }),
        ),
        (
            "well-formed changes",
            "admin",
            serde_json::json!({ "changes": [
            { "op": "add", "path": "/a", "new": [1, "x"] },
            { "op": "remove", "path": "/b~1c", "old": { "k": true } },
            { "op": "replace", "path": "/d", "old": 1, "new": 18446744073709551615u64 }
        ] }),
        ),
        (
            "set in order",
            "audit_policy",
            serde_json::json!({ "changes": ["success_added", "failure_removed"] }),
        ),
    ] {
        good.push((name, with("1.1.0", key, val)));
    }
    for (name, value) in good {
        assert_eq!(check(&value), (true, true), "{name}: {value}");
    }
    for (name, value) in bad {
        assert_eq!(check(&value), (false, false), "{name}: {value}");
    }
}

/// The schema's own `since` table covers every property that the 1.0
/// schema did not have, so a new field cannot slip in unversioned.
#[test]
fn every_new_schema_path_has_a_version() {
    let schema = schema::generate();
    let defs = schema["$defs"].as_object().unwrap();
    let mut paths = Vec::new();
    collect_paths(&schema, defs, "", &mut paths, 0);
    let v1_0: std::collections::BTreeSet<&str> = V1_0_PATHS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    for path in &paths {
        if v1_0.contains(path.as_str()) {
            continue;
        }
        assert!(
            palisade_proto::events::pointer_since(path) > palisade_proto::events::V1_0,
            "{path} is not in the 1.0 schema and has no `since` in `ADDED`"
        );
    }
    // And every 1.0 path is still there.
    for path in &v1_0 {
        assert!(paths.iter().any(|p| p == path), "1.0 field {path} is gone");
    }
}

fn collect_paths(
    node: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    at: &str,
    out: &mut Vec<String>,
    depth: usize,
) {
    if depth > 12 {
        return;
    }
    let mut node = node;
    while let Some(r) = node.get("$ref").and_then(|r| r.as_str()) {
        let name = r.trim_start_matches("#/$defs/");
        if name == "JsonValue" {
            return;
        }
        node = &defs[name];
    }
    if let Some(items) = node.get("items") {
        collect_paths(items, defs, at, out, depth + 1);
    }
    if let Some(props) = node.get("properties").and_then(|p| p.as_object()) {
        for (key, child) in props {
            let path = format!("{at}/{key}");
            out.push(path.clone());
            collect_paths(child, defs, &path, out, depth + 1);
        }
    }
}

/// Every property path of the 1.0 schema (`schemas/events/v1.json` as #254
/// published it). Arrays are transparent: `/file/signers/publisher`.
const V1_0_PATHS: &str = include_str!("fixtures/schema_1_0_paths.txt");
