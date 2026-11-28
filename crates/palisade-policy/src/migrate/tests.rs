use proptest::prelude::*;
use serde_json::{Value, json};

use super::*;
use crate::model::arbitrary;

fn object(v: Value) -> Object {
    match v {
        Value::Object(o) => o,
        _ => panic!("not an object"),
    }
}

/// Writes a v1 document in the v0 shape: the inverse of [`v0_to_v1`].
fn to_v0(doc: &PolicyDocument, version: &str) -> Value {
    let mut v = serde_json::to_value(doc).unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("schema_version");
    o["policy"]
        .as_object_mut()
        .unwrap()
        .insert("schema_version".to_owned(), version.into());
    if let Some(Value::Array(sets)) = o.get_mut("rule_sets") {
        for set in sets {
            if let Some(Value::Array(rules)) = set.get_mut("rules") {
                for rule in rules {
                    let rule = rule.as_object_mut().unwrap();
                    if let Some(effects) = rule.remove("effects") {
                        rule.insert("flags".to_owned(), effects);
                    }
                }
            }
        }
    }
    v
}

#[test]
fn every_major_below_the_current_one_has_one_step_in_order() {
    let froms: Vec<u64> = STEPS.iter().map(|s| s.from).collect();
    let expected: Vec<u64> = (0..CURRENT.major).collect();
    assert_eq!(froms, expected);
}

#[test]
fn v0_to_v1_moves_the_version_and_renames_flags() {
    let v0 = object(json!({
        "policy": {"schema_version": "0.2.0", "name": "p"},
        "rule_sets": [
            {"rules": [{"flags": {"log": "always"}}, {"name": "no flags"}]},
            {"name": "no rules"},
        ],
    }));
    let v1 = v0_to_v1(v0).unwrap();
    assert_eq!(
        Value::Object(v1),
        json!({
            "schema_version": "1.0.0",
            "policy": {"name": "p"},
            "rule_sets": [
                {"rules": [{"effects": {"log": "always"}}, {"name": "no flags"}]},
                {"name": "no rules"},
            ],
        })
    );
}

#[test]
fn v0_to_v1_leaves_shapes_it_does_not_know_for_the_strict_reader() {
    // Not objects or arrays where the step looks: left as they are, so the
    // strict reader reports them.
    for doc in [
        json!({"policy": 1, "rule_sets": 2}),
        json!({"rule_sets": [1, {"rules": 3}, {"rules": [4]}]}),
    ] {
        let mut expected = doc.clone();
        expected["schema_version"] = "1.0.0".into();
        assert_eq!(Value::Object(v0_to_v1(object(doc)).unwrap()), expected);
    }
}

#[test]
fn v0_to_v1_refuses_a_rule_with_flags_and_effects() {
    let v0 = object(json!({
        "rule_sets": [{}, {"rules": [{}, {"flags": {}, "effects": {}}]}],
    }));
    let e = v0_to_v1(v0).unwrap_err();
    assert_eq!(e.pointer, "/rule_sets/1/rules/1/flags");
    assert_eq!(
        e.to_string(),
        "/rule_sets/1/rules/1/flags: a rule has `flags` (v0) and `effects` (v1); keep one"
    );
}

#[test]
fn the_version_is_read_from_the_document_then_from_a_v0_policy() {
    let v = |doc: Value| schema_version(&doc).map(|v| v.to_string());
    assert_eq!(v(json!({"schema_version": "1.2.3"})).unwrap(), "1.2.3");
    assert_eq!(
        v(json!({"policy": {"schema_version": "0.4.0"}})).unwrap(),
        "0.4.0"
    );
    // The document's version wins, and must be valid.
    assert_eq!(
        v(json!({"schema_version": "1.0.0", "policy": {"schema_version": "0.1.0"}})).unwrap(),
        "1.0.0"
    );
    for bad in [
        json!({"schema_version": "1.0"}),
        json!({"schema_version": 1}),
        json!({"schema_version": "x", "policy": {"schema_version": "0.1.0"}}),
        // Only a v0 version may be in the policy.
        json!({"policy": {"schema_version": "1.0.0"}}),
        json!({"policy": {"schema_version": 0}}),
        json!({"policy": 1}),
        json!({}),
        json!([]),
        json!("0.1.0"),
    ] {
        assert!(
            matches!(
                schema_version(&bad),
                Err(MigrateError::MissingSchemaVersion)
            ),
            "{bad}"
        );
    }
}

#[test]
fn migrate_refuses_a_newer_major() {
    let e = migrate(json!({"schema_version": "2.0.0"})).unwrap_err();
    assert!(matches!(e, MigrateError::UnsupportedSchemaVersion(v) if v.major == 2));
}

#[test]
fn migrate_reports_the_failing_step() {
    let doc = json!({
        "policy": {"schema_version": "0.1.0"},
        "rule_sets": [{"rules": [{"flags": {}, "effects": {}}]}],
    });
    let e = migrate(doc).unwrap_err();
    assert!(matches!(&e, MigrateError::Step { from: 0, .. }));
    assert_eq!(
        e.to_string(),
        "cannot migrate from version 0: /rule_sets/0/rules/0/flags: a rule has `flags` (v0) and `effects` (v1); keep one"
    );
    assert!(std::error::Error::source(&e).is_some());
}

#[test]
fn read_json_rejects_repeated_keys_at_any_depth() {
    for text in [
        r#"{"schema_version": "1.0.0", "schema_version": "1.0.0"}"#,
        r#"{"policy": {"schema_version": "0.1.0", "a": [{"b": 1, "b": 2}]}}"#,
    ] {
        let e = read_json(text).unwrap_err();
        assert!(matches!(&e, MigrateError::Json(_)), "{text}: {e}");
        assert!(e.to_string().contains("duplicate key"), "{e}");
        assert!(std::error::Error::source(&e).is_some());
    }
}

#[test]
fn read_json_reads_every_json_value_kind() {
    // Numbers of each kind, booleans, null and nested arrays reach the
    // strict reader unchanged; it then rejects what the model does not
    // allow.
    let e = read_json(
        r#"{"policy": {"schema_version": "0.1.0", "x": [true, null, -1, 1, 0.5, "s", []]}}"#,
    )
    .unwrap_err();
    assert!(e.to_string().contains("unknown field `x`"), "{e}");
    assert!(matches!(read_json("[1"), Err(MigrateError::Json(_))));
}

#[test]
fn errors_display_their_cause() {
    assert_eq!(
        MigrateError::MissingSchemaVersion.to_string(),
        "invalid policy document: missing or invalid `schema_version`"
    );
    assert_eq!(
        MigrateError::UnsupportedSchemaVersion(SchemaVersion::new(3, 1, 0)).to_string(),
        "unsupported schema version 3.1.0: this reader migrates versions up to 1.0.0"
    );
    assert!(std::error::Error::source(&MigrateError::MissingSchemaVersion).is_none());
}

#[test]
fn a_current_document_is_not_marked_migrated() {
    let text = include_str!("../../tests/fixtures/valid/minimal.json");
    let read = read_json(text).unwrap();
    assert!(!read.was_migrated());
    assert_eq!(read.document, PolicyDocument::from_json(text).unwrap());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn migrating_a_current_document_changes_nothing(doc in arbitrary::document_with_lifecycle()) {
        let v = serde_json::to_value(&doc).unwrap();
        let once = migrate(v.clone()).unwrap();
        prop_assert_eq!(&once, &v);
        // Idempotent: migrating again changes nothing either.
        prop_assert_eq!(migrate(once).unwrap(), v);
    }

    #[test]
    fn a_v0_document_migrates_to_the_v1_document_it_was_written_from(
        doc in arbitrary::document_with_lifecycle(),
        minor in 0u64..20,
    ) {
        let v0 = to_v0(&doc, &format!("0.{minor}.0"));
        let read = read_json(&v0.to_string()).unwrap();
        prop_assert!(read.was_migrated());
        prop_assert_eq!(read.from, SchemaVersion::new(0, minor, 0));
        prop_assert_eq!(&read.document, &doc);
        // Migrating the result again changes nothing.
        let migrated = migrate(v0).unwrap();
        prop_assert_eq!(migrate(migrated.clone()).unwrap(), migrated);
    }

    #[test]
    fn read_json_never_panics(text in "\\PC{0,200}") {
        let _ = read_json(&text);
    }
}
