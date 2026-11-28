use proptest::prelude::*;
use serde_json::{Value, json};

use super::*;
use crate::model::arbitrary;

const EVERY_ACTION: &str = include_str!("../../tests/fixtures/valid/actions-and-effects.json");

fn fixture() -> Value {
    serde_json::from_str(EVERY_ACTION).unwrap()
}

/// The rule at `/rule_sets/{s}/rules/{r}`.
fn rule(doc: &mut Value, s: usize, r: usize) -> &mut Value {
    &mut doc["rule_sets"][s]["rules"][r]
}

/// Makes a rule unreadable with a criterion field from a newer minor.
fn unknown_criterion(doc: &mut Value, s: usize, r: usize) {
    rule(doc, s, r)["match"] =
        json!({"criterion": {"field": "future.field", "operator": "equals", "values": ["x"]}});
}

#[test]
fn a_readable_document_reads_as_the_strict_reader_reads_it() {
    let read = read_json(EVERY_ACTION).unwrap();
    assert_eq!(
        read.document,
        PolicyDocument::from_json(EVERY_ACTION).unwrap()
    );
    assert!(read.ignored.is_empty());
    assert_eq!(read.from, crate::schema::CURRENT);
}

#[test]
fn unknown_governance_fields_are_set_aside_with_their_values() {
    let mut doc = fixture();
    doc["schema_version"] = "1.7.0".into();
    doc["policy"]["metadata"] = json!({"owner": "it", "cost_centre": "42"});
    doc["policy"]["governance"] = json!({"stale_after_days": 30, "auto_close": true});
    doc["rule_sets"][0]["metadata"] = json!({"steward": {"name": "x"}});
    // A known field with a value this reader cannot read is set aside too.
    rule(&mut doc, 0, 0)["metadata"] = json!({"risk_rating": "extreme", "ticket_ref": "T-1"});
    let read = read_json(&doc.to_string()).unwrap();
    let pointers: Vec<(&str, &Value)> = read
        .ignored
        .iter()
        .map(|i| {
            assert_eq!(i.kind, IgnoredKind::GovernanceField);
            assert!(!i.reason.is_empty());
            (i.pointer.as_str(), &i.value)
        })
        .collect();
    assert_eq!(
        pointers,
        vec![
            ("/policy/metadata/cost_centre", &json!("42")),
            ("/policy/governance/auto_close", &json!(true)),
            ("/rule_sets/0/metadata/steward", &json!({"name": "x"})),
            (
                "/rule_sets/0/rules/0/metadata/risk_rating",
                &json!("extreme")
            ),
        ]
    );
    let d = &read.document;
    assert_eq!(d.policy.metadata.owner.as_deref(), Some("it"));
    assert_eq!(d.policy.governance.stale_after_days, 30);
    assert_eq!(
        d.rule_sets[0].rules[0].metadata.ticket_ref.as_deref(),
        Some("T-1")
    );
    assert_eq!(read.from, SchemaVersion::new(1, 7, 0));
    // What decides is exactly what the author wrote.
    let mut original = PolicyDocument::from_json(EVERY_ACTION).unwrap();
    original.schema_version = SchemaVersion::new(1, 7, 0);
    assert_eq!(d.decision_relevant(), original.decision_relevant());
}

#[test]
fn field_names_are_escaped_in_pointers() {
    let mut doc = fixture();
    doc["policy"]["metadata"] = json!({"a/b~c": 1});
    let read = read_json(&doc.to_string()).unwrap();
    assert_eq!(read.ignored[0].pointer, "/policy/metadata/a~1b~0c");
}

#[test]
fn unreadable_rules_that_never_let_an_object_run_are_set_aside() {
    // audit (1/1), trust_source (4/0), ignore (5/0) and defer (5/1).
    let mut doc = fixture();
    for (s, r) in [(1, 1), (4, 0), (5, 0), (5, 1)] {
        unknown_criterion(&mut doc, s, r);
    }
    let read = read_json(&doc.to_string()).unwrap();
    let set_aside: Vec<(&str, IgnoredKind)> = read
        .ignored
        .iter()
        .map(|i| (i.pointer.as_str(), i.kind))
        .collect();
    assert_eq!(
        set_aside,
        vec![
            ("/rule_sets/1/rules/1", IgnoredKind::Rule(ActionKind::Audit)),
            (
                "/rule_sets/4/rules/0",
                IgnoredKind::Rule(ActionKind::TrustSource)
            ),
            (
                "/rule_sets/5/rules/0",
                IgnoredKind::Rule(ActionKind::Ignore)
            ),
            ("/rule_sets/5/rules/1", IgnoredKind::Rule(ActionKind::Defer)),
        ]
    );
    assert_eq!(read.ignored[0].value, *rule(&mut doc, 1, 1));
    assert!(read.ignored[0].reason.contains("future.field"));
    let sets = &read.document.rule_sets;
    assert_eq!(
        sets.iter().map(|s| s.rules.len()).collect::<Vec<_>>(),
        vec![1, 1, 1, 1, 0, 0]
    );
}

#[test]
fn an_unreadable_rule_that_could_relax_a_decision_refuses_the_document() {
    // deny (0/0), allow (1/0), allow_contained (2/0), allow_elevated (3/0).
    for (s, r, kind) in [
        (0, 0, ActionKind::Deny),
        (1, 0, ActionKind::Allow),
        (2, 0, ActionKind::AllowContained),
        (3, 0, ActionKind::AllowElevated),
    ] {
        let mut doc = fixture();
        unknown_criterion(&mut doc, s, r);
        let e = read_json(&doc.to_string()).unwrap_err();
        let LenientError::UnreadableRule {
            pointer, action, ..
        } = &e
        else {
            panic!("{e}");
        };
        assert_eq!(pointer, &format!("/rule_sets/{s}/rules/{r}"));
        assert_eq!(*action, Some(kind));
        assert!(
            e.to_string().starts_with(&format!(
                "/rule_sets/{s}/rules/{r}: an unreadable `{}` rule could relax a decision",
                kind.as_str()
            )),
            "{e}"
        );
        assert!(std::error::Error::source(&e).is_none());
    }
}

#[test]
fn a_rule_with_an_unknown_action_refuses_the_document() {
    for action in [
        json!({"type": "allow_sandboxed"}),
        json!({"type": 1}),
        json!({}),
        json!("allow"),
    ] {
        let mut doc = fixture();
        rule(&mut doc, 1, 1)["action"] = action.clone();
        let e = read_json(&doc.to_string()).unwrap_err();
        assert!(
            matches!(&e, LenientError::UnreadableRule { action: None, .. }),
            "{action}: {e}"
        );
        assert!(e.to_string().contains("unknown action"), "{e}");
    }
    let mut doc = fixture();
    rule(&mut doc, 1, 1)
        .as_object_mut()
        .unwrap()
        .remove("action");
    assert!(matches!(
        read_json(&doc.to_string()),
        Err(LenientError::UnreadableRule { action: None, .. })
    ));
}

#[test]
fn a_known_option_of_a_permissive_action_is_not_skipped() {
    // A new option on a deny may make it apply more widely: refused.
    let mut doc = fixture();
    rule(&mut doc, 0, 0)["action"]["block_children"] = true.into();
    assert!(matches!(
        read_json(&doc.to_string()),
        Err(LenientError::UnreadableRule {
            action: Some(ActionKind::Deny),
            ..
        })
    ));
}

#[test]
fn unknown_fields_elsewhere_refuse_the_document() {
    let cases: [fn(&mut Value); 5] = [
        |d| d["unknown"] = 1.into(),
        |d| d["policy"]["settings"] = json!({"new_control": "enforce"}),
        |d| d["policy"]["unknown"] = json!({"default": "block", "new_level": 1}),
        |d| d["rule_sets"][0]["new_flag"] = true.into(),
        |d| d["policy"]["scope"] = json!({"future_dimension": []}),
    ];
    for change in cases {
        let mut doc = fixture();
        change(&mut doc);
        let e = read_json(&doc.to_string()).unwrap_err();
        assert!(
            matches!(&e, LenientError::Read(MigrateError::Json(_))),
            "{e}"
        );
        assert!(std::error::Error::source(&e).is_some());
    }
}

#[test]
fn shapes_it_does_not_know_are_left_for_the_strict_reader() {
    for doc in [
        json!({"schema_version": "1.0.0", "policy": 1}),
        json!({"schema_version": "1.0.0", "policy": {"metadata": 1}}),
        json!({"schema_version": "1.0.0", "policy": {}, "rule_sets": 1}),
        json!({"schema_version": "1.0.0", "policy": {}, "rule_sets": [{"rules": 1}]}),
    ] {
        let e = read_json(&doc.to_string()).unwrap_err();
        assert!(matches!(e, LenientError::Read(_)), "{doc}: {e}");
    }
}

#[test]
fn reading_fails_on_bad_json_and_bad_versions() {
    for (text, message) in [
        ("{", "invalid policy document"),
        (r#"{"a": 1, "a": 2}"#, "duplicate key"),
        (
            r#"{"schema_version": "2.0.0"}"#,
            "unsupported schema version",
        ),
        (r#"{"policy": {}}"#, "missing or invalid"),
    ] {
        let e = read_json(text).unwrap_err();
        assert!(e.to_string().contains(message), "{text}: {e}");
    }
}

#[test]
fn an_old_major_is_migrated_first() {
    let text = include_str!("../../tests/fixtures/migrate/v0/flags.json");
    let read = read_json(text).unwrap();
    assert_eq!(read.from.major, 0);
    assert_eq!(
        read.document,
        crate::migrate::read_json(text).unwrap().document
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn a_current_document_reads_unchanged(doc in arbitrary::document_with_lifecycle()) {
        let read = read_json(&doc.to_json_pretty().unwrap()).unwrap();
        prop_assert_eq!(&read.document, &doc);
        prop_assert!(read.ignored.is_empty());
    }

    /// Whatever is added to a valid document, the lenient reader either
    /// refuses it or keeps every rule that allows or denies, unchanged.
    #[test]
    fn nothing_that_allows_or_denies_is_ever_dropped(
        doc in arbitrary::document_with_lifecycle(),
        picks in proptest::collection::vec((any::<prop::sample::Index>(), any::<prop::sample::Index>()), 1..4),
    ) {
        let mut value = serde_json::to_value(&doc).unwrap();
        for (s, r) in &picks {
            let Some(Value::Array(sets)) = value.get_mut("rule_sets") else { break };
            if sets.is_empty() { break; }
            let i = s.index(sets.len());
            let set = &mut sets[i];
            let Some(Value::Array(rules)) = set.get_mut("rules") else { continue };
            if rules.is_empty() { continue; }
            let len = rules.len();
            rules[r.index(len)]["match"] =
                json!({"criterion": {"field": "future.field", "operator": "equals", "values": ["x"]}});
        }
        let Ok(read) = read_json(&value.to_string()) else { return Ok(()) };
        let deciding = |d: &PolicyDocument| -> Vec<crate::model::Rule> {
            d.rule_sets.iter().flat_map(|s| s.rules.iter()).filter(|r| matches!(
                r.action.kind(),
                ActionKind::Allow | ActionKind::Deny | ActionKind::AllowContained | ActionKind::AllowElevated
            )).cloned().collect()
        };
        prop_assert_eq!(deciding(&read.document), deciding(&doc));
        for i in &read.ignored {
            let is_rule = matches!(i.kind, IgnoredKind::Rule(_));
            prop_assert!(is_rule);
        }
    }

    #[test]
    fn read_json_never_panics(text in "\\PC{0,200}") {
        let _ = read_json(&text);
    }
}
