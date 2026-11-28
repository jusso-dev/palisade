//! Validation of probed and user-controlled context (#329).

use super::tests::{doc, error, findings, rule};
use crate::validate::{ErrorCode, Severity};
use serde_json::{Value, json};

/// A probe criterion as JSON (#329).
fn probe(field: &str, target: &str) -> Value {
    let mut c = json!({"field": field, "operator": "exists", "target": target});
    // A cold criterion needs a cadence.
    if field.starts_with("fs.") {
        c["evaluate"] = json!("once_per_session");
    }
    json!({ "criterion": c })
}

fn hash_and(other: Value) -> Value {
    json!({"all": [
        {"criterion": {"field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]}},
        other
    ]})
}

fn warning(code: ErrorCode, path: &str) -> (ErrorCode, Severity, String) {
    (code, Severity::Warning, path.to_owned())
}

#[test]
fn user_controlled_context_only_narrows_and_is_reported() {
    let allow = json!({"type": "allow"});
    // In an allow, with an identity: a warning on the criterion.
    for (field, target) in [
        ("env.var", "BUILD"),
        ("fs.file", r"C:\flag"),
        ("fs.folder", r"C:\dir"),
        ("reg.key", r"HKCU\Software\X"),
        ("reg.value", r"HKEY_USERS\X"),
    ] {
        let d = doc(
            json!({}),
            vec![rule(
                1,
                json!({"match": hash_and(probe(field, target)), "action": allow}),
            )],
            vec![],
        );
        assert_eq!(
            findings(d),
            [warning(
                ErrorCode::UserControlledContext,
                "/rule_sets/0/rules/0/match/all/1/criterion"
            )],
            "{field}"
        );
    }
    // The machine hive is not user-controlled.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": hash_and(probe("reg.key", r"HKLM\Software\X")), "action": allow}),
        )],
        vec![],
    );
    assert_eq!(findings(d), []);
    // Alone, it is no identity: the allow is rejected.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": probe("env.var", "X"), "action": allow}),
        )],
        vec![],
    );
    let f = findings(d);
    assert!(
        f.contains(&error(
            ErrorCode::NoIdentityAnchor,
            "/rule_sets/0/rules/0/match"
        )),
        "{f:?}"
    );
    // A deny that reads it: a user could keep it from applying.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": hash_and(probe("fs.file", r"C:\x"))}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [warning(
            ErrorCode::UserControlledContext,
            "/rule_sets/0/rules/0/match/all/1/criterion"
        )]
    );
    // A catch-all that lets objects run may not read it at all; a default
    // deny may, with the warning.
    let d = doc(
        json!({"confirm_permit_all": "I UNDERSTAND"}),
        vec![rule(
            1,
            json!({"name": "Default allow", "catch_all": true, "match": probe("env.var", "X"), "action": allow}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidCatchAll,
            "/rule_sets/0/rules/0/match/criterion"
        )]
    );
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"name": "Default deny", "catch_all": true, "match": probe("env.var", "X")}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [warning(
            ErrorCode::UserControlledContext,
            "/rule_sets/0/rules/0/match/criterion"
        )]
    );
}

#[test]
fn a_probe_needs_a_valid_target() {
    let tree = |c: Value| hash_and(json!({"criterion": c}));
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "reg.key", "operator": "exists"}))}),
        )],
        vec![],
    );
    // With no hive to read, it also counts as user-controlled.
    assert_eq!(
        findings(d),
        [
            error(
                ErrorCode::InvalidValue,
                "/rule_sets/0/rules/0/match/all/1/criterion/target"
            ),
            warning(
                ErrorCode::UserControlledContext,
                "/rule_sets/0/rules/0/match/all/1/criterion"
            ),
        ]
    );
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "fs.file", "operator": "exists", "target": "relative", "evaluate": "on_policy_change"}))}),
        )],
        vec![],
    );
    let f = findings(d);
    assert!(
        f.contains(&error(
            ErrorCode::InvalidValue,
            "/rule_sets/0/rules/0/match/all/1/criterion/target"
        )),
        "{f:?}"
    );
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "user.sid", "operator": "equals", "values": ["S-1-5-18"], "target": "x"}))}),
        )],
        vec![],
    );
    let f = findings(d);
    assert!(
        f.contains(&error(
            ErrorCode::OptionNotApplicable,
            "/rule_sets/0/rules/0/match/all/1/criterion/target"
        )),
        "{f:?}"
    );
    assert_eq!(
        ErrorCode::UserControlledContext.as_str(),
        "user_controlled_context"
    );
}

#[test]
fn a_cold_criterion_needs_a_cadence() {
    let tree = |c: Value| hash_and(json!({ "criterion": c }));
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "fs.folder", "operator": "exists", "target": r"C:\x"}))}),
        )],
        vec![],
    );
    let f = findings(d);
    assert!(
        f.contains(&error(
            ErrorCode::InvalidValue,
            "/rule_sets/0/rules/0/match/all/1/criterion/evaluate"
        )),
        "{f:?}"
    );
    // A warm one may have one, and a hot one may not.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "reg.key", "operator": "exists", "target": r"HKLM\X", "evaluate": "once_per_boot"}))}),
        )],
        vec![],
    );
    assert_eq!(findings(d), []);
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": tree(json!({"field": "user.sid", "operator": "equals", "values": ["S-1-5-18"], "evaluate": "once_per_boot"}))}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::OptionNotApplicable,
            "/rule_sets/0/rules/0/match/all/1/criterion/evaluate"
        )]
    );
}

#[test]
fn the_condition_budget_is_bounded() {
    for (budget, ok) in [
        (0, false),
        (1, true),
        (50, true),
        (10_000, true),
        (10_001, false),
    ] {
        let d = doc(
            json!({"settings": {"condition_budget_ms": budget}}),
            vec![rule(1, json!({}))],
            vec![],
        );
        let f = findings(d);
        assert_eq!(f.is_empty(), ok, "{budget}: {f:?}");
    }
}
