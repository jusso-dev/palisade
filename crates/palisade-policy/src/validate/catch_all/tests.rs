//! Validation of catch-all rules (#329).

use serde_json::{Value, json};

use crate::model::PolicyDocument;
use crate::validate::{ErrorCode, Severity, ValidationError};

const SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60";
const MANDATORY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70";

/// A rule with ID `n`: a hash deny unless `extra` changes it.
pub(super) fn rule(n: u32, extra: Value) -> Value {
    let mut r = json!({
        "id": format!("01936b2e-8c4a-7b3d-9f21-0a1b2c3d{n:04x}"),
        "name": format!("Rule {n}"),
        "match": {"criterion": {
            "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]
        }},
        "action": {"type": "deny"},
        "order": 100_001 + n
    });
    for (k, v) in extra.as_object().unwrap() {
        r[k] = v.clone();
    }
    r
}

/// A catch-all with ID `n` and `action`.
fn catch_all(n: u32, name: &str, action: Value) -> Value {
    rule(
        n,
        json!({
            "name": name,
            "catch_all": true,
            "match": {"all": []},
            "action": action,
            "order": 999_990
        }),
    )
}

/// A policy with `policy` fields merged in, one mixed rule set of `rules`
/// and a mandatory blocklist of `mandatory`.
pub(super) fn doc(policy: Value, rules: Vec<Value>, mandatory: Vec<Value>) -> PolicyDocument {
    let mut p = json!({
        "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
        "name": "Catch-all",
        "revision": 1,
        "mode": "enforce",
        "rule_sets": [SET, MANDATORY]
    });
    for (k, v) in policy.as_object().unwrap() {
        p[k] = v.clone();
    }
    let json = json!({
        "schema_version": "1.0.0",
        "policy": p,
        "rule_sets": [
            {"id": SET, "name": "Rules", "kind": "mixed", "rules": rules},
            {"id": MANDATORY, "name": "Never", "kind": "blocklist", "mandatory": true, "rules": mandatory}
        ]
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

pub(super) fn findings(doc: PolicyDocument) -> Vec<(ErrorCode, Severity, String)> {
    let all: Vec<ValidationError> = match doc.validate() {
        Ok(v) => v.warnings().to_vec(),
        Err(e) => e,
    };
    all.into_iter()
        .map(|e| (e.code, e.severity, e.path))
        .collect()
}

pub(super) fn error(code: ErrorCode, path: &str) -> (ErrorCode, Severity, String) {
    (code, Severity::Error, path.to_owned())
}

#[test]
fn a_default_deny_needs_no_identity_anchor() {
    for name in ["Default deny", "Block the rest (Catch-all)"] {
        let d = doc(
            json!({}),
            vec![
                rule(1, json!({})),
                catch_all(2, name, json!({"type": "deny"})),
            ],
            vec![],
        );
        assert_eq!(findings(d), [], "{name}");
    }
    // Context alone, without `catch_all`, still needs an anchor.
    let context = json!({"criterion": {"field": "user.is_admin", "operator": "is_false"}});
    let d = doc(json!({}), vec![rule(1, json!({"match": context}))], vec![]);
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::NoIdentityAnchor,
            "/rule_sets/0/rules/0/match"
        )]
    );
    // A catch-all may narrow by context alone.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"match": context, "catch_all": true, "name": "Default deny for users"}),
        )],
        vec![],
    );
    assert_eq!(findings(d), []);
}

#[test]
fn only_a_catch_all_may_match_with_an_empty_all() {
    let d = doc(
        json!({}),
        vec![rule(1, json!({"match": {"all": []}}))],
        vec![],
    );
    let f = findings(d);
    assert!(
        f.contains(&error(
            ErrorCode::EmptyGroup,
            "/rule_sets/0/rules/0/match/all"
        )),
        "{f:?}"
    );
    // Below the root, an empty group is an error even in a catch-all.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"name": "Default deny", "catch_all": true, "match": {"not": {"all": []}}}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::EmptyGroup,
            "/rule_sets/0/rules/0/match/not/all"
        )]
    );
}

#[test]
fn a_catch_all_is_named_as_one_and_decides() {
    let d = doc(
        json!({}),
        vec![catch_all(1, "Everything else", json!({"type": "deny"}))],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidCatchAll,
            "/rule_sets/0/rules/0/name"
        )]
    );
    for action in [json!({"type": "audit"}), json!({"type": "defer"})] {
        let d = doc(
            json!({}),
            vec![catch_all(1, "Default", action.clone())],
            vec![],
        );
        assert_eq!(
            findings(d),
            [error(
                ErrorCode::InvalidCatchAll,
                "/rule_sets/0/rules/0/action"
            )],
            "{action}"
        );
    }
}

#[test]
fn a_rule_set_holds_one_catch_all_and_a_mandatory_one_none() {
    let d = doc(
        json!({}),
        vec![
            catch_all(1, "Default deny", json!({"type": "deny"})),
            catch_all(2, "Default deny 2", json!({"type": "deny"})),
        ],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidCatchAll,
            "/rule_sets/0/rules/1/catch_all"
        )]
    );
    let d = doc(
        json!({}),
        vec![],
        vec![catch_all(1, "Default deny", json!({"type": "deny"}))],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidCatchAll,
            "/rule_sets/1/rules/0/catch_all"
        )]
    );
}

#[test]
fn a_permit_all_needs_confirmation_and_no_compliance_preset() {
    let permit = || vec![catch_all(1, "Default allow", json!({"type": "allow"}))];
    assert_eq!(
        findings(doc(json!({}), permit(), vec![])),
        [error(
            ErrorCode::PermitAllUnconfirmed,
            "/rule_sets/0/rules/0/action"
        )]
    );
    assert_eq!(
        findings(doc(json!({"confirm_permit_all": "yes"}), permit(), vec![])),
        [
            error(
                ErrorCode::PermitAllUnconfirmed,
                "/policy/confirm_permit_all"
            ),
            error(
                ErrorCode::PermitAllUnconfirmed,
                "/rule_sets/0/rules/0/action"
            ),
        ]
    );
    let confirmed = json!({"confirm_permit_all": "I UNDERSTAND"});
    assert_eq!(findings(doc(confirmed.clone(), permit(), vec![])), []);
    // An Essential Eight preset requires default deny.
    let mut e8 = confirmed;
    e8["unknown"] = json!({"preset": "e8_ml2"});
    let f = findings(doc(e8, permit(), vec![]));
    assert!(
        f.contains(&error(
            ErrorCode::UnknownAllowNotPermitted,
            "/rule_sets/0/rules/0/action"
        )),
        "{f:?}"
    );
}

#[test]
fn first_match_warns_without_an_enabled_catch_all() {
    let warning = (
        ErrorCode::CatchAllMissing,
        Severity::Warning,
        "/policy/precedence_model".to_owned(),
    );
    let fm = json!({"precedence_model": "first_match"});
    assert_eq!(
        findings(doc(fm.clone(), vec![rule(1, json!({}))], vec![])),
        core::slice::from_ref(&warning)
    );
    let disabled = with_enabled(catch_all(2, "Default deny", json!({"type": "deny"})), false);
    assert_eq!(
        findings(doc(fm.clone(), vec![rule(1, json!({})), disabled], vec![])),
        [warning]
    );
    let enabled = catch_all(2, "Default deny", json!({"type": "deny"}));
    assert_eq!(
        findings(doc(fm, vec![rule(1, json!({})), enabled], vec![])),
        []
    );
    // Other models need none.
    assert_eq!(
        findings(doc(json!({}), vec![rule(1, json!({}))], vec![])),
        []
    );
}

fn with_enabled(mut rule: Value, enabled: bool) -> Value {
    rule["enabled"] = enabled.into();
    rule
}

#[test]
fn the_new_codes_have_stable_names() {
    assert_eq!(ErrorCode::InvalidCatchAll.as_str(), "invalid_catch_all");
    assert_eq!(
        ErrorCode::PermitAllUnconfirmed.as_str(),
        "permit_all_unconfirmed"
    );
    assert_eq!(ErrorCode::CatchAllMissing.as_str(), "catch_all_missing");
    assert_eq!(ErrorCode::CatchAllMissing.severity(), Severity::Warning);
    assert_eq!(ErrorCode::InvalidCatchAll.severity(), Severity::Error);
}

#[test]
fn an_attribute_rule_only_narrows() {
    let context = json!({"criterion": {"field": "user.is_admin", "operator": "is_false"}});
    // A deny or an audit with context alone: no identity anchor needed.
    for action in [json!({"type": "deny"}), json!({"type": "audit"})] {
        let d = doc(
            json!({}),
            vec![rule(
                1,
                json!({"attribute": true, "match": context, "action": action}),
            )],
            vec![],
        );
        assert_eq!(findings(d), []);
    }
    // Under first_match an attribute rule needs no order.
    let d = doc(
        json!({"precedence_model": "first_match"}),
        vec![
            rule(1, json!({"attribute": true, "match": context})),
            catch_all(2, "Default deny", json!({"type": "deny"})),
        ],
        vec![],
    );
    let mut d = d;
    d.rule_sets[0].rules[0].order = None;
    assert_eq!(findings(d), []);
    // Not an allow, not in a mandatory set, not a catch-all.
    let d = doc(
        json!({}),
        vec![rule(
            1,
            json!({"attribute": true, "action": {"type": "allow"}}),
        )],
        vec![],
    );
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidAttributeRule,
            "/rule_sets/0/rules/0/action"
        )]
    );
    let d = doc(json!({}), vec![], vec![rule(1, json!({"attribute": true}))]);
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidAttributeRule,
            "/rule_sets/1/rules/0/attribute"
        )]
    );
    let mut both = catch_all(1, "Default deny", json!({"type": "deny"}));
    both["attribute"] = true.into();
    let d = doc(json!({}), vec![both], vec![]);
    assert_eq!(
        findings(d),
        [error(
            ErrorCode::InvalidAttributeRule,
            "/rule_sets/0/rules/0/attribute"
        )]
    );
    assert_eq!(
        ErrorCode::InvalidAttributeRule.as_str(),
        "invalid_attribute_rule"
    );
}
