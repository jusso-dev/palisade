//! Validation of the precedence model's inputs (#35).

use crate::model::PolicyDocument;
use crate::validate::{ErrorCode, Severity, ValidationError};

/// A document with the model and options, and one custom rule set (`set
/// 0`) and one curated rule set (`set 1`) holding the given rules.
fn doc(
    model: &str,
    options: serde_json::Value,
    custom: &[serde_json::Value],
    curated: &[serde_json::Value],
) -> PolicyDocument {
    let rules = |rules: &[serde_json::Value], base: usize| -> Vec<serde_json::Value> {
        rules
            .iter()
            .enumerate()
            .map(|(i, extra)| {
                let mut r = serde_json::json!({
                    "id": format!("01936b2e-8c4a-7b3d-9f21-0a1b2c3d{:04x}", base + i),
                    "name": "Rule",
                    "match": {"criterion": {
                        "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]
                    }},
                    "action": {"type": "allow"}
                });
                for (k, v) in extra.as_object().unwrap() {
                    r[k] = v.clone();
                }
                r
            })
            .collect()
    };
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Precedence",
            "revision": 1,
            "mode": "enforce",
            "precedence_model": model,
            "precedence_options": options,
            "rule_sets": [
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70"
            ]
        },
        "rule_sets": [
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
                "name": "Custom",
                "kind": "mixed",
                "rules": rules(custom, 0x1000)
            },
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70",
                "name": "Curated",
                "kind": "mixed",
                "read_only": true,
                "rules": rules(curated, 0x2000)
            }
        ]
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn findings(doc: PolicyDocument) -> Vec<(ErrorCode, String)> {
    let all: Vec<ValidationError> = match doc.validate() {
        Ok(v) => v.warnings().to_vec(),
        Err(e) => e,
    };
    all.into_iter().map(|e| (e.code, e.path)).collect()
}

fn at(code: ErrorCode, path: &str) -> (ErrorCode, String) {
    (code, path.to_owned())
}

#[test]
fn first_match_needs_an_order_on_every_deciding_rule() {
    let f = findings(doc(
        "first_match",
        serde_json::json!({}),
        &[
            serde_json::json!({}),
            serde_json::json!({"order": 100_001}),
            // Non-terminal rules need none.
            serde_json::json!({"action": {"type": "audit"}}),
            serde_json::json!({"action": {"type": "defer"}}),
        ],
        &[],
    ));
    assert_eq!(
        f,
        vec![at(ErrorCode::OrderRequired, "/rule_sets/0/rules/0/action")]
    );
}

#[test]
fn first_match_reserves_order_ranges_for_custom_rules() {
    let custom = [0, 99, 100, 100_000, 100_001, 999_989, 999_990, 1_000_000]
        .map(|o| serde_json::json!({"order": o}));
    let f = findings(doc("first_match", serde_json::json!({}), &custom, &[]));
    let reserved: Vec<_> = [0, 1, 2, 3, 6, 7]
        .iter()
        .map(|i| {
            at(
                ErrorCode::OrderReserved,
                &format!("/rule_sets/0/rules/{i}/order"),
            )
        })
        .collect();
    assert_eq!(f, reserved);
    // Every action is checked, not only those that decide.
    let f = findings(doc(
        "first_match",
        serde_json::json!({}),
        &[
            serde_json::json!({"action": {"type": "defer"}, "order": 50}),
            serde_json::json!({"action": {"type": "audit"}, "order": 999_995}),
            serde_json::json!({"action": {"type": "defer"}, "order": 100_002}),
        ],
        &[],
    ));
    assert_eq!(
        f,
        vec![
            at(ErrorCode::OrderReserved, "/rule_sets/0/rules/0/order"),
            at(ErrorCode::OrderReserved, "/rule_sets/0/rules/1/order"),
        ]
    );
    // Curated rule sets may use any range.
    let f = findings(doc("first_match", serde_json::json!({}), &[], &custom));
    assert!(f.is_empty(), "{f:?}");
    // Other models do not check orders.
    let f = findings(doc("deny_wins", serde_json::json!({}), &custom, &[]));
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn an_order_above_the_range_is_rejected_under_every_model() {
    // The schema caps `order` at 1000000, and validation checks the same
    // limit, in curated rule sets and under every model.
    let schema = crate::schema::generate();
    assert_eq!(
        schema["$defs"]["Rule"]["properties"]["order"]["maximum"],
        1_000_000
    );
    for model in ["deny_wins", "first_match"] {
        let f = findings(doc(
            model,
            serde_json::json!({}),
            // In a custom and a curated rule set: one finding each, not
            // also `order_reserved`.
            &[serde_json::json!({"order": 1_000_001})],
            &[serde_json::json!({"order": 1_000_001})],
        ));
        assert_eq!(
            f,
            vec![
                at(ErrorCode::OrderOutOfRange, "/rule_sets/0/rules/0/order"),
                at(ErrorCode::OrderOutOfRange, "/rule_sets/1/rules/0/order"),
            ],
            "{model}"
        );
    }
}

#[test]
fn priority_needs_a_priority_and_warns_on_duplicates_with_other_actions() {
    let f = findings(doc(
        "priority",
        serde_json::json!({}),
        &[
            serde_json::json!({}),
            serde_json::json!({"priority": 5}),
            // The same priority and action: fine.
            serde_json::json!({"priority": 5}),
            // The same priority, another action: a warning.
            serde_json::json!({"priority": 5, "action": {"type": "deny"}}),
            serde_json::json!({"priority": 6, "action": {"type": "deny"}}),
        ],
        &[],
    ));
    assert_eq!(
        f,
        vec![
            at(ErrorCode::PriorityRequired, "/rule_sets/0/rules/0/action"),
            at(
                ErrorCode::DuplicatePriority,
                "/rule_sets/0/rules/3/priority"
            ),
        ]
    );
    assert_eq!(ErrorCode::DuplicatePriority.severity(), Severity::Warning);
    // Only a warning: the document is valid without the missing priority.
    let mut warn_only = doc(
        "priority",
        serde_json::json!({}),
        &[
            serde_json::json!({"priority": 5}),
            serde_json::json!({"priority": 5, "action": {"type": "deny"}}),
        ],
        &[],
    );
    let v = warn_only.clone().validate().unwrap();
    assert_eq!(v.warnings().len(), 1);
    assert!(v.warnings()[0].message.contains("/rule_sets/0/rules/0"));
    // Mandatory rule sets are decided before the model.
    warn_only.rule_sets[0].kind = crate::model::RuleSetKind::Blocklist;
    warn_only.rule_sets[0].mandatory = true;
    warn_only.rule_sets[0].rules[0].action = crate::model::Action::deny();
    warn_only.rule_sets[0].rules[0].priority = None;
    let f = findings(warn_only);
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn rule_sets_the_policy_does_not_use_are_not_checked() {
    let mut d = doc(
        "first_match",
        serde_json::json!({}),
        &[serde_json::json!({})],
        &[],
    );
    d.policy.rule_sets.remove(0);
    assert!(findings(d).is_empty());
}

#[test]
fn unused_options_warn() {
    let f = findings(doc(
        "deny_wins",
        serde_json::json!({
            "allow_tiebreak": "most_permissive",
            "granularity_tiebreak": true,
            "curated_first": false,
            "same_tier_tiebreak": "allow",
            "priority_direction": "higher_wins"
        }),
        &[],
        &[],
    ));
    let base = "/policy/precedence_options";
    assert_eq!(
        f,
        vec![
            at(
                ErrorCode::PrecedenceOptionUnused,
                &format!("{base}/granularity_tiebreak")
            ),
            at(
                ErrorCode::PrecedenceOptionUnused,
                &format!("{base}/curated_first")
            ),
            at(
                ErrorCode::PrecedenceOptionUnused,
                &format!("{base}/same_tier_tiebreak")
            ),
            at(
                ErrorCode::PrecedenceOptionUnused,
                &format!("{base}/priority_direction")
            ),
        ]
    );
    // Options at their defaults are never reported, even when written out.
    let f = findings(doc(
        "priority",
        serde_json::json!({"curated_first": true, "allow_tiebreak": "most_restrictive"}),
        &[],
        &[],
    ));
    assert!(f.is_empty(), "{f:?}");
    // Each option is used by its own model.
    for (model, option) in [
        (
            "allow_wins",
            serde_json::json!({"granularity_tiebreak": true}),
        ),
        ("first_match", serde_json::json!({"curated_first": false})),
        (
            "specificity",
            serde_json::json!({"same_tier_tiebreak": "allow"}),
        ),
        (
            "priority",
            serde_json::json!({"priority_direction": "higher_wins"}),
        ),
        (
            "specificity",
            serde_json::json!({"allow_tiebreak": "most_permissive"}),
        ),
    ] {
        let codes: Vec<_> = findings(doc(model, option.clone(), &[], &[]))
            .into_iter()
            .filter(|(c, _)| *c == ErrorCode::PrecedenceOptionUnused)
            .collect();
        assert!(codes.is_empty(), "{model} {option}: {codes:?}");
    }
}

#[test]
fn options_are_strict_and_round_trip() {
    let mut value: serde_json::Value =
        serde_json::to_value(doc("deny_wins", serde_json::json!({}), &[], &[])).unwrap();
    value["policy"]["precedence_options"] = serde_json::json!({"surprise": 1});
    assert!(PolicyDocument::from_json(&value.to_string()).is_err());
    // Defaults are left out when written.
    let d = doc(
        "deny_wins",
        serde_json::json!({"curated_first": true}),
        &[],
        &[],
    );
    let written = serde_json::to_value(&d).unwrap();
    assert!(written["policy"].get("precedence_options").is_none());
    let d = doc(
        "first_match",
        serde_json::json!({"curated_first": false}),
        &[],
        &[],
    );
    let written = serde_json::to_value(&d).unwrap();
    assert_eq!(
        written["policy"]["precedence_options"],
        serde_json::json!({"curated_first": false})
    );
}
