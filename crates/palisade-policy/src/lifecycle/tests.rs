//! Tests of the rule lifecycle (#40), with a simulated clock.

use proptest::prelude::*;

use super::*;
use crate::context::EvaluationContext;
use crate::decision::{Outcome, ReasonCode, TraceId};
use crate::evaluate::{Evaluator, Subject};
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{Field, ObjectType};
use crate::validate::{ErrorCode, ValidatedPolicy};

const TRACE: TraceId = TraceId([5; 16]);
const POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";
const SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001";
/// 2026-11-25T00:00:00Z.
const NOW: Timestamp = Timestamp(1_795_564_800);
const DAY: i64 = 86_400;

fn t(days: i64) -> Timestamp {
    Timestamp(NOW.0 + days * DAY)
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn rule_id(n: u32) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61")
}

fn rule(n: u32, action: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut r = serde_json::json!({
        "id": rule_id(n), "name": format!("R{n}"),
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": action},
    });
    for (k, v) in extra.as_object().unwrap() {
        r.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    r
}

fn doc_with(policy_extra: serde_json::Value, rules: Vec<serde_json::Value>) -> PolicyDocument {
    let mut policy = serde_json::json!({
        "id": POLICY, "name": "Lifecycle", "revision": 2, "mode": "enforce", "rule_sets": [SET],
    });
    for (k, v) in policy_extra.as_object().unwrap() {
        policy.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": policy,
        "rule_sets": [{"id": SET, "name": "Set", "kind": "mixed", "rules": rules}],
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn valid(doc: PolicyDocument) -> ValidatedPolicy {
    doc.validate().unwrap_or_else(|e| panic!("{e:#?}"))
}

fn decide_at(v: &ValidatedPolicy, clock: Option<RuleClock>) -> crate::decision::Decision {
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let mut e = Evaluator::new(v).unwrap();
    if let Some(c) = clock {
        e.set_clock(c);
    }
    e.evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    )
}

fn ts(t: Timestamp) -> serde_json::Value {
    t.to_string().into()
}

// ------------------------------------------------------------- activity

#[test]
fn disabled_expired_and_future_rules_never_decide() {
    for extra in [
        serde_json::json!({"enabled": false}),
        serde_json::json!({"expires_at": ts(t(-1))}),
        serde_json::json!({"activates_at": ts(t(1))}),
    ] {
        let v = valid(doc_with(
            serde_json::json!({}),
            vec![rule(1, "allow", extra.clone())],
        ));
        let d = decide_at(&v, Some(RuleClock::at(NOW)));
        assert_eq!(d.outcome(), Outcome::Blocked, "{extra}");
        assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
        assert_eq!(d.matched_rule(), None);
    }
    // Inside its window, the rule decides.
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"activates_at": ts(t(-1)), "expires_at": ts(t(1))}),
        )],
    ));
    assert_eq!(
        decide_at(&v, Some(RuleClock::at(NOW))).outcome(),
        Outcome::Allowed
    );
}

#[test]
fn an_expiry_is_exclusive_and_an_activation_inclusive() {
    let r: Rule = serde_json::from_value(rule(
        1,
        "allow",
        serde_json::json!({"activates_at": ts(NOW), "expires_at": ts(t(1))}),
    ))
    .unwrap();
    assert_eq!(
        activity(&r, &RuleClock::at(Timestamp(NOW.0 - 1))),
        Activity::NotYetActive
    );
    assert_eq!(activity(&r, &RuleClock::at(NOW)), Activity::Active);
    assert_eq!(
        activity(&r, &RuleClock::at(Timestamp(t(1).0 - 1))),
        Activity::Active
    );
    assert_eq!(activity(&r, &RuleClock::at(t(1))), Activity::Expired);
}

#[test]
fn an_expired_allow_never_revives_after_a_clock_rollback() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"expires_at": ts(t(0))}),
        )],
    ));
    // The agent saw the expiry: its floor passed it. Then the clock is set
    // back a month.
    let rolled_back = RuleClock {
        now: t(-30),
        floor: t(1),
        anchored: true,
    };
    assert_eq!(decide_at(&v, Some(rolled_back)).outcome(), Outcome::Blocked);
    // Even with the floor just at the expiry.
    let rolled_back = RuleClock {
        now: t(-30),
        floor: t(0),
        anchored: true,
    };
    assert_eq!(decide_at(&v, Some(rolled_back)).outcome(), Outcome::Blocked);
}

#[test]
fn a_forward_clock_cannot_start_an_allow_early_or_end_a_deny_early() {
    let allow: Rule = serde_json::from_value(rule(
        1,
        "allow",
        serde_json::json!({"activates_at": ts(t(5))}),
    ))
    .unwrap();
    let deny: Rule =
        serde_json::from_value(rule(2, "deny", serde_json::json!({"expires_at": ts(t(5))})))
            .unwrap();
    let jumped = RuleClock {
        now: t(10),
        floor: NOW,
        anchored: true,
    };
    assert_eq!(activity(&allow, &jumped), Activity::NotYetActive);
    assert_eq!(activity(&deny, &jumped), Activity::Active);
    // A deny starts on either reading.
    let deny_later: Rule = serde_json::from_value(rule(
        3,
        "deny",
        serde_json::json!({"activates_at": ts(t(5))}),
    ))
    .unwrap();
    assert_eq!(activity(&deny_later, &jumped), Activity::Active);
    // Once real time catches up (the floor passes), both agree.
    let caught_up = RuleClock::at(t(10));
    assert_eq!(activity(&allow, &caught_up), Activity::Active);
    assert_eq!(activity(&deny, &caught_up), Activity::Expired);
}

#[test]
fn without_a_clock_time_bounded_rules_fail_closed() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"expires_at": ts(t(100))}),
        )],
    ));
    assert_eq!(decide_at(&v, None).outcome(), Outcome::Blocked);
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            2,
            "deny",
            serde_json::json!({"expires_at": ts(t(-100))}),
        )],
    ));
    assert_eq!(decide_at(&v, None).reason_code(), ReasonCode::ExplicitDeny);
}

#[test]
fn convert_to_audit_annotates_after_expiry() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![
            rule(
                1,
                "deny",
                serde_json::json!({"expires_at": ts(t(0)), "on_expire": "convert_to_audit"}),
            ),
            rule(2, "allow", serde_json::json!({})),
        ],
    ));
    let before = decide_at(&v, Some(RuleClock::at(t(-1))));
    assert_eq!(before.reason_code(), ReasonCode::ExplicitDeny);
    assert!(before.annotations().is_empty());
    let after = decide_at(&v, Some(RuleClock::at(t(1))));
    assert_eq!(after.outcome(), Outcome::Allowed);
    assert_eq!(after.annotations().len(), 1);
    assert_eq!(after.annotations()[0].rule_id.to_string(), rule_id(1));
}

#[test]
fn inactive_rules_are_reported_with_their_reason() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![
            rule(1, "allow", serde_json::json!({"enabled": false})),
            rule(2, "allow", serde_json::json!({"expires_at": ts(t(-1))})),
            rule(3, "deny", serde_json::json!({"activates_at": ts(t(1))})),
            rule(4, "allow", serde_json::json!({})),
        ],
    ));
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &context,
    };
    let inactive = inactive_matches(&v, &subject, &RuleClock::at(NOW));
    let got: Vec<(String, Activity)> = inactive
        .iter()
        .map(|(r, a)| (r.rule_id.to_string(), *a))
        .collect();
    assert_eq!(
        got,
        vec![
            (rule_id(1), Activity::Disabled),
            (rule_id(2), Activity::Expired),
            (rule_id(3), Activity::NotYetActive),
        ]
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Whatever the clock does, a permissive rule is only active when both
    /// readings are in its window, and once the floor passes its expiry it
    /// stays expired for every later reading.
    #[test]
    fn permissive_rules_are_active_only_inside_both_readings(
        start in proptest::option::of(-50i64..50),
        len in 1i64..50,
        now in -100i64..100,
        floor in -100i64..100,
        later_now in -200i64..200,
        bump in 0i64..100,
    ) {
        let start_t = start.map(t);
        let end = t(start.unwrap_or(0) + len);
        let mut r: Rule = serde_json::from_value(rule(1, "allow", serde_json::json!({}))).unwrap();
        r.activates_at = start_t;
        r.expires_at = Some(end);
        let clock = RuleClock { now: t(now), floor: t(floor), anchored: true };
        let inside = |x: Timestamp| start_t.is_none_or(|s| s <= x) && x < end;
        prop_assert_eq!(activity(&r, &clock).is_active(), inside(clock.now) && inside(clock.floor));
        if activity(&r, &clock) == Activity::Expired && clock.floor >= end {
            // The floor never goes back: any later reading is still expired.
            let later = RuleClock { now: t(later_now), floor: t(floor + bump), anchored: true };
            prop_assert_eq!(activity(&r, &later), Activity::Expired);
        }
    }
}

// ------------------------------------------------------------ governance

#[test]
fn exceptions_are_detected_by_nature_and_by_flag() {
    let path_allow = serde_json::json!({
        "id": rule_id(1), "name": "Path",
        "match": {"criterion": {"field": "path.directory", "operator": "starts_with", "values": ["C:\\Tools"]}},
        "action": {"type": "allow"},
    });
    let name_allow = serde_json::json!({
        "id": rule_id(2), "name": "Name",
        "match": {"all": [
            {"criterion": {"field": "path.file_name", "operator": "equals", "values": ["a.exe"]}},
            {"criterion": {"field": "meta.product_name", "operator": "equals", "values": ["A"]}},
        ]},
        "action": {"type": "allow"},
    });
    for (r, want) in [
        (path_allow, true),
        (name_allow, true),
        (rule(3, "allow", serde_json::json!({})), false),
        (rule(4, "deny", serde_json::json!({})), false),
        (
            rule(
                5,
                "allow",
                serde_json::json!({"metadata": {"exception": true}}),
            ),
            true,
        ),
    ] {
        let r: Rule = serde_json::from_value(r).unwrap();
        assert_eq!(is_exception(&r), want, "{}", r.name);
    }
}

fn codes(doc: PolicyDocument) -> Vec<(ErrorCode, String)> {
    match doc.validate() {
        Ok(v) => v
            .warnings()
            .iter()
            .map(|e| (e.code, e.path.clone()))
            .collect(),
        Err(e) => e.iter().map(|e| (e.code, e.path.clone())).collect(),
    }
}

#[test]
fn governance_mode_rejects_incomplete_exceptions() {
    let g = serde_json::json!({"governance": {"require_justification": true}});
    let exception = rule(
        1,
        "allow",
        serde_json::json!({"metadata": {"exception": true, "created_at": ts(NOW)}}),
    );
    let found = codes(doc_with(g.clone(), vec![exception]));
    assert_eq!(
        found,
        vec![
            (
                ErrorCode::JustificationRequired,
                "/rule_sets/0/rules/0/metadata/justification".to_owned()
            ),
            (
                ErrorCode::ExceptionIncomplete,
                "/rule_sets/0/rules/0".to_owned()
            ),
        ]
    );
    // An expiry more than a year after approval.
    let long = rule(
        1,
        "allow",
        serde_json::json!({
            "expires_at": ts(t(400)),
            "metadata": {"exception": true, "justification": "vendor tool", "approved_by": "ciso",
                         "approved_at": ts(NOW), "risk_rating": "medium", "created_at": ts(NOW)},
        }),
    );
    assert_eq!(
        codes(doc_with(g.clone(), vec![long])),
        vec![(
            ErrorCode::ExceptionIncomplete,
            "/rule_sets/0/rules/0".to_owned()
        )]
    );
    // Complete.
    let ok = rule(
        1,
        "allow",
        serde_json::json!({
            "expires_at": ts(t(365)),
            "metadata": {"exception": true, "justification": "vendor tool", "approved_by": "ciso",
                         "approved_at": ts(NOW), "risk_rating": "medium", "created_at": ts(NOW)},
        }),
    );
    assert_eq!(codes(doc_with(g.clone(), vec![ok])), vec![]);
    // An allow needs a review date, or a creation time to derive it.
    let plain = rule(
        1,
        "allow",
        serde_json::json!({"metadata": {"justification": "x"}}),
    );
    assert_eq!(
        codes(doc_with(g.clone(), vec![plain])),
        vec![(
            ErrorCode::ReviewDateRequired,
            "/rule_sets/0/rules/0/metadata/review_by".to_owned()
        )]
    );
    // A deny needs none of it.
    assert_eq!(
        codes(doc_with(g, vec![rule(1, "deny", serde_json::json!({}))])),
        vec![]
    );
    // Governance off: nothing is required.
    let exception = rule(
        1,
        "allow",
        serde_json::json!({"metadata": {"exception": true}}),
    );
    assert_eq!(
        codes(doc_with(serde_json::json!({}), vec![exception])),
        vec![]
    );
}

#[test]
fn presets_turn_governance_mode_on_by_default() {
    let p = serde_json::json!({"unknown": {"preset": "e8_ml2"}});
    let found = codes(doc_with(p, vec![rule(1, "allow", serde_json::json!({}))]));
    assert!(
        found
            .iter()
            .any(|(c, _)| *c == ErrorCode::JustificationRequired),
        "{found:?}"
    );
    let p = serde_json::json!({"unknown": {"preset": "e8_ml2"}, "governance": {"require_justification": false}});
    assert_eq!(
        codes(doc_with(p, vec![rule(1, "allow", serde_json::json!({}))])),
        vec![]
    );
}

#[test]
fn lifecycle_fields_are_validated() {
    let bad = vec![
        rule(
            1,
            "allow",
            serde_json::json!({"activates_at": ts(NOW), "expires_at": ts(NOW)}),
        ),
        rule(
            2,
            "allow",
            serde_json::json!({"on_expire": "convert_to_audit"}),
        ),
        rule(
            3,
            "allow",
            serde_json::json!({"expires_at": ts(NOW), "on_expire": {"delete_after_days": 0}}),
        ),
    ];
    let g = serde_json::json!({"governance": {"stale_after_days": 0, "expiry_notice_days": [3, 3], "severity": {"no_such_check": "error"}}});
    let found = codes(doc_with(g, bad));
    for (code, path) in [
        (
            ErrorCode::InvalidActivityWindow,
            "/rule_sets/0/rules/0/expires_at",
        ),
        (
            ErrorCode::OnExpireNotApplicable,
            "/rule_sets/0/rules/1/on_expire",
        ),
        (
            ErrorCode::OnExpireNotApplicable,
            "/rule_sets/0/rules/2/on_expire/delete_after_days",
        ),
        (
            ErrorCode::InvalidGovernance,
            "/policy/governance/stale_after_days",
        ),
        (
            ErrorCode::InvalidGovernance,
            "/policy/governance/expiry_notice_days/1",
        ),
        (
            ErrorCode::InvalidGovernance,
            "/policy/governance/severity/no_such_check",
        ),
    ] {
        assert!(
            found.contains(&(code, path.to_owned())),
            "{code} {path}: {found:#?}"
        );
    }
}

#[test]
fn metadata_is_not_decision_relevant() {
    let a = doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"metadata": {"justification": "a", "owner": "x"}}),
        )],
    );
    let b = doc_with(
        serde_json::json!({"governance": {"stale_after_days": 30}}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"metadata": {"justification": "b", "review_by": "2027-01-01"}}),
        )],
    );
    assert_ne!(a, b);
    assert_eq!(a.decision_relevant(), b.decision_relevant());
    // A change to what decides is relevant.
    let c = doc_with(
        serde_json::json!({}),
        vec![rule(1, "allow", serde_json::json!({"expires_at": ts(NOW)}))],
    );
    assert_ne!(a.decision_relevant(), c.decision_relevant());
}

// --------------------------------------------------------------- reviews

#[test]
fn review_dates_default_to_a_year_after_creation() {
    let m: Metadata = serde_json::from_value(serde_json::json!({"created_at": ts(NOW)})).unwrap();
    assert_eq!(review_by(&m, Some(ActionKind::Allow)), Some(t(365).date()));
    assert_eq!(review_by(&m, Some(ActionKind::Deny)), None);
    let m: Metadata = serde_json::from_value(
        serde_json::json!({"created_at": ts(NOW), "review_by": "2027-01-01"}),
    )
    .unwrap();
    assert_eq!(
        review_by(&m, Some(ActionKind::Deny)),
        Date::parse("2027-01-01")
    );
}

#[test]
fn review_campaigns_list_due_rules_and_review_updates_them() {
    let mut d = doc_with(
        serde_json::json!({}),
        vec![
            rule(
                1,
                "allow",
                serde_json::json!({"metadata": {"review_by": "2026-11-01", "owner": "alice"}}),
            ),
            rule(
                2,
                "allow",
                serde_json::json!({"metadata": {"created_at": ts(t(-400))}}),
            ),
            rule(
                3,
                "allow",
                serde_json::json!({"metadata": {"review_by": "2027-06-01"}}),
            ),
            rule(
                4,
                "deny",
                serde_json::json!({"metadata": {"review_by": "2020-01-01"}}),
            ),
            rule(5, "allow", serde_json::json!({})),
        ],
    );
    let due = review_due(&d, NOW.date());
    let ids: Vec<String> = due.iter().map(|i| i.rule.rule_id.to_string()).collect();
    // No date at all is due first, then by date.
    assert_eq!(ids, vec![rule_id(5), rule_id(2), rule_id(1)]);
    assert_eq!(due[2].owner.as_deref(), Some("alice"));
    let summary = review_summary(&d, NOW.date());
    assert_eq!(
        (summary.reviewable, summary.due, summary.reviewed_last_year),
        (4, 3, 0)
    );
    // Attest the first, renew the second, retire the fifth.
    let rules = &mut d.rule_sets[0].rules;
    review(&mut rules[0], &ReviewAction::Attest, "bob", NOW).unwrap();
    review(
        &mut rules[1],
        &ReviewAction::Renew { expires_at: t(90) },
        "bob",
        NOW,
    )
    .unwrap();
    review(&mut rules[4], &ReviewAction::Retire, "bob", NOW).unwrap();
    assert_eq!(rules[0].metadata.review_by, Some(t(365).date()));
    assert_eq!(rules[0].metadata.last_reviewed_by.as_deref(), Some("bob"));
    assert_eq!(rules[1].expires_at, Some(t(90)));
    assert!(!rules[4].enabled);
    assert!(review_due(&d, NOW.date()).is_empty());
    assert_eq!(review_summary(&d, NOW.date()).reviewed_last_year, 2);
    // Deterministic evidence: the same input gives the same JSON.
    assert_eq!(
        serde_json::to_string(&review_summary(&d, t(400).date())).unwrap(),
        serde_json::to_string(&review_summary(&d, t(400).date())).unwrap()
    );
}

// ----------------------------------------------------- notices and bulk

#[test]
fn expiry_notices_fire_once_at_each_configured_offset() {
    let d = doc_with(
        serde_json::json!({}),
        vec![
            rule(
                1,
                "allow",
                serde_json::json!({"expires_at": ts(t(14)), "metadata": {"owner": "alice"}}),
            ),
            rule(2, "allow", serde_json::json!({"expires_at": ts(t(3))})),
            rule(
                3,
                "allow",
                serde_json::json!({"expires_at": ts(t(3)), "enabled": false}),
            ),
        ],
    );
    // A scheduler that runs every 12 hours for 20 days.
    let mut all = Vec::new();
    let mut since = Timestamp(NOW.0 - 1);
    for step in 1..=40 {
        let until = Timestamp(NOW.0 + step * DAY / 2);
        all.extend(expiry_notices(&d, since, until));
        since = until;
    }
    let got: Vec<(String, u16)> = all
        .iter()
        .map(|n| (n.rule.rule_id.to_string(), n.days_before))
        .collect();
    assert_eq!(
        got,
        vec![
            (rule_id(1), 14),
            (rule_id(2), 3),
            (rule_id(2), 0),
            (rule_id(1), 3),
            (rule_id(1), 0),
        ]
    );
    assert_eq!(all[0].owner.as_deref(), Some("alice"));
    // Custom offsets.
    let d2 = doc_with(
        serde_json::json!({"governance": {"expiry_notice_days": [7]}}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"expires_at": ts(t(14))}),
        )],
    );
    let n = expiry_notices(&d2, NOW, t(30));
    assert_eq!(n.len(), 1);
    assert_eq!(n[0].due_at, t(7));
}

#[test]
fn delete_after_days_lists_rules_for_retirement() {
    let d = doc_with(
        serde_json::json!({}),
        vec![
            rule(
                1,
                "allow",
                serde_json::json!({"expires_at": ts(t(-10)), "on_expire": {"delete_after_days": 7}}),
            ),
            rule(
                2,
                "allow",
                serde_json::json!({"expires_at": ts(t(-3)), "on_expire": {"delete_after_days": 7}}),
            ),
            rule(3, "allow", serde_json::json!({"expires_at": ts(t(-30))})),
        ],
    );
    let due: Vec<String> = retire_due(&d, NOW)
        .iter()
        .map(|r| r.rule_id.to_string())
        .collect();
    assert_eq!(due, vec![rule_id(1)]);
}

#[test]
fn bulk_operations_are_one_change_set_with_a_reason() {
    let mut d = doc_with(
        serde_json::json!({}),
        vec![
            rule(1, "allow", serde_json::json!({})),
            rule(2, "allow", serde_json::json!({"expires_at": ts(t(1))})),
        ],
    );
    let set: RuleSetId = SET.parse().unwrap();
    let locs: Vec<RuleLocation> = d.rule_sets[0]
        .rules
        .iter()
        .map(|r| RuleLocation {
            rule_set_id: set,
            rule_id: r.id,
        })
        .collect();
    assert_eq!(
        bulk(&mut d, &locs, &BulkOp::Disable, "bob", "  ", NOW),
        Err(BulkError::ReasonRequired)
    );
    let cs = bulk(
        &mut d,
        &locs,
        &BulkOp::Extend(t(30)),
        "bob",
        "quarterly extension",
        NOW,
    )
    .unwrap();
    assert_eq!(cs.changes.len(), 2);
    assert_eq!(cs.reason, "quarterly extension");
    assert_eq!(cs.changes[1].expires_at, (Some(t(1)), Some(t(30))));
    assert!(
        d.rule_sets[0]
            .rules
            .iter()
            .all(|r| r.expires_at == Some(t(30)))
    );
    let cs = bulk(&mut d, &locs, &BulkOp::Retire, "bob", "app removed", NOW).unwrap();
    assert!(cs.changes.iter().all(|c| c.enabled == (true, false)));
    // Nothing changes when one rule is missing or read-only.
    let missing = RuleLocation {
        rule_set_id: set,
        rule_id: rule_id(9).parse().unwrap(),
    };
    let before = d.clone();
    assert_eq!(
        bulk(
            &mut d,
            &[locs[0], missing],
            &BulkOp::Enable,
            "bob",
            "x",
            NOW
        ),
        Err(BulkError::UnknownRule(missing))
    );
    assert_eq!(d, before);
    d.rule_sets[0].read_only = true;
    assert_eq!(
        bulk(&mut d, &locs, &BulkOp::Enable, "bob", "x", NOW),
        Err(BulkError::ReadOnly(locs[0]))
    );
}

// -------------------------------------------------------------- counters

#[test]
fn evaluator_counters_record_decisions_and_annotations() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![
            rule(1, "allow", serde_json::json!({})),
            rule(2, "audit", serde_json::json!({})),
            rule(3, "deny", serde_json::json!({"enabled": false})),
        ],
    ));
    let e = Evaluator::new(&v).unwrap();
    let counters = e.counters();
    assert_eq!(counters.len(), 2);
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &context,
    };
    for i in 0..3 {
        let d = e.evaluate(&subject, TRACE);
        counters.record(&d, sha('a').as_bytes(), t(i));
    }
    let report = counters.report(t(5));
    assert_eq!(report.revision, 2);
    let hits: Vec<(String, u64)> = report
        .rules
        .iter()
        .map(|r| (r.rule_id.to_string(), r.hits_total))
        .collect();
    assert_eq!(hits, vec![(rule_id(1), 3), (rule_id(2), 3)]);
    assert_eq!(report.rules[0].last_matched_at, Some(t(2)));
    assert_eq!(report.rules[0].distinct_objects, 1);
}

#[test]
fn an_expired_rule_with_an_audit_twin_counts_as_the_same_rule() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "deny",
            serde_json::json!({"expires_at": ts(NOW), "on_expire": "convert_to_audit"}),
        )],
    ));
    let e = Evaluator::new(&v).unwrap().at(RuleClock::at(t(1)));
    let counters = e.counters();
    assert_eq!(counters.len(), 1);
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let d = e.evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    );
    counters.record(&d, b"x", t(1));
    assert_eq!(counters.report(t(2)).rules[0].hits_total, 1);
}

// ------------------------------------------------- review regressions

#[test]
fn undated_rules_are_due_without_a_sentinel_date() {
    let d = doc_with(
        serde_json::json!({}),
        vec![rule(1, "allow", serde_json::json!({}))],
    );
    let due = review_due(&d, NOW.date());
    assert_eq!(due[0].review_by, None);
    let summary = review_summary(&d, NOW.date());
    assert_eq!((summary.undated, summary.earliest_due), (1, None));
    let json = serde_json::to_value(&due).unwrap();
    assert!(json[0]["review_by"].is_null());
    // Extreme dates neither panic nor wrap.
    let _ = review_summary(&d, Date(i64::MIN));
    let _ = review_summary(&d, Date(i64::MAX));
}

#[test]
fn renewing_or_extending_a_governed_exception_keeps_it_valid() {
    let g = serde_json::json!({"governance": {"require_justification": true}});
    let exception = rule(
        1,
        "allow",
        serde_json::json!({
            "expires_at": ts(t(300)),
            "metadata": {"exception": true, "justification": "vendor tool", "approved_by": "ciso",
                         "approved_at": ts(NOW), "created_at": ts(NOW), "risk_rating": "medium"},
        }),
    );
    let mut d = doc_with(g, vec![exception]);
    d.clone().validate().unwrap();
    // A year later, the reviewer renews it for another 300 days.
    let later = t(360);
    review(
        &mut d.rule_sets[0].rules[0],
        &ReviewAction::Renew { expires_at: t(660) },
        "auditor",
        later,
    )
    .unwrap();
    assert_eq!(
        d.rule_sets[0].rules[0].metadata.approved_by.as_deref(),
        Some("auditor")
    );
    d.clone().validate().unwrap();
    // Bulk extension past the year is refused, within it allowed.
    let set: RuleSetId = SET.parse().unwrap();
    let loc = RuleLocation {
        rule_set_id: set,
        rule_id: d.rule_sets[0].rules[0].id,
    };
    assert_eq!(
        bulk(&mut d, &[loc], &BulkOp::Extend(t(800)), "bob", "x", later),
        Err(BulkError::ExceptionTooLong(loc))
    );
    bulk(&mut d, &[loc], &BulkOp::Extend(t(700)), "bob", "x", later).unwrap();
    d.clone().validate().unwrap();
}

#[test]
fn reviews_and_bulk_changes_refuse_invalid_input() {
    let mut r: Rule = serde_json::from_value(rule(1, "allow", serde_json::json!({}))).unwrap();
    let before = r.clone();
    assert_eq!(
        review(&mut r, &ReviewAction::Attest, " ", NOW),
        Err(ChangeError::InvalidActor)
    );
    assert_eq!(
        review(
            &mut r,
            &ReviewAction::Renew { expires_at: t(-1) },
            "bob",
            NOW
        ),
        Err(ChangeError::InvalidExpiry)
    );
    assert_eq!(r, before);
    let mut d = doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"metadata": {"comment": "keep me"}}),
        )],
    );
    let loc = RuleLocation {
        rule_set_id: SET.parse().unwrap(),
        rule_id: d.rule_sets[0].rules[0].id,
    };
    assert_eq!(
        bulk(&mut d, &[loc], &BulkOp::Disable, "", "x", NOW),
        Err(BulkError::Invalid(ChangeError::InvalidActor))
    );
    let cs = bulk(&mut d, &[loc], &BulkOp::Retire, "bob", "app removed", NOW).unwrap();
    assert_eq!(cs.changes[0].comment.0.as_deref(), Some("keep me"));
    assert_eq!(
        d.rule_sets[0].rules[0].metadata.comment.as_deref(),
        Some("keep me\nretired: app removed")
    );
    d.validate().unwrap();
}

#[test]
fn inactive_matches_apply_unknown_handling_and_skip_defer() {
    let unknown_deny = serde_json::json!({"id": rule_id(1), "name": "U", "enabled": false,
        "match": {"criterion": {"field": "meta.product_name", "operator": "equals", "values": ["X"]}},
        "action": {"type": "deny", "unknown_as": "match"}});
    let defer = rule(2, "defer", serde_json::json!({"enabled": false}));
    let v = valid(doc_with(serde_json::json!({}), vec![unknown_deny, defer]));
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &context,
    };
    let got: Vec<String> = inactive_matches(&v, &subject, &RuleClock::at(NOW))
        .iter()
        .map(|(r, _)| r.rule_id.to_string())
        .collect();
    assert_eq!(got, vec![rule_id(1)]);
}

#[test]
fn counters_record_by_index_for_large_policies() {
    let rules: Vec<serde_json::Value> = (0..2000u32)
        .map(|n| serde_json::json!({"id": format!("01936b2e-{:04x}-7{:03x}-9f21-0a1b2c3d4e61", n >> 12, n & 0xfff), "name": "R",
            "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [format!("{n:064x}")]}}, "action": {"type": "allow"}}))
        .collect();
    let v = valid(doc_with(serde_json::json!({}), rules));
    let e = Evaluator::new(&v).unwrap();
    let c = e.counters();
    let last = v.document().rule_sets[0].rules[1999].id;
    assert_eq!(c.ordinal(last), Some(1999));
}

// ------------------------------------------------- review findings (#301)

/// F2: an offline-started agent (no anchored time) keeps every
/// time-bounded grant closed, whatever the wall clock says, exactly as with
/// no clock (ADR 0018 rule 2). Timed denies stay active.
#[test]
fn an_offline_started_agent_keeps_timed_grants_closed() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            1,
            "allow",
            serde_json::json!({"expires_at": ts(t(0))}),
        )],
    ));
    // The reviewer's scenario: the agent restarts offline after the allow
    // expired, before its floor reached the expiry (the floor lags real
    // time over a shutdown), and the wall clock is set back a month.
    let offline = RuleClock::offline_started(t(-30), t(-1));
    assert_eq!(decide_at(&v, Some(offline)).outcome(), Outcome::Blocked);
    let allow = &v.document().rule_sets[0].rules[0];
    assert_eq!(activity(allow, &offline), Activity::NotYetActive);
    // Once the floor has passed the expiry, it is reported as expired.
    assert_eq!(
        activity(allow, &RuleClock::offline_started(t(-30), t(1))),
        Activity::Expired
    );
    // An allow still inside its window does not continue offline either.
    let open = valid(doc_with(
        serde_json::json!({}),
        vec![rule(
            2,
            "allow",
            serde_json::json!({"activates_at": ts(t(-10)), "expires_at": ts(t(10))}),
        )],
    ));
    assert_eq!(
        decide_at(&open, Some(RuleClock::offline_started(NOW, NOW))).outcome(),
        Outcome::Blocked
    );
    // Anchored, the same rule decides.
    assert_eq!(
        decide_at(&open, Some(RuleClock::at(NOW))).outcome(),
        Outcome::Allowed
    );
    // An untimed allow is unaffected, and a timed deny stays active.
    let untimed = valid(doc_with(
        serde_json::json!({}),
        vec![rule(3, "allow", serde_json::json!({}))],
    ));
    assert_eq!(
        decide_at(&untimed, Some(RuleClock::offline_started(NOW, NOW))).outcome(),
        Outcome::Allowed
    );
    let deny = valid(doc_with(
        serde_json::json!({}),
        vec![
            rule(4, "deny", serde_json::json!({"expires_at": ts(t(10))})),
            rule(5, "allow", serde_json::json!({})),
        ],
    ));
    assert_eq!(
        decide_at(&deny, Some(RuleClock::offline_started(NOW, NOW))).reason_code(),
        ReasonCode::ExplicitDeny
    );
}

proptest! {
    /// F2: offline-started, a time-bounded permissive rule is never active,
    /// whatever the two readings are.
    #[test]
    fn offline_started_permissive_rules_are_never_active(
        start in proptest::option::of(-50i64..50),
        len in 1i64..50,
        now in -100i64..100,
        floor in -100i64..100,
        action in prop::sample::select(vec!["allow", "ignore"]),
    ) {
        let mut r: Rule = serde_json::from_value(rule(1, action, serde_json::json!({}))).unwrap();
        r.activates_at = start.map(t);
        r.expires_at = Some(t(start.unwrap_or(0) + len));
        let clock = RuleClock::offline_started(t(now), t(floor));
        prop_assert!(!activity(&r, &clock).is_active());
        prop_assert!(!activity_at(&r, Some(&clock)).is_active());
    }
}

fn exception_rule(n: u32, expires: Timestamp, metadata: serde_json::Value) -> serde_json::Value {
    let mut m = serde_json::json!({"exception": true, "justification": "vendor tool",
        "approved_by": "ciso", "risk_rating": "medium", "created_at": ts(NOW)});
    for (k, v) in metadata.as_object().unwrap() {
        m.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    rule(
        n,
        "allow",
        serde_json::json!({"expires_at": ts(expires), "metadata": m}),
    )
}

fn governed(rules: Vec<serde_json::Value>) -> PolicyDocument {
    doc_with(
        serde_json::json!({"governance": {"require_justification": true}}),
        rules,
    )
}

fn error_codes(d: PolicyDocument) -> Vec<ErrorCode> {
    d.validate()
        .err()
        .unwrap_or_default()
        .iter()
        .map(|e| e.code)
        .collect()
}

/// F3: the 365 days count from `approved_at` only. A future-dated
/// `created_at` or `last_reviewed_at` cannot stretch them, and governance
/// mode needs `approved_at` on an exception.
#[test]
fn the_exception_year_counts_from_approval_only() {
    // The reviewer's scenario: approved now, `created_at` written four
    // years ahead, expiry five years ahead.
    let stretched = governed(vec![exception_rule(
        1,
        t(5 * 365),
        serde_json::json!({"approved_at": ts(NOW), "created_at": ts(t(4 * 365))}),
    )]);
    assert!(error_codes(stretched).contains(&ErrorCode::ExceptionIncomplete));
    let reviewed_ahead = governed(vec![exception_rule(
        1,
        t(700),
        serde_json::json!({"approved_at": ts(NOW), "last_reviewed_at": ts(t(400))}),
    )]);
    assert!(error_codes(reviewed_ahead).contains(&ErrorCode::ExceptionIncomplete));
    // No `approved_at`: `created_at` alone no longer bounds it.
    let unapproved = governed(vec![exception_rule(1, t(30), serde_json::json!({}))]);
    let errors = unapproved.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code == ErrorCode::ExceptionIncomplete && e.message.contains("approved_at")),
        "{errors:#?}"
    );
    // Within a year of the approval, it is valid.
    governed(vec![exception_rule(
        1,
        t(365),
        serde_json::json!({"approved_at": ts(NOW)}),
    )])
    .validate()
    .unwrap();
}

/// F3: attesting does not reset the year, a bulk extension is checked
/// from `approved_at`, and only a renewal re-approves.
#[test]
fn attesting_does_not_extend_an_exception_and_renewal_is_bounded() {
    let mut d = governed(vec![exception_rule(
        1,
        t(300),
        serde_json::json!({"approved_at": ts(NOW)}),
    )]);
    d.clone().validate().unwrap();
    let loc = RuleLocation {
        rule_set_id: SET.parse().unwrap(),
        rule_id: d.rule_sets[0].rules[0].id,
    };
    // The reviewer's scenario: attest after 300 days, then bulk-extend a
    // year from the attestation. Before the fix the attestation reset the
    // year, so the extension passed with an expiry 665 days after approval.
    review(
        &mut d.rule_sets[0].rules[0],
        &ReviewAction::Attest,
        "bob",
        t(300),
    )
    .unwrap();
    assert_eq!(d.rule_sets[0].rules[0].metadata.approved_at, Some(NOW));
    assert_eq!(
        bulk(&mut d, &[loc], &BulkOp::Extend(t(665)), "bob", "x", t(300)),
        Err(BulkError::ExceptionTooLong(loc))
    );
    bulk(&mut d, &[loc], &BulkOp::Extend(t(365)), "bob", "x", t(300)).unwrap();
    d.clone().validate().unwrap();
    // A future-dated approval cannot stretch a bulk extension either.
    let mut ahead = governed(vec![exception_rule(
        1,
        t(30),
        serde_json::json!({"approved_at": ts(t(200))}),
    )]);
    assert_eq!(
        bulk(&mut ahead, &[loc], &BulkOp::Extend(t(500)), "bob", "x", NOW),
        Err(BulkError::ExceptionTooLong(loc))
    );
    // A renewal re-approves, for at most 365 days from the review.
    let rule = &mut d.rule_sets[0].rules[0];
    let before = rule.clone();
    assert_eq!(
        review(
            rule,
            &ReviewAction::Renew { expires_at: t(700) },
            "auditor",
            t(300)
        ),
        Err(ChangeError::ExceptionTooLong)
    );
    assert_eq!(*rule, before);
    review(
        rule,
        &ReviewAction::Renew { expires_at: t(665) },
        "auditor",
        t(300),
    )
    .unwrap();
    assert_eq!(rule.metadata.approved_at, Some(t(300)));
    d.validate().unwrap();
}

/// Minor: bulk `Enable` refuses a rule that would fail governance
/// validation, and changes nothing.
#[test]
fn bulk_enable_refuses_a_rule_governance_would_reject() {
    let mut d = governed(vec![
        rule(1, "allow", serde_json::json!({"enabled": false})),
        rule(
            2,
            "allow",
            serde_json::json!({"enabled": false, "metadata": {"justification": "x", "created_at": ts(NOW)}}),
        ),
    ]);
    d.clone().validate().unwrap();
    let set: RuleSetId = SET.parse().unwrap();
    let locs: Vec<RuleLocation> = d.rule_sets[0]
        .rules
        .iter()
        .map(|r| RuleLocation {
            rule_set_id: set,
            rule_id: r.id,
        })
        .collect();
    let before = d.clone();
    let err = bulk(&mut d, &locs, &BulkOp::Enable, "bob", "x", NOW).unwrap_err();
    assert_eq!(
        err,
        BulkError::Governance(
            locs[0],
            vec![
                ErrorCode::JustificationRequired,
                ErrorCode::ReviewDateRequired
            ]
        )
    );
    assert!(err.to_string().contains("justification_required"));
    assert_eq!(d, before);
    bulk(&mut d, &locs[1..], &BulkOp::Enable, "bob", "x", NOW).unwrap();
    d.validate().unwrap();
}

/// F1: `read_only` on a policy's own rule set exempts nothing.
#[test]
fn a_read_only_inline_set_is_still_governed_and_reviewed() {
    let mut d = governed(vec![rule(1, "allow", serde_json::json!({}))]);
    d.rule_sets[0].read_only = true;
    let codes = error_codes(d.clone());
    assert!(
        codes.contains(&ErrorCode::JustificationRequired),
        "{codes:?}"
    );
    assert!(codes.contains(&ErrorCode::ReviewDateRequired), "{codes:?}");
    assert_eq!(review_due(&d, NOW.date()).len(), 1);
}

// --------------------------------------------- CodeRabbit review (#301)

/// evaluate.rs:458: a native `audit` rule with `convert_to_audit` keeps
/// annotating after it expires, exactly once.
#[test]
fn a_native_audit_rule_that_converts_annotates_once_after_expiry() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![
            rule(
                1,
                "audit",
                serde_json::json!({"expires_at": ts(t(0)), "on_expire": "convert_to_audit"}),
            ),
            rule(2, "allow", serde_json::json!({})),
        ],
    ));
    for at in [t(-1), t(1)] {
        let d = decide_at(&v, Some(RuleClock::at(at)));
        assert_eq!(d.outcome(), Outcome::Allowed);
        assert_eq!(d.annotations().len(), 1, "at {at}");
        assert_eq!(d.annotations()[0].rule_id.to_string(), rule_id(1));
    }
}

/// lifecycle/counters.rs:413: restoring from the last report does not send
/// its hits again; restoring from a snapshot still sends the pending ones.
#[test]
fn restoring_a_report_does_not_resend_it() {
    let v = valid(doc_with(
        serde_json::json!({}),
        vec![rule(1, "allow", serde_json::json!({}))],
    ));
    let e = Evaluator::new(&v).unwrap();
    let c = e.counters();
    let d = decide_at(&v, None);
    c.record(&d, b"x", NOW);
    c.record(&d, b"y", NOW);
    let sent = c.report(t(1));
    assert_eq!(sent.rules[0].hits_since_report, 2);
    assert!(!sent.snapshot);
    let after = e.counters();
    assert!(after.restore(&sent));
    let next = after.report(t(2));
    assert_eq!(next.rules[0].hits_total, 2);
    assert_eq!(next.rules[0].hits_since_report, 0);
    // A snapshot taken before reporting keeps its pending hit.
    let c = e.counters();
    c.record(&d, b"z", NOW);
    let snap = c.snapshot(t(1));
    assert!(snap.snapshot);
    let json = serde_json::to_string(&snap).unwrap();
    let snap: HitReport = serde_json::from_str(&json).unwrap();
    let after = e.counters();
    assert!(after.restore(&snap));
    assert_eq!(after.report(t(2)).rules[0].hits_since_report, 1);
}
