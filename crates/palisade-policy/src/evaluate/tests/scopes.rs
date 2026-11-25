//! Scopes in the pipeline (#38): how they combine with rules, precedence,
//! the instance limit and the window-close directive.

use super::*;
use crate::decision::WindowClose;
use crate::scope::{OnWindowClose, ScopeNote, Token, TrustedTime};

const ADMINS: &str = "S-1-5-32-544";
const USERS: &str = "S-1-5-32-545";
/// The user the tests' tokens belong to.
const USER: &str = "S-1-5-21-1000-2000-3000-1001";
/// 2026-09-21T10:00:00Z, a Monday.
const MONDAY_10: i64 = 1_789_948_800 + 10 * 3600;

/// A policy of one mixed rule set, with `scope`, `rule_set_scopes` and
/// `location_profiles` on the policy as given.
fn policy(rules: Vec<serde_json::Value>, extra: serde_json::Value) -> ValidatedPolicy {
    let mut doc = serde_json::to_value(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, rules)],
    ))
    .unwrap();
    for (k, v) in extra.as_object().unwrap() {
        doc["policy"][k] = v.clone();
    }
    validated(PolicyDocument::from_json(&doc.to_string()).unwrap())
}

fn scoped(n: u32, action: serde_json::Value, scope: serde_json::Value) -> serde_json::Value {
    with(rule(n, hash_a(), action), "scope", scope)
}

fn users_only() -> serde_json::Value {
    serde_json::json!({"principals": {"include": [{"sid": USERS}]}})
}

fn context(groups: &[(&str, bool)]) -> EvaluationContext {
    let mut c = EvaluationContext::new();
    // A complete token: the user SID and the groups, so a group the user
    // is not in is `NoMatch`, not unknown.
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(USER), None)
            .with_groups(groups.iter().copied()),
    );
    c.scope.time = Some(TrustedTime {
        unix_secs: MONDAY_10,
        trusted: true,
    });
    c.scope.device_time_zone = Some("UTC".to_owned());
    c
}

fn decide_in(policy: &ValidatedPolicy, context: &EvaluationContext) -> Decision {
    let variables = PathVariables::new();
    let facts = facts();
    Evaluator::new(policy).unwrap().evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context,
        },
        TRACE,
    )
}

#[test]
fn an_out_of_scope_rule_is_absent() {
    // A deny for users only, and an allow for everyone.
    let p = policy(
        vec![scoped(1, deny(), users_only()), rule(2, hash_a(), allow())],
        serde_json::json!({}),
    );
    let user = decide_in(&p, &context(&[(USERS, false)]));
    assert_eq!(user.outcome(), Outcome::Blocked);
    assert_eq!(numbers(user.overridden()), vec![2]);
    let admin = decide_in(&p, &context(&[(ADMINS, false)]));
    assert_eq!(admin.outcome(), Outcome::Allowed);
    assert_eq!(winner(&admin), Some(2));
    // The out-of-scope deny is not listed as overridden.
    assert!(admin.overridden().is_empty());
}

#[test]
fn scopes_intersect_down_the_chain() {
    let rule_in_finance = serde_json::json!({
        "devices": {"include": [{"tag": "dept=finance"}]}
    });
    let p = policy(
        vec![scoped(1, allow(), rule_in_finance)],
        serde_json::json!({
            "scope": {"sessions": {"types": ["console"]}},
            "rule_set_scopes": [{
                "rule_set": set_id(1),
                "scopes": [users_only()]
            }]
        }),
    );
    let mut c = context(&[(USERS, false)]);
    c.device.tags = Some(vec!["dept=finance".to_owned()]);
    c.session.session_type = Some(crate::context::SessionType::Console);
    assert_eq!(decide_in(&p, &c).outcome(), Outcome::Allowed);
    // Each level on its own can take the rule out.
    let mut rdp = c.clone();
    rdp.session.session_type = Some(crate::context::SessionType::Rdp);
    assert_eq!(
        decide_in(&p, &rdp).reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
    let admin = EvaluationContext {
        scope: context(&[(ADMINS, false)]).scope,
        ..c.clone()
    };
    assert_eq!(
        decide_in(&p, &admin).reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
    let mut hr = c;
    hr.device.tags = Some(vec!["dept=hr".to_owned()]);
    assert_eq!(
        decide_in(&p, &hr).reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
}

#[test]
fn scopes_do_not_change_specificity_or_precedence() {
    // Under `specificity`, a scoped hash allow beats an unscoped publisher
    // deny exactly as it would unscoped.
    let doc = document(
        "specificity",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                scoped(1, allow(), users_only()),
                rule(2, publisher(), deny()),
            ],
        )],
    );
    let p = validated(doc);
    let d = decide_in(&p, &context(&[(USERS, false)]));
    assert_eq!(winner(&d), Some(1));
    let d = decide_in(&p, &context(&[]));
    assert_eq!(winner(&d), Some(2));
}

#[test]
fn unknown_scopes_fail_allows_closed_and_follow_unknown_as_for_denies() {
    let p = policy(
        vec![scoped(1, allow(), users_only())],
        serde_json::json!({}),
    );
    let unknown = EvaluationContext::new();
    let d = decide_in(&p, &unknown);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    assert_eq!(d.scope_notes(), &[ScopeNote::FactMissing]);
    // A deny on an unknown scope does not apply by default...
    let p = policy(
        vec![scoped(1, deny(), users_only()), rule(2, hash_a(), allow())],
        serde_json::json!({}),
    );
    assert_eq!(decide_in(&p, &unknown).outcome(), Outcome::Allowed);
    // ...and does with `unknown_as: match`.
    let p = policy(
        vec![
            scoped(
                1,
                serde_json::json!({"type": "deny", "unknown_as": "match"}),
                users_only(),
            ),
            rule(2, hash_a(), allow()),
        ],
        serde_json::json!({}),
    );
    assert_eq!(decide_in(&p, &unknown).outcome(), Outcome::Blocked);
}

#[test]
fn stale_group_caches_are_reported() {
    let cloud = serde_json::json!({"principals": {"include": [{"cloud_group": {
        "tenant_id": "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
        "object_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e"
    }}]}});
    let p = policy(vec![scoped(1, allow(), cloud)], serde_json::json!({}));
    let mut c = context(&[]);
    c.scope.process_token = Some(Token::new().with_cloud_groups(
        MONDAY_10 - 2 * 86_400,
        [(
            "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e",
        )],
    ));
    let d = decide_in(&p, &c);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert!(d.scope_notes().contains(&ScopeNote::ScopeStale));
}

#[test]
fn filtered_admin_tokens_are_read_restrictively() {
    let admins = serde_json::json!({"principals": {"include": [{"well_known": "administrators"}]}});
    let allow_admins = policy(
        vec![scoped(1, allow(), admins.clone())],
        serde_json::json!({}),
    );
    let filtered = context(&[(USERS, false), (ADMINS, true)]);
    assert_eq!(
        decide_in(&allow_admins, &filtered).outcome(),
        Outcome::Blocked
    );
    let elevated = context(&[(USERS, false), (ADMINS, false)]);
    assert_eq!(
        decide_in(&allow_admins, &elevated).outcome(),
        Outcome::Allowed
    );
    let deny_admins = policy(
        vec![scoped(1, deny(), admins), rule(2, hash_a(), allow())],
        serde_json::json!({}),
    );
    assert_eq!(
        decide_in(&deny_admins, &filtered).outcome(),
        Outcome::Blocked
    );
}

fn business_hours(on_close: &str) -> serde_json::Value {
    let mut schedule = serde_json::json!({
        "timezone_basis": "utc",
        "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "start": "09:00", "end": "17:00"}]
    });
    if on_close != "none" {
        schedule["on_window_close"] = on_close.into();
    }
    if on_close == "warn_then_terminate" {
        schedule["grace_secs"] = 120.into();
    }
    serde_json::json!({ "schedule": schedule })
}

#[test]
fn scheduled_rules_are_absent_outside_their_windows() {
    let p = policy(
        vec![scoped(1, allow(), business_hours("none"))],
        serde_json::json!({}),
    );
    let mut c = context(&[]);
    assert_eq!(decide_in(&p, &c).outcome(), Outcome::Allowed);
    c.scope.time = Some(TrustedTime {
        unix_secs: MONDAY_10 + 8 * 3600,
        trusted: true,
    });
    assert_eq!(
        decide_in(&p, &c).reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
    // A scheduled deny outside its window does not deny.
    let p = policy(
        vec![
            scoped(1, deny(), business_hours("none")),
            rule(2, hash_a(), allow()),
        ],
        serde_json::json!({}),
    );
    assert_eq!(decide_in(&p, &c).outcome(), Outcome::Allowed);
}

#[test]
fn scheduled_allows_go_inactive_when_clock_integrity_is_lost() {
    let p = policy(
        vec![
            scoped(1, allow(), business_hours("none")),
            with(
                rule(2, publisher(), deny()),
                "scope",
                business_hours("none"),
            ),
        ],
        serde_json::json!({}),
    );
    let mut c = context(&[]);
    c.scope.time = Some(TrustedTime {
        unix_secs: MONDAY_10 + 8 * 3600,
        trusted: false,
    });
    let d = decide_in(&p, &c);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(2), "the scheduled deny stays active");
    assert!(d.scope_notes().contains(&ScopeNote::ClockUntrusted));
}

#[test]
fn window_close_directive_carries_the_close_time() {
    let p = policy(
        vec![scoped(1, allow(), business_hours("warn_then_terminate"))],
        serde_json::json!({}),
    );
    let d = decide_in(&p, &context(&[]));
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(
        d.directives().window_close,
        Some(WindowClose {
            action: OnWindowClose::WarnThenTerminate,
            grace_secs: 120,
            closes_at: Some(MONDAY_10 + 7 * 3600),
        })
    );
    // The policy's default basis applies, and an unknown zone leaves the
    // close time open.
    let local = serde_json::json!({"schedule": {
        "windows": [{"days": ["mon"], "start": "00:00", "end": "00:00"}],
        "on_window_close": "warn"
    }});
    let p = policy(vec![scoped(1, allow(), local)], serde_json::json!({}));
    let mut c = context(&[]);
    c.scope.device_time_zone = None;
    // Without a zone the scheduled allow is inactive.
    assert_eq!(decide_in(&p, &c).outcome(), Outcome::Blocked);
    c.scope.device_time_zone = Some("Australia/Sydney".to_owned());
    // 10:00 UTC Monday is 20:00 Monday in Sydney; Monday ends 14:00 UTC.
    let close = decide_in(&p, &c).directives().window_close.unwrap();
    assert_eq!(close.action, OnWindowClose::Warn);
    assert_eq!(close.grace_secs, 300);
    assert_eq!(close.closes_at, Some(MONDAY_10 + 4 * 3600));
}

#[test]
fn the_instance_limit_blocks_the_next_instance() {
    let limited = serde_json::json!({"max_instances_per_session": 2});
    let p = policy(
        vec![
            scoped(1, allow(), limited),
            with(
                rule(2, folder(), trust()),
                "object_types",
                serde_json::json!(["executable"]),
            ),
        ],
        serde_json::json!({}),
    );
    let mut c = context(&[]);
    for (running, outcome) in [
        (0, Outcome::Allowed),
        (1, Outcome::Allowed),
        (2, Outcome::Blocked),
        (5, Outcome::Blocked),
    ] {
        c.scope.instances_in_session = Some(running);
        let d = decide_in(&p, &c);
        assert_eq!(d.outcome(), outcome, "{running} running");
        if outcome == Outcome::Blocked {
            assert_eq!(d.reason_code(), ReasonCode::InstanceLimit);
            assert_eq!(winner(&d), Some(1));
            assert!(d.directives().trust_sources.is_empty());
            assert_eq!(numbers(d.overridden()), vec![2]);
            assert!(d.scope_notes().contains(&ScopeNote::InstanceLimit));
        } else {
            assert_eq!(d.directives().trust_sources.len(), 1);
        }
    }
    // An unknown count never allows.
    c.scope.instances_in_session = None;
    assert_eq!(decide_in(&p, &c).reason_code(), ReasonCode::InstanceLimit);
}

#[test]
fn the_instance_limit_is_relaxed_by_audit_mode() {
    let limited = serde_json::json!({"max_instances_per_session": 1});
    let mut doc = serde_json::to_value(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, vec![scoped(1, allow(), limited)])],
    ))
    .unwrap();
    doc["policy"]["mode"] = "audit".into();
    let p = validated(PolicyDocument::from_json(&doc.to_string()).unwrap());
    let mut c = context(&[]);
    c.scope.instances_in_session = Some(1);
    let variables = PathVariables::new();
    let facts = facts();
    let d = Evaluator::new(&p)
        .unwrap()
        .evaluate_in(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables: &variables,
                context: &c,
            },
            &crate::mode::DeviceState::of(&p.document().policy),
            TRACE,
        )
        .unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
}

#[test]
fn a_relaxed_instance_limit_keeps_the_allows_directives() {
    // A contained allow, limited to one instance, with a schedule that
    // warns on close and tags on its events.
    let mut scope = business_hours("warn");
    scope["max_instances_per_session"] = 1.into();
    let contained = with(
        scoped(
            1,
            serde_json::json!({"type": "allow_contained", "profile_id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e90"}),
            scope,
        ),
        "effects",
        serde_json::json!({"tags": ["licensed"]}),
    );
    let mut doc = serde_json::to_value(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, vec![contained])],
    ))
    .unwrap();
    doc["policy"]["mode"] = "audit".into();
    let p = validated(PolicyDocument::from_json(&doc.to_string()).unwrap());
    let mut c = context(&[]);
    c.scope.instances_in_session = Some(1);
    let variables = PathVariables::new();
    let facts = facts();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &c,
    };
    let evaluator = Evaluator::new(&p).unwrap();
    // Enforce mode blocks the second instance, with no directives.
    let blocked = evaluator.evaluate(&subject, TRACE);
    assert_eq!(blocked.reason_code(), ReasonCode::InstanceLimit);
    assert!(blocked.directives().containment.is_none());
    assert_eq!(blocked.effects().tags, vec!["licensed".to_owned()]);
    // Audit mode lets it run, but contained and with the window close.
    let d = evaluator
        .evaluate_in(
            &subject,
            &crate::mode::DeviceState::of(&p.document().policy),
            TRACE,
        )
        .unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert!(d.directives().containment.is_some(), "{d:?}");
    assert_eq!(
        d.directives().window_close.map(|w| w.action),
        Some(OnWindowClose::Warn)
    );
}

fn scope_strategy() -> impl Strategy<Value = serde_json::Value> {
    let principal = prop_oneof![
        Just(serde_json::json!({"sid": USERS})),
        Just(serde_json::json!({"sid": ADMINS})),
        Just(serde_json::json!({"well_known": "everyone"})),
    ];
    let session = proptest::sample::select(vec!["console", "rdp", "service"]);
    (
        proptest::collection::vec(principal.clone(), 0..2),
        proptest::collection::vec(principal, 0..2),
        proptest::option::of(session),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(include, exclude, session, any, negate)| {
            let mut s = serde_json::json!({});
            if !include.is_empty() || !exclude.is_empty() {
                s["principals"] = serde_json::json!({"include": include, "exclude": exclude});
            }
            if let Some(t) = session {
                s["sessions"] = serde_json::json!({"types": [t]});
            }
            if any {
                s["combine"] = "any".into();
            }
            if negate && (s.get("principals").is_some() || s.get("sessions").is_some()) {
                s["negate"] = true.into();
            }
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Adding a scope to a rule never makes it apply where it did not: an
    /// allowed object stays allowed only if the scoped allow still
    /// matches, and a scope never turns a block into an allow by itself.
    #[test]
    fn a_rule_scope_never_widens_a_rule(
        scope in scope_strategy(),
        groups in proptest::collection::vec(
            (proptest::sample::select(vec![USERS, ADMINS]), any::<bool>()), 0..3),
        session in proptest::option::of(proptest::sample::select(vec![
            crate::context::SessionType::Console,
            crate::context::SessionType::Rdp,
        ])),
        is_allow in any::<bool>(),
    ) {
        let action = if is_allow { allow() } else { deny() };
        let plain = policy(vec![rule(1, hash_a(), action.clone())], serde_json::json!({}));
        let with_scope = policy(vec![scoped(1, action, scope)], serde_json::json!({}));
        let mut c = context(&groups);
        c.session.session_type = session;
        let before = decide_in(&plain, &c);
        let after = decide_in(&with_scope, &c);
        // The scoped rule decides only where the unscoped one did.
        if after.matched_rule().is_some() {
            prop_assert_eq!(before.matched_rule(), after.matched_rule());
        }
        // Without the rule, the implicit deny decides.
        if after.matched_rule().is_none() {
            prop_assert_eq!(after.reason_code(), ReasonCode::ImplicitDenyUnknown);
        }
    }
}

#[test]
fn an_out_of_scope_rule_is_no_match_with_a_complete_token() {
    let p = policy(
        vec![scoped(1, allow(), users_only())],
        serde_json::json!({}),
    );
    let admin = context(&[(ADMINS, false)]);
    let variables = PathVariables::new();
    let facts = facts();
    let ev = Evaluator::new(&p).unwrap();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &admin,
    };
    let rule = ev.policy();
    let _ = rule;
    let id = crate::model::RuleId(rule_id(1).parse().unwrap());
    let s = ev.scope_of(id, &subject).unwrap();
    assert_eq!(s.result, Tri::NoMatch);
    assert!(s.notes.is_empty(), "{:?}", s.notes);
    assert_eq!(
        decide_in(&p, &admin).reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
    assert!(decide_in(&p, &admin).scope_notes().is_empty());
}
