//! Tests of modes applied to decisions (#36): `Evaluator::evaluate_in`.

use super::*;
use crate::mode::{Connectivity, SessionKind};
use crate::model::{ControlLevel, EnforcementOverride, Mode, Notify, ScriptKind};

fn decide_in(policy: &ValidatedPolicy, state: &DeviceState, t: ObjectType) -> Option<Decision> {
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let facts = facts();
    Evaluator::new(policy).unwrap().evaluate_in(
        &Subject {
            object_type: t,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        state,
        TRACE,
    )
}

fn in_mode(policy: &ValidatedPolicy, mode: Mode) -> Decision {
    let state = DeviceState {
        mode,
        ..DeviceState::of(&policy.document().policy)
    };
    decide_in(policy, &state, ObjectType::Executable).unwrap()
}

fn kill() -> serde_json::Value {
    serde_json::json!({"type": "deny", "kill_running": true, "allow_request": true})
}

fn contained() -> serde_json::Value {
    serde_json::json!({
        "type": "allow_contained",
        "profile_id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e80"
    })
}

/// One ordinary blocklist (set 1) and one mandatory blocklist (set 2).
fn blocklists(
    ordinary: Vec<serde_json::Value>,
    mandatory: Vec<serde_json::Value>,
) -> ValidatedPolicy {
    validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (1, "blocklist", false, false, ordinary),
            (2, "blocklist", true, false, mandatory),
        ],
    ))
}

const RELAXED: [Mode; 3] = [Mode::Monitor, Mode::Audit, Mode::Learning];

#[test]
fn non_enforcing_modes_report_would_block_without_blocking() {
    let policy = blocklists(vec![rule(1, hash_a(), kill())], vec![]);
    let enforced = in_mode(&policy, Mode::Enforce);
    assert_eq!(enforced.outcome(), Outcome::Blocked);
    assert_eq!(enforced.mode(), Mode::Enforce);
    assert!(enforced.directives().kill_running);
    for mode in RELAXED {
        let d = in_mode(&policy, mode);
        assert_eq!(d.outcome(), Outcome::AllowedAudit, "{mode:?}");
        assert_eq!(d.would_have_been(), Outcome::Blocked);
        assert_eq!(d.reason_code(), ReasonCode::AuditModeWouldBlock);
        assert_eq!(d.mode(), mode);
        assert_eq!(winner(&d), Some(1));
        // Nothing was blocked: no notification, nothing to terminate or
        // request. The would-block event is still logged and sent.
        assert!(!d.directives().kill_running);
        assert_eq!(d.directives().request, None);
        assert_eq!(d.effects().notify, Notify::None);
        assert_eq!(d.effects().log, enforced.effects().log);
        assert_eq!(d.effects().severity, enforced.effects().severity);
        assert!(!d.learning_candidate());
    }
}

#[test]
fn an_allowed_object_is_unchanged_by_the_mode() {
    let policy = validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "allowlist",
            false,
            false,
            vec![rule(1, hash_a(), contained())],
        )],
    ));
    let enforced = in_mode(&policy, Mode::Enforce);
    for mode in RELAXED {
        let d = in_mode(&policy, mode);
        assert_eq!(d.outcome(), Outcome::Allowed);
        assert_eq!(d.would_have_been(), Outcome::Allowed);
        assert_eq!(d.directives(), enforced.directives());
        assert_eq!(d.mode(), mode);
    }
}

#[test]
fn the_implicit_deny_follows_the_mode_and_learning_marks_candidates() {
    let policy = blocklists(vec![rule(1, hash_b(), deny())], vec![]);
    assert_eq!(in_mode(&policy, Mode::Enforce).outcome(), Outcome::Blocked);
    assert!(!in_mode(&policy, Mode::Enforce).learning_candidate());
    for mode in RELAXED {
        let d = in_mode(&policy, mode);
        assert_eq!(d.outcome(), Outcome::AllowedAudit);
        assert_eq!(d.would_have_been(), Outcome::Blocked);
        assert_eq!(d.matched_rule(), None);
        assert_eq!(d.learning_candidate(), mode == Mode::Learning, "{mode:?}");
    }
    // An object a deny rule would block is never a learning candidate.
    let policy = blocklists(vec![rule(1, hash_a(), deny())], vec![]);
    assert!(!in_mode(&policy, Mode::Learning).learning_candidate());
}

#[test]
fn a_disabled_device_is_not_consulted_even_for_a_mandatory_deny() {
    let policy = blocklists(vec![], vec![rule(2, hash_a(), deny())]);
    let state = DeviceState {
        mode: Mode::Disabled,
        ..DeviceState::of(&policy.document().policy)
    };
    assert_eq!(decide_in(&policy, &state, ObjectType::Executable), None);
    // Lockdown enforces it again.
    let state = DeviceState {
        lockdown: true,
        ..state
    };
    let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
}

#[test]
fn a_mandatory_deny_blocks_in_every_mode_and_session() {
    // The blocklist always wins (#125): with an allow, a trust source and
    // a matching ordinary deny that does not enforce.
    let policy = validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (
                1,
                "mixed",
                false,
                false,
                vec![
                    rule(1, hash_a(), allow()),
                    rule(3, hash_a(), trust()),
                    with(
                        rule(4, hash_a(), deny()),
                        "enforcement_override",
                        "never_enforce".into(),
                    ),
                ],
            ),
            (
                2,
                "blocklist",
                true,
                false,
                vec![rule(2, publisher(), deny())],
            ),
        ],
    ));
    for mode in [Mode::Monitor, Mode::Audit, Mode::Learning, Mode::Enforce] {
        for session in [
            None,
            Some(SessionKind::Audit),
            Some(SessionKind::FullBypass),
        ] {
            for connectivity in [Connectivity::Connected, Connectivity::Disconnected] {
                let state = DeviceState {
                    mode,
                    connectivity,
                    session,
                    lockdown: false,
                };
                let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
                assert_eq!(d.outcome(), Outcome::Blocked, "{mode:?} {session:?}");
                assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
                assert_eq!(d.mode(), Mode::Enforce);
                assert_eq!(winner(&d), Some(2));
            }
        }
    }
}

#[test]
fn always_enforce_blocks_in_audit_and_learning_but_not_full_bypass() {
    let policy = blocklists(
        vec![with(
            rule(1, hash_a(), deny()),
            "enforcement_override",
            "always_enforce".into(),
        )],
        vec![],
    );
    for mode in RELAXED {
        let d = in_mode(&policy, mode);
        assert_eq!(d.outcome(), Outcome::Blocked, "{mode:?}");
        assert_eq!(d.mode(), Mode::Enforce);
    }
    let session = |kind| DeviceState {
        session: Some(kind),
        ..DeviceState::of(&policy.document().policy)
    };
    let d = decide_in(
        &policy,
        &session(SessionKind::Audit),
        ObjectType::Executable,
    )
    .unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
    let d = decide_in(
        &policy,
        &session(SessionKind::FullBypass),
        ObjectType::Executable,
    )
    .unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedOverride);
    assert_eq!(d.reason_code(), ReasonCode::OverrideSession);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
}

#[test]
fn an_override_session_relaxes_ordinary_denies_and_the_implicit_deny() {
    for tree in [hash_a(), hash_b()] {
        let policy = blocklists(vec![rule(1, tree, deny())], vec![]);
        let state = DeviceState {
            session: Some(SessionKind::Audit),
            ..DeviceState::of(&policy.document().policy)
        };
        let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
        assert_eq!(d.outcome(), Outcome::AllowedOverride);
        assert_eq!(d.reason_code(), ReasonCode::OverrideSession);
        assert_eq!(d.mode(), Mode::Audit);
        // In a device already in audit, the session changes nothing.
        let state = DeviceState {
            mode: Mode::Audit,
            ..state
        };
        let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
        assert_eq!(d.outcome(), Outcome::AllowedAudit);
    }
}

#[test]
fn a_relaxed_deny_never_lets_through_what_an_enforcing_rule_blocks() {
    // Rule 1 is in a blocklist under test in audit; rule 2 is enforced.
    let audit_set = |rules: Vec<serde_json::Value>, rest: Vec<serde_json::Value>| {
        let mut doc = document(
            "deny_wins",
            serde_json::json!({}),
            vec![
                (1, "blocklist", false, false, rules),
                (3, "mixed", false, false, rest),
            ],
        );
        doc.rule_sets[0].mode_override = Some(Mode::Audit);
        validated(doc)
    };
    // Another enforcing deny matches: it blocks, and the audit one is
    // listed as overridden.
    let policy = audit_set(
        vec![rule(1, hash_a(), deny())],
        vec![rule(2, publisher(), deny())],
    );
    // Rule 1 is more specific, so the enforce-mode decision names it; the
    // second decision, without it, names rule 2.
    assert_eq!(winner(&decide(&policy)), Some(1));
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(2));
    assert_eq!(numbers(d.overridden()), vec![1]);
    assert_eq!(d.mode(), Mode::Enforce);

    // Nothing allows the object: the enforcing implicit deny blocks it.
    let policy = audit_set(vec![rule(1, hash_a(), deny())], vec![]);
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    assert_eq!(numbers(d.overridden()), vec![1]);

    // An allow lets it run: with the allow's containment, as it would run
    // without the blocklist.
    let policy = audit_set(
        vec![rule(1, hash_a(), deny())],
        vec![rule(2, hash_a(), contained())],
    );
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(1));
    assert_eq!(d.mode(), Mode::Audit);
    assert!(d.directives().containment.is_some());
}

#[test]
fn never_enforce_only_reports() {
    let policy = blocklists(
        vec![with(
            rule(1, hash_a(), kill()),
            "enforcement_override",
            "never_enforce".into(),
        )],
        vec![],
    );
    // Nothing allows the object, so the implicit deny blocks it anyway.
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    assert_eq!(numbers(d.overridden()), vec![1]);
    // With an allow, the never-enforced deny only reports.
    let policy = validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(1, hash_a(), kill()),
                    "enforcement_override",
                    "never_enforce".into(),
                ),
                rule(2, publisher(), allow()),
            ],
        )],
    ));
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(winner(&d), Some(1));
    assert!(!d.directives().kill_running);
}

#[test]
fn modes_by_type_and_control_levels_apply_per_object() {
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "blocklist",
            false,
            false,
            vec![rule(1, hash_a(), deny())],
        )],
    );
    doc.rule_sets[0].rules[0].object_types = vec![];
    let ps = ObjectType::Script(ScriptKind::Powershell);
    doc.policy.mode_options.mode_by_type.insert(ps, Mode::Audit);
    doc.policy.settings.dll_control = ControlLevel::Off;
    let policy = validated(doc);
    let state = DeviceState::of(&policy.document().policy);
    let outcome = |t| decide_in(&policy, &state, t).unwrap().outcome();
    assert_eq!(outcome(ObjectType::Executable), Outcome::Blocked);
    assert_eq!(outcome(ps), Outcome::AllowedAudit);
    assert_eq!(outcome(ObjectType::Library), Outcome::AllowedAudit);
    assert_eq!(
        decide_in(&policy, &state, ObjectType::Library)
            .unwrap()
            .mode(),
        Mode::Monitor
    );
}

#[test]
fn a_disconnected_device_uses_the_stricter_offline_mode() {
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "blocklist",
            false,
            false,
            vec![rule(1, hash_a(), deny())],
        )],
    );
    doc.policy.mode = Mode::Audit;
    doc.policy.mode_options.mode_disconnected = Some(Mode::Enforce);
    let policy = validated(doc);
    let connected = DeviceState::of(&policy.document().policy);
    let offline = DeviceState {
        connectivity: Connectivity::Disconnected,
        ..connected
    };
    let t = ObjectType::Executable;
    assert_eq!(
        decide_in(&policy, &connected, t).unwrap().outcome(),
        Outcome::AllowedAudit
    );
    assert_eq!(
        decide_in(&policy, &offline, t).unwrap().outcome(),
        Outcome::Blocked
    );
}

#[test]
fn lockdown_overrides_every_weaker_setting() {
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "blocklist",
            false,
            false,
            vec![with(
                rule(1, hash_a(), deny()),
                "enforcement_override",
                "never_enforce".into(),
            )],
        )],
    );
    doc.policy.mode = Mode::Monitor;
    doc.rule_sets[0].mode_override = Some(Mode::Monitor);
    doc.policy
        .mode_options
        .mode_by_type
        .insert(ObjectType::Executable, Mode::Monitor);
    let policy = validated(doc);
    let state = DeviceState {
        session: Some(SessionKind::FullBypass),
        lockdown: true,
        ..DeviceState::of(&policy.document().policy)
    };
    let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(1));
    // Restore: the prior modes return.
    let state = DeviceState {
        lockdown: false,
        ..state
    };
    let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.mode(), Mode::Monitor);
}

#[test]
fn a_relaxed_decision_has_a_stable_json_form() {
    let policy = blocklists(vec![rule(1, hash_a(), kill())], vec![]);
    let value = serde_json::to_value(in_mode(&policy, Mode::Learning)).unwrap();
    assert_eq!(value["outcome"], "allowed_audit");
    assert_eq!(value["would_have_been"], "blocked");
    assert_eq!(value["mode"], "learning");
    assert_eq!(value["learning_candidate"], false);
    assert_eq!(value["reason_code"], "audit_mode_would_block");
    assert_eq!(value["directives"]["kill_running"], false);
}

#[test]
fn a_session_that_relaxes_the_implicit_deny_is_an_override() {
    // A trial deny in monitor matches; nothing allows the object. Without
    // a session, the enforcing implicit deny blocks it.
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "blocklist",
            false,
            false,
            vec![rule(1, hash_a(), deny())],
        )],
    );
    doc.rule_sets[0].mode_override = Some(Mode::Monitor);
    let policy = validated(doc);
    let base = DeviceState::of(&policy.document().policy);
    let d = decide_in(&policy, &base, ObjectType::Executable).unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    // The session is what lets it run, so it is reported as an override,
    // in the session's mode, naming what the session bypassed.
    for kind in [SessionKind::Audit, SessionKind::FullBypass] {
        let state = DeviceState {
            session: Some(kind),
            ..base
        };
        let d = decide_in(&policy, &state, ObjectType::Executable).unwrap();
        assert_eq!(d.outcome(), Outcome::AllowedOverride, "{kind:?}");
        assert_eq!(d.reason_code(), ReasonCode::OverrideSession);
        assert_eq!(d.mode(), Mode::Audit);
        assert_eq!(d.matched_rule(), None);
        assert_eq!(numbers(d.overridden()), vec![1]);
    }
}

#[test]
fn a_session_names_the_enforcing_deny_it_bypassed() {
    // Rule 1 (hash, trial, monitor) is more specific than rule 2
    // (publisher, always_enforce); rule 3 allows.
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (
                1,
                "blocklist",
                false,
                false,
                vec![rule(1, hash_a(), deny())],
            ),
            (
                2,
                "mixed",
                false,
                false,
                vec![
                    with(
                        rule(2, publisher(), deny()),
                        "enforcement_override",
                        "always_enforce".into(),
                    ),
                    rule(3, folder(), allow()),
                ],
            ),
        ],
    );
    doc.rule_sets[0].mode_override = Some(Mode::Monitor);
    let policy = validated(doc);
    let base = DeviceState::of(&policy.document().policy);
    let d = decide_in(&policy, &base, ObjectType::Executable).unwrap();
    assert_eq!((d.outcome(), winner(&d)), (Outcome::Blocked, Some(2)));
    // An audit session cannot relax `always_enforce`.
    let audit = DeviceState {
        session: Some(SessionKind::Audit),
        ..base
    };
    let d = decide_in(&policy, &audit, ObjectType::Executable).unwrap();
    assert_eq!((d.outcome(), winner(&d)), (Outcome::Blocked, Some(2)));
    // A full bypass can: it names rule 2, not the trial rule 1.
    let bypass = DeviceState {
        session: Some(SessionKind::FullBypass),
        ..base
    };
    let d = decide_in(&policy, &bypass, ObjectType::Executable).unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedOverride);
    assert_eq!(winner(&d), Some(2));
    assert_eq!(d.mode(), Mode::Audit);
    assert_eq!(numbers(d.overridden()), vec![1, 3]);
}

#[test]
fn a_granted_trust_source_is_not_also_overridden() {
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (
                1,
                "blocklist",
                false,
                false,
                vec![rule(1, hash_a(), deny())],
            ),
            (
                2,
                "mixed",
                false,
                false,
                vec![rule(2, publisher(), allow()), rule(3, hash_a(), trust())],
            ),
        ],
    );
    doc.rule_sets[0].mode_override = Some(Mode::Audit);
    let policy = validated(doc);
    let d = in_mode(&policy, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    let grants: Vec<RuleRef> = d
        .directives()
        .trust_sources
        .iter()
        .map(|g| g.rule)
        .collect();
    assert_eq!(numbers(&grants), vec![3]);
    assert_eq!(numbers(d.overridden()), vec![2]);
}

// Property tests.

fn state() -> impl Strategy<Value = DeviceState> {
    (
        proptest::sample::select(vec![
            Mode::Disabled,
            Mode::Monitor,
            Mode::Audit,
            Mode::Learning,
            Mode::Enforce,
        ]),
        any::<bool>(),
        proptest::sample::select(vec![
            None,
            Some(SessionKind::Audit),
            Some(SessionKind::FullBypass),
        ]),
        proptest::bool::weighted(0.2),
    )
        .prop_map(|(mode, offline, session, lockdown)| DeviceState {
            mode,
            connectivity: if offline {
                Connectivity::Disconnected
            } else {
                Connectivity::Connected
            },
            session,
            lockdown,
        })
}

fn decide_both(
    policy: &ValidatedPolicy,
    state: &DeviceState,
    t: ObjectType,
) -> (Decision, Option<Decision>) {
    (
        decide_with(policy, &facts(), t),
        decide_in(policy, state, t),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Over random policies and device states: a disabled device is not
    /// consulted; otherwise `would_have_been` is the enforce-mode outcome,
    /// a mode never blocks what enforce mode allows, a block always
    /// enforces, and a matching mandatory deny always blocks (#125).
    #[test]
    fn modes_only_relax_and_never_touch_the_mandatory_tier(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        state in state(),
        t in object_type(),
    ) {
        let mut doc = doc;
        let matching = anchor(&mut doc, &picks);
        let policy = doc.clone().validate().unwrap();
        let (enforce, d) = decide_both(&policy, &state, t);
        if state.mode == Mode::Disabled && !state.lockdown {
            prop_assert!(d.is_none());
            return Ok(());
        }
        let d = d.unwrap();
        prop_assert_eq!(d.would_have_been(), enforce.outcome());
        if !enforce.outcome().stops() {
            prop_assert_eq!(&d, &enforce.clone().in_mode(d.mode()).with_learning(d.learning_candidate()));
        }
        match d.outcome() {
            Outcome::Blocked | Outcome::PendingUser => prop_assert_eq!(d.mode(), Mode::Enforce),
            Outcome::AllowedAudit | Outcome::AllowedOverride => {
                prop_assert!(d.would_have_been().stops());
                prop_assert_ne!(d.mode(), Mode::Enforce);
                // A mode names the rule enforce mode decided by; a session
                // names the enforcing rule it bypassed.
                if d.outcome() == Outcome::AllowedAudit {
                    prop_assert_eq!(d.matched_rule(), enforce.matched_rule());
                }
                // The same mode without the session would have blocked.
                if d.outcome() == Outcome::AllowedOverride {
                    let base = DeviceState { session: None, ..state };
                    let without = decide_in(&policy, &base, t).unwrap();
                    prop_assert!(without.outcome().stops());
                    prop_assert_eq!(d.matched_rule(), without.matched_rule());
                }
                // Granted trust sources are never also overridden.
                for g in &d.directives().trust_sources {
                    prop_assert!(!d.overridden().contains(&g.rule));
                }
            }
            Outcome::Allowed | Outcome::Ignored => {}
        }
        if d.outcome() == Outcome::AllowedOverride {
            prop_assert!(state.session.is_some());
        }
        // A session only ever relaxes: what runs without it runs with it,
        // and it never turns a mode's relaxation into an override.
        if state.session.is_some() {
            let base = DeviceState { session: None, ..state };
            let without = decide_in(&policy, &base, t).unwrap();
            if !without.outcome().stops() {
                prop_assert_eq!(&without.clone().in_mode(d.mode()), &d.clone().in_mode(d.mode()));
            }
        }
        if d.learning_candidate() {
            prop_assert_eq!(d.mode(), Mode::Learning);
            prop_assert_eq!(d.matched_rule(), None);
        }
        if applies(&doc, &matching, t, |s, _| s.mandatory) {
            prop_assert_eq!(d.outcome(), Outcome::Blocked);
            prop_assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
        }
        if state.lockdown {
            prop_assert_eq!(&d, &enforce);
        }
        // Shuffling the document changes nothing.
        let other = shuffled(&doc, picks.len() as u64).validate().unwrap();
        prop_assert_eq!(decide_in(&other, &state, t), Some(d));
    }

    /// With every relaxation removed, applying the mode is the identity.
    #[test]
    fn enforce_mode_is_the_enforce_decision(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        t in object_type(),
    ) {
        let mut doc = doc;
        anchor(&mut doc, &picks);
        doc.policy.mode = Mode::Enforce;
        doc.policy.mode_options = crate::model::ModeOptions::default();
        doc.policy.settings.script_control = ControlLevel::Enforce;
        doc.policy.settings.script_control_by_kind.clear();
        doc.policy.settings.dll_control = ControlLevel::Enforce;
        doc.policy.settings.driver_control = ControlLevel::Enforce;
        for set in &mut doc.rule_sets {
            set.mode_override = None;
            for r in &mut set.rules {
                if r.enforcement_override == EnforcementOverride::NeverEnforce {
                    r.enforcement_override = EnforcementOverride::Inherit;
                }
            }
        }
        let policy = doc.validate().unwrap();
        let (enforce, d) = decide_both(&policy, &DeviceState::of(&policy.document().policy), t);
        prop_assert_eq!(d, Some(enforce));
    }
}

/// The `log` flag of rules that log every decision.
fn always() -> serde_json::Value {
    serde_json::json!({"log": "always"})
}

#[test]
fn each_mode_reports_the_decisions_the_issue_lists() {
    use crate::mode::events::{EventFidelity, Report, fidelity};
    let report = |d: &Decision| fidelity(Some(d)).report;
    // A disabled device reports nothing.
    assert_eq!(
        fidelity(None),
        EventFidelity {
            report: Report::None,
            learning_candidate: false
        }
    );
    // A would-block is an event in every non-enforcing mode, and a block
    // keeps its rule's `log` (always, for a deny by default).
    let blocklist = blocklists(vec![rule(1, hash_a(), deny())], vec![]);
    assert_eq!(report(&in_mode(&blocklist, Mode::Enforce)), Report::Event);
    for mode in RELAXED {
        assert_eq!(
            report(&in_mode(&blocklist, mode)),
            Report::Event,
            "{mode:?}"
        );
    }
    // An allow logs `summary` by default: kept in enforce and monitor,
    // raised to a full event in audit and learning.
    let allowlist = |r: serde_json::Value| {
        validated(document(
            "deny_wins",
            serde_json::json!({}),
            vec![(1, "allowlist", false, false, vec![r])],
        ))
    };
    let summary = allowlist(rule(1, hash_a(), allow()));
    let expect = [
        (Mode::Enforce, Report::Summary),
        (Mode::Monitor, Report::Summary),
        (Mode::Audit, Report::Event),
        (Mode::Learning, Report::Event),
    ];
    for (mode, r) in expect {
        assert_eq!(report(&in_mode(&summary, mode)), r, "{mode:?}");
    }
    // An allow with `log: always` is still only summarised in monitor;
    // `log: never` stays silent there, but not in audit.
    let loud = allowlist(with(rule(1, hash_a(), allow()), "effects", always()));
    assert_eq!(report(&in_mode(&loud, Mode::Enforce)), Report::Event);
    assert_eq!(report(&in_mode(&loud, Mode::Monitor)), Report::Summary);
    let quiet = allowlist(with(
        rule(1, hash_a(), allow()),
        "effects",
        serde_json::json!({"log": "never"}),
    ));
    assert_eq!(report(&in_mode(&quiet, Mode::Enforce)), Report::None);
    assert_eq!(report(&in_mode(&quiet, Mode::Monitor)), Report::None);
    assert_eq!(report(&in_mode(&quiet, Mode::Audit)), Report::Event);
    // A learning candidate is an event with the object's full facts.
    let unknown = blocklists(vec![rule(1, hash_b(), deny())], vec![]);
    for mode in [Mode::Enforce, Mode::Monitor, Mode::Audit, Mode::Learning] {
        let f = fidelity(Some(&in_mode(&unknown, mode)));
        assert_eq!(f.learning_candidate, mode == Mode::Learning, "{mode:?}");
    }
    // A pending prompt (#39) keeps the unknown policy's `log`, as a block
    // does; a relaxed one is a would-block event.
    let mut doc = document("deny_wins", serde_json::json!({}), vec![]);
    doc.policy.unknown = serde_json::from_value(
        serde_json::json!({"default": "prompt", "effects": {"log": "sampled"}}),
    )
    .unwrap();
    let prompt = validated(doc);
    // A prompt needs a user at a console or remote desktop.
    let mut context = EvaluationContext::new();
    context.session.session_type = Some(crate::context::SessionType::Console);
    let (variables, facts) = (PathVariables::new(), facts());
    let prompted = |mode: Mode| {
        let state = DeviceState {
            mode,
            ..DeviceState::of(&prompt.document().policy)
        };
        let subject = Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        };
        Evaluator::new(&prompt)
            .unwrap()
            .evaluate_in(&subject, &state, TRACE)
            .unwrap()
    };
    let pending = prompted(Mode::Enforce);
    assert_eq!(pending.outcome(), Outcome::PendingUser);
    assert_eq!(report(&pending), Report::Sampled);
    for mode in RELAXED {
        assert_eq!(report(&prompted(mode)), Report::Event, "{mode:?}");
    }
    // The use of an override session is always an event.
    let state = DeviceState {
        session: Some(SessionKind::Audit),
        ..DeviceState::of(&blocklist.document().policy)
    };
    let d = decide_in(&blocklist, &state, ObjectType::Executable).unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedOverride);
    assert_eq!(report(&d), Report::Event);
}
