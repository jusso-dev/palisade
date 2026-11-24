//! Tests of effective-mode resolution and protection status (#36).
//!
//! `every_combination_matches_the_spec` enumerates every combination of
//! device mode, connectivity, `mode_disconnected`, `mode_by_type`, control
//! level, deciding rule (none, ordinary, mandatory), rule set
//! `mode_override`, `enforcement_override`, session and lockdown, and
//! checks [`resolve`] against [`spec`], which states the rules of the
//! module documentation as a list of cases rather than as a pipeline.

use super::*;
use crate::model::{PolicyDocument, PolicySettings};

const MODES: [Mode; 5] = [
    Mode::Disabled,
    Mode::Monitor,
    Mode::Audit,
    Mode::Learning,
    Mode::Enforce,
];
const ENABLED: [Mode; 4] = [Mode::Monitor, Mode::Audit, Mode::Learning, Mode::Enforce];
const LEVELS: [ControlLevel; 3] = [
    ControlLevel::Off,
    ControlLevel::Audit,
    ControlLevel::Enforce,
];
const OVERRIDES: [EnforcementOverride; 3] = [
    EnforcementOverride::Inherit,
    EnforcementOverride::AlwaysEnforce,
    EnforcementOverride::NeverEnforce,
];
const SESSIONS: [Option<SessionKind>; 3] = [
    None,
    Some(SessionKind::Audit),
    Some(SessionKind::FullBypass),
];

/// The decider of one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decider {
    /// The implicit deny.
    None,
    /// A rule in a blocklist.
    Ordinary,
    /// A rule in a mandatory blocklist.
    Mandatory,
}

const T: ObjectType = ObjectType::Script(ScriptKind::Powershell);

/// A policy with one blocklist (mandatory or not) holding one rule.
fn document() -> PolicyDocument {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Modes",
            "revision": 1,
            "mode": "enforce",
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
            "name": "Blocklist",
            "kind": "blocklist",
            "rules": [{
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
                "name": "Rule",
                "match": {"criterion": {
                    "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]
                }},
                "action": {"type": "deny"},
            }],
        }],
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

/// The rules of the module documentation, written as cases.
#[allow(clippy::too_many_arguments)]
fn spec(
    device: Mode,
    disconnected: bool,
    offline: Option<Mode>,
    by_type: Option<Mode>,
    level: ControlLevel,
    decider: Decider,
    set_mode: Option<Mode>,
    enforcement: EnforcementOverride,
    session: Option<SessionKind>,
    lockdown: bool,
) -> (Mode, bool) {
    let rank = |m: Mode| match m {
        Mode::Disabled => 0,
        Mode::Monitor => 1,
        Mode::Audit | Mode::Learning => 2,
        Mode::Enforce => 3,
    };
    let stricter = |a: Mode, b: Mode| if rank(b) > rank(a) { b } else { a };
    let at_most = |a: Mode, cap: Mode| if rank(a) > rank(cap) { cap } else { a };
    if lockdown {
        return (Mode::Enforce, false);
    }
    if device == Mode::Disabled {
        return (Mode::Disabled, false);
    }
    if decider == Decider::Mandatory {
        return (Mode::Enforce, false);
    }
    let raise = |m: Mode| match (disconnected, offline) {
        (true, Some(o)) => stricter(m, o),
        _ => m,
    };
    let mut mode = raise(by_type.unwrap_or(device));
    mode = match level {
        ControlLevel::Enforce => mode,
        ControlLevel::Audit => at_most(mode, Mode::Audit),
        ControlLevel::Off => at_most(mode, Mode::Monitor),
    };
    let (set_mode, enforcement) = match decider {
        Decider::None => (None, EnforcementOverride::Inherit),
        _ => (set_mode, enforcement),
    };
    if let Some(m) = set_mode {
        mode = m;
    }
    match enforcement {
        EnforcementOverride::AlwaysEnforce => mode = Mode::Enforce,
        EnforcementOverride::NeverEnforce => mode = at_most(mode, Mode::Audit),
        EnforcementOverride::Inherit => {}
    }
    match session {
        None => (mode, false),
        Some(SessionKind::Audit) if enforcement == EnforcementOverride::AlwaysEnforce => {
            (mode, false)
        }
        Some(_) => (at_most(mode, Mode::Audit), mode == Mode::Enforce),
    }
}

#[test]
fn every_combination_matches_the_spec() {
    let base = document();
    let mut cases = 0u32;
    for device in MODES {
        for disconnected in [false, true] {
            for offline in std::iter::once(None).chain(ENABLED.map(Some)) {
                for by_type in std::iter::once(None).chain(ENABLED.map(Some)) {
                    for level in LEVELS {
                        let mut doc = base.clone();
                        doc.policy.mode_options.mode_disconnected = offline;
                        if let Some(m) = by_type {
                            doc.policy.mode_options.mode_by_type.insert(T, m);
                        }
                        doc.policy.settings = PolicySettings {
                            script_control: level,
                            ..PolicySettings::default()
                        };
                        for decider in [Decider::None, Decider::Ordinary, Decider::Mandatory] {
                            for set_mode in std::iter::once(None).chain(ENABLED.map(Some)) {
                                for enforcement in OVERRIDES {
                                    let mut doc = doc.clone();
                                    let set = &mut doc.rule_sets[0];
                                    set.mandatory = decider == Decider::Mandatory;
                                    set.mode_override = set_mode;
                                    set.rules[0].enforcement_override = enforcement;
                                    let set = &doc.rule_sets[0];
                                    let rule =
                                        (decider != Decider::None).then(|| (set, &set.rules[0]));
                                    for session in SESSIONS {
                                        for lockdown in [false, true] {
                                            let state = DeviceState {
                                                mode: device,
                                                connectivity: if disconnected {
                                                    Connectivity::Disconnected
                                                } else {
                                                    Connectivity::Connected
                                                },
                                                session,
                                                lockdown,
                                            };
                                            let got = resolve(&doc.policy, T, rule, &state);
                                            let want = spec(
                                                device,
                                                disconnected,
                                                offline,
                                                by_type,
                                                level,
                                                decider,
                                                set_mode,
                                                enforcement,
                                                session,
                                                lockdown,
                                            );
                                            assert_eq!(
                                                (got.mode, got.by_session),
                                                want,
                                                "device {device:?} disconnected {disconnected} offline {offline:?} type {by_type:?} level {level:?} {decider:?} set {set_mode:?} {enforcement:?} {session:?} lockdown {lockdown}"
                                            );
                                            check_invariants(
                                                got,
                                                device,
                                                decider,
                                                enforcement,
                                                session,
                                                lockdown,
                                            );
                                            cases += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 5 * 2 * 5 * 5 * 3 * 3 * 5 * 3 * 3 * 2);
}

/// The guarantees the issue states, checked on every combination.
fn check_invariants(
    got: EffectiveMode,
    device: Mode,
    decider: Decider,
    enforcement: EnforcementOverride,
    session: Option<SessionKind>,
    lockdown: bool,
) {
    // Lockdown overrides every weaker setting.
    if lockdown {
        assert_eq!(got.mode, Mode::Enforce);
        return;
    }
    if device == Mode::Disabled {
        assert_eq!(got.mode, Mode::Disabled);
        return;
    }
    // Only a whole device is ever disabled.
    assert_ne!(got.mode, Mode::Disabled);
    // A mandatory deny enforces in every mode and every session.
    if decider == Decider::Mandatory {
        assert_eq!(got.mode, Mode::Enforce);
    }
    // `always_enforce` enforces unless a full-bypass session is active.
    if decider == Decider::Ordinary
        && enforcement == EnforcementOverride::AlwaysEnforce
        && session != Some(SessionKind::FullBypass)
    {
        assert_eq!(got.mode, Mode::Enforce);
    }
    // `never_enforce` never enforces.
    if decider == Decider::Ordinary && enforcement == EnforcementOverride::NeverEnforce {
        assert_ne!(got.mode, Mode::Enforce);
    }
    // A session reports itself only when it lowered an enforcing mode.
    if got.by_session {
        assert!(session.is_some());
        assert_ne!(got.mode, Mode::Enforce);
    }
}

#[test]
fn a_session_never_makes_a_mode_stricter_and_disconnection_never_weaker() {
    let doc = document();
    let set = &doc.rule_sets[0];
    for device in ENABLED {
        for offline in ENABLED {
            let mut policy = doc.policy.clone();
            policy.mode_options.mode_disconnected = Some(offline);
            let state = |connectivity, session| DeviceState {
                mode: device,
                connectivity,
                session,
                lockdown: false,
            };
            for rule in [None, Some((set, &set.rules[0]))] {
                let connected = resolve(&policy, T, rule, &state(Connectivity::Connected, None));
                let offline_mode =
                    resolve(&policy, T, rule, &state(Connectivity::Disconnected, None));
                assert!(strictness(offline_mode.mode) >= strictness(connected.mode));
                for session in [SessionKind::Audit, SessionKind::FullBypass] {
                    let s = resolve(
                        &policy,
                        T,
                        rule,
                        &state(Connectivity::Connected, Some(session)),
                    );
                    assert!(strictness(s.mode) <= strictness(connected.mode));
                }
            }
        }
    }
}

#[test]
fn clearing_lockdown_restores_the_prior_modes() {
    let mut doc = document();
    doc.policy.mode = Mode::Audit;
    doc.policy
        .mode_options
        .mode_by_type
        .insert(ObjectType::Library, Mode::Monitor);
    let mut state = DeviceState {
        session: Some(SessionKind::Audit),
        ..DeviceState::of(&doc.policy)
    };
    let before: Vec<_> = ObjectType::ALL
        .into_iter()
        .map(|t| object_mode(&doc.policy, &state, t))
        .collect();
    state.lockdown = true;
    for t in ObjectType::ALL {
        assert_eq!(object_mode(&doc.policy, &state, t), Mode::Enforce);
        assert_eq!(resolve(&doc.policy, t, None, &state).mode, Mode::Enforce);
    }
    assert_eq!(
        ProtectionStatus::of(&doc.policy, &state),
        ProtectionStatus::Lockdown
    );
    state.lockdown = false;
    let after: Vec<_> = ObjectType::ALL
        .into_iter()
        .map(|t| object_mode(&doc.policy, &state, t))
        .collect();
    assert_eq!(before, after);
    assert_eq!(
        ProtectionStatus::of(&doc.policy, &state),
        ProtectionStatus::OverrideActive
    );
}

#[test]
fn lockdown_enforces_a_disabled_device() {
    let doc = document();
    let state = DeviceState {
        mode: Mode::Disabled,
        lockdown: true,
        ..DeviceState::of(&doc.policy)
    };
    assert_eq!(device_mode(&doc.policy, &state), Mode::Enforce);
    let state = DeviceState {
        lockdown: false,
        ..state
    };
    assert_eq!(device_mode(&doc.policy, &state), Mode::Disabled);
}

#[test]
fn control_levels_come_from_the_settings() {
    let mut doc = document();
    doc.policy.settings.script_control = ControlLevel::Audit;
    doc.policy
        .settings
        .script_control_by_kind
        .insert(ScriptKind::Batch, ControlLevel::Off);
    doc.policy.settings.dll_control = ControlLevel::Off;
    doc.policy.settings.driver_control = ControlLevel::Audit;
    let p = &doc.policy;
    assert_eq!(control_level(p, T), ControlLevel::Audit);
    assert_eq!(
        control_level(p, ObjectType::Script(ScriptKind::Batch)),
        ControlLevel::Off
    );
    assert_eq!(control_level(p, ObjectType::Library), ControlLevel::Off);
    assert_eq!(control_level(p, ObjectType::Driver), ControlLevel::Audit);
    assert_eq!(
        control_level(p, ObjectType::Executable),
        ControlLevel::Enforce
    );
    let state = DeviceState::of(p);
    assert_eq!(object_mode(p, &state, ObjectType::Library), Mode::Monitor);
    assert_eq!(object_mode(p, &state, ObjectType::Driver), Mode::Audit);
}

#[test]
fn connectivity_follows_the_time_since_check_in() {
    let doc = document();
    let after = doc
        .policy
        .mode_options
        .disconnected_after(doc.policy.settings.poll_interval_secs);
    assert_eq!(after, 2_700);
    assert_eq!(
        Connectivity::since_check_in(2_699, after),
        Connectivity::Connected
    );
    assert_eq!(
        Connectivity::since_check_in(2_700, after),
        Connectivity::Disconnected
    );
    let mut options = doc.policy.mode_options;
    options.disconnected_after_secs = Some(600);
    assert_eq!(options.disconnected_after(900), 600);
}

#[test]
fn protection_status_distinguishes_partial_enforcement() {
    let mut doc = document();
    let status =
        |doc: &PolicyDocument| ProtectionStatus::of(&doc.policy, &DeviceState::of(&doc.policy));
    assert_eq!(status(&doc), ProtectionStatus::ProtectedEnforce);
    // A type outside Essential Eight does not matter.
    doc.policy
        .mode_options
        .mode_by_type
        .insert(ObjectType::PackagedApp, Mode::Audit);
    assert_eq!(status(&doc), ProtectionStatus::ProtectedEnforce);
    // One script kind in audit makes the device partial.
    doc.policy.mode_options.mode_by_type.insert(T, Mode::Audit);
    assert_eq!(status(&doc), ProtectionStatus::ProtectedPartial);
    doc.policy.mode_options.mode_by_type.clear();
    doc.policy.settings.dll_control = ControlLevel::Off;
    assert_eq!(status(&doc), ProtectionStatus::ProtectedPartial);
    // A device in audit with every type raised to enforce is enforced.
    let mut doc = document();
    doc.policy.mode = Mode::Audit;
    for t in essential_eight_types() {
        doc.policy
            .mode_options
            .mode_by_type
            .insert(t, Mode::Enforce);
    }
    assert_eq!(status(&doc), ProtectionStatus::ProtectedEnforce);
    for (mode, expected) in [
        (Mode::Audit, ProtectionStatus::Audit),
        (Mode::Learning, ProtectionStatus::Learning),
        (Mode::Monitor, ProtectionStatus::Monitor),
        (Mode::Disabled, ProtectionStatus::Disabled),
    ] {
        let mut doc = document();
        doc.policy.mode = mode;
        assert_eq!(status(&doc), expected);
    }
    // Disconnected and stricter offline: the offline mode counts.
    let mut doc = document();
    doc.policy.mode = Mode::Audit;
    doc.policy.mode_options.mode_disconnected = Some(Mode::Enforce);
    let state = DeviceState {
        connectivity: Connectivity::Disconnected,
        ..DeviceState::of(&doc.policy)
    };
    assert_eq!(
        ProtectionStatus::of(&doc.policy, &state),
        ProtectionStatus::ProtectedEnforce
    );
    assert_eq!(
        serde_json::to_value(ProtectionStatus::ProtectedPartial).unwrap(),
        "protected_partial"
    );
}

#[test]
fn essential_eight_types_are_the_controlled_classes() {
    let types = essential_eight_types();
    assert!(types.contains(&ObjectType::Executable));
    assert!(types.contains(&ObjectType::Driver));
    assert!(types.contains(&ObjectType::Script(ScriptKind::Other)));
    assert!(!types.contains(&ObjectType::PackagedApp));
    assert!(!types.contains(&ObjectType::Command));
    assert!(!types.contains(&ObjectType::ComObject));
}
