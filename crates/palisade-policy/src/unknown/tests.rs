//! Tests of stage 6, the unknown-application policy (#39).

use std::collections::BTreeSet;

use palisade_core::path::VolumeMap;
use proptest::prelude::*;

use super::*;
use crate::decision::TraceId;
use crate::evaluate::{Evaluator, Subject};
use crate::facts::{PathFact, SignatureSource, SignerFact, SignerStatus};
use crate::mode::{Connectivity, DeviceState};
use crate::model::{CompliancePreset, Mode, PolicyDocument, PromptSettings, ScriptKind};
use crate::validate::{ErrorCode, ValidatedPolicy};

const TRACE: TraceId = TraceId([3; 16]);
const POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";
const SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001";
const MANDATORY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002";
const PROFILE: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0c01";
const OS_PUBLISHER: &str = "Example OS Publisher";

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn rule_id(n: u32) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61")
}

/// A document with `unknown` and the given rule sets (`(id, kind,
/// mandatory, rules)`).
fn doc_with(
    unknown: serde_json::Value,
    sets: &[(&str, &str, bool, Vec<serde_json::Value>)],
) -> PolicyDocument {
    let rule_sets: Vec<serde_json::Value> = sets
        .iter()
        .map(|(id, kind, mandatory, rules)| {
            serde_json::json!({"id": id, "name": "Set", "kind": kind, "mandatory": mandatory, "rules": rules})
        })
        .collect();
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": POLICY, "name": "Unknown", "revision": 1, "mode": "enforce",
            "unknown": unknown,
            "rule_sets": sets.iter().map(|s| s.0).collect::<Vec<_>>(),
        },
        "rule_sets": rule_sets,
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn doc(unknown: serde_json::Value) -> PolicyDocument {
    doc_with(unknown, &[])
}

fn valid(doc: PolicyDocument) -> ValidatedPolicy {
    doc.validate().unwrap_or_else(|e| panic!("{e:#?}"))
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

fn interactive_context() -> EvaluationContext {
    let mut c = EvaluationContext::new();
    c.session.session_type = Some(SessionType::Console);
    c.user.is_system = Some(false);
    c.user.sid = Some("S-1-5-21-1-2-3-1001".into());
    c.device.containment_available = Some(true);
    c
}

fn object(locations: &[LocationClass], origins: &[OriginClass]) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha('a'))
        .with_location_class(locations.iter().copied())
        .with_origin(origins.iter().copied())
}

fn decide_with(
    v: &ValidatedPolicy,
    t: ObjectType,
    facts: &ObjectFacts,
    context: &EvaluationContext,
) -> Decision {
    let variables = PathVariables::new();
    Evaluator::new(v).unwrap().evaluate(
        &Subject {
            object_type: t,
            facts,
            variables: &variables,
            context,
        },
        TRACE,
    )
}

fn decide(v: &ValidatedPolicy, t: ObjectType, facts: &ObjectFacts) -> Decision {
    decide_with(v, t, facts, &interactive_context())
}

/// [`decide`] with every path variable the classifier reads set
/// ([`vars`]): full facts for an object classified from its path.
fn decide_full(v: &ValidatedPolicy, t: ObjectType, facts: &ObjectFacts) -> Decision {
    let variables = vars();
    let context = interactive_context();
    Evaluator::new(v).unwrap().evaluate(
        &Subject {
            object_type: t,
            facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    )
}

fn level_set<T: Ord + Copy>(items: &[T]) -> BTreeSet<T> {
    items.iter().copied().collect()
}

// ---------------------------------------------------------------- levels

#[test]
fn the_default_blocks_every_unknown_object_in_every_location() {
    let v = valid(doc(serde_json::json!({})));
    for t in ObjectType::ALL {
        for class in LocationClass::ALL {
            for origin in OriginClass::ALL {
                let d = decide(&v, t, &object(&[class], &[origin]));
                assert_eq!(d.outcome(), Outcome::Blocked, "{t} {class:?} {origin:?}");
                assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
                assert!(d.unhandled());
                assert_eq!(d.matched_rule(), None);
            }
        }
    }
}

#[test]
fn default_unknown_is_not_serialised() {
    let d = doc(serde_json::json!({}));
    assert!(!d.to_json_pretty().unwrap().contains("\"unknown\""));
}

#[test]
fn the_most_restrictive_entry_wins_over_location_origin_and_type() {
    let p: UnknownPolicy = serde_json::from_value(serde_json::json!({
        "default": "allow",
        "by_location": {"program_files": "detect", "temp": "block", "user_profile": "prompt"},
        "by_origin": {"internet": "restrict", "preexisting": "detect"},
        "by_type": {"script.powershell": "prompt", "executable": "detect"},
    }))
    .unwrap();
    let ps = ObjectType::Script(ScriptKind::Powershell);
    let cases = [
        (
            ObjectType::Executable,
            vec![LocationClass::ProgramFiles],
            vec![OriginClass::Preexisting],
            Level::Detect,
        ),
        (
            ObjectType::Executable,
            vec![LocationClass::ProgramFiles],
            vec![OriginClass::Internet],
            Level::Restrict,
        ),
        (
            ObjectType::Executable,
            vec![LocationClass::UserProfile, LocationClass::Temp],
            vec![OriginClass::Internet],
            Level::Block,
        ),
        (
            ps,
            vec![LocationClass::ProgramFiles],
            vec![OriginClass::Unknown],
            Level::Prompt,
        ),
        (
            ps,
            vec![LocationClass::UserProfile],
            vec![OriginClass::Internet],
            Level::Restrict,
        ),
        // No entry applies: the default.
        (
            ObjectType::Library,
            vec![LocationClass::OtherFixed],
            vec![OriginClass::Unknown],
            Level::Allow,
        ),
    ];
    for (t, locations, origins, want) in cases {
        let (got, entries) = resolve_level(&p, t, &level_set(&locations), &level_set(&origins));
        assert_eq!(got, want, "{t} {locations:?} {origins:?}");
        assert!(!entries.is_empty());
    }
    let (_, entries) = resolve_level(
        &p,
        ObjectType::Library,
        &level_set(&[LocationClass::OtherFixed]),
        &level_set(&[OriginClass::Unknown]),
    );
    assert_eq!(entries[0].kind, EntryKind::Default);
}

#[test]
fn level_order_is_block_restrict_prompt_detect_allow() {
    assert!(Level::Block > Level::Restrict);
    assert!(Level::Restrict > Level::Prompt);
    assert!(Level::Prompt > Level::Detect);
    assert!(Level::Detect > Level::Allow);
}

/// A naive statement of the rule: the maximum over every entry that
/// applies, or the default.
fn reference_level(
    p: &UnknownPolicy,
    t: ObjectType,
    locations: &BTreeSet<LocationClass>,
    origins: &BTreeSet<OriginClass>,
) -> Level {
    let mut applied: Vec<Level> = Vec::new();
    if let Some(l) = p.by_type.get(&t) {
        applied.push(*l);
    }
    for c in locations {
        if let Some(l) = p.by_location.get(c) {
            applied.push(*l);
        }
    }
    for o in origins {
        if let Some(l) = p.by_origin.get(o) {
            applied.push(*l);
        }
    }
    let mut best = None;
    for l in applied {
        best = Some(match best {
            None => l,
            Some(b) if l > b => l,
            Some(b) => b,
        });
    }
    best.unwrap_or(p.default)
}

fn arb_level() -> impl Strategy<Value = Level> {
    prop::sample::select(Level::ALL.to_vec())
}

fn arb_policy() -> impl Strategy<Value = UnknownPolicy> {
    (
        arb_level(),
        prop::collection::btree_map(
            prop::sample::select(LocationClass::ALL.to_vec()),
            arb_level(),
            0..6,
        ),
        prop::collection::btree_map(
            prop::sample::select(OriginClass::ALL.to_vec()),
            arb_level(),
            0..5,
        ),
        prop::collection::btree_map(
            prop::sample::select(ObjectType::ALL.to_vec()),
            arb_level(),
            0..6,
        ),
    )
        .prop_map(|(default, by_location, by_origin, by_type)| UnknownPolicy {
            default,
            by_location,
            by_origin,
            by_type,
            ..UnknownPolicy::default()
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The resolved level is the most restrictive applicable entry, and
    /// adding a class or an origin never makes an object's level weaker.
    #[test]
    fn resolution_is_the_most_restrictive_and_monotonic(
        p in arb_policy(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 0..4),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3),
        more_l in prop::sample::select(LocationClass::ALL.to_vec()),
        more_o in prop::sample::select(OriginClass::ALL.to_vec()),
    ) {
        let (got, _) = resolve_level(&p, t, &locations, &origins);
        prop_assert_eq!(got, reference_level(&p, t, &locations, &origins));
        // Only when some entry already applied: otherwise the default may
        // be stricter than the entry the new class brings.
        let any_entry = p.by_type.contains_key(&t)
            || locations.iter().any(|c| p.by_location.contains_key(c))
            || origins.iter().any(|o| p.by_origin.contains_key(o));
        if any_entry {
            let mut l2 = locations.clone();
            l2.insert(more_l);
            let mut o2 = origins.clone();
            o2.insert(more_o);
            let (wider, _) = resolve_level(&p, t, &l2, &o2);
            prop_assert!(wider >= got);
        }
    }

    /// Stage 6 never overrides a rule: an object that a rule decides gets
    /// the same decision whatever the unknown policy says.
    #[test]
    fn stage_six_never_overrides_an_explicit_rule(p in arb_policy(), deny in any::<bool>()) {
        let action = if deny { serde_json::json!({"type": "deny"}) } else { serde_json::json!({"type": "allow"}) };
        let rule = serde_json::json!({
            "id": rule_id(1), "name": "R", "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
            "action": action,
        });
        let mut d = doc_with(serde_json::json!({}), &[(SET, "mixed", false, vec![rule])]);
        let base = decide(&valid(d.clone()), ObjectType::Executable, &object(&[LocationClass::Temp], &[OriginClass::Internet]));
        d.policy.unknown = UnknownPolicy { restrict_profile: Some(PROFILE.parse().map(crate::model::ContainmentProfileRef).unwrap()), ..p };
        // Some random policies are invalid (a `restrict` on a library);
        // only the valid ones matter here.
        if let Ok(v) = d.validate() {
            let again = decide(&v, ObjectType::Executable, &object(&[LocationClass::Temp], &[OriginClass::Internet]));
            prop_assert_eq!(again, base);
        }
    }
}

// ------------------------------------------------------- level decisions

fn with_profile(mut u: serde_json::Value) -> serde_json::Value {
    u.as_object_mut()
        .unwrap()
        .insert("restrict_profile".into(), PROFILE.into());
    u
}

#[test]
fn each_level_has_its_documented_decision() {
    let cases = [
        (
            "block",
            Outcome::Blocked,
            ReasonCode::ImplicitDenyUnknown,
            ActionKind::Deny,
        ),
        (
            "restrict",
            Outcome::Allowed,
            ReasonCode::UnknownRestricted,
            ActionKind::AllowContained,
        ),
        (
            "prompt",
            Outcome::PendingUser,
            ReasonCode::UnknownPrompt,
            ActionKind::Deny,
        ),
        (
            "detect",
            Outcome::Allowed,
            ReasonCode::UnknownDetected,
            ActionKind::Allow,
        ),
        (
            "allow",
            Outcome::Allowed,
            ReasonCode::UnknownAllowed,
            ActionKind::Allow,
        ),
    ];
    for (level, outcome, reason, action) in cases {
        let v = valid(doc(with_profile(serde_json::json!({"default": level}))));
        let d = decide(
            &v,
            ObjectType::Executable,
            &object(&[LocationClass::OtherFixed], &[]),
        );
        assert_eq!(
            (d.outcome(), d.reason_code(), d.action()),
            (outcome, reason, action),
            "{level}"
        );
        let h = d.unknown().unwrap();
        assert_eq!(h.applied.as_str(), level);
        assert_eq!(h.fallback, None);
        assert_eq!(h.origins, vec![OriginClass::Unknown]);
    }
}

#[test]
fn detect_logs_at_medium_and_restrict_carries_the_profile() {
    let v = valid(doc(with_profile(
        serde_json::json!({"default": "detect", "by_location": {"temp": "restrict"}}),
    )));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::OtherFixed], &[]),
    );
    assert_eq!(d.effects().severity, EventSeverity::Medium);
    assert_eq!(d.effects().log, LogLevel::Always);
    assert_eq!(d.effects().upload, Upload::Immediate);
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    assert_eq!(
        d.directives().containment.unwrap().profile_id.to_string(),
        PROFILE
    );
    assert_eq!(d.effects().severity, EventSeverity::Medium);
}

#[test]
fn the_policy_effects_apply_to_stage_six() {
    let v = valid(doc(serde_json::json!({
        "effects": {"severity": "high", "tags": ["unhandled"], "notify": "none"}
    })));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    assert_eq!(d.effects().severity, EventSeverity::High);
    assert_eq!(d.effects().tags, vec!["unhandled".to_owned()]);
    assert_eq!(d.effects().notify, Notify::None);
}

#[test]
fn allow_request_on_block_gives_a_request_directive() {
    let v = valid(doc(serde_json::json!({"allow_request": true})));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    assert!(d.directives().request.is_some());
}

// ------------------------------------------------------------- fallbacks

#[test]
fn restrict_without_the_containment_component_fails_closed() {
    let v = valid(doc(with_profile(
        serde_json::json!({"default": "restrict"}),
    )));
    let mut context = interactive_context();
    for available in [None, Some(false)] {
        context.device.containment_available = available;
        let d = decide_with(
            &v,
            ObjectType::Executable,
            &object(&[LocationClass::Temp], &[]),
            &context,
        );
        assert_eq!(d.outcome(), Outcome::Blocked);
        assert_eq!(d.reason_code(), ReasonCode::RestrictUnavailable);
        assert_eq!(
            d.unknown().unwrap().fallback,
            Some(FallbackReason::RestrictUnavailable)
        );
        assert!(d.directives().containment.is_none());
    }
}

#[test]
fn restrict_on_a_type_that_cannot_be_contained_blocks() {
    // By location, so validation cannot see the type.
    let v = valid(doc(with_profile(
        serde_json::json!({"by_location": {"temp": "restrict"}, "default": "detect"}),
    )));
    let d = decide(
        &v,
        ObjectType::Library,
        &object(&[LocationClass::Temp], &[]),
    );
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::RestrictUnavailable);
    assert_eq!(
        d.unknown().unwrap().fallback,
        Some(FallbackReason::RestrictNotValidForType)
    );
}

#[test]
fn prompts_never_appear_for_libraries_drivers_or_non_interactive_sessions() {
    let v = valid(doc(
        serde_json::json!({"by_location": {"temp": "prompt"}, "default": "detect"}),
    ));
    for t in [ObjectType::Library, ObjectType::Driver] {
        let d = decide(&v, t, &object(&[LocationClass::Temp], &[]));
        assert_eq!(d.outcome(), Outcome::Blocked, "{t}");
        assert_eq!(
            d.unknown().unwrap().fallback,
            Some(FallbackReason::NotPromptableType)
        );
        assert!(d.directives().prompt.is_none());
    }
    let mut cases = Vec::new();
    for session in [
        None,
        Some(SessionType::Service),
        Some(SessionType::Batch),
        Some(SessionType::Network),
        Some(SessionType::RemoteShell),
    ] {
        let mut c = interactive_context();
        c.session.session_type = session;
        cases.push(c);
    }
    let mut system = interactive_context();
    system.user.is_system = Some(true);
    cases.push(system);
    for c in cases {
        let d = decide_with(
            &v,
            ObjectType::Executable,
            &object(&[LocationClass::Temp], &[]),
            &c,
        );
        assert_eq!(d.outcome(), Outcome::Blocked);
        assert_eq!(
            d.unknown().unwrap().fallback,
            Some(FallbackReason::NonInteractive)
        );
    }
    // An RDP session of an ordinary user is interactive.
    let mut rdp = interactive_context();
    rdp.session.session_type = Some(SessionType::Rdp);
    let d = decide_with(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
        &rdp,
    );
    assert_eq!(d.outcome(), Outcome::PendingUser);
}

#[test]
fn a_blocklisted_object_is_never_promptable() {
    // An audit-mode blocklist sets its deny aside, but the object still is
    // not promptable; neither is an object only an `audit` rule in a
    // blocklist matched.
    let deny = serde_json::json!({
        "id": rule_id(1), "name": "D",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": "deny", "unknown_as": "no_match"},
    });
    let audit = serde_json::json!({
        "id": rule_id(2), "name": "A",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": "audit"},
    });
    for rule in [deny, audit] {
        let mut d = doc_with(
            serde_json::json!({"default": "prompt", "prompt": {"fallback": "detect"}}),
            &[(SET, "blocklist", false, vec![rule])],
        );
        d.rule_sets[0].mode_override = Some(Mode::Audit);
        let v = valid(d);
        let e = Evaluator::new(&v).unwrap();
        let facts = object(&[LocationClass::Temp], &[]);
        let variables = PathVariables::new();
        let context = interactive_context();
        let subject = Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        };
        let d = e
            .evaluate_in(&subject, &DeviceState::of(&v.document().policy), TRACE)
            .unwrap();
        assert_ne!(d.outcome(), Outcome::PendingUser);
        assert!(d.directives().prompt.is_none());
        if d.unhandled() {
            assert_eq!(
                d.unknown().unwrap().fallback,
                Some(FallbackReason::Blocklisted)
            );
            assert_eq!(d.outcome(), Outcome::Allowed);
        }
    }
}

#[test]
fn preexisting_files_are_blocked_unless_the_baseline_allows_them() {
    let v = valid(doc(serde_json::json!({"default": "detect"})));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::ProgramFiles], &[OriginClass::Preexisting]),
    );
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(
        d.unknown().unwrap().fallback,
        Some(FallbackReason::PreexistingBaselineOnly)
    );
    let v = valid(doc(
        serde_json::json!({"default": "detect", "preexisting_policy": "treat_as_unknown"}),
    ));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::ProgramFiles], &[OriginClass::Preexisting]),
    );
    assert_eq!(d.outcome(), Outcome::Allowed);
}

#[test]
fn missing_location_facts_classify_from_the_path_or_fail_closed() {
    let v = valid(doc(
        serde_json::json!({"default": "detect", "by_location": {"user_writable_other": "block"}}),
    ));
    // No path at all: every location class is `Unknown` (round six; it
    // was a definite `user_writable_other`), so the strictest applies.
    let d = decide(
        &v,
        ObjectType::Executable,
        &ObjectFacts::new().with_origin([]),
    );
    assert_eq!(d.outcome(), Outcome::Blocked);
    let u = d.unknown().unwrap();
    assert!(u.locations.is_empty());
    assert_eq!(u.unknown_locations, LocationClass::ALL.to_vec());
    assert!(u.missing_facts.contains(&MissingFact::Path));
    // A path with unknown ACL facts could be user-writable, so the
    // `user_writable_other` entry applies too.
    let facts = ObjectFacts::new()
        .with_path(
            PathFact::new("D:\\data\\a.exe", &VolumeMap::new()).with_volume(VolumeKind::Fixed),
        )
        .with_origin([]);
    let d = decide_full(&v, ObjectType::Executable, &facts);
    assert_eq!(d.outcome(), Outcome::Blocked);
    // A safe path elsewhere on a fixed disk (full facts: the volume and
    // the origin collection's answer).
    let facts = ObjectFacts::new()
        .with_path(
            PathFact::new("D:\\data\\a.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed)
                .with_volume(VolumeKind::Fixed),
        )
        .with_origin([]);
    let d = decide_full(&v, ObjectType::Executable, &facts);
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(
        d.unknown().unwrap().locations,
        vec![LocationClass::OtherFixed]
    );
}

// ---------------------------------------------------------------- prompts

fn prompt_policy(extra: serde_json::Value) -> ValidatedPolicy {
    let mut u = serde_json::json!({"default": "prompt", "prompt": {
        "options": ["allow_once", "allow_always_local", "request_approval", "block"],
    }});
    for (k, v) in extra.as_object().unwrap() {
        u["prompt"]
            .as_object_mut()
            .unwrap()
            .insert(k.clone(), v.clone());
    }
    valid(doc(u))
}

#[test]
fn a_prompt_carries_its_options_timeout_and_fallback() {
    let v = prompt_policy(
        serde_json::json!({"timeout_secs": 30, "require_justification": true, "reauth": "mfa"}),
    );
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    let p = d.directives().prompt.as_ref().unwrap();
    assert_eq!(p.timeout_secs, 30);
    assert_eq!(p.reauth, Reauth::Mfa);
    assert!(p.require_justification);
    assert_eq!(p.options.len(), 4);
    assert_eq!(p.fallback.level, Level::Block);
    assert_eq!(p.fallback.outcome, Outcome::Blocked);
    assert_eq!(p.sha256.as_deref(), Some(sha('a').as_str()));
    assert_eq!(d.effects().notify, Notify::None);
}

#[test]
fn the_default_prompt_timeout_is_sixty_seconds_and_falls_back_to_block() {
    let p = PromptSettings::default();
    assert_eq!(p.timeout_secs, 60);
    assert_eq!(p.fallback, Level::Block);
    assert_eq!(p.temp_approval_days, 14);
}

#[test]
fn allow_always_local_is_only_offered_with_a_hash() {
    let v = prompt_policy(serde_json::json!({}));
    let facts = ObjectFacts::new()
        .with_location_class([LocationClass::Temp])
        .with_origin([]);
    let d = decide(&v, ObjectType::Executable, &facts);
    let p = d.directives().prompt.as_ref().unwrap();
    assert!(!p.options.contains(&PromptOption::AllowAlwaysLocal));
}

#[test]
fn allow_always_local_from_risky_origins_is_a_fourteen_day_approval() {
    let v = prompt_policy(serde_json::json!({}));
    let now = 1_800_000_000;
    let sid = Some("S-1-5-21-1-2-3-1001");
    let choose = PromptAnswer::Chose {
        option: PromptOption::AllowAlwaysLocal,
        justification: None,
        reauthenticated: false,
    };
    for (locations, origins) in [
        (vec![LocationClass::OtherFixed], vec![OriginClass::Internet]),
        (
            vec![LocationClass::OtherFixed],
            vec![OriginClass::RemovableCopy],
        ),
        (
            vec![LocationClass::OtherFixed],
            vec![OriginClass::NetworkShare],
        ),
        (
            vec![LocationClass::OtherFixed],
            vec![OriginClass::EmailAttachment],
        ),
        (
            vec![LocationClass::Removable],
            vec![OriginClass::TrustedSource],
        ),
        (
            vec![LocationClass::Network],
            vec![OriginClass::TrustedSource],
        ),
        (vec![LocationClass::OtherFixed], vec![]),
    ] {
        let d = decide(&v, ObjectType::Executable, &object(&locations, &origins));
        let r = answer(&d, &choose, sid, now).unwrap();
        let a = r.approval.unwrap();
        assert_eq!(
            a.expires_at,
            Some(now + 14 * 86_400),
            "{locations:?} {origins:?}"
        );
        assert!(a.upload_for_review);
        assert_eq!(r.outcome, Outcome::Allowed);
        assert!(a.applies(&sha('A'), sid, now + 14 * 86_400 - 1));
        assert!(!a.applies(&sha('a'), sid, now + 14 * 86_400));
        assert!(!a.applies(&sha('b'), sid, now));
        assert!(!a.applies(&sha('a'), Some("S-1-5-21-1-2-3-1002"), now));
    }
    // A preexisting... no: a trusted-source file on a fixed disk is permanent.
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::OtherFixed], &[OriginClass::TrustedSource]),
    );
    let a = answer(&d, &choose, sid, now).unwrap().approval.unwrap();
    assert_eq!(a.expires_at, None);
    assert_eq!(a.scope, ApprovalScope::User);
    assert_eq!(a.user_sid.as_deref(), Some("S-1-5-21-1-2-3-1001"));
}

#[test]
fn a_device_scoped_approval_applies_to_every_user() {
    let v = prompt_policy(
        serde_json::json!({"local_approval_scope": "device", "temp_approval_days": 7}),
    );
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::OtherFixed], &[OriginClass::Internet]),
    );
    let choose = PromptAnswer::Chose {
        option: PromptOption::AllowAlwaysLocal,
        justification: None,
        reauthenticated: false,
    };
    let a = answer(&d, &choose, None, 0).unwrap().approval.unwrap();
    assert_eq!(a.expires_at, Some(7 * 86_400));
    assert!(a.applies(&sha('a'), None, 1));
    assert!(a.applies(&sha('a'), Some("S-1-5-18"), 1));
}

#[test]
fn answers_are_checked_against_the_prompt() {
    let v = prompt_policy(
        serde_json::json!({"require_justification": true, "reauth": "password", "options": ["allow_once", "block"]}),
    );
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    let chose = |option, justification: Option<&str>, reauthenticated| PromptAnswer::Chose {
        option,
        justification: justification.map(str::to_owned),
        reauthenticated,
    };
    assert_eq!(
        answer(
            &d,
            &chose(PromptOption::AllowAlwaysLocal, Some("x"), true),
            None,
            0
        ),
        Err(AnswerError::NotOffered)
    );
    assert_eq!(
        answer(&d, &chose(PromptOption::AllowOnce, None, true), None, 0),
        Err(AnswerError::JustificationRequired)
    );
    assert_eq!(
        answer(
            &d,
            &chose(PromptOption::AllowOnce, Some("  "), true),
            None,
            0
        ),
        Err(AnswerError::JustificationRequired)
    );
    assert_eq!(
        answer(
            &d,
            &chose(PromptOption::AllowOnce, Some("why"), false),
            None,
            0
        ),
        Err(AnswerError::ReauthRequired)
    );
    let ok = answer(
        &d,
        &chose(PromptOption::AllowOnce, Some("why"), true),
        None,
        0,
    )
    .unwrap();
    assert_eq!(ok.outcome, Outcome::Allowed);
    assert!(ok.approval.is_none());
    // Blocking needs neither a reason nor re-authentication.
    let block = answer(&d, &chose(PromptOption::Block, None, false), None, 0).unwrap();
    assert_eq!(block.outcome, Outcome::Blocked);
    // Timeouts and prompts that cannot be shown take the fallback.
    for a in [PromptAnswer::TimedOut, PromptAnswer::NotShown] {
        assert_eq!(answer(&d, &a, None, 0).unwrap().outcome, Outcome::Blocked);
    }
    // A decision that is not a prompt.
    let blocked = decide(
        &valid(doc(serde_json::json!({}))),
        ObjectType::Executable,
        &object(&[], &[]),
    );
    assert_eq!(
        answer(&blocked, &PromptAnswer::TimedOut, None, 0),
        Err(AnswerError::NotAPrompt)
    );
}

#[test]
fn request_approval_blocks_and_raises_a_request() {
    let v = prompt_policy(serde_json::json!({}));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    let r = answer(
        &d,
        &PromptAnswer::Chose {
            option: PromptOption::RequestApproval,
            justification: None,
            reauthenticated: false,
        },
        None,
        0,
    )
    .unwrap();
    assert_eq!(r.outcome, Outcome::Blocked);
    assert!(r.request_approval);
}

#[test]
fn a_user_scoped_approval_needs_the_user() {
    let v = prompt_policy(serde_json::json!({}));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    let choose = PromptAnswer::Chose {
        option: PromptOption::AllowAlwaysLocal,
        justification: None,
        reauthenticated: false,
    };
    assert_eq!(answer(&d, &choose, None, 0), Err(AnswerError::UserUnknown));
    assert_eq!(
        answer(&d, &choose, Some("S-1-5-21-1"), i64::MAX),
        Err(AnswerError::TimeOverflow)
    );
}

#[test]
fn a_restrict_fallback_carries_the_profile() {
    let v = valid(doc(with_profile(
        serde_json::json!({"default": "prompt", "prompt": {"fallback": "restrict"}}),
    )));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    let p = d.directives().prompt.as_ref().unwrap();
    assert_eq!(p.fallback.level, Level::Restrict);
    let r = answer(&d, &PromptAnswer::TimedOut, None, 0).unwrap();
    assert_eq!(r.outcome, Outcome::Allowed);
    assert!(r.containment.is_some());
    // Without the component, the fallback fails closed too.
    let mut c = interactive_context();
    c.device.containment_available = Some(false);
    let d = decide_with(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
        &c,
    );
    let p = d.directives().prompt.as_ref().unwrap();
    assert_eq!(p.fallback.outcome, Outcome::Blocked);
    assert_eq!(p.fallback.reason_code, ReasonCode::RestrictUnavailable);
}

// ----------------------------------------------------------------- modes

fn evaluate_in(
    v: &ValidatedPolicy,
    t: ObjectType,
    facts: &ObjectFacts,
    context: &EvaluationContext,
    mode: Mode,
) -> Decision {
    let variables = PathVariables::new();
    let mut state = DeviceState::of(&v.document().policy);
    state.mode = mode;
    Evaluator::new(v)
        .unwrap()
        .evaluate_in(
            &Subject {
                object_type: t,
                facts,
                variables: &variables,
                context,
            },
            &state,
            TRACE,
        )
        .unwrap()
}

#[test]
fn a_prompt_is_relaxed_in_audit_and_every_stage_six_object_is_a_learning_candidate() {
    let v = prompt_policy(serde_json::json!({}));
    let facts = object(&[LocationClass::Temp], &[]);
    let d = evaluate_in(
        &v,
        ObjectType::Executable,
        &facts,
        &interactive_context(),
        Mode::Audit,
    );
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::PendingUser);
    assert!(d.directives().prompt.is_none());
    for level in ["block", "detect", "prompt"] {
        let v = valid(doc(serde_json::json!({"default": level})));
        let d = evaluate_in(
            &v,
            ObjectType::Executable,
            &facts,
            &interactive_context(),
            Mode::Learning,
        );
        assert!(d.learning_candidate(), "{level}");
        assert_eq!(d.mode(), Mode::Learning);
        let d = evaluate_in(
            &v,
            ObjectType::Executable,
            &facts,
            &interactive_context(),
            Mode::Enforce,
        );
        assert!(!d.learning_candidate());
    }
}

#[test]
fn a_denied_object_is_never_a_learning_candidate() {
    let rule = serde_json::json!({
        "id": rule_id(1), "name": "D",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": "deny"},
    });
    let v = valid(doc_with(
        serde_json::json!({"default": "detect"}),
        &[(SET, "blocklist", false, vec![rule])],
    ));
    let d = evaluate_in(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
        &interactive_context(),
        Mode::Learning,
    );
    assert!(!d.learning_candidate());
    assert!(!d.unhandled());
}

#[test]
fn early_boot_drivers_follow_driver_boot_policy() {
    let mut c = interactive_context();
    c.device.boot_phase = Some(BootPhase::Early);
    let facts = object(&[LocationClass::Windows], &[]);
    let audit = valid(doc(serde_json::json!({})));
    let d = evaluate_in(&audit, ObjectType::Driver, &facts, &c, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
    // Only drivers, and only in early boot.
    let d = evaluate_in(&audit, ObjectType::Executable, &facts, &c, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    c.device.boot_phase = Some(BootPhase::Running);
    let d = evaluate_in(&audit, ObjectType::Driver, &facts, &c, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    // `enforce` applies the level.
    c.device.boot_phase = Some(BootPhase::Early);
    let enforce = valid(doc(serde_json::json!({"driver_boot_policy": "enforce"})));
    let d = evaluate_in(&enforce, ObjectType::Driver, &facts, &c, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    // A deny rule still blocks a driver in early boot.
    let rule = serde_json::json!({
        "id": rule_id(1), "name": "D",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": "deny"},
    });
    let v = valid(doc_with(
        serde_json::json!({}),
        &[(SET, "blocklist", false, vec![rule])],
    ));
    let d = evaluate_in(&v, ObjectType::Driver, &facts, &c, Mode::Enforce);
    assert_eq!(d.outcome(), Outcome::Blocked);
    // Lockdown enforces stage 6 even in early boot.
    let variables = PathVariables::new();
    let mut state = DeviceState::of(&audit.document().policy);
    state.lockdown = true;
    let d = Evaluator::new(&audit)
        .unwrap()
        .evaluate_in(
            &Subject {
                object_type: ObjectType::Driver,
                facts: &facts,
                variables: &variables,
                context: &c,
            },
            &state,
            TRACE,
        )
        .unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
}

#[test]
fn disconnected_devices_keep_unknown_handling() {
    let v = valid(doc(
        serde_json::json!({"default": "detect", "by_location": {"temp": "block"}}),
    ));
    let variables = PathVariables::new();
    let facts = object(&[LocationClass::Temp], &[]);
    let c = interactive_context();
    let mut state = DeviceState::of(&v.document().policy);
    state.connectivity = Connectivity::Disconnected;
    let d = Evaluator::new(&v)
        .unwrap()
        .evaluate_in(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables: &variables,
                context: &c,
            },
            &state,
            TRACE,
        )
        .unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
}

// ------------------------------------------------------------- validation

#[test]
fn validation_of_levels_and_prompt_settings() {
    let found = codes(doc(serde_json::json!({
        "by_type": {"library": "prompt", "driver": "restrict", "executable": "restrict", "compiled_html": "allow"},
        "prompt": {"options": ["block", "block"], "fallback": "prompt", "timeout_secs": 5, "temp_approval_days": 365},
    })));
    let want = [
        (
            ErrorCode::UnknownLevelNotValidForType,
            "/policy/unknown/by_type/driver",
        ),
        (
            ErrorCode::UnknownLevelNotValidForType,
            "/policy/unknown/by_type/library",
        ),
        (
            ErrorCode::RestrictProfileRequired,
            "/policy/unknown/restrict_profile",
        ),
        (
            ErrorCode::InvalidPromptSettings,
            "/policy/unknown/prompt/options/1",
        ),
        (
            ErrorCode::InvalidPromptSettings,
            "/policy/unknown/prompt/fallback",
        ),
        (
            ErrorCode::SettingOutOfRange,
            "/policy/unknown/prompt/timeout_secs",
        ),
        (
            ErrorCode::SettingOutOfRange,
            "/policy/unknown/prompt/temp_approval_days",
        ),
        (
            ErrorCode::UnknownAllow,
            "/policy/unknown/by_type/compiled_html",
        ),
    ];
    for (code, path) in want {
        assert!(
            found.contains(&(code, path.to_owned())),
            "{code} {path}: {found:#?}"
        );
    }
}

#[test]
fn allow_warns_and_empty_options_are_rejected() {
    let found = codes(doc(serde_json::json!({"default": "allow"})));
    assert_eq!(
        found,
        vec![(
            ErrorCode::UnknownAllow,
            "/policy/unknown/default".to_owned()
        )]
    );
    let found = codes(doc(serde_json::json!({"prompt": {"options": []}})));
    assert!(found.contains(&(
        ErrorCode::InvalidPromptSettings,
        "/policy/unknown/prompt/options".to_owned()
    )));
}

#[test]
fn unknown_effects_are_validated_as_a_deny() {
    let found = codes(doc(
        serde_json::json!({"effects": {"log": "never"}, "allow_request": true}),
    ));
    assert!(found.contains(&(
        ErrorCode::LogLevelNotAllowed,
        "/policy/unknown/effects/log".to_owned()
    )));
    let found = codes(doc(
        serde_json::json!({"effects": {"notify": "none"}, "allow_request": true}),
    ));
    assert!(found.contains(&(
        ErrorCode::InvalidActionOption,
        "/policy/unknown/allow_request".to_owned()
    )));
}

// ---------------------------------------------------------------- presets

fn preset_json(p: CompliancePreset) -> serde_json::Value {
    serde_json::to_value(UnknownPolicy::preset(p)).unwrap()
}

fn mandatory_set() -> (&'static str, &'static str, bool, Vec<serde_json::Value>) {
    let rule = serde_json::json!({
        "id": rule_id(9), "name": "M",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('f')]}},
        "action": {"type": "deny"},
    });
    (MANDATORY, "blocklist", true, vec![rule])
}

#[test]
fn presets_produce_the_documented_configuration() {
    let ml1 = UnknownPolicy::preset(CompliancePreset::E8Ml1);
    assert_eq!(ml1.default, Level::Detect);
    for c in [
        LocationClass::UserProfile,
        LocationClass::Temp,
        LocationClass::UserWritableOther,
    ] {
        assert_eq!(ml1.by_location.get(&c), Some(&Level::Block));
    }
    assert_eq!(ml1.by_location.len(), 3);
    let ml2 = UnknownPolicy::preset(CompliancePreset::E8Ml2);
    assert_eq!(ml2.default, Level::Block);
    assert!(ml2.by_location.is_empty() && ml2.by_type.is_empty());
    let ml3 = UnknownPolicy::preset(CompliancePreset::E8Ml3);
    assert_eq!(ml3.by_type.get(&ObjectType::Driver), Some(&Level::Block));
    for p in [CompliancePreset::E8Ml1, CompliancePreset::E8Ml2] {
        assert_eq!(codes(doc(preset_json(p))), vec![], "{p:?}");
    }
    // The early-boot exemption is reported (deliberate, see
    // `ml3_warns_while_early_boot_drivers_are_only_audited`).
    let boot = (
        ErrorCode::ComplianceWeakened,
        "/policy/unknown/driver_boot_policy".to_owned(),
    );
    assert_eq!(
        codes(doc(preset_json(CompliancePreset::E8Ml3))),
        vec![
            boot.clone(),
            (
                ErrorCode::MandatoryBlocklistRequired,
                "/policy/rule_sets".to_owned()
            )
        ]
    );
    assert_eq!(
        codes(doc_with(
            preset_json(CompliancePreset::E8Ml3),
            &[mandatory_set()]
        )),
        vec![boot]
    );
}

#[test]
fn ml1_blocks_user_locations_and_detects_elsewhere() {
    let v = valid(doc(preset_json(CompliancePreset::E8Ml1)));
    for (class, want) in [
        (LocationClass::UserProfile, Outcome::Blocked),
        (LocationClass::Temp, Outcome::Blocked),
        (LocationClass::UserWritableOther, Outcome::Blocked),
        (LocationClass::ProgramFiles, Outcome::Allowed),
        (LocationClass::Network, Outcome::Allowed),
    ] {
        let d = decide(&v, ObjectType::Executable, &object(&[class], &[]));
        assert_eq!(d.outcome(), want, "{class:?}");
    }
}

#[test]
fn weakening_a_preset_raises_the_compliance_warning() {
    let mut u = preset_json(CompliancePreset::E8Ml2);
    u["by_location"] = serde_json::json!({"network": "detect"});
    let found = codes(doc(u));
    assert_eq!(
        found,
        vec![(ErrorCode::ComplianceWeakened, "/policy/unknown".to_owned())]
    );
    // A stricter change is fine.
    let mut u = preset_json(CompliancePreset::E8Ml1);
    u["by_location"]["network"] = "block".into();
    assert_eq!(codes(doc(u)), vec![]);
    // A prompt is weaker than a block: the user can let the object run.
    let mut u = preset_json(CompliancePreset::E8Ml2);
    u["by_origin"] = serde_json::json!({"internet": "prompt"});
    assert_eq!(
        codes(doc(u)),
        vec![(ErrorCode::ComplianceWeakened, "/policy/unknown".to_owned())]
    );
    // Under ML1, a prompt where the preset detects is stricter, unless its
    // fallback is weaker than `detect`.
    let mut u = preset_json(CompliancePreset::E8Ml1);
    u["by_location"]["network"] = "prompt".into();
    assert_eq!(codes(doc(u.clone())), vec![]);
    u["prompt"] = serde_json::json!({"fallback": "allow"});
    let found = codes(doc(u));
    assert!(
        found.contains(&(ErrorCode::ComplianceWeakened, "/policy/unknown".to_owned())),
        "{found:?}"
    );
    // `preexisting_policy`.
    let mut u = preset_json(CompliancePreset::E8Ml2);
    u["preexisting_policy"] = "treat_as_unknown".into();
    assert_eq!(
        codes(doc(u)),
        vec![(
            ErrorCode::ComplianceWeakened,
            "/policy/unknown/preexisting_policy".to_owned()
        )]
    );
}

#[test]
fn a_preset_never_permits_a_silent_allow_in_user_locations() {
    let mut u = preset_json(CompliancePreset::E8Ml1);
    u["by_location"]["temp"] = "allow".into();
    let found = codes(doc(u));
    assert!(
        found.contains(&(
            ErrorCode::UnknownAllowNotPermitted,
            "/policy/unknown".to_owned()
        )),
        "{found:?}"
    );
    assert!(found.contains(&(
        ErrorCode::UnknownAllow,
        "/policy/unknown/by_location/temp".to_owned()
    )));
    // An allow that a location block outranks is not silent there.
    let mut u = preset_json(CompliancePreset::E8Ml1);
    u["by_type"] = serde_json::json!({"script.python": "allow"});
    let found = codes(doc(u));
    assert!(
        !found
            .iter()
            .any(|(c, _)| *c == ErrorCode::UnknownAllowNotPermitted),
        "{found:?}"
    );
}

// --------------------------------------------------------------- location

fn vars() -> PathVariables {
    PathVariables::new()
        .with(crate::facts::PathVariable::Windir, &["C:\\Windows"])
        .with(
            crate::facts::PathVariable::ProgramFiles,
            &["C:\\Program Files", "C:\\Program Files (x86)"],
        )
        .with(
            crate::facts::PathVariable::UserProfile,
            &["C:\\Users\\alice"],
        )
        .with(
            crate::facts::PathVariable::AppData,
            &["C:\\Users\\alice\\AppData\\Roaming"],
        )
        .with(
            crate::facts::PathVariable::LocalAppData,
            &["C:\\Users\\alice\\AppData\\Local"],
        )
        .with(
            crate::facts::PathVariable::Temp,
            &["C:\\Users\\alice\\AppData\\Local\\Temp"],
        )
        // Every variable the classifier reads, so these are full facts.
        .with(crate::facts::PathVariable::Public, &["C:\\Users\\Public"])
}

/// The classes the facts establish.
fn known(c: location::Classified) -> BTreeSet<LocationClass> {
    c.classes.matching()
}

/// The classes the facts establish for `raw`, with `vars()`. The table
/// tests describe a fixed disk unless they name another volume, so the
/// volume fact defaults to `Fixed` (full facts); a missing volume fact is
/// tested on its own.
fn classes(
    raw: &str,
    writable: Option<bool>,
    volume: Option<VolumeKind>,
) -> BTreeSet<LocationClass> {
    let mut p = PathFact::new(raw, &VolumeMap::new());
    p.user_writable = writable;
    known(classify(
        &p,
        &vars(),
        Some(volume.unwrap_or(VolumeKind::Fixed)),
        &[],
    ))
}

#[test]
fn locations_are_classified_from_paths() {
    use LocationClass as L;
    type Case = (&'static str, Option<bool>, Option<VolumeKind>, Vec<L>);
    let cases: Vec<Case> = vec![
        (
            "C:\\Users\\alice\\Downloads\\a.exe",
            Some(true),
            None,
            vec![L::UserProfile, L::UserWritableOther],
        ),
        (
            "c:\\users\\ALICE\\desktop\\a.exe",
            Some(true),
            None,
            vec![L::UserProfile, L::UserWritableOther],
        ),
        (
            "C:\\Users\\bob\\a.exe",
            Some(true),
            None,
            vec![L::UserProfile, L::UserWritableOther],
        ),
        (
            "C:\\Users\\alice\\AppData\\Local\\Temp\\x\\a.exe",
            Some(true),
            None,
            vec![L::UserProfile, L::Temp, L::UserWritableOther],
        ),
        (
            "C:\\Windows\\Temp\\a.exe",
            Some(true),
            None,
            vec![L::Temp, L::UserWritableOther, L::Windows],
        ),
        (
            "C:\\Users\\alice\\AppData\\Local\\Vendor\\INetCache\\Low\\a.exe",
            Some(true),
            None,
            vec![L::UserProfile, L::Temp, L::UserWritableOther],
        ),
        (
            "C:\\Program Files\\App\\a.exe",
            Some(false),
            None,
            vec![L::ProgramFiles],
        ),
        (
            "C:\\Program Files (x86)\\App\\a.exe",
            Some(false),
            None,
            vec![L::ProgramFiles],
        ),
        (
            "C:\\Windows\\System32\\a.exe",
            Some(false),
            None,
            vec![L::Windows],
        ),
        (
            "C:\\WindowsApps\\a.exe",
            Some(false),
            None,
            vec![L::OtherFixed],
        ),
        ("D:\\Tools\\a.exe", Some(false), None, vec![L::OtherFixed]),
        // Round six: without the ACL fact `user_writable_other` is
        // `Unknown`, not established (see
        // `without_the_acl_fact_a_file_could_be_user_writable`).
        ("D:\\Tools\\a.exe", None, None, vec![L::OtherFixed]),
        (
            "E:\\a.exe",
            Some(false),
            Some(VolumeKind::Removable),
            vec![L::Removable],
        ),
        (
            "F:\\setup.exe",
            Some(false),
            Some(VolumeKind::Optical),
            vec![L::Optical],
        ),
        (
            "\\\\server\\share\\a.exe",
            Some(false),
            None,
            vec![L::Network],
        ),
        (
            "Z:\\a.exe",
            Some(false),
            Some(VolumeKind::Network),
            vec![L::Network],
        ),
        (
            "C:\\Tools\\a.txt:payload",
            Some(false),
            None,
            vec![L::OtherFixed, L::Ads],
        ),
        (
            // Round six: an unusable path decides nothing, so every class
            // it would decide is `Unknown` (it used to be a definite
            // `user_writable_other`).
            "relative\\a.exe",
            Some(false),
            None,
            vec![],
        ),
    ];
    for (raw, writable, volume, want) in cases {
        assert_eq!(classes(raw, writable, volume), level_set(&want), "{raw}");
    }
}

#[test]
fn a_mapped_drive_is_a_network_location() {
    let mut p = PathFact::new("Z:\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    p.alias = Some(palisade_core::path::normalize("\\\\server\\share\\a.exe"));
    assert_eq!(
        known(classify(&p, &vars(), None, &[])),
        level_set(&[LocationClass::Network])
    );
}

#[test]
fn scanner_flagged_directories_are_user_writable() {
    let p = PathFact::new("C:\\Windows\\Tasks\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    let flagged = [palisade_core::path::normalize("C:\\Windows\\Tasks")];
    let fixed = Some(VolumeKind::Fixed);
    assert_eq!(
        known(classify(&p, &vars(), fixed, &flagged)),
        level_set(&[LocationClass::UserWritableOther, LocationClass::Windows])
    );
    // A sibling with a common prefix is not.
    let p = PathFact::new("C:\\Windows\\TasksX\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    assert_eq!(
        known(classify(&p, &vars(), fixed, &flagged)),
        level_set(&[LocationClass::Windows])
    );
}

#[test]
fn agent_temp_directories_add_the_temp_class() {
    let p = PathFact::new("D:\\MailCache\\a.exe", &VolumeMap::new()).with_user_writable(true);
    let temp = [palisade_core::path::normalize("D:\\MailCache")];
    let got = known(location::classify_with(
        &p,
        &vars(),
        &location::Hints {
            volume: None,
            writable_dirs: &[],
            temp_dirs: &temp,
        },
    ));
    assert_eq!(
        got,
        level_set(&[LocationClass::Temp, LocationClass::UserWritableOther])
    );
}

// --------------------------------------------------------------- baseline

fn os_signed(path: &str, writable: bool) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha('c'))
        .with_signers(vec![SignerFact {
            status: SignerStatus::CatalogSigned,
            source: SignatureSource::Catalog,
            publisher: Some(OS_PUBLISHER.into()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }])
        .with_path(
            PathFact::new(path, &VolumeMap::new())
                .with_user_writable(writable)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        )
        .with_location_class([LocationClass::Windows])
}

fn variables_full() -> PathVariables {
    vars().with(
        crate::facts::PathVariable::System32,
        &["C:\\Windows\\System32", "C:\\Windows\\SysWOW64"],
    )
}

fn baseline_doc(
    unknown: serde_json::Value,
    extra: &[(&str, &str, bool, Vec<serde_json::Value>)],
) -> ValidatedPolicy {
    let facts = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: vec!["C:\\Windows\\ScannerFound".into()],
    };
    valid(doc_with(unknown, extra))
        .with_system_baseline(&facts)
        .unwrap()
}

fn decide_os(v: &ValidatedPolicy, t: ObjectType, facts: &ObjectFacts) -> Decision {
    let variables = variables_full();
    let context = interactive_context();
    Evaluator::new(v).unwrap().evaluate(
        &Subject {
            object_type: t,
            facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    )
}

#[test]
fn the_baseline_allows_os_binaries_in_protected_os_locations() {
    let v = baseline_doc(preset_json(CompliancePreset::E8Ml2), &[]);
    for path in [
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\drivers\\disk.sys",
        "C:\\Windows\\SysWOW64\\kernel32.dll",
        "C:\\Windows\\explorer.exe",
        "C:\\Program Files\\OS Component\\a.exe",
    ] {
        for t in [
            ObjectType::Executable,
            ObjectType::Library,
            ObjectType::Driver,
        ] {
            let d = decide_os(&v, t, &os_signed(path, false));
            assert_eq!(d.outcome(), Outcome::Allowed, "{path} {t}");
            assert_eq!(
                d.matched_rule().unwrap().rule_id.to_string(),
                baseline::SYSTEM_BASELINE_RULE_ID
            );
        }
    }
}

#[test]
fn the_baseline_excludes_every_mandatory_exception() {
    let v = baseline_doc(serde_json::json!({}), &[]);
    for path in [
        "C:\\Windows\\System32\\spool\\drivers\\color\\a.exe",
        "C:\\Windows\\System32\\Tasks\\x\\a.exe",
        "C:\\Windows\\SysWOW64\\Tasks\\a.exe",
        "C:\\Windows\\Tasks\\a.exe",
        "C:\\Windows\\Temp\\a.exe",
        "C:\\Windows\\System32\\Vendor\\Crypto\\RSA\\MachineKeys\\a.exe",
        "C:\\Windows\\System32\\Com\\dmp\\a.exe",
        "C:\\Windows\\System32\\FxsTmp\\a.exe",
        "C:\\Windows\\System32\\spool\\PRINTERS\\a.exe",
        "C:\\Windows\\System32\\spool\\SERVERS\\a.exe",
        "C:\\Windows\\Registration\\CRMLog\\a.exe",
        "C:\\Windows\\tracing\\a.exe",
        "C:\\Windows\\ScannerFound\\a.exe",
        "C:\\Windows\\System32\\a.exe:hidden",
    ] {
        let d = decide_os(&v, ObjectType::Executable, &os_signed(path, false));
        assert_eq!(d.outcome(), Outcome::Blocked, "{path}");
        assert!(d.unhandled());
    }
    // Writable files, other publishers and other locations are not allowed.
    let d = decide_os(
        &v,
        ObjectType::Executable,
        &os_signed("C:\\Windows\\System32\\a.exe", true),
    );
    assert_eq!(d.outcome(), Outcome::Blocked);
    let d = decide_os(
        &v,
        ObjectType::Executable,
        &os_signed("D:\\Windows\\a.exe", false),
    );
    assert_eq!(d.outcome(), Outcome::Blocked);
    let mut other = os_signed("C:\\Windows\\System32\\a.exe", false);
    other.signers.as_mut().unwrap()[0].publisher = Some("Someone Else".into());
    assert_eq!(
        decide_os(&v, ObjectType::Executable, &other).outcome(),
        Outcome::Blocked
    );
    let mut revoked = os_signed("C:\\Windows\\System32\\a.exe", false);
    revoked.signers.as_mut().unwrap()[0].status = SignerStatus::Revoked;
    assert_eq!(
        decide_os(&v, ObjectType::Executable, &revoked).outcome(),
        Outcome::Blocked
    );
}

#[test]
fn a_mandatory_deny_beats_the_baseline() {
    let rule = serde_json::json!({
        "id": rule_id(9), "name": "M",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('c')]}},
        "action": {"type": "deny"},
    });
    let v = baseline_doc(
        serde_json::json!({}),
        &[(MANDATORY, "blocklist", true, vec![rule])],
    );
    let d = decide_os(
        &v,
        ObjectType::Executable,
        &os_signed("C:\\Windows\\System32\\a.exe", false),
    );
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
}

#[test]
fn the_baseline_validates_under_every_model() {
    for (model, options) in [
        ("deny_wins", serde_json::json!({})),
        ("allow_wins", serde_json::json!({})),
        ("specificity", serde_json::json!({})),
        ("first_match", serde_json::json!({})),
        ("priority", serde_json::json!({})),
        (
            "priority",
            serde_json::json!({"priority_direction": "higher_wins"}),
        ),
    ] {
        let mut d = doc(serde_json::json!({}));
        d.policy.precedence_model = serde_json::from_value(model.into()).unwrap();
        d.policy.precedence_options = serde_json::from_value(options).unwrap();
        let v = d
            .validate()
            .unwrap_or_else(|e| panic!("{model}: {e:#?}"))
            .with_system_baseline(&SystemBaseline {
                publishers: vec![OS_PUBLISHER.into()],
                writable_dirs: vec![],
            })
            .unwrap();
        assert_baseline_valid(&v, model);
        let decision = decide_os(
            &v,
            ObjectType::Executable,
            &os_signed("C:\\Windows\\System32\\a.exe", false),
        );
        assert_eq!(decision.outcome(), Outcome::Allowed, "{model}");
    }
}

#[test]
fn adding_the_baseline_twice_replaces_it() {
    let facts = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: vec![],
    };
    let v = valid(doc(serde_json::json!({})))
        .with_system_baseline(&facts)
        .unwrap()
        .with_system_baseline(&facts)
        .unwrap();
    let d = v.document();
    assert_eq!(d.rule_sets.len(), 1);
    assert_eq!(d.policy.rule_sets.len(), 1);
    assert!(d.rule_sets[0].read_only);
}

#[test]
fn baseline_inputs_are_bounded() {
    let none = SystemBaseline::default();
    assert_eq!(
        system_baseline(
            &none,
            crate::model::PrecedenceModel::DenyWins,
            crate::model::PriorityDirection::LowerWins
        ),
        Err(baseline::BaselineError::Publishers(0))
    );
    let many = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: (0..=baseline::MAX_WRITABLE_DIRS)
            .map(|i| format!("C:\\Windows\\d{i}"))
            .collect(),
    };
    assert!(matches!(
        system_baseline(
            &many,
            crate::model::PrecedenceModel::DenyWins,
            crate::model::PriorityDirection::LowerWins
        ),
        Err(baseline::BaselineError::TooManyWritableDirs(_))
    ));
    let most = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: (0..baseline::MAX_WRITABLE_DIRS)
            .map(|i| format!("C:\\Windows\\d{i}"))
            .collect(),
    };
    let v = valid(doc(serde_json::json!({})))
        .with_system_baseline(&most)
        .unwrap();
    assert_baseline_valid(&v, "deny_wins");
}

/// The baseline is added after validation and never validated with the
/// policy, so check here that the set it adds is one validation would
/// accept (under a fresh ID, which an authored document may use).
fn assert_baseline_valid(v: &ValidatedPolicy, what: &str) {
    let mut d = v.document().clone();
    for set in &mut d.rule_sets {
        if baseline::is_system_baseline(set) {
            let fresh: crate::model::RuleSetId =
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3db001".parse().unwrap();
            d.policy
                .rule_sets
                .iter_mut()
                .filter(|r| **r == set.id)
                .for_each(|r| *r = fresh);
            set.id = fresh;
        }
    }
    d.validate().unwrap_or_else(|e| panic!("{what}: {e:#?}"));
}

// ---------------------------------------------------------------- selfpin

/// The facts the agent's parser computes for its own executable.
fn agent_file_facts() -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, format!("0x{}", sha('E')))
        .with(Field::MetaProductName, "Palisade")
        .with(Field::MetaOriginalFilename, "agent.exe")
        .with_signers(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some("Palisade Agent".into()),
            issuer: Some("Example Code Signing CA".into()),
            leaf_thumbprint_sha256: Some(sha('d')),
            details: Default::default(),
        }])
        .with_path(
            PathFact::new("C:\\Program Files\\Palisade\\agent.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        )
}

/// The agent's service context.
fn agent_context() -> EvaluationContext {
    let mut c = EvaluationContext::new();
    c.user.is_system = Some(true);
    c.user.sid = Some("S-1-5-18".into());
    c.session.session_type = Some(SessionType::Service);
    c
}

fn agent_image() -> SelfImage {
    SelfImage::new(
        ObjectType::Executable,
        "Palisade Agent",
        agent_file_facts(),
        agent_context(),
    )
    .unwrap()
}

#[test]
fn a_self_image_needs_a_hash_and_a_trusted_signature() {
    assert_eq!(agent_image().sha256(), sha('e'));
    let facts = agent_file_facts();
    assert!(SelfImage::new(ObjectType::Executable, "  ", facts.clone(), agent_context()).is_none());
    assert!(
        SelfImage::new(
            ObjectType::Executable,
            "Someone",
            facts.clone(),
            agent_context()
        )
        .is_none()
    );
    let mut short = facts.clone();
    short.set(Field::HashSha256, "abcd");
    assert!(
        SelfImage::new(
            ObjectType::Executable,
            "Palisade Agent",
            short,
            agent_context()
        )
        .is_none()
    );
    let mut revoked = facts;
    revoked.signers.as_mut().unwrap()[0].status = SignerStatus::Revoked;
    assert!(
        SelfImage::new(
            ObjectType::Executable,
            "Palisade Agent",
            revoked,
            agent_context()
        )
        .is_none()
    );
}

fn agent_facts(publisher: &str, hash: char) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha(hash))
        .with_signers(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some(publisher.into()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }])
        .with_location_class([LocationClass::ProgramFiles])
}

#[test]
fn palisade_images_are_allowed_by_hash_and_signer() {
    let rule = serde_json::json!({
        "id": rule_id(1), "name": "Everything in Program Files",
        "match": {"criterion": {"field": "path.directory", "operator": "starts_with", "values": ["C:\\Program Files"]}},
        "action": {"type": "deny"},
    });
    let v = valid(doc_with(
        serde_json::json!({}),
        &[(SET, "blocklist", false, vec![rule])],
    ));
    let e = Evaluator::new(&v)
        .unwrap()
        .with_self_images(vec![agent_image()]);
    let variables = PathVariables::new();
    let context = interactive_context();
    let mut facts = agent_facts("palisade agent", 'E');
    facts.path = Some(
        PathFact::new("C:\\Program Files\\Palisade\\agent.exe", &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed),
    );
    let d = e.evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    );
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(d.reason_code(), ReasonCode::SelfAllow);
    assert_eq!(d.overridden().len(), 1);
    // Another signer, other content, or another type is not pinned.
    for (facts, t) in [
        (agent_facts("Someone Else", 'e'), ObjectType::Executable),
        (agent_facts("Palisade Agent", 'f'), ObjectType::Executable),
        (agent_facts("Palisade Agent", 'e'), ObjectType::Library),
    ] {
        let d = e.evaluate(
            &Subject {
                object_type: t,
                facts: &facts,
                variables: &variables,
                context: &context,
            },
            TRACE,
        );
        assert_ne!(d.reason_code(), ReasonCode::SelfAllow);
    }
}

#[test]
fn a_mandatory_deny_still_applies_before_the_pin() {
    let (id, kind, m, _) = mandatory_set();
    let rule = serde_json::json!({
        "id": rule_id(9), "name": "M",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('e')]}},
        "action": {"type": "deny"},
    });
    let v = valid(doc_with(
        serde_json::json!({}),
        &[(id, kind, m, vec![rule])],
    ));
    let e = Evaluator::new(&v)
        .unwrap()
        .with_self_images(vec![agent_image()]);
    let facts = agent_facts("Palisade Agent", 'e');
    let variables = PathVariables::new();
    let context = interactive_context();
    let d = e.evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    );
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
}

#[test]
fn validation_rejects_a_deny_that_matches_a_palisade_image() {
    let hash = serde_json::json!({
        "id": rule_id(1), "name": "H",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('E')]}},
        "action": {"type": "deny"},
    });
    let publisher = serde_json::json!({
        "id": rule_id(2), "name": "P",
        "match": {"criterion": {"field": "signer.publisher", "operator": "equals", "values": ["Palisade Agent"]}},
        "action": {"type": "deny"},
    });
    let path = serde_json::json!({
        "id": rule_id(3), "name": "Path",
        "match": {"criterion": {"field": "path.directory", "operator": "starts_with", "values": ["C:\\Program Files\\Palisade"]}},
        "action": {"type": "deny"},
    });
    let unrelated = serde_json::json!({
        "id": rule_id(4), "name": "U",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('b')]}},
        "action": {"type": "deny"},
    });
    let libraries_only = serde_json::json!({
        "id": rule_id(5), "name": "L", "object_types": ["library"],
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('e')]}},
        "action": {"type": "deny"},
    });
    let unknown_fails_closed = serde_json::json!({
        "id": rule_id(6), "name": "Unknown",
        "match": {"criterion": {"field": "meta.product_name", "operator": "equals", "values": ["X"]}},
        "action": {"type": "deny", "unknown_as": "match"},
    });
    let crit = |field: &str, op: &str, v: &str| serde_json::json!({"criterion": {"field": field, "operator": op, "values": [v]}});
    let deny = |n: u32, tree: serde_json::Value| serde_json::json!({"id": rule_id(n), "name": "R", "match": tree, "action": {"type": "deny"}});
    let variable_path = deny(
        7,
        crit("path.directory", "starts_with", "%PROGRAMFILES%\\Palisade"),
    );
    let with_context = deny(
        8,
        serde_json::json!({"all": [crit("hash.sha256", "equals", &sha('e')), {"criterion": {"field": "user.is_system", "operator": "is_true"}}]}),
    );
    let unknown_device = deny(
        9,
        serde_json::json!({"all": [crit("hash.sha256", "equals", &sha('e')), {"criterion": {"field": "device.is_server", "operator": "is_true"}}]}),
    );
    let thumbprint = deny(10, crit("signer.leaf_thumbprint", "equals", &sha('d')));
    let product = deny(11, crit("meta.product_name", "equals", "Palisade"));
    let excluded = deny(
        12,
        serde_json::json!({"all": [crit("signer.publisher", "equals", "Palisade Agent"), {"not": crit("hash.sha256", "equals", &sha('e'))}]}),
    );
    let d = doc_with(
        serde_json::json!({}),
        &[(
            SET,
            "blocklist",
            false,
            vec![
                hash,
                publisher,
                path,
                unrelated,
                libraries_only,
                unknown_fails_closed,
                variable_path,
                with_context,
                unknown_device,
                thumbprint,
                product,
                excluded,
            ],
        )],
    );
    let variables = PathVariables::new().with(
        crate::facts::PathVariable::ProgramFiles,
        &["C:\\Program Files"],
    );
    let errors = d
        .clone()
        .validate_with_self_images(&[agent_image()], &variables)
        .unwrap_err();
    let paths: Vec<&str> = errors
        .iter()
        .filter(|e| e.code == ErrorCode::DenyMatchesSelf)
        .map(|e| e.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "/rule_sets/0/rules/0/match",
            "/rule_sets/0/rules/1/match",
            "/rule_sets/0/rules/2/match",
            "/rule_sets/0/rules/6/match",
            "/rule_sets/0/rules/7/match",
            "/rule_sets/0/rules/8/match",
            "/rule_sets/0/rules/9/match",
            "/rule_sets/0/rules/10/match",
        ]
    );
    // Without images, the same policy is valid.
    d.validate_with_self_images(&[], &variables).unwrap();
}

#[test]
fn a_prompt_decision_has_a_stable_json_form() {
    let v = prompt_policy(serde_json::json!({"require_justification": true}));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(
            &[LocationClass::Temp, LocationClass::UserProfile],
            &[OriginClass::Internet],
        ),
    );
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/decision/pending-user-prompt.json");
    let mut text = serde_json::to_string_pretty(&d).unwrap();
    text.push('\n');
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == text,
        "{} differs:\n{text}\nRegenerate with PALISADE_BLESS=1",
        path.display()
    );
}

fn arb_state() -> impl Strategy<Value = DeviceState> {
    (
        prop::sample::select(vec![
            Mode::Enforce,
            Mode::Audit,
            Mode::Learning,
            Mode::Monitor,
        ]),
        any::<bool>(),
        prop::option::of(prop::sample::select(vec![
            crate::mode::SessionKind::Audit,
            crate::mode::SessionKind::FullBypass,
        ])),
        any::<bool>(),
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Over random unknown policies, objects, contexts and device states:
    /// the enforce-mode outcome is kept, a prompt is only ever pending in
    /// an enforcing mode, every stage-6 object (and only those) is a
    /// learning candidate in `learning`, and a `restrict` never runs
    /// without the containment component.
    #[test]
    fn stage_six_in_every_mode(
        p in arb_policy(),
        state in arb_state(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 0..3),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3),
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        containment in prop::option::of(any::<bool>()),
        early in any::<bool>(),
    ) {
        let mut d = doc(serde_json::json!({}));
        d.policy.unknown = UnknownPolicy {
            restrict_profile: Some(PROFILE.parse().map(crate::model::ContainmentProfileRef).unwrap()),
            ..p
        };
        let Ok(v) = d.validate() else { return Ok(()) };
        let mut context = EvaluationContext::new();
        context.session.session_type = session;
        context.device.containment_available = containment;
        context.device.boot_phase = Some(if early { BootPhase::Early } else { BootPhase::Running });
        let facts = ObjectFacts::new()
            .with(Field::HashSha256, sha('a'))
            .with_location_class(locations)
            .with_origin(origins);
        let variables = PathVariables::new();
        let e = Evaluator::new(&v).unwrap();
        let subject = Subject { object_type: t, facts: &facts, variables: &variables, context: &context };
        let enforce = e.evaluate(&subject, TRACE);
        prop_assert!(enforce.unhandled());
        let h = enforce.unknown().unwrap();
        prop_assert!(h.applied >= h.resolved || h.fallback.is_some());
        if enforce.outcome() == Outcome::PendingUser {
            prop_assert!(prompt_valid_for(t) && interactive(&context));
        }
        if enforce.reason_code() == ReasonCode::UnknownRestricted {
            prop_assert_eq!(containment, Some(true));
            prop_assert!(restrict_valid_for(t));
        }
        let Some(d) = e.evaluate_in(&subject, &state, TRACE) else { return Ok(()) };
        prop_assert_eq!(d.would_have_been(), enforce.outcome());
        if d.outcome() == Outcome::PendingUser || d.outcome() == Outcome::Blocked {
            prop_assert_eq!(d.mode(), Mode::Enforce);
        }
        prop_assert_eq!(d.learning_candidate(), d.mode() == Mode::Learning);
        // Lockdown enforces stage 6 as enforce mode decides it.
        if state.lockdown {
            prop_assert_eq!(d.outcome(), enforce.outcome());
        }
    }
}

// ------------------------------------------------- review regressions

#[test]
fn the_baseline_never_overrides_a_tenant_rule_under_any_model() {
    for (model, options) in [
        ("deny_wins", serde_json::json!({})),
        ("allow_wins", serde_json::json!({})),
        (
            "specificity",
            serde_json::json!({"same_tier_tiebreak": "allow"}),
        ),
        ("first_match", serde_json::json!({})),
        ("first_match", serde_json::json!({"curated_first": false})),
        ("priority", serde_json::json!({})),
    ] {
        for action in ["deny", "allow_contained"] {
            let mut rule = serde_json::json!({
                "id": rule_id(1), "name": "Tenant",
                "match": {"criterion": {"field": "signer.publisher", "operator": "equals", "values": [OS_PUBLISHER]}},
                "action": {"type": action},
                "order": 500_000,
                "priority": 10,
            });
            if action == "allow_contained" {
                rule["action"]["profile_id"] = PROFILE.into();
                rule["object_types"] = serde_json::json!(["executable"]);
            }
            let mut d = doc_with(serde_json::json!({}), &[(SET, "mixed", false, vec![rule])]);
            d.policy.precedence_model = serde_json::from_value(model.into()).unwrap();
            d.policy.precedence_options = serde_json::from_value(options.clone()).unwrap();
            let v = d
                .validate()
                .unwrap_or_else(|e| panic!("{model}: {e:#?}"))
                .with_system_baseline(&SystemBaseline {
                    publishers: vec![OS_PUBLISHER.into()],
                    writable_dirs: vec![],
                })
                .unwrap();
            let decision = decide_os(
                &v,
                ObjectType::Executable,
                &os_signed("C:\\Windows\\System32\\a.exe", false),
            );
            assert_eq!(
                decision.matched_rule().unwrap().rule_id.to_string(),
                rule_id(1),
                "{model} {options} {action}"
            );
            // The baseline would have decided without the tenant's rule, so
            // it is listed as overridden.
            assert_eq!(
                decision.overridden()[0].rule_id.to_string(),
                baseline::SYSTEM_BASELINE_RULE_ID,
                "{model}"
            );
        }
    }
}

#[test]
fn baseline_inputs_must_be_usable_values() {
    let model = crate::model::PrecedenceModel::DenyWins;
    let dir = crate::model::PriorityDirection::LowerWins;
    for bad in [
        "relative\\dir",
        "C:\\Windows\\Sub:stream",
        "%WINDIR%\\Sub",
        "C:\\Windows\\*",
        " C:\\Windows\\Sub",
        "C:\\Windows\\Sub\u{7}",
    ] {
        let facts = SystemBaseline {
            publishers: vec![OS_PUBLISHER.into()],
            writable_dirs: vec![bad.into()],
        };
        assert!(
            matches!(
                system_baseline(&facts, model, dir),
                Err(baseline::BaselineError::InvalidValue(_))
            ),
            "{bad:?}"
        );
    }
    let facts = SystemBaseline {
        publishers: vec![" padded ".into()],
        writable_dirs: vec![],
    };
    assert!(system_baseline(&facts, model, dir).is_err());
    let facts = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: vec!["\\\\server\\share\\dir".into()],
    };
    let v = valid(doc(serde_json::json!({})))
        .with_system_baseline(&facts)
        .unwrap();
    assert_baseline_valid(&v, "unc");
}

#[test]
fn external_volumes_are_never_protected_locations() {
    use LocationClass as L;
    for (raw, volume) in [
        ("F:\\Windows\\System32\\a.exe", Some(VolumeKind::Optical)),
        ("E:\\Program Files\\App\\a.exe", Some(VolumeKind::Removable)),
        ("Z:\\Windows\\a.exe", Some(VolumeKind::Network)),
    ] {
        let got = classes(raw, Some(false), volume);
        assert!(
            !got.contains(&L::Windows) && !got.contains(&L::ProgramFiles),
            "{raw}: {got:?}"
        );
    }
    // A mapped drive whose alias is UNC.
    let mut p = PathFact::new("Z:\\Program Files\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    p.alias = Some(palisade_core::path::normalize(
        "\\\\server\\share\\Program Files\\a.exe",
    ));
    let no_vars = PathVariables::new();
    let got = known(classify(&p, &no_vars, None, &[]));
    assert_eq!(got, level_set(&[L::Network]));
    // With the variables set, only the system's own folders count.
    assert_eq!(
        classes("D:\\Windows\\a.exe", Some(false), None),
        level_set(&[L::OtherFixed])
    );
    assert_eq!(
        classes("D:\\Program Files\\a.exe", Some(false), None),
        level_set(&[L::OtherFixed])
    );
    // Without them, the drive-root folder is not a fact: `windows` is
    // `Unknown`, even on a fixed disk.
    let p = PathFact::new("D:\\Windows\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    let c = classify(&p, &no_vars, Some(VolumeKind::Fixed), &[]).classes;
    assert_eq!(c.get(L::Windows), Tri::Unknown);
    assert_eq!(c.get(L::OtherFixed), Tri::Unknown);
}

#[test]
fn a_unc_path_with_a_drive_alias_is_classified_in_both_forms() {
    use LocationClass as L;
    let mut p = PathFact::new(
        "\\\\localhost\\c$\\Users\\alice\\AppData\\Local\\Temp\\a.exe",
        &VolumeMap::new(),
    )
    .with_user_writable(true);
    p.alias = Some(palisade_core::path::normalize(
        "C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe",
    ));
    let got = known(classify(&p, &vars(), None, &[]));
    assert!(
        got.contains(&L::Temp) && got.contains(&L::UserProfile) && got.contains(&L::Network),
        "{got:?}"
    );
    assert!(!got.contains(&L::OtherFixed));
}

#[test]
fn a_pinned_driver_in_early_boot_keeps_the_device_mode() {
    let image = SelfImage::new(
        ObjectType::Driver,
        "Palisade Agent",
        agent_file_facts(),
        agent_context(),
    )
    .unwrap();
    let v = valid(doc(serde_json::json!({})));
    let e = Evaluator::new(&v).unwrap().with_self_images(vec![image]);
    let mut c = interactive_context();
    c.device.boot_phase = Some(BootPhase::Early);
    let facts = agent_file_facts();
    let variables = PathVariables::new();
    let d = e
        .evaluate_in(
            &Subject {
                object_type: ObjectType::Driver,
                facts: &facts,
                variables: &variables,
                context: &c,
            },
            &DeviceState::of(&v.document().policy),
            TRACE,
        )
        .unwrap();
    assert_eq!(d.reason_code(), ReasonCode::SelfAllow);
    assert_eq!(d.mode(), Mode::Enforce);
}

#[test]
fn stage_six_never_shows_a_link_without_a_notification() {
    let v = valid(doc(serde_json::json!({
        "default": "detect",
        "effects": {"help_url": "https://help.example.org/unknown"},
    })));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::OtherFixed], &[]),
    );
    assert_eq!(d.effects().notify, Notify::None);
    assert_eq!(d.effects().help_url, None);
    // A block shows the default notification, with its link.
    let v = valid(doc(
        serde_json::json!({"effects": {"help_url": "https://help.example.org/unknown"}}),
    ));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::OtherFixed], &[]),
    );
    assert_eq!(d.effects().notify, Notify::Default);
    assert!(d.effects().help_url.is_some());
}

#[test]
fn ml3_needs_an_enabled_mandatory_rule() {
    let (id, kind, m, mut rules) = mandatory_set();
    let ml3 = || {
        let mut u = preset_json(CompliancePreset::E8Ml3);
        u["driver_boot_policy"] = "enforce".into();
        u
    };
    rules[0]["enabled"] = false.into();
    let found = codes(doc_with(ml3(), &[(id, kind, m, rules)]));
    assert_eq!(
        found,
        vec![(
            ErrorCode::MandatoryBlocklistRequired,
            "/policy/rule_sets".to_owned()
        )]
    );
    let found = codes(doc_with(ml3(), &[(id, kind, m, vec![])]));
    assert_eq!(
        found,
        vec![(
            ErrorCode::MandatoryBlocklistRequired,
            "/policy/rule_sets".to_owned()
        )]
    );
}

/// Minor: validation has no clock, so a mandatory rule with an activity
/// window does not satisfy `e8_ml3`: it may have expired or not started.
#[test]
fn ml3_needs_a_mandatory_rule_in_force_at_every_time() {
    let (id, kind, m, rules) = mandatory_set();
    let ml3 = || {
        let mut u = preset_json(CompliancePreset::E8Ml3);
        u["driver_boot_policy"] = "enforce".into();
        u
    };
    for window in [
        serde_json::json!({"expires_at": "2020-01-01T00:00:00Z"}),
        serde_json::json!({"activates_at": "9000-01-01T00:00:00Z"}),
    ] {
        let mut timed = rules.clone();
        for (k, v) in window.as_object().unwrap() {
            timed[0][k] = v.clone();
        }
        assert_eq!(
            codes(doc_with(ml3(), &[(id, kind, m, timed)])),
            vec![(
                ErrorCode::MandatoryBlocklistRequired,
                "/policy/rule_sets".to_owned()
            )],
            "{window}"
        );
    }
    assert_eq!(codes(doc_with(ml3(), &[(id, kind, m, rules)])), vec![]);
}

/// F1: a policy document can never contain the baseline's ID, however
/// exactly it copies the generated set. A deliberate forgery (the exact
/// generated shape with an arbitrary publisher) and a copy of the real
/// baseline are both rejected; only the engine adds it, after validation.
#[test]
fn an_authored_document_cannot_contain_the_baseline() {
    let real = valid(doc(serde_json::json!({})))
        .with_system_baseline(&SystemBaseline {
            publishers: vec![OS_PUBLISHER.into()],
            writable_dirs: vec!["C:\\Windows\\Flagged".into()],
        })
        .unwrap();
    // A copy of what the engine added, submitted as an authored document.
    let copied = real.document().clone();
    assert_eq!(
        codes(copied),
        vec![(ErrorCode::ReservedRuleSetId, "/rule_sets/0/id".to_owned())]
    );
    // The reviewer's forgery: the generated shape, built for another
    // publisher, so `facts_of`-style checks would accept it.
    let forged = system_baseline(
        &SystemBaseline {
            publishers: vec!["Any Vendor Ltd".into()],
            writable_dirs: vec![],
        },
        crate::model::PrecedenceModel::DenyWins,
        crate::model::PriorityDirection::LowerWins,
    )
    .unwrap();
    let mut d = doc(serde_json::json!({}));
    d.policy.rule_sets.push(forged.id);
    d.rule_sets.push(forged);
    assert_eq!(
        codes(d),
        vec![(ErrorCode::ReservedRuleSetId, "/rule_sets/0/id".to_owned())]
    );
}

#[test]
fn justifications_are_bounded_text() {
    let v = prompt_policy(serde_json::json!({}));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
    );
    for bad in [
        "a\u{7}b".to_owned(),
        "x\u{202e}y".to_owned(),
        "x".repeat(4097),
    ] {
        let a = PromptAnswer::Chose {
            option: PromptOption::AllowOnce,
            justification: Some(bad),
            reauthenticated: false,
        };
        assert_eq!(
            answer(&d, &a, None, 0),
            Err(AnswerError::InvalidJustification)
        );
    }
    let ok = PromptAnswer::Chose {
        option: PromptOption::AllowOnce,
        justification: Some("line one\nline two".into()),
        reauthenticated: false,
    };
    assert!(answer(&d, &ok, None, 0).is_ok());
}

#[test]
fn a_stored_approval_with_a_bad_hash_never_applies() {
    let a = LocalApproval {
        sha256: "0xABCD".into(),
        scope: ApprovalScope::Device,
        user_sid: None,
        approved_at: 0,
        expires_at: None,
        justification: None,
        upload_for_review: true,
    };
    assert!(!a.applies("abcd", None, 1));
    let a = LocalApproval {
        sha256: format!("0x{}", sha('A')),
        ..a
    };
    assert!(a.applies(&sha('a'), None, 1));
}

#[test]
fn preset_checks_cover_objects_in_several_locations() {
    // `default: block` with a weaker entry on a class that occurs together
    // with `user_profile` or `temp` lets those run.
    for (key, level) in [
        ("user_writable_other", "allow"),
        ("windows", "allow"),
        ("ads", "allow"),
    ] {
        let mut u = preset_json(CompliancePreset::E8Ml2);
        u["by_location"] = serde_json::json!({ key: level });
        let found = codes(doc(u));
        assert!(
            found.contains(&(
                ErrorCode::UnknownAllowNotPermitted,
                "/policy/unknown".to_owned()
            )),
            "{key}: {found:?}"
        );
    }
    // ML1 with the user-location blocks replaced by a block default and
    // detects on the system locations: `C:\Windows\Temp` is weakened.
    let u = serde_json::json!({
        "preset": "e8_ml1",
        "default": "block",
        "by_location": {"windows": "detect", "program_files": "detect", "other_fixed": "detect"},
    });
    let found = codes(doc(u));
    assert!(
        found.contains(&(ErrorCode::ComplianceWeakened, "/policy/unknown".to_owned())),
        "{found:?}"
    );
    // The preset itself still validates cleanly.
    assert_eq!(codes(doc(preset_json(CompliancePreset::E8Ml1))), vec![]);
}

/// The pair check is exact: for random policies, the weakest level over
/// every set of up to four classes is reached by a set of at most two.
#[test]
fn pairs_reach_the_weakest_level_of_any_class_set() {
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::default();
    runner
        .run(
            &(
                arb_policy(),
                prop::sample::select(ObjectType::ALL.to_vec()),
                prop::collection::btree_set(
                    prop::sample::select(LocationClass::ALL.to_vec()),
                    1..5,
                ),
                prop::sample::select(OriginClass::ALL.to_vec()),
            ),
            |(p, t, classes, origin)| {
                let any = resolve_level(&p, t, &classes, &BTreeSet::from([origin])).0;
                let first = *classes.iter().next().unwrap();
                let best_pair = LocationClass::ALL
                    .iter()
                    .map(|b| {
                        resolve_level(
                            &p,
                            t,
                            &BTreeSet::from([first, *b]),
                            &BTreeSet::from([origin]),
                        )
                        .0
                    })
                    .min()
                    .unwrap();
                prop_assert!(best_pair <= any);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn self_image_checks_run_after_the_document_limits() {
    // Over the regular-expression limit: rejected by validation, before any
    // self-image check compiles a tree.
    let rules: Vec<serde_json::Value> = (0..2001u32)
        .map(|n| serde_json::json!({
            "id": rule_id(n + 100), "name": "R",
            "match": {"criterion": {"field": "meta.product_name", "operator": "regex", "values": [format!("x{n}")]}},
            "action": {"type": "deny"},
        }))
        .collect();
    let d = doc_with(serde_json::json!({}), &[(SET, "blocklist", false, rules)]);
    let errors = d
        .validate_with_self_images(&[agent_image()], &PathVariables::new())
        .unwrap_err();
    assert!(errors.iter().any(|e| e.code == ErrorCode::TooManyRegexes));
    assert!(!errors.iter().any(|e| e.code == ErrorCode::DenyMatchesSelf));
}

#[test]
fn self_image_hashes_are_canonicalised() {
    let facts = agent_file_facts().with(Field::HashSha1, format!("0X{}", "AB".repeat(20)));
    let image = SelfImage::new(
        ObjectType::Executable,
        "Palisade Agent",
        facts,
        agent_context(),
    )
    .unwrap();
    let rule = serde_json::json!({
        "id": rule_id(1), "name": "Unrelated SHA-1",
        "match": {"criterion": {"field": "hash.sha1", "operator": "equals", "values": ["cd".repeat(20)]}},
        "action": {"type": "deny"},
    });
    let d = doc_with(
        serde_json::json!({}),
        &[(SET, "blocklist", false, vec![rule])],
    );
    d.validate_with_self_images(&[image], &PathVariables::new())
        .unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Merging two layers' unknown policies is at least as strict as each
    /// of them for every object (#37's inheritance).
    #[test]
    fn the_stricter_merge_is_at_least_as_strict_as_both(
        a in arb_policy(),
        b in arb_policy(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 0..3),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3),
    ) {
        let m = a.stricter(&b);
        let level = |p: &UnknownPolicy| resolve_level(p, t, &locations, &origins).0;
        prop_assert!(level(&m) >= level(&a));
        prop_assert!(level(&m) >= level(&b));
        prop_assert!(m.prompt.fallback >= a.prompt.fallback.max(b.prompt.fallback));
    }

    /// Over policies with random fallbacks, restrict levels and effects,
    /// the merged policy is valid, and in every context (type, classes,
    /// origins, session, containment, a blocklist match) it applies a level
    /// at least as strict as each side's, and never one stricter than the
    /// strictest of them except where one policy cannot reproduce both
    /// ([`UnknownPolicy::stricter`]). Where both sides make the same kind
    /// of decision, the merged effects log and rate it at least as
    /// strongly.
    #[test]
    fn merged_decisions_are_at_least_as_strict_as_both(
        a in arb_full_policy(),
        b in arb_full_policy(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 1..3),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 1..3),
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        containment in prop::option::of(any::<bool>()),
        blocklisted in any::<bool>(),
    ) {
        let m = a.stricter(&b);
        let validated = |u: &UnknownPolicy| {
            let mut d = doc(serde_json::json!({}));
            d.policy.unknown = u.clone();
            d.validate()
        };
        let (Ok(_), Ok(_)) = (validated(&a), validated(&b)) else { return Ok(()) };
        let vm = validated(&m);
        prop_assert!(vm.is_ok(), "{:?}", vm.err());
        let ctx = Ctx { t, locations: &locations, origins: &origins, session, containment, blocklisted };
        let (la, lb, lm) = (applied(&a, &ctx), applied(&b, &ctx), applied(&m, &ctx));
        prop_assert!(lm.never_weaker(la), "{lm:?} weaker than {la:?}");
        prop_assert!(lm.never_weaker(lb), "{lm:?} weaker than {lb:?}");
        let vm = vm.unwrap();
        let (va, vb) = (validated(&a).unwrap(), validated(&b).unwrap());
        let mut context = EvaluationContext::new();
        context.session.session_type = session;
        context.device.containment_available = containment;
        let facts = ObjectFacts::new()
            .with(Field::HashSha256, sha('a'))
            .with_location_class(locations.clone())
            .with_origin(origins.clone());
        let dm = decide_with(&vm, t, &facts, &context);
        for v in [&va, &vb] {
            let d = decide_with(v, t, &facts, &context);
            if d.reason_code() == dm.reason_code() {
                if d.effects().log == LogLevel::Always {
                    prop_assert_eq!(dm.effects().log, LogLevel::Always);
                }
                prop_assert!(dm.effects().severity >= d.effects().severity);
                prop_assert!(dm.effects().suppress_duplicates_secs <= d.effects().suppress_duplicates_secs);
            }
        }
    }
}

#[test]
fn a_detect_floor_is_kept_when_the_other_layer_prompts() {
    // The reviewers' case: outer detects in `temp` with a permissive
    // fallback, inner prompts everywhere. A service on the device must
    // still get at least `detect`, never a silent allow.
    let outer: UnknownPolicy = serde_json::from_value(serde_json::json!({
        "default": "detect", "by_location": {"other_fixed": "prompt"}, "prompt": {"fallback": "allow"},
    })).unwrap();
    let inner: UnknownPolicy = serde_json::from_value(serde_json::json!({
        "default": "prompt", "prompt": {"fallback": "allow"},
    }))
    .unwrap();
    let m = inner.stricter(&outer);
    assert_eq!(m.prompt.fallback, Level::Detect);
    let mut d = doc(serde_json::json!({}));
    d.policy.unknown = m;
    let v = d.validate().unwrap();
    let mut service = EvaluationContext::new();
    service.session.session_type = Some(SessionType::Service);
    let got = decide_with(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::Temp], &[]),
        &service,
    );
    assert_eq!(got.reason_code(), ReasonCode::UnknownDetected);
}

#[test]
fn merged_notification_settings_stay_valid_and_unset_effects_keep_their_defaults() {
    let eff = |v: serde_json::Value| -> UnknownPolicy {
        serde_json::from_value(serde_json::json!({"effects": v})).unwrap()
    };
    let valid = |u: UnknownPolicy| {
        let mut d = doc(serde_json::json!({}));
        d.policy.unknown = u;
        d.validate().map(|_| ()).map_err(|e| format!("{e:?}"))
    };
    for (inner, outer) in [
        (
            serde_json::json!({"notify": "default"}),
            serde_json::json!({"notify": "custom", "notification_text": "Blocked {file}"}),
        ),
        (
            serde_json::json!({"notify": "none"}),
            serde_json::json!({"notify": "default", "help_url": "https://help.example.org/u"}),
        ),
        (
            serde_json::json!({"help_url": "https://help.example.org/u"}),
            serde_json::json!({"notify": "none"}),
        ),
    ] {
        let m = eff(inner.clone()).stricter(&eff(outer.clone()));
        assert_eq!(valid(m), Ok(()), "{inner} over {outer}");
    }
    // Even a side whose text does not belong to its notification (built in
    // code, not validated) merges into a valid policy.
    let odd = UnknownPolicy {
        effects: crate::model::Effects {
            notify: Some(Notify::None),
            notification_text: Some("Blocked {file}".into()),
            help_url: Some("https://help.example.org/u".into()),
            ..crate::model::Effects::default()
        },
        ..UnknownPolicy::default()
    };
    let m = odd.stricter(&UnknownPolicy::default());
    assert_eq!(
        (
            m.effects.notification_text.as_deref(),
            m.effects.help_url.as_deref()
        ),
        (None, None)
    );
    assert_eq!(valid(m), Ok(()));
    // A weaker explicit setting cannot undercut an outer layer's defaults.
    let weak = eff(
        serde_json::json!({"log": "sampled", "upload": "local_only", "severity": "info", "suppress_duplicates_secs": 604800}),
    );
    let m = weak.stricter(&UnknownPolicy::default());
    assert_eq!(m.effects.log, Some(LogLevel::Always));
    assert_eq!(m.effects.upload, Some(Upload::Immediate));
    assert_eq!(m.effects.severity, Some(EventSeverity::Medium));
    assert_eq!(m.effects.suppress_duplicates_secs, Some(600));
}

fn arb_effects() -> impl Strategy<Value = crate::model::Effects> {
    (
        prop::option::of(prop::sample::select(vec![
            LogLevel::Always,
            LogLevel::Sampled,
        ])),
        prop::option::of(prop::sample::select(vec![
            Upload::Immediate,
            Upload::Batched,
            Upload::LocalOnly,
        ])),
        prop::option::of(prop::sample::select(vec![
            Notify::None,
            Notify::Default,
            Notify::Custom,
        ])),
        any::<bool>(),
        prop::option::of(prop::sample::select(vec![
            EventSeverity::Info,
            EventSeverity::Medium,
            EventSeverity::Critical,
        ])),
        prop::option::of(0u32..604_800),
    )
        .prop_map(|(log, upload, notify, link, severity, suppress)| {
            let notify_eff = notify.unwrap_or(Notify::Default);
            crate::model::Effects {
                log,
                upload,
                notify,
                notification_text: (notify == Some(Notify::Custom))
                    .then(|| "Blocked {file}".to_owned()),
                help_url: (link && notify_eff != Notify::None)
                    .then(|| "https://help.example.org/u".to_owned()),
                severity,
                tags: Vec::new(),
                suppress_duplicates_secs: suppress,
            }
        })
}

/// Unknown policies with random prompt fallbacks, restrict levels (with a
/// profile) and effects.
fn arb_full_policy() -> impl Strategy<Value = UnknownPolicy> {
    (
        arb_policy(),
        prop::sample::select(vec![
            Level::Block,
            Level::Restrict,
            Level::Detect,
            Level::Allow,
        ]),
        arb_effects(),
    )
        .prop_map(|(mut p, fallback, effects)| {
            p.prompt.fallback = fallback;
            p.restrict_profile = Some(
                PROFILE
                    .parse()
                    .map(crate::model::ContainmentProfileRef)
                    .unwrap(),
            );
            p.effects = effects;
            p
        })
}

#[test]
fn a_nearer_layer_cannot_loosen_prompt_controls_or_the_preset() {
    let outer: UnknownPolicy = serde_json::from_value(serde_json::json!({
        "preset": "e8_ml3",
        "default": "prompt",
        "prompt": {"options": ["request_approval", "block"], "require_justification": true,
                   "reauth": "mfa", "local_approval_scope": "user", "temp_approval_days": 7},
        "effects": {"severity": "critical", "upload": "immediate", "log": "always"},
    }))
    .unwrap();
    let inner: UnknownPolicy = serde_json::from_value(serde_json::json!({
        "preset": "e8_ml1",
        "default": "prompt",
        "prompt": {"options": ["allow_once", "allow_always_local", "block"], "reauth": "none",
                   "local_approval_scope": "device", "temp_approval_days": 90, "timeout_secs": 30},
        "effects": {"severity": "low", "upload": "batched", "log": "sampled", "tags": ["inner"]},
    }))
    .unwrap();
    let m = inner.stricter(&outer);
    assert_eq!(m.preset, Some(CompliancePreset::E8Ml3));
    assert_eq!(m.prompt.options, vec![PromptOption::Block]);
    assert!(m.prompt.require_justification);
    assert_eq!(m.prompt.reauth, Reauth::Mfa);
    assert_eq!(m.prompt.local_approval_scope, ApprovalScope::User);
    assert_eq!(m.prompt.temp_approval_days, 7);
    assert_eq!(m.prompt.timeout_secs, 30, "the nearer layer's timeout");
    assert_eq!(m.effects.severity, Some(EventSeverity::Critical));
    assert_eq!(m.effects.upload, Some(Upload::Immediate));
    assert_eq!(m.effects.log, Some(LogLevel::Always));
    assert_eq!(m.effects.tags, vec!["inner".to_owned()]);
    // Overlapping options are kept in the nearer layer's order.
    let a = PromptSettings {
        options: vec![PromptOption::Block, PromptOption::AllowOnce],
        ..PromptSettings::default()
    };
    let b = PromptSettings {
        options: vec![
            PromptOption::AllowOnce,
            PromptOption::RequestApproval,
            PromptOption::Block,
        ],
        ..PromptSettings::default()
    };
    assert_eq!(
        a.stricter(&b).options,
        vec![PromptOption::Block, PromptOption::AllowOnce]
    );
}

fn arb_prompt() -> impl Strategy<Value = PromptSettings> {
    (
        prop::sample::subsequence(
            vec![
                PromptOption::AllowOnce,
                PromptOption::AllowAlwaysLocal,
                PromptOption::RequestApproval,
                PromptOption::Block,
            ],
            1..=4,
        ),
        any::<bool>(),
        prop::sample::select(vec![Reauth::None, Reauth::Password, Reauth::Mfa]),
        prop::sample::select(vec![ApprovalScope::User, ApprovalScope::Device]),
        1u16..=90,
        prop::sample::select(vec![Level::Block, Level::Detect, Level::Allow]),
    )
        .prop_map(
            |(
                options,
                require_justification,
                reauth,
                local_approval_scope,
                temp_approval_days,
                fallback,
            )| PromptSettings {
                options,
                require_justification,
                reauth,
                local_approval_scope,
                temp_approval_days,
                fallback,
                ..PromptSettings::default()
            },
        )
}

proptest! {
    /// Every prompt control of the merge is at least as strict as each
    /// side's, and the merged policy is still valid.
    #[test]
    fn merged_prompts_are_stricter_and_valid(a in arb_prompt(), b in arb_prompt()) {
        let m = a.stricter(&b);
        prop_assert!(m.options.iter().all(|o| *o == PromptOption::Block || (a.options.contains(o) && b.options.contains(o))));
        prop_assert!(!m.options.is_empty());
        prop_assert!(m.require_justification >= (a.require_justification || b.require_justification));
        prop_assert!(m.reauth >= a.reauth.max(b.reauth));
        prop_assert!(m.temp_approval_days <= a.temp_approval_days.min(b.temp_approval_days));
        if a.local_approval_scope == ApprovalScope::User || b.local_approval_scope == ApprovalScope::User {
            prop_assert_eq!(m.local_approval_scope, ApprovalScope::User);
        }
        let mut d = doc(serde_json::json!({}));
        d.policy.unknown = UnknownPolicy { prompt: m, ..UnknownPolicy::default() };
        prop_assert!(d.validate().is_ok());
    }
}

// ------------------------------------------- review fixes (#277, CodeRabbit)

/// One stage-6 context: what [`Known::applicable`] depends on.
struct Ctx<'a> {
    t: ObjectType,
    locations: &'a BTreeSet<LocationClass>,
    origins: &'a BTreeSet<OriginClass>,
    session: Option<SessionType>,
    containment: Option<bool>,
    blocklisted: bool,
}

/// What a policy applies in one context, for the merge oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Applied {
    /// The level the entries resolved to.
    resolved: Level,
    /// The level applied.
    level: Level,
    /// For a prompt: the level its timeout or a failed prompt ends in.
    on_timeout: Option<Level>,
}

impl Applied {
    /// Whether `self` is never weaker than `other`: a stricter level, or a
    /// prompt that ends no weaker. A prompt is an answer away from
    /// running, so it is weaker than `restrict` or `block`, and stricter
    /// than `detect` or `allow` only if its timeout is too.
    fn never_weaker(self, other: Self) -> bool {
        match (self.level, other.level) {
            (Level::Prompt, Level::Prompt) => self.on_timeout >= other.on_timeout,
            (Level::Prompt, o) => o <= Level::Detect && self.on_timeout >= Some(o),
            (s, _) => s >= other.level,
        }
    }
}

/// The level `p` applies in `ctx`, as stage 6 decides it: through the
/// evaluator, so the oracle is the engine and not a model of it.
fn applied(p: &UnknownPolicy, ctx: &Ctx<'_>) -> Applied {
    let mut d = if ctx.blocklisted {
        // An audit rule of a blocklist matches every object of the type,
        // so nothing is prompted for, and nothing is decided by a rule.
        let rule = serde_json::json!({
            "id": rule_id(77), "name": "Watch",
            "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
            "action": {"type": "audit"},
        });
        doc_with(
            serde_json::json!({}),
            &[(SET, "blocklist", false, vec![rule])],
        )
    } else {
        doc(serde_json::json!({}))
    };
    d.policy.unknown = p.clone();
    let v = d.validate().unwrap_or_else(|e| panic!("{e:#?}"));
    let mut context = EvaluationContext::new();
    context.session.session_type = ctx.session;
    context.device.containment_available = ctx.containment;
    let facts = ObjectFacts::new()
        .with(Field::HashSha256, sha('a'))
        .with_location_class(ctx.locations.iter().copied())
        .with_origin(ctx.origins.iter().copied());
    let got = decide_with(&v, ctx.t, &facts, &context);
    let u = got.unknown().expect("stage 6 decides");
    Applied {
        resolved: u.resolved,
        level: u.applied,
        on_timeout: got.directives().prompt.as_ref().map(|p| p.fallback.level),
    }
}

/// The merge as it was before the review fix: levels compared as written,
/// the fallback the stricter of both, and a level a type cannot take
/// replaced with `block`.
fn old_merge(a: &UnknownPolicy, b: &UnknownPolicy) -> UnknownPolicy {
    let mut m = a.stricter(b);
    let pick = |x: Option<&Level>, dx: Level, y: Option<&Level>, dy: Level| {
        x.copied().unwrap_or(dx).max(y.copied().unwrap_or(dy))
    };
    m.default = a.default.max(b.default);
    m.prompt.fallback = a.prompt.fallback.max(b.prompt.fallback);
    for (k, l) in &mut m.by_location {
        *l = pick(
            a.by_location.get(k),
            a.default,
            b.by_location.get(k),
            b.default,
        );
    }
    for (k, l) in &mut m.by_origin {
        *l = pick(a.by_origin.get(k), a.default, b.by_origin.get(k), b.default);
    }
    for (t, l) in &mut m.by_type {
        let level = pick(a.by_type.get(t), a.default, b.by_type.get(t), b.default);
        let usable = match level {
            Level::Prompt => prompt_valid_for(*t),
            Level::Restrict => restrict_valid_for(*t),
            _ => true,
        };
        *l = if usable { level } else { Level::Block };
    }
    m
}

fn unknown(v: serde_json::Value) -> UnknownPolicy {
    serde_json::from_value(v).unwrap()
}

#[test]
fn a_merged_restrict_never_undercuts_a_prompt_that_falls_back_to_block() {
    // The reviewer's case: A prompts and falls back to `block`, B
    // restricts. Without an interactive session A blocks.
    let a = unknown(serde_json::json!({"default": "prompt", "prompt": {"fallback": "block"}}));
    let b = unknown(serde_json::json!({"default": "restrict", "restrict_profile": PROFILE}));
    let locations = BTreeSet::from([LocationClass::OtherFixed]);
    let origins = BTreeSet::from([OriginClass::Unknown]);
    let ctx = Ctx {
        t: ObjectType::Executable,
        locations: &locations,
        origins: &origins,
        session: Some(SessionType::Service),
        containment: Some(true),
        blocklisted: false,
    };
    let la = applied(&a, &ctx);
    assert_eq!(la.level, Level::Block);
    // The old merge restricts, so the new oracle rejects it.
    let old = applied(&old_merge(&a, &b), &ctx);
    assert_eq!(old.level, Level::Restrict);
    assert!(!old.never_weaker(la), "the oracle must catch the old merge");
    // The fixed merge blocks, in both orders.
    for m in [a.stricter(&b), b.stricter(&a)] {
        let lm = applied(&m, &ctx);
        assert_eq!(lm.level, Level::Block, "{m:?}");
        assert!(lm.never_weaker(la));
    }
}

#[test]
fn the_old_merge_also_failed_the_oracle_for_unpromptable_types() {
    // A prompts with fallback `detect`; B detects libraries. Each side
    // detects a library; the old merge blocked it, which the oracle's
    // upper bound reports as stricter than needed, and the new merge
    // detects it.
    let a = unknown(serde_json::json!({"default": "prompt", "prompt": {"fallback": "detect"}}));
    let b = unknown(serde_json::json!({"default": "detect", "by_type": {"library": "detect"}}));
    let locations = BTreeSet::from([LocationClass::ProgramFiles]);
    let origins = BTreeSet::from([OriginClass::Unknown]);
    let ctx = Ctx {
        t: ObjectType::Library,
        locations: &locations,
        origins: &origins,
        session: Some(SessionType::Console),
        containment: Some(true),
        blocklisted: false,
    };
    assert_eq!(applied(&a, &ctx).level, Level::Detect);
    assert_eq!(applied(&b, &ctx).level, Level::Detect);
    assert_eq!(applied(&old_merge(&b, &a), &ctx).level, Level::Block);
    assert_eq!(applied(&b.stricter(&a), &ctx).level, Level::Detect);
    assert_eq!(applied(&a.stricter(&b), &ctx).level, Level::Detect);
}

#[test]
fn a_merged_fallback_comes_from_the_sides_that_prompt() {
    // B never prompts, so its `block` fallback never applies, and the
    // merged prompt keeps A's `detect` fallback.
    let a = unknown(serde_json::json!({"default": "prompt", "prompt": {"fallback": "detect"}}));
    let b = unknown(serde_json::json!({"default": "detect"}));
    let m = a.stricter(&b);
    assert_eq!(m.prompt.fallback, Level::Detect);
    // A side's `prompt` fallback is unusable and counts as `block`.
    let c = UnknownPolicy {
        default: Level::Prompt,
        prompt: PromptSettings {
            fallback: Level::Prompt,
            ..PromptSettings::default()
        },
        ..UnknownPolicy::default()
    };
    assert_eq!(c.stricter(&a).prompt.fallback, Level::Block);
}

#[test]
fn a_restrict_next_to_a_blocking_prompt_elsewhere_is_deliberately_blocked_everywhere() {
    // Exception 2 of `UnknownPolicy::stricter`, pinned: B prompts for
    // internet downloads with a `block` fallback, so its `restrict` default
    // becomes `block` in the merged policy. A static merge cannot know that
    // in this console session B's prompt could have been shown, so the
    // object is blocked though A allows it and B would only ask. It fails
    // closed; a context-aware merge is deferred (#37).
    let a = unknown(serde_json::json!({
        "default": "allow", "by_type": {"script.other": "allow"}, "prompt": {"fallback": "block"},
    }));
    let mut b = unknown(serde_json::json!({
        "default": "restrict", "by_origin": {"internet": "prompt"}, "prompt": {"fallback": "block"},
    }));
    b.restrict_profile = PROFILE
        .parse()
        .map(crate::model::ContainmentProfileRef)
        .ok();
    let locations = BTreeSet::from([LocationClass::UserProfile]);
    let origins = BTreeSet::from([OriginClass::Internet]);
    let ctx = Ctx {
        t: ObjectType::Script(ScriptKind::Other),
        locations: &locations,
        origins: &origins,
        session: Some(SessionType::Console),
        containment: Some(true),
        blocklisted: false,
    };
    assert_eq!(applied(&a, &ctx).level, Level::Allow);
    assert_eq!(applied(&b, &ctx).level, Level::Prompt);
    for m in [a.stricter(&b), b.stricter(&a)] {
        assert_eq!(applied(&m, &ctx).level, Level::Block, "{m:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The merged policy is never stricter than the strictest side applies
    /// in the same context, except in the cases one policy cannot
    /// reproduce, each listed on [`UnknownPolicy::stricter`]:
    ///
    /// 1. the merged prompt's fallback is one setting, so where the merged
    ///    policy resolves to `prompt` and cannot show it, it may apply the
    ///    strictest fallback of the sides that prompt anywhere;
    /// 2. a `restrict` turns to `block` where a side's prompt falls back to
    ///    `block`;
    /// 3. an entry only one side sets is compared with the other side's
    ///    `default`, even where another entry of that side applies to the
    ///    object, so the merged level may reach, for some entry that
    ///    applies, the stricter of the two sides' levels for that entry.
    ///
    /// Half the cases give both sides the same entries, where exception 3
    /// cannot arise and the bound is the strict one; the rest keep each
    /// side's own entries and allow exception 3. A side's fallback is only
    /// counted where the merged policy resolves to `prompt` in this context,
    /// so an unused fallback never widens the bound.
    #[test]
    fn merged_decisions_are_no_stricter_than_needed(
        a in arb_full_policy(),
        b in arb_full_policy(),
        align in any::<bool>(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 1..3),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 1..3),
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        containment in prop::option::of(any::<bool>()),
    ) {
        let validates = |u: &UnknownPolicy| {
            let mut d = doc(serde_json::json!({}));
            d.policy.unknown = u.clone();
            d.validate().is_ok()
        };
        let mut b = b;
        if align {
            // `b` takes `a`'s keys, with its own levels.
            fn same_keys<K: Ord + Copy>(
                a: &std::collections::BTreeMap<K, Level>,
                b: &std::collections::BTreeMap<K, Level>,
                fill: Level,
            ) -> std::collections::BTreeMap<K, Level> {
                a.keys().map(|k| (*k, b.get(k).copied().unwrap_or(fill))).collect()
            }
            b.by_location = same_keys(&a.by_location, &b.by_location, b.default);
            b.by_origin = same_keys(&a.by_origin, &b.by_origin, b.default);
            b.by_type = same_keys(&a.by_type, &b.by_type, b.default)
                .into_iter()
                .map(|(t, l)| {
                    let ok = (l != Level::Prompt || prompt_valid_for(t))
                        && (l != Level::Restrict || restrict_valid_for(t));
                    (t, if ok { l } else { Level::Block })
                })
                .collect();
        }
        // As in the oracle above: invalid inputs (random effects) are skipped.
        if !(validates(&a) && validates(&b)) {
            return Ok(());
        }
        let ctx = Ctx { t, locations: &locations, origins: &origins, session, containment, blocklisted: false };
        let m = a.stricter(&b);
        let (la, lb, lm) = (applied(&a, &ctx), applied(&b, &ctx), applied(&m, &ctx));
        let containable = containment == Some(true) && restrict_valid_for(t);
        let uncontained = |l: Level| if l == Level::Restrict && !containable { Level::Block } else { l };
        // Exception 1, only where the merged policy resolves to `prompt`.
        let usable = |f: Level| if f == Level::Prompt { Level::Block } else { f };
        let prompts = |p: &UnknownPolicy| {
            core::iter::once(p.default)
                .chain(p.by_location.values().copied())
                .chain(p.by_origin.values().copied())
                .chain(p.by_type.values().copied())
                .any(|l| l == Level::Prompt)
        };
        let any_fallback = [&a, &b]
            .into_iter()
            .filter(|p| prompts(p))
            .map(|p| usable(p.prompt.fallback))
            .max()
            .unwrap_or(Level::Allow)
            .max(Level::Detect);
        let fallback_bound = if lm.resolved == Level::Prompt { any_fallback } else { Level::Allow };
        // Exception 3, only where the sides set different entries.
        let keyed = if align {
            Level::Allow
        } else {
            let side = |p: &UnknownPolicy, l: Option<&Level>| l.copied().unwrap_or(p.default);
            let mut keys: Vec<Level> = Vec::new();
            if a.by_type.contains_key(&t) || b.by_type.contains_key(&t) {
                keys.push(side(&a, a.by_type.get(&t)).max(side(&b, b.by_type.get(&t))));
            }
            for c in &locations {
                if a.by_location.contains_key(c) || b.by_location.contains_key(c) {
                    keys.push(side(&a, a.by_location.get(c)).max(side(&b, b.by_location.get(c))));
                }
            }
            for o in &origins {
                if a.by_origin.contains_key(o) || b.by_origin.contains_key(o) {
                    keys.push(side(&a, a.by_origin.get(o)).max(side(&b, b.by_origin.get(o))));
                }
            }
            keys.into_iter().max().unwrap_or(Level::Allow)
        };
        // A keyed `prompt` the object cannot get (a library or driver, or
        // no prompt shown) ends in a prompting side's fallback.
        let keyed = if keyed == Level::Prompt { any_fallback.max(Level::Prompt) } else { keyed };
        let top = la.level.max(lb.level);
        let bound = uncontained(top.max(fallback_bound).max(keyed));
        // Exception 2, only where it can arise: some input prompts with a
        // `block` fallback somewhere (in any session: a static merge cannot
        // depend on the session), and the merged level being raised is a
        // `restrict`. Two restrict-only inputs never qualify.
        let blocking_prompt =
            [&a, &b].into_iter().any(|p| prompts(p) && usable(p.prompt.fallback) == Level::Block);
        let restrict_raised = blocking_prompt && lm.level == Level::Block && bound == Level::Restrict;
        prop_assert!(
            lm.level <= bound || restrict_raised,
            "{lm:?} stricter than {la:?} and {lb:?} (bound {bound:?}, aligned {align})"
        );
    }

    /// The control for exception 2: two policies that only restrict an
    /// executable, with containment available, merge into one that
    /// restricts it. Neither prompts, so no promotion to `block` is allowed.
    #[test]
    fn two_restrict_only_policies_merge_to_restrict(
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        class in prop::sample::select(LocationClass::ALL.to_vec()),
        by_location in any::<bool>(),
    ) {
        let restrict = |u: serde_json::Value| -> UnknownPolicy {
            let mut p: UnknownPolicy = serde_json::from_value(u).unwrap();
            p.restrict_profile = PROFILE.parse().map(crate::model::ContainmentProfileRef).ok();
            p
        };
        let a = restrict(serde_json::json!({"default": "restrict"}));
        let b = if by_location {
            restrict(serde_json::json!({"default": "detect", "by_location": {class.as_str(): "restrict"}}))
        } else {
            restrict(serde_json::json!({"default": "restrict", "by_type": {"executable": "restrict"}}))
        };
        let locations = BTreeSet::from([class]);
        let origins = BTreeSet::from([OriginClass::Unknown]);
        let ctx = Ctx { t: ObjectType::Executable, locations: &locations, origins: &origins, session, containment: Some(true), blocklisted: false };
        prop_assert_eq!(applied(&a, &ctx).level, Level::Restrict);
        for m in [a.stricter(&b), b.stricter(&a)] {
            prop_assert_eq!(applied(&m, &ctx).level, Level::Restrict, "{:?}", m);
        }
    }

    /// The library case of the review, in the property: both sides detect a
    /// library, so the merged policy must too. B's unused `block` fallback
    /// does not widen the bound.
    #[test]
    fn an_unused_fallback_never_lets_the_merge_block_what_both_sides_detect(
        fallback in prop::sample::select(vec![Level::Detect, Level::Allow]),
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        class in prop::sample::select(LocationClass::ALL.to_vec()),
    ) {
        let mut a = UnknownPolicy { default: Level::Prompt, ..UnknownPolicy::default() };
        a.prompt.fallback = fallback;
        let b = unknown(serde_json::json!({"default": "detect", "by_type": {"library": "detect"}}));
        let locations = BTreeSet::from([class]);
        let origins = BTreeSet::from([OriginClass::Unknown]);
        let ctx = Ctx { t: ObjectType::Library, locations: &locations, origins: &origins, session, containment: Some(true), blocklisted: false };
        let (la, lb) = (applied(&a, &ctx), applied(&b, &ctx));
        prop_assert_eq!(la.level, fallback);
        prop_assert_eq!(lb.level, Level::Detect);
        for m in [a.stricter(&b), b.stricter(&a)] {
            let lm = applied(&m, &ctx);
            prop_assert!(lm.level <= Level::Detect, "{:?}", lm);
            prop_assert!(lm.never_weaker(la) && lm.never_weaker(lb));
        }
        // The previous merge blocks it, which this property rejects.
        prop_assert_eq!(applied(&old_merge(&b, &a), &ctx).level, Level::Block);
    }
}

#[test]
fn a_cross_dimension_merge_blocks_what_each_side_only_detects() {
    // The review's case, pinned as a documented exception (it fails
    // closed): A detects executables by type, B detects `temp` by
    // location. Each alone detects an executable in `temp`, but B's `temp`
    // entry is compared with A's `block` default, so the merge blocks it.
    let a = unknown(serde_json::json!({"default": "block", "by_type": {"executable": "detect"}}));
    let b = unknown(serde_json::json!({"default": "detect", "by_location": {"temp": "detect"}}));
    let locations = BTreeSet::from([LocationClass::Temp]);
    let origins = BTreeSet::from([OriginClass::Unknown]);
    let ctx = Ctx {
        t: ObjectType::Executable,
        locations: &locations,
        origins: &origins,
        session: Some(SessionType::Console),
        containment: Some(true),
        blocklisted: false,
    };
    assert_eq!(applied(&a, &ctx).level, Level::Detect);
    assert_eq!(applied(&b, &ctx).level, Level::Detect);
    for m in [a.stricter(&b), b.stricter(&a)] {
        assert_eq!(m.by_location.get(&LocationClass::Temp), Some(&Level::Block));
        assert_eq!(applied(&m, &ctx).level, Level::Block, "{m:?}");
    }
}

// -------------------------------------------------- policy scope (#38)

/// A document whose policy has `scope` and an unknown policy `unknown`.
fn scoped_doc(unknown: serde_json::Value, scope: serde_json::Value) -> PolicyDocument {
    let mut d = doc(unknown);
    d.policy.scope = Some(serde_json::from_value(scope).unwrap());
    d
}

fn console_only() -> serde_json::Value {
    serde_json::json!({"sessions": {"types": ["console"]}})
}

fn in_session(session: Option<SessionType>) -> EvaluationContext {
    let mut c = interactive_context();
    c.session.session_type = session;
    c
}

#[test]
fn the_policy_scope_limits_its_unknown_settings() {
    let v = valid(scoped_doc(
        serde_json::json!({"default": "allow"}),
        console_only(),
    ));
    let facts = object(&[LocationClass::OtherFixed], &[]);
    // In scope: the policy's level.
    let inside = decide_with(
        &v,
        ObjectType::Executable,
        &facts,
        &in_session(Some(SessionType::Console)),
    );
    assert_eq!(inside.reason_code(), ReasonCode::UnknownAllowed);
    assert_eq!(inside.outcome(), Outcome::Allowed);
    // Out of scope, and with the session unknown: the implicit deny, even
    // with `default: allow`.
    for session in [Some(SessionType::Rdp), None] {
        let outside = decide_with(&v, ObjectType::Executable, &facts, &in_session(session));
        assert_eq!(outside.outcome(), Outcome::Blocked, "{session:?}");
        assert_eq!(outside.reason_code(), ReasonCode::ImplicitDenyUnknown);
        let u = outside.unknown().unwrap();
        assert_eq!(u.fallback, Some(FallbackReason::PolicyOutOfScope));
        assert_eq!((u.resolved, u.applied), (Level::Allow, Level::Block));
    }
    // An unknown session is noted.
    let unknown_session = decide_with(&v, ObjectType::Executable, &facts, &in_session(None));
    assert!(
        unknown_session
            .scope_notes()
            .contains(&crate::scope::ScopeNote::FactMissing)
    );
}

#[test]
fn out_of_scope_prompts_restrictions_and_requests_take_the_builtin_default() {
    let v = valid(scoped_doc(
        serde_json::json!({
            "default": "prompt", "by_origin": {"internet": "restrict"},
            "restrict_profile": PROFILE, "allow_request": true,
        }),
        console_only(),
    ));
    let rdp = in_session(Some(SessionType::Rdp));
    for origins in [&[][..], &[OriginClass::Internet][..]] {
        let d = decide_with(
            &v,
            ObjectType::Executable,
            &object(&[LocationClass::OtherFixed], origins),
            &rdp,
        );
        assert_eq!(d.outcome(), Outcome::Blocked);
        assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
        assert!(d.directives().prompt.is_none());
        assert!(d.directives().containment.is_none());
        // The built-in default raises no request.
        assert!(d.directives().request.is_none());
    }
}

#[test]
fn a_policy_without_a_scope_applies_its_unknown_settings_everywhere() {
    let v = valid(doc(serde_json::json!({"default": "detect"})));
    for session in [Some(SessionType::Console), Some(SessionType::Service), None] {
        let d = decide_with(
            &v,
            ObjectType::Executable,
            &object(&[LocationClass::OtherFixed], &[]),
            &in_session(session),
        );
        assert_eq!(d.reason_code(), ReasonCode::UnknownDetected, "{session:?}");
    }
}

#[test]
fn unknown_scopes_apply_when_any_of_them_matches() {
    let mut d = doc(serde_json::json!({"default": "detect"}));
    d.policy.unknown.scopes = vec![
        serde_json::from_value(console_only()).unwrap(),
        serde_json::from_value(serde_json::json!({"sessions": {"types": ["service"]}})).unwrap(),
    ];
    let v = valid(d);
    let facts = object(&[LocationClass::OtherFixed], &[]);
    for (session, want) in [
        (SessionType::Console, ReasonCode::UnknownDetected),
        (SessionType::Service, ReasonCode::UnknownDetected),
        (SessionType::Batch, ReasonCode::ImplicitDenyUnknown),
    ] {
        let got = decide_with(
            &v,
            ObjectType::Executable,
            &facts,
            &in_session(Some(session)),
        );
        assert_eq!(got.reason_code(), want, "{session:?}");
    }
}

#[test]
fn a_policy_scope_is_checked_as_an_allow_when_unknown_settings_permit() {
    // A name pattern may not widen where something runs.
    let pattern = serde_json::json!({"principals": {"include": [{"user_pattern": "*\\alice"}]}});
    let found = codes(scoped_doc(
        serde_json::json!({"default": "detect"}),
        pattern.clone(),
    ));
    assert!(
        found.contains(&(
            ErrorCode::UserPatternNotAllowed,
            "/policy/scope/principals/include/0".to_owned()
        )),
        "{found:?}"
    );
    // With every level `block` and only a deny under it, the scope cannot
    // widen anything.
    let deny = serde_json::json!({
        "id": rule_id(5), "name": "D",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('d')]}},
        "action": {"type": "deny"},
    });
    let mut d = doc_with(
        serde_json::json!({}),
        &[(SET, "blocklist", false, vec![deny.clone()])],
    );
    d.policy.scope = Some(serde_json::from_value(pattern.clone()).unwrap());
    assert_eq!(codes(d), vec![]);
    let mut d = doc_with(
        serde_json::json!({"default": "detect"}),
        &[(SET, "blocklist", false, vec![deny])],
    );
    d.policy.scope = Some(serde_json::from_value(pattern).unwrap());
    assert!(codes(d).contains(&(
        ErrorCode::UserPatternNotAllowed,
        "/policy/scope/principals/include/0".to_owned()
    )));
    // At most 1000 `unknown.scopes`.
    let mut d = doc(serde_json::json!({}));
    d.policy.unknown.scopes = vec![serde_json::from_value(console_only()).unwrap(); 1001];
    assert!(codes(d).contains(&(ErrorCode::InvalidScope, "/policy/unknown/scopes".to_owned())));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Out of the policy's scope, stage 6 is the implicit deny whatever the
    /// unknown settings; in scope, it is what the same policy without a
    /// scope decides.
    #[test]
    fn out_of_scope_is_always_the_implicit_deny(
        p in arb_full_policy(),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
        locations in prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 1..3),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 1..3),
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
    ) {
        let mut scoped = doc(serde_json::json!({}));
        scoped.policy.unknown = p.clone();
        let mut open = scoped.clone();
        scoped.policy.scope = Some(serde_json::from_value(console_only()).unwrap());
        let (Ok(vs), Ok(vo)) = (scoped.validate(), open.clone().validate()) else { return Ok(()) };
        let _ = &mut open;
        let facts = ObjectFacts::new()
            .with(Field::HashSha256, sha('a'))
            .with_location_class(locations.iter().copied())
            .with_origin(origins.iter().copied());
        let ctx = in_session(session);
        let got = decide_with(&vs, t, &facts, &ctx);
        if session == Some(SessionType::Console) {
            let want = decide_with(&vo, t, &facts, &ctx);
            prop_assert_eq!(got.outcome(), want.outcome());
            prop_assert_eq!(got.reason_code(), want.reason_code());
        } else {
            prop_assert_eq!(got.outcome(), Outcome::Blocked);
            prop_assert_eq!(got.reason_code(), ReasonCode::ImplicitDenyUnknown);
            prop_assert_eq!(got.unknown().unwrap().fallback, Some(FallbackReason::PolicyOutOfScope));
        }
    }
}

// ------------------------------------------------ e8_ml3 early boot

#[test]
fn ml3_warns_while_early_boot_drivers_are_only_audited() {
    let found = codes(doc_with(
        preset_json(CompliancePreset::E8Ml3),
        &[mandatory_set()],
    ));
    assert_eq!(
        found,
        vec![(
            ErrorCode::ComplianceWeakened,
            "/policy/unknown/driver_boot_policy".to_owned()
        )]
    );
    let mut enforced = preset_json(CompliancePreset::E8Ml3);
    enforced["driver_boot_policy"] = "enforce".into();
    assert_eq!(codes(doc_with(enforced, &[mandatory_set()])), vec![]);
    // Other presets do not block drivers, so they have no such exemption.
    for p in [CompliancePreset::E8Ml1, CompliancePreset::E8Ml2] {
        assert_eq!(codes(doc(preset_json(p))), vec![], "{p:?}");
    }
    // The preset itself keeps `audit`.
    assert_eq!(
        UnknownPolicy::preset(CompliancePreset::E8Ml3).driver_boot_policy,
        DriverBootPolicy::Audit
    );
}

// ------------------------------------------------ location classifier

#[test]
fn a_windows_temp_folder_without_windir_is_unknown_not_temp() {
    // Expectation changed in round 5: the `X:\Windows\Temp` fallback used
    // to grant `temp` without `%WINDIR%`; a drive-root folder is not a fact,
    // so `temp` is now `Unknown` (and stage 6 applies its level too).
    use LocationClass as L;
    let with = |raw: &str, v: &PathVariables| {
        let p = PathFact::new(raw, &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed);
        classify(&p, v, Some(VolumeKind::Fixed), &[]).classes
    };
    // Full facts: every variable set, `%WINDIR%` among them.
    let windir = vars();
    // With `%WINDIR%`, it decides: another drive's `\Windows\Temp` is not
    // the system's.
    assert_eq!(
        with("D:\\Windows\\Temp\\a.exe", &windir).get(L::Temp),
        Tri::NoMatch
    );
    assert_eq!(
        with("C:\\Windows\\Temp\\a.exe", &windir).get(L::Temp),
        Tri::Match
    );
    // Without it, no `\Windows\Temp` is certain, on any drive.
    let none = PathVariables::new();
    for raw in [
        "C:\\Windows\\Temp\\a.exe",
        "D:\\Windows\\Temp\\a.exe",
        "D:\\Tools\\a.exe",
    ] {
        assert_eq!(with(raw, &none).get(L::Temp), Tri::Unknown, "{raw}");
    }
}

#[test]
fn a_unc_server_or_share_name_is_not_a_cache_folder() {
    use LocationClass as L;
    let with = |raw: &str| {
        let p = PathFact::new(raw, &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed);
        known(classify(&p, &PathVariables::new(), None, &[]))
    };
    assert!(!with("\\\\INetCache\\apps\\a.exe").contains(&L::Temp));
    assert!(!with("\\\\server\\INetCache\\a.exe").contains(&L::Temp));
    assert!(with("\\\\server\\apps\\INetCache\\a.exe").contains(&L::Temp));
    assert!(with("D:\\data\\INetCache\\x\\a.exe").contains(&L::Temp));
    // A drive root has no directory name to mistake.
    assert!(!with("D:\\a.exe").contains(&L::Temp));
}

#[test]
fn without_volume_facts_a_drive_could_be_removable() {
    // Expectation changed in round 5: an unknown volume kind used to read
    // as a fixed disk (`other_fixed`). It is now a missing fact: `removable`,
    // `optical`, `network` and `other_fixed` are all `Unknown`.
    use LocationClass as L;
    let p = PathFact::new("E:\\setup.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    let unknown_volume = classify(&p, &PathVariables::new(), None, &[]);
    for c in [L::Removable, L::Optical, L::Network, L::OtherFixed] {
        assert_eq!(unknown_volume.classes.get(c), Tri::Unknown, "{c:?}");
    }
    assert!(unknown_volume.missing.contains(&MissingFact::VolumeKind));
    let removable = known(classify(
        &p,
        &PathVariables::new(),
        Some(VolumeKind::Removable),
        &[],
    ));
    assert_eq!(removable, BTreeSet::from([L::Removable]));
    let fixed = known(classify(&p, &vars(), Some(VolumeKind::Fixed), &[]));
    assert_eq!(fixed, BTreeSet::from([L::OtherFixed]));
}

#[test]
fn the_baseline_needs_the_system32_variable() {
    // Without `%SYSTEM32%` its exceptions are unknown, so the baseline's
    // allow does not apply and stage 6 decides (the README says so).
    let v = baseline_doc(serde_json::json!({}), &[]);
    let facts = os_signed("C:\\Windows\\System32\\winlogon.exe", false);
    let decide = |variables: &PathVariables| {
        let context = interactive_context();
        Evaluator::new(&v).unwrap().evaluate(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables,
                context: &context,
            },
            TRACE,
        )
    };
    assert_eq!(decide(&variables_full()).outcome(), Outcome::Allowed);
    let d = decide(&vars());
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
}

#[test]
fn the_example_applies_the_strictest_matching_entry() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/examples/policies/unknown-applications.yaml"
    ))
    .unwrap();
    let v = valid(PolicyDocument::from_yaml(&text).unwrap());
    let ps = ObjectType::Script(ScriptKind::Powershell);
    let cases = [
        // A download in a user profile is blocked, not contained.
        (
            ObjectType::Executable,
            LocationClass::UserProfile,
            Some(OriginClass::Internet),
            ReasonCode::ImplicitDenyUnknown,
        ),
        (
            ObjectType::Executable,
            LocationClass::ProgramFiles,
            Some(OriginClass::Internet),
            ReasonCode::UnknownRestricted,
        ),
        // A downloaded PowerShell script in a program folder is contained, not prompted.
        (
            ps,
            LocationClass::ProgramFiles,
            Some(OriginClass::Internet),
            ReasonCode::UnknownRestricted,
        ),
        (
            ps,
            LocationClass::ProgramFiles,
            None,
            ReasonCode::UnknownPrompt,
        ),
        (
            ps,
            LocationClass::UserProfile,
            None,
            ReasonCode::ImplicitDenyUnknown,
        ),
        (
            ObjectType::Executable,
            LocationClass::ProgramFiles,
            None,
            ReasonCode::UnknownDetected,
        ),
    ];
    for (t, class, origin, want) in cases {
        let origins: Vec<OriginClass> = origin.into_iter().collect();
        let d = decide(&v, t, &object(&[class], &origins));
        assert_eq!(d.reason_code(), want, "{t} {class:?} {origin:?}");
    }
}

// ------------------------------------- three-valued classes (#39, round 5)

use crate::facts::PathVariable as PV;
use crate::ops::Tri;

/// Stage 6's applied level for an executable at `raw` (fixed unless
/// `volume` says otherwise), under `u`, with `variables`, and `origins`
/// (`None`: origin collection did not report).
fn applied_level(
    u: serde_json::Value,
    raw: &str,
    volume: Option<VolumeKind>,
    variables: &PathVariables,
    origins: Option<Vec<OriginClass>>,
) -> Level {
    let v = valid(doc(with_profile(u)));
    let mut path = PathFact::new(raw, &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    path.volume = volume;
    let mut facts = ObjectFacts::new()
        .with(Field::HashSha256, sha('a'))
        .with_path(path);
    facts.origin = origins.map(|o| o.into_iter().collect());
    let context = interactive_context();
    Evaluator::new(&v)
        .unwrap()
        .evaluate(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &facts,
                variables,
                context: &context,
            },
            TRACE,
        )
        .unknown()
        .unwrap()
        .applied
}

fn without(v: &PathVariables, drop: PV) -> PathVariables {
    let mut out = PathVariables::new();
    for var in crate::facts::PathVariable::ALL {
        if var != drop {
            let vals: Vec<String> = v.get(var).iter().map(|p| p.as_str().to_owned()).collect();
            let vals: Vec<&str> = vals.iter().map(String::as_str).collect();
            out.set(var, &vals);
        }
    }
    out
}

/// Every row of the round-five table, and the `(x86)` case: removing the
/// fact never lowers the applied level. Each row names the level the old
/// classifier gave without the fact, to show what it relaxed.
#[test]
fn removing_a_fact_never_relaxes_the_documented_cases() {
    let ml1 = preset_json(CompliancePreset::E8Ml1);
    let full = vars();
    let fixed = Some(VolumeKind::Fixed);
    let none = Some(vec![]);
    type Row = (
        &'static str,
        serde_json::Value,
        &'static str,
        Option<VolumeKind>,
        PathVariables,
        Option<VolumeKind>,
        PathVariables,
    );
    let rows: Vec<Row> = vec![
        // The reviewer's case (the old code detected it without %WINDIR%).
        (
            "reviewer temp",
            serde_json::json!({"default": "block", "by_location": {"temp": "detect"}}),
            "D:\\Windows\\Temp\\a.exe",
            fixed,
            full.clone(),
            fixed,
            without(&full, PV::Windir),
        ),
        // `e8_ml1` on the real temp folder (ruling 1 of round four would have detected it).
        (
            "e8_ml1 C:\\Windows\\Temp",
            ml1.clone(),
            "C:\\Windows\\Temp\\a.exe",
            fixed,
            full.clone(),
            fixed,
            without(&full, PV::Windir),
        ),
        // `%TEMP%` (the old code detected it without the variable).
        (
            "e8_ml1 %TEMP%",
            ml1.clone(),
            "C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe",
            fixed,
            full.clone(),
            fixed,
            without(&full, PV::Temp),
        ),
        // A redirected profile (the old code detected it without %USERPROFILE%).
        (
            "e8_ml1 %USERPROFILE%",
            ml1.clone(),
            "D:\\Profiles\\alice\\a.exe",
            fixed,
            full.clone().with(PV::UserProfile, &["D:\\Profiles\\alice"]),
            fixed,
            without(&full, PV::UserProfile),
        ),
        // `windows: block` (the old code detected it without %WINDIR%).
        (
            "windows: block",
            serde_json::json!({"default": "detect", "by_location": {"windows": "block"}}),
            "C:\\Windows\\a.exe",
            fixed,
            full.clone(),
            fixed,
            without(&full, PV::Windir),
        ),
        // The volume kind (the old code read an unknown volume as fixed).
        (
            "removable: block",
            serde_json::json!({"default": "detect", "by_location": {"removable": "block"}}),
            "E:\\setup.exe",
            Some(VolumeKind::Removable),
            full.clone(),
            None,
            full.clone(),
        ),
        // `(x86)` with a partial %PROGRAMFILES% list.
        (
            "program_files: allow, partial",
            serde_json::json!({"default": "detect", "by_location": {"program_files": "allow"}}),
            "C:\\Program Files (x86)\\App\\a.exe",
            fixed,
            without(&full, PV::ProgramFiles).with(PV::ProgramFiles, &["C:\\Program Files"]),
            fixed,
            without(&full, PV::ProgramFiles),
        ),
    ];
    for (label, u, raw, vol_full, vars_full, vol_part, vars_part) in rows {
        let before = applied_level(u.clone(), raw, vol_full, &vars_full, none.clone());
        let after = applied_level(u, raw, vol_part, &vars_part, none.clone());
        assert!(after >= before, "{label}: {before:?} -> {after:?}");
    }
    // The origin fact: under `baseline_only` (the default), no origin facts
    // block an object `detect` would allow.
    let u = serde_json::json!({"default": "detect"});
    assert_eq!(
        applied_level(u.clone(), "C:\\Tools\\a.exe", fixed, &full, none.clone()),
        Level::Detect
    );
    assert_eq!(
        applied_level(u.clone(), "C:\\Tools\\a.exe", fixed, &full, None),
        Level::Block
    );
    assert_eq!(
        applied_level(
            serde_json::json!({"default": "detect", "preexisting_policy": "treat_as_unknown"}),
            "C:\\Tools\\a.exe",
            fixed,
            &full,
            None
        ),
        Level::Detect
    );
    // `by_origin` entries decide an object with no origin facts.
    let internet = serde_json::json!({"default": "detect", "preexisting_policy": "treat_as_unknown", "by_origin": {"internet": "block"}});
    assert_eq!(
        applied_level(internet.clone(), "C:\\Tools\\a.exe", fixed, &full, None),
        Level::Block
    );
    assert_eq!(
        applied_level(internet, "C:\\Tools\\a.exe", fixed, &full, none),
        Level::Detect
    );
}

#[test]
fn a_missing_fact_is_named_in_the_decision_and_explained() {
    let v = valid(doc(serde_json::json!({"default": "detect"})));
    let facts = ObjectFacts::new()
        .with(Field::HashSha256, sha('a'))
        .with_path(
            PathFact::new("C:\\Tools\\a.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed)
                .with_volume(VolumeKind::Fixed),
        );
    let d = decide_full(&v, ObjectType::Executable, &facts);
    let u = d.unknown().unwrap();
    assert_eq!(u.applied, Level::Block);
    assert_eq!(u.fallback, Some(FallbackReason::MissingFact));
    assert_eq!(u.missing_facts, vec![MissingFact::Origin]);
    assert!(u.unknown_origins.contains(&OriginClass::Preexisting));
    // With the origin collection's answer, the same object is detected and
    // nothing is missing.
    let d = decide_full(&v, ObjectType::Executable, &facts.clone().with_origin([]));
    let u = d.unknown().unwrap();
    assert_eq!((u.applied, u.fallback), (Level::Detect, None));
    assert!(
        u.missing_facts.is_empty()
            && u.unknown_locations.is_empty()
            && u.unknown_origins.is_empty()
    );
}

#[test]
fn an_empty_origin_set_is_the_unknown_origin() {
    let v = valid(doc(
        serde_json::json!({"default": "detect", "by_origin": {"unknown": "block"}}),
    ));
    let d = decide(
        &v,
        ObjectType::Executable,
        &object(&[LocationClass::ProgramFiles], &[]),
    );
    assert_eq!(d.unknown().unwrap().origins, vec![OriginClass::Unknown]);
    assert_eq!(d.unknown().unwrap().applied, Level::Block);
}

#[test]
fn with_full_facts_the_classes_are_what_they_were() {
    // The round-five classifier, given every fact (all variables, the
    // volume kind), certain about every class, and equal to the 8923bd8
    // classifier.
    let variables = vars();
    for raw in [
        "C:\\Users\\alice\\Downloads\\a.exe",
        "C:\\Users\\bob\\a.exe",
        "C:\\Users\\alice\\AppData\\Local\\Temp\\x\\a.exe",
        "C:\\Windows\\Temp\\a.exe",
        "C:\\Users\\alice\\AppData\\Local\\Vendor\\INetCache\\Low\\a.exe",
        "C:\\Program Files\\App\\a.exe",
        "C:\\Program Files (x86)\\App\\a.exe",
        "C:\\Windows\\System32\\a.exe",
        "C:\\WindowsApps\\a.exe",
        "D:\\Tools\\a.exe",
        "D:\\Windows\\a.exe",
        "D:\\Users\\alice\\a.exe",
        "C:\\Tools\\a.txt:payload",
        "\\\\server\\share\\a.exe",
        "relative\\a.exe",
    ] {
        // Full facts include the ACL fact; without it the old classifier
        // guessed `user_writable_other` (round six made that `Unknown`).
        for writable in [Some(false), Some(true)] {
            for volume in [
                VolumeKind::Fixed,
                VolumeKind::Removable,
                VolumeKind::Optical,
                VolumeKind::Network,
            ] {
                let mut p = PathFact::new(raw, &VolumeMap::new());
                p.user_writable = writable;
                let now = classify(&p, &variables, Some(volume), &[]);
                let before =
                    super::previous_classifier::classify(&p, &variables, Some(volume), &[]);
                if !p.path.is_resolved() {
                    // An unusable path is a missing fact, not full facts.
                    continue;
                }
                assert!(
                    now.classes.unknown().is_empty(),
                    "{raw} {volume:?}: {:?}",
                    now.classes.unknown()
                );
                assert_eq!(
                    now.classes.matching(),
                    before,
                    "{raw} {writable:?} {volume:?}"
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// With full facts (every variable, the volume kind, the origin
    /// collection's answer), every decision is what it was: the levels
    /// come from the 8923bd8 classes, and nothing is `Unknown`.
    #[test]
    fn with_full_facts_every_decision_is_what_it_was(
        p in arb_full_policy(),
        raw in arb_round5_path(),
        writable in any::<bool>(),
        volume in prop::sample::select(vec![VolumeKind::Fixed, VolumeKind::Removable, VolumeKind::Optical, VolumeKind::Network]),
        origins in prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3),
        t in prop::sample::select(ObjectType::ALL.to_vec()),
    ) {
        let mut d = doc(serde_json::json!({}));
        d.policy.unknown = p;
        let Ok(v) = d.validate() else { return Ok(()) };
        let mut path = PathFact::new(&raw, &VolumeMap::new());
        path.user_writable = Some(writable);
        path.volume = Some(volume);
        let variables = vars();
        let before = super::previous_classifier::classify(&path, &variables, Some(volume), &[]);
        let facts = ObjectFacts::new().with(Field::HashSha256, sha('a')).with_path(path.clone()).with_origin(origins.iter().copied());
        let given = ObjectFacts::new().with(Field::HashSha256, sha('a')).with_location_class(before.iter().copied()).with_origin(origins.iter().copied());
        // Only resolved paths have full facts; an unusable path is a
        // missing fact.
        prop_assume!(path.path.is_resolved() && !before.is_empty());
        let context = interactive_context();
        let decide = |f: &ObjectFacts| Evaluator::new(&v).unwrap().evaluate(
            &Subject { object_type: t, facts: f, variables: &variables, context: &context }, TRACE);
        let (now, then) = (decide(&facts), decide(&given));
        prop_assert_eq!(now.outcome(), then.outcome());
        prop_assert_eq!(now.reason_code(), then.reason_code());
        let u = now.unknown().unwrap();
        prop_assert_eq!(&u.locations, &then.unknown().unwrap().locations);
        prop_assert!(u.unknown_locations.is_empty() && u.unknown_origins.is_empty());
        prop_assert_ne!(u.fallback, Some(FallbackReason::MissingFact));
    }
}

/// Random paths, under the folders the classifier knows and elsewhere.
fn arb_round5_path() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["C", "D", "E"]),
        prop::sample::select(vec![
            "Windows",
            "Windows\\System32",
            "Windows\\Temp",
            "Program Files\\App",
            "Program Files (x86)\\App",
            "Users\\alice",
            "Users\\alice\\AppData\\Local\\Temp",
            "Users\\Public",
            "Profiles\\alice",
            "Data",
            "Data\\INetCache",
        ]),
        prop::sample::select(vec!["a.exe", "b.dll", "c.ps1:stream"]),
    )
        .prop_map(|(d, dir, f)| format!("{d}:\\{dir}\\{f}"))
}

/// A device's variables, each one possibly left out, and possibly
/// partial: `%PROGRAMFILES%` may list only one folder, and the per-user
/// variables may point anywhere.
fn arb_round5_variables() -> impl Strategy<Value = PathVariables> {
    (
        prop::sample::select(vec!["C", "D"]),
        prop::option::of(prop::sample::select(vec![0u8, 1, 2])),
        prop::option::of(any::<bool>()),
        prop::option::of(prop::sample::select(vec![
            "C:\\Users\\alice",
            "D:\\Profiles\\alice",
        ])),
        prop::option::of(prop::sample::select(vec![
            "C:\\Users\\alice\\AppData\\Local\\Temp",
            "D:\\Data",
        ])),
        prop::option::of(any::<bool>()),
    )
        .prop_map(|(os, pf, windir, profile, temp, public)| {
            let mut v = PathVariables::new();
            if windir.is_some() {
                v.set(PV::Windir, &[&format!("{os}:\\Windows")]);
            }
            match pf {
                Some(0) => v.set(PV::ProgramFiles, &[&format!("{os}:\\Program Files")]),
                Some(1) => v.set(PV::ProgramFiles, &[&format!("{os}:\\Program Files (x86)")]),
                Some(_) => v.set(
                    PV::ProgramFiles,
                    &[
                        &format!("{os}:\\Program Files"),
                        &format!("{os}:\\Program Files (x86)"),
                    ],
                ),
                None => {}
            }
            if let Some(p) = profile {
                v.set(PV::UserProfile, &[p]);
                v.set(PV::AppData, &[&format!("{p}\\AppData\\Roaming")]);
                v.set(PV::LocalAppData, &[&format!("{p}\\AppData\\Local")]);
            }
            if let Some(t) = temp {
                v.set(PV::Temp, &[t]);
            }
            if public.is_some() {
                v.set(PV::Public, &[&format!("{os}:\\Users\\Public")]);
            }
            v
        })
}

/// An unknown policy built for the missing-fact property. Every level is
/// drawn from the full range, entries use the classes and origins the
/// paths below can reach, and the prompt's fallback and
/// `preexisting_policy` are varied. Validation requires a containment
/// profile wherever `restrict` is used, so the profile is always set and
/// whether containment is available is varied instead. A third of the
/// policies prompt on the object type and two thirds of the fallbacks are
/// `block`, so a definite match that undercut a prompt's blocking
/// fallback (both round-six blockers) is reached often; every level stays
/// possible everywhere.
fn arb_fact_policy() -> impl Strategy<Value = UnknownPolicy> {
    let level = || prop::sample::select(Level::ALL.to_vec());
    (
        level(),
        prop::collection::btree_map(
            prop::sample::select(LocationClass::ALL.to_vec()),
            level(),
            0..4,
        ),
        prop::collection::btree_map(
            prop::sample::select(OriginClass::ALL.to_vec()),
            level(),
            0..4,
        ),
        prop::option::of(level()),
        prop::option::of(level()),
        prop::option::of(level()),
        prop_oneof![
            2 => Just(Level::Block),
            1 => prop::sample::select(vec![Level::Restrict, Level::Detect, Level::Allow]),
        ],
        prop::sample::select(vec![
            PreexistingPolicy::BaselineOnly,
            PreexistingPolicy::TreatAsUnknown,
            PreexistingPolicy::LocalApprove,
        ]),
        prop::bool::weighted(0.5),
    )
        .prop_map(
            |(
                default,
                mut by_location,
                mut by_origin,
                executable,
                unknown,
                writable,
                fallback,
                preexisting,
                prompts,
            )| {
                // The origin and class a missing fact must not make definite get
                // entries often, so a relaxation through them is reached.
                if let Some(l) = unknown {
                    by_origin.insert(OriginClass::Unknown, l);
                }
                if let Some(l) = writable {
                    by_location.insert(LocationClass::UserWritableOther, l);
                }
                let mut p = UnknownPolicy {
                    default,
                    by_location,
                    by_origin,
                    preexisting_policy: preexisting,
                    ..UnknownPolicy::default()
                };
                match (prompts, executable) {
                    (true, _) => {
                        p.by_type.insert(ObjectType::Executable, Level::Prompt);
                    }
                    (false, Some(l)) => {
                        p.by_type.insert(ObjectType::Executable, l);
                    }
                    (false, None) => {}
                }
                p.prompt.fallback = fallback;
                p.restrict_profile = PROFILE
                    .parse()
                    .map(crate::model::ContainmentProfileRef)
                    .ok();
                p
            },
        )
}

/// Every variable the classifier reads, as Windows sets them on a device
/// whose OS is on drive `os`.
fn complete_variables(os: &str) -> PathVariables {
    PathVariables::new()
        .with(PV::Windir, &[&format!("{os}:\\Windows")])
        .with(
            PV::ProgramFiles,
            &[
                &format!("{os}:\\Program Files"),
                &format!("{os}:\\Program Files (x86)"),
            ],
        )
        .with(PV::UserProfile, &[&format!("{os}:\\Users\\alice")])
        .with(
            PV::AppData,
            &[&format!("{os}:\\Users\\alice\\AppData\\Roaming")],
        )
        .with(
            PV::LocalAppData,
            &[&format!("{os}:\\Users\\alice\\AppData\\Local")],
        )
        .with(
            PV::Temp,
            &[&format!("{os}:\\Users\\alice\\AppData\\Local\\Temp")],
        )
        .with(PV::Public, &[&format!("{os}:\\Users\\Public")])
}

/// The facts one step of the property can remove.
#[derive(Clone, Copy, Debug)]
enum Drop {
    Volume,
    Origin,
    Acl,
    Path,
    Variable(PV),
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Removing any one volume, ACL, path, variable or origin fact never
    /// makes stage six's applied level less restrictive, for any unknown
    /// policy, path and partial facts (#39, ADR 0018).
    ///
    /// Nothing that could mask a relaxation is left at a default: the
    /// `preexisting_policy` (under `baseline_only` a missing origin always
    /// brings in `block`, which hid the case where it did not), the
    /// containment profile and availability, the session and whether its
    /// user is the system account, a blocklist match, and whether the agent
    /// supplied the location classes itself.
    #[test]
    fn removing_a_fact_never_lowers_the_applied_level(
        p in arb_fact_policy(),
        complete in any::<bool>(),
        os in prop::sample::select(vec!["C", "D"]),
        raw in arb_round5_path(),
        writable in prop::option::of(any::<bool>()),
        volume in prop::option::of(prop::sample::select(vec![VolumeKind::Fixed, VolumeKind::Removable, VolumeKind::Optical, VolumeKind::Network])),
        variables in arb_round5_variables(),
        origins in prop::option::of(prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3)),
        supplied in prop::option::of(prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 1..3)),
        t in prop_oneof![Just(ObjectType::Executable), prop::sample::select(ObjectType::ALL.to_vec())],
        session in prop::option::of(prop::sample::select(SessionType::ALL.to_vec())),
        system in prop::option::of(any::<bool>()),
        containment in prop::option::of(any::<bool>()),
        blocklisted in any::<bool>(),
    ) {
        // Half the cases start from complete facts. Dropping a fact from an
        // already partial set is weak: each class a missing fact already
        // left `Unknown` brings in `default`, which can mask a relaxation.
        // Agent-supplied classes are complete facts too, so with them set,
        // a path fact has nothing to decide; start without them.
        let supplied = if complete { None } else { supplied };
        let (variables, volume, writable, origins) = if complete {
            (
                complete_variables(os),
                Some(volume.unwrap_or(VolumeKind::Fixed)),
                Some(writable.unwrap_or(false)),
                Some(origins.unwrap_or_default()),
            )
        } else {
            (variables, volume, writable, origins)
        };
        let u = p;
        let rules = if blocklisted {
            // An audit rule of a blocklist matching every object of the
            // type: nothing is prompted for, and no rule decides.
            vec![(SET, "blocklist", false, vec![serde_json::json!({
                "id": rule_id(77), "name": "Watch",
                "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
                "action": {"type": "audit"},
            })])]
        } else {
            vec![]
        };
        let mut d = doc_with(serde_json::json!({}), &rules);
        d.policy.unknown = u;
        // The generator only builds valid policies: a skipped case would
        // hide what it was meant to test.
        let v = d.validate().unwrap_or_else(|e| panic!("{e:#?}"));
        let build = |volume: Option<VolumeKind>, writable: Option<bool>, path: bool, origins: &Option<BTreeSet<OriginClass>>| {
            let mut f = ObjectFacts::new().with(Field::HashSha256, sha('a'));
            if path {
                let mut fact = PathFact::new(&raw, &VolumeMap::new());
                fact.user_writable = writable;
                fact.volume = volume;
                f = f.with_path(fact);
            }
            f.location_class = supplied.clone();
            f.origin = origins.clone();
            f
        };
        // The case's own context, and the contexts that decide whether a
        // prompt or a restriction can apply, each with and without
        // containment.
        let contexts = [
            (session, system),
            (Some(SessionType::Console), Some(false)),
            (Some(SessionType::Service), Some(false)),
        ];
        for (session, system) in contexts {
            for containment in [containment, Some(true), Some(false)] {
                let mut context = EvaluationContext::new();
                context.session.session_type = session;
                context.user.is_system = system;
                context.device.containment_available = containment;
                let level = |f: &ObjectFacts, vars: &PathVariables| {
                    Evaluator::new(&v).unwrap().evaluate(
                        &Subject { object_type: t, facts: f, variables: vars, context: &context }, TRACE,
                    ).unknown().unwrap().applied
                };
                let before = level(&build(volume, writable, true, &origins), &variables);
                // Every fact, one at a time.
                for drop in [
                    Drop::Volume, Drop::Origin, Drop::Acl, Drop::Path,
                    Drop::Variable(PV::Windir), Drop::Variable(PV::ProgramFiles), Drop::Variable(PV::UserProfile),
                    Drop::Variable(PV::AppData), Drop::Variable(PV::LocalAppData), Drop::Variable(PV::Temp), Drop::Variable(PV::Public),
                ] {
                    let after = match drop {
                        Drop::Volume => level(&build(None, writable, true, &origins), &variables),
                        Drop::Origin => level(&build(volume, writable, true, &None), &variables),
                        Drop::Acl => level(&build(volume, None, true, &origins), &variables),
                        Drop::Path => level(&build(volume, writable, false, &origins), &variables),
                        Drop::Variable(var) => level(&build(volume, writable, true, &origins), &without(&variables, var)),
                    };
                    prop_assert!(after >= before, "dropping {drop:?} ({session:?}, containment {containment:?}): {before:?} -> {after:?}");
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// The lemma the missing-fact property rests on, checked directly: a
    /// class is a definite `Match` or `NoMatch` only when the facts that
    /// decide it are present. So removing any one fact leaves every
    /// location class and origin as it was or makes it `Unknown`; it never
    /// makes one a definite `Match` (or `NoMatch`) it was not with the full
    /// facts. Both round-six blockers broke this: a missing origin made
    /// `unknown` a definite match, and a missing ACL fact made
    /// `user_writable_other` one.
    #[test]
    fn removing_a_fact_never_makes_a_class_definite(
        raw in arb_round5_path(),
        writable in prop::option::of(any::<bool>()),
        short_name in prop::bool::weighted(0.1),
        volume in prop::option::of(prop::sample::select(vec![VolumeKind::Fixed, VolumeKind::Removable, VolumeKind::Optical, VolumeKind::Network])),
        variables in arb_round5_variables(),
        origins in prop::option::of(prop::collection::btree_set(prop::sample::select(OriginClass::ALL.to_vec()), 0..3)),
        supplied in prop::option::of(prop::collection::btree_set(prop::sample::select(LocationClass::ALL.to_vec()), 1..3)),
        drop in prop::sample::select(vec![
            Drop::Volume, Drop::Origin, Drop::Acl, Drop::Path,
            Drop::Variable(PV::Windir), Drop::Variable(PV::ProgramFiles), Drop::Variable(PV::UserProfile),
            Drop::Variable(PV::AppData), Drop::Variable(PV::LocalAppData), Drop::Variable(PV::Temp), Drop::Variable(PV::Public),
        ]),
    ) {
        let v = valid(doc(serde_json::json!({})));
        let build = |volume: Option<VolumeKind>, writable: Option<bool>, path: bool, origins: &Option<BTreeSet<OriginClass>>| {
            let mut f = ObjectFacts::new().with(Field::HashSha256, sha('a'));
            if path {
                let mut fact = PathFact::new(&raw, &VolumeMap::new());
                fact.user_writable = writable;
                fact.volume = volume;
                fact.short_name_unresolved = short_name;
                f = f.with_path(fact);
            }
            f.location_class = supplied.clone();
            f.origin = origins.clone();
            f
        };
        let context = interactive_context();
        // Each class's value, read back from the decision.
        let classes = |f: &ObjectFacts, vars: &PathVariables| {
            let d = Evaluator::new(&v).unwrap().evaluate(
                &Subject { object_type: ObjectType::Executable, facts: f, variables: vars, context: &context }, TRACE,
            );
            let u = d.unknown().unwrap().clone();
            let loc = |c: LocationClass| if u.locations.contains(&c) { Tri::Match } else if u.unknown_locations.contains(&c) { Tri::Unknown } else { Tri::NoMatch };
            let ori = |o: OriginClass| if u.origins.contains(&o) { Tri::Match } else if u.unknown_origins.contains(&o) { Tri::Unknown } else { Tri::NoMatch };
            (
                LocationClass::ALL.map(loc).to_vec(),
                OriginClass::ALL.map(ori).to_vec(),
            )
        };
        let full = classes(&build(volume, writable, true, &origins), &variables);
        let partial = match drop {
            Drop::Volume => classes(&build(None, writable, true, &origins), &variables),
            Drop::Origin => classes(&build(volume, writable, true, &None), &variables),
            Drop::Acl => classes(&build(volume, None, true, &origins), &variables),
            Drop::Path => classes(&build(volume, writable, false, &origins), &variables),
            Drop::Variable(var) => classes(&build(volume, writable, true, &origins), &without(&variables, var)),
        };
        for (i, (f, p)) in full.0.iter().zip(&partial.0).enumerate() {
            prop_assert!(p == f || *p == Tri::Unknown,
                "dropping {drop:?}: {:?} went from {f:?} to {p:?}", LocationClass::ALL[i]);
        }
        for (i, (f, p)) in full.1.iter().zip(&partial.1).enumerate() {
            prop_assert!(p == f || *p == Tri::Unknown,
                "dropping {drop:?}: {:?} went from {f:?} to {p:?}", OriginClass::ALL[i]);
        }
    }
}

/// F1: the policy simulator re-validates candidate documents. A candidate
/// built from a policy with the engine's baseline validates without it and
/// gets the current policy's baseline back; a draft's own baseline-shaped
/// set is dropped, never trusted.
#[test]
fn simulator_candidates_keep_the_engines_baseline() {
    use crate::trace::simulate::Candidate;
    let facts = SystemBaseline {
        publishers: vec![OS_PUBLISHER.into()],
        writable_dirs: vec![],
    };
    let current = valid(doc(serde_json::json!({})))
        .with_system_baseline(&facts)
        .unwrap();
    let resolved = Candidate::Mode(Mode::Audit).resolve(&current).unwrap();
    assert_eq!(resolved.document().policy.mode, Mode::Audit);
    assert_eq!(resolved.document().rule_sets, current.document().rule_sets);
    // A draft carrying a forged baseline.
    let mut draft = current.document().clone();
    draft.rule_sets[0] = system_baseline(
        &SystemBaseline {
            publishers: vec!["Any Vendor Ltd".into()],
            writable_dirs: vec![],
        },
        draft.policy.precedence_model,
        draft.policy.precedence_options.priority_direction,
    )
    .unwrap();
    let resolved = Candidate::Document(Box::new(draft))
        .resolve(&current)
        .unwrap();
    assert_eq!(resolved.document().rule_sets, current.document().rule_sets);
}

/// evaluate.rs:488: only a denying rule (or a blocklist's own `audit`
/// entry) makes an object blocklisted. The `audit` twin of an expired
/// deny does not turn a prompt into the block fallback.
#[test]
fn an_expired_deny_does_not_make_an_object_blocklisted() {
    let deny = serde_json::json!({
        "id": rule_id(1), "name": "D",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}},
        "action": {"type": "deny", "unknown_as": "no_match"},
        "expires_at": "2026-01-01T00:00:00Z", "on_expire": "convert_to_audit",
    });
    let v = valid(doc_with(
        serde_json::json!({"default": "prompt", "prompt": {"fallback": "block"}}),
        &[(SET, "blocklist", false, vec![deny])],
    ));
    let e = Evaluator::new(&v)
        .unwrap()
        .at(crate::lifecycle::RuleClock::at(crate::model::Timestamp(
            1_795_564_800,
        )));
    let facts = object(&[LocationClass::Temp], &[]).with(crate::model::Field::HashSha256, sha('a'));
    let variables = PathVariables::new();
    let context = interactive_context();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &variables,
        context: &context,
    };
    let d = e
        .evaluate_in(&subject, &DeviceState::of(&v.document().policy), TRACE)
        .unwrap();
    assert_eq!(d.annotations().len(), 1);
    assert_eq!(d.outcome(), Outcome::PendingUser, "{d:#?}");
}
