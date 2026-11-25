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
    // No path at all.
    let d = decide(&v, ObjectType::Executable, &ObjectFacts::new());
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(
        d.unknown().unwrap().locations,
        vec![LocationClass::UserWritableOther]
    );
    // A path with unknown ACL facts is user-writable.
    let facts = ObjectFacts::new().with_path(PathFact::new("D:\\data\\a.exe", &VolumeMap::new()));
    let d = decide(&v, ObjectType::Executable, &facts);
    assert_eq!(d.outcome(), Outcome::Blocked);
    // A safe path elsewhere on a fixed disk.
    let facts = ObjectFacts::new()
        .with_path(PathFact::new("D:\\data\\a.exe", &VolumeMap::new()).with_user_writable(false));
    let d = decide(&v, ObjectType::Executable, &facts);
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
    let facts = ObjectFacts::new().with_location_class([LocationClass::Temp]);
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
    assert_eq!(
        codes(doc(preset_json(CompliancePreset::E8Ml3))),
        vec![(
            ErrorCode::MandatoryBlocklistRequired,
            "/policy/rule_sets".to_owned()
        )]
    );
    assert_eq!(
        codes(doc_with(
            preset_json(CompliancePreset::E8Ml3),
            &[mandatory_set()]
        )),
        vec![]
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
}

fn classes(
    raw: &str,
    writable: Option<bool>,
    volume: Option<VolumeKind>,
) -> BTreeSet<LocationClass> {
    let mut p = PathFact::new(raw, &VolumeMap::new());
    p.user_writable = writable;
    classify(&p, &vars(), volume, &[])
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
        (
            "D:\\Tools\\a.exe",
            None,
            None,
            vec![L::UserWritableOther, L::OtherFixed],
        ),
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
            "relative\\a.exe",
            Some(false),
            None,
            vec![L::UserWritableOther],
        ),
    ];
    for (raw, writable, volume, want) in cases {
        assert_eq!(classes(raw, writable, volume), level_set(&want), "{raw}");
    }
}

#[test]
fn a_mapped_drive_is_a_network_location() {
    let mut p = PathFact::new("Z:\\a.exe", &VolumeMap::new()).with_user_writable(false);
    p.alias = Some(palisade_core::path::normalize("\\\\server\\share\\a.exe"));
    assert_eq!(
        classify(&p, &vars(), None, &[]),
        level_set(&[LocationClass::Network])
    );
}

#[test]
fn scanner_flagged_directories_are_user_writable() {
    let p = PathFact::new("C:\\Windows\\Tasks\\a.exe", &VolumeMap::new()).with_user_writable(false);
    let flagged = [palisade_core::path::normalize("C:\\Windows\\Tasks")];
    assert_eq!(
        classify(&p, &vars(), None, &flagged),
        level_set(&[LocationClass::UserWritableOther, LocationClass::Windows])
    );
    // A sibling with a common prefix is not.
    let p =
        PathFact::new("C:\\Windows\\TasksX\\a.exe", &VolumeMap::new()).with_user_writable(false);
    assert_eq!(
        classify(&p, &vars(), None, &flagged),
        level_set(&[LocationClass::Windows])
    );
}

#[test]
fn agent_temp_directories_add_the_temp_class() {
    let p = PathFact::new("D:\\MailCache\\a.exe", &VolumeMap::new()).with_user_writable(true);
    let temp = [palisade_core::path::normalize("D:\\MailCache")];
    let got = location::classify_with(
        &p,
        &vars(),
        &location::Hints {
            volume: None,
            writable_dirs: &[],
            temp_dirs: &temp,
        },
    );
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
        }])
        .with_path(PathFact::new(path, &VolumeMap::new()).with_user_writable(writable))
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
    let d = doc_with(unknown, extra)
        .with_system_baseline(&facts)
        .unwrap();
    valid(d)
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
        let d = d
            .with_system_baseline(&SystemBaseline {
                publishers: vec![OS_PUBLISHER.into()],
                writable_dirs: vec![],
            })
            .unwrap();
        let v = d.validate().unwrap_or_else(|e| panic!("{model}: {e:#?}"));
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
    let d = doc(serde_json::json!({}))
        .with_system_baseline(&facts)
        .unwrap()
        .with_system_baseline(&facts)
        .unwrap();
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
    let d = doc(serde_json::json!({}))
        .with_system_baseline(&most)
        .unwrap();
    d.validate().unwrap();
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
        }])
        .with_path(
            PathFact::new("C:\\Program Files\\Palisade\\agent.exe", &VolumeMap::new())
                .with_user_writable(false),
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
            .with_user_writable(false),
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
            let d = d
                .with_system_baseline(&SystemBaseline {
                    publishers: vec![OS_PUBLISHER.into()],
                    writable_dirs: vec![],
                })
                .unwrap();
            let v = d.validate().unwrap_or_else(|e| panic!("{model}: {e:#?}"));
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
    doc(serde_json::json!({}))
        .with_system_baseline(&facts)
        .unwrap()
        .validate()
        .unwrap();
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
    let mut p =
        PathFact::new("Z:\\Program Files\\a.exe", &VolumeMap::new()).with_user_writable(false);
    p.alias = Some(palisade_core::path::normalize(
        "\\\\server\\share\\Program Files\\a.exe",
    ));
    let no_vars = PathVariables::new();
    let got = classify(&p, &no_vars, None, &[]);
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
    // Without them, the drive-letter fallback applies on a local disk.
    let p = PathFact::new("D:\\Windows\\a.exe", &VolumeMap::new()).with_user_writable(false);
    assert_eq!(classify(&p, &no_vars, None, &[]), level_set(&[L::Windows]));
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
    let got = classify(&p, &vars(), None, &[]);
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
    rules[0]["enabled"] = false.into();
    let found = codes(doc_with(
        preset_json(CompliancePreset::E8Ml3),
        &[(id, kind, m, rules)],
    ));
    assert_eq!(
        found,
        vec![(
            ErrorCode::MandatoryBlocklistRequired,
            "/policy/rule_sets".to_owned()
        )]
    );
    let found = codes(doc_with(
        preset_json(CompliancePreset::E8Ml3),
        &[(id, kind, m, vec![])],
    ));
    assert_eq!(
        found,
        vec![(
            ErrorCode::MandatoryBlocklistRequired,
            "/policy/rule_sets".to_owned()
        )]
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
