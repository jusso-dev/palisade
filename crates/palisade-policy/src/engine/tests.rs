//! Tests of the engine (#42): the cache never returns a stale decision,
//! uncacheable decisions are never cached, the watchdog falls back, and
//! a snapshot swap is atomic under concurrent decisions.

use std::cell::Cell;
use std::sync::Arc;

use palisade_core::path::VolumeMap;

use super::*;
use crate::context::EvaluationContext;
use crate::decision::{Outcome as Verdict, ReasonCode};
use crate::facts::{ObjectFacts, PathFact, PathVariables};
use crate::facts::{SignatureSource, SignerFact, SignerStatus};
use crate::mode::SessionKind;
use crate::model::{Field, ObjectType, PolicyDocument};

const TRACE: TraceId = TraceId([9; 16]);

/// A test clock, in microseconds, that moves forward by `step` on every
/// reading.
struct TestClock {
    now: Cell<u64>,
    step: u64,
    trusted: bool,
}

impl TestClock {
    fn at(secs: u64) -> Self {
        Self {
            now: Cell::new(secs * 1_000_000),
            step: 0,
            trusted: true,
        }
    }
}

impl Clock for TestClock {
    fn monotonic_micros(&self) -> u64 {
        let t = self.now.get();
        self.now.set(t + self.step);
        t
    }

    fn trusted(&self) -> bool {
        self.trusted
    }
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn rule(n: u32, tree: serde_json::Value, action: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"),
        "name": format!("Rule {n}"),
        "object_types": ["executable"],
        "match": tree,
        "action": action,
    })
}

fn crit(field: &str, operator: &str, value: &str) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": [value]}})
}

fn policy(rules: Vec<serde_json::Value>, ttl: u32, revision: u64) -> ValidatedPolicy {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Engine",
            "revision": revision,
            "mode": "enforce",
            "settings": {"decision_cache_ttl_secs": ttl},
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001"],
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
            "name": "Rules",
            "kind": "mixed",
            "rules": rules,
        }],
    });
    PolicyDocument::from_json(&json.to_string())
        .unwrap()
        .validate()
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn allow_a() -> ValidatedPolicy {
    policy(
        vec![rule(
            1,
            crit("hash.sha256", "equals", &sha('a')),
            serde_json::json!({"type": "allow"}),
        )],
        300,
        1,
    )
}

fn facts(c: char) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha(c))
        .with_path(
            PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        )
}

const FILE: FileIdentity = FileIdentity::File {
    volume_serial: 7,
    file_id: 42,
    change_stamp: 1,
    size: 100,
};

struct Call<'a> {
    facts: &'a ObjectFacts,
    context: &'a EvaluationContext,
    variables: &'a PathVariables,
    state: &'a DeviceState,
    file: Option<FileIdentity>,
    session: Option<u32>,
    expires_before: Option<u64>,
}

impl Call<'_> {
    fn request(&self) -> Request<'_> {
        Request {
            subject: Subject {
                object_type: ObjectType::Executable,
                facts: self.facts,
                variables: self.variables,
                context: self.context,
            },
            computed: FactSet::ALL,
            state: self.state,
            trace_id: TRACE,
            file: self.file,
            session: self.session,
            expires_before: self.expires_before,
        }
    }
}

/// The decision and whether it was a hit (the hit counter moved).
fn decide(engine: &Engine, call: &Call<'_>, clock: &dyn Clock) -> (Decision, bool) {
    let before = engine.cache_stats().hits;
    match engine.evaluate(&call.request(), clock) {
        Outcome::Decided(Some(d)) => ((*d).clone(), engine.cache_stats().hits > before),
        other => panic!("{other:?}"),
    }
}

fn setup() -> (ObjectFacts, EvaluationContext, PathVariables, DeviceState) {
    let p = allow_a();
    let state = DeviceState::of(&p.document().policy);
    (
        facts('a'),
        EvaluationContext::new(),
        PathVariables::new(),
        state,
    )
}

#[test]
fn a_repeat_is_a_hit_with_the_same_decision() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    let clock = TestClock::at(10);
    let (first, hit) = decide(&engine, &call, &clock);
    assert!(!hit);
    assert_eq!(first.outcome(), Verdict::Allowed);
    let (second, hit) = decide(&engine, &call, &clock);
    assert!(hit);
    assert_eq!(second, first);
    let stats = engine.cache_stats();
    assert_eq!(
        (stats.hits, stats.misses, stats.inserts, stats.entries),
        (1, 1, 1, 1)
    );
    assert!((stats.hit_ratio() - 0.5).abs() < f64::EPSILON);
}

#[test]
fn a_policy_swap_never_returns_the_old_decision() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    let clock = TestClock::at(10);
    assert_eq!(decide(&engine, &call, &clock).0.outcome(), Verdict::Allowed);
    // The new policy denies the same hash.
    let deny = policy(
        vec![rule(
            2,
            crit("hash.sha256", "equals", &sha('a')),
            serde_json::json!({"type": "deny"}),
        )],
        300,
        2,
    );
    engine.load(deny).unwrap();
    assert_eq!(engine.cache_stats().entries, 0, "purged");
    let (d, hit) = decide(&engine, &call, &clock);
    assert!(!hit);
    assert_eq!(d.outcome(), Verdict::Blocked);
    assert_eq!(d.matched_rule().map(|r| r.policy_revision), Some(2));
}

#[test]
fn a_file_change_is_never_served_from_the_cache() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let clock = TestClock::at(10);
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    decide(&engine, &call, &clock);
    // A write changes the stamp: a new key, so a miss even before the
    // notification.
    let written = FileIdentity::File {
        volume_serial: 7,
        file_id: 42,
        change_stamp: 2,
        size: 100,
    };
    let other = facts('b');
    let call2 = Call {
        facts: &other,
        file: Some(written),
        ..call
    };
    let (d, hit) = decide(&engine, &call2, &clock);
    assert!(!hit);
    assert_eq!(d.outcome(), Verdict::Blocked);
    // The notification removes every entry of the file.
    engine.invalidate_file(7, 42);
    assert_eq!(engine.cache_stats().entries, 0);
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    assert!(!decide(&engine, &call, &clock).1);
}

#[test]
fn logoff_forgets_the_session() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let clock = TestClock::at(10);
    let in_1 = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: Some(1),
        expires_before: None,
    };
    let other_file = FileIdentity::Sha256([1; 32]);
    let in_2 = Call {
        file: Some(other_file),
        session: Some(2),
        ..in_1
    };
    decide(&engine, &in_1, &clock);
    decide(&engine, &in_2, &clock);
    engine.invalidate_session(1);
    let in_1 = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: Some(1),
        expires_before: None,
    };
    assert!(!decide(&engine, &in_1, &clock).1);
    let in_2 = Call {
        file: Some(other_file),
        session: Some(2),
        ..in_1
    };
    assert!(decide(&engine, &in_2, &clock).1);
}

#[test]
fn entries_expire_at_the_ttl_and_at_a_schedule_boundary() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    decide(&engine, &call, &TestClock::at(1000));
    assert!(decide(&engine, &call, &TestClock::at(1299)).1);
    assert!(
        !decide(&engine, &call, &TestClock::at(1300)).1,
        "TTL of 300 s"
    );
    // A boundary in 60 s cuts the entry short.
    engine.purge_cache();
    let bounded = Call {
        expires_before: Some(2060 * 1_000_000),
        ..call
    };
    decide(&engine, &bounded, &TestClock::at(2000));
    assert!(decide(&engine, &bounded, &TestClock::at(2059)).1);
    assert!(
        !decide(&engine, &bounded, &TestClock::at(2060)).1,
        "schedule boundary"
    );
}

#[test]
fn a_ttl_of_zero_and_an_untrusted_clock_disable_the_cache() {
    let p = policy(
        vec![rule(
            1,
            crit("hash.sha256", "equals", &sha('a')),
            serde_json::json!({"type": "allow"}),
        )],
        0,
        1,
    );
    let engine = Engine::new(p, EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    decide(&engine, &call, &TestClock::at(1));
    assert!(!decide(&engine, &call, &TestClock::at(1)).1);
    assert_eq!(engine.cache_stats().inserts, 0);

    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let untrusted = TestClock {
        trusted: false,
        ..TestClock::at(1)
    };
    decide(&engine, &call, &untrusted);
    decide(&engine, &call, &untrusted);
    assert_eq!(engine.cache_stats().inserts, 0);
}

#[test]
fn uncacheable_decisions_are_never_cached() {
    let (f, c, v, _) = setup();
    let clock = TestClock::at(1);
    let check = |p: ValidatedPolicy, facts: &ObjectFacts, state: DeviceState, why: &str| {
        let engine = Engine::new(p, EngineConfig::default()).unwrap();
        let call = Call {
            facts,
            context: &c,
            variables: &v,
            state: &state,
            file: Some(FILE),
            session: None,
            expires_before: None,
        };
        decide(&engine, &call, &clock);
        decide(&engine, &call, &clock);
        assert_eq!(engine.cache_stats().inserts, 0, "{why}");
    };
    // An approval request: a prompt.
    let request = policy(
        vec![
            rule(
                1,
                crit("hash.sha256", "equals", &sha('a')),
                serde_json::json!({"type": "deny", "allow_request": true}),
            )
            .as_object()
            .cloned()
            .map(|mut r| {
                r.insert("effects".into(), serde_json::json!({"notify": "default"}));
                serde_json::Value::Object(r)
            })
            .unwrap(),
        ],
        300,
        1,
    );
    let state = DeviceState::of(&request.document().policy);
    check(request, &f, state, "approval prompt");
    // An elevation with a reason prompt.
    let elevate = policy(
        vec![rule(
            1,
            crit("hash.sha256", "equals", &sha('a')),
            serde_json::json!({"type": "allow_elevated", "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d9999", "condition": "always", "reason_prompt": "Why?"}),
        )],
        300,
        1,
    );
    let state = DeviceState::of(&elevate.document().policy);
    check(elevate, &f, state, "reason prompt");
    // An unknown fact: the version is not a version.
    let version = policy(
        vec![rule(
            1,
            serde_json::json!({"all": [
                crit("hash.sha256", "equals", &sha('a')),
                crit("meta.file_version", "version_ge", "1.0"),
            ]}),
            serde_json::json!({"type": "allow"}),
        )],
        300,
        1,
    );
    let state = DeviceState::of(&version.document().policy);
    let bad = facts('a').with(Field::MetaFileVersion, "garbage");
    check(version, &bad, state, "unknown fact");
    // An override session.
    let mut state = DeviceState::of(&allow_a().document().policy);
    state.session = Some(SessionKind::Audit);
    check(allow_a(), &f, state, "override session");
    // Learning mode.
    let mut state = DeviceState::of(&allow_a().document().policy);
    state.mode = Mode::Learning;
    check(allow_a(), &facts('z'), state, "learning");
}

#[test]
fn the_key_covers_principals_context_state_and_path() {
    let p = policy(
        vec![rule(
            1,
            serde_json::json!({"all": [
                crit("hash.sha256", "equals", &sha('a')),
                {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-544"]}},
            ]}),
            serde_json::json!({"type": "allow"}),
        )],
        300,
        1,
    );
    let engine = Engine::new(p, EngineConfig::default()).unwrap();
    let (f, _, v, s) = setup();
    let clock = TestClock::at(1);
    let mut admin = EvaluationContext::new();
    admin.user.groups = Some(vec!["S-1-5-32-544".into(), "S-1-5-11".into()]);
    let mut other_admin = admin.clone();
    // Another user in the same group, with other unrelated groups.
    other_admin.user.groups = Some(vec!["s-1-5-32-544".into(), "S-1-5-4".into()]);
    other_admin.user.sid = Some("S-1-5-21-9".into());
    let mut user = EvaluationContext::new();
    user.user.groups = Some(vec!["S-1-5-11".into()]);
    let call = |c| Call {
        facts: &f,
        context: c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    assert_eq!(
        decide(&engine, &call(&admin), &clock).0.outcome(),
        Verdict::Allowed
    );
    // Same principals the policy names: shared.
    assert!(decide(&engine, &call(&other_admin), &clock).1);
    // Not in the group: not shared.
    let (d, hit) = decide(&engine, &call(&user), &clock);
    assert!(!hit);
    assert_eq!(d.outcome(), Verdict::Blocked);
    // Another device state: not shared.
    let mut lockdown = s;
    lockdown.lockdown = true;
    let locked = Call {
        state: &lockdown,
        ..call(&admin)
    };
    assert!(!decide(&engine, &locked, &clock).1);
    // Another path for the same file (a hard link): not shared.
    let other_path = f
        .clone()
        .with_path(PathFact::new(r"C:\Users\x\a.exe", &VolumeMap::new()));
    let linked = Call {
        facts: &other_path,
        ..call(&admin)
    };
    assert!(!decide(&engine, &linked, &clock).1);
}

#[test]
fn the_key_covers_the_numeric_network_and_time_facts() {
    // A rule on the client address (#33): two contexts that differ only
    // there must not share a cache entry.
    let p = policy(
        vec![rule(
            1,
            serde_json::json!({"all": [
                crit("hash.sha256", "equals", &sha('a')),
                crit("session.client_ip", "ip_in_cidr", "10.0.0.0/8"),
            ]}),
            serde_json::json!({"type": "allow"}),
        )],
        300,
        1,
    );
    let engine = Engine::new(p, EngineConfig::default()).unwrap();
    let (f, _, v, s) = setup();
    let clock = TestClock::at(1);
    let mut inside = EvaluationContext::new();
    inside.session.client_ip = Some("10.1.2.3".parse().unwrap());
    let mut outside = inside.clone();
    outside.session.client_ip = Some("192.168.1.1".parse().unwrap());
    let call = |c| Call {
        facts: &f,
        context: c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    assert_eq!(
        decide(&engine, &call(&inside), &clock).0.outcome(),
        Verdict::Allowed
    );
    let (d, hit) = decide(&engine, &call(&outside), &clock);
    assert!(!hit);
    assert_eq!(d.outcome(), Verdict::Blocked);
}

#[test]
fn scoped_and_unknown_policy_decisions_are_never_cached() {
    // A scope (#38) reads facts the key does not hold, such as the token
    // and the trusted time.
    let scoped = policy(
        vec![{
            let mut r = rule(
                1,
                crit("hash.sha256", "equals", &sha('a')),
                serde_json::json!({"type": "allow"}),
            );
            r["scope"] = serde_json::json!({"sessions": {"types": ["console"]}});
            r
        }],
        300,
        1,
    );
    let engine = Engine::new(scoped, EngineConfig::default()).unwrap();
    let (f, c, v, s) = setup();
    let clock = TestClock::at(1);
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    decide(&engine, &call, &clock);
    assert!(!decide(&engine, &call, &clock).1);
    // Stage 6 (#39) reads the object's origin and location class.
    let engine = Engine::new(policy(vec![], 300, 1), EngineConfig::default()).unwrap();
    let (d, _) = decide(&engine, &call, &clock);
    assert!(d.unhandled());
    assert!(!decide(&engine, &call, &clock).1);
}

#[test]
fn the_cache_stays_within_its_size() {
    let config = EngineConfig {
        cache: CacheConfig {
            max_bytes: 64 * 1024,
            shards: 4,
        },
        ..EngineConfig::default()
    };
    let engine = Engine::new(allow_a(), config).unwrap();
    let (f, c, v, s) = setup();
    let clock = TestClock::at(1);
    for id in 0..10_000u128 {
        let file = FileIdentity::File {
            volume_serial: 1,
            file_id: id,
            change_stamp: 0,
            size: 1,
        };
        let call = Call {
            facts: &f,
            context: &c,
            variables: &v,
            state: &s,
            file: Some(file),
            session: None,
            expires_before: None,
        };
        decide(&engine, &call, &clock);
    }
    let stats = engine.cache_stats();
    assert!(stats.bytes <= 64 * 1024, "{stats:?}");
    assert!(stats.evictions > 9_000, "{stats:?}");
    assert!(stats.entries > 0);
    // The most recent entry survives.
    let file = FileIdentity::File {
        volume_serial: 1,
        file_id: 9_999,
        change_stamp: 0,
        size: 1,
    };
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(file),
        session: None,
        expires_before: None,
    };
    assert!(decide(&engine, &call, &clock).1);
}

#[test]
fn the_watchdog_falls_back_and_names_the_slow_rule() {
    let (f, c, v, s) = setup();
    // Every reading advances 10 ms; the budget is 15 ms, so the second
    // tree is not evaluated.
    let rules = (1..=3)
        .map(|n| {
            rule(
                n,
                crit("path.directory", "starts_with", r"C:\Tools"),
                serde_json::json!({"type": "audit"}),
            )
        })
        .collect();
    let p = policy(rules, 300, 1);
    for (mode, on_timeout, want) in [
        (Mode::Enforce, None, Verdict::Blocked),
        (Mode::Audit, None, Verdict::AllowedAudit),
        (
            Mode::Enforce,
            Some(TimeoutAction::AllowAudit),
            Verdict::AllowedAudit,
        ),
        (Mode::Audit, Some(TimeoutAction::Block), Verdict::Blocked),
    ] {
        let engine = Engine::new(
            p.clone(),
            EngineConfig {
                budget_micros: 15_000,
                on_timeout,
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let state = DeviceState { mode, ..s };
        let call = Call {
            facts: &f,
            context: &c,
            variables: &v,
            state: &state,
            file: Some(FILE),
            session: None,
            expires_before: None,
        };
        let clock = TestClock {
            step: 10_000,
            ..TestClock::at(1)
        };
        match engine.evaluate(&call.request(), &clock) {
            Outcome::TimedOut { decision, event } => {
                assert_eq!(decision.outcome(), want, "{mode:?} {on_timeout:?}");
                assert_eq!(decision.would_have_been(), Verdict::Blocked);
                assert_eq!(decision.reason_code(), ReasonCode::EvalTimeout);
                assert!(event.elapsed_micros > 15_000);
                assert_eq!(
                    event.slow_rule.rule_id.to_string(),
                    "01936b2e-0002-7b3d-9f21-0a1b2c3d4e61"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(engine.cache_stats().inserts, 0, "a timeout is never cached");
    }
    assert_eq!(EVAL_TIMEOUT_EVENT, "policy.eval_timeout");
}

#[test]
fn need_facts_comes_through_the_engine() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (_, c, v, s) = setup();
    let f = ObjectFacts::new().with_path(PathFact::new(r"C:\a.exe", &VolumeMap::new()));
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: None,
        session: None,
        expires_before: None,
    };
    let mut request = call.request();
    request.computed = FactSet::EMPTY;
    assert_eq!(
        engine.evaluate(&request, &TestClock::at(1)),
        Outcome::NeedFacts(NeedFacts(FactSet::hash(Field::HashSha256)))
    );
}

#[test]
fn a_disabled_device_decides_nothing() {
    let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
    let (f, c, v, mut s) = setup();
    s.mode = Mode::Disabled;
    let call = Call {
        facts: &f,
        context: &c,
        variables: &v,
        state: &s,
        file: Some(FILE),
        session: None,
        expires_before: None,
    };
    assert_eq!(
        engine.evaluate(&call.request(), &TestClock::at(1)),
        Outcome::Decided(None)
    );
}

#[test]
fn profiles_tune_but_never_change_decisions() {
    let (f, c, v, s) = setup();
    let mut seen = Vec::new();
    for profile in [
        PerfProfile::Workstation,
        PerfProfile::Server,
        PerfProfile::MultiSession,
    ] {
        let config = EngineConfig::for_profile(profile);
        assert_eq!(config.cache, profile.cache());
        let engine = Engine::new(allow_a(), config).unwrap();
        let call = Call {
            facts: &f,
            context: &c,
            variables: &v,
            state: &s,
            file: Some(FILE),
            session: None,
            expires_before: None,
        };
        seen.push(decide(&engine, &call, &TestClock::at(1)).0);
    }
    assert!(seen.windows(2).all(|w| w[0] == w[1]));
    let required = Engine::new(allow_a(), EngineConfig::default())
        .unwrap()
        .snapshot()
        .evaluator()
        .required_facts();
    assert!(PerfProfile::Workstation.hash_eagerly(required));
    assert!(!PerfProfile::Server.hash_eagerly(required));
}

#[test]
fn the_engine_is_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<Engine>();
    check::<Snapshot>();
    check::<Arc<Snapshot>>();
}

/// A decision in flight finishes on the snapshot it started with, and
/// concurrent decisions during many swaps only ever see one whole policy.
#[test]
fn swaps_are_atomic_under_concurrent_decisions() {
    let allow = allow_a();
    let deny = policy(
        vec![rule(
            2,
            crit("hash.sha256", "equals", &sha('a')),
            serde_json::json!({"type": "deny"}),
        )],
        300,
        2,
    );
    // No watchdog: a thread the scheduler pauses must not time out.
    let engine = Arc::new(
        Engine::new(
            allow.clone(),
            EngineConfig {
                budget_micros: u64::MAX,
                ..EngineConfig::default()
            },
        )
        .unwrap(),
    );
    // A held snapshot outlives a swap.
    let held = engine.snapshot();
    engine.load(deny.clone()).unwrap();
    assert_eq!(held.policy().document().policy.revision, 1);
    assert_eq!(engine.snapshot().policy().document().policy.revision, 2);
    drop(held);

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let workers: Vec<_> = (0..8)
        .map(|t| {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let (f, c, v, s) = setup();
                let clock = SystemClock::new();
                let mut n = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let file = FileIdentity::File {
                        volume_serial: t,
                        file_id: u128::from(n % 64),
                        change_stamp: 0,
                        size: 1,
                    };
                    let call = Call {
                        facts: &f,
                        context: &c,
                        variables: &v,
                        state: &s,
                        file: Some(file),
                        session: None,
                        expires_before: None,
                    };
                    let Outcome::Decided(Some(d)) = engine.evaluate(&call.request(), &clock) else {
                        panic!("undecided");
                    };
                    // Revision 1 allows and revision 2 denies: a decision
                    // is always one whole policy's.
                    match d.matched_rule().map(|r| r.policy_revision) {
                        Some(1) => assert_eq!(d.outcome(), Verdict::Allowed),
                        Some(2) => assert_eq!(d.outcome(), Verdict::Blocked),
                        other => panic!("{other:?}"),
                    }
                    n += 1;
                    if n <= 100 {
                        done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                n
            })
        })
        .collect();
    // Swap until every worker has decided many times, so decisions and
    // swaps really overlap, however the threads are scheduled.
    let mut i = 0u64;
    while done.load(std::sync::atomic::Ordering::Relaxed) < 8 * 100 || i < 200 {
        engine
            .load(if i.is_multiple_of(2) {
                allow.clone()
            } else {
                deny.clone()
            })
            .unwrap();
        i += 1;
        std::thread::yield_now();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let total: u64 = workers.into_iter().map(|w| w.join().unwrap()).sum();
    assert!(total >= 800);
}

mod properties {
    use proptest::prelude::*;

    use super::*;
    use crate::evaluate::index_tests::{
        pool_document, pool_facts, restrict, state, subject, type_of, variables,
    };
    use crate::facts::PathVariable;

    /// One change to a request: the second request of a pair is the first
    /// with this applied.
    #[derive(Clone, Debug)]
    enum Change {
        None,
        Context(Box<crate::context::EvaluationContext>),
        Path(Option<PathFact>),
        State(DeviceState),
        Variables,
        /// The first evaluation lacked some content facts (a transient
        /// failure to hash, read the signatures or the version resource),
        /// which the second has, for the same file. A decision cached then
        /// must not hide them. The classes are those the first one kept.
        Content(FactSet),
    }

    fn change() -> impl Strategy<Value = Change> {
        prop_oneof![
            1 => Just(Change::None),
            3 => pool_facts().prop_map(|p| Change::Context(Box::new(p.context))),
            3 => pool_facts().prop_map(|p| Change::Path(p.facts.path)),
            2 => state().prop_map(Change::State),
            1 => Just(Change::Variables),
            3 => proptest::sample::subsequence(FactSet::ALL.classes().collect::<Vec<_>>(), 0..8)
                .prop_map(|kept| Change::Content(kept.into_iter().fold(FactSet::CHEAP, FactSet::union))),
        ]
    }

    /// A state that caches: enforce or audit, no session.
    fn plain_state() -> impl Strategy<Value = DeviceState> {
        state().prop_map(|mut s| {
            s.session = None;
            if s.mode == Mode::Learning {
                s.mode = Mode::Enforce;
            }
            s
        })
    }

    /// Whatever the policy, a decision from the cache is the decision
    /// a fresh evaluation gives. The second request is about the same
    /// file (same identity, same content facts) with one change to
    /// what is not content: the context, the path, the device state or
    /// the path variables. The key must tell them apart whenever the
    /// policy reads the change.
    ///
    /// Generating a random pool policy recurses deeply in debug builds:
    /// with the scope, unknown-application and lifecycle model of #38, #39
    /// and #40 it needs about 2 MiB, which is the size of a test thread on
    /// some runners and more than others give. The test therefore runs its
    /// cases on a thread with an 8 MiB stack. This is test data generation
    /// only; the engine itself never recurses deeper than the validated
    /// tree depth limit.
    #[test]
    fn a_hit_is_always_the_fresh_decision() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let mut runner =
                    proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(2048));
                let strategy = (
                    pool_document(),
                    pool_facts(),
                    any::<prop::sample::Index>(),
                    plain_state(),
                    change(),
                );
                runner
                    .run(&strategy, |(policy, first, pick, s1, change)| {
                        let t = type_of(&policy, pick);
                        let engine = Engine::new(policy.clone(), EngineConfig::default()).unwrap();
                        let fresh = crate::evaluate::Evaluator::new(&policy).unwrap();
                        let v1 = variables();
                        let v2 =
                            PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Tools"]);
                        let mut first = first;
                        let mut second = first.clone();
                        let mut s2 = s1;
                        let mut v = &v1;
                        match &change {
                            Change::None => {}
                            Change::Context(c) => second.context = (**c).clone(),
                            Change::Path(p) => second.facts.path.clone_from(p),
                            Change::State(s) => s2 = *s,
                            Change::Variables => v = &v2,
                            Change::Content(kept) => first = restrict(&first, *kept),
                        }
                        let clock = TestClock::at(1);
                        let mut hits = 0;
                        for (pool, state, vars) in [(&first, &s1, &v1), (&second, &s2, v)] {
                            let request = Request {
                                subject: subject(t, pool, vars),
                                computed: FactSet::ALL,
                                state,
                                trace_id: TRACE,
                                file: Some(FILE),
                                session: None,
                                expires_before: None,
                            };
                            let want = fresh.evaluate_in(&request.subject, state, TRACE);
                            let before = engine.cache_stats().hits;
                            match engine.evaluate(&request, &clock) {
                                Outcome::Decided(got) => {
                                    prop_assert_eq!(got.as_deref(), want.as_ref(), "{:?}", change);
                                }
                                other => prop_assert!(false, "{:?}", other),
                            }
                            hits += engine.cache_stats().hits - before;
                        }
                        // A content change can only be served from the cache if the
                        // first decision did not rest on an unknown content fact; the
                        // assertion above already checked that whatever was served is
                        // the fresh decision. With no change and a cacheable first
                        // decision, the second is a hit.
                        if matches!(change, Change::None) && engine.cache_stats().inserts == 1 {
                            prop_assert_eq!(hits, 1);
                        }
                        Ok(())
                    })
                    .unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

/// Regressions found in review (#42).
mod review {
    use super::*;

    /// A policy with a mandatory deny on a hash and an allow on a path, in
    /// that rule set order or the other.
    fn mandatory_and_path(mandatory_first: bool) -> ValidatedPolicy {
        let ordinary = serde_json::json!({
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
            "name": "Rules",
            "kind": "mixed",
            "rules": [rule(1, crit("path.directory", "starts_with", r"C:\Tools"), serde_json::json!({"type": "allow"}))],
        });
        let mandatory = serde_json::json!({
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
            "name": "Mandatory",
            "kind": "blocklist",
            "mandatory": true,
            "rules": [
                rule(2, crit("hash.sha256", "equals", &sha('b')), serde_json::json!({"type": "deny"})),
                rule(3, crit("signer.publisher", "equals", "Bad Ltd"), serde_json::json!({"type": "deny"})),
            ],
        });
        let sets = if mandatory_first {
            vec![mandatory, ordinary]
        } else {
            vec![ordinary, mandatory]
        };
        let ids: Vec<_> = sets.iter().map(|s| s["id"].clone()).collect();
        let json = serde_json::json!({
            "schema_version": "1.0.0",
            "policy": {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
                "name": "Engine",
                "revision": 1,
                "mode": "enforce",
                "settings": {"decision_cache_ttl_secs": 300},
                "rule_sets": ids,
            },
            "rule_sets": sets,
        });
        PolicyDocument::from_json(&json.to_string())
            .unwrap()
            .validate()
            .unwrap_or_else(|e| panic!("{e:#?}"))
    }

    fn call<'a>(
        f: &'a ObjectFacts,
        c: &'a EvaluationContext,
        v: &'a PathVariables,
        s: &'a DeviceState,
    ) -> Call<'a> {
        Call {
            facts: f,
            context: c,
            variables: v,
            state: s,
            file: Some(FILE),
            session: None,
            expires_before: None,
        }
    }

    /// A decision made while an indexed deny's fact is missing or malformed
    /// rests on an unknown fact, so it is not cached: a later launch with
    /// the full facts is decided afresh, and the mandatory deny blocks.
    #[test]
    fn a_missing_or_malformed_anchor_fact_is_never_cached() {
        let p = mandatory_and_path(false);
        let state = DeviceState::of(&p.document().policy);
        let c = EvaluationContext::new();
        let v = PathVariables::new();
        let path = PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed);
        let bad_signer = vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some("Bad Ltd".to_owned()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }];
        let partial: Vec<(&str, ObjectFacts)> = vec![
            // The hash was computed but could not be read.
            (
                "hash missing",
                ObjectFacts::new()
                    .with_path(path.clone())
                    .with_signers(vec![]),
            ),
            // The hash is malformed.
            (
                "hash malformed",
                ObjectFacts::new()
                    .with(Field::HashSha256, "zz")
                    .with_path(path.clone())
                    .with_signers(vec![]),
            ),
            // The signatures were not examined.
            (
                "signers missing",
                ObjectFacts::new()
                    .with(Field::HashSha256, sha('a'))
                    .with_path(path.clone()),
            ),
            // A trusted signer without a publisher.
            (
                "publisher missing",
                ObjectFacts::new()
                    .with(Field::HashSha256, sha('a'))
                    .with_path(path.clone())
                    .with_signers(vec![SignerFact {
                        publisher: None,
                        ..bad_signer[0].clone()
                    }]),
            ),
        ];
        for (why, first) in &partial {
            let engine = Engine::new(p.clone(), EngineConfig::default()).unwrap();
            let one = call(first, &c, &v, &state);
            let mut request = one.request();
            request.computed = FactSet::ALL;
            let Outcome::Decided(Some(d)) = engine.evaluate(&request, &TestClock::at(1)) else {
                panic!("{why}");
            };
            assert_eq!(
                d.outcome(),
                Verdict::Allowed,
                "{why}: the path allow decides"
            );
            assert_eq!(engine.cache_stats().inserts, 0, "{why}: not cached");
            // The same file, now with the facts that the deny blocks.
            let full = ObjectFacts::new()
                .with(Field::HashSha256, sha('b'))
                .with_path(path.clone())
                .with_signers(bad_signer.clone());
            let (d, hit) = decide(&engine, &call(&full, &c, &v, &state), &TestClock::at(2));
            assert!(!hit, "{why}");
            assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny, "{why}");
        }
        // With every anchor fact present and known, it is cached.
        let engine = Engine::new(p, EngineConfig::default()).unwrap();
        let known = ObjectFacts::new()
            .with(Field::HashSha256, sha('a'))
            .with_path(path)
            .with_signers(vec![]);
        decide(&engine, &call(&known, &c, &v, &state), &TestClock::at(1));
        assert_eq!(engine.cache_stats().inserts, 1);
    }

    /// Duplicate group members, in any spelling, never cancel out of the
    /// subject key, however many principals the policy names.
    #[test]
    fn duplicate_members_never_collide_in_the_subject_key() {
        let sids: Vec<String> = (0..300)
            .map(|i| format!("S-1-5-21-1-2-3-{}", 1000 + i))
            .collect();
        let rules: Vec<_> = sids
            .iter()
            .enumerate()
            .map(|(i, sid)| {
                rule(
                    u32::try_from(i).unwrap() + 1,
                    serde_json::json!({"all": [
                        crit("hash.sha256", "equals", &sha('a')),
                        {"criterion": {"field": "user.groups", "operator": "member_of", "values": [sid]}},
                    ]}),
                    serde_json::json!({"type": "allow"}),
                )
            })
            .collect();
        let p = policy(rules, 300, 1);
        let state = DeviceState::of(&p.document().policy);
        let engine = Engine::new(p, EngineConfig::default()).unwrap();
        let snapshot = engine.snapshot();
        let seed = KeySeed::new();
        let key = |groups: Vec<String>| {
            let mut c = EvaluationContext::new();
            c.user.groups = Some(groups);
            snapshot.plan.subject_key(&c, &seed)
        };
        // The last principal (index 299), twice and in two spellings.
        let member = sids[299].clone();
        let lower = member.to_lowercase().replace("-1000", "-01000");
        assert_ne!(key(vec![member.clone(), lower.clone()]), key(vec![]));
        assert_ne!(key(vec![member.clone(), member.clone()]), key(vec![]));
        assert_eq!(key(vec![member.clone(), lower]), key(vec![member.clone()]));
        // And end to end: a non-member never gets the member's decision.
        let f = facts('a');
        let v = PathVariables::new();
        let mut inside = EvaluationContext::new();
        inside.user.groups = Some(vec![member.clone(), member]);
        let outside = EvaluationContext::new();
        let (d, _) = decide(&engine, &call(&f, &inside, &v, &state), &TestClock::at(1));
        assert_eq!(d.outcome(), Verdict::Allowed);
        let (d, hit) = decide(&engine, &call(&f, &outside, &v, &state), &TestClock::at(1));
        assert!(!hit);
        assert_eq!(d.outcome(), Verdict::Blocked);
    }

    /// The cache bounds the real memory of its entries, as the allocator
    /// counts it, not only its own estimate.
    #[test]
    fn the_cache_counts_whole_decisions() {
        let one = Decision::implicit_deny(TRACE);
        assert!(cache::decision_bytes(&one) >= core::mem::size_of::<Decision>());
        assert!(cache::ENTRY_OVERHEAD >= core::mem::size_of::<CacheKey>());
        // An entry larger than a shard's budget is not stored, and evicts
        // nothing.
        let cache = DecisionCache::new(CacheConfig {
            max_bytes: 64,
            shards: 1,
        });
        cache.insert(
            CacheKey {
                file: FILE,
                object_type: ObjectType::Executable,
                subject: 0,
                context: 0,
                object: 0,
                policy: 1,
            },
            Arc::new(one),
            None,
            u64::MAX,
        );
        let stats = cache.stats();
        assert_eq!((stats.inserts, stats.entries, stats.evictions), (0, 0, 0));
    }

    /// A deadline in the same second as the decision is honoured to the
    /// microsecond, and one already past stores nothing.
    #[test]
    fn deadlines_are_kept_to_the_microsecond() {
        let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
        let (f, c, v, s) = setup();
        let soon = Call {
            expires_before: Some(10_500_000),
            ..call(&f, &c, &v, &s)
        };
        let at = |micros: u64| TestClock {
            now: Cell::new(micros),
            step: 0,
            trusted: true,
        };
        decide(&engine, &soon, &at(10_100_000));
        assert!(decide(&engine, &soon, &at(10_400_000)).1);
        assert!(!decide(&engine, &soon, &at(10_500_000)).1);
        let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
        let past = Call {
            expires_before: Some(1_000_000),
            ..call(&f, &c, &v, &s)
        };
        decide(&engine, &past, &at(2_000_000));
        assert_eq!(engine.cache_stats().inserts, 0);
    }

    /// A timeout never lets a mandatory-denied object run, whatever the
    /// rule set order, the mode or `on_eval_timeout`; and it names the rule
    /// that was evaluated when the budget ran out, the last one included.
    #[test]
    fn a_timeout_never_bypasses_a_mandatory_deny() {
        let c = EvaluationContext::new();
        let v = PathVariables::new();
        let blocked = ObjectFacts::new()
            .with(Field::HashSha256, sha('b'))
            .with_path(
                PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new())
                    .with_user_writable(false)
                    .with_volume(crate::unknown::VolumeKind::Fixed),
            )
            .with_signers(vec![]);
        for mandatory_first in [false, true] {
            for mode in [Mode::Enforce, Mode::Audit, Mode::Monitor, Mode::Learning] {
                for on_timeout in [
                    None,
                    Some(TimeoutAction::AllowAudit),
                    Some(TimeoutAction::Block),
                ] {
                    let p = mandatory_and_path(mandatory_first);
                    let state = DeviceState {
                        mode,
                        ..DeviceState::of(&p.document().policy)
                    };
                    for budget in [0, 5_000, 15_000] {
                        let engine = Engine::new(
                            p.clone(),
                            EngineConfig {
                                budget_micros: budget,
                                on_timeout,
                                ..EngineConfig::default()
                            },
                        )
                        .unwrap();
                        let clock = TestClock {
                            step: 10_000,
                            ..TestClock::at(1)
                        };
                        let request = call(&blocked, &c, &v, &state);
                        let d = match engine.evaluate(&request.request(), &clock) {
                            Outcome::TimedOut { decision, .. } => decision,
                            Outcome::Decided(Some(d)) => (*d).clone(),
                            other => panic!("{other:?}"),
                        };
                        assert_eq!(
                            d.outcome(),
                            Verdict::Blocked,
                            "{mandatory_first} {mode:?} {on_timeout:?} {budget}"
                        );
                    }
                }
            }
        }
        // The slow rule is the one evaluated last, and a slow last rule
        // still times out.
        let p = mandatory_and_path(true);
        let state = DeviceState::of(&p.document().policy);
        let engine = Engine::new(
            p,
            EngineConfig {
                budget_micros: 5_000,
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let only_path = ObjectFacts::new()
            .with(Field::HashSha256, sha('a'))
            .with_path(
                PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new())
                    .with_user_writable(false)
                    .with_volume(crate::unknown::VolumeKind::Fixed),
            )
            .with_signers(vec![]);
        // One reading at the start, one per tree: the path allow is the only
        // candidate, and it takes 10 ms.
        let clock = TestClock {
            step: 10_000,
            ..TestClock::at(1)
        };
        match engine.evaluate(&call(&only_path, &c, &v, &state).request(), &clock) {
            Outcome::TimedOut { event, decision } => {
                assert_eq!(
                    event.slow_rule.rule_id.to_string(),
                    "01936b2e-0001-7b3d-9f21-0a1b2c3d4e61"
                );
                assert_eq!(decision.reason_code(), ReasonCode::EvalTimeout);
            }
            other => panic!("{other:?}"),
        }
    }

    /// On the lazy path, with only the cheap facts, a mandatory deny on a
    /// hash has not been evaluated yet. An ordinary rule timing out then
    /// blocks, in every mode and with every fallback: the mandatory tier
    /// was not settled.
    #[test]
    fn a_lazy_timeout_blocks_while_a_mandatory_deny_waits_for_its_fact() {
        let c = EvaluationContext::new();
        let v = PathVariables::new();
        let cheap = ObjectFacts::new().with_path(
            PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        );
        for mode in [Mode::Audit, Mode::Monitor, Mode::Learning, Mode::Enforce] {
            for on_timeout in [None, Some(TimeoutAction::AllowAudit)] {
                let p = mandatory_and_path(true);
                let state = DeviceState {
                    mode,
                    ..DeviceState::of(&p.document().policy)
                };
                let engine = Engine::new(
                    p,
                    EngineConfig {
                        budget_micros: 5_000,
                        on_timeout,
                        ..EngineConfig::default()
                    },
                )
                .unwrap();
                let made = call(&cheap, &c, &v, &state);
                let mut request = made.request();
                request.computed = FactSet::EMPTY;
                let clock = TestClock {
                    step: 10_000,
                    ..TestClock::at(1)
                };
                match engine.evaluate(&request, &clock) {
                    Outcome::TimedOut { decision, .. } => {
                        assert_eq!(
                            decision.outcome(),
                            Verdict::Blocked,
                            "{mode:?} {on_timeout:?}"
                        );
                    }
                    other => panic!("{mode:?} {on_timeout:?}: {other:?}"),
                }
            }
        }
    }

    /// Rules that wait on a missing class but read facts that are known
    /// too are evaluated on the known facts; the watchdog stops that as
    /// well, and names the rule it stopped after.
    #[test]
    fn the_watchdog_covers_rules_waiting_on_a_fact() {
        let rules = (1..=4)
            .map(|n| {
                rule(
                    n,
                    serde_json::json!({"all": [
                        crit("hash.sha256", "equals", &sha('a')),
                        crit("meta.product_name", "regex", "x.*"),
                    ]}),
                    serde_json::json!({"type": "allow"}),
                )
            })
            .collect();
        let p = policy(rules, 300, 1);
        let state = DeviceState {
            mode: Mode::Audit,
            ..DeviceState::of(&p.document().policy)
        };
        let engine = Engine::new(
            p,
            EngineConfig {
                budget_micros: 15_000,
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let c = EvaluationContext::new();
        let v = PathVariables::new();
        let cheap = ObjectFacts::new()
            // No rule's regex matches it, so each rule is settled as
            // `NoMatch` on the cheap facts and none needs the hash: only
            // the watchdog stops the loop.
            .with(Field::MetaProductName, "zzz")
            .with_path(PathFact::new(r"C:\Tools\a.exe", &VolumeMap::new()));
        let made = call(&cheap, &c, &v, &state);
        let mut request = made.request();
        request.computed = FactSet::EMPTY;
        let clock = TestClock {
            step: 10_000,
            ..TestClock::at(1)
        };
        match engine.evaluate(&request, &clock) {
            Outcome::TimedOut { event, decision } => {
                assert_eq!(
                    event.slow_rule.rule_id.to_string(),
                    "01936b2e-0002-7b3d-9f21-0a1b2c3d4e61"
                );
                assert_eq!(decision.reason_code(), ReasonCode::EvalTimeout);
            }
            other => panic!("{other:?}"),
        }
    }

    /// Several mandatory denies that matched before a timeout are decided
    /// as stage 1 decides them: the most specific, the others overridden.
    #[test]
    fn a_timeout_after_several_mandatory_denies_decides_by_specificity() {
        let mandatory = serde_json::json!({
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
            "name": "Mandatory",
            "kind": "blocklist",
            "mandatory": true,
            "rules": [
                rule(1, crit("path.directory", "starts_with", r"C:\Tools"), serde_json::json!({"type": "deny"})),
                rule(2, crit("hash.sha256", "equals", &sha('a')), serde_json::json!({"type": "deny"})),
            ],
        });
        let ordinary = serde_json::json!({
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
            "name": "Rules",
            "kind": "mixed",
            "rules": [rule(3, crit("path.directory", "starts_with", r"C:\Tools"), serde_json::json!({"type": "audit"}))],
        });
        let json = serde_json::json!({
            "schema_version": "1.0.0",
            "policy": {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
                "name": "Engine",
                "revision": 1,
                "mode": "audit",
                "rule_sets": [mandatory["id"], ordinary["id"]],
            },
            "rule_sets": [mandatory, ordinary],
        });
        let p = PolicyDocument::from_json(&json.to_string())
            .unwrap()
            .validate()
            .unwrap();
        let state = DeviceState::of(&p.document().policy);
        let engine = Engine::new(
            p,
            EngineConfig {
                budget_micros: 15_000,
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let (f, c, v, _) = setup();
        let clock = TestClock {
            step: 10_000,
            ..TestClock::at(1)
        };
        match engine.evaluate(&call(&f, &c, &v, &state).request(), &clock) {
            Outcome::TimedOut { decision, .. } => {
                assert_eq!(decision.reason_code(), ReasonCode::MandatoryDeny);
                // The hash is more specific than the folder.
                assert_eq!(
                    decision.matched_rule().map(|r| r.rule_id.to_string()),
                    Some("01936b2e-0002-7b3d-9f21-0a1b2c3d4e61".to_owned())
                );
                assert_eq!(decision.overridden().len(), 1);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A miss that stores its decision returns it as made now (`Fresh`):
    /// only a later hit is `Cached`, with the trace ID of the evaluation
    /// that stored it.
    #[test]
    fn only_a_hit_is_cached() {
        let engine = Engine::new(allow_a(), EngineConfig::default()).unwrap();
        let (f, c, v, s) = setup();
        let one = call(&f, &c, &v, &s);
        let first = engine.evaluate(&one.request(), &TestClock::at(1));
        assert!(
            matches!(first, Outcome::Decided(Some(Decided::Fresh(_)))),
            "{first:?}"
        );
        assert_eq!(engine.cache_stats().inserts, 1);
        let mut again = one.request();
        again.trace_id = TraceId([1; 16]);
        match engine.evaluate(&again, &TestClock::at(2)) {
            Outcome::Decided(Some(Decided::Cached(d))) => assert_eq!(d.trace_id(), TRACE),
            other => panic!("{other:?}"),
        }
    }

    /// Every prompt makes a decision uncacheable: re-authentication and a
    /// multi-factor challenge on an elevation, and a custom notification.
    #[test]
    fn every_prompt_is_uncacheable() {
        let (f, c, v, _) = setup();
        for (why, action, effects) in [
            (
                "reauth",
                serde_json::json!({"type": "allow_elevated", "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d9999", "condition": "always", "auth": "reauth"}),
                None,
            ),
            (
                "mfa",
                serde_json::json!({"type": "allow_elevated", "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d9999", "condition": "always", "auth": "mfa"}),
                None,
            ),
            (
                "custom notification",
                serde_json::json!({"type": "deny"}),
                Some(
                    serde_json::json!({"notify": "custom", "notification_text": "Blocked {file}"}),
                ),
            ),
        ] {
            let mut r = rule(1, crit("hash.sha256", "equals", &sha('a')), action);
            if let Some(e) = effects {
                r["effects"] = e;
            }
            let p = policy(vec![r], 300, 1);
            let state = DeviceState::of(&p.document().policy);
            let engine = Engine::new(p, EngineConfig::default()).unwrap();
            decide(&engine, &call(&f, &c, &v, &state), &TestClock::at(1));
            decide(&engine, &call(&f, &c, &v, &state), &TestClock::at(1));
            assert_eq!(engine.cache_stats().inserts, 0, "{why}");
        }
    }

    /// A rule whose `any` anchor spans a cheap and an expensive class, and
    /// which the cheap branch already settles as `Match`, needs nothing
    /// more: it decides without asking for the hash.
    #[test]
    fn a_rule_settled_by_its_cheap_branch_asks_for_nothing() {
        let p = policy(
            vec![rule(
                1,
                serde_json::json!({"any": [
                    crit("path.directory", "starts_with", r"C:\Blocked"),
                    crit("hash.sha256", "equals", &sha('b')),
                ]}),
                serde_json::json!({"type": "deny"}),
            )],
            300,
            1,
        );
        let state = DeviceState::of(&p.document().policy);
        let engine = Engine::new(p, EngineConfig::default()).unwrap();
        let (_, c, v, _) = setup();
        let cheap =
            ObjectFacts::new().with_path(PathFact::new(r"C:\Blocked\a.exe", &VolumeMap::new()));
        let made = call(&cheap, &c, &v, &state);
        let mut request = made.request();
        request.computed = FactSet::EMPTY;
        match engine.evaluate(&request, &TestClock::at(1)) {
            Outcome::Decided(Some(d)) => assert_eq!(d.reason_code(), ReasonCode::ExplicitDeny),
            other => panic!("{other:?}"),
        }
    }

    /// The default fallback follows the mode of the object's type.
    #[test]
    fn the_default_fallback_follows_the_type_mode() {
        let mut d = allow_a().into_document();
        d.policy.mode = Mode::Audit;
        d.policy
            .mode_options
            .mode_by_type
            .insert(ObjectType::Executable, Mode::Enforce);
        let p = d.validate().unwrap();
        let state = DeviceState::of(&p.document().policy);
        let engine = Engine::new(
            p,
            EngineConfig {
                budget_micros: 0,
                ..EngineConfig::default()
            },
        )
        .unwrap();
        let (f, c, v, _) = setup();
        let clock = TestClock {
            step: 10,
            ..TestClock::at(1)
        };
        match engine.evaluate(&call(&f, &c, &v, &state).request(), &clock) {
            Outcome::TimedOut { decision, .. } => assert_eq!(decision.outcome(), Verdict::Blocked),
            other => panic!("{other:?}"),
        }
    }
}
