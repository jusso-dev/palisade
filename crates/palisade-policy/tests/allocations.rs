//! Zero heap allocations per decision (#42).
//!
//! This test binary replaces the global allocator with one that counts
//! (`allocation-counter`), so it is its own integration test: the counting
//! allocator never reaches the library or the other tests.
//!
//! The engine decides a warm object (its thread's scratch buffers already
//! sized by earlier decisions) and the test asserts that no allocation was
//! made: on the uncached path with several matching rules of every role, on
//! the cache-hit path, in a relaxed mode, for a mandatory deny, and for a
//! `NeedFacts` answer. The decision trace is not built here, which is the
//! `minimal` trace level of #41: its `standard` and `full` levels allocate
//! by design.
//!
//! What may allocate is documented, not counted: building a fresh
//! decision's effects copies a rule's notification text, help URL and tags
//! (`ResolvedEffects`), and a trust grant copies its scope paths. Rules
//! without those (most rules) allocate nothing. A decision is cached as an
//! `Arc`, so storing it allocates once; a hit does not.

#![allow(missing_docs, clippy::unwrap_used)]

use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::{Outcome as Verdict, TraceId};
use palisade_policy::demand::FactSet;
use palisade_policy::engine::{Engine, EngineConfig, FileIdentity, Outcome, Request, SystemClock};
use palisade_policy::evaluate::Subject;
use palisade_policy::facts::{
    ObjectFacts, PathFact, PathVariable, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{Field, Mode, ObjectType, PolicyDocument};
use palisade_policy::validate::ValidatedPolicy;

fn crit(field: &str, operator: &str, value: &str) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": [value]}})
}

fn rule(n: u32, tree: serde_json::Value, action: &str) -> serde_json::Value {
    serde_json::json!({
        "id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"),
        "name": format!("Rule {n}"),
        "object_types": ["executable"],
        "match": tree,
        "action": {"type": action},
    })
}

/// A policy where one object matches many rules: allows on its hash and
/// publisher, a deny on its folder, audit rules on its file name, product
/// and the user's group, and rules it does not match on every anchor kind.
fn policy(mandatory_hash: &str) -> ValidatedPolicy {
    let sha = "a".repeat(64);
    let mut rules = vec![
        rule(1, crit("hash.sha256", "equals", &sha), "allow"),
        rule(
            2,
            crit("signer.publisher", "equals", "Example Ltd"),
            "allow",
        ),
        rule(
            3,
            crit("path.directory", "starts_with", r"C:\Program Files\App"),
            "deny",
        ),
        rule(
            4,
            serde_json::json!({"all": [
                crit("path.full", "wildcard", r"%PROGRAMFILES%\*\*.exe"),
                crit("meta.product_name", "equals", "Suite"),
            ]}),
            "audit",
        ),
        rule(
            5,
            serde_json::json!({"all": [
                crit("hash.sha256", "equals", &sha),
                {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-544"]}},
            ]}),
            "audit",
        ),
        rule(
            6,
            serde_json::json!({"all": [
                crit("signer.publisher", "equals", "Example Ltd"),
                crit("meta.file_version", "version_ge", "1.0"),
                {"not": crit("meta.product_name", "regex", "Bad.*")},
            ]}),
            "audit",
        ),
    ];
    for n in 0..200u32 {
        rules.push(rule(
            100 + n,
            crit("hash.sha256", "equals", &format!("{n:064x}")),
            "allow",
        ));
        rules.push(rule(
            400 + n,
            crit("path.full", "starts_with", &format!(r"D:\Other{n}")),
            "deny",
        ));
    }
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Allocations",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": [
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
            ],
        },
        "rule_sets": [
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
                "name": "Rules",
                "kind": "mixed",
                "rules": rules,
            },
            {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002",
                "name": "Mandatory",
                "kind": "blocklist",
                "mandatory": true,
                "rules": [rule(900, crit("hash.sha256", "equals", mandatory_hash), "deny")],
            }
        ],
    });
    PolicyDocument::from_json(&json.to_string())
        .unwrap()
        .validate()
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn facts(sha: char) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha.to_string().repeat(64))
        .with(Field::MetaProductName, "Suite")
        .with(Field::MetaFileVersion, "2.0.1.0")
        .with_path(
            PathFact::new(r"C:\Program Files\App\tool.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(palisade_policy::unknown::VolumeKind::Fixed),
        )
        .with_signers(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some("Example Ltd".to_owned()),
            issuer: Some("Example CA".to_owned()),
            leaf_thumbprint_sha256: Some("b".repeat(64)),
            details: Default::default(),
        }])
}

fn context() -> EvaluationContext {
    let mut c = EvaluationContext::new();
    c.user.sid = Some("S-1-5-21-1-2-3-1001".to_owned());
    c.user.groups = Some(vec!["S-1-5-32-544".to_owned(), "S-1-5-11".to_owned()]);
    c
}

/// Decides twice to warm the thread's buffers, then counts a third time.
fn allocations(engine: &Engine, request: &Request<'_>) -> (u64, Outcome) {
    let clock = SystemClock::new();
    for _ in 0..2 {
        drop(engine.evaluate(request, &clock));
    }
    let mut out = None;
    let info = allocation_counter::measure(|| {
        out = Some(engine.evaluate(request, &clock));
    });
    // Dropping the result is outside the measurement; nothing it holds was
    // allocated inside it.
    (info.count_total, out.unwrap())
}

#[test]
fn a_decision_allocates_nothing() {
    let engine = Engine::new(policy(&"f".repeat(64)), EngineConfig::default()).unwrap();
    let f = facts('a');
    let c = context();
    let v = PathVariables::new().with(PathVariable::ProgramFiles, &[r"C:\Program Files"]);
    let enforce = DeviceState::of(&engine.snapshot().policy().document().policy);
    let audit = DeviceState {
        mode: Mode::Audit,
        ..enforce
    };
    for (state, file, want) in [
        // Uncached: the deny on the folder wins over both allows, with
        // three annotations and the allows overridden.
        (&enforce, None, Verdict::Blocked),
        // The same, relaxed by audit mode.
        (&audit, None, Verdict::AllowedAudit),
        // A cache hit, after the warm-up stored it.
        (
            &enforce,
            Some(FileIdentity::Sha256([7; 32])),
            Verdict::Blocked,
        ),
    ] {
        let request = Request {
            subject: Subject {
                object_type: ObjectType::Executable,
                facts: &f,
                variables: &v,
                context: &c,
            },
            computed: FactSet::ALL,
            state,
            trace_id: TraceId([1; 16]),
            file,
            session: None,
            expires_before: None,
        };
        let (count, outcome) = allocations(&engine, &request);
        let Outcome::Decided(Some(d)) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(d.outcome(), want);
        assert_eq!(d.annotations().len(), 3, "{:?}", d.annotations());
        assert!(d.overridden().len() >= 2);
        assert_eq!(count, 0, "{state:?} cached={}", file.is_some());
    }
    // The cached case: its first warm-up stored the decision, and the
    // second warm-up and the measured call were hits.
    assert_eq!(engine.cache_stats().hits, 2);
}

#[test]
fn a_mandatory_deny_and_need_facts_allocate_nothing() {
    let engine = Engine::new(policy(&"a".repeat(64)), EngineConfig::default()).unwrap();
    let c = context();
    let v = PathVariables::new();
    let state = DeviceState::of(&engine.snapshot().policy().document().policy);
    let f = facts('a');
    let request = Request {
        subject: Subject {
            object_type: ObjectType::Executable,
            facts: &f,
            variables: &v,
            context: &c,
        },
        computed: FactSet::ALL,
        state: &state,
        trace_id: TraceId([1; 16]),
        file: None,
        session: None,
        expires_before: None,
    };
    let (count, outcome) = allocations(&engine, &request);
    let Outcome::Decided(Some(d)) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(d.outcome(), Verdict::Blocked);
    assert_eq!(count, 0, "mandatory deny");

    // Only the cheap facts: the engine asks for the hash, without
    // allocating.
    let cheap = ObjectFacts::new().with_path(PathFact::new(
        r"C:\Program Files\App\tool.exe",
        &VolumeMap::new(),
    ));
    let request = Request {
        subject: Subject {
            facts: &cheap,
            ..request.subject
        },
        computed: FactSet::EMPTY,
        ..request
    };
    let (count, outcome) = allocations(&engine, &request);
    assert!(matches!(outcome, Outcome::NeedFacts(_)), "{outcome:?}");
    assert_eq!(count, 0, "need facts");
}
