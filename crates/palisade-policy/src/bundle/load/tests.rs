use std::net::IpAddr;

use serde_json::json;

use super::*;
use crate::bundle::compile::{Compiled, Source, compile};
use crate::bundle::format::{SourceRevisions, Target, TargetScope};
use crate::context::EvaluationContext;
use crate::engine::{Engine, EngineConfig};
use crate::evaluate::Subject;
use crate::facts::PathVariables;
use crate::library::{Catalogue, Library, Visibility};
use crate::model::{ObjectType, PolicyDocument};
use crate::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, facts, hash};
use palisade_core::Uuid7;

const NET: &str = "01936b2e-8c4a-7004-9f21-000000000001";

fn catalogue() -> Catalogue {
    let lib: Library = serde_json::from_value(json!({
        "id": NET, "version": 1, "name": "Office", "realm": "global",
        "content": {"kind": "network_set", "entries": ["10.0.0.0/8"]},
    }))
    .unwrap();
    Catalogue::new(vec![lib]).unwrap()
}

fn header() -> Header {
    let id = |n: u8| {
        let mut b = [0u8; 16];
        b[15] = n;
        b[6] = 0x70;
        b[8] = 0x80;
        Uuid7::from_bytes(b).unwrap()
    };
    Header::new(
        Target {
            tenant: id(1),
            scope: TargetScope::Group(id(2)),
        },
        3,
        1_764_201_600_000_000,
    )
}

/// An allow of `a` scoped to the office network set, a profile `office`
/// on the same set, and a deny of `b`.
fn policy() -> ValidatedPolicy {
    let mut doc: PolicyDocument = PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::mixed(1)
                .rule(RuleBuilder::allow(1, hash('a')))
                .rule(RuleBuilder::deny(2, hash('b'))),
        )
        .build();
    doc.rule_sets[0].rules[0].scope = Some(
        serde_json::from_value(json!({"network": {"include": [{"network_set": {"id": NET}}]}}))
            .unwrap(),
    );
    doc.policy.location_profiles = vec![
        serde_json::from_value(json!({"name": "office", "all": [{"network_set": {"id": NET}}]}))
            .unwrap(),
    ];
    doc.validate().unwrap()
}

fn bytes() -> Vec<u8> {
    let (policy, cat) = (policy(), catalogue());
    let p = &policy.document().policy;
    let source = Source {
        policy: &policy,
        catalogue: &cat,
        from: Visibility::Global,
        sources: SourceRevisions {
            policies: vec![(p.id, p.revision)],
            libraries: Vec::new(),
        },
        facts: crate::analysis::Facts::default(),
        admin: None,
    };
    let Compiled { bytes, .. } = compile(&source, header(), &BundleLimits::DEFAULT).unwrap();
    bytes
}

fn context(addr: &str) -> EvaluationContext {
    let mut c = EvaluationContext::default();
    c.network.addresses = Some(vec![addr.parse::<IpAddr>().unwrap()]);
    c
}

/// The rule that decides `digit` on `addr`, if any.
fn decide(loaded: &LoadedPolicy, digit: char, addr: &str) -> Option<crate::model::RuleId> {
    let f = facts().sha256(digit).build();
    let vars = PathVariables::default();
    let ctx = context(addr);
    loaded
        .snapshot()
        .evaluator()
        .evaluate(
            &Subject {
                object_type: ObjectType::Executable,
                facts: &f,
                variables: &vars,
                context: &ctx,
            },
            TRACE,
        )
        .matched_rule()
        .map(|r| r.rule_id)
}

#[test]
fn a_bundle_loads_in_one_step_with_its_sets() {
    let bytes = bytes();
    let loaded = load(&bytes, &BundleLimits::DEFAULT, None).unwrap();
    assert_eq!(loaded.header(), &header());
    assert_eq!(loaded.bundle_hash(), &bundle_hash(&bytes));
    // The scope reads the inlined set: inside it the allow decides, outside
    // it does not.
    assert_eq!(
        decide(&loaded, 'a', "10.1.2.3"),
        Some(crate::test_util::rule_id(1))
    );
    assert_eq!(decide(&loaded, 'a', "192.168.1.1"), None);
    assert_eq!(
        decide(&loaded, 'b', "192.168.1.1"),
        Some(crate::test_util::rule_id(2))
    );
    // So does the location profile.
    assert_eq!(
        loaded.profiles().active(&context("10.1.2.3").network),
        ["OFFICE"]
    );
    assert!(
        loaded
            .profiles()
            .active(&context("192.168.1.1").network)
            .is_empty()
    );
}

#[test]
fn bytes_that_are_not_a_bundle_do_not_load() {
    let err = load(b"not a bundle", &BundleLimits::DEFAULT, None).unwrap_err();
    assert!(matches!(err, LoadError::Decode(_)), "{err}");
    assert!(err.to_string().starts_with("the bundle does not decode"));
    // Over the limit is refused before anything is read.
    let tiny = BundleLimits {
        max_bytes: 16,
        ..BundleLimits::DEFAULT
    };
    assert!(matches!(
        load(&bytes(), &tiny, None),
        Err(LoadError::Decode(BundleError::TooLarge { .. }))
    ));
}

#[test]
fn a_bundle_whose_policy_is_invalid_does_not_load() {
    // A body the decoder reads but validation refuses: a rule set the
    // policy names that it does not hold.
    let mut doc = policy().into_document();
    doc.policy.rule_sets.push(crate::test_util::rule_set_id(9));
    let body =
        super::super::format::Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap();
    let bytes = PolicyBundle::new(header(), body).to_bytes().unwrap();
    let err = load(&bytes, &BundleLimits::DEFAULT, None).unwrap_err();
    assert!(
        matches!(&err, LoadError::Invalid(e) if !e.is_empty()),
        "{err}"
    );
    assert!(err.to_string().contains("not valid"), "{err}");
}

#[test]
fn the_agent_adds_its_system_baseline() {
    let baseline = SystemBaseline {
        publishers: vec!["Example OS Publisher".to_owned()],
        writable_dirs: Vec::new(),
    };
    let loaded = load(&bytes(), &BundleLimits::DEFAULT, Some(&baseline)).unwrap();
    assert!(
        loaded
            .policy()
            .document()
            .rule_sets
            .iter()
            .any(crate::unknown::baseline::is_system_baseline)
    );
    // Facts that do not fit in one rule fail the load.
    let none = SystemBaseline::default();
    let err = load(&bytes(), &BundleLimits::DEFAULT, Some(&none)).unwrap_err();
    assert!(matches!(err, LoadError::Baseline(_)), "{err}");
    assert!(err.to_string().contains("system baseline"), "{err}");
}

#[test]
fn an_engine_takes_a_loaded_policy() {
    let engine = Engine::from_loaded(
        load(&bytes(), &BundleLimits::DEFAULT, None).unwrap(),
        EngineConfig::default(),
    );
    let first = engine.snapshot().generation();
    engine.install(load(&bytes(), &BundleLimits::DEFAULT, None).unwrap());
    let second = engine.snapshot().generation();
    assert_ne!(first, second);
    assert_eq!(
        engine.snapshot().policy().document(),
        load(&bytes(), &BundleLimits::DEFAULT, None)
            .unwrap()
            .policy()
            .document()
    );
}

#[test]
fn every_error_displays() {
    let build = LoadError::Build(BuildError {
        rule_id: crate::test_util::rule_id(1),
        errors: Vec::new(),
    });
    assert!(build.to_string().contains("does not compile"));
    let empty = LoadError::Invalid(Vec::new());
    assert_eq!(
        empty.to_string(),
        "the bundle's policy is not valid (0 findings)"
    );
}
