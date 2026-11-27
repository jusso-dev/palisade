use std::net::IpAddr;

use serde_json::json;

use super::*;
use crate::bundle::format::{BundleLimits, DEFAULT_MAX_BYTES, Target, TargetScope, decode_header};
use crate::context::EvaluationContext;
use crate::evaluate::{Evaluator, Subject};
use crate::facts::PathVariables;
use crate::library::Library;
use crate::model::{ObjectType, PolicyDocument};
use crate::scope::CatalogueLibrary;
use crate::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, facts, hash};
use palisade_core::Uuid7;

const NET: &str = "01936b2e-8c4a-7004-9f21-000000000001";

fn net_set(version: u32, block: &str) -> Library {
    serde_json::from_value(json!({
        "id": NET, "version": version, "name": "Office", "realm": "global",
        "content": {"kind": "network_set", "entries": [block]},
    }))
    .unwrap()
}

fn catalogue() -> Catalogue {
    Catalogue::new(vec![net_set(1, "10.0.0.0/8"), net_set(2, "192.168.0.0/16")]).unwrap()
}

/// An allow scoped to the office network set at `pin`, and a deny.
fn policy(pin: serde_json::Value) -> ValidatedPolicy {
    let mut doc: PolicyDocument = PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::mixed(1)
                .rule(RuleBuilder::allow(1, hash('a')))
                .rule(RuleBuilder::deny(2, hash('b'))),
        )
        .build();
    let set_ref = if pin.is_null() {
        json!({"id": NET})
    } else {
        json!({"id": NET, "pin": pin})
    };
    doc.rule_sets[0].rules[0].scope = Some(
        serde_json::from_value(json!({"network": {"include": [{"network_set": set_ref}]}}))
            .unwrap(),
    );
    doc.validate().unwrap()
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

fn source<'a>(policy: &'a ValidatedPolicy, catalogue: &'a Catalogue) -> Source<'a> {
    let p = &policy.document().policy;
    Source {
        policy,
        catalogue,
        from: Visibility::Global,
        sources: SourceRevisions {
            policies: vec![(p.id, p.revision)],
            libraries: Vec::new(),
        },
    }
}

fn context(addr: &str) -> EvaluationContext {
    let mut c = EvaluationContext::default();
    c.network.addresses = Some(vec![addr.parse::<IpAddr>().unwrap()]);
    c
}

#[test]
fn compiling_twice_gives_the_same_bytes() {
    let (policy, cat) = (policy(json!(2)), catalogue());
    let (_, a) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
    let (_, b) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
    assert_eq!(a, b);
    assert_eq!(decode_header(&a, &BundleLimits::DEFAULT).unwrap(), header());
}

#[test]
fn only_the_pinned_version_of_a_set_is_inlined() {
    let (policy, cat) = (policy(json!(1)), catalogue());
    let (bundle, _) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
    let inlined: Vec<(u32, &SetContent)> = bundle
        .body
        .libraries()
        .iter()
        .map(|l| (l.resolved_version, &l.content))
        .collect();
    assert_eq!(
        inlined,
        [(1, &SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]))]
    );
}

#[test]
fn a_missing_set_fails_the_compile() {
    let policy = policy(json!(9));
    let cat = catalogue();
    let err = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap_err();
    assert!(
        matches!(
            err,
            CompileError::UnresolvedSet {
                pin: Pin::Version(9),
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn an_oversized_bundle_fails_with_advice() {
    let (policy, cat) = (policy(json!(2)), catalogue());
    let err = compile(&source(&policy, &cat), header(), 64).unwrap_err();
    assert!(matches!(err, CompileError::TooLarge { limit: 64, .. }));
    assert!(err.to_string().contains("split it"));
}

#[test]
fn the_bundle_resolves_latest_only_when_it_holds_one_version() {
    let (policy, cat) = (policy(serde_json::Value::Null), catalogue());
    let (bundle, _) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
    let sets = BundleSets::new(&bundle);
    let latest = SetRef {
        id: LibraryId(NET.parse().unwrap()),
        pin: Pin::Latest,
    };
    assert_eq!(
        sets.network_set(&latest),
        Some(vec!["192.168.0.0/16".to_owned()])
    );
    assert_eq!(sets.principal_set(&latest), None, "wrong kind");
    let old = SetRef {
        pin: Pin::Version(1),
        ..latest
    };
    assert_eq!(sets.network_set(&old), None, "not in the bundle");
}

/// The simulator and the agent decide alike: the policy evaluated against
/// the server's catalogue, and the decoded bundle evaluated against the
/// sets it inlines, give the same decision for every object and network.
#[test]
fn a_loaded_bundle_decides_as_the_policy_it_was_compiled_from() {
    let cat = catalogue();
    for pin in [json!(1), json!(2), serde_json::Value::Null] {
        let policy = policy(pin);
        let (_, bytes) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
        let loaded = PolicyBundle::decode(&bytes, &BundleLimits::DEFAULT).unwrap();
        let validated = loaded.validate().unwrap();
        let sets = BundleSets::new(&loaded);
        let server = Evaluator::with_library(
            &policy,
            &CatalogueLibrary {
                catalogue: &cat,
                from: Visibility::Global,
            },
        )
        .unwrap();
        let agent = Evaluator::with_library(&validated, &sets).unwrap();
        let vars = PathVariables::default();
        for digit in ['a', 'b', 'c'] {
            let f = facts().sha256(digit).build();
            for addr in ["10.1.2.3", "192.168.1.1", "172.16.0.1"] {
                let ctx = context(addr);
                let subject = Subject {
                    object_type: ObjectType::Executable,
                    facts: &f,
                    variables: &vars,
                    context: &ctx,
                };
                assert_eq!(
                    agent.evaluate(&subject, TRACE),
                    server.evaluate(&subject, TRACE),
                    "{digit} on {addr}"
                );
            }
        }
    }
}

#[test]
fn the_network_set_changes_what_the_bundle_allows() {
    let cat = catalogue();
    let policy = policy(json!(1));
    let (bundle, _) = compile(&source(&policy, &cat), header(), DEFAULT_MAX_BYTES).unwrap();
    let validated = bundle.validate().unwrap();
    let sets = BundleSets::new(&bundle);
    let agent = Evaluator::with_library(&validated, &sets).unwrap();
    let f = facts().sha256('a').build();
    let vars = PathVariables::default();
    let decide = |addr: &str| {
        let ctx = context(addr);
        agent
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
    };
    assert!(decide("10.1.2.3").is_some(), "inside the set");
    assert!(
        decide("192.168.1.1").is_none(),
        "outside the pinned version"
    );
}
