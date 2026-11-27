use std::net::IpAddr;

use serde_json::json;

use super::*;
use crate::bundle::format::{BundleLimits, Target, TargetScope, decode_header};
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
    let (_, a) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let (_, b) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    assert_eq!(a, b);
    assert_eq!(decode_header(&a, &BundleLimits::DEFAULT).unwrap(), header());
}

#[test]
fn only_the_pinned_version_of_a_set_is_inlined() {
    let (policy, cat) = (policy(json!(1)), catalogue());
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let err = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap_err();
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
    let tiny = BundleLimits {
        max_bytes: 64,
        ..BundleLimits::DEFAULT
    };
    let err = compile(&source(&policy, &cat), header(), &tiny).unwrap_err();
    assert!(matches!(err, CompileError::TooLarge { limit: 64, .. }));
    assert!(err.to_string().contains("split it"));
}

#[test]
fn the_bundle_resolves_latest_only_when_it_holds_one_version() {
    let (policy, cat) = (policy(serde_json::Value::Null), catalogue());
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
        let (_, bytes) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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

// Review findings on #315: each test below failed on the code before its
// fix.

/// A profile `quarantine` matching the network set at v1, and an allow that
/// excludes it, so the allow applies outside quarantine only.
fn profile_policy() -> ValidatedPolicy {
    let mut doc: PolicyDocument = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::mixed(1).rule(RuleBuilder::allow(1, hash('a'))))
        .build();
    doc.policy.location_profiles = vec![
        serde_json::from_value(json!({
            "name": "quarantine",
            "all": [{"network_set": {"id": NET, "pin": 1}}],
        }))
        .unwrap(),
    ];
    doc.rule_sets[0].rules[0].scope = Some(Box::new(
        serde_json::from_value(
            json!({"network": {"exclude": [{"location_profile": "quarantine"}]}}),
        )
        .unwrap(),
    ));
    doc.validate().unwrap()
}

/// The profiles the agent sees as active on `addr`, through `library`.
fn active(policy: &ValidatedPolicy, library: &dyn ScopeLibrary, addr: &str) -> Vec<String> {
    crate::scope::CompiledProfiles::compile(&policy.document().policy.location_profiles, library)
        .active(&context(addr).network)
}

#[test]
fn a_location_profile_network_set_is_not_inlined_and_fails_open() {
    let cat = catalogue();
    let policy = profile_policy();
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let server = CatalogueLibrary {
        catalogue: &cat,
        from: Visibility::Global,
    };
    let sets = BundleSets::new(&bundle);
    let validated = bundle.validate().unwrap();
    assert_eq!(active(&policy, &server, "10.1.2.3"), ["QUARANTINE"]);
    // The agent must see the same profile active, so the allow that
    // excludes quarantine does not apply there.
    assert_eq!(active(&validated, &sets, "10.1.2.3"), ["QUARANTINE"]);
}

#[test]
fn latest_and_a_pin_of_one_set_diverge() {
    // One rule reads the set at `latest` (v2), another pinned at v1: the
    // bundle must resolve both exactly as the server does.
    let mut doc = policy(json!(1)).into_document();
    let mut latest = doc.rule_sets[0].rules[0].clone();
    latest.id = crate::test_util::rule_id(3);
    latest.scope = Some(Box::new(
        serde_json::from_value(json!({"network": {"include": [{"network_set": {"id": NET}}]}}))
            .unwrap(),
    ));
    latest.match_ = hash('c');
    doc.rule_sets[0].rules.push(latest);
    let policy = doc.validate().unwrap();
    let cat = catalogue();
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let validated = bundle.validate().unwrap();
    let sets = BundleSets::new(&bundle);
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
    let f = facts().sha256('c').build();
    let ctx = context("192.168.1.1");
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &f,
        variables: &vars,
        context: &ctx,
    };
    assert_eq!(
        agent.evaluate(&subject, TRACE),
        server.evaluate(&subject, TRACE)
    );
}

#[test]
fn nfc_on_write_makes_a_valid_policy_invalid_tags() {
    // Two tags that differ only in normal form are distinct when validated,
    // and equal once the bundle writes both in NFC.
    let mut doc = policy(json!(1)).into_document();
    doc.rule_sets[0].rules[0].effects.tags = vec!["caf\u{e9}".to_owned(), "cafe\u{301}".to_owned()];
    let Ok(policy) = doc.validate() else {
        return; // Validation already folds them: nothing to prove.
    };
    let cat = catalogue();
    match compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT) {
        Err(CompileError::Invalid(_)) => {}
        Ok((bundle, _)) => {
            assert!(
                bundle.validate().is_ok(),
                "the server shipped a bundle every agent refuses"
            );
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn nfc_on_write_makes_a_valid_policy_invalid_name_length() {
    // U+0958 is NFC-excluded: its NFC form is two characters. 100 of them
    // are a valid 100-character name, and 200 characters in NFC.
    let mut doc = policy(json!(1)).into_document();
    doc.rule_sets[0].rules[0].name = "\u{958}".repeat(100);
    let policy = doc.validate().unwrap();
    let cat = catalogue();
    match compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT) {
        Err(CompileError::Invalid(_)) => {}
        Ok((bundle, _)) => {
            assert!(
                bundle.validate().is_ok(),
                "the server shipped a bundle every agent refuses"
            );
        }
        Err(e) => panic!("{e}"),
    }
}

#[test]
fn a_valid_compiled_bundle_exceeds_the_agents_item_limit() {
    // An agent configured with a tighter item limit than the bundle needs:
    // the bundle is valid and under the byte limit, but that agent would
    // refuse it. The server compiles against the agents' limits, so it
    // must refuse it first.
    let mut builder = RuleSetBuilder::allowlist(1);
    for n in 1..=50 {
        builder = builder.rule(RuleBuilder::allow(n, hash('a')));
    }
    let policy = PolicyBuilder::new().rule_set(builder).validate();
    let cat = catalogue();
    let agents = BundleLimits {
        max_items: 500,
        ..BundleLimits::DEFAULT
    };
    match compile(&source(&policy, &cat), header(), &agents) {
        Err(CompileError::Invalid(why)) => assert!(why.contains("too many"), "{why}"),
        Ok((_, bytes)) => {
            PolicyBundle::decode(&bytes, &agents)
                .expect("the server shipped a bundle every agent refuses");
        }
        Err(e) => panic!("{e}"),
    }
}

/// The system baseline is built from facts the agent collects (the OS
/// publishers and the writable directories it found), so it is the
/// agent's to add, after it loads a bundle. A policy that already holds it
/// is refused: compiled in, the baseline would be the server's guess at
/// one device's facts, and the agent's reserved-ID check on `validate`
/// would refuse the bundle.
#[test]
fn bundles_never_carry_the_system_baseline_and_the_agent_adds_it() {
    let facts = crate::unknown::SystemBaseline {
        publishers: vec!["Example OS Publisher".to_owned()],
        writable_dirs: Vec::new(),
    };
    let cat = catalogue();
    let plain = policy(json!(1));
    let with_baseline = plain.clone().with_system_baseline(&facts).unwrap();
    let err = compile(
        &source(&with_baseline, &cat),
        header(),
        &BundleLimits::DEFAULT,
    )
    .unwrap_err();
    assert!(
        matches!(&err, CompileError::Invalid(why) if why.contains("system_baseline")),
        "{err}"
    );
    // The agent's path: load, validate, then add the baseline from its own
    // facts. The result decides as the server's policy with the baseline.
    let (bundle, _) = compile(&source(&plain, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let on_agent = bundle
        .validate()
        .unwrap()
        .with_system_baseline(&facts)
        .unwrap();
    assert!(
        on_agent
            .document()
            .rule_sets
            .iter()
            .any(crate::unknown::baseline::is_system_baseline)
    );
    assert_eq!(
        on_agent.document().rule_sets.len(),
        with_baseline.document().rule_sets.len()
    );
}

/// The sources a bundle records include every set it inlines, also those
/// only a location profile reads.
#[test]
fn inlined_sets_are_recorded_as_sources() {
    let cat = catalogue();
    let policy = profile_policy();
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    assert_eq!(
        bundle.body.source_revisions().libraries,
        [(LibraryId(NET.parse().unwrap()), 1)]
    );
}

/// The differential test for profiles: an allow that applies outside the
/// `quarantine` profile decides alike on the server and on the agent, on
/// and off the quarantined network.
#[test]
fn a_loaded_bundle_decides_as_the_server_with_location_profiles() {
    let cat = catalogue();
    let policy = profile_policy();
    let (_, bytes) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let loaded = PolicyBundle::decode(&bytes, &BundleLimits::DEFAULT).unwrap();
    let validated = loaded.validate().unwrap();
    let sets = BundleSets::new(&loaded);
    let server_lib = CatalogueLibrary {
        catalogue: &cat,
        from: Visibility::Global,
    };
    let server = Evaluator::with_library(&policy, &server_lib).unwrap();
    let agent = Evaluator::with_library(&validated, &sets).unwrap();
    let vars = PathVariables::default();
    let f = facts().sha256('a').build();
    for addr in ["10.1.2.3", "192.168.1.1"] {
        let mut server_ctx = context(addr);
        server_ctx.network.locations = Some(active(&policy, &server_lib, addr));
        let mut agent_ctx = context(addr);
        agent_ctx.network.locations = Some(active(&validated, &sets, addr));
        let decide = |e: &Evaluator<'_>, ctx: &EvaluationContext| {
            e.evaluate(
                &Subject {
                    object_type: ObjectType::Executable,
                    facts: &f,
                    variables: &vars,
                    context: ctx,
                },
                TRACE,
            )
        };
        assert_eq!(
            decide(&agent, &agent_ctx),
            decide(&server, &server_ctx),
            "{addr}"
        );
    }
    let mut ctx = context("10.1.2.3");
    ctx.network.locations = Some(active(&validated, &sets, "10.1.2.3"));
    let quarantined = agent.evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &f,
            variables: &vars,
            context: &ctx,
        },
        TRACE,
    );
    assert!(
        quarantined.matched_rule().is_none(),
        "the allow must not apply in quarantine"
    );
}

mod coverage {
    //! The rest of the compile API: an effective policy as the source, the
    //! scopes of unknown-policy limits and rule-set assignments, the
    //! refusals, every error's message, and each kind of inlined set.

    use super::*;
    use crate::hierarchy::tests::{base_nodes, policy as h_policy, rule, set, snapshot, validated};

    #[test]
    fn an_effective_policy_compiles_with_its_own_sources() {
        let mut nodes = base_nodes();
        for n in &mut nodes {
            if n["id"] == json!(crate::hierarchy::tests::id(20)) {
                n["assignments"] =
                    json!([{"policy": crate::hierarchy::tests::id(50), "slot_order": 0}]);
            }
        }
        let h = validated(&snapshot(
            nodes,
            vec![h_policy(
                50,
                "enforce",
                vec![set(60, "allowlist", false, vec![rule(70, "allow", 'a')])],
            )],
            vec![],
        ));
        let device = crate::hierarchy::NodeId(crate::hierarchy::tests::id(20).parse().unwrap());
        let e = h
            .effective_policy_as(device, &crate::hierarchy::Membership::default())
            .unwrap();
        let src = Source::effective(&e, h.catalogue(), Visibility::Global).unwrap();
        let p = &e.policy().unwrap().document().policy;
        assert_eq!(src.sources.policies, [(p.id, p.revision)]);
        let (bundle, _) = compile(&src, header(), &BundleLimits::DEFAULT).unwrap();
        assert_eq!(
            bundle.body.source_revisions().policies,
            [(p.id, p.revision)]
        );
    }

    #[test]
    fn sets_in_unknown_limits_and_rule_set_assignments_are_inlined_and_pinned() {
        let mut doc = policy(json!(1)).into_document();
        let latest: crate::scope::Scope =
            serde_json::from_value(json!({"network": {"include": [{"network_set": {"id": NET}}]}}))
                .unwrap();
        doc.policy.rule_set_scopes = vec![crate::scope::RuleSetScope {
            rule_set: doc.rule_sets[0].id,
            scopes: vec![latest.clone()],
        }];
        doc.policy.unknown.scope_limits = vec![
            serde_json::from_value(json!({"all_of": [latest.clone()], "any_of": [latest]}))
                .unwrap(),
        ];
        let Ok(policy) = doc.validate() else {
            return;
        };
        let cat = catalogue();
        let (bundle, _) =
            compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
        let pins: Vec<Pin> = crate::scope::document_scopes(bundle.body.document())
            .into_iter()
            .flat_map(|(_, s)| crate::scope::set_refs(s))
            .map(|(_, r, _)| r.pin)
            .collect();
        assert!(!pins.is_empty());
        assert!(
            pins.iter().all(|p| matches!(p, Pin::Version(_))),
            "{pins:?}"
        );
    }

    #[test]
    fn mismatched_schema_versions_are_refused_and_errors_explain_themselves() {
        let cat = catalogue();
        let policy = policy(json!(1));
        let newer = Header {
            schema_version: palisade_core::SchemaVersion::new(1, 99, 0),
            ..header()
        };
        let err = compile(&source(&policy, &cat), newer, &BundleLimits::DEFAULT).unwrap_err();
        assert!(
            matches!(&err, CompileError::Invalid(w) if w.contains("schema")),
            "{err}"
        );
        let errors = [
            CompileError::Invalid("x".to_owned()),
            CompileError::UnresolvedSet {
                id: LibraryId(NET.parse().unwrap()),
                pin: Pin::Latest,
            },
            CompileError::Encode(serial::Error::Float),
            CompileError::TooLarge { size: 2, limit: 1 },
        ];
        let texts: std::collections::BTreeSet<String> =
            errors.iter().map(ToString::to_string).collect();
        assert_eq!(texts.len(), errors.len());
    }

    #[test]
    fn each_kind_of_inlined_set_resolves_only_as_its_kind() {
        let sets = |content: SetContent, versions: &[u32]| {
            let b = PolicyBundle::new(
                header(),
                crate::bundle::format::Body::new(
                    policy(json!(1)).into_document(),
                    versions
                        .iter()
                        .map(|v| InlineLibrary {
                            id: LibraryId(NET.parse().unwrap()),
                            resolved_version: *v,
                            content: content.clone(),
                        })
                        .collect(),
                    SourceRevisions::default(),
                )
                .unwrap(),
            );
            BundleSets::new(&b)
        };
        let r = |pin| SetRef {
            id: LibraryId(NET.parse().unwrap()),
            pin,
        };
        let principals = sets(
            SetContent::PrincipalSet(vec!["S-1-5-32-544".to_owned()]),
            &[1],
        );
        assert_eq!(
            principals.principal_set(&r(Pin::Version(1))),
            Some(vec!["S-1-5-32-544".to_owned()])
        );
        assert_eq!(principals.network_set(&r(Pin::Version(1))), None);
        assert_eq!(principals.schedule_set(&r(Pin::Version(1))), None);
        let schedule =
            json!({"windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}]}).to_string();
        let schedules = sets(SetContent::ScheduleSet(vec![schedule]), &[1]);
        assert!(schedules.schedule_set(&r(Pin::Latest)).is_some());
        assert_eq!(schedules.principal_set(&r(Pin::Latest)), None);
        let two = sets(
            SetContent::ScheduleSet(vec!["{}".to_owned(), "{}".to_owned()]),
            &[1],
        );
        assert!(
            two.schedule_set(&r(Pin::Version(1))).is_none(),
            "a set holds one schedule"
        );
        // `latest` with two versions held is ambiguous: unresolved.
        let both = sets(
            SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]),
            &[1, 2],
        );
        assert_eq!(both.network_set(&r(Pin::Latest)), None);
        assert!(both.network_set(&r(Pin::Version(2))).is_some());
    }
}

#[test]
fn a_set_named_by_many_references_is_inlined_once() {
    // Many rules name the same set version: it is copied into the bundle
    // once, and every reference is pinned to it.
    let mut doc = policy(json!(1)).into_document();
    let template = doc.rule_sets[0].rules[0].clone();
    for n in 10..60 {
        let mut r = template.clone();
        r.id = crate::test_util::rule_id(n);
        doc.rule_sets[0].rules.push(r);
    }
    let policy = doc.validate().unwrap();
    let cat = catalogue();
    let (bundle, _) = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let inlined: Vec<(LibraryId, u32)> = bundle
        .body
        .libraries()
        .iter()
        .map(|l| (l.id, l.resolved_version))
        .collect();
    assert_eq!(inlined.len(), 1, "{inlined:?}");
    assert_eq!(inlined[0].1, 1);
    let mut pins = 0;
    for rule in &bundle.body.document().rule_sets[0].rules {
        if rule.scope.is_some() {
            pins += 1;
        }
    }
    assert_eq!(pins, 51);
}
