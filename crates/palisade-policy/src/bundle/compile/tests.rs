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
        facts: Facts::default(),
        admin: None,
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
    let Compiled { bytes: a, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    let Compiled { bytes: b, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    assert_eq!(a, b);
    assert_eq!(decode_header(&a, &BundleLimits::DEFAULT).unwrap(), header());
}

#[test]
fn only_the_pinned_version_of_a_set_is_inlined() {
    let (policy, cat) = (policy(json!(1)), catalogue());
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
        let Compiled { bytes, .. } =
            compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
        Ok(Compiled { bundle, .. }) => {
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
        Ok(Compiled { bundle, .. }) => {
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
        Ok(Compiled { bytes, .. }) => {
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
    let Compiled { bundle, .. } =
        compile(&source(&plain, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
    let Compiled { bytes, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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
        let Compiled { bundle, .. } = compile(&src, header(), &BundleLimits::DEFAULT).unwrap();
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
        let Compiled { bundle, .. } =
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
    let Compiled { bundle, .. } =
        compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
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

/// A policy whose only allow trusts a whole publisher that the facts
/// restrict: a `restricted_publisher_broad` error (#40).
fn broad_publisher() -> (ValidatedPolicy, Facts) {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(
            1,
            crate::test_util::publisher("OS Publisher"),
        )))
        .validate();
    let facts = Facts {
        restricted_publishers: vec!["OS Publisher".to_owned()],
        ..Facts::default()
    };
    (policy, facts)
}

#[test]
fn an_error_finding_stops_the_compile() {
    let (policy, facts) = broad_publisher();
    let cat = catalogue();
    let src = Source {
        facts,
        ..source(&policy, &cat)
    };
    let err = compile(&src, header(), &BundleLimits::DEFAULT).unwrap_err();
    let CompileError::Blocked(findings) = &err else {
        panic!("{err}");
    };
    assert!(
        findings
            .iter()
            .any(|f| f.code == analysis::FindingCode::RestrictedPublisherBroad),
        "{findings:?}"
    );
    assert!(
        err.to_string().contains("restricted_publisher_broad"),
        "{err}"
    );
    // An override without a reason is no override.
    let blank = Source {
        admin: Some(Override {
            actor: "admin@example.org".to_owned(),
            reason: "  ".to_owned(),
        }),
        ..src.clone()
    };
    assert!(matches!(
        compile(&blank, header(), &BundleLimits::DEFAULT),
        Err(CompileError::Blocked(_))
    ));
}

#[test]
fn an_override_compiles_and_is_recorded() {
    let (policy, facts) = broad_publisher();
    let cat = catalogue();
    let src = Source {
        facts,
        admin: Some(Override {
            actor: "admin@example.org".to_owned(),
            reason: "vendor tooling, ticket 42".to_owned(),
        }),
        ..source(&policy, &cat)
    };
    let compiled = compile(&src, header(), &BundleLimits::DEFAULT).unwrap();
    match &compiled.gate {
        Gate::Overridden {
            actor,
            reason,
            findings,
        } => {
            assert_eq!(actor, "admin@example.org");
            assert_eq!(reason, "vendor tooling, ticket 42");
            assert!(!findings.is_empty());
        }
        other => panic!("{other:?}"),
    }
    // The override changes nothing in the bundle itself.
    let plain = compile(&source(&policy, &cat), header(), &BundleLimits::DEFAULT).unwrap();
    assert_eq!(plain.gate, Gate::Pass);
    assert_eq!(plain.bytes, compiled.bytes);
}

#[test]
fn a_generated_at_the_assistant_cannot_read_fails_the_compile() {
    let (policy, cat) = (policy(json!(1)), catalogue());
    let mut h = header();
    h.generated_at = i64::MAX;
    let err = compile(&source(&policy, &cat), h, &BundleLimits::DEFAULT).unwrap_err();
    assert!(
        matches!(&err, CompileError::Invalid(why) if why.contains("generated_at")),
        "{err}"
    );
}

// --- First-class hash sets (#368) ------------------------------------------

const HASHES: &str = "01936b2e-8c4a-7004-9f21-000000000068";

fn hash_lib(version: u32, digits: &[char]) -> Library {
    let hashes: Vec<String> = digits
        .iter()
        .map(|c| std::iter::repeat_n(*c, 64).collect())
        .collect();
    serde_json::from_value(json!({
        "id": HASHES, "version": version, "name": "Approved", "realm": "global",
        "content": {"kind": "hash_set", "field": "hash.sha256", "hashes": hashes},
    }))
    .unwrap()
}

fn set_ref(version: u32) -> crate::library::LibraryRef {
    crate::library::LibraryRef {
        id: serde_json::from_value(json!(HASHES)).unwrap(),
        pin: crate::library::Pin::Version(version),
    }
}

/// An allow for hashes in the set at `version`, on `field`.
fn set_policy(field: crate::model::Field, version: u32, negated: bool) -> ValidatedPolicy {
    let mut doc: PolicyDocument = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::mixed(1).rule(RuleBuilder::allow(1, hash('f'))))
        .build();
    doc.rule_sets[0].rules[0].match_ = crate::model::Match::Criterion(
        crate::model::Criterion::in_hash_set(field, set_ref(version), negated),
    );
    doc.validate().unwrap()
}

fn compile_set(policy: &ValidatedPolicy, libs: Vec<Library>) -> Result<Compiled, CompileError> {
    let catalogue = Catalogue::new(libs).unwrap();
    compile(
        &Source {
            policy,
            catalogue: &catalogue,
            from: Visibility::Global,
            sources: SourceRevisions::default(),
            facts: crate::analysis::Facts::default(),
            admin: None,
        },
        header(),
        &BundleLimits::DEFAULT,
    )
}

/// The outcome for an object with hash `c`, through the loaded bundle.
fn loaded_outcome(bytes: &[u8], c: char) -> crate::decision::Outcome {
    let loaded = match crate::bundle::load(bytes, &BundleLimits::DEFAULT, None) {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let object = facts().sha256(c).build();
    let vars = PathVariables::new();
    let ctx = EvaluationContext::default();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &object,
        variables: &vars,
        context: &ctx,
    };
    loaded
        .snapshot()
        .evaluator()
        .evaluate(&subject, TRACE)
        .outcome()
}

#[test]
fn a_hash_set_is_inlined_as_raw_digests_and_matches() {
    let policy = set_policy(crate::model::Field::HashSha256, 2, false);
    let c = compile_set(&policy, vec![hash_lib(1, &['a']), hash_lib(2, &['c', 'b'])]).unwrap();
    let libs = c.bundle.body.libraries();
    assert_eq!(libs.len(), 1, "only the pinned version");
    assert_eq!(libs[0].resolved_version, 2);
    let SetContent::HashSet { field, digests } = &libs[0].content else {
        panic!("{libs:?}")
    };
    assert_eq!(*field, crate::model::Field::HashSha256);
    assert_eq!(digests.as_bytes().len(), 64);
    assert_eq!(&digests.as_bytes()[..32], &[0xbb; 32], "sorted");
    assert!(
        c.bundle
            .body
            .source_revisions()
            .libraries
            .contains(&(set_ref(2).id, 2))
    );
    use crate::decision::Outcome;
    assert_eq!(loaded_outcome(&c.bytes, 'b'), Outcome::Allowed);
    assert_eq!(loaded_outcome(&c.bytes, 'c'), Outcome::Allowed);
    // Version 1's entry is not in version 2.
    assert_eq!(loaded_outcome(&c.bytes, 'a'), Outcome::Blocked);
}

#[test]
fn a_set_that_does_not_resolve_does_not_compile() {
    let policy = set_policy(crate::model::Field::HashSha256, 3, false);
    assert!(matches!(
        compile_set(&policy, vec![hash_lib(1, &['a'])]),
        Err(CompileError::UnresolvedSet { .. })
    ));
    // Another kind of library at that ID and version.
    let other: Library = serde_json::from_value(json!({
        "id": HASHES, "version": 3, "name": "Office", "realm": "global",
        "content": {"kind": "network_set", "entries": ["10.0.0.0/8"]},
    }))
    .unwrap();
    assert!(matches!(
        compile_set(&policy, vec![other]),
        Err(CompileError::UnresolvedSet { .. })
    ));
}

#[test]
fn a_missing_or_wrong_set_never_matches_an_allow() {
    use crate::decision::Outcome;
    let ok = compile_set(
        &set_policy(crate::model::Field::HashSha256, 1, false),
        vec![hash_lib(1, &['a'])],
    )
    .unwrap();
    // The bundle with its set removed, then with the set at another
    // version, on another field, or of another kind: the allow never
    // applies.
    let rebuild = |libraries: Vec<InlineLibrary>| {
        let body = Body::new(
            ok.bundle.body.document().clone(),
            libraries,
            SourceRevisions::default(),
        )
        .unwrap();
        PolicyBundle::new(header(), body).to_bytes().unwrap()
    };
    let inlined = ok.bundle.body.libraries()[0].clone();
    let SetContent::HashSet { digests, .. } = inlined.content.clone() else {
        panic!()
    };
    let cases = [
        Vec::new(),
        vec![InlineLibrary {
            resolved_version: 2,
            ..inlined.clone()
        }],
        vec![InlineLibrary {
            content: SetContent::HashSet {
                field: crate::model::Field::HashAuthenticodeSha256,
                digests,
            },
            ..inlined.clone()
        }],
        vec![InlineLibrary {
            content: SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]),
            ..inlined.clone()
        }],
    ];
    for libs in cases {
        assert_eq!(
            loaded_outcome(&rebuild(libs.clone()), 'a'),
            Outcome::Blocked,
            "{libs:?}"
        );
    }
    assert_eq!(
        loaded_outcome(&rebuild(vec![inlined]), 'a'),
        Outcome::Allowed
    );
    // An allow on `not_member_of` alone identifies nothing: refused.
    let mut doc = ok.bundle.body.document().clone();
    let crate::model::Match::Criterion(c) = &mut doc.rule_sets[0].rules[0].match_ else {
        panic!()
    };
    c.operator = crate::model::Operator::NotMemberOf;
    let errors = doc.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code.as_str() == "no_identity_anchor"),
        "{errors:?}"
    );
}

#[test]
fn a_set_test_is_unknown_with_a_note_until_bound() {
    use crate::ops::{CompiledCriterion, Note, Tri};
    let c =
        crate::model::Criterion::in_hash_set(crate::model::Field::HashSha256, set_ref(1), false);
    let mut compiled = CompiledCriterion::compile(&c).unwrap();
    assert_eq!(compiled.set(), Some(set_ref(1)));
    let object = facts().sha256('a').build();
    let vars = PathVariables::new();
    let ctx = EvaluationContext::default();
    let eval_ctx = crate::ops::EvalContext {
        action: crate::model::ActionKind::Allow,
        variables: &vars,
        context: &ctx,
    };
    let e = compiled.eval(&object, &eval_ctx);
    assert_eq!(e.result, Tri::Unknown);
    assert!(e.notes.contains(Note::SetUnresolved));
    let catalogue = Catalogue::new(vec![hash_lib(1, &['a'])]).unwrap();
    compiled.bind_set(&CatalogueLibrary {
        catalogue: &catalogue,
        from: Visibility::Global,
    });
    assert_eq!(compiled.eval(&object, &eval_ctx).result, Tri::Match);
    // A malformed fact is unknown, not a miss.
    let bad = facts().with(crate::model::Field::HashSha256, "abc").build();
    let e = compiled.eval(&bad, &eval_ctx);
    assert_eq!(e.result, Tri::Unknown);
    assert!(e.notes.contains(Note::FactMalformed));
    // An unpinned reference is never bound by a catalogue.
    let latest = crate::library::LibraryRef {
        pin: crate::library::Pin::Latest,
        ..set_ref(1)
    };
    let lib = CatalogueLibrary {
        catalogue: &catalogue,
        from: Visibility::Global,
    };
    assert!(
        lib.hash_set(&latest, crate::model::Field::HashSha256)
            .is_none()
    );
    assert!(
        BundleSets::default()
            .hash_set(&latest, crate::model::Field::HashSha256)
            .is_none()
    );
}

#[test]
fn set_criteria_are_validated() {
    use crate::model::{Criterion, Field, Match, Operator};
    let check = |c: Criterion| {
        let mut doc: PolicyDocument = PolicyBuilder::new()
            .rule_set(RuleSetBuilder::mixed(1).rule(RuleBuilder::deny(1, hash('f'))))
            .build();
        doc.rule_sets[0].rules[0].match_ = Match::Criterion(c);
        doc.validate()
            .err()
            .map(|e| e.iter().map(|e| e.code.as_str()).collect::<Vec<_>>())
    };
    assert_eq!(
        check(Criterion::in_hash_set(Field::HashSha256, set_ref(1), false)),
        None
    );
    // Unpinned.
    let latest = crate::library::LibraryRef {
        pin: crate::library::Pin::Latest,
        ..set_ref(1)
    };
    assert_eq!(
        check(Criterion::in_hash_set(Field::HashSha256, latest, false)),
        Some(vec!["unresolved_ref"])
    );
    // A field that takes no set, another operator, or values as well.
    assert!(check(Criterion::in_hash_set(Field::HashSha1, set_ref(1), false)).is_some());
    let mut equals = Criterion::in_hash_set(Field::HashSha256, set_ref(1), false);
    equals.operator = Operator::Equals;
    assert!(check(equals).is_some());
    let mut with_values = Criterion::in_hash_set(Field::HashSha256, set_ref(1), false);
    with_values.values = vec!["a".repeat(64)];
    assert_eq!(check(with_values), Some(vec!["invalid_value_count"]));
}
