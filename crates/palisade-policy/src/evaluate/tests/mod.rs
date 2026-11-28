//! Tests of the evaluation pipeline (#35).
//!
//! The documents are written as JSON and validated, so every case is a
//! policy a real author could write. `facts()` describes the object every
//! case decides: it has the SHA-256 `a`×64, the publisher `Example Ltd`, the
//! path `C:\Tools\Sub\tool.exe` (not user-writable), and a file version that
//! is not a version.

use proptest::prelude::*;

use super::*;
use crate::decision::{Outcome, ReasonCode};
use crate::facts::{PathFact, SignatureSource, SignerFact, SignerStatus};
use crate::model::{ActionKind, Field, PolicyDocument, PrecedenceModel};
use palisade_core::path::VolumeMap;

const TRACE: TraceId = TraceId([7; 16]);
const POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

/// The ID of rule `n`: a UUIDv7 whose time grows with `n`.
fn rule_id(n: u32) -> String {
    format!("01936b2e-{:04x}-7b3d-9f21-0a1b2c3d4e61", n)
}

fn set_id(n: u32) -> String {
    format!("01936b2e-8c4a-7b3d-9f21-0a1b2c3d{:04x}", n)
}

/// A criterion as JSON.
fn crit(field: &str, operator: &str, value: &str) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": [value]}})
}

fn hash_a() -> serde_json::Value {
    crit("hash.sha256", "equals", &sha('a'))
}

fn hash_b() -> serde_json::Value {
    crit("hash.sha256", "equals", &sha('b'))
}

fn publisher() -> serde_json::Value {
    crit("signer.publisher", "equals", "Example Ltd")
}

fn folder() -> serde_json::Value {
    crit("path.directory", "starts_with", "C:\\Tools")
}

/// A rule with ID `n`, a match tree and an action, plus any extra fields.
fn rule(n: u32, tree: serde_json::Value, action: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": rule_id(n),
        "name": format!("Rule {n}"),
        "object_types": ["executable", "installer"],
        "match": tree,
        "action": action,
    })
}

fn with(mut rule: serde_json::Value, key: &str, value: serde_json::Value) -> serde_json::Value {
    rule.as_object_mut().unwrap().insert(key.to_owned(), value);
    rule
}

fn allow() -> serde_json::Value {
    serde_json::json!({"type": "allow"})
}

fn deny() -> serde_json::Value {
    serde_json::json!({"type": "deny"})
}

fn audit() -> serde_json::Value {
    serde_json::json!({"type": "audit"})
}

fn trust() -> serde_json::Value {
    serde_json::json!({"type": "trust_source", "mode": "direct", "scope_paths": ["C:\\Apps"]})
}

/// A rule set: `(number, kind, mandatory, read_only, rules)`.
type Set = (u32, &'static str, bool, bool, Vec<serde_json::Value>);

fn document(model: &str, options: serde_json::Value, sets: Vec<Set>) -> PolicyDocument {
    let rule_sets: Vec<serde_json::Value> = sets
        .iter()
        .map(|(n, kind, mandatory, read_only, rules)| {
            serde_json::json!({
                "id": set_id(*n),
                "name": format!("Set {n}"),
                "kind": kind,
                "mandatory": mandatory,
                "read_only": read_only,
                "rules": rules,
            })
        })
        .collect();
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": POLICY,
            "name": "Precedence",
            "revision": 3,
            "mode": "enforce",
            "precedence_model": model,
            "precedence_options": options,
            "rule_sets": sets.iter().map(|s| set_id(s.0)).collect::<Vec<_>>(),
        },
        "rule_sets": rule_sets,
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn validated(doc: PolicyDocument) -> ValidatedPolicy {
    doc.validate().unwrap_or_else(|e| panic!("{e:#?}"))
}

fn facts() -> ObjectFacts {
    ObjectFacts::new()
        // The origin collection ran and found nothing (#39).
        .with_origin([])
        .with(Field::HashSha256, sha('a'))
        .with(Field::MetaFileVersion, "unknown build")
        .with_path(
            PathFact::new("C:\\Tools\\Sub\\tool.exe", &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed),
        )
        .with_signers(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some("Example Ltd".to_owned()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }])
}

fn decide_with(policy: &ValidatedPolicy, facts: &ObjectFacts, object_type: ObjectType) -> Decision {
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    Evaluator::new(policy).unwrap().evaluate(
        &Subject {
            object_type,
            facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    )
}

fn decide(policy: &ValidatedPolicy) -> Decision {
    decide_with(policy, &facts(), ObjectType::Executable)
}

/// The rule numbers of a list of refs.
fn numbers(refs: &[RuleRef]) -> Vec<u32> {
    refs.iter()
        .map(|r| {
            let text = r.rule_id.to_string();
            u32::from_str_radix(&text[9..13], 16).unwrap()
        })
        .collect()
}

fn winner(d: &Decision) -> Option<u32> {
    d.matched_rule().map(|r| numbers(&[*r])[0])
}

const MODELS: [&str; 5] = [
    "deny_wins",
    "allow_wins",
    "specificity",
    "first_match",
    "priority",
];

/// Gives every deciding rule an order and a priority, so the same rules
/// are valid under every model.
fn ordered(rules: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            let i = u32::try_from(i).unwrap();
            let r = with(r, "order", (200_000 + i).into());
            with(r, "priority", i.into())
        })
        .collect()
}

#[test]
fn a_mandatory_deny_beats_everything_under_every_model() {
    for model in MODELS {
        let doc = document(
            model,
            serde_json::json!({}),
            vec![
                (
                    1,
                    "mixed",
                    false,
                    false,
                    ordered(vec![
                        rule(1, hash_a(), allow()),
                        rule(
                            2,
                            publisher(),
                            serde_json::json!({
                                "type": "allow_elevated",
                                "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e90",
                                "condition": "always"
                            }),
                        ),
                        rule(3, hash_a(), trust()),
                        rule(4, hash_a(), audit()),
                    ]),
                ),
                (2, "blocklist", true, true, vec![rule(5, folder(), deny())]),
            ],
        );
        let d = decide(&validated(doc));
        assert_eq!(d.outcome(), Outcome::Blocked, "{model}");
        assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny, "{model}");
        assert_eq!(winner(&d), Some(5), "{model}");
        // Every rule that would have decided or granted is listed.
        assert_eq!(numbers(d.overridden()), vec![1, 2, 3], "{model}");
        assert_eq!(numbers(d.annotations()), vec![4], "{model}");
        assert!(d.directives().trust_sources.is_empty());
        assert!(d.directives().elevation.is_none());
    }
}

#[test]
fn a_mandatory_deny_beats_an_exclusion() {
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (
                1,
                "mixed",
                false,
                false,
                vec![with(
                    rule(1, hash_a(), serde_json::json!({"type": "ignore"})),
                    "object_types",
                    serde_json::json!(["library"]),
                )],
            ),
            (
                2,
                "blocklist",
                true,
                false,
                vec![with(
                    rule(2, hash_a(), deny()),
                    "object_types",
                    serde_json::json!(["library"]),
                )],
            ),
        ],
    );
    let d = decide_with(&validated(doc), &facts(), ObjectType::Library);
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
    assert_eq!(numbers(d.overridden()), vec![1]);
}

#[test]
fn an_exclusion_decides_before_the_model() {
    let doc = document(
        "allow_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(1, hash_a(), serde_json::json!({"type": "ignore"})),
                    "object_types",
                    serde_json::json!(["library"]),
                ),
                with(
                    rule(2, hash_a(), allow()),
                    "object_types",
                    serde_json::json!(["library"]),
                ),
                with(
                    rule(3, hash_a(), deny()),
                    "object_types",
                    serde_json::json!(["library"]),
                ),
            ],
        )],
    );
    let d = decide_with(&validated(doc), &facts(), ObjectType::Library);
    assert_eq!(d.outcome(), Outcome::Ignored);
    assert_eq!(winner(&d), Some(1));
    assert_eq!(numbers(d.overridden()), vec![2, 3]);
}

#[test]
fn several_mandatory_denies_choose_the_most_specific() {
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (1, "blocklist", true, false, vec![rule(1, folder(), deny())]),
            (2, "blocklist", true, false, vec![rule(2, hash_a(), deny())]),
        ],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(2));
    assert_eq!(numbers(d.overridden()), vec![1]);
}

#[test]
fn nothing_matching_is_the_implicit_deny() {
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                rule(1, hash_b(), allow()),
                rule(2, hash_a(), audit()),
                rule(3, hash_a(), trust()),
                rule(4, hash_a(), serde_json::json!({"type": "defer"})),
            ],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    assert_eq!(d.matched_rule(), None);
    assert_eq!(numbers(d.annotations()), vec![2]);
    // The trust source matched but cannot let the object run.
    assert_eq!(numbers(d.overridden()), vec![3]);
    assert!(d.directives().trust_sources.is_empty());
}

#[test]
fn trust_sources_attach_only_to_an_allowed_object() {
    let rules = |decision| {
        vec![
            rule(1, hash_a(), decision),
            rule(2, hash_a(), trust()),
            rule(3, publisher(), trust()),
        ]
    };
    let allowed = decide(&validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, rules(allow()))],
    )));
    assert_eq!(allowed.outcome(), Outcome::Allowed);
    let grants: Vec<RuleRef> = allowed
        .directives()
        .trust_sources
        .iter()
        .map(|g| g.rule)
        .collect();
    assert_eq!(numbers(&grants), vec![2, 3]);
    assert!(allowed.overridden().is_empty());

    let blocked = decide(&validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, rules(deny()))],
    )));
    assert_eq!(blocked.outcome(), Outcome::Blocked);
    assert!(blocked.directives().trust_sources.is_empty());
    assert_eq!(numbers(blocked.overridden()), vec![2, 3]);
}

#[test]
fn every_model_names_its_winner_and_every_overridden_rule() {
    // A hash allow, a publisher deny and a folder allow all match.
    let rules = || {
        ordered(vec![
            rule(1, folder(), allow()),
            rule(2, publisher(), deny()),
            rule(3, hash_a(), allow()),
            rule(4, hash_a(), audit()),
        ])
    };
    // (model, options, winner)
    let cases = [
        ("deny_wins", serde_json::json!({}), 2),
        ("allow_wins", serde_json::json!({}), 3),
        ("specificity", serde_json::json!({}), 3),
        // Orders 200000, 200001, 200002: the folder allow is first.
        ("first_match", serde_json::json!({}), 1),
        // Priorities 0, 1, 2: the lowest wins, or the highest.
        ("priority", serde_json::json!({}), 1),
        (
            "priority",
            serde_json::json!({"priority_direction": "higher_wins"}),
            3,
        ),
    ];
    for (model, options, expected) in cases {
        let doc = document(model, options, vec![(1, "mixed", false, false, rules())]);
        let d = decide(&validated(doc));
        assert_eq!(winner(&d), Some(expected), "{model}");
        let mut others: Vec<u32> = vec![1, 2, 3];
        others.retain(|n| *n != expected);
        assert_eq!(numbers(d.overridden()), others, "{model}");
        assert_eq!(numbers(d.annotations()), vec![4], "{model}");
    }
}

#[test]
fn first_match_falls_through_a_defer() {
    // The defer comes first, but has no opinion, so the next rule decides.
    let doc = document(
        "first_match",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(1, hash_a(), serde_json::json!({"type": "defer"})),
                    "order",
                    100_001.into(),
                ),
                with(rule(2, hash_a(), deny()), "order", 100_002.into()),
                with(rule(3, hash_a(), allow()), "order", 100_003.into()),
            ],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(2));
    assert_eq!(numbers(d.overridden()), vec![3]);
}

#[test]
fn first_match_puts_curated_rule_sets_first() {
    let sets = || {
        vec![
            (
                1,
                "allowlist",
                false,
                false,
                vec![with(rule(1, hash_a(), allow()), "order", 100_001.into())],
            ),
            (
                2,
                "blocklist",
                false,
                true,
                vec![with(rule(2, hash_a(), deny()), "order", 900_000.into())],
            ),
        ]
    };
    let d = decide(&validated(document(
        "first_match",
        serde_json::json!({}),
        sets(),
    )));
    assert_eq!(winner(&d), Some(2));
    let d = decide(&validated(document(
        "first_match",
        serde_json::json!({"curated_first": false}),
        sets(),
    )));
    assert_eq!(winner(&d), Some(1));
}

#[test]
fn allow_wins_granularity_keeps_a_denied_file_in_an_allowed_folder_denied() {
    let rules = || {
        vec![
            rule(1, folder(), allow()),
            rule(
                2,
                crit("path.full", "equals", "C:\\Tools\\Sub\\tool.exe"),
                deny(),
            ),
        ]
    };
    let plain = decide(&validated(document(
        "allow_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, rules())],
    )));
    assert_eq!(plain.outcome(), Outcome::Allowed);
    let granular = decide(&validated(document(
        "allow_wins",
        serde_json::json!({"granularity_tiebreak": true}),
        vec![(1, "mixed", false, false, rules())],
    )));
    assert_eq!(granular.outcome(), Outcome::Blocked);
    assert_eq!(numbers(granular.overridden()), vec![1]);
}

#[test]
fn unknown_facts_follow_the_deny_options() {
    // The object has no `meta.product_name`, so this tree is `Unknown`.
    let unknown_tree =
        serde_json::json!({"all": [publisher(), crit("meta.product_name", "equals", "Tool")]});
    let case = |options: serde_json::Value| {
        let mut action = deny();
        action
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        decide(&validated(document(
            "deny_wins",
            serde_json::json!({}),
            vec![(
                1,
                "mixed",
                false,
                false,
                vec![
                    rule(1, unknown_tree.clone(), action),
                    rule(2, hash_a(), allow()),
                ],
            )],
        )))
    };
    // Default: an unknown fact does not block, so the allow decides.
    let d = case(serde_json::json!({}));
    assert_eq!(winner(&d), Some(2));
    assert!(d.overridden().is_empty());
    // unknown_as: match fails closed.
    let d = case(serde_json::json!({"unknown_as": "match"}));
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(1));
    assert_eq!(numbers(d.overridden()), vec![2]);

    // An allow rule never allows on an unknown fact.
    let d = decide(&validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![rule(1, unknown_tree.clone(), allow())],
        )],
    )));
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
}

#[test]
fn unparseable_versions_follow_on_unparseable() {
    // The object's file version is not a version.
    let old =
        serde_json::json!({"all": [publisher(), crit("meta.file_version", "version_lt", "2.0")]});
    let case = |options: serde_json::Value| {
        let mut action = deny();
        action
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        decide(&validated(document(
            "deny_wins",
            serde_json::json!({}),
            vec![(
                1,
                "mixed",
                false,
                false,
                vec![rule(1, old.clone(), action), rule(2, hash_a(), allow())],
            )],
        )))
    };
    assert_eq!(winner(&case(serde_json::json!({}))), Some(2));
    assert_eq!(
        winner(&case(serde_json::json!({"on_unparseable": "match"}))),
        Some(1)
    );
    // unknown_as covers every unknown, unparseable versions included.
    assert_eq!(
        winner(&case(serde_json::json!({"unknown_as": "match"}))),
        Some(1)
    );
}

#[test]
fn mandatory_denies_follow_the_same_unknown_options() {
    let unknown_tree =
        serde_json::json!({"all": [hash_a(), crit("meta.product_name", "equals", "Tool")]});
    let case = |unknown_as: &str| {
        decide(&validated(document(
            "allow_wins",
            serde_json::json!({}),
            vec![
                (
                    1,
                    "allowlist",
                    false,
                    false,
                    vec![rule(1, hash_a(), allow())],
                ),
                (
                    2,
                    "blocklist",
                    true,
                    false,
                    vec![rule(
                        2,
                        unknown_tree.clone(),
                        serde_json::json!({"type": "deny", "unknown_as": unknown_as}),
                    )],
                ),
            ],
        )))
    };
    assert_eq!(case("no_match").outcome(), Outcome::Allowed);
    let d = case("match");
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
}

#[test]
fn object_types_and_disabled_rules_are_respected() {
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(1, hash_a(), deny()),
                    "object_types",
                    serde_json::json!(["installer"]),
                ),
                with(rule(2, hash_a(), deny()), "enabled", false.into()),
                rule(3, hash_a(), allow()),
            ],
        )],
    );
    let policy = validated(doc);
    let d = decide(&policy);
    assert_eq!(winner(&d), Some(3));
    assert!(d.overridden().is_empty());
    let d = decide_with(&policy, &facts(), ObjectType::Installer);
    assert_eq!(winner(&d), Some(1));
}

#[test]
fn rule_sets_the_policy_does_not_reference_are_ignored() {
    let mut doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![
            (
                1,
                "allowlist",
                false,
                false,
                vec![rule(1, hash_a(), allow())],
            ),
            (2, "blocklist", true, false, vec![rule(2, hash_a(), deny())]),
        ],
    );
    doc.policy.rule_sets.truncate(1);
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(1));
}

#[test]
fn the_decision_json_lists_overridden_rules_and_grants() {
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                rule(1, hash_a(), allow()),
                rule(2, folder(), allow()),
                rule(3, hash_a(), trust()),
                rule(4, hash_a(), audit()),
            ],
        )],
    );
    let d = decide(&validated(doc));
    let value = serde_json::to_value(&d).unwrap();
    assert_eq!(value["matched_rule"]["rule_id"], rule_id(1));
    assert_eq!(value["overridden"][0]["rule_id"], rule_id(2));
    assert_eq!(value["annotations"][0]["rule_id"], rule_id(4));
    assert_eq!(
        value["directives"]["trust_sources"][0]["rule"]["rule_id"],
        rule_id(3)
    );
    assert_eq!(value["directives"]["trust_sources"][0]["mode"], "direct");
}

// Property tests over generated policies.

/// The match trees the property tests give generated rules: each is one
/// criterion, so whether it matches [`facts`] is known, and together they
/// span several specificity tiers, including two directory depths.
fn anchors() -> [(serde_json::Value, bool); 6] {
    [
        (hash_a(), true),
        (publisher(), true),
        (
            crit("path.full", "equals", "C:\\Tools\\Sub\\tool.exe"),
            true,
        ),
        (folder(), true),
        (
            crit("path.directory", "starts_with", "C:\\Tools\\Sub"),
            true,
        ),
        (hash_b(), false),
    ]
}

/// Replaces every generated rule's tree with the anchor `picks` chooses
/// for it, and returns the IDs of the rules whose tree matches.
fn anchor(doc: &mut PolicyDocument, picks: &[usize]) -> std::collections::BTreeSet<RuleId> {
    let anchors = anchors();
    let mut matching = std::collections::BTreeSet::new();
    for (rule, pick) in doc
        .rule_sets
        .iter_mut()
        .flat_map(|s| s.rules.iter_mut())
        .zip(picks.iter().cycle())
    {
        let (tree, matches) = &anchors[pick % anchors.len()];
        rule.match_ = serde_json::from_value(tree.clone()).unwrap();
        if *matches {
            matching.insert(rule.id);
        }
    }
    matching
}

/// Whether a rule of a referenced rule set matches the object and applies
/// to its type.
fn applies(
    doc: &PolicyDocument,
    matching: &std::collections::BTreeSet<RuleId>,
    t: ObjectType,
    keep: impl Fn(&RuleSet, &Rule) -> bool,
) -> bool {
    doc.rule_sets
        .iter()
        .filter(|s| doc.policy.rule_sets.contains(&s.id))
        .flat_map(|s| s.rules.iter().map(move |r| (s, r)))
        .any(|(s, r)| {
            r.enabled
                && matching.contains(&r.id)
                && (r.object_types.is_empty() || r.object_types.contains(&t))
                && keep(s, r)
        })
}

fn shuffled(doc: &PolicyDocument, seed: u64) -> PolicyDocument {
    let mut doc = doc.clone();
    let mut s = seed | 1;
    let mut next = move |n: usize| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        usize::try_from(s % u64::try_from(n.max(1)).unwrap()).unwrap()
    };
    let len = doc.policy.rule_sets.len();
    for i in (1..len).rev() {
        doc.policy.rule_sets.swap(i, next(i + 1));
    }
    let len = doc.rule_sets.len();
    for i in (1..len).rev() {
        doc.rule_sets.swap(i, next(i + 1));
    }
    for set in &mut doc.rule_sets {
        let len = set.rules.len();
        for i in (1..len).rev() {
            set.rules.swap(i, next(i + 1));
        }
    }
    doc
}

fn object_type() -> impl Strategy<Value = ObjectType> {
    proptest::sample::select(ObjectType::ALL.to_vec())
}

fn picks() -> impl Strategy<Value = Vec<usize>> {
    proptest::collection::vec(0usize..6, 1..12)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The decision does not depend on the order of rule sets or rules,
    /// under any model and options, and evaluating twice gives the same
    /// decision. The rules span several specificity tiers, so
    /// `specificity` and `granularity_tiebreak` make real choices.
    #[test]
    fn decisions_do_not_depend_on_list_order(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        seed in any::<u64>(),
        t in object_type(),
    ) {
        let mut doc = doc;
        anchor(&mut doc, &picks);
        let policy = doc.clone().validate().unwrap();
        let first = decide_with(&policy, &facts(), t);
        prop_assert_eq!(&decide_with(&policy, &facts(), t), &first);
        let other = shuffled(&doc, seed).validate().unwrap();
        prop_assert_eq!(&decide_with(&other, &facts(), t), &first);
    }

    /// Each model in turn, on the same generated rules: the shuffle
    /// invariance above holds for every one of the five.
    #[test]
    fn every_model_is_order_independent_on_the_same_rules(
        doc in crate::model::arbitrary::document(),
        options in crate::model::arbitrary::precedence_options(),
        picks in picks(),
        seed in any::<u64>(),
        t in object_type(),
    ) {
        for model in [
            PrecedenceModel::DenyWins,
            PrecedenceModel::AllowWins,
            PrecedenceModel::Specificity,
            PrecedenceModel::FirstMatch,
            PrecedenceModel::Priority,
        ] {
            let mut doc = doc.clone();
            doc.policy.precedence_model = model;
            doc.policy.precedence_options = options;
            crate::model::arbitrary::fit_to_model(model, &mut doc.rule_sets);
            anchor(&mut doc, &picks);
            let policy = doc.clone().validate().unwrap();
            let first = decide_with(&policy, &facts(), t);
            let other = shuffled(&doc, seed).validate().unwrap();
            prop_assert_eq!(&decide_with(&other, &facts(), t), &first, "{:?}", model);
        }
    }

    /// A matching mandatory deny always blocks, whatever else matches and
    /// whatever the model and options (ADR 0004, #125).
    #[test]
    fn a_matching_mandatory_deny_always_blocks(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        t in object_type(),
    ) {
        let mut doc = doc;
        let matching = anchor(&mut doc, &picks);
        let policy = doc.clone().validate().unwrap();
        let d = decide_with(&policy, &facts(), t);
        if applies(&doc, &matching, t, |s, _| s.mandatory) {
            prop_assert_eq!(d.outcome(), Outcome::Blocked);
            prop_assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
        } else {
            prop_assert_ne!(d.reason_code(), ReasonCode::MandatoryDeny);
        }
    }

    /// Under `deny_wins`, a matching deny always beats every allow
    /// (ADR 0004). Only a mandatory deny or an exclusion decides first.
    #[test]
    fn under_deny_wins_a_matching_deny_always_blocks(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        t in object_type(),
    ) {
        let mut doc = doc;
        doc.policy.precedence_model = PrecedenceModel::DenyWins;
        let matching = anchor(&mut doc, &picks);
        let policy = doc.clone().validate().unwrap();
        let d = decide_with(&policy, &facts(), t);
        let deny = applies(&doc, &matching, t, |_, r| r.action.kind() == ActionKind::Deny);
        if deny && d.outcome() != Outcome::Ignored {
            prop_assert_eq!(d.outcome(), Outcome::Blocked);
        }
        if d.outcome() == Outcome::Allowed {
            prop_assert!(!deny);
        }
    }

    /// Under `allow_wins` without granularity, a matching allow decides
    /// unless a mandatory deny or an exclusion does first.
    #[test]
    fn under_allow_wins_a_matching_allow_decides(
        doc in crate::model::arbitrary::document(),
        picks in picks(),
        t in object_type(),
    ) {
        let mut doc = doc;
        doc.policy.precedence_model = PrecedenceModel::AllowWins;
        doc.policy.precedence_options.granularity_tiebreak = false;
        let matching = anchor(&mut doc, &picks);
        let policy = doc.clone().validate().unwrap();
        let d = decide_with(&policy, &facts(), t);
        let allow = applies(&doc, &matching, t, |s, r| !s.mandatory && r.action.kind().permits());
        if allow && !matches!(d.reason_code(), ReasonCode::MandatoryDeny | ReasonCode::Exclusion) {
            prop_assert_eq!(d.outcome(), Outcome::Allowed);
        }
    }
}

mod modes;
mod scopes;

/// A catch-all with ID `n`: matches every object, with `action`.
fn catch_all(n: u32, action: serde_json::Value) -> serde_json::Value {
    let r = rule(n, serde_json::json!({"all": []}), action);
    let r = with(r, "catch_all", true.into());
    let r = with(r, "name", "Default".into());
    let r = with(r, "order", 999_990.into());
    with(r, "priority", i32::MAX.into())
}

#[test]
fn a_catch_all_decides_only_what_no_other_rule_matched_under_every_model() {
    for model in MODELS {
        let options = serde_json::json!({});
        let confirm = |mut doc: PolicyDocument| {
            doc.policy.confirm_permit_all = Some(crate::model::CONFIRM_PERMIT_ALL.to_owned());
            doc
        };
        // Alone, the default decides.
        let doc = confirm(document(
            model,
            options.clone(),
            vec![(1, "mixed", false, false, vec![catch_all(9, allow())])],
        ));
        let d = decide(&validated(doc));
        assert_eq!(winner(&d), Some(9), "{model}");
        assert_eq!(d.outcome(), Outcome::Allowed, "{model}");

        // A deny that matches wins over a default allow, and the other way
        // round, whatever their order or priority.
        for (rule_action, default, outcome) in [
            (deny(), allow(), Outcome::Blocked),
            (allow(), deny(), Outcome::Allowed),
        ] {
            let rules = vec![
                with(
                    with(
                        rule(1, hash_a(), rule_action.clone()),
                        "order",
                        999_989.into(),
                    ),
                    "priority",
                    1_000.into(),
                ),
                with(
                    with(catch_all(9, default), "order", 100_001.into()),
                    "priority",
                    (-5).into(),
                ),
            ];
            let doc = confirm(document(
                model,
                options.clone(),
                vec![(1, "mixed", false, false, rules)],
            ));
            let d = decide(&validated(doc));
            assert_eq!(winner(&d), Some(1), "{model}");
            assert_eq!(d.outcome(), outcome, "{model}");
            // The default would have decided without the rule.
            assert_eq!(numbers(d.overridden()), vec![9], "{model}");
        }

        // A mandatory deny still decides first.
        let doc = confirm(document(
            model,
            options.clone(),
            vec![
                (1, "mixed", false, false, vec![catch_all(9, allow())]),
                (2, "blocklist", true, true, vec![rule(5, hash_a(), deny())]),
            ],
        ));
        let d = decide(&validated(doc));
        assert_eq!(winner(&d), Some(5), "{model}");
        assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny, "{model}");
    }
}

#[test]
fn a_disabled_or_unmatched_catch_all_leaves_the_unknown_policy() {
    let disabled = with(catch_all(9, deny()), "enabled", false.into());
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, vec![disabled])],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), None);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    // A catch-all narrowed by context: an unknown fact never lets it apply.
    let narrowed = with(
        catch_all(9, deny()),
        "match",
        crit("device.hostname", "equals", "build-01"),
    );
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, vec![narrowed])],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), None);
}

#[test]
fn a_probed_fact_never_relaxes_a_decision_when_it_is_missing() {
    // An allow narrowed by a machine-hive key, and a deny of the same file
    // unless a kill-switch file exists. With nothing probed, the allow does
    // not apply and the deny does not apply either: the unknown policy
    // blocks (#329, ADR 0018).
    let key = serde_json::json!({"criterion": {"field": "reg.key", "operator": "exists", "target": "HKLM\\Software\\Approved"}});
    let allow_rule = rule(1, serde_json::json!({"all": [hash_a(), key]}), allow());
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(1, "mixed", false, false, vec![allow_rule])],
    );
    let policy = validated(doc);
    let d = decide(&policy);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    // Probed and present: the allow applies.
    let variables = PathVariables::new();
    let mut context = EvaluationContext::new();
    context.probes.insert(
        Field::RegKey,
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\approved",
        None,
        crate::context::Probe::Present,
    );
    let facts = facts();
    let d = Evaluator::new(&policy).unwrap().evaluate(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &variables,
            context: &context,
        },
        TRACE,
    );
    assert_eq!(d.outcome(), Outcome::Allowed);
}

/// A post-allow attribute rule with ID `n` (#329).
fn attribute(n: u32, tree: serde_json::Value, action: serde_json::Value) -> serde_json::Value {
    with(rule(n, tree, action), "attribute", true.into())
}

#[test]
fn an_attribute_deny_narrows_an_allow_under_every_model() {
    // The file is allowed by hash; the attribute rule blocks it by its file
    // name, a weak attribute that alone could never allow.
    let narrow = crit("path.file_name", "equals", "tool.exe");
    for model in MODELS {
        let doc = document(
            model,
            serde_json::json!({}),
            vec![(
                1,
                "mixed",
                false,
                false,
                ordered(vec![
                    rule(1, hash_a(), allow()),
                    attribute(2, narrow.clone(), deny()),
                ]),
            )],
        );
        let d = decide(&validated(doc));
        assert_eq!(winner(&d), Some(2), "{model}");
        assert_eq!(d.outcome(), Outcome::Blocked, "{model}");
        assert_eq!(d.reason_code(), ReasonCode::ExplicitDeny, "{model}");
        assert_eq!(numbers(d.overridden()), vec![1], "{model}");
    }
}

#[test]
fn an_attribute_rule_never_allows_and_never_acts_without_an_allow() {
    let narrow = crit("path.file_name", "equals", "tool.exe");
    // No allow: the attribute deny does not apply, the unknown policy
    // decides.
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![attribute(2, narrow.clone(), deny())],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), None);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    // A deny decided at stage 4: the attribute rule changes nothing.
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                rule(1, hash_a(), deny()),
                attribute(2, narrow.clone(), deny()),
            ],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(1));
    // An attribute audit annotates an allowed object, which stays allowed.
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![
                rule(1, hash_a(), allow()),
                attribute(3, narrow.clone(), audit()),
            ],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(1));
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(numbers(d.annotations()), vec![3]);
    // An attribute rule that does not match leaves the allow alone.
    let other = crit("path.file_name", "equals", "other.exe");
    let doc = document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "mixed",
            false,
            false,
            vec![rule(1, hash_a(), allow()), attribute(2, other, deny())],
        )],
    );
    let d = decide(&validated(doc));
    assert_eq!(winner(&d), Some(1));
    assert!(d.overridden().is_empty());
}

/// #399: a deny on `\\srv\share\setup.exe` against `\\srv\share\ſetup.exe`
/// on a share whose case folding is not known. The standard table keeps
/// `ſ` apart from `S`, but the server may not: the deny is unknown, not a
/// miss, so an allow on the publisher does not let the file run past it
/// under `unknown_as: match`, and no allow on the path matches at all. The
/// decision rests on an unknown fact, so it is not cached.
#[test]
fn a_deny_on_a_share_is_unknown_for_a_spelling_the_share_may_fold() {
    let doc = |deny_options: serde_json::Value, extra: Vec<serde_json::Value>| {
        let mut rules = vec![
            rule(1, publisher(), allow()),
            rule(
                2,
                crit("path.full", "equals", "\\\\srv\\share\\setup.exe"),
                deny_options,
            ),
        ];
        rules.extend(extra);
        validated(document(
            "deny_wins",
            serde_json::json!({}),
            vec![(1, "mixed", false, false, rules)],
        ))
    };
    let at = |raw: &str, fold_unknown: bool| {
        let mut path = PathFact::new(raw, &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Network);
        path.fold_unknown = fold_unknown;
        let mut f = facts();
        f.path = Some(path);
        f
    };
    let long_s = at("\\\\srv\\share\\\u{17f}etup.exe", true);
    let fail_closed = doc(
        serde_json::json!({"type": "deny", "unknown_as": "match"}),
        vec![],
    );
    let d = decide_with(&fail_closed, &long_s, ObjectType::Executable);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(winner(&d), Some(2));
    // The same spelling on a share whose folding is known is another file.
    let d = decide_with(
        &fail_closed,
        &at("\\\\srv\\share\\\u{17f}etup.exe", false),
        ObjectType::Executable,
    );
    assert_eq!(winner(&d), Some(1));
    // With the default `unknown_as: no_match` the deny does not apply, but
    // the decision is not cached: it rests on an unknown fact.
    let default = doc(deny(), vec![]);
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let watched = |policy: &ValidatedPolicy, facts: &ObjectFacts| {
        Evaluator::new(policy)
            .unwrap()
            .evaluate_watched(
                &Subject {
                    object_type: ObjectType::Executable,
                    facts,
                    variables: &variables,
                    context: &context,
                },
                FactSet::ALL,
                &crate::mode::DeviceState::of(&policy.document().policy),
                TRACE,
                &mut |_| false,
            )
            .unwrap()
            .unwrap()
    };
    let (d, unknown) = watched(&default, &long_s);
    assert_eq!(winner(&d), Some(1));
    assert!(
        unknown,
        "a decision on an unknown-fold path must not be cached"
    );
    let (_, unknown) = watched(&default, &at("\\\\srv\\share\\\u{17f}etup.exe", false));
    assert!(!unknown);
    // A path allow on an unknown-fold path never matches, even for the
    // exact spelling.
    let path_allow = validated(document(
        "deny_wins",
        serde_json::json!({}),
        vec![(
            1,
            "allowlist",
            false,
            false,
            vec![rule(
                3,
                crit("path.full", "equals", "\\\\srv\\share\\setup.exe"),
                allow(),
            )],
        )],
    ));
    let mut exact = at("\\\\srv\\share\\setup.exe", true);
    if let Some(p) = exact.path.as_mut() {
        p.volume = Some(crate::unknown::VolumeKind::Fixed);
    }
    let d = decide_with(&path_allow, &exact, ObjectType::Executable);
    assert_ne!(winner(&d), Some(3));
    if let Some(p) = exact.path.as_mut() {
        p.fold_unknown = false;
    }
    let d = decide_with(&path_allow, &exact, ObjectType::Executable);
    assert_eq!(winner(&d), Some(3));
}
