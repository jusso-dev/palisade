//! The `publisher_product` preset, the strength of TBS hashes by position
//! and the precedence tiers of the signer criteria (#31).

#![allow(clippy::unwrap_used)]

use palisade_core::ObjectType;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::Outcome;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathVariables, SignerStatus};
use palisade_policy::model::preset::PublisherProduct;
use palisade_policy::model::{
    Criterion, Field, Match, Operator, PrecedenceModel, PrecedenceOptions, SignerOptions,
    TbsPosition, TierTiebreak,
};
use palisade_policy::precedence::{Spec, Tier};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, facts, publisher,
};
use palisade_policy::validate::{ErrorCode, Severity, ValidatedPolicy, ValidationError};

const TBS: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const RULE: &str = "/rule_sets/0/rules/0/match";

fn allow_policy(tree: Match) -> PolicyBuilder {
    PolicyBuilder::new().rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, tree)))
}

fn deny_policy(tree: Match) -> PolicyBuilder {
    PolicyBuilder::new().rule_set(RuleSetBuilder::blocklist(1).rule(RuleBuilder::deny(1, tree)))
}

fn findings(p: PolicyBuilder) -> Vec<(ErrorCode, Severity, String)> {
    let list: Vec<ValidationError> = match p.build().validate() {
        Ok(v) => v.warnings().to_vec(),
        Err(e) => e,
    };
    list.into_iter()
        .map(|f| (f.code, f.severity, f.path))
        .collect()
}

fn decide(policy: &ValidatedPolicy, facts: &ObjectFacts) -> Outcome {
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts,
        variables: &variables,
        context: &context,
    };
    Evaluator::new(policy)
        .unwrap()
        .evaluate(&subject, TRACE)
        .outcome()
}

fn tbs_at(position: Option<TbsPosition>) -> Match {
    Match::Criterion(Criterion {
        signer: Some(Box::new(SignerOptions {
            position,
            ..SignerOptions::default()
        })),
        ..Criterion::new(Field::SignerTbsHash, Operator::Equals, [TBS])
    })
}

#[test]
fn preset_builds_the_recommended_tree() {
    let tree = PublisherProduct::new("Example Software Ltd", "Example Editor")
        .original_filename("editor.exe")
        .min_version("2.0")
        .max_version("2.9")
        .into_match();
    let Match::All(children) = &tree else {
        panic!("not an `all`: {tree:?}");
    };
    let shape: Vec<(Field, Operator, Vec<String>)> = children
        .iter()
        .map(|c| match c {
            Match::Criterion(c) => (c.field, c.operator, c.values.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    let v = |s: &[&str]| s.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        shape,
        [
            (
                Field::SignerPublisher,
                Operator::Equals,
                v(&["Example Software Ltd"])
            ),
            (
                Field::MetaProductName,
                Operator::Equals,
                v(&["Example Editor"])
            ),
            (
                Field::MetaOriginalFilename,
                Operator::Equals,
                v(&["editor.exe"])
            ),
            (
                Field::MetaFileVersion,
                Operator::VersionBetween,
                v(&["2.0", "2.9"])
            ),
        ]
    );
    // Values are trimmed.
    let padded = PublisherProduct::new("  Example Software Ltd\t", " Example Editor ")
        .min_version(" 2.0 ")
        .into_match();
    let Match::All(c) = &padded else { panic!() };
    let values: Vec<&str> = c
        .iter()
        .filter_map(|m| match m {
            Match::Criterion(c) => Some(c.values[0].as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(values, ["Example Software Ltd", "Example Editor", "2.0"]);
    // Bad values are left to validation, which reports each one.
    let bad = PublisherProduct::new("Example Software Ltd", "   ")
        .min_version("two")
        .into_match();
    let codes: Vec<(ErrorCode, String)> = findings(allow_policy(bad))
        .into_iter()
        .map(|(code, _, path)| (code, path))
        .collect();
    assert_eq!(
        codes,
        [
            (
                ErrorCode::InvalidValue,
                format!("{RULE}/all/1/criterion/values/0")
            ),
            (
                ErrorCode::InvalidValue,
                format!("{RULE}/all/2/criterion/values/0")
            ),
        ]
    );
    // The smallest form, and one-sided version ranges.
    let small = PublisherProduct::new("P", "Q").into_match();
    assert!(matches!(&small, Match::All(c) if c.len() == 2));
    for (preset, op) in [
        (
            PublisherProduct::new("P", "Q").min_version("1.0"),
            Operator::VersionGe,
        ),
        (
            PublisherProduct::new("P", "Q").max_version("1.0"),
            Operator::VersionLe,
        ),
    ] {
        let tree = preset.into_match();
        let Match::All(c) = &tree else { panic!() };
        assert!(matches!(&c[2], Match::Criterion(c) if c.operator == op));
    }
}

#[test]
fn preset_is_a_clean_allow_that_fails_closed() {
    let tree = PublisherProduct::new("Example Software Ltd", "Example Editor")
        .original_filename("editor.exe")
        .min_version("2.0")
        .max_version("2.9")
        .into_match();
    // The recommended allow form: no finding at all, and the specificity
    // tier of a signer with a file name and a version.
    assert!(findings(allow_policy(tree.clone())).is_empty());
    assert_eq!(Spec::of(&tree).tier, Tier::SignerFileVersion);
    let policy = allow_policy(tree).validate();
    let object = |version: &str, status| {
        facts()
            .with(Field::MetaProductName, "Example Editor")
            .with(Field::MetaOriginalFilename, "EDITOR.EXE")
            .with(Field::MetaFileVersion, version)
            .signer(status, "Example Software Ltd")
            .build()
    };
    assert_eq!(
        decide(&policy, &object("2.5", SignerStatus::Valid)),
        Outcome::Allowed
    );
    assert_eq!(
        decide(&policy, &object("3.0", SignerStatus::Valid)),
        Outcome::Blocked
    );
    for status in [
        SignerStatus::DigestMismatch,
        SignerStatus::Revoked,
        SignerStatus::Expired,
        SignerStatus::UntrustedRoot,
    ] {
        assert_eq!(
            decide(&policy, &object("2.5", status)),
            Outcome::Blocked,
            "{status:?}"
        );
    }
    // The signatures not examined, or the product unknown: not allowed.
    let mut unexamined = object("2.5", SignerStatus::Valid);
    unexamined.signers = None;
    assert_eq!(decide(&policy, &unexamined), Outcome::Blocked);
    let no_product = facts()
        .with(Field::MetaOriginalFilename, "editor.exe")
        .with(Field::MetaFileVersion, "2.5")
        .signer(SignerStatus::Valid, "Example Software Ltd")
        .build();
    assert_eq!(decide(&policy, &no_product), Outcome::Blocked);
    // A publisher alone remains a valid, medium identity.
    assert!(findings(allow_policy(publisher("Example Software Ltd"))).is_empty());
}

#[test]
fn a_tbs_hash_above_the_leaf_is_weak_in_an_allow() {
    for position in [
        None,
        Some(TbsPosition::Any),
        Some(TbsPosition::Intermediate),
        Some(TbsPosition::Root),
    ] {
        assert_eq!(
            findings(allow_policy(tbs_at(position))),
            [(ErrorCode::WeakIdentity, Severity::Warning, RULE.to_owned())],
            "{position:?}"
        );
        // Blocking a stolen CA certificate is what a TBS hash is for.
        assert!(findings(deny_policy(tbs_at(position))).is_empty());
    }
    // The leaf's TBS hash names the signer's own certificate.
    assert!(findings(allow_policy(tbs_at(Some(TbsPosition::Leaf)))).is_empty());
    // SHA-1 values alone are a weak hash at any position, the stricter
    // finding (ADR 0008).
    for position in [Some(TbsPosition::Leaf), Some(TbsPosition::Root), None] {
        let sha1 = Match::Criterion(Criterion {
            signer: Some(Box::new(SignerOptions {
                position,
                ..SignerOptions::default()
            })),
            ..Criterion::new(Field::SignerTbsHash, Operator::Equals, ["a".repeat(40)])
        });
        assert_eq!(
            findings(allow_policy(sha1)),
            [(
                ErrorCode::WeakHashOnlyAllow,
                Severity::Error,
                RULE.to_owned()
            )],
            "{position:?}"
        );
    }
}

#[test]
fn signer_precedence_tiers() {
    let crit = |field, values: &[&str]| {
        Match::Criterion(Criterion::new(
            field,
            Operator::Equals,
            values.iter().copied(),
        ))
    };
    let sha1 = "a".repeat(40);
    let sha256 = "b".repeat(64);
    for (tree, tier) in [
        (crit(Field::SignerPublisher, &["P"]), Tier::Signer),
        (crit(Field::SignerLeafThumbprint, &[&sha256]), Tier::Signer),
        (
            crit(Field::SignerLeafThumbprintSha1, &[&sha1]),
            Tier::Signer,
        ),
        (tbs_at(Some(TbsPosition::Leaf)), Tier::Signer),
        // A TBS hash that may name a CA ranks with the CA identities.
        (tbs_at(None), Tier::Metadata),
        (tbs_at(Some(TbsPosition::Any)), Tier::Metadata),
        (tbs_at(Some(TbsPosition::Intermediate)), Tier::Metadata),
        (tbs_at(Some(TbsPosition::Root)), Tier::Metadata),
        (crit(Field::SignerIssuer, &["CA"]), Tier::Metadata),
        (crit(Field::SignerPca, &["PCA"]), Tier::Metadata),
        (
            crit(Field::SignerRootThumbprint, &[&sha256]),
            Tier::Metadata,
        ),
        (
            crit(Field::SignerRootThumbprintSha1, &[&sha1]),
            Tier::Metadata,
        ),
        (
            Match::Criterion(Criterion::new(
                Field::SignerEku,
                Operator::MemberOf,
                ["1.3.6.1.5.5.7.3.3"],
            )),
            Tier::Metadata,
        ),
    ] {
        assert_eq!(Spec::of(&tree).tier, tier, "{tree:?}");
    }
    // A TBS hash with a product name ranks as a signer with a product.
    let with_product = Match::All(vec![
        tbs_at(Some(TbsPosition::Leaf)),
        crit(Field::MetaProductName, &["Editor"]),
    ]);
    assert_eq!(Spec::of(&with_product).tier, Tier::SignerProduct);
    // At a CA position it does not combine into tiers 2 or 3.
    for position in [None, Some(TbsPosition::Root)] {
        let ca_product = Match::All(vec![
            tbs_at(position),
            crit(Field::MetaProductName, &["Editor"]),
        ]);
        assert_eq!(Spec::of(&ca_product).tier, Tier::Metadata, "{position:?}");
        let ca_file_version = Match::All(vec![
            tbs_at(position),
            crit(Field::MetaOriginalFilename, &["editor.exe"]),
            Match::Criterion(Criterion::new(
                Field::MetaFileVersion,
                Operator::VersionGe,
                ["2.0"],
            )),
        ]);
        assert_eq!(
            Spec::of(&ca_file_version).tier,
            Tier::Metadata,
            "{position:?}"
        );
    }
}

/// A file signed by "Evil Corp" through the shared root `R` (whose TBS
/// hash is [`TBS`]), with the product, name and version an allow for
/// another publisher's product would look for.
fn evil_corp() -> ObjectFacts {
    let mut f = facts()
        .with(Field::MetaProductName, "Example Editor")
        .with(Field::MetaOriginalFilename, "editor.exe")
        .with(Field::MetaFileVersion, "2.5")
        .signer(SignerStatus::Valid, "Evil Corp")
        .build();
    let s = &mut f.signers.as_mut().unwrap()[0];
    s.leaf_thumbprint_sha256 = Some(LEAF_THUMB.to_owned());
    s.details.leaf_tbs_hash = Some(LEAF_TBS.to_owned());
    s.details.intermediate_tbs_hashes = Some(vec![]);
    s.details.root_tbs_hash = Some(TBS.to_owned());
    f
}

const LEAF_THUMB: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const LEAF_TBS: &str = "6666666666666666666666666666666666666666666666666666666666666666";

fn crit(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion::new(field, operator, values.iter().copied()))
}

fn leaf_tbs(value: &str) -> Match {
    Match::Criterion(Criterion {
        signer: Some(Box::new(SignerOptions {
            position: Some(TbsPosition::Leaf),
            ..SignerOptions::default()
        })),
        ..Criterion::new(Field::SignerTbsHash, Operator::Equals, [value])
    })
}

/// An allow rule and a deny rule decided under `model` and `options`, in
/// separate allow and block lists, or in one mixed set with `mixed`.
fn decide_pair(
    allow: Match,
    deny: Match,
    model: PrecedenceModel,
    options: PrecedenceOptions,
    mixed: bool,
    facts: &ObjectFacts,
) -> Outcome {
    let mut p = PolicyBuilder::new().precedence(model);
    p = if mixed {
        p.rule_set(
            RuleSetBuilder::mixed(1)
                .rule(RuleBuilder::allow(1, allow))
                .rule(RuleBuilder::deny(2, deny)),
        )
    } else {
        p.rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, allow)))
            .rule_set(RuleSetBuilder::blocklist(2).rule(RuleBuilder::deny(2, deny)))
    };
    let mut doc = p.build();
    doc.policy.precedence_options = options;
    let policy = doc.validate().unwrap();
    decide(&policy, facts)
}

fn opts(f: impl FnOnce(&mut PrecedenceOptions)) -> PrecedenceOptions {
    let mut o = PrecedenceOptions::default();
    f(&mut o);
    o
}

/// The review probes of #317: an allow that names only a CA (a TBS hash at
/// the root) must not outrank a deny of one publisher the CA signs for.
#[test]
fn a_ca_tbs_allow_never_outranks_a_publisher_deny() {
    let root = || tbs_at(Some(TbsPosition::Root));
    let evil = || publisher("Evil Corp");
    let cases = [
        // `specificity`: the CA plus a product is not tier 3.
        (
            "specificity, CA + product vs publisher",
            Match::All(vec![
                root(),
                crit(
                    Field::MetaProductName,
                    Operator::Equals,
                    &["Example Editor"],
                ),
            ]),
            evil(),
            PrecedenceModel::Specificity,
            PrecedenceOptions::default(),
            false,
        ),
        // `specificity`: the CA plus a file name and version is not tier 2.
        (
            "specificity, CA + file + version vs publisher_product",
            Match::All(vec![
                root(),
                crit(
                    Field::MetaOriginalFilename,
                    Operator::Equals,
                    &["editor.exe"],
                ),
                crit(Field::MetaFileVersion, Operator::VersionGe, &["2.0"]),
            ]),
            PublisherProduct::new("Evil Corp", "Example Editor").into_match(),
            PrecedenceModel::Specificity,
            PrecedenceOptions::default(),
            false,
        ),
        // `specificity` with ties going to the allow: the CA is not tier 4.
        (
            "specificity, same_tier_tiebreak allow",
            root(),
            evil(),
            PrecedenceModel::Specificity,
            opts(|o| o.same_tier_tiebreak = TierTiebreak::Allow),
            false,
        ),
        // `allow_wins` with granularity: the publisher deny is the more
        // specific rule of the set.
        (
            "allow_wins, granularity_tiebreak, one mixed set",
            root(),
            evil(),
            PrecedenceModel::AllowWins,
            opts(|o| o.granularity_tiebreak = true),
            true,
        ),
    ];
    // Every probe is checked, so a failure names each one that regressed.
    let allowed: Vec<&str> = cases
        .into_iter()
        .filter(|(_, allow, deny, model, options, mixed)| {
            decide_pair(
                allow.clone(),
                deny.clone(),
                *model,
                *options,
                *mixed,
                &evil_corp(),
            ) != Outcome::Blocked
        })
        .map(|(name, ..)| name)
        .collect();
    assert!(
        allowed.is_empty(),
        "a CA-wide allow beat a publisher deny: {allowed:?}"
    );
}

/// The leaf thumbprint and the leaf TBS hash rank with the publisher, in
/// both directions, under `specificity` and `allow_wins` with granularity.
#[test]
fn leaf_certificate_identities_rank_with_the_publisher() {
    let leaf_ids = || {
        [
            crit(Field::SignerLeafThumbprint, Operator::Equals, &[LEAF_THUMB]),
            leaf_tbs(LEAF_TBS),
        ]
    };
    for leaf in leaf_ids() {
        // Same tier as a publisher: the tie-break decides.
        for (tiebreak, expected) in [
            (TierTiebreak::Deny, Outcome::Blocked),
            (TierTiebreak::Allow, Outcome::Allowed),
        ] {
            let options = opts(|o| o.same_tier_tiebreak = tiebreak);
            // Leaf allow, publisher deny.
            assert_eq!(
                decide_pair(
                    leaf.clone(),
                    publisher("Evil Corp"),
                    PrecedenceModel::Specificity,
                    options,
                    false,
                    &evil_corp()
                ),
                expected,
                "{leaf:?} allow, {tiebreak:?}"
            );
            // Publisher allow, leaf deny.
            let flipped = if expected == Outcome::Blocked {
                Outcome::Blocked
            } else {
                Outcome::Allowed
            };
            assert_eq!(
                decide_pair(
                    publisher("Evil Corp"),
                    leaf.clone(),
                    PrecedenceModel::Specificity,
                    options,
                    false,
                    &evil_corp()
                ),
                flipped,
                "{leaf:?} deny, {tiebreak:?}"
            );
        }
        // A more specific rule wins either way: a publisher and product
        // (tier 3) beats a leaf identity (tier 4) under `specificity`.
        let product = || PublisherProduct::new("Evil Corp", "Example Editor").into_match();
        let allow_ties = opts(|o| o.same_tier_tiebreak = TierTiebreak::Allow);
        assert_eq!(
            decide_pair(
                leaf.clone(),
                product(),
                PrecedenceModel::Specificity,
                allow_ties,
                false,
                &evil_corp()
            ),
            Outcome::Blocked,
            "{leaf:?} allow vs tier-3 deny"
        );
        assert_eq!(
            decide_pair(
                product(),
                leaf.clone(),
                PrecedenceModel::Specificity,
                PrecedenceOptions::default(),
                false,
                &evil_corp()
            ),
            Outcome::Allowed,
            "tier-3 allow vs {leaf:?} deny"
        );
        // `allow_wins` with granularity, in one set: the most specific rules
        // of the set take part. Equal tiers: the allow wins.
        let granular = opts(|o| o.granularity_tiebreak = true);
        assert_eq!(
            decide_pair(
                leaf.clone(),
                publisher("Evil Corp"),
                PrecedenceModel::AllowWins,
                granular,
                true,
                &evil_corp()
            ),
            Outcome::Allowed,
            "{leaf:?} allow, allow_wins"
        );
        assert_eq!(
            decide_pair(
                publisher("Evil Corp"),
                leaf.clone(),
                PrecedenceModel::AllowWins,
                granular,
                true,
                &evil_corp()
            ),
            Outcome::Allowed,
            "{leaf:?} deny, allow_wins"
        );
        // A more specific deny in the set beats a leaf allow.
        assert_eq!(
            decide_pair(
                leaf.clone(),
                product(),
                PrecedenceModel::AllowWins,
                granular,
                true,
                &evil_corp()
            ),
            Outcome::Blocked,
            "{leaf:?} allow vs tier-3 deny, allow_wins"
        );
        // ...and a leaf deny beats a CA-wide allow.
        assert_eq!(
            decide_pair(
                tbs_at(Some(TbsPosition::Root)),
                leaf,
                PrecedenceModel::AllowWins,
                granular,
                true,
                &evil_corp()
            ),
            Outcome::Blocked,
            "CA allow vs leaf deny, allow_wins"
        );
    }
}
