//! The `publisher_product` preset, the strength of TBS hashes by position
//! and the precedence tiers of the signer criteria (#31).

#![allow(clippy::unwrap_used)]

use palisade_core::ObjectType;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::Outcome;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathVariables, SignerStatus};
use palisade_policy::model::preset::PublisherProduct;
use palisade_policy::model::{Criterion, Field, Match, Operator, SignerOptions, TbsPosition};
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
        (tbs_at(None), Tier::Signer),
        (tbs_at(Some(TbsPosition::Root)), Tier::Signer),
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
}
