//! Validation and serialisation of the signer criteria (#31), through the
//! public API.

#![allow(clippy::unwrap_used)]

use palisade_core::ObjectType;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::Outcome;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{
    ObjectFacts, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use palisade_policy::model::{
    Criterion, Field, Match, Operator, SignerOptions, SubjectComponent, TbsPosition,
};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, all, facts, hash, publisher,
};
use palisade_policy::validate::{ErrorCode, Severity, ValidatedPolicy, ValidationError};

const TBS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn signer_crit(field: Field, operator: Operator, values: &[&str], o: SignerOptions) -> Match {
    Match::Criterion(Criterion {
        signer: Some(Box::new(o)),
        ..Criterion::new(field, operator, values.iter().copied())
    })
}

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

fn decide_facts(policy: &ValidatedPolicy, facts: &ObjectFacts) -> Outcome {
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

const RULE: &str = "/rule_sets/0/rules/0/match";

#[test]
fn sha1_thumbprints_alone_are_compatibility_only() {
    for field in [
        Field::SignerLeafThumbprintSha1,
        Field::SignerRootThumbprintSha1,
    ] {
        let tree = Match::Criterion(Criterion::new(field, Operator::Equals, ["a".repeat(40)]));
        assert_eq!(
            findings(allow_policy(tree)),
            [(
                ErrorCode::WeakHashOnlyAllow,
                Severity::Error,
                RULE.to_owned()
            )],
            "{field:?}"
        );
    }
}

#[test]
fn relaxed_signature_statuses_warn() {
    let relaxed = |o| {
        all(vec![
            signer_crit(
                Field::SignerPublisher,
                Operator::Equals,
                &["Example Ltd"],
                o,
            ),
            Match::Criterion(Criterion::new(
                Field::MetaProductName,
                Operator::Equals,
                ["Editor"],
            )),
        ])
    };
    let expired = SignerOptions {
        accept_status: Some(vec![SignerStatus::Valid, SignerStatus::Expired]),
        ..SignerOptions::default()
    };
    let at = format!("{RULE}/all/0/criterion/signer/accept_status");
    assert_eq!(
        findings(allow_policy(relaxed(expired.clone()))),
        [(ErrorCode::SignatureStatusRelaxed, Severity::Warning, at)]
    );
    // A deny that matches more signatures blocks more: no warning.
    assert!(findings(deny_policy(relaxed(expired))).is_empty());
    // `allow_digest_mismatch` always warns.
    let tampered = SignerOptions {
        allow_digest_mismatch: true,
        ..SignerOptions::default()
    };
    let at = format!("{RULE}/all/0/criterion/signer/allow_digest_mismatch");
    for p in [
        allow_policy(relaxed(tampered.clone())),
        deny_policy(relaxed(tampered)),
    ] {
        assert_eq!(
            findings(p),
            [(
                ErrorCode::SignatureStatusRelaxed,
                Severity::Warning,
                at.clone()
            )]
        );
    }
}

#[test]
fn misplaced_and_invalid_signer_options_are_errors() {
    let mut product = Criterion::new(Field::MetaProductName, Operator::Equals, ["Editor"]);
    product.signer = Some(Box::new(SignerOptions {
        component: Some(SubjectComponent::O),
        ..SignerOptions::default()
    }));
    let tree = all(vec![
        hash('a'),
        Match::Criterion(product),
        signer_crit(
            Field::SignerPublisher,
            Operator::Equals,
            &["x"],
            SignerOptions {
                position: Some(TbsPosition::Leaf),
                accept_status: Some(vec![SignerStatus::DigestMismatch]),
                signed_after: Some("yesterday".into()),
                ..SignerOptions::default()
            },
        ),
    ]);
    let base = format!("{RULE}/all");
    assert_eq!(
        findings(deny_policy(tree)),
        [
            (
                ErrorCode::OptionNotApplicable,
                Severity::Error,
                format!("{base}/1/criterion/signer")
            ),
            (
                ErrorCode::OptionNotApplicable,
                Severity::Error,
                format!("{base}/2/criterion/signer/position")
            ),
            (
                ErrorCode::InvalidValue,
                Severity::Error,
                format!("{base}/2/criterion/signer/accept_status")
            ),
            (
                ErrorCode::InvalidValue,
                Severity::Error,
                format!("{base}/2/criterion/signer/signed_after")
            ),
        ]
    );
    // TBS hashes are 40, 64, 96 or 128 hex digits, normalised on validation.
    let bad = signer_crit(
        Field::SignerTbsHash,
        Operator::Equals,
        &["abc"],
        SignerOptions::default(),
    );
    assert_eq!(
        findings(deny_policy(bad)),
        [(
            ErrorCode::InvalidValue,
            Severity::Error,
            format!("{RULE}/criterion/values/0")
        )]
    );
    let upper = signer_crit(
        Field::SignerTbsHash,
        Operator::Equals,
        &[&format!("0x{}", "A".repeat(40))],
        SignerOptions::default(),
    );
    let validated = deny_policy(upper).validate();
    let Match::Criterion(c) = &validated.document().rule_sets[0].rules[0].match_ else {
        panic!("not a criterion");
    };
    assert_eq!(c.values, ["a".repeat(40)]);
}

#[test]
fn signer_options_round_trip_through_json_and_yaml() {
    let tree = signer_crit(
        Field::SignerTbsHash,
        Operator::Equals,
        &[TBS],
        SignerOptions {
            position: Some(TbsPosition::Intermediate),
            accept_status: Some(vec![SignerStatus::Valid, SignerStatus::Expired]),
            allow_digest_mismatch: true,
            source: Some(palisade_policy::model::SignerSource::Embedded),
            signature_index: Some(1),
            signed_after: Some("2024-01-01T00:00:00Z".into()),
            countersigned: true,
            min_key_bits: Some(3072),
            disallowed_algorithms: vec![palisade_policy::facts::DigestAlgorithm::Sha1],
            ..SignerOptions::default()
        },
    );
    let doc = deny_policy(tree).build();
    let json = doc.to_json_pretty().unwrap();
    assert!(json.contains("\"position\": \"intermediate\""), "{json}");
    assert!(json.contains("\"accept_status\": [\n"), "{json}");
    let back = palisade_policy::model::PolicyDocument::from_json(&json).unwrap();
    assert_eq!(back, doc);
    let yaml = doc.to_yaml().unwrap();
    assert_eq!(
        palisade_policy::model::PolicyDocument::from_yaml(&yaml).unwrap(),
        doc
    );
}

#[test]
fn a_tbs_block_on_a_stolen_certificate_beats_a_publisher_allow() {
    let stolen = signer_crit(
        Field::SignerTbsHash,
        Operator::Equals,
        &[TBS],
        SignerOptions::default(),
    );
    let product = Match::Criterion(Criterion::new(
        Field::MetaProductName,
        Operator::Equals,
        ["Example Editor"],
    ));
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(
            1,
            all(vec![publisher("Example Software Ltd"), product]),
        )))
        .rule_set(RuleSetBuilder::blocklist(2).rule(RuleBuilder::deny(2, stolen)))
        .validate();
    let mut sig = SignerFact::new(SignerStatus::Valid, SignatureSource::Embedded);
    sig.publisher = Some("Example Software Ltd".into());
    sig.details.intermediate_tbs_hashes = Some(vec![TBS.to_ascii_uppercase()]);
    let mut f = facts()
        .with(Field::MetaProductName, "Example Editor")
        .build();
    f.signers = Some(vec![sig.clone()]);
    assert_eq!(decide_facts(&policy, &f), Outcome::Blocked);
    // Re-signed through another CA: allowed again.
    sig.details.intermediate_tbs_hashes = Some(vec!["2".repeat(64)]);
    sig.details.leaf_tbs_hash = Some("3".repeat(64));
    sig.details.root_tbs_hash = Some("4".repeat(64));
    f.signers = Some(vec![sig.clone()]);
    assert_eq!(decide_facts(&policy, &f), Outcome::Allowed);
    // Unknown TBS hashes: the deny cannot be ruled out, so it does not
    // apply (`unknown_as: no_match`), and the allow, which does not need
    // them, decides.
    sig.details = Default::default();
    f.signers = Some(vec![sig]);
    assert_eq!(decide_facts(&policy, &f), Outcome::Allowed);
}

#[test]
fn certificate_authority_identities_alone_are_weak() {
    let ca_only = [
        Match::Criterion(Criterion::new(
            Field::SignerPca,
            Operator::Equals,
            ["Example PCA"],
        )),
        Match::Criterion(Criterion::new(
            Field::SignerRootThumbprint,
            Operator::Equals,
            ["b".repeat(64)],
        )),
        Match::Criterion(Criterion::new(
            Field::SignerEku,
            Operator::MemberOf,
            ["1.3.6.1.5.5.7.3.3"],
        )),
    ];
    for tree in ca_only {
        assert_eq!(
            findings(allow_policy(tree.clone())),
            [(ErrorCode::WeakIdentity, Severity::Warning, RULE.to_owned())],
            "{tree:?}"
        );
        assert!(findings(deny_policy(tree)).is_empty());
    }
}
