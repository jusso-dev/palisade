//! Version-resource, PE and Windows Installer criteria (#328), through the
//! public API: none is an identity alone, and a deny on them blocks.

#![allow(clippy::unwrap_used)]

use palisade_core::ObjectType;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::Outcome;
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{ObjectFacts, PathVariables};
use palisade_policy::model::{Criterion, Field, Match, Operator};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, TRACE, all, facts, hash,
};
use palisade_policy::validate::{ErrorCode, Severity, ValidationError};

const CODE: &str = "{12345678-9ABC-DEF0-1234-56789ABCDEF0}";

fn crit(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion::new(field, operator, values.iter().copied()))
}

fn findings(p: PolicyBuilder) -> Vec<(ErrorCode, Severity)> {
    let list: Vec<ValidationError> = match p.build().validate() {
        Ok(v) => v.warnings().to_vec(),
        Err(e) => e,
    };
    list.into_iter().map(|f| (f.code, f.severity)).collect()
}

fn allow(tree: Match) -> PolicyBuilder {
    PolicyBuilder::new().rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, tree)))
}

fn decide(p: PolicyBuilder, f: &ObjectFacts) -> Outcome {
    let policy = p.validate();
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: f,
        variables: &variables,
        context: &context,
    };
    Evaluator::new(&policy)
        .unwrap()
        .evaluate(&subject, TRACE)
        .outcome()
}

fn each_new_field() -> Vec<Match> {
    vec![
        crit(Field::MetaLegalCopyright, Operator::Contains, &["Example"]),
        crit(Field::MetaLanguage, Operator::Equals, &["040904b0"]),
        crit(Field::MetaFileNameFallback, Operator::Equals, &["tool.exe"]),
        crit(Field::MetaFileSize, Operator::Gt, &["0"]),
        crit(Field::MetaPeMachine, Operator::Equals, &["amd64"]),
        crit(Field::MetaPeSubsystem, Operator::Equals, &["windows_gui"]),
        crit(Field::MetaIsDotnet, Operator::IsTrue, &[]),
        crit(Field::MsiProductCode, Operator::Equals, &[CODE]),
        crit(Field::MsiUpgradeCode, Operator::Equals, &[CODE]),
        crit(Field::MsiProductName, Operator::Equals, &["Suite"]),
        crit(Field::MsiManufacturer, Operator::Equals, &["Example"]),
        crit(Field::MsiProductVersion, Operator::VersionGe, &["1.0"]),
        crit(Field::MsiPackageCode, Operator::Equals, &[CODE]),
    ]
}

#[test]
fn none_is_an_identity_alone() {
    for tree in each_new_field() {
        assert_eq!(
            findings(allow(tree.clone())),
            [(ErrorCode::WeakIdentity, Severity::Warning)],
            "{tree:?}"
        );
        // Beside a strong identity it only narrows.
        assert!(findings(allow(all(vec![hash('a'), tree.clone()]))).is_empty());
    }
}

#[test]
fn a_deny_on_an_upgrade_code_blocks_every_version() {
    let p = || {
        PolicyBuilder::new()
            .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
            .rule_set(RuleSetBuilder::blocklist(2).rule(RuleBuilder::deny(
                2,
                crit(Field::MsiUpgradeCode, Operator::Equals, &[CODE]),
            )))
    };
    let blocked = facts()
        .sha256('a')
        .with(Field::MsiUpgradeCode, &CODE.to_ascii_lowercase())
        .with(Field::MsiProductVersion, "3.0")
        .build();
    assert_eq!(decide(p(), &blocked), Outcome::Blocked);
    let other = facts()
        .sha256('a')
        .with(
            Field::MsiUpgradeCode,
            "{00000000-0000-0000-0000-000000000000}",
        )
        .build();
    assert_eq!(decide(p(), &other), Outcome::Allowed);
}

#[test]
fn an_unknown_fact_never_matches_an_allow() {
    // The allow needs a hash and a .NET image: without the .NET fact, or
    // with one that is not `true` or `false`, it cannot match.
    let p = || {
        allow(all(vec![
            hash('a'),
            crit(Field::MetaIsDotnet, Operator::IsTrue, &[]),
            crit(Field::MetaFileSize, Operator::Lt, &["1000000"]),
        ]))
    };
    let known = facts()
        .sha256('a')
        .with(Field::MetaIsDotnet, "true")
        .with(Field::MetaFileSize, "4096")
        .build();
    assert_eq!(decide(p(), &known), Outcome::Allowed);
    for (field, odd) in [(Field::MetaIsDotnet, "maybe"), (Field::MetaFileSize, "big")] {
        let mut f = known.clone();
        f.set(field, odd);
        assert_ne!(decide(p(), &f), Outcome::Allowed, "{field:?}");
    }
    let mut missing = facts()
        .sha256('a')
        .with(Field::MetaFileSize, "4096")
        .build();
    assert_ne!(decide(p(), &missing), Outcome::Allowed);
    missing.set(Field::MetaIsDotnet, "true");
    assert_eq!(decide(p(), &missing), Outcome::Allowed);
}
