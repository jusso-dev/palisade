//! The builders build what they say, and the documents they build are
//! valid.

use super::*;
use crate::decision::{Outcome, ReasonCode};

#[test]
fn ids_are_distinct_per_kind_and_stable() {
    assert_eq!(policy_id(1), policy_id(1));
    assert_ne!(policy_id(1).to_string(), rule_set_id(1).to_string());
    assert_ne!(rule_set_id(1).to_string(), rule_id(1).to_string());
    assert_ne!(rule_id(1), rule_id(2));
    assert_eq!(
        rule_id(0xdead_beef).to_string(),
        "01936b2e-8c4a-7003-9f21-0000deadbeef"
    );
}

#[test]
fn the_smallest_policy_is_valid_and_denies_by_default() {
    let policy = PolicyBuilder::new().validate();
    let d = subject(&facts().sha256('a')).decide(&policy);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
}

#[test]
fn an_allow_rule_allows_its_hash_only() {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .validate();
    assert_eq!(
        subject(&facts().sha256('a')).decide(&policy).outcome(),
        Outcome::Allowed
    );
    assert_eq!(
        subject(&facts().sha256('b')).decide(&policy).outcome(),
        Outcome::Blocked
    );
    // Rules are for executables and installers unless set otherwise.
    let a = facts().sha256('a');
    let dll = subject(&a).object_type(ObjectType::Library);
    assert_eq!(dll.decide(&policy).outcome(), Outcome::Blocked);
}

#[test]
fn a_mandatory_deny_beats_an_allow() {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::mandatory_blocklist(1).rule(RuleBuilder::deny(1, hash('a'))))
        .rule_set(
            RuleSetBuilder::allowlist(2).rule(RuleBuilder::allow(2, publisher("Example Ltd"))),
        )
        .validate();
    let f = facts().sha256('a').signed_by("Example Ltd");
    let d = subject(&f).decide(&policy);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
}

#[test]
fn trees_paths_and_context_reach_the_evaluator() {
    let tree = all(vec![under(r"C:\Tools"), not(hash('b'))]);
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, tree)))
        .validate();
    let inside = facts().sha256('a').path(r"C:\Tools\x.exe");
    assert_eq!(subject(&inside).decide(&policy).outcome(), Outcome::Allowed);
    let excluded = facts().sha256('b').path(r"C:\Tools\x.exe");
    assert_eq!(
        subject(&excluded).decide(&policy).outcome(),
        Outcome::Blocked
    );
    let outside = facts().sha256('a').path(r"C:\Other\x.exe");
    assert_eq!(
        subject(&outside).decide(&policy).outcome(),
        Outcome::Blocked
    );

    // Context criteria narrow a rule; every rule also needs an identity
    // criterion. Allow hash `a`, except for non-administrators.
    let not_admin = criterion(Field::UserIsAdmin, Operator::IsFalse, &[]);
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .rule_set(
            RuleSetBuilder::blocklist(2)
                .rule(RuleBuilder::deny(2, all(vec![hash('a'), not_admin]))),
        )
        .validate();
    let f = facts().sha256('a');
    let ctx = || {
        context()
            .user("S-1-5-21-1-2-3-1001", &[])
            .hostname("host-1")
    };
    assert_eq!(
        subject(&f)
            .context(ctx().admin(true))
            .decide(&policy)
            .outcome(),
        Outcome::Allowed
    );
    let d = subject(&f).context(ctx().admin(false)).decide(&policy);
    assert_eq!(
        (d.outcome(), d.reason_code()),
        (Outcome::Blocked, ReasonCode::ExplicitDeny)
    );
}

#[test]
fn rule_options_are_set() {
    let rule = RuleBuilder::audit(4, hash('c'))
        .object_types(&[])
        .disabled()
        .order(200_000)
        .priority(-3)
        .build();
    assert_eq!(rule.id, rule_id(4));
    assert_eq!(rule.name, "Rule 4");
    assert!(rule.object_types.is_empty() && !rule.enabled);
    assert_eq!((rule.order, rule.priority), (Some(200_000), Some(-3)));
    let set = RuleSetBuilder::mixed(9).read_only().build();
    assert!(set.read_only && !set.mandatory);
    let doc = PolicyBuilder::new()
        .precedence(PrecedenceModel::FirstMatch)
        .mode(Mode::Audit)
        .build();
    assert_eq!(doc.policy.precedence_model, PrecedenceModel::FirstMatch);
    assert_eq!(doc.policy.mode, Mode::Audit);
}

#[test]
#[should_panic(expected = "the test policy is not valid")]
fn an_invalid_policy_panics_with_its_errors() {
    // Two rules with the same ID.
    let _ = PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(1, hash('a')))
                .rule(RuleBuilder::allow(1, hash('b'))),
        )
        .validate();
}

#[test]
fn decide_in_mode_applies_the_policy_mode() {
    let policy = PolicyBuilder::new().mode(Mode::Audit).validate();
    let f = facts().sha256('a');
    // Enforce-mode view: blocked.
    assert_eq!(subject(&f).decide(&policy).outcome(), Outcome::Blocked);
    // In the policy's audit mode it runs, and enforce mode would have blocked.
    let d = subject(&f).decide_in_mode(&policy).unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
    assert_eq!(d.mode(), Mode::Audit);
}

#[test]
fn stored_facts_are_kept() {
    let f = facts()
        .with(Field::MetaProductName, "Example Suite")
        .sha256('a')
        .build();
    assert_eq!(f.get(Field::MetaProductName), Some("Example Suite"));
    assert_eq!(f.get(Field::HashSha256), Some(sha256_of('a').as_str()));
}

#[test]
#[should_panic(expected = "is not a stored fact")]
fn a_path_field_by_name_panics_instead_of_being_dropped() {
    let _ = facts().with(Field::PathExtension, "exe");
}

#[test]
#[should_panic(expected = "is not a stored fact")]
fn a_context_field_by_name_panics_instead_of_being_dropped() {
    let _ = facts().with(Field::UserName, "alice");
}

#[test]
#[should_panic(expected = "is not a hex digit")]
fn a_hash_needs_a_hex_digit() {
    let _ = sha256_of('z');
}
