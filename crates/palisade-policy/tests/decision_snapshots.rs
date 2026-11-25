//! Snapshot tests of whole-pipeline decisions (#25), with `insta`.
//!
//! Each case builds a policy with the `test_util` builders, decides one
//! object, and compares the decision's JSON (outcome, deciding rule, the
//! rules it overrode, annotations, directives and effects) with a reviewed
//! snapshot in `tests/snapshots/pipeline/`. A change to how the engine decides, or
//! to the JSON form, shows up as a snapshot diff in the PR.
//!
//! After a deliberate change, review and accept the new snapshots with
//! `cargo insta review` (or rerun with `INSTA_UPDATE=always` and read the
//! diff). CI runs `cargo insta test --check`, which fails on any pending or
//! unreferenced snapshot (docs/testing.md#snapshot-tests).

#![allow(clippy::unwrap_used)]

use palisade_policy::model::{Mode, ObjectType, PrecedenceModel};
use palisade_policy::test_util::{
    PolicyBuilder, RuleBuilder, RuleSetBuilder, all, facts, hash, publisher, subject, under,
};

fn settings() -> insta::Settings {
    let mut s = insta::Settings::clone_current();
    s.set_prepend_module_to_snapshot(false);
    s.set_omit_expression(true);
    s.set_snapshot_path("snapshots/pipeline");
    s
}

#[test]
fn an_allow_by_hash() {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .validate();
    let d = subject(&facts().sha256('a')).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("allow_by_hash", d));
}

#[test]
fn an_implicit_deny() {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .validate();
    let d = subject(&facts().sha256('b')).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("implicit_deny", d));
}

#[test]
fn a_mandatory_deny_overrides_a_publisher_allow() {
    let policy = PolicyBuilder::new()
        .rule_set(RuleSetBuilder::mandatory_blocklist(1).rule(RuleBuilder::deny(1, hash('a'))))
        .rule_set(
            RuleSetBuilder::allowlist(2).rule(RuleBuilder::allow(2, publisher("Example Ltd"))),
        )
        .validate();
    let f = facts().sha256('a').signed_by("Example Ltd");
    let d = subject(&f).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("mandatory_deny_over_allow", d));
}

#[test]
fn deny_wins_over_an_allow_with_an_audit_annotation() {
    let policy = PolicyBuilder::new()
        .precedence(PrecedenceModel::DenyWins)
        .rule_set(
            RuleSetBuilder::mixed(1)
                .rule(RuleBuilder::allow(1, under(r"C:\Tools")).object_types(&[]))
                .rule(RuleBuilder::deny(
                    2,
                    all(vec![hash('a'), under(r"C:\Tools")]),
                ))
                .rule(RuleBuilder::audit(3, hash('a'))),
        )
        .validate();
    let f = facts().sha256('a').path(r"C:\Tools\tool.exe");
    let d = subject(&f).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("deny_wins_with_audit", d));
}

#[test]
fn a_rule_for_another_object_type_does_not_apply() {
    let policy = PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(1, hash('a')).object_types(&[ObjectType::Library])),
        )
        .validate();
    let f = facts().sha256('a');
    let d = subject(&f).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("other_object_type", d));
    // The same rule decides for the type it names.
    let library = subject(&f).object_type(ObjectType::Library).decide(&policy);
    settings().bind(|| insta::assert_json_snapshot!("library_allowed", library));
}

#[test]
fn audit_mode_lets_an_implicit_deny_run() {
    let policy = PolicyBuilder::new()
        .mode(Mode::Audit)
        .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
        .validate();
    let d = subject(&facts().sha256('b'))
        .decide_in_mode(&policy)
        .unwrap();
    settings().bind(|| insta::assert_json_snapshot!("audit_mode_would_block", d));
}
