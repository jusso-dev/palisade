use proptest::prelude::*;

use super::*;
use crate::bundle::format::{BundleLimits, Target, TargetScope};
use crate::model::{Mode, arbitrary};
use crate::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash, publisher};
use palisade_core::Uuid7;

fn header(version: u64) -> Header {
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
            scope: TargetScope::Device(id(2)),
        },
        version,
        1_764_201_600_000_000 + i64::try_from(version).unwrap(),
    )
}

fn bundle(doc: PolicyDocument, version: u64) -> PolicyBundle {
    PolicyBundle::new(
        header(version),
        Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap(),
    )
}

fn base() -> PolicyDocument {
    PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(1, hash('a')))
                .rule(RuleBuilder::allow(2, publisher("CN=Example"))),
        )
        .rule_set(RuleSetBuilder::mandatory_blocklist(2).rule(RuleBuilder::deny(3, hash('b'))))
        .build()
}

fn round_trip(old: &PolicyBundle, new: &PolicyBundle) -> BundleDelta {
    let delta = diff(old, new).unwrap();
    let bytes = delta.to_bytes().unwrap();
    let read = BundleDelta::from_bytes(&bytes, &BundleLimits::DEFAULT).unwrap();
    assert_eq!(read, delta);
    let (result, result_bytes) = apply(old, &read).unwrap();
    assert_eq!(&result, new);
    assert_eq!(result_bytes, new.to_bytes().unwrap());
    delta
}

#[test]
fn an_unchanged_policy_needs_only_a_new_header() {
    let old = bundle(base(), 1);
    let new = bundle(base(), 2);
    assert!(round_trip(&old, &new).ops.is_empty());
}

#[test]
fn a_new_rule_is_one_put() {
    let old = bundle(base(), 1);
    let mut doc = base();
    doc.rule_sets[0]
        .rules
        .push(RuleBuilder::allow(9, hash('c')).build());
    let new = bundle(doc, 2);
    let delta = round_trip(&old, &new);
    assert!(
        matches!(delta.ops.as_slice(), [Op::PutRule(_, r)] if r.id == crate::test_util::rule_id(9))
    );
}

#[test]
fn removals_mode_and_rule_set_changes_apply() {
    let old = bundle(base(), 1);
    let mut doc = base();
    doc.policy.mode = Mode::Audit;
    doc.rule_sets[0].rules.remove(1);
    doc.rule_sets[0].name = "Renamed".to_owned();
    doc.rule_sets.remove(1);
    doc.policy.rule_sets.remove(1);
    let new = bundle(doc, 2);
    let delta = round_trip(&old, &new);
    assert!(delta.ops.iter().any(|o| matches!(o, Op::RemoveRuleSet(_))));
    assert!(delta.ops.iter().any(|o| matches!(o, Op::RemoveRule(..))));
    assert!(delta.ops.iter().any(|o| matches!(o, Op::PutRuleSet(_))));
    assert!(delta.ops.iter().any(|o| matches!(o, Op::PutPolicy(_))));
}

#[test]
fn metadata_changes_travel_as_the_digest() {
    let old = bundle(base(), 1);
    let mut doc = base();
    doc.rule_sets[0].rules[0].metadata.ticket_ref = Some("CHG-9".to_owned());
    let new = bundle(doc, 2);
    let delta = round_trip(&old, &new);
    assert!(delta.ops.is_empty());
    assert_eq!(&delta.metadata_digest, new.body.metadata_digest());
}

#[test]
fn a_wrong_base_is_rejected() {
    let old = bundle(base(), 1);
    let new = bundle(base(), 2);
    let delta = diff(&old, &new).unwrap();
    assert_eq!(apply(&new, &delta).unwrap_err(), DeltaError::WrongBase);
}

#[test]
fn a_tampered_delta_fails_the_result_hash() {
    let old = bundle(base(), 1);
    let mut doc = base();
    doc.rule_sets[0]
        .rules
        .push(RuleBuilder::allow(9, hash('c')).build());
    let new = bundle(doc, 2);
    let mut delta = diff(&old, &new).unwrap();
    if let Some(Op::PutRule(_, rule)) = delta.ops.first_mut() {
        rule.match_ = hash('d');
    }
    assert_eq!(apply(&old, &delta).unwrap_err(), DeltaError::ResultMismatch);
}

#[test]
fn operations_on_missing_rules_and_sets_are_errors() {
    let old = bundle(base(), 1);
    let mut delta = diff(&old, &old).unwrap();
    let ghost = crate::test_util::rule_set_id(77);
    delta.ops = vec![Op::RemoveRuleSet(ghost)];
    assert_eq!(
        apply(&old, &delta).unwrap_err(),
        DeltaError::MissingRuleSet(ghost)
    );
    let set = crate::test_util::rule_set_id(1);
    let rule = crate::test_util::rule_id(77);
    delta.ops = vec![Op::RemoveRule(set, rule)];
    assert_eq!(
        apply(&old, &delta).unwrap_err(),
        DeltaError::MissingRule(rule)
    );
}

#[test]
fn a_delta_is_sent_only_to_its_base_and_when_small() {
    let old = bundle(base(), 1);
    let new = bundle(base(), 2);
    let delta = diff(&old, &new).unwrap();
    let len = delta.to_bytes().unwrap().len();
    let base_hash = old.bundle_hash().unwrap();
    assert!(worth_sending(&delta, len, 2 * len + 1, &base_hash));
    assert!(!worth_sending(&delta, len, 2 * len, &base_hash));
    assert!(!worth_sending(
        &delta,
        len,
        10 * len,
        &new.bundle_hash().unwrap()
    ));
}

#[test]
fn delta_bytes_are_strict() {
    let old = bundle(base(), 1);
    let new = bundle(base(), 2);
    let bytes = diff(&old, &new).unwrap().to_bytes().unwrap();
    let limits = BundleLimits::DEFAULT;
    assert!(BundleDelta::from_bytes(&bytes[..bytes.len() - 1], &limits).is_err());
    let mut long = bytes.clone();
    long.push(0);
    assert!(BundleDelta::from_bytes(&long, &limits).is_err());
    let small = BundleLimits {
        max_bytes: bytes.len() - 1,
        ..limits
    };
    assert!(matches!(
        BundleDelta::from_bytes(&bytes, &small),
        Err(DeltaError::Decode(BundleError::TooLarge { .. }))
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// apply(old, diff(old, new)) == new, byte for byte, for any two valid
    /// policies.
    #[test]
    fn apply_of_diff_reproduces_the_new_bytes(
        a in arbitrary::scoped_document(),
        b in arbitrary::scoped_document(),
    ) {
        let (old, new) = (bundle(a, 1), bundle(b, 2));
        let delta = diff(&old, &new).unwrap();
        let read = BundleDelta::from_bytes(&delta.to_bytes().unwrap(), &BundleLimits::DEFAULT).unwrap();
        let (_, bytes) = apply(&old, &read).unwrap();
        prop_assert_eq!(bytes, new.to_bytes().unwrap());
    }

    /// The same for a small edit of one policy: one rule dropped.
    #[test]
    fn apply_of_diff_reproduces_an_edit(a in arbitrary::document(), drop in 0usize..4) {
        let old = bundle(a.clone(), 1);
        let mut edited = a;
        if let Some(set) = edited.rule_sets.first_mut() {
            if !set.rules.is_empty() {
                let i = drop % set.rules.len();
                set.rules.remove(i);
            }
        }
        let new = bundle(edited, 2);
        let delta = diff(&old, &new).unwrap();
        let (_, bytes) = apply(&old, &delta).unwrap();
        prop_assert_eq!(bytes, new.to_bytes().unwrap());
    }
}
