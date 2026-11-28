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
    let (result, result_bytes) =
        apply(&old.to_bytes().unwrap(), &read, &BundleLimits::DEFAULT).unwrap();
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
    assert_eq!(
        apply(&new.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap_err(),
        DeltaError::WrongBase
    );
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
    assert_eq!(
        apply(&old.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap_err(),
        DeltaError::ResultMismatch
    );
}

#[test]
fn operations_on_missing_rules_and_sets_are_errors() {
    let old = bundle(base(), 1);
    let mut delta = diff(&old, &old).unwrap();
    let ghost = crate::test_util::rule_set_id(77);
    delta.ops = vec![Op::RemoveRuleSet(ghost)];
    assert_eq!(
        apply(&old.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap_err(),
        DeltaError::MissingRuleSet(ghost)
    );
    let set = crate::test_util::rule_set_id(1);
    let rule = crate::test_util::rule_id(77);
    delta.ops = vec![Op::RemoveRule(set, rule)];
    assert_eq!(
        apply(&old.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap_err(),
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

#[test]
fn a_delta_that_grows_the_bundle_past_the_limits_is_refused() {
    // The base fits the limits; the result, with an extra rule, does not.
    // The agent would fail to load it, so `apply` refuses it.
    let old = bundle(base(), 1);
    let bigger = PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(1, hash('a')))
                .rule(RuleBuilder::allow(2, publisher("CN=Example")))
                .rule(RuleBuilder::allow(4, hash('c'))),
        )
        .rule_set(RuleSetBuilder::mandatory_blocklist(2).rule(RuleBuilder::deny(3, hash('b'))))
        .build();
    let new = bundle(bigger, 2);
    let old_bytes = old.to_bytes().unwrap();
    let new_len = new.to_bytes().unwrap().len();
    assert!(new_len > old_bytes.len());
    let delta = diff(&old, &new).unwrap();
    let tight = BundleLimits {
        max_bytes: new_len - 1,
        ..BundleLimits::DEFAULT
    };
    assert!(matches!(
        apply(&old_bytes, &delta, &tight),
        Err(DeltaError::Decode(BundleError::TooLarge { .. }))
    ));
    // Within the default limits the same delta applies.
    apply(&old_bytes, &delta, &BundleLimits::DEFAULT).unwrap();
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
        let (_, bytes) = apply(&old.to_bytes().unwrap(), &read, &BundleLimits::DEFAULT).unwrap();
        prop_assert_eq!(bytes, new.to_bytes().unwrap());
    }

    /// The same for a small edit of one policy: one rule dropped.
    #[test]
    fn apply_of_diff_reproduces_an_edit(a in arbitrary::document(), drop in 0usize..4) {
        let old = bundle(a.clone(), 1);
        let mut edited = a;
        if let Some(set) = edited.rule_sets.first_mut()
            && !set.rules.is_empty() {
                let i = drop % set.rules.len();
                set.rules.remove(i);
            }
        let new = bundle(edited, 2);
        let delta = diff(&old, &new).unwrap();
        let (_, bytes) = apply(&old.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap();
        prop_assert_eq!(bytes, new.to_bytes().unwrap());
    }
}

#[test]
fn a_schema_minor_bump_breaks_every_delta() {
    // The new bundle is at a newer schema minor: header and policy both.
    let old = bundle(base(), 1);
    let mut doc = base();
    let newer = palisade_core::SchemaVersion::new(
        doc.schema_version.major,
        doc.schema_version.minor + 1,
        0,
    );
    doc.schema_version = newer;
    let new = PolicyBundle::new(
        Header {
            schema_version: newer,
            ..header(2)
        },
        Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap(),
    );
    let delta = diff(&old, &new).unwrap();
    let (_, bytes) = apply(&old.to_bytes().unwrap(), &delta, &BundleLimits::DEFAULT).unwrap();
    assert_eq!(bytes, new.to_bytes().unwrap());
}

#[test]
fn every_delta_error_explains_itself() {
    let errors = [
        DeltaError::WrongBase,
        DeltaError::MissingRuleSet(crate::test_util::rule_set_id(1)),
        DeltaError::MissingRule(crate::test_util::rule_id(1)),
        DeltaError::ResultMismatch,
        DeltaError::Encode(serial::Error::Float),
        DeltaError::Decode(BundleError::NonCanonical),
    ];
    let texts: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), errors.len());
}

#[test]
fn library_and_source_changes_travel_as_replacements() {
    let lib = |v| crate::bundle::format::InlineLibrary {
        id: crate::library::LibraryId(crate::test_util::policy_id(9).0),
        resolved_version: v,
        content: crate::bundle::format::SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]),
    };
    let make = |v: u32, version: u64| {
        PolicyBundle::new(
            header(version),
            Body::new(
                base(),
                vec![lib(v)],
                SourceRevisions {
                    policies: vec![(crate::test_util::policy_id(1), u64::from(v))],
                    libraries: Vec::new(),
                },
            )
            .unwrap(),
        )
    };
    let (old, new) = (make(1, 1), make(2, 2));
    let delta = round_trip(&old, &new);
    // One library version out, one in: per library, not the whole list.
    assert!(
        delta
            .ops
            .iter()
            .any(|o| matches!(o, Op::RemoveLibrary(_, 1)))
    );
    assert!(
        delta
            .ops
            .iter()
            .any(|o| matches!(o, Op::PutLibrary(l) if l.resolved_version == 2))
    );
    assert!(!delta.ops.iter().any(|o| matches!(o, Op::PutLibraries(_))));
    assert!(delta.ops.iter().any(|o| matches!(o, Op::PutSources(_))));
}

/// The delta encoding's field checks, each with the error it gives.
#[test]
fn malformed_deltas_are_refused_by_name() {
    use crate::bundle::cbor::{self, Map, Value};
    let old = bundle(base(), 1);
    let new = bundle(base(), 2);
    let bytes = diff(&old, &new).unwrap().to_bytes().unwrap();
    let Value::Map(m) = cbor::decode(&bytes).unwrap() else {
        panic!("a delta is a map")
    };
    let k = |n: &str| Value::int(crate::bundle::keys::id(n).unwrap());
    let with = |key: Value, v: Value| {
        let mut e: Vec<_> = m
            .entries()
            .iter()
            .filter(|(x, _)| *x != key)
            .cloned()
            .collect();
        e.push((key, v));
        cbor::encode(&Value::Map(Map::new(e).unwrap())).unwrap()
    };
    let read = |b: &[u8]| BundleDelta::from_bytes(b, &BundleLimits::DEFAULT);
    let shape = |what: &'static str| Err(DeltaError::Decode(BundleError::Shape(what)));
    assert_eq!(
        read(&with(k("base_bundle_hash"), Value::Bytes(vec![0; 31]))),
        shape("a hash is not 32 bytes")
    );
    assert_eq!(
        read(&with(k("base_bundle_hash"), Value::Uint(1))),
        shape("a hash is not a byte string")
    );
    assert_eq!(
        read(&cbor::encode(&Value::Array(vec![])).unwrap()),
        shape("a delta is a map")
    );
    // Unknown keys follow their sign; a known key that is no delta field
    // is refused by name.
    let critical = i64::try_from(crate::bundle::keys::KEYS.len()).unwrap() + 900;
    assert_eq!(
        read(&with(Value::int(critical), Value::Null)),
        Err(DeltaError::Decode(BundleError::UnknownCriticalKey(
            critical
        )))
    );
    assert!(read(&with(Value::int(-900), Value::Null)).is_ok());
    assert!(matches!(
        read(&with(k("tenant"), Value::Null)),
        Err(DeltaError::Decode(BundleError::Body(serial::Error::Message(m)))) if m.contains("tenant")
    ));
    let no_ops = {
        let e: Vec<_> = m
            .entries()
            .iter()
            .filter(|(x, _)| *x != k("ops"))
            .cloned()
            .collect();
        cbor::encode(&Value::Map(Map::new(e).unwrap())).unwrap()
    };
    assert_eq!(
        read(&no_ops),
        Err(DeltaError::Decode(BundleError::Missing("ops")))
    );
    let text_key = {
        let mut e: Vec<_> = m.entries().to_vec();
        e.push((Value::Text("x".into()), Value::Null));
        cbor::encode(&Value::Map(Map::new(e).unwrap())).unwrap()
    };
    assert!(matches!(
        read(&text_key),
        Err(DeltaError::Decode(BundleError::Shape(_)))
    ));
}

// --- Hash set patches (#368) -----------------------------------------------

fn hash_set(
    version: u32,
    digits: impl IntoIterator<Item = u8>,
) -> crate::bundle::format::InlineLibrary {
    crate::bundle::format::InlineLibrary {
        id: crate::library::LibraryId(crate::test_util::policy_id(68).0),
        resolved_version: version,
        content: crate::bundle::format::SetContent::HashSet {
            field: crate::model::Field::HashSha256,
            digests: crate::hashset::Digests::from_digests(digits.into_iter().map(|n| [n; 32])),
        },
    }
}

fn with_libraries(
    libraries: Vec<crate::bundle::format::InlineLibrary>,
    version: u64,
) -> PolicyBundle {
    PolicyBundle::new(
        header(version),
        Body::new(base(), libraries, SourceRevisions::default()).unwrap(),
    )
}

#[test]
fn a_new_hash_set_version_travels_as_a_patch() {
    let old = with_libraries(vec![hash_set(1, 0..100)], 1);
    let new = with_libraries(vec![hash_set(2, (2..100).chain([200, 201]))], 2);
    let delta = round_trip(&old, &new);
    let patch = delta
        .ops
        .iter()
        .find_map(|o| match o {
            Op::PatchHashSet(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert_eq!((patch.base_version, patch.resolved_version), (1, 2));
    assert_eq!((patch.add.len(), patch.remove.len()), (2, 2));
    assert!(
        delta
            .ops
            .iter()
            .any(|o| matches!(o, Op::RemoveLibrary(_, 1)))
    );
    // Far smaller than the set.
    assert!(delta.to_bytes().unwrap().len() < new.to_bytes().unwrap().len() / 2);
}

#[test]
fn a_patch_bigger_than_the_set_is_sent_whole() {
    let old = with_libraries(vec![hash_set(1, 0..10)], 1);
    let new = with_libraries(vec![hash_set(2, 100..105)], 2);
    let delta = round_trip(&old, &new);
    assert!(delta.ops.iter().any(|o| matches!(o, Op::PutLibrary(_))));
    assert!(!delta.ops.iter().any(|o| matches!(o, Op::PatchHashSet(_))));
}

#[test]
fn a_patch_that_does_not_fit_its_base_is_refused() {
    let old = with_libraries(vec![hash_set(1, 0..100)], 1);
    let new = with_libraries(vec![hash_set(2, 1..100)], 2);
    let good = diff(&old, &new).unwrap();
    let old_bytes = old.to_bytes().unwrap();
    let limits = BundleLimits::DEFAULT;
    let edit = |f: &dyn Fn(&mut HashSetPatch)| {
        let mut d = good.clone();
        for op in &mut d.ops {
            if let Op::PatchHashSet(p) = op {
                f(p);
            }
        }
        apply(&old_bytes, &d, &limits)
    };
    let digests = |ns: &[u8]| crate::hashset::Digests::from_digests(ns.iter().map(|n| [*n; 32]));
    use crate::hashset::DigestsError;
    assert_eq!(
        edit(&|p| p.remove = digests(&[150])).unwrap_err(),
        DeltaError::Patch(DigestsError::RemoveMissing)
    );
    assert_eq!(
        edit(&|p| p.add = digests(&[5])).unwrap_err(),
        DeltaError::Patch(DigestsError::AddPresent)
    );
    assert!(matches!(
        edit(&|p| p.base_version = 9).unwrap_err(),
        DeltaError::MissingLibrary(_, 9)
    ));
    // A patch that applies but gives another set than was signed.
    assert_eq!(
        edit(&|p| p.remove = digests(&[1])).unwrap_err(),
        DeltaError::ResultMismatch
    );
    // A patch on a library that is not a hash set.
    let net = crate::bundle::format::InlineLibrary {
        content: crate::bundle::format::SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]),
        ..hash_set(1, [])
    };
    let net_old = with_libraries(vec![net], 1);
    let mut d = good.clone();
    d.base_bundle_hash = net_old.bundle_hash().unwrap();
    assert!(matches!(
        apply(&net_old.to_bytes().unwrap(), &d, &limits).unwrap_err(),
        DeltaError::MissingLibrary(_, 1)
    ));
    // Removing a library the base does not hold.
    let mut d = good;
    d.ops = vec![Op::RemoveLibrary(net_old.body.libraries()[0].id, 7)];
    assert!(matches!(
        apply(&old_bytes, &d, &limits).unwrap_err(),
        DeltaError::MissingLibrary(_, 7)
    ));
    for e in [
        DeltaError::MissingLibrary(net_old.body.libraries()[0].id, 1),
        DeltaError::Patch(DigestsError::AddPresent),
    ] {
        assert!(!e.to_string().is_empty());
    }
}
