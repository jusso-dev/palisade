//! The match-tree presets of #33, each with a snapshot of its expansion.
//!
//! A preset is sugar for an ordinary tree, so its expansion is part of the
//! policy format: a change shows up as a snapshot diff. Review and accept
//! new snapshots with `cargo insta review`.

#![allow(clippy::unwrap_used)]

use palisade_policy::model::preset::{
    MAX_METARULE_CONTEXT, PresetError, metarule, publisher_product_version, signed_in_directory,
};
use palisade_policy::model::{Criterion, Field, Match, Operator};

fn settings() -> insta::Settings {
    let mut s = insta::Settings::clone_current();
    s.set_prepend_module_to_snapshot(false);
    s.set_omit_expression(true);
    s.set_snapshot_path("snapshots/presets");
    s
}

fn no_values(field: Field, operator: Operator) -> Criterion {
    Criterion::new(field, operator, Vec::<String>::new())
}

/// Every preset's tree passes validation as an allow rule.
fn validates(tree: &Match) {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Presets",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"]
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
            "name": "Set",
            "kind": "allowlist",
            "rules": [{
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
                "name": "Rule",
                "match": tree,
                "action": {"type": "allow"}
            }]
        }]
    });
    let doc = palisade_policy::model::PolicyDocument::from_json(&json.to_string()).unwrap();
    if let Err(e) = doc.validate() {
        panic!("{e:#?}");
    }
}

#[test]
fn metarule_expands_to_an_identity_and_its_context() {
    let tree = metarule(
        Criterion::new(Field::SignerPublisher, Operator::Equals, ["Example Ltd"]),
        vec![
            no_values(Field::UserIsAdmin, Operator::IsFalse),
            Criterion::new(Field::DeviceHostname, Operator::Wildcard, ["WS-*"]),
        ],
    )
    .unwrap();
    validates(&tree);
    settings().bind(|| insta::assert_json_snapshot!("metarule", tree));
    // One criterion alone is the identity itself.
    let alone = metarule(
        Criterion::new(Field::HashSha256, Operator::Equals, ["a".repeat(64)]),
        vec![],
    )
    .unwrap();
    assert!(matches!(alone, Match::Criterion(_)));
}

#[test]
fn metarule_rejects_what_the_form_does_not_allow() {
    let identity = || Criterion::new(Field::SignerPublisher, Operator::Equals, ["Example Ltd"]);
    let admin = || no_values(Field::UserIsAdmin, Operator::IsTrue);
    assert_eq!(metarule(admin(), vec![]), Err(PresetError::NotAnIdentity));
    assert_eq!(
        metarule(
            Criterion::new(Field::SignerPublisher, Operator::NotEquals, ["Example Ltd"]),
            vec![]
        ),
        Err(PresetError::NotAnIdentity)
    );
    assert_eq!(
        metarule(identity(), vec![admin(); MAX_METARULE_CONTEXT + 1]),
        Err(PresetError::TooManyContextCriteria(
            MAX_METARULE_CONTEXT + 1
        ))
    );
    assert_eq!(
        metarule(identity(), vec![admin(), identity()]),
        Err(PresetError::NotContext(1))
    );
    assert!(metarule(identity(), vec![admin(); MAX_METARULE_CONTEXT]).is_ok());
    for e in [
        PresetError::NotAnIdentity,
        PresetError::TooManyContextCriteria(5),
        PresetError::NotContext(2),
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn signed_in_directory_expands_to_a_directory_and_a_signer() {
    let tree = signed_in_directory(r" C:\Program Files\Example ", "Example Ltd", None);
    validates(&tree);
    settings().bind(|| insta::assert_json_snapshot!("signed_in_directory", tree));
    let with_product = signed_in_directory(
        r"C:\Program Files\Example",
        "Example Ltd",
        Some("Example Editor".to_owned()),
    );
    validates(&with_product);
    settings().bind(|| insta::assert_json_snapshot!("signed_in_directory_product", with_product));
}

#[test]
fn publisher_product_version_expands_to_a_version_floor() {
    let tree = publisher_product_version("Example Ltd", "Example Editor", "2.0");
    validates(&tree);
    settings().bind(|| insta::assert_json_snapshot!("publisher_product_version", tree));
}
