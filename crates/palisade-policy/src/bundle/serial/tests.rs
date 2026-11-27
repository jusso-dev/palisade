use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use crate::bundle::cbor::{self, Value};
use crate::model::{Action, Mode, PolicyDocument, PolicySettings, ScriptKind};

/// Governance metadata stays on the server (#43, #40): who asked, approved,
/// created and reviewed a rule, when, its risk rating, compensating
/// controls, justification, ticket and comments, and where it came from.
/// None of it decides (evaluation never reads `Metadata`), and much of it
/// names people. These names have no key, and [`to_value`] also refuses the
/// `Metadata` struct itself ([`Error::ServerOnly`]), because some of its
/// field names (`source`, `tags`) are keys elsewhere.
const NOT_IN_BUNDLES: &[&str] = &[
    "metadata",
    "justification",
    "ticket_ref",
    "comment",
    "owner",
    "requested_by",
    "approved_by",
    "approved_at",
    "created_by",
    "created_at",
    "updated_by",
    "updated_at",
    "review_by",
    "last_reviewed_at",
    "last_reviewed_by",
    "risk_rating",
    "compensating_controls",
    "exception",
    // `RuleSource`, only reachable as `Metadata.source`.
    "api",
    "approval_request",
    "catalogue",
    "import",
    "learned",
    "manual",
    "recommendation",
];

/// Names the model writes as text rather than as a field or variant, so
/// they need no key: a library pin of `latest`.
const WRITTEN_AS_TEXT: [&str; 1] = ["latest"];

/// `doc` without governance metadata, as the bundle compiler writes it.
pub(crate) fn without_metadata(mut doc: PolicyDocument) -> PolicyDocument {
    doc.policy.metadata = crate::model::Metadata::default();
    for set in &mut doc.rule_sets {
        set.metadata = crate::model::Metadata::default();
        for rule in &mut set.rules {
            rule.metadata = crate::model::RuleMetadata::default();
        }
    }
    doc
}

fn round_trip<T>(v: &T) -> T
where
    T: Serialize + DeserializeOwned,
{
    let value = to_value(v).unwrap();
    let bytes = cbor::encode(&value).unwrap();
    from_value(cbor::decode(&bytes).unwrap()).unwrap()
}

/// Every field and variant name in the policy schema: property names and
/// string constants. The schema is generated from the model, so a field or
/// variant added to the model appears here.
fn schema_names() -> BTreeSet<String> {
    fn walk(v: &serde_json::Value, data_map: bool, out: &mut BTreeSet<String>) {
        match v {
            serde_json::Value::Object(o) => {
                for (k, v) in o {
                    match k.as_str() {
                        "properties" => {
                            for (name, sub) in v.as_object().into_iter().flatten() {
                                if !data_map {
                                    out.insert(name.clone());
                                }
                                let data = matches!(
                                    name.as_str(),
                                    "mode_by_type" | "script_control_by_kind" | "advanced"
                                );
                                walk(sub, data, out);
                            }
                        }
                        "const" | "enum" => {
                            let items =
                                v.as_array().map_or_else(|| vec![v], |a| a.iter().collect());
                            out.extend(
                                items
                                    .into_iter()
                                    .filter_map(|s| s.as_str())
                                    .map(str::to_owned),
                            );
                        }
                        "description" | "pattern" | "$id" | "$schema" | "title" | "default" => {}
                        _ => walk(v, data_map, out),
                    }
                }
            }
            serde_json::Value::Array(a) => {
                for v in a {
                    walk(v, data_map, out);
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    walk(&crate::schema::generate(), false, &mut out);
    out
}

/// The guard against silently dropped criteria: every field and variant of
/// the model has a bundle key. A new field, operator, criterion field or
/// object type fails here until it is registered in `bundle/keys.rs`, and
/// [`to_value`] refuses to write it meanwhile.
#[test]
fn every_model_field_and_variant_has_a_key() {
    let names = schema_names();
    assert!(
        names.len() > 300,
        "the schema walk found only {} names",
        names.len()
    );
    let missing: Vec<&String> = names
        .iter()
        .filter(|n| {
            keys::id(n).is_none()
                && !NOT_IN_BUNDLES.contains(&n.as_str())
                && !WRITTEN_AS_TEXT.contains(&n.as_str())
        })
        .collect();
    for excluded in NOT_IN_BUNDLES {
        assert!(
            names.iter().any(|n| n == excluded),
            "`{excluded}` is no longer in the model"
        );
        assert_eq!(
            keys::id(excluded),
            None,
            "`{excluded}` must not reach a bundle"
        );
    }
    assert!(
        missing.is_empty(),
        "these model names have no bundle key; add them to bundle/keys.rs: {missing:?}"
    );
}

/// The operators and criterion fields, checked from the Rust tables as
/// well, since they are the lists most often extended.
#[test]
fn every_operator_field_and_object_type_has_a_key() {
    let text = |v: serde_json::Value| v.as_str().unwrap().to_owned();
    let names: Vec<String> = crate::model::Field::ALL
        .iter()
        .map(|f| text(serde_json::to_value(f).unwrap()))
        .chain(
            crate::model::Operator::ALL
                .iter()
                .map(|o| text(serde_json::to_value(o).unwrap())),
        )
        .chain(
            palisade_core::ObjectType::ALL
                .iter()
                .map(ToString::to_string),
        )
        .chain(ScriptKind::ALL.iter().map(|k| k.as_str().to_owned()))
        .collect();
    for name in names {
        assert!(keys::id(&name).is_some(), "`{name}` has no bundle key");
    }
}

#[test]
fn governance_metadata_cannot_be_written() {
    let mut doc = PolicyDocument {
        schema_version: crate::schema::CURRENT,
        policy: serde_json::from_value(serde_json::json!({
            "id": "01890a5d-ac96-774b-bcce-b302099a8057",
            "name": "p", "revision": 1, "mode": "enforce"
        }))
        .unwrap(),
        rule_sets: Vec::new(),
    };
    assert!(to_value(&doc).is_ok());
    doc.policy.metadata.ticket_ref = Some("CHG-1".to_owned());
    assert_eq!(
        to_value(&doc),
        Err(Error::UnregisteredKey("metadata".to_owned()))
    );
}

#[test]
fn a_struct_is_a_map_of_registered_ids() {
    let Value::Map(m) = to_value(&PolicySettings::default()).unwrap() else {
        panic!("settings must be a map");
    };
    for (k, _) in m.entries() {
        let id = k.as_i64().unwrap();
        assert!(keys::name(id).is_some(), "key {id}");
    }
    assert_eq!(
        m.get(&Value::int(keys::id("poll_interval_secs").unwrap())),
        Some(&Value::Uint(900))
    );
}

#[test]
fn unit_variants_are_their_ids_and_newtype_variants_one_entry_maps() {
    assert_eq!(
        to_value(&Mode::Enforce).unwrap(),
        Value::int(keys::id("enforce").unwrap())
    );
    let Value::Map(m) = to_value(&crate::scope::NetworkRef::ServerReachable(true)).unwrap() else {
        panic!("a newtype variant must be a map");
    };
    assert_eq!(m.len(), 1);
    assert_eq!(
        m.get(&Value::int(keys::id("server_reachable").unwrap())),
        Some(&Value::Bool(true))
    );
}

#[test]
fn actions_round_trip_through_their_strict_reader() {
    for action in [
        Action::Allow {},
        Action::deny(),
        Action::Audit {},
        Action::Ignore {},
        Action::Defer {},
    ] {
        assert_eq!(round_trip(&action), action);
    }
}

#[test]
fn text_is_written_in_nfc() {
    assert_eq!(
        to_value("Cafe\u{301}").unwrap(),
        Value::Text("Caf\u{e9}".to_owned())
    );
}

#[test]
fn floats_are_refused_both_ways() {
    assert_eq!(to_value(&1.5f64), Err(Error::Float));
    assert_eq!(from_value::<f64>(Value::Uint(1)), Err(Error::Float));
}

#[test]
fn unregistered_names_cannot_be_written() {
    #[derive(::serde::Serialize)]
    struct Novel {
        brand_new_field: u8,
    }
    assert_eq!(
        to_value(&Novel { brand_new_field: 1 }),
        Err(Error::UnregisteredKey("brand_new_field".to_owned()))
    );
}

fn with_extra(value: Value, key: i64) -> Value {
    let Value::Map(m) = value else {
        panic!("not a map")
    };
    let mut entries = m.into_entries();
    entries.push((Value::int(key), Value::Bool(true)));
    Value::Map(cbor::Map::new(entries).unwrap())
}

fn unused_critical_id() -> i64 {
    i64::try_from(keys::KEYS.len()).unwrap() + 1000
}

#[test]
fn unknown_critical_keys_are_refused_and_unknown_ignorable_ones_skipped() {
    let settings = PolicySettings::default();
    let value = to_value(&settings).unwrap();
    let critical = unused_critical_id();
    assert_eq!(
        from_value::<PolicySettings>(with_extra(value.clone(), critical)),
        Err(Error::UnknownCriticalKey(critical))
    );
    assert_eq!(
        from_value::<PolicySettings>(with_extra(value.clone(), -1000)).unwrap(),
        settings
    );
    // A registered ignorable key that this struct does not have is skipped
    // too: a newer writer may add a description anywhere.
    let description = keys::id("description").unwrap();
    assert_eq!(
        from_value::<PolicySettings>(with_extra(value, description)).unwrap(),
        settings
    );
}

#[test]
fn unknown_critical_keys_are_refused_inside_tagged_enums() {
    let value = to_value(&Action::deny()).unwrap();
    let critical = unused_critical_id();
    assert_eq!(
        from_value::<Action>(with_extra(value, critical)),
        Err(Error::UnknownCriticalKey(critical))
    );
}

#[test]
fn a_known_critical_key_the_struct_lacks_is_refused_by_the_model() {
    let value = to_value(&PolicySettings::default()).unwrap();
    let err =
        from_value::<PolicySettings>(with_extra(value, keys::id("rules").unwrap())).unwrap_err();
    assert!(
        matches!(&err, Error::Message(m) if m.contains("rules")),
        "{err}"
    );
}

#[test]
fn unknown_variants_are_refused() {
    let id = unused_critical_id();
    assert_eq!(
        from_value::<Mode>(Value::int(id)),
        Err(Error::UnknownVariant(id))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every valid document survives the bundle encoding unchanged.
    #[test]
    fn documents_round_trip(doc in crate::model::arbitrary::scoped_document()) {
        let doc = without_metadata(doc);
        prop_assert_eq!(round_trip(&doc), doc);
    }

    /// Decoding and encoding again gives the same bytes.
    #[test]
    fn encoding_is_stable_across_a_round_trip(doc in crate::model::arbitrary::document()) {
        let doc = without_metadata(doc);
        let a = cbor::encode(&to_value(&doc).unwrap()).unwrap();
        let again: PolicyDocument = round_trip(&doc);
        let b = cbor::encode(&to_value(&again).unwrap()).unwrap();
        prop_assert_eq!(a, b);
    }
}

#[test]
fn every_error_explains_itself() {
    let errors = [
        Error::UnregisteredKey("x".to_owned()),
        Error::UnknownCriticalKey(9),
        Error::UnknownVariant(9),
        Error::Float,
        Error::Encode(cbor::EncodeError::NotNfc),
        Error::Message("m".to_owned()),
        Error::ServerOnly("Metadata"),
    ];
    let texts: BTreeSet<String> = errors.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), errors.len());
}

#[test]
fn scalars_and_containers_round_trip() {
    assert_eq!(round_trip(&-5i8), -5);
    assert_eq!(round_trip(&-300i16), -300);
    assert_eq!(round_trip(&-70_000i32), -70_000);
    assert_eq!(round_trip(&i64::MIN), i64::MIN);
    assert_eq!(round_trip(&7u8), 7);
    assert_eq!(round_trip(&300u16), 300);
    assert_eq!(round_trip(&u64::MAX), u64::MAX);
    assert_eq!(round_trip(&-1i128), -1);
    assert_eq!(round_trip(&5u128), 5);
    assert_eq!(round_trip(&'x'), 'x');
    assert_eq!(round_trip(&()), ());
    assert_eq!(round_trip(&(1u8, "two".to_owned())), (1, "two".to_owned()));
    assert_eq!(round_trip(&Some(3u8)), Some(3));
    assert_eq!(round_trip(&None::<u8>), None);
    assert!(to_value(&(u128::MAX)).is_err());
    assert!(to_value(&i128::MIN).is_err());
    struct Raw(Vec<u8>);
    impl Serialize for Raw {
        fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            s.serialize_bytes(&self.0)
        }
    }
    assert_eq!(
        to_value(&Raw(vec![1, 2])).unwrap(),
        Value::Bytes(vec![1, 2])
    );
}

#[test]
fn malformed_shapes_are_refused() {
    // A struct with a text key, an enum that is neither an ID nor a
    // one-entry map, and a variant ID that is not an integer.
    let text_key =
        Value::Map(cbor::Map::new(vec![(Value::Text("k".to_owned()), Value::Null)]).unwrap());
    assert!(from_value::<PolicySettings>(text_key).is_err());
    assert!(from_value::<Mode>(Value::Bool(true)).is_err());
    let two = Value::Map(
        cbor::Map::new(vec![
            (Value::Uint(0), Value::Null),
            (Value::Uint(1), Value::Null),
        ])
        .unwrap(),
    );
    assert!(from_value::<crate::scope::NetworkRef>(two).is_err());
    let text_variant =
        Value::Map(cbor::Map::new(vec![(Value::Text("cidr".to_owned()), Value::Null)]).unwrap());
    assert!(from_value::<crate::scope::NetworkRef>(text_variant).is_err());
    // A unit variant given content.
    let unit_with_content =
        Value::Map(cbor::Map::new(vec![(to_value(&Mode::Audit).unwrap(), Value::Null)]).unwrap());
    assert!(from_value::<Mode>(unit_with_content).is_err());
}
