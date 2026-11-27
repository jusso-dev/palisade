use proptest::prelude::*;

use super::*;
use crate::bundle::cbor::{Map, Value};
use crate::model::{Mode, arbitrary};
use crate::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash, publisher};

fn id(n: u8) -> Uuid7 {
    let mut b = [0u8; 16];
    b[0] = n;
    b[6] = 0x70;
    b[8] = 0x80;
    Uuid7::from_bytes(b).unwrap()
}

fn target() -> Target {
    Target {
        tenant: id(1),
        scope: TargetScope::Group(id(2)),
    }
}

fn header() -> Header {
    Header {
        min_agent_version: AgentVersion::new(0, 3, 1),
        expires_at: Some(1_900_000_000_000_000),
        ..Header::new(target(), 7, 1_800_000_000_000_000)
    }
}

fn sample() -> PolicyDocument {
    PolicyBuilder::new()
        .rule_set(
            RuleSetBuilder::allowlist(1)
                .rule(RuleBuilder::allow(2, hash('a')))
                .rule(RuleBuilder::allow(1, publisher("O=Example Corp, C=AU"))),
        )
        .rule_set(RuleSetBuilder::mandatory_blocklist(2).rule(RuleBuilder::deny(3, hash('b'))))
        .build()
}

fn bundle_of(doc: PolicyDocument) -> PolicyBundle {
    let sources = SourceRevisions {
        policies: vec![(doc.policy.id, doc.policy.revision)],
        libraries: Vec::new(),
    };
    PolicyBundle::new(header(), Body::new(doc, Vec::new(), sources).unwrap())
}

fn bytes_of(doc: PolicyDocument) -> Vec<u8> {
    bundle_of(doc).to_bytes().unwrap()
}

fn decode(bytes: &[u8]) -> Result<PolicyBundle, BundleError> {
    PolicyBundle::decode(bytes, &BundleLimits::DEFAULT)
}

/// The decoded value of a bundle, for editing in tests.
fn parts(bytes: &[u8]) -> (Map, Value) {
    let Value::Array(mut items) = cbor::decode(bytes).unwrap() else {
        panic!("not an array")
    };
    let body = items.pop().unwrap();
    let Value::Map(header) = items.pop().unwrap() else {
        panic!("no header map")
    };
    (header, body)
}

fn join(header: Map, body: Value) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![Value::Map(header), body])).unwrap()
}

fn with_entry(m: Map, key: i64, value: Value) -> Map {
    let mut entries: Vec<_> = m
        .into_entries()
        .into_iter()
        .filter(|(k, _)| k.as_i64() != Some(key))
        .collect();
    entries.push((Value::int(key), value));
    Map::new(entries).unwrap()
}

fn key(name: &str) -> i64 {
    keys::id(name).unwrap()
}

#[test]
fn every_header_and_body_key_is_registered() {
    for name in [
        "format_version",
        "schema_version",
        "tenant",
        "target",
        "group",
        "device",
        "policy_version",
        "min_agent_version",
        "generated_at",
        "expires_at",
        "document",
        "libraries",
        "source_revisions",
        "metadata_digest",
        "policies",
        "resolved_version",
        "content",
    ] {
        assert!(keys::id(name).is_some(), "`{name}` has no key");
    }
}

#[test]
fn a_bundle_round_trips_byte_for_byte() {
    let bundle = bundle_of(sample());
    let bytes = bundle.to_bytes().unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.to_bytes().unwrap(), bytes);
}

#[test]
fn the_header_decodes_without_the_body() {
    let bytes = bytes_of(sample());
    assert_eq!(
        decode_header(&bytes, &BundleLimits::DEFAULT).unwrap(),
        header()
    );
    // A corrupt body does not stop the header from reading, so the envelope
    // can report the target and version of a bundle it then rejects.
    let damaged = &bytes[..bytes.len() - 1];
    assert_eq!(
        decode_header(damaged, &BundleLimits::DEFAULT).unwrap(),
        header()
    );
    assert!(decode(damaged).is_err());
}

#[test]
fn header_checks_report_agent_and_schema_support() {
    let h = header();
    assert!(h.supports_agent(AgentVersion::new(0, 3, 1)));
    assert!(h.supports_agent(AgentVersion::new(1, 0, 0)));
    assert!(!h.supports_agent(AgentVersion::new(0, 3, 0)));
    assert!(h.schema_supported());
    let newer = Header {
        schema_version: SchemaVersion::new(2, 0, 0),
        ..h
    };
    assert!(!newer.schema_supported());
}

#[test]
fn rule_and_rule_set_order_never_changes_the_bytes() {
    let doc = sample();
    let mut reversed = doc.clone();
    reversed.rule_sets.reverse();
    reversed.policy.rule_sets.reverse();
    for set in &mut reversed.rule_sets {
        set.rules.reverse();
    }
    assert_ne!(doc, reversed);
    assert_eq!(bytes_of(doc), bytes_of(reversed));
}

#[test]
fn governance_metadata_becomes_a_digest() {
    let doc = sample();
    let mut with_ticket = doc.clone();
    with_ticket.rule_sets[0].rules[0].metadata.ticket_ref = Some("CHG-42".to_owned());
    let plain = bundle_of(doc);
    let ticketed = bundle_of(with_ticket);
    assert_eq!(ticketed.body.document(), plain.body.document());
    assert_ne!(
        ticketed.body.metadata_digest(),
        plain.body.metadata_digest()
    );
    assert_ne!(
        ticketed.bundle_hash().unwrap(),
        plain.bundle_hash().unwrap()
    );
    assert_eq!(
        ticketed.decision_hash().unwrap(),
        plain.decision_hash().unwrap()
    );
    let bytes = ticketed.to_bytes().unwrap();
    assert!(
        !bytes.windows(6).any(|w| w == b"CHG-42"),
        "the ticket leaked"
    );
}

#[test]
fn the_decision_hash_ignores_text_header_and_sources() {
    let base = bundle_of(sample());
    let h = base.decision_hash().unwrap();
    let mut edited = sample();
    edited.policy.name = "Renamed".to_owned();
    edited.policy.description = Some("New words".to_owned());
    edited.policy.revision = 99;
    edited.rule_sets[0].name = "Other".to_owned();
    edited.rule_sets[0].version = Some("2.0".to_owned());
    edited.rule_sets[0].rules[0].name = "Rule".to_owned();
    edited.rule_sets[0].rules[0].description = Some("x".to_owned());
    let mut b = bundle_of(edited);
    b.header.policy_version = 8;
    b.header.generated_at += 1;
    b.header.expires_at = None;
    b.body.source_revisions.policies = vec![(PolicyId(id(9)), 99)];
    assert_eq!(b.decision_hash().unwrap(), h);
    assert_ne!(b.bundle_hash().unwrap(), base.bundle_hash().unwrap());
}

#[test]
fn the_decision_hash_changes_with_any_rule_mode_or_setting() {
    let h = bundle_of(sample()).decision_hash().unwrap();
    let mut edits: Vec<(&str, PolicyDocument)> = Vec::new();
    let mut d = sample();
    d.policy.mode = Mode::Audit;
    edits.push(("mode", d));
    let mut d = sample();
    d.policy.settings.poll_interval_secs += 60;
    edits.push(("setting", d));
    let mut d = sample();
    d.policy.precedence_model = crate::model::PrecedenceModel::AllowWins;
    edits.push(("precedence", d));
    let mut d = sample();
    d.rule_sets[0].rules[0].enabled = false;
    edits.push(("rule enabled", d));
    let mut d = sample();
    d.rule_sets[0].rules[0].match_ = hash('c');
    edits.push(("rule match", d));
    let mut d = sample();
    d.rule_sets[1].rules.clear();
    edits.push(("rule removed", d));
    let mut d = sample();
    d.policy.mode_options.disconnected_after_secs = Some(3600);
    edits.push(("mode options", d));
    for (what, doc) in edits {
        assert_ne!(bundle_of(doc).decision_hash().unwrap(), h, "{what}");
    }
}

#[test]
fn the_size_limit_is_enforced_with_advice() {
    let bytes = bytes_of(sample());
    let limits = BundleLimits {
        max_bytes: bytes.len() - 1,
        ..BundleLimits::DEFAULT
    };
    assert!(decode(&bytes).is_ok());
    let err = PolicyBundle::decode(&bytes, &limits);
    let Err(e @ BundleError::TooLarge { .. }) = err else {
        panic!("{err:?}");
    };
    assert!(e.to_string().contains("split it"));
    assert!(matches!(
        decode_header(&bytes, &limits),
        Err(BundleError::TooLarge { .. })
    ));
}

#[test]
fn unknown_header_keys_follow_their_sign() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let critical = i64::try_from(keys::KEYS.len()).unwrap() + 500;
    let bad = join(
        with_entry(header_map.clone(), critical, Value::Null),
        body.clone(),
    );
    assert_eq!(decode(&bad), Err(BundleError::UnknownCriticalKey(critical)));
    assert_eq!(
        decode_header(&bad, &BundleLimits::DEFAULT),
        Err(BundleError::UnknownCriticalKey(critical))
    );
    let fine = join(with_entry(header_map, -500, Value::Null), body);
    let decoded = decode(&fine).unwrap();
    assert_eq!(decoded.header, header());
    // The unknown ignorable entry is dropped, so the bytes differ.
    assert_ne!(decoded.to_bytes().unwrap(), fine);
}

#[test]
fn unknown_body_keys_follow_their_sign() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let Value::Map(body) = body else { panic!() };
    let critical = i64::try_from(keys::KEYS.len()).unwrap() + 500;
    let bad = join(
        header_map.clone(),
        Value::Map(with_entry(body.clone(), critical, Value::Null)),
    );
    assert_eq!(decode(&bad), Err(BundleError::UnknownCriticalKey(critical)));
    let fine = join(header_map, Value::Map(with_entry(body, -500, Value::Null)));
    assert!(decode(&fine).is_ok());
}

#[test]
fn a_newer_format_or_schema_is_refused_by_name() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let newer = join(
        with_entry(header_map.clone(), key("format_version"), Value::Uint(2)),
        body.clone(),
    );
    assert_eq!(decode(&newer), Err(BundleError::UnsupportedFormat(2)));
    assert_eq!(
        decode_header(&newer, &BundleLimits::DEFAULT),
        Err(BundleError::UnsupportedFormat(2))
    );
    let schema = Value::Array(vec![Value::Uint(2), Value::Uint(0), Value::Uint(0)]);
    let newer = join(with_entry(header_map, key("schema_version"), schema), body);
    assert_eq!(
        decode(&newer),
        Err(BundleError::UnsupportedSchema(SchemaVersion::new(2, 0, 0)))
    );
}

#[test]
fn a_body_out_of_canonical_order_is_refused() {
    // Encode the body of the unsorted document directly, bypassing
    // `Body::new`, so the rules are out of order.
    let mut doc = sample();
    doc.rule_sets.reverse();
    let unsorted = BodyRepr {
        document: doc,
        libraries: Vec::new(),
        source_revisions: SourceRevisions::default(),
        metadata_digest: Bytes32([0; 32]),
    };
    let body = serial::to_value(&unsorted).unwrap();
    let bytes = cbor::encode(&Value::Array(vec![header().to_value().unwrap(), body])).unwrap();
    assert_eq!(decode(&bytes), Err(BundleError::NonCanonical));
}

#[test]
fn a_default_written_out_is_refused() {
    // `rule_sets[].band` is left out when 0; writing it is a second
    // encoding of the same content.
    let (header_map, body) = parts(&bytes_of(sample()));
    let Value::Map(body) = body else { panic!() };
    let doc_key = Value::int(key("document"));
    let Value::Map(doc) = body.get(&doc_key).unwrap().clone() else {
        panic!()
    };
    let sets_key = Value::int(key("rule_sets"));
    let Value::Array(mut sets) = doc.get(&sets_key).unwrap().clone() else {
        panic!()
    };
    let Value::Map(first) = sets.remove(0) else {
        panic!()
    };
    sets.insert(
        0,
        Value::Map(with_entry(first, key("band"), Value::Uint(0))),
    );
    let doc = with_entry(doc, key("rule_sets"), Value::Array(sets));
    let body = with_entry(body, key("document"), Value::Map(doc));
    assert_eq!(
        decode(&join(header_map, Value::Map(body))),
        Err(BundleError::NonCanonical)
    );
}

/// Malformed inputs and what the decoder says about them.
#[test]
fn malformed_bundles_are_rejected() {
    let good = bytes_of(sample());
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("not an array", vec![0xa0]),
        ("one item", vec![0x81, 0xa0]),
        ("three items", {
            let mut b = good.clone();
            b[0] = 0x83;
            b.push(0xf6);
            b
        }),
        ("trailing byte", {
            let mut b = good.clone();
            b.push(0);
            b
        }),
        ("truncated", good[..good.len() / 2].to_vec()),
        ("float header", vec![0x82, 0xf9, 0x3c, 0x00, 0xa0]),
        ("indefinite body", vec![0x82, 0xa0, 0xbf, 0xff]),
    ];
    for (name, bytes) in cases {
        assert!(decode(&bytes).is_err(), "{name} was accepted");
    }
}

#[test]
fn missing_header_fields_are_named() {
    let (header_map, body) = parts(&bytes_of(sample()));
    for field in ["tenant", "target", "policy_version", "generated_at"] {
        let m = Map::new(
            header_map
                .entries()
                .iter()
                .filter(|(k, _)| k.as_i64() != Some(key(field)))
                .cloned()
                .collect(),
        )
        .unwrap();
        assert!(
            matches!(decode(&join(m, body.clone())), Err(BundleError::Missing(f)) if f == field),
            "{field}"
        );
    }
}

#[test]
fn invalid_ids_and_overflow_are_refused() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let not_v7 = join(
        with_entry(header_map.clone(), key("tenant"), Value::Bytes(vec![0; 16])),
        body.clone(),
    );
    assert_eq!(decode(&not_v7), Err(BundleError::InvalidId("tenant")));
    let negative = join(
        with_entry(header_map.clone(), key("policy_version"), Value::int(-1)),
        body.clone(),
    );
    assert_eq!(
        decode(&negative),
        Err(BundleError::Overflow("policy_version"))
    );
    let big = Value::Array(vec![Value::Uint(1 << 40), Value::Uint(0), Value::Uint(0)]);
    let agent = join(with_entry(header_map, key("min_agent_version"), big), body);
    assert_eq!(
        decode(&agent),
        Err(BundleError::Overflow("min_agent_version"))
    );
}

#[test]
fn a_decoded_body_that_is_not_a_valid_policy_is_refused_by_validate() {
    let mut doc = sample();
    doc.policy.rule_sets.push(crate::model::RuleSetId(id(77)));
    let bundle = decode(&bytes_of(doc)).unwrap();
    let errors = bundle.validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.path.starts_with("/policy/rule_sets")),
        "{errors:?}"
    );
}

#[test]
fn a_device_target_round_trips() {
    let mut b = bundle_of(sample());
    b.header.target.scope = TargetScope::Device(id(3));
    b.header.expires_at = None;
    let bytes = b.to_bytes().unwrap();
    assert_eq!(decode(&bytes).unwrap(), b);
}

#[test]
fn inlined_sets_are_sorted_and_unique() {
    let lib = |n, v| InlineLibrary {
        id: LibraryId(id(n)),
        resolved_version: v,
        content: SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()]),
    };
    let body = Body::new(
        sample(),
        vec![lib(5, 2), lib(4, 1), lib(5, 2), lib(5, 1)],
        SourceRevisions::default(),
    )
    .unwrap();
    let order: Vec<(u8, u32)> = body
        .libraries()
        .iter()
        .map(|l| (l.id.0.as_bytes()[0], l.resolved_version))
        .collect();
    assert_eq!(order, [(4, 1), (5, 1), (5, 2)]);
    let b = PolicyBundle::new(header(), body);
    assert_eq!(decode(&b.to_bytes().unwrap()).unwrap(), b);
}

#[test]
fn text_is_held_in_nfc_so_memory_and_bytes_agree() {
    let mut doc = sample();
    doc.rule_sets[0].rules[0].name = "Cafe\u{301}".to_owned();
    let rule = doc.rule_sets[0].rules[0].id;
    let b = bundle_of(doc);
    let names: Vec<&str> = b
        .body
        .document()
        .rule_sets
        .iter()
        .flat_map(|s| &s.rules)
        .filter(|r| r.id == rule)
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(names, ["Caf\u{e9}"]);
    assert_eq!(decode(&b.to_bytes().unwrap()).unwrap(), b);
}

#[test]
fn hex_is_lowercase_and_64_digits() {
    let h = hex(&bundle_hash(b""));
    assert_eq!(
        h,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// encode → decode → encode is byte-identical for every valid policy.
    #[test]
    fn every_policy_round_trips(doc in arbitrary::scoped_document()) {
        let bundle = bundle_of(doc);
        let bytes = bundle.to_bytes().unwrap();
        let decoded = decode(&bytes).unwrap();
        prop_assert_eq!(decoded.to_bytes().unwrap(), bytes);
        prop_assert_eq!(decoded, bundle);
    }

    /// Shuffling rule sets, rules, assignments and profiles never changes
    /// the bytes.
    #[test]
    fn order_never_changes_the_bytes(doc in arbitrary::scoped_document(), seed in any::<u64>()) {
        let mut s = seed | 1;
        let mut next = move |n: usize| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            usize::try_from(s % u64::try_from(n.max(1)).unwrap()).unwrap()
        };
        let mut shuffled = doc.clone();
        for i in (1..shuffled.rule_sets.len()).rev() {
            shuffled.rule_sets.swap(i, next(i + 1));
        }
        for i in (1..shuffled.policy.rule_sets.len()).rev() {
            shuffled.policy.rule_sets.swap(i, next(i + 1));
        }
        for set in &mut shuffled.rule_sets {
            for i in (1..set.rules.len()).rev() {
                set.rules.swap(i, next(i + 1));
            }
        }
        prop_assert_eq!(bytes_of(doc), bytes_of(shuffled));
    }

    /// Any mutation of a valid bundle either fails to decode or decodes to
    /// a bundle whose bytes are the mutated bytes, with at most unknown
    /// ignorable entries dropped. It never panics.
    #[test]
    fn mutated_bundles_never_decode_to_other_bytes(
        doc in arbitrary::document(),
        at in any::<usize>(),
        x in 1u8..,
    ) {
        let mut bytes = bytes_of(doc);
        let i = at % bytes.len();
        bytes[i] ^= x;
        let _ = decode_header(&bytes, &BundleLimits::DEFAULT);
        if let Ok(b) = decode(&bytes) {
            // Turning a critical key into an unknown ignorable one drops
            // that entry: whether a key may be skipped is in its bytes, so
            // only the signature (#225) protects against it. Everything
            // else must be exactly what was read.
            let again = cbor::decode(&b.to_bytes().unwrap()).unwrap();
            prop_assert!(same_but_dropped(&cbor::decode(&bytes).unwrap(), &again));
        }
    }

    /// The decoded policy is still a valid policy, and decides as the
    /// policy it was built from: validation gives the same document.
    #[test]
    fn decoded_policies_validate_to_the_same_document(doc in arbitrary::document()) {
        let bundle = decode(&bytes_of(doc.clone())).unwrap();
        let validated = bundle.validate().unwrap();
        let expected = Body::new(doc.validate().unwrap().into_document(), Vec::new(), SourceRevisions::default()).unwrap();
        prop_assert_eq!(validated.document(), expected.document());
    }
}

/// Each malformed header field and the error the reader gives for it, by
/// name, so the envelope can report exactly what is wrong.
#[test]
fn malformed_header_fields_are_named() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let three = |a, b, c| Value::Array(vec![Value::Uint(a), Value::Uint(b), Value::Uint(c)]);
    let one = |k: i64, v: Value| Value::Map(Map::new(vec![(Value::int(k), v)]).unwrap());
    let uuid = Value::Bytes(id(5).as_bytes().to_vec());
    let critical = i64::try_from(keys::KEYS.len()).unwrap() + 700;
    let cases: Vec<(&str, i64, Value, BundleError)> = vec![
        (
            "text format version",
            key("format_version"),
            Value::Text("1".into()),
            BundleError::Shape("`format_version` is not an integer"),
        ),
        (
            "text policy version",
            key("policy_version"),
            Value::Text("7".into()),
            BundleError::Shape("an integer field holds something else"),
        ),
        (
            "text generated_at",
            key("generated_at"),
            Value::Null,
            BundleError::Shape("an integer field holds something else"),
        ),
        (
            "generated_at beyond i64",
            key("generated_at"),
            Value::Uint(u64::MAX),
            BundleError::Overflow("generated_at"),
        ),
        (
            "schema version as text",
            key("schema_version"),
            Value::Text("1.0.0".into()),
            BundleError::Shape("a version is not an array"),
        ),
        (
            "schema version of two parts",
            key("schema_version"),
            Value::Array(vec![Value::Uint(1), Value::Uint(0)]),
            BundleError::Shape("a version is not three integers"),
        ),
        (
            "negative schema part",
            key("schema_version"),
            Value::Array(vec![Value::Uint(1), Value::int(-1), Value::Uint(0)]),
            BundleError::Overflow("schema_version"),
        ),
        (
            "tenant as text",
            key("tenant"),
            Value::Text("t".into()),
            BundleError::Shape("an ID is not a byte string"),
        ),
        (
            "tenant of 15 bytes",
            key("tenant"),
            Value::Bytes(vec![0; 15]),
            BundleError::InvalidId("tenant"),
        ),
        (
            "target as an array",
            key("target"),
            Value::Array(vec![]),
            BundleError::Shape("the target is not a map"),
        ),
        (
            "target naming two scopes",
            key("target"),
            Value::Map(
                Map::new(vec![
                    (Value::int(key("group")), uuid.clone()),
                    (Value::int(key("device")), uuid.clone()),
                ])
                .unwrap(),
            ),
            BundleError::Shape("the target names more than one scope"),
        ),
        (
            "target of an unknown critical kind",
            key("target"),
            one(critical, uuid.clone()),
            BundleError::UnknownCriticalKey(critical),
        ),
        (
            "target of a known key that is no scope",
            key("target"),
            one(key("tenant"), uuid.clone()),
            BundleError::UnknownCriticalKey(key("tenant")),
        ),
        (
            "target of an ignorable kind",
            key("target"),
            one(-5, uuid),
            BundleError::Shape("the target is neither a group nor a device"),
        ),
        (
            "min agent version part beyond u32",
            key("min_agent_version"),
            three(1 << 33, 0, 0),
            BundleError::Overflow("min_agent_version"),
        ),
    ];
    for (what, k, v, expected) in cases {
        let bytes = join(with_entry(header_map.clone(), k, v), body.clone());
        assert_eq!(decode(&bytes), Err(expected.clone()), "{what}");
        assert_eq!(
            decode_header(&bytes, &BundleLimits::DEFAULT),
            Err(expected),
            "{what} (header only)"
        );
    }
    // A missing format version, and a header key that is not an integer.
    let no_format = Map::new(
        header_map
            .entries()
            .iter()
            .filter(|(k, _)| k.as_i64() != Some(key("format_version")))
            .cloned()
            .collect(),
    )
    .unwrap();
    assert_eq!(
        decode(&join(no_format, body.clone())),
        Err(BundleError::Missing("format_version"))
    );
    let mut entries = header_map.into_entries();
    entries.push((Value::Text("x".into()), Value::Null));
    assert_eq!(
        decode(&join(Map::new(entries).unwrap(), body.clone())),
        Err(BundleError::Shape("a header key is not an integer"))
    );
    // A header that is not a map at all.
    let bytes = cbor::encode(&Value::Array(vec![Value::Uint(1), body])).unwrap();
    assert_eq!(
        decode(&bytes),
        Err(BundleError::Shape("the header is not a map"))
    );
}

#[test]
fn every_bundle_error_explains_itself() {
    let errors = [
        BundleError::TooLarge { size: 2, limit: 1 },
        BundleError::Cbor(cbor::decode(&[0xff]).unwrap_err()),
        BundleError::Shape("s"),
        BundleError::Missing("tenant"),
        BundleError::Overflow("policy_version"),
        BundleError::InvalidId("tenant"),
        BundleError::UnknownCriticalKey(9),
        BundleError::UnsupportedFormat(2),
        BundleError::UnsupportedSchema(SchemaVersion::new(2, 0, 0)),
        BundleError::Body(serial::Error::Float),
        BundleError::NonCanonical,
    ];
    let texts: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(texts.len(), errors.len(), "two errors share a message");
    assert!(texts.iter().all(|t| !t.is_empty()));
    assert_eq!(AgentVersion::new(1, 2, 3).to_string(), "1.2.3");
    assert_eq!(BundleLimits::default(), BundleLimits::DEFAULT);
}

#[test]
fn only_the_sets_a_scope_reads_can_be_inlined() {
    let lib =
        |content: serde_json::Value| -> LibraryContent { serde_json::from_value(content).unwrap() };
    let cases = [
        (
            lib(serde_json::json!({"kind": "principal_set", "principals": ["S-1-5-32-544"]})),
            Some(SetContent::PrincipalSet(vec!["S-1-5-32-544".to_owned()])),
        ),
        (
            lib(serde_json::json!({"kind": "device_set", "devices": ["d"]})),
            Some(SetContent::DeviceSet(vec!["d".to_owned()])),
        ),
        (
            lib(serde_json::json!({"kind": "network_set", "entries": ["10.0.0.0/8"]})),
            Some(SetContent::NetworkSet(vec!["10.0.0.0/8".to_owned()])),
        ),
        (
            lib(serde_json::json!({"kind": "schedule_set", "entries": ["{}"]})),
            Some(SetContent::ScheduleSet(vec!["{}".to_owned()])),
        ),
        (
            lib(serde_json::json!({"kind": "message_template", "text": "t"})),
            None,
        ),
    ];
    for (content, expected) in cases {
        assert_eq!(SetContent::of(&content), expected);
    }
}

#[test]
fn sources_and_profiles_are_kept_in_canonical_order() {
    let mut doc = sample();
    doc.policy.location_profiles = ["zeta", "alpha"]
        .iter()
        .map(|n| {
            serde_json::from_value(serde_json::json!({
                "name": n, "all": [{"server_reachable": true}],
            }))
            .unwrap()
        })
        .collect();
    let sources = SourceRevisions {
        policies: vec![
            (PolicyId(id(9)), 2),
            (PolicyId(id(3)), 1),
            (PolicyId(id(9)), 2),
        ],
        libraries: vec![(LibraryId(id(4)), 2), (LibraryId(id(4)), 1)],
    };
    let body = Body::new(doc, Vec::new(), sources).unwrap();
    let names: Vec<&str> = body
        .document()
        .policy
        .location_profiles
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(names, ["alpha", "zeta"]);
    let s = body.source_revisions();
    assert_eq!(s.policies, [(PolicyId(id(3)), 1), (PolicyId(id(9)), 2)]);
    assert_eq!(s.libraries, [(LibraryId(id(4)), 1), (LibraryId(id(4)), 2)]);
}

#[test]
fn a_metadata_digest_must_be_32_bytes() {
    let (header_map, body) = parts(&bytes_of(sample()));
    let Value::Map(body) = body else { panic!() };
    let short = with_entry(body, key("metadata_digest"), Value::Bytes(vec![0; 31]));
    assert!(matches!(
        decode(&join(header_map, Value::Map(short))),
        Err(BundleError::Body(serial::Error::Message(m))) if m.contains("32 bytes")
    ));
}
