use proptest::prelude::*;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(Map::new(entries).unwrap())
}

/// The examples of RFC 8949 Appendix A that are in the subset, in their
/// canonical form.
fn rfc_vectors() -> Vec<(Value, &'static str)> {
    vec![
        (Value::Uint(0), "00"),
        (Value::Uint(1), "01"),
        (Value::Uint(10), "0a"),
        (Value::Uint(23), "17"),
        (Value::Uint(24), "1818"),
        (Value::Uint(25), "1819"),
        (Value::Uint(100), "1864"),
        (Value::Uint(1000), "1903e8"),
        (Value::Uint(1_000_000), "1a000f4240"),
        (Value::Uint(1_000_000_000_000), "1b000000e8d4a51000"),
        (Value::Uint(u64::MAX), "1bffffffffffffffff"),
        (Value::Nint(u64::MAX), "3bffffffffffffffff"),
        (Value::int(-1), "20"),
        (Value::int(-10), "29"),
        (Value::int(-100), "3863"),
        (Value::int(-1000), "3903e7"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Null, "f6"),
        (Value::Bytes(vec![]), "40"),
        (Value::Bytes(vec![1, 2, 3, 4]), "4401020304"),
        (text(""), "60"),
        (text("a"), "6161"),
        (text("IETF"), "6449455446"),
        (text("\"\\"), "62225c"),
        (text("\u{fc}"), "62c3bc"),
        (text("\u{6c34}"), "63e6b0b4"),
        (text("\u{10151}"), "64f0908591"),
        (Value::Array(vec![]), "80"),
        (
            Value::Array(vec![Value::Uint(1), Value::Uint(2), Value::Uint(3)]),
            "83010203",
        ),
        (
            Value::Array(vec![
                Value::Uint(1),
                Value::Array(vec![Value::Uint(2), Value::Uint(3)]),
                Value::Array(vec![Value::Uint(4), Value::Uint(5)]),
            ]),
            "8301820203820405",
        ),
        (
            Value::Array((1..=25).map(Value::Uint).collect()),
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
        ),
        (map(vec![]), "a0"),
        (
            map(vec![
                (Value::Uint(1), Value::Uint(2)),
                (Value::Uint(3), Value::Uint(4)),
            ]),
            "a201020304",
        ),
        (
            map(vec![
                (text("a"), Value::Uint(1)),
                (
                    text("b"),
                    Value::Array(vec![Value::Uint(2), Value::Uint(3)]),
                ),
            ]),
            "a26161016162820203",
        ),
        (
            Value::Array(vec![text("a"), map(vec![(text("b"), text("c"))])]),
            "826161a161626163",
        ),
    ]
}

#[test]
fn rfc_8949_examples_encode_and_decode_exactly() {
    for (value, expected) in rfc_vectors() {
        let bytes = hex(expected);
        assert_eq!(encode(&value).unwrap(), bytes, "encoding {value:?}");
        assert_eq!(decode(&bytes).unwrap(), value, "decoding {expected}");
    }
}

#[test]
fn integers_take_the_shortest_form_at_every_boundary() {
    let cases: [(u64, usize); 10] = [
        (23, 1),
        (24, 2),
        (0xff, 2),
        (0x100, 3),
        (0xffff, 3),
        (0x1_0000, 5),
        (0xffff_ffff, 5),
        (0x1_0000_0000, 9),
        (u64::MAX - 1, 9),
        (u64::MAX, 9),
    ];
    for (n, len) in cases {
        assert_eq!(encode(&Value::Uint(n)).unwrap().len(), len, "{n}");
        assert_eq!(encode(&Value::Nint(n)).unwrap().len(), len, "-1-{n}");
    }
}

#[test]
fn map_keys_sort_by_their_encoded_bytes() {
    // RFC 8949 §4.2.1: bytewise lexicographic order of the encoded keys, so
    // a shorter encoding sorts first, and 10 sorts before -1.
    let keys = [
        Value::Uint(10),
        Value::Uint(100),
        Value::int(-1),
        text("z"),
        text("aa"),
        Value::Array(vec![Value::Uint(100)]),
        Value::Array(vec![Value::int(-1)]),
        Value::Bool(false),
    ];
    let mut shuffled: Vec<(Value, Value)> = keys
        .iter()
        .rev()
        .map(|k| (k.clone(), Value::Null))
        .collect();
    shuffled.swap(1, 5);
    let m = Map::new(shuffled).unwrap();
    let sorted: Vec<&Value> = m.entries().iter().map(|(k, _)| k).collect();
    assert_eq!(sorted, keys.iter().collect::<Vec<_>>());
}

#[test]
fn equal_keys_are_refused_when_a_map_is_built() {
    let err = Map::new(vec![
        (Value::Uint(1), Value::Null),
        (Value::Uint(1), Value::Bool(true)),
    ])
    .unwrap_err();
    assert_eq!(err, EncodeError::DuplicateKey);
}

#[test]
fn text_that_is_not_nfc_cannot_be_encoded() {
    // `e` followed by a combining acute accent is NFD for `é`.
    assert_eq!(encode(&text("e\u{301}")), Err(EncodeError::NotNfc));
    assert!(encode(&text("\u{e9}")).is_ok());
}

#[test]
fn nesting_is_bounded_on_both_sides() {
    let mut v = Value::Null;
    for _ in 0..MAX_DEPTH {
        v = Value::Array(vec![v]);
    }
    let bytes = encode(&v).unwrap();
    assert_eq!(decode(&bytes).unwrap(), v);
    let deeper = Value::Array(vec![v]);
    assert_eq!(encode(&deeper), Err(EncodeError::TooDeep));
    let mut bytes = bytes;
    bytes.insert(0, 0x81);
    assert_eq!(decode(&bytes).unwrap_err().kind, DecodeErrorKind::TooDeep);
}

/// Inputs that are valid CBOR, or nearly, but not canonical, with what the
/// decoder must say about them.
const REJECTED: &[(&str, &str, DecodeErrorKind)] = &[
    ("empty", "", DecodeErrorKind::Truncated),
    ("trailing", "0000", DecodeErrorKind::TrailingBytes),
    ("long 0 in one byte", "1800", DecodeErrorKind::NonCanonical),
    ("long 23 in one byte", "1817", DecodeErrorKind::NonCanonical),
    (
        "long 255 in two bytes",
        "1900ff",
        DecodeErrorKind::NonCanonical,
    ),
    (
        "long 65535 in four",
        "1a0000ffff",
        DecodeErrorKind::NonCanonical,
    ),
    (
        "long u32 in eight",
        "1b00000000ffffffff",
        DecodeErrorKind::NonCanonical,
    ),
    ("long negative", "3800", DecodeErrorKind::NonCanonical),
    ("long length", "580161", DecodeErrorKind::NonCanonical),
    ("long count", "980100", DecodeErrorKind::NonCanonical),
    ("indefinite bytes", "5f4101ff", DecodeErrorKind::Indefinite),
    ("indefinite text", "7f6161ff", DecodeErrorKind::Indefinite),
    ("indefinite array", "9f01ff", DecodeErrorKind::Indefinite),
    ("indefinite map", "bf0101ff", DecodeErrorKind::Indefinite),
    ("break code", "ff", DecodeErrorKind::Indefinite),
    ("reserved info", "1c", DecodeErrorKind::Reserved),
    ("reserved simple", "fc", DecodeErrorKind::Reserved),
    ("half float", "f93c00", DecodeErrorKind::Float),
    ("single float", "fa47c35000", DecodeErrorKind::Float),
    ("double float", "fb3ff199999999999a", DecodeErrorKind::Float),
    ("tag", "c11a514b67b0", DecodeErrorKind::Tag),
    ("bignum tag", "c249010000000000000000", DecodeErrorKind::Tag),
    ("undefined", "f7", DecodeErrorKind::Simple),
    ("simple 16", "f0", DecodeErrorKind::Simple),
    ("simple in a byte", "f818", DecodeErrorKind::Simple),
    ("invalid UTF-8", "62c328", DecodeErrorKind::InvalidUtf8),
    ("not NFC", "6365cc81", DecodeErrorKind::NotNfc),
    ("duplicate key", "a201000100", DecodeErrorKind::DuplicateKey),
    ("unsorted keys", "a202000100", DecodeErrorKind::UnsortedKeys),
    (
        "shorter key after",
        "a218640017f6",
        DecodeErrorKind::UnsortedKeys,
    ),
    (
        "negative before positive",
        "a2200001f6",
        DecodeErrorKind::UnsortedKeys,
    ),
    ("truncated argument", "19ff", DecodeErrorKind::Truncated),
    ("truncated bytes", "4501", DecodeErrorKind::Truncated),
    ("truncated array", "8201", DecodeErrorKind::Truncated),
    ("truncated map value", "a101", DecodeErrorKind::Truncated),
    (
        "huge length",
        "5bffffffffffffffff",
        DecodeErrorKind::Truncated,
    ),
    (
        "huge count",
        "9bffffffffffffffff",
        DecodeErrorKind::Truncated,
    ),
    ("huge map", "bb7fffffffffffffff", DecodeErrorKind::Truncated),
];

#[test]
fn non_canonical_and_unsupported_inputs_are_rejected() {
    for (name, input, kind) in REJECTED {
        let err = decode(&hex(input)).expect_err(name);
        assert_eq!(err.kind, *kind, "{name}: {err}");
    }
}

#[test]
fn limits_bound_size_and_item_count() {
    let bytes = encode(&Value::Array(vec![Value::Uint(0); 10])).unwrap();
    let small = Limits {
        max_bytes: bytes.len() - 1,
        ..Limits::DEFAULT
    };
    assert_eq!(
        decode_with_limits(&bytes, &small).unwrap_err().kind,
        DecodeErrorKind::TooLarge
    );
    let few = Limits {
        max_items: 10,
        ..Limits::DEFAULT
    };
    assert_eq!(
        decode_with_limits(&bytes, &few).unwrap_err().kind,
        DecodeErrorKind::TooManyItems
    );
    let enough = Limits {
        max_items: 11,
        ..Limits::DEFAULT
    };
    assert!(decode_with_limits(&bytes, &enough).is_ok());
}

#[test]
fn a_prefix_is_read_without_what_follows() {
    let mut bytes = encode(&text("head")).unwrap();
    let len = bytes.len();
    bytes.extend_from_slice(&[0xff, 0xff]);
    let (value, used) = decode_prefix(&bytes, &Limits::DEFAULT).unwrap();
    assert_eq!((value, used), (text("head"), len));
}

#[test]
fn errors_name_the_offset_of_the_item_at_fault() {
    // The second element of the array is a float, at byte 2.
    let err = decode(&hex("8201f93c00")).unwrap_err();
    assert_eq!(
        err,
        DecodeError {
            offset: 2,
            kind: DecodeErrorKind::Float
        }
    );
    assert_eq!(err.to_string(), "floating point is not allowed (at byte 2)");
}

#[test]
fn as_i64_reads_both_signs_and_refuses_overflow() {
    assert_eq!(Value::int(i64::MIN).as_i64(), Some(i64::MIN));
    assert_eq!(Value::int(i64::MAX).as_i64(), Some(i64::MAX));
    assert_eq!(Value::Uint(u64::MAX).as_i64(), None);
    assert_eq!(Value::Nint(u64::MAX).as_i64(), None);
    assert_eq!(text("1").as_i64(), None);
}

pub(crate) fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        (0u64..30).prop_map(Value::Uint),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        // Any text, normalised: decomposed input must not leak through.
        ".{0,12}".prop_map(|s| {
            use unicode_normalization::UnicodeNormalization;
            Value::Text(s.nfc().collect())
        }),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(5, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::vec((inner.clone(), inner), 0..8).prop_map(|entries| {
                // Later duplicates are dropped, so the map can be built.
                let mut seen = Vec::new();
                let entries = entries
                    .into_iter()
                    .filter(|(k, _)| {
                        let e = encode(k).unwrap();
                        let fresh = !seen.contains(&e);
                        seen.push(e);
                        fresh
                    })
                    .collect();
                Value::Map(Map::new(entries).unwrap())
            }),
        ]
    })
}

/// A mutation of a valid encoding: flip a byte, truncate, insert or remove.
#[derive(Clone, Debug)]
enum Mutation {
    Flip(usize, u8),
    Truncate(usize),
    Insert(usize, u8),
    Remove(usize),
}

fn mutate(mut bytes: Vec<u8>, m: &Mutation) -> Vec<u8> {
    let len = bytes.len();
    match *m {
        Mutation::Flip(i, x) if len > 0 => bytes[i % len] ^= x | 1,
        Mutation::Truncate(i) => bytes.truncate(i % (len + 1)),
        Mutation::Insert(i, x) => bytes.insert(i % (len + 1), x),
        Mutation::Remove(i) if len > 0 => {
            bytes.remove(i % len);
        }
        _ => {}
    }
    bytes
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(i, x)| Mutation::Flip(i, x)),
        any::<usize>().prop_map(Mutation::Truncate),
        (any::<usize>(), any::<u8>()).prop_map(|(i, x)| Mutation::Insert(i, x)),
        any::<usize>().prop_map(Mutation::Remove),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Every value round-trips, and its encoding is the only one the decoder
    /// accepts for it.
    #[test]
    fn every_value_round_trips(v in value()) {
        let bytes = encode(&v).unwrap();
        prop_assert_eq!(decode(&bytes).unwrap(), v);
    }

    /// The order entries are given in never changes a map's bytes.
    #[test]
    fn map_bytes_do_not_depend_on_entry_order(v in value(), seed in any::<u64>()) {
        if let Value::Map(m) = &v {
            let mut entries = m.entries().to_vec();
            let mut s = seed | 1;
            for i in (1..entries.len()).rev() {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                let j = usize::try_from(s % u64::try_from(i + 1).unwrap()).unwrap();
                entries.swap(i, j);
            }
            let again = Value::Map(Map::new(entries).unwrap());
            prop_assert_eq!(encode(&again).unwrap(), encode(&v).unwrap());
        }
    }

    /// Whatever a mutated encoding decodes to, if anything, encodes back to
    /// exactly the mutated bytes: the decoder accepts only canonical input.
    #[test]
    fn accepted_input_is_always_canonical(v in value(), m in mutation()) {
        let bytes = mutate(encode(&v).unwrap(), &m);
        if let Ok(decoded) = decode(&bytes) {
            prop_assert_eq!(encode(&decoded).unwrap(), bytes);
        }
    }

    /// Arbitrary bytes never panic the decoder, and anything accepted is
    /// canonical.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(decoded) = decode(&bytes) {
            prop_assert_eq!(encode(&decoded).unwrap(), bytes);
        }
    }
}
