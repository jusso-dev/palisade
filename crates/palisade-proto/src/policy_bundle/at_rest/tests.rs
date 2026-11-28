// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::collections::HashSet;

use proptest::prelude::*;

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ring() -> KeyRing {
    KeyRing::generate().unwrap()
}

fn sealed(ring: &mut KeyRing, plaintext: &[u8]) -> Vec<u8> {
    ring.reserve().unwrap();
    ring.seal(plaintext).unwrap()
}

/// AES-256-GCM known answer: test case 16 of the GCM specification
/// (McGrew and Viega), which NIST's GCMVS vectors include.
#[test]
fn aes_256_gcm_known_answer() {
    let key: [u8; 32] = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        .try_into()
        .unwrap();
    let nonce: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
    let plaintext = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    );
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let expected = hex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662\
         76fc6ece0f4e1768cddf8853bb2d551b",
    );
    let k = AeadKey::new(&key).unwrap();
    assert_eq!(k.seal_with_nonce(nonce, &aad, &plaintext), expected);
    let mut framed = nonce.to_vec();
    framed.extend_from_slice(&expected);
    assert_eq!(k.open(&aad, &framed).unwrap(), plaintext);
    assert!(k.open(b"other", &framed).is_none());
    assert_eq!(format!("{k:?}"), "AeadKey(..)");
}

#[test]
fn a_sealed_file_opens_to_its_plaintext_and_nothing_else() {
    let mut r = ring();
    let file = sealed(&mut r, b"envelope bytes");
    assert!(looks_sealed(&file));
    assert_eq!(file.len(), b"envelope bytes".len() + OVERHEAD);
    assert_eq!(r.open(&file).unwrap(), b"envelope bytes");
    // An empty plaintext seals too.
    let empty = sealed(&mut r, b"");
    assert_eq!(r.open(&empty).unwrap(), b"");

    // Any flipped byte fails: header (key ID, magic, version), nonce, body
    // or tag.
    for i in 0..file.len() {
        let mut bad = file.clone();
        bad[i] ^= 1;
        assert!(r.open(&bad).is_err(), "byte {i}");
    }
    for n in 0..OVERHEAD {
        assert!(r.open(&file[..n]).is_err(), "length {n}");
    }
    // Another keyring cannot open it.
    assert_eq!(ring().open(&file), Err(AtRestError::UnknownKey));
}

#[test]
fn every_seal_needs_a_reservation() {
    let mut r = ring();
    assert_eq!(r.seal(b"x"), Err(AtRestError::NotReserved));
    r.reserve().unwrap();
    r.reserve().unwrap();
    assert_eq!(r.seals(), 2);
    r.seal(b"x").unwrap();
    r.seal(b"x").unwrap();
    assert_eq!(r.seal(b"x"), Err(AtRestError::NotReserved));
    // A keyring read back holds no reservation, only the count.
    let mut back = KeyRing::decode(&r.encode()).unwrap();
    assert_eq!(back.seals(), 2);
    assert_eq!(back.seal(b"x"), Err(AtRestError::NotReserved));
}

#[test]
fn many_seals_never_repeat_a_nonce() {
    let mut r = ring();
    let mut nonces = HashSet::new();
    for _ in 0..10_000 {
        let file = sealed(&mut r, b"same plaintext");
        let nonce = file[HEADER_LEN..HEADER_LEN + NONCE_LEN].to_vec();
        assert!(nonces.insert(nonce));
    }
}

#[test]
fn a_used_up_key_rotates_and_the_one_before_still_opens() {
    let mut r = ring().with_limit(2);
    let first = sealed(&mut r, b"1");
    let second = sealed(&mut r, b"2");
    assert!(r.reserve().unwrap(), "the third seal rotates");
    let third = r.seal(b"3").unwrap();
    assert_eq!(r.seals(), 1);
    assert_ne!(first[5..HEADER_LEN], third[5..HEADER_LEN]);
    for (file, text) in [(&first, b"1"), (&second, b"2"), (&third, b"3")] {
        assert_eq!(r.open(file).unwrap(), text);
    }
    // A second rotation drops the first key.
    r.reserve().unwrap();
    assert!(r.reserve().unwrap());
    assert_eq!(r.open(&first), Err(AtRestError::UnknownKey));
    assert_eq!(r.open(&third).unwrap(), b"3");
    // The limit is capped.
    assert_eq!(ring().with_limit(u64::MAX).limit, KeyRing::SEAL_LIMIT);
}

#[test]
fn the_keyring_round_trips_and_refuses_anything_else() {
    let mut r = ring().with_limit(1);
    let one = r.encode();
    assert_eq!(one.len(), KEYRING_ONE);
    assert_eq!(KeyRing::decode(&one).unwrap().encode(), one);
    let file = sealed(&mut r, b"x");
    r.reserve().unwrap();
    let two = r.encode();
    assert_eq!(two.len(), KEYRING_TWO);
    let back = KeyRing::decode(&two).unwrap();
    assert_eq!(back.encode(), two);
    assert_eq!(back.open(&file).unwrap(), b"x");
    assert!(!format!("{back:?}").contains(&format!("{:?}", &two[13..45])));

    let mut cases = vec![Vec::new(), one[..one.len() - 1].to_vec(), {
        let mut b = one.clone();
        b.push(0);
        b
    }];
    for i in [0, 4] {
        let mut b = one.clone();
        b[i] ^= 1;
        cases.push(b);
    }
    // Flag says "retired" with no retired key, and the other way round.
    let mut b = one.clone();
    b[KEYRING_ONE - 1] = 1;
    cases.push(b);
    let mut b = two.clone();
    b[KEYRING_ONE - 1] = 0;
    cases.push(b);
    let mut b = two.clone();
    b[KEYRING_ONE - 1] = 2;
    cases.push(b);
    // The retired key has the current key's ID.
    let mut b = two.clone();
    let id = b[13..29].to_vec();
    b[KEYRING_ONE..KEYRING_ONE + 16].copy_from_slice(&id);
    cases.push(b);
    for case in cases {
        assert_eq!(
            KeyRing::decode(&case).unwrap_err(),
            AtRestError::Malformed,
            "{case:?}"
        );
    }
}

#[test]
fn every_error_displays() {
    for e in [
        AtRestError::Malformed,
        AtRestError::UnknownKey,
        AtRestError::Authentication,
        AtRestError::NotReserved,
        AtRestError::Random,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

proptest! {
    #[test]
    fn opening_arbitrary_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let r = ring();
        prop_assert!(r.open(&bytes).is_err());
        let _ = KeyRing::decode(&bytes);
    }

    #[test]
    fn sealing_round_trips(plaintext in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut r = ring();
        let file = sealed(&mut r, &plaintext);
        prop_assert_eq!(r.open(&file).unwrap(), plaintext);
    }
}
