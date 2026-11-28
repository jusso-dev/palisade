use proptest::prelude::*;

use super::*;

fn d(n: u8) -> Digest {
    [n; DIGEST_LEN]
}

fn set(ns: &[u8]) -> Digests {
    Digests::from_digests(ns.iter().map(|n| d(*n)))
}

#[test]
fn digests_are_sorted_and_unique() {
    let s = set(&[3, 1, 2, 1]);
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
    assert_eq!(
        s.iter().collect::<Vec<_>>(),
        vec![&d(1)[..], &d(2)[..], &d(3)[..]]
    );
    assert!(s.contains(&d(2)));
    assert!(!s.contains(&d(4)));
    assert!(!s.contains(&d(0)));
    assert!(!s.contains(&[1u8; 31]), "a digest of another length");
    assert!(Digests::default().is_empty());
    assert!(!Digests::default().contains(&d(0)));
    assert_eq!(format!("{s:?}"), "Digests(3 entries)");
}

#[test]
fn the_reader_is_strict() {
    let s = set(&[1, 2]);
    assert_eq!(Digests::from_sorted_bytes(s.as_bytes()).unwrap(), s);
    assert_eq!(Digests::from_sorted_bytes(&[]).unwrap(), Digests::default());
    assert_eq!(
        Digests::from_sorted_bytes(&[0; 33]),
        Err(DigestsError::Length(33))
    );
    let mut swapped = d(2).to_vec();
    swapped.extend_from_slice(&d(1));
    assert_eq!(
        Digests::from_sorted_bytes(&swapped),
        Err(DigestsError::NotAscending(1))
    );
    let mut repeated = d(1).to_vec();
    repeated.extend_from_slice(&d(1));
    assert_eq!(
        Digests::from_sorted_bytes(&repeated),
        Err(DigestsError::NotAscending(1))
    );
}

#[test]
fn hex_is_read_in_any_spelling() {
    let lower = "ab".repeat(32);
    let s = Digests::from_hex([format!("0X{}", lower.to_uppercase())]).unwrap();
    assert_eq!(s.contains_hex(&lower), Some(true));
    assert_eq!(s.contains_hex(&lower.to_uppercase()), Some(true));
    assert_eq!(s.contains_hex(&"cd".repeat(32)), Some(false));
    // A fact must be bare hex of the right length.
    assert_eq!(s.contains_hex("ab"), None);
    assert_eq!(s.contains_hex(&"zz".repeat(32)), None);
    assert_eq!(Digests::from_hex(["ab"]), Err(DigestsError::NotHex));
}

#[test]
fn patches_are_strict() {
    let base = set(&[1, 3, 5]);
    assert_eq!(
        base.patch(&set(&[2, 6]), &set(&[3])).unwrap(),
        set(&[1, 2, 5, 6])
    );
    assert_eq!(
        base.patch(&set(&[0]), &set(&[])).unwrap(),
        set(&[0, 1, 3, 5])
    );
    assert_eq!(
        base.patch(&set(&[]), &set(&[1, 3, 5])).unwrap(),
        Digests::default()
    );
    assert_eq!(
        base.patch(&set(&[3]), &set(&[])),
        Err(DigestsError::AddPresent)
    );
    assert_eq!(
        base.patch(&set(&[]), &set(&[2])),
        Err(DigestsError::RemoveMissing)
    );
    assert_eq!(
        base.patch(&set(&[]), &set(&[9])),
        Err(DigestsError::RemoveMissing)
    );
    assert_eq!(
        base.patch(&set(&[]), &set(&[0])),
        Err(DigestsError::RemoveMissing)
    );
    for e in [
        DigestsError::Length(1),
        DigestsError::NotAscending(1),
        DigestsError::NotHex,
        DigestsError::RemoveMissing,
        DigestsError::AddPresent,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn only_sha256_file_hashes_take_a_set() {
    assert!(field_allowed(Field::HashSha256));
    assert!(field_allowed(Field::HashAuthenticodeSha256));
    assert!(!field_allowed(Field::HashSha1));
    assert!(!field_allowed(Field::HashSha512));
    assert!(!field_allowed(Field::SignerLeafThumbprint));
    assert!(!field_allowed(Field::PathFull));
}

proptest! {
    #[test]
    fn diff_then_patch_gives_the_new_set(
        a in proptest::collection::vec(any::<u8>(), 0..40),
        b in proptest::collection::vec(any::<u8>(), 0..40),
    ) {
        let (old, new) = (set(&a), set(&b));
        let (add, remove) = old.diff(&new);
        prop_assert_eq!(old.patch(&add, &remove).unwrap(), new.clone());
        // Each set reads back from its bytes.
        prop_assert_eq!(Digests::from_sorted_bytes(new.as_bytes()).unwrap(), new);
    }
}
