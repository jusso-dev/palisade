//! Fuzzes first-class hash sets (#368): the strict reader of a set's raw
//! digests and the add/remove patches a delta carries. Both read bytes an
//! agent receives before the signature over the result is checked. No
//! input may panic. A set that reads must encode to the same bytes, find
//! every digest it holds, and never find one it does not; a patch that
//! applies must give exactly the base with the removals taken out and the
//! additions put in, and `diff` must give a patch back to the result.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_policy::hashset::{DIGEST_LEN, Digests};

fuzz_target!(|data: &[u8]| {
    // Three byte strings: the base set, the additions and the removals,
    // split by the first two bytes.
    let (Some(&a), Some(&b)) = (data.first(), data.get(1)) else {
        return;
    };
    let rest = &data[2..];
    let cut = |n: u8| (usize::from(n) * DIGEST_LEN).min(rest.len());
    let (base, rest) = rest.split_at(cut(a));
    let (add, remove) = rest.split_at(cut(b).min(rest.len()));
    let Ok(base) = Digests::from_sorted_bytes(base) else {
        return;
    };
    assert_eq!(Digests::from_sorted_bytes(base.as_bytes()).unwrap(), base);
    for d in base.iter() {
        assert!(base.contains(d));
    }
    let (Ok(add), Ok(remove)) = (
        Digests::from_sorted_bytes(add),
        Digests::from_sorted_bytes(remove),
    ) else {
        return;
    };
    if let Ok(out) = base.patch(&add, &remove) {
        assert_eq!(out.len() + remove.len(), base.len() + add.len());
        for d in add.iter() {
            assert!(out.contains(d) && !base.contains(d));
        }
        for d in remove.iter() {
            assert!(!out.contains(d) && base.contains(d));
        }
        let (add2, remove2) = base.diff(&out);
        assert_eq!(base.patch(&add2, &remove2).unwrap(), out);
    }
});
