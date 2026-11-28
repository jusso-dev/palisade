//! Seeds for the `policy_at_rest_open` fuzz target (#326).

use std::path::Path;

use palisade_proto::policy_bundle::at_rest::KeyRing;

/// Writes keyrings with and without a retired key, a sealed file, and
/// damaged copies of each.
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/policy_at_rest_open" \
///     cargo test -p palisade-proto --test policy_at_rest -- --ignored write_policy_at_rest_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_at_rest_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    };
    let mut ring = KeyRing::generate().unwrap().with_limit(1);
    write("keyring-one", &ring.encode());
    ring.reserve().unwrap();
    let sealed = ring.seal(b"palisade policy envelope").unwrap();
    write("sealed", &sealed);
    write("sealed-truncated", &sealed[..sealed.len() - 1]);
    ring.reserve().unwrap();
    let two = ring.encode();
    write("keyring-two", &two);
    write("keyring-truncated", &two[..two.len() - 1]);
}

#[test]
fn a_keyring_round_trips_through_the_public_api() {
    let mut ring = KeyRing::generate().unwrap();
    ring.reserve().unwrap();
    let sealed = ring.seal(b"x").unwrap();
    let back = KeyRing::decode(&ring.encode()).unwrap();
    assert_eq!(back.open(&sealed).unwrap(), b"x");
}
