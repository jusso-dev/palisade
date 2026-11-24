//! Seed inputs for the `trust_set_decode` fuzz target
//! (`fuzz/fuzz_targets/trust_set_decode.rs`).

#![allow(clippy::unwrap_used)]

use std::path::Path;

use palisade_proto::events::{Sha256Hex, Timestamp};
use palisade_proto::pki::{
    KeyPurpose, KeyStatus, Kid, SignatureAlgorithm, SignedTrustSet, Signer, SoftwareSigner,
    TrustSet, TrustedKey, UpdateRootPointer, Validity,
};

const DAY: i64 = 86_400 * 1_000_000;

/// 2026-11-24T00:00:00Z.
fn now() -> Timestamp {
    Timestamp::from_unix_micros(1_795_478_400_000_000).unwrap()
}

fn listed(signer: &SoftwareSigner, kid: Kid, alg: SignatureAlgorithm) -> TrustedKey {
    let micros = now().unix_micros();
    let validity = Validity::new(
        Timestamp::from_unix_micros(micros - 180 * DAY).unwrap(),
        Timestamp::from_unix_micros(micros + 180 * DAY).unwrap(),
    )
    .unwrap();
    TrustedKey::new(
        signer.public_key(&kid).unwrap(),
        signer.purpose(&kid).unwrap(),
        alg,
        KeyStatus::Active,
        validity,
    )
    .unwrap()
}

/// Writes seed inputs for the `trust_set_decode` fuzz target into the
/// directory in `PALISADE_FUZZ_SEED_DIR`: a minimal and a full trust-set
/// payload, each also as a signed envelope, and a few malformed variants
/// (empty, truncated, a trailing byte, an unknown format version).
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/trust_set_decode" \
///     cargo test -p palisade-proto --test trust_set -- --ignored write_trust_set_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_trust_set_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    };

    let p384 = SignatureAlgorithm::EcdsaP384Sha384;
    let ed25519 = SignatureAlgorithm::Ed25519;
    let mut signer = SoftwareSigner::new();
    let root = signer.generate(KeyPurpose::RootCa, p384).unwrap();
    let trust = signer.generate(KeyPurpose::TrustSet, p384).unwrap();
    let policy = signer.generate(KeyPurpose::PolicySigning, p384).unwrap();
    let unlock = signer.generate(KeyPurpose::UnlockToken, ed25519).unwrap();

    // One algorithm, one trust key, nothing else.
    let mut minimal = TrustSet::new(1, now(), &[p384]).unwrap();
    minimal.add_trust_key(listed(&signer, root, p384)).unwrap();

    // Every list in use, and the update-root pointer.
    let mut full = TrustSet::new(42, now(), &[p384, ed25519]).unwrap();
    full.add_trust_key(listed(&signer, root, p384)).unwrap();
    full.add_trust_key(listed(&signer, trust, p384)).unwrap();
    full.add_server_pin(Sha256Hex::from_bytes([7; 32])).unwrap();
    full.add_server_pin(Sha256Hex::from_bytes([9; 32])).unwrap();
    full.add_policy_key(listed(&signer, policy, p384)).unwrap();
    full.add_unlock_key(listed(&signer, unlock, ed25519))
        .unwrap();
    full.set_update_root(UpdateRootPointer {
        version: 9,
        sha256: Sha256Hex::from_bytes([3; 32]),
    });

    for (name, set, kids) in [
        ("minimal", &minimal, &[root][..]),
        ("full", &full, &[root, trust][..]),
    ] {
        let payload = set.encode().unwrap();
        assert_eq!(
            TrustSet::decode(&payload).unwrap().encode().unwrap(),
            payload
        );
        let envelope = SignedTrustSet::sign(set, &signer, kids).unwrap().encode();
        assert_eq!(
            SignedTrustSet::decode(&envelope).unwrap().encode(),
            envelope
        );
        write(&format!("{name}-payload"), &payload);
        write(&format!("{name}-envelope"), &envelope);

        let truncated = &envelope[..envelope.len() - 1];
        assert!(SignedTrustSet::decode(truncated).is_err());
        write(&format!("{name}-envelope-truncated"), truncated);

        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(TrustSet::decode(&trailing).is_err());
        write(&format!("{name}-payload-trailing"), &trailing);

        let mut version = envelope.clone();
        version[0] = 2;
        assert!(SignedTrustSet::decode(&version).is_err());
        write(&format!("{name}-envelope-version-2"), &version);
    }
    write("empty", b"");
}
