//! Seed inputs for the `policy_envelope_decode` fuzz target
//! (`fuzz/fuzz_targets/policy_envelope_decode.rs`).

#![allow(clippy::unwrap_used)]

use std::path::Path;

use palisade_policy::bundle::{BundleLimits, PolicyBundle, diff};
use palisade_proto::pki::{KeyPurpose, SignatureAlgorithm, SoftwareSigner};
use palisade_proto::policy_bundle::envelope::{Envelope, Kind};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/policy_envelope"
);
const GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../palisade-policy/tests/golden/bundles"
);

/// Writes seed inputs for the `policy_envelope_decode` fuzz target into the
/// directory in `PALISADE_FUZZ_SEED_DIR`: the known-answer envelope, a
/// bundle envelope and a delta envelope signed here, and malformed variants
/// of each (truncated, a trailing byte, another format version, another
/// kind).
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/policy_envelope_decode" \
///     cargo test -p palisade-proto --test policy_envelope -- --ignored write_policy_envelope_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_policy_envelope_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    };
    let limits = BundleLimits::DEFAULT;
    let read = |path: String| std::fs::read(path).unwrap();

    let kat = read(format!("{FIXTURES}/minimal.envelope"));
    let minimal = read(format!("{GOLDEN}/minimal.cbor"));
    let baseline = read(format!("{GOLDEN}/baseline.cbor"));

    let mut signer = SoftwareSigner::new();
    let p384 = signer
        .generate(
            KeyPurpose::PolicySigning,
            SignatureAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();
    let ed = signer
        .generate(KeyPurpose::PolicySigning, SignatureAlgorithm::Ed25519)
        .unwrap();
    let full = Envelope::sign_bundle(&baseline, &signer, &[p384, ed])
        .unwrap()
        .encode();
    let delta = diff(
        &PolicyBundle::decode(&minimal, &limits).unwrap(),
        &PolicyBundle::decode(&baseline, &limits).unwrap(),
    )
    .unwrap();
    let delta = Envelope::sign_delta(&delta, &baseline, &signer, &[p384])
        .unwrap()
        .encode();

    for (name, envelope) in [("kat", &kat), ("full", &full), ("delta", &delta)] {
        let decoded = Envelope::decode(envelope, &limits).unwrap();
        assert_eq!(&decoded.encode(), envelope);
        write(name, envelope);

        let truncated = &envelope[..envelope.len() - 1];
        assert!(Envelope::decode(truncated, &limits).is_err());
        write(&format!("{name}-truncated"), truncated);

        let mut trailing = envelope.clone();
        trailing.push(0);
        assert!(Envelope::decode(&trailing, &limits).is_err());
        write(&format!("{name}-trailing"), &trailing);

        let mut version = envelope.clone();
        version[0] = 2;
        assert!(Envelope::decode(&version, &limits).is_err());
        write(&format!("{name}-version-2"), &version);

        let mut kind = envelope.clone();
        kind[1] = match decoded.kind() {
            Kind::Bundle => Kind::Delta.code(),
            Kind::Delta => Kind::Bundle.code(),
        };
        write(&format!("{name}-other-kind"), &kind);
    }
    write("empty", b"");
}
