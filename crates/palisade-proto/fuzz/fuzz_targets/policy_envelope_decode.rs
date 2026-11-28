//! Fuzzes the signed policy bundle envelope (#325): the strict envelope
//! decoder, the agent's verification, and rebuilding a bundle from a delta
//! envelope. The input is an envelope, which an agent receives from the
//! network or reads from its cache. No input may panic. Every input that
//! decodes must re-encode to exactly the same bytes. The trust set lists
//! the two known-answer keys, whose private halves are not available here,
//! so a signature may only ever verify over the known-answer bundle itself.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use palisade_policy::bundle::{AgentVersion, BundleLimits};
use palisade_proto::events::Timestamp;
use palisade_proto::pki::{
    KeyPurpose, KeyStatus, PublicKey, SignatureAlgorithm, SkewTolerance, TrustSet, TrustedKey,
    Validity,
};
use palisade_proto::policy_bundle::EffectiveMode;
use palisade_proto::policy_bundle::envelope::{Agent, Envelope, rebuild, verify};

/// The known-answer bundle and its keys (`tests/fixtures/policy_envelope`).
const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/policy_envelope/minimal.cbor");
const ED25519_SPKI: &str =
    "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const P384_SPKI: &str = "3076301006072a8648ce3d020106052b8104002203620004886a9b772c4ecd25a43bbbe6a7a679eda87fa29788ef1bd0ca4d8a5b05cf6e3fe55c41f142f6b9aacef80bdc218774de0895b9dafc5b4b3b6bda0e690caa7c05c2767316f724dd1ad2686126ef13e5fe3082bc10bfe60bb7512a582ee74788e4";

/// 2026-11-24T00:00:00Z.
const NOW: i64 = 1_795_478_400_000_000;
const DAY: i64 = 86_400 * 1_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn trust() -> &'static TrustSet {
    static TRUST: OnceLock<TrustSet> = OnceLock::new();
    TRUST.get_or_init(|| {
        let ts = |m| Timestamp::from_unix_micros(m).unwrap();
        let p384 = SignatureAlgorithm::EcdsaP384Sha384;
        let ed = SignatureAlgorithm::Ed25519;
        let validity = Validity::new(ts(NOW - 180 * DAY), ts(NOW + 180 * DAY)).unwrap();
        let key = |spki: &str, purpose, alg| {
            let public = PublicKey::from_spki_der(&hex(spki)).unwrap();
            TrustedKey::new(public, purpose, alg, KeyStatus::Active, validity).unwrap()
        };
        let mut set = TrustSet::new(1, ts(NOW), &[p384, ed]).unwrap();
        // Any P-384 key serves as the trust key; it signs nothing here.
        set.add_trust_key(key(P384_SPKI, KeyPurpose::TrustSet, p384))
            .unwrap();
        set.add_policy_key(key(ED25519_SPKI, KeyPurpose::PolicySigning, ed))
            .unwrap();
        set
    })
}

fuzz_target!(|data: &[u8]| {
    let limits = BundleLimits::DEFAULT;
    if let Ok(env) = Envelope::decode(data, &limits) {
        assert_eq!(env.encode(), data);
    }
    let agent = Agent {
        version: AgentVersion::new(1, 0, 0),
        limits,
        skew: SkewTolerance::DEFAULT,
        mode: EffectiveMode::ENFORCE,
    };
    let now = Timestamp::from_unix_micros(NOW).unwrap();
    let check = |bytes: &[u8]| {
        let v = verify(bytes, trust(), &agent, now);
        if v.signer().is_some() {
            let env = Envelope::decode(bytes, &limits).unwrap();
            assert_eq!(env.payload(), BUNDLE, "a signature verified over other bytes");
        }
        let _ = v.into_bundle();
    };
    check(data);
    if let Ok(rebuilt) = rebuild(data, BUNDLE, &limits) {
        check(&rebuilt.encode());
    }
});
