// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::str::FromStr;
use std::sync::OnceLock;

use palisade_core::{SchemaVersion, Uuid7};
use palisade_policy::bundle::{self, Body, SourceRevisions, TargetScope};
use palisade_policy::model::Mode;
use palisade_policy::test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash};
use proptest::prelude::*;

use super::*;
use crate::events::{EventType, Sha256Hex};
use crate::pki::crypto::{PrivateKey, Rng};
use crate::pki::{KeyPurpose, KeyStatus, KeyType, PublicKey, SoftwareSigner, Validity};
use crate::policy_bundle::record::Record;
use crate::policy_bundle::select::{self, PendingOutcome};
use crate::policy_bundle::{EffectiveMode, ModeGate, Rejection, SignatureMode};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DAY: i64 = 86_400 * 1_000_000;
const P384: SignatureAlgorithm = SignatureAlgorithm::EcdsaP384Sha384;
const ED25519: SignatureAlgorithm = SignatureAlgorithm::Ed25519;

/// 2026-11-24T00:00:00Z, the tests' "now".
fn now() -> Timestamp {
    Timestamp::from_str("2026-11-24T00:00:00.000000Z").unwrap()
}

fn at(days: i64) -> Timestamp {
    Timestamp::from_unix_micros(now().unix_micros() + days * DAY).unwrap()
}

fn year() -> Validity {
    Validity::new(at(-180), at(180)).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn id(text: &str) -> Uuid7 {
    text.parse().unwrap()
}

/// The tenant and group of the golden bundles in `palisade-policy`.
fn tenant() -> Uuid7 {
    id("01890a5d-ac96-774b-bcce-b302099a8057")
}

fn group() -> Uuid7 {
    id("01890a5d-ac96-774b-bcce-b302099a8058")
}

fn device_target() -> Target {
    target_of(bundle::Target {
        tenant: tenant(),
        scope: TargetScope::Group(group()),
    })
}

fn agent() -> Agent {
    Agent {
        version: AgentVersion::new(1, 0, 0),
        limits: BundleLimits::DEFAULT,
        skew: SkewTolerance::DEFAULT,
        mode: EffectiveMode::ENFORCE,
    }
}

/// Bundle bytes for `version`, with `edit` applied to the header.
fn bundle_with(version: u64, rules: u32, edit: impl FnOnce(&mut Header)) -> Vec<u8> {
    let mut set = RuleSetBuilder::allowlist(1);
    for n in 1..=rules {
        let digit = char::from_digit(n % 16, 16).unwrap();
        set = set.rule(RuleBuilder::allow(n, hash(digit)));
    }
    let doc = PolicyBuilder::new()
        .mode(Mode::Enforce)
        .rule_set(set)
        .build();
    let mut header = Header::new(
        bundle::Target {
            tenant: tenant(),
            scope: TargetScope::Group(group()),
        },
        version,
        1_764_201_600_000_000,
    );
    edit(&mut header);
    let body = Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap();
    PolicyBundle::new(header, body).to_bytes().unwrap()
}

fn bundle_bytes(version: u64) -> Vec<u8> {
    bundle_with(version, 2, |_| {})
}

/// A signer with two policy keys (one of each algorithm), a key the trust
/// set does not list, and a trust-set key.
struct Fixture {
    signer: SoftwareSigner,
    p384: Kid,
    ed25519: Kid,
    unlisted: Kid,
    trust_key: Kid,
}

impl Fixture {
    fn new() -> Self {
        let mut signer = SoftwareSigner::new();
        let p384 = signer.generate(KeyPurpose::PolicySigning, P384).unwrap();
        let ed25519 = signer.generate(KeyPurpose::PolicySigning, ED25519).unwrap();
        let unlisted = signer.generate(KeyPurpose::PolicySigning, P384).unwrap();
        let trust_key = signer.generate(KeyPurpose::TrustSet, P384).unwrap();
        Self {
            signer,
            p384,
            ed25519,
            unlisted,
            trust_key,
        }
    }

    fn listed(&self, kid: Kid, validity: Validity) -> TrustedKey {
        let public = self.signer.public_key(&kid).unwrap();
        let alg = match public.key_type() {
            KeyType::P384 => P384,
            KeyType::Ed25519 => ED25519,
        };
        let purpose = self.signer.purpose(&kid).unwrap();
        TrustedKey::new(public, purpose, alg, KeyStatus::Active, validity).unwrap()
    }

    /// A trust set accepting `algorithms`, listing the two policy keys.
    fn trust_with(&self, algorithms: &[SignatureAlgorithm], validity: Validity) -> TrustSet {
        let mut set = TrustSet::new(1, now(), algorithms).unwrap();
        set.add_trust_key(self.listed(self.trust_key, year()))
            .unwrap();
        for kid in [self.p384, self.ed25519] {
            let key = self.listed(kid, validity);
            if algorithms.contains(&key.algorithm()) {
                set.add_policy_key(key).unwrap();
            }
        }
        set
    }

    fn trust(&self) -> TrustSet {
        self.trust_with(&[P384, ED25519], year())
    }

    fn sign(&self, bundle: &[u8], kids: &[Kid]) -> Vec<u8> {
        Envelope::sign_bundle(bundle, &self.signer, kids)
            .unwrap()
            .encode()
    }
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(Fixture::new)
}

fn verify_now(envelope: &[u8], trust: &TrustSet) -> Verified {
    verify(envelope, trust, &agent(), now())
}

/// Runs a verified envelope through the decision layer, as the agent does
/// for a downloaded bundle with nothing active yet.
fn decide(verified: &Verified, record: Record) -> Result<PendingOutcome, Rejection> {
    select::pending(
        verified.examined(),
        device_target(),
        record,
        None,
        EffectiveMode::ENFORCE,
    )
}

fn decide_fresh(verified: &Verified) -> Result<PendingOutcome, Rejection> {
    decide(verified, Record::empty(device_target()))
}

/// A signature made outside the signer, which refuses cross-domain and
/// cross-purpose signing.
fn raw_signature(
    alg: SignatureAlgorithm,
    domain: Domain,
    payload: &[u8],
) -> (PublicKey, Signature) {
    let rng = Rng::new();
    let key = PrivateKey::generate(alg, &rng).unwrap();
    let key_type = match alg {
        SignatureAlgorithm::EcdsaP384Sha384 => KeyType::P384,
        SignatureAlgorithm::Ed25519 => KeyType::Ed25519,
    };
    let public = PublicKey::from_raw(key_type, key.raw_public_key()).unwrap();
    let bytes = key.sign(&rng, &domain.message(payload)).unwrap();
    let sig = Signature::new(public.kid(), alg, bytes).unwrap();
    (public, sig)
}

// ---------------------------------------------------------------------------
// Known-answer vectors from an independent implementation
// ---------------------------------------------------------------------------

const KAT_BUNDLE: &[u8] = include_bytes!("../../../tests/fixtures/policy_envelope/minimal.cbor");
const KAT_ENVELOPE: &[u8] =
    include_bytes!("../../../tests/fixtures/policy_envelope/minimal.envelope");
const KAT_BUNDLE_HASH: &str = "a624aa7585a0d12980d89669d8cec784402631420c145f939d6979f7c591d958";

/// RFC 8032 section 7.1, test 1: the secret key, as unencrypted PKCS#8 v1.
const RFC8032_PKCS8: &str = "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// Its public key as a `SubjectPublicKeyInfo` (`openssl pkey -pubout`).
const KAT_ED25519_SPKI: &str =
    "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const KAT_ED25519_KID: &str = "06e3fd8fda29bb60ab59557de61edb0a";
/// A P-384 key generated with OpenSSL for the vector; its private key was
/// not kept.
const KAT_P384_SPKI: &str = "3076301006072a8648ce3d020106052b81040022036200045bf848ff22bf5364e1b1722790be027f193ac7b4affc23aa745576d2b6d40c8856ffda589989765b60f517f55884224471f6babb6400010b909ca7e898c6fc414abdbae1515d7a747ee2bf2aa0bd6a3fde1fb01c7064bc2b60f3c99a54758c85";
const KAT_P384_KID: &str = "d98c2236b95d8d85eda888ffd0c7acea";

/// A trust set accepting both algorithms that lists the known-answer
/// keys of `listed` only.
fn kat_trust(listed: &[SignatureAlgorithm]) -> TrustSet {
    let f = fixture();
    let mut set = TrustSet::new(1, now(), &[P384, ED25519]).unwrap();
    set.add_trust_key(f.listed(f.trust_key, year())).unwrap();
    for (spki, alg) in [(KAT_P384_SPKI, P384), (KAT_ED25519_SPKI, ED25519)] {
        if listed.contains(&alg) {
            let key = PublicKey::from_spki_der(&hex(spki)).unwrap();
            set.add_policy_key(
                TrustedKey::new(
                    key,
                    KeyPurpose::PolicySigning,
                    alg,
                    KeyStatus::Active,
                    year(),
                )
                .unwrap(),
            )
            .unwrap();
        }
    }
    set
}

#[test]
fn known_answer_envelope_decodes_to_its_parts() {
    assert_eq!(
        bundle::format::hex(&bundle_hash(KAT_BUNDLE)),
        KAT_BUNDLE_HASH
    );
    let env = Envelope::decode(KAT_ENVELOPE, &BundleLimits::DEFAULT).unwrap();
    assert_eq!(env.kind(), Kind::Bundle);
    assert_eq!(env.payload(), KAT_BUNDLE);
    let kids: Vec<String> = env
        .signatures()
        .iter()
        .map(|s| s.kid().to_string())
        .collect();
    assert_eq!(kids, [KAT_ED25519_KID, KAT_P384_KID]);
    assert_eq!(env.signatures()[0].algorithm(), ED25519);
    assert_eq!(env.signatures()[1].algorithm(), P384);
    assert_eq!(env.encode(), KAT_ENVELOPE);
    for (spki, kid) in [
        (KAT_ED25519_SPKI, KAT_ED25519_KID),
        (KAT_P384_SPKI, KAT_P384_KID),
    ] {
        assert_eq!(Kid::of_spki(&hex(spki)).to_string(), kid);
    }
}

#[test]
fn known_answer_envelope_verifies_under_each_algorithm() {
    // Each algorithm on its own: the trust set lists one key, and the other
    // signature is from a key it does not know, which is ignored.
    for (alg, kid) in [(P384, KAT_P384_KID), (ED25519, KAT_ED25519_KID)] {
        let v = verify_now(KAT_ENVELOPE, &kat_trust(&[alg]));
        assert_eq!(v.signer().unwrap().to_string(), kid, "{alg}");
        let Examined::Parsed {
            meta,
            signature_valid,
            agent_supported,
            schema_supported,
        } = v.examined()
        else {
            panic!("unreadable under {alg}");
        };
        assert!(signature_valid && agent_supported && schema_supported);
        assert_eq!(meta.version, 1);
        assert_eq!(meta.target, device_target());
        assert_eq!(meta.sha256.to_string(), KAT_BUNDLE_HASH);
        assert_eq!(v.into_bundle().unwrap().to_bytes().unwrap(), KAT_BUNDLE);
    }
    // Both: the lowest key ID is reported.
    let v = verify_now(KAT_ENVELOPE, &kat_trust(&[P384, ED25519]));
    assert_eq!(v.signer().unwrap().to_string(), KAT_ED25519_KID);
}

#[test]
fn known_answer_signing_is_reproducible() {
    // Ed25519 is deterministic, so signing the golden bundle with the
    // RFC 8032 key gives exactly the committed signature. (ECDSA nonces are
    // random, so the P-384 half is checked by verification above.)
    let mut signer = SoftwareSigner::new();
    let kid = signer
        .import_pkcs8(KeyPurpose::PolicySigning, ED25519, &hex(RFC8032_PKCS8))
        .unwrap();
    assert_eq!(kid.to_string(), KAT_ED25519_KID);
    let env = Envelope::sign_bundle(KAT_BUNDLE, &signer, &[kid]).unwrap();
    let committed = Envelope::decode(KAT_ENVELOPE, &BundleLimits::DEFAULT).unwrap();
    assert_eq!(env.signatures()[0], committed.signatures()[0]);
    let joined = Envelope::from_parts(
        Kind::Bundle,
        KAT_BUNDLE.to_vec(),
        committed.signatures().iter().rev().cloned().collect(),
        &BundleLimits::DEFAULT,
    )
    .unwrap();
    assert_eq!(joined.encode(), KAT_ENVELOPE);
}

#[test]
fn known_answer_envelope_fails_once_changed() {
    let trust = kat_trust(&[P384, ED25519]);
    // The last byte of the bundle, the last byte of a signature.
    for at in [6 + KAT_BUNDLE.len() - 1, KAT_ENVELOPE.len() - 1] {
        let mut bytes = KAT_ENVELOPE.to_vec();
        bytes[at] ^= 1;
        assert!(verify_now(&bytes, &trust).signer().is_none(), "byte {at}");
    }
}

// ---------------------------------------------------------------------------
// Signing and the accepted path
// ---------------------------------------------------------------------------

#[test]
fn a_signed_bundle_verifies_and_is_activated() {
    let f = fixture();
    for kid in [f.p384, f.ed25519] {
        let bytes = bundle_bytes(3);
        let v = verify_now(&f.sign(&bytes, &[kid]), &f.trust());
        assert_eq!(v.signer(), Some(kid));
        assert_eq!(v.signature_error(), None);
        assert_eq!(v.unreadable(), None);
        assert_eq!(v.body_error(), None);
        assert_eq!(v.header().unwrap().policy_version, 3);
        let Ok(PendingOutcome::Activate(plan)) = decide_fresh(&v) else {
            panic!("not activated");
        };
        assert!(plan.signed);
        assert_eq!(plan.bundle.sha256, content_hash(&bytes));
        assert_eq!(v.into_bundle().unwrap().to_bytes().unwrap(), bytes);
    }
}

#[test]
fn dual_signed_bundles_verify_for_agents_on_either_key() {
    // #224 rotation: a bundle signed by the old and the new key verifies for
    // an agent that trusts only one of them.
    let f = fixture();
    let env = f.sign(&bundle_bytes(1), &[f.unlisted, f.p384]);
    let decoded = Envelope::decode(&env, &BundleLimits::DEFAULT).unwrap();
    assert_eq!(decoded.signatures().len(), 2);
    assert!(decoded.signatures()[0].kid() < decoded.signatures()[1].kid());
    assert_eq!(verify_now(&env, &f.trust()).signer(), Some(f.p384));
}

#[test]
fn signing_refuses_bad_requests() {
    let f = fixture();
    let bytes = bundle_bytes(1);
    let sign = |kids: &[Kid]| Envelope::sign_bundle(&bytes, &f.signer, kids);
    assert_eq!(sign(&[]), Err(SignError::SignatureCount));
    assert_eq!(sign(&[f.p384; 9]), Err(SignError::SignatureCount));
    assert_eq!(
        sign(&[f.p384, f.p384]),
        Err(SignError::DuplicateKey(f.p384))
    );
    // threat: T-signer-06. A trust-set key may not sign policy.
    assert!(matches!(
        sign(&[f.trust_key]),
        Err(SignError::Signer(SignerError::WrongPurpose { .. }))
    ));
    let unknown = Kid::from_bytes([0xee; 16]);
    assert_eq!(
        sign(&[unknown]),
        Err(SignError::Signer(SignerError::UnknownKey(unknown)))
    );
    assert!(matches!(
        Envelope::sign_bundle(b"not a bundle", &f.signer, &[f.p384]),
        Err(SignError::NotABundle(_))
    ));
}

// ---------------------------------------------------------------------------
// One test per rejection, each mapped to its event type
// ---------------------------------------------------------------------------

/// Asserts `verified` is refused for `reason`, which raises `event`.
fn refused(verified: &Verified, reason: Rejection, event: EventType) {
    assert_eq!(decide_fresh(verified), Err(reason));
    assert_eq!(reason.event_type(), event);
}

#[test]
fn rejects_an_unknown_kid() {
    let f = fixture();
    let v = verify_now(&f.sign(&bundle_bytes(1), &[f.unlisted]), &f.trust());
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::NoTrustedSignature)
    );
    assert!(v.into_bundle().is_none(), "the body was decoded unsigned");
    let v = verify_now(&f.sign(&bundle_bytes(1), &[f.unlisted]), &f.trust());
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );
}

#[test]
fn rejects_an_algorithm_the_trust_set_does_not_accept() {
    // The trust set lists the Ed25519 key but accepts only ECDSA P-384, as
    // a tenant that turned Ed25519 off would have. `TrustSet` refuses to
    // list such a key, so the set is built for both and the signature
    // claims the other algorithm.
    let f = fixture();
    let bytes = bundle_bytes(1);
    let only_p384 = f.trust_with(&[P384], year());
    let v = verify_now(&f.sign(&bytes, &[f.ed25519]), &only_p384);
    // Not listed under a P-384-only set: an unknown key.
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::NoTrustedSignature)
    );
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );

    // A listed key whose signature names an algorithm the set does not
    // accept: the P-384 key's entry relabelled as Ed25519, with 64 bytes.
    let (_, ed_sig) = raw_signature(ED25519, Domain::Policy, &bytes);
    let relabelled = Signature::new(f.p384, ED25519, ed_sig.bytes().to_vec()).unwrap();
    let env = Envelope::from_parts(
        Kind::Bundle,
        bytes.clone(),
        vec![relabelled],
        &BundleLimits::DEFAULT,
    )
    .unwrap()
    .encode();
    let v = verify_now(&env, &only_p384);
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::AlgorithmNotAccepted(f.p384, ED25519))
    );
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );
    // Accepted by the set, but not the key's algorithm.
    let v = verify_now(&env, &f.trust());
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::AlgorithmMismatch(f.p384))
    );
}

#[test]
fn rejects_a_signature_from_another_domain() {
    // threat: T-signer-02. A policy key's signature over the same bytes in
    // the trust-set or unlock domain does not verify as a policy signature.
    let f = fixture();
    let bytes = bundle_bytes(1);
    for domain in [Domain::TrustSet, Domain::Unlock] {
        let (public, sig) = raw_signature(P384, domain, &bytes);
        let mut trust = f.trust();
        trust
            .add_policy_key(
                TrustedKey::new(
                    public,
                    KeyPurpose::PolicySigning,
                    P384,
                    KeyStatus::Active,
                    year(),
                )
                .unwrap(),
            )
            .unwrap();
        let env = Envelope::from_parts(
            Kind::Bundle,
            bytes.clone(),
            vec![sig.clone()],
            &BundleLimits::DEFAULT,
        )
        .unwrap()
        .encode();
        let v = verify_now(&env, &trust);
        assert_eq!(
            v.signature_error(),
            Some(SignatureError::BadSignature(sig.kid()))
        );
        refused(
            &v,
            Rejection::SignatureInvalid,
            EventType::PolicySignatureInvalid,
        );
    }
}

#[test]
fn rejects_a_tampered_bundle() {
    // threat: T-cache-01. A bundle changed after signing (here: a higher
    // version written over the signed one) fails, and a bad signature from a
    // known key fails the bundle even next to a good one.
    let f = fixture();
    let signed = Envelope::sign_bundle(&bundle_bytes(1), &f.signer, &[f.p384, f.ed25519]).unwrap();
    let forged = Envelope::from_parts(
        Kind::Bundle,
        bundle_bytes(2),
        signed.signatures().to_vec(),
        &BundleLimits::DEFAULT,
    )
    .unwrap()
    .encode();
    let v = verify_now(&forged, &f.trust());
    assert!(matches!(
        v.signature_error(),
        Some(SignatureError::BadSignature(_))
    ));
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );

    let good = Envelope::sign_bundle(&bundle_bytes(1), &f.signer, &[f.p384]).unwrap();
    let ed = signed
        .signatures()
        .iter()
        .find(|s| s.kid() == f.ed25519)
        .unwrap();
    let mut bad = ed.bytes().to_vec();
    bad[0] ^= 1;
    let mixed = Envelope::from_parts(
        Kind::Bundle,
        bundle_bytes(1),
        vec![
            good.signatures()[0].clone(),
            Signature::new(f.ed25519, ED25519, bad).unwrap(),
        ],
        &BundleLimits::DEFAULT,
    )
    .unwrap()
    .encode();
    let v = verify_now(&mixed, &f.trust());
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::BadSignature(f.ed25519))
    );
}

#[test]
fn rejects_another_tenant_or_target() {
    // threat: T-cache-01 (AT-06.3). A validly signed bundle for another
    // device or tenant.
    let f = fixture();
    let other = id("01890a5d-ac96-774b-bcce-b302099a8099");
    for edit in [
        Box::new(|h: &mut Header| h.target.tenant = other) as Box<dyn Fn(&mut Header)>,
        Box::new(|h: &mut Header| h.target.scope = TargetScope::Device(other)),
        Box::new(|h: &mut Header| h.target.scope = TargetScope::Group(other)),
    ] {
        let env = f.sign(&bundle_with(1, 1, edit), &[f.p384]);
        let v = verify_now(&env, &f.trust());
        assert!(v.signer().is_some());
        refused(
            &v,
            Rejection::TargetMismatch,
            EventType::PolicyTargetMismatch,
        );
    }
}

#[test]
fn rejects_an_older_version() {
    // threat: T-cache-03. A validly signed but older bundle is refused
    // against the anti-rollback floor.
    let f = fixture();
    let v = verify_now(&f.sign(&bundle_bytes(4), &[f.p384]), &f.trust());
    let record = Record::new(device_target(), 5, None).unwrap();
    assert_eq!(decide(&v, record), Err(Rejection::Rollback));
    assert_eq!(
        Rejection::Rollback.event_type(),
        EventType::PolicyRollbackRejected
    );
    // Version 0 is never valid.
    let v = verify_now(&f.sign(&bundle_bytes(0), &[f.p384]), &f.trust());
    refused(&v, Rejection::Rollback, EventType::PolicyRollbackRejected);
}

#[test]
fn rejects_an_oversized_envelope() {
    // The limit is checked before anything is read.
    let f = fixture();
    let bytes = bundle_bytes(1);
    let env = f.sign(&bytes, &[f.p384]);
    let small = Agent {
        limits: BundleLimits {
            max_bytes: bytes.len() - 1,
            ..BundleLimits::DEFAULT
        },
        ..agent()
    };
    let v = verify(&env, &f.trust(), &small, now());
    assert!(matches!(
        v.unreadable(),
        Some(EnvelopeError::TooLarge { .. })
    ));
    assert_eq!(v.header(), None);
    refused(&v, Rejection::Unreadable, EventType::PolicySignatureInvalid);
    // At the limit, it verifies.
    let exact = Agent {
        limits: BundleLimits {
            max_bytes: bytes.len(),
            ..BundleLimits::DEFAULT
        },
        ..agent()
    };
    assert!(verify(&env, &f.trust(), &exact, now()).signer().is_some());
    // Over the envelope limit, whatever the declared length.
    let mut huge = env.clone();
    huge.resize(max_envelope_len(bytes.len() - 1) + 1, 0);
    assert!(matches!(
        Envelope::decode(&huge, &small.limits),
        Err(EnvelopeError::TooLarge { .. })
    ));
}

#[test]
fn rejects_an_unsupported_schema() {
    let f = fixture();
    let newer = bundle_with(1, 1, |h| {
        h.schema_version = SchemaVersion::new(h.schema_version.major + 1, 0, 0);
    });
    let v = verify_now(&f.sign(&newer, &[f.p384]), &f.trust());
    assert!(v.signer().is_some());
    assert!(matches!(
        v.body_error(),
        Some(BundleError::UnsupportedSchema(_))
    ));
    refused(
        &v,
        Rejection::SchemaUnsupported,
        EventType::PolicySchemaUnsupported,
    );
}

#[test]
fn rejects_a_bundle_for_a_newer_agent() {
    let f = fixture();
    let newer = bundle_with(1, 1, |h| h.min_agent_version = AgentVersion::new(1, 0, 1));
    let v = verify_now(&f.sign(&newer, &[f.p384]), &f.trust());
    refused(
        &v,
        Rejection::AgentTooOld,
        EventType::PolicySchemaUnsupported,
    );
    // At exactly the agent's version it is supported.
    let same = bundle_with(1, 1, |h| h.min_agent_version = AgentVersion::new(1, 0, 0));
    let v = verify_now(&f.sign(&same, &[f.p384]), &f.trust());
    assert!(decide_fresh(&v).is_ok());
}

#[test]
fn rejects_a_signing_key_outside_its_window() {
    let f = fixture();
    let expired = Validity::new(at(-30), at(-10)).unwrap();
    let v = verify_now(
        &f.sign(&bundle_bytes(1), &[f.p384]),
        &f.trust_with(&[P384, ED25519], expired),
    );
    assert!(matches!(
        v.signature_error(),
        Some(SignatureError::KeyNotValid(kid, TimeError::Expired { .. })) if kid == f.p384
    ));
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );
}

// ---------------------------------------------------------------------------
// Fail closed: order and decoding
// ---------------------------------------------------------------------------

#[test]
fn the_signature_is_checked_before_the_target() {
    // A forged bundle for another target is reported as a bad signature,
    // not as a target mismatch: nothing in it is believed.
    let f = fixture();
    let other = bundle_with(1, 1, |h| {
        h.target.tenant = id("01890a5d-ac96-774b-bcce-b302099a8099");
    });
    let env = f.sign(&other, &[f.unlisted]);
    refused(
        &verify_now(&env, &f.trust()),
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );
}

#[test]
fn an_unsigned_body_is_not_decoded_in_enforce_mode() {
    // The body is broken past the header; the signature is from an unknown
    // key. In enforce mode the body is never decoded, so its schema is not
    // reported as supported.
    let f = fixture();
    let mut bytes = bundle_bytes(1);
    bytes.pop();
    let env = Envelope::from_parts(
        Kind::Bundle,
        bytes.clone(),
        Envelope::decode(
            &f.sign(&bundle_bytes(1), &[f.unlisted]),
            &BundleLimits::DEFAULT,
        )
        .unwrap()
        .signatures()
        .to_vec(),
        &BundleLimits::DEFAULT,
    )
    .unwrap()
    .encode();
    let v = verify_now(&env, &f.trust());
    assert_eq!(v.body_error(), None);
    assert!(matches!(
        v.examined(),
        Examined::Parsed {
            signature_valid: false,
            schema_supported: false,
            ..
        }
    ));
    // A relaxed mode decodes it, and the broken body is unsupported.
    let audit = Agent {
        mode: EffectiveMode::resolve(
            SignatureMode::Audit,
            ModeGate {
                dev_build: true,
                group_opt_in: false,
            },
        ),
        ..agent()
    };
    let v = verify(&env, &f.trust(), &audit, now());
    assert!(v.body_error().is_some());
    // And an intact unsigned bundle is loadable only as unsigned.
    let env = f.sign(&bundle_bytes(1), &[f.unlisted]);
    let v = verify(&env, &f.trust(), &audit, now());
    assert!(v.signer().is_none());
    let outcome = select::pending(
        v.examined(),
        device_target(),
        Record::empty(device_target()),
        None,
        audit.mode,
    );
    let Ok(PendingOutcome::Activate(plan)) = outcome else {
        panic!("not activated in audit mode");
    };
    assert!(!plan.signed);
    assert!(v.into_bundle().is_some());
}

#[test]
fn a_bad_header_is_unreadable() {
    let f = fixture();
    let (_, sig) = raw_signature(P384, Domain::Policy, b"\x82not a bundle");
    let env = Envelope::from_parts(
        Kind::Bundle,
        b"\x82not a bundle".to_vec(),
        vec![sig],
        &BundleLimits::DEFAULT,
    )
    .unwrap()
    .encode();
    let v = verify_now(&env, &f.trust());
    assert!(matches!(v.unreadable(), Some(EnvelopeError::Header(_))));
    assert_eq!(v.examined(), Examined::Unreadable);
    assert_eq!(v.signer(), None);
    assert_eq!(v.signature_error(), None);
    assert_eq!(v.body_error(), None);
    assert!(v.into_bundle().is_none());
}

#[test]
fn the_envelope_encoding_is_strict() {
    let f = fixture();
    let limits = BundleLimits::DEFAULT;
    let env = f.sign(&bundle_bytes(1), &[f.p384, f.ed25519]);
    let decoded = Envelope::decode(&env, &limits).unwrap();
    assert_eq!(decoded.encode(), env);

    // Every truncation fails.
    for len in 0..env.len() {
        assert!(Envelope::decode(&env[..len], &limits).is_err(), "{len}");
    }
    let edit = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = env.clone();
        f(&mut b);
        Envelope::decode(&b, &limits)
    };
    let payload_len = decoded.payload().len();
    let count_at = 6 + payload_len;
    assert_eq!(edit(&|b| b.push(0)), Err(EnvelopeError::TrailingBytes));
    assert_eq!(
        edit(&|b| b[0] = 2),
        Err(EnvelopeError::UnsupportedVersion(2))
    );
    assert_eq!(edit(&|b| b[1] = 0), Err(EnvelopeError::UnknownKind(0)));
    assert_eq!(edit(&|b| b[1] = 3), Err(EnvelopeError::UnknownKind(3)));
    assert_eq!(
        edit(&|b| b[count_at] = 0),
        Err(EnvelopeError::SignatureCount(0))
    );
    assert_eq!(
        edit(&|b| b[count_at] = 9),
        Err(EnvelopeError::SignatureCount(9))
    );
    assert_eq!(
        edit(&|b| b[count_at + 17] = 9),
        Err(EnvelopeError::UnknownAlgorithm(9))
    );
    // An empty payload.
    let mut empty = vec![1, 1, 0, 0, 0, 0];
    empty.extend_from_slice(&env[count_at..]);
    assert_eq!(
        Envelope::decode(&empty, &limits),
        Err(EnvelopeError::EmptyPayload)
    );
    // A declared length over the limit is refused before it is read.
    assert!(matches!(
        edit(&|b| b[2..6].copy_from_slice(&u32::MAX.to_be_bytes())),
        Err(EnvelopeError::TooLarge { .. })
    ));
    // Signatures out of order, or repeated.
    let sigs = decoded.signatures();
    let swapped = Envelope {
        kind: Kind::Bundle,
        payload: decoded.payload().to_vec(),
        signatures: vec![sigs[1].clone(), sigs[0].clone()],
    }
    .encode();
    assert_eq!(
        Envelope::decode(&swapped, &limits),
        Err(EnvelopeError::NotAscending)
    );
    let repeated = Envelope {
        kind: Kind::Bundle,
        payload: decoded.payload().to_vec(),
        signatures: vec![sigs[0].clone(), sigs[0].clone()],
    }
    .encode();
    assert_eq!(
        Envelope::decode(&repeated, &limits),
        Err(EnvelopeError::NotAscending)
    );
    // Through `from_parts`, a repeated key is refused too.
    assert_eq!(
        Envelope::from_parts(
            Kind::Bundle,
            decoded.payload().to_vec(),
            vec![sigs[0].clone(), sigs[0].clone()],
            &limits
        ),
        Err(EnvelopeError::NotAscending)
    );
}

#[test]
fn a_delta_envelope_is_not_a_bundle() {
    let (env, _, _) = delta_case();
    let v = verify_now(&env, &fixture().trust());
    assert_eq!(
        v.unreadable(),
        Some(&EnvelopeError::WrongKind {
            expected: Kind::Bundle,
            found: Kind::Delta
        })
    );
}

// ---------------------------------------------------------------------------
// Deltas
// ---------------------------------------------------------------------------

/// A delta envelope from version 1 to version 2, the base bytes and the
/// result bytes.
fn delta_case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let f = fixture();
    let base = bundle_with(1, 2, |_| {});
    let result = bundle_with(2, 3, |_| {});
    let limits = BundleLimits::DEFAULT;
    let delta = bundle::diff(
        &PolicyBundle::decode(&base, &limits).unwrap(),
        &PolicyBundle::decode(&result, &limits).unwrap(),
    )
    .unwrap();
    let env = Envelope::sign_delta(&delta, &result, &f.signer, &[f.p384])
        .unwrap()
        .encode();
    (env, base, result)
}

#[test]
fn a_delta_rebuilds_the_signed_full_bundle() {
    let f = fixture();
    let (env, base, result) = delta_case();
    let limits = BundleLimits::DEFAULT;
    let rebuilt = rebuild(&env, &base, &limits).unwrap();
    assert_eq!(rebuilt.kind(), Kind::Bundle);
    assert_eq!(rebuilt.payload(), result);
    // Exactly the envelope the server would send for the full bundle.
    let v = verify_now(&rebuilt.encode(), &f.trust());
    assert_eq!(v.signer(), Some(f.p384));
    assert_eq!(v.header().unwrap().policy_version, 2);
}

#[test]
fn an_unsigned_or_forged_delta_is_never_applied() {
    let f = fixture();
    let (env, base, result) = delta_case();
    let limits = BundleLimits::DEFAULT;
    let decoded = Envelope::decode(&env, &limits).unwrap();
    let delta = BundleDelta::from_bytes(decoded.payload(), &limits).unwrap();

    // A delta to another result, carrying the signatures of the real one:
    // it rebuilds, and verification refuses it.
    let other = bundle_with(2, 1, |_| {});
    let forged_delta = bundle::diff(
        &PolicyBundle::decode(&base, &limits).unwrap(),
        &PolicyBundle::decode(&other, &limits).unwrap(),
    )
    .unwrap();
    let forged = Envelope {
        kind: Kind::Delta,
        payload: forged_delta.to_bytes().unwrap(),
        signatures: decoded.signatures().to_vec(),
    }
    .encode();
    let rebuilt = rebuild(&forged, &base, &limits).unwrap();
    assert_eq!(rebuilt.payload(), other);
    let v = verify_now(&rebuilt.encode(), &f.trust());
    assert!(matches!(
        v.signature_error(),
        Some(SignatureError::BadSignature(_))
    ));
    refused(
        &v,
        Rejection::SignatureInvalid,
        EventType::PolicySignatureInvalid,
    );

    // Signed by a key the agent does not trust.
    let untrusted = Envelope::sign_delta(&delta, &result, &f.signer, &[f.unlisted])
        .unwrap()
        .encode();
    let v = verify_now(
        &rebuild(&untrusted, &base, &limits).unwrap().encode(),
        &f.trust(),
    );
    assert_eq!(
        v.signature_error(),
        Some(SignatureError::NoTrustedSignature)
    );

    // Another base: refused before anything is built.
    assert_eq!(
        rebuild(&env, &result, &limits),
        Err(RebuildError::Delta(DeltaError::WrongBase))
    );
    // A bundle envelope is not a delta.
    let full = f.sign(&result, &[f.p384]);
    assert_eq!(
        rebuild(&full, &base, &limits),
        Err(RebuildError::Envelope(EnvelopeError::WrongKind {
            expected: Kind::Delta,
            found: Kind::Bundle
        }))
    );
    // Not an envelope, and not a delta.
    assert!(matches!(
        rebuild(&env[1..], &base, &limits),
        Err(RebuildError::Envelope(_))
    ));
    let junk = Envelope {
        kind: Kind::Delta,
        payload: vec![0xa0],
        signatures: decoded.signatures().to_vec(),
    }
    .encode();
    assert!(matches!(
        rebuild(&junk, &base, &limits),
        Err(RebuildError::Delta(DeltaError::Decode(_)))
    ));
}

#[test]
fn signing_a_delta_checks_its_result() {
    let f = fixture();
    let (env, base, _) = delta_case();
    let limits = BundleLimits::DEFAULT;
    let delta =
        BundleDelta::from_bytes(Envelope::decode(&env, &limits).unwrap().payload(), &limits)
            .unwrap();
    assert_eq!(
        Envelope::sign_delta(&delta, &base, &f.signer, &[f.p384]),
        Err(SignError::ResultMismatch)
    );
    assert!(matches!(
        Envelope::sign_delta(&delta, b"junk", &f.signer, &[f.p384]),
        Err(SignError::NotABundle(_))
    ));
}

// ---------------------------------------------------------------------------
// Display, codes and odds and ends
// ---------------------------------------------------------------------------

#[test]
fn codes_and_messages() {
    for kind in [Kind::Bundle, Kind::Delta] {
        assert_eq!(Kind::from_code(kind.code()), Some(kind));
    }
    assert_eq!(Kind::from_code(0), None);
    assert_eq!(Kind::Bundle.to_string(), "bundle");
    assert_eq!(Kind::Delta.to_string(), "delta");
    let kid = Kid::from_bytes([1; 16]);
    let messages = [
        EnvelopeError::TooLarge { size: 2, limit: 1 }.to_string(),
        EnvelopeError::Truncated.to_string(),
        EnvelopeError::TrailingBytes.to_string(),
        EnvelopeError::UnsupportedVersion(9).to_string(),
        EnvelopeError::UnknownKind(9).to_string(),
        EnvelopeError::WrongKind {
            expected: Kind::Bundle,
            found: Kind::Delta,
        }
        .to_string(),
        EnvelopeError::EmptyPayload.to_string(),
        EnvelopeError::SignatureCount(0).to_string(),
        EnvelopeError::NotAscending.to_string(),
        EnvelopeError::UnknownAlgorithm(9).to_string(),
        EnvelopeError::Header(BundleError::Shape("x")).to_string(),
        SignatureError::NoTrustedSignature.to_string(),
        SignatureError::AlgorithmNotAccepted(kid, ED25519).to_string(),
        SignatureError::AlgorithmMismatch(kid).to_string(),
        SignatureError::BadSignature(kid).to_string(),
        SignatureError::KeyNotValid(kid, TimeError::Expired { not_after: now() }).to_string(),
        SignError::NotABundle(BundleError::Shape("x")).to_string(),
        SignError::TooLarge.to_string(),
        SignError::ResultMismatch.to_string(),
        SignError::Delta(DeltaError::WrongBase).to_string(),
        SignError::SignatureCount.to_string(),
        SignError::DuplicateKey(kid).to_string(),
        SignError::Signer(SignerError::UnknownKey(kid)).to_string(),
    ];
    for m in &messages {
        assert!(!m.is_empty());
    }
    let unique: BTreeSet<&String> = messages.iter().collect();
    assert_eq!(unique.len(), messages.len());
    // The wrappers add nothing to the message.
    assert_eq!(
        RebuildError::Envelope(EnvelopeError::Truncated).to_string(),
        EnvelopeError::Truncated.to_string()
    );
    assert_eq!(
        RebuildError::Delta(DeltaError::WrongBase).to_string(),
        SignError::Delta(DeltaError::WrongBase).to_string()
    );
    assert_eq!(max_envelope_len(usize::MAX), usize::MAX);
    assert_eq!(MAX_OVERHEAD, 7 + 8 * 113);
}

#[test]
fn target_of_maps_both_scopes() {
    let device = id("01890a5d-ac96-774b-bcce-b302099a8059");
    assert_eq!(
        target_of(bundle::Target {
            tenant: tenant(),
            scope: TargetScope::Device(device),
        }),
        Target {
            tenant: TenantId(tenant()),
            scope: Scope::Device(HostId(device)),
        }
    );
    assert_eq!(device_target().scope, Scope::Group(group()));
    let _ = Sha256Hex::from_bytes([0; 32]);
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// A bundle envelope with one signature, a dual-signed one, and the trust
/// set that lists both keys.
struct Sample {
    single: Vec<u8>,
    dual: Vec<u8>,
    trust: TrustSet,
}

fn sample() -> &'static Sample {
    static S: OnceLock<Sample> = OnceLock::new();
    S.get_or_init(|| {
        let f = fixture();
        let bytes = bundle_bytes(1);
        Sample {
            single: f.sign(&bytes, &[f.p384]),
            dual: f.sign(&bytes, &[f.p384, f.ed25519]),
            trust: f.trust(),
        }
    })
}

fn flip(
    envelope: &[u8],
    at: &prop::sample::Index,
    bit: u8,
    range: std::ops::Range<usize>,
) -> Vec<u8> {
    let mut bytes = envelope.to_vec();
    let i = range.start + at.index(range.len());
    bytes[i] ^= 1 << bit;
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000)
    ))]

    /// Flipping any single bit of a signed envelope, in its framing, the
    /// bundle or the signature, makes verification fail: no signature
    /// counts, or the envelope no longer reads.
    #[test]
    fn any_single_bit_flip_fails_verification(at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let s = sample();
        let bytes = flip(&s.single, &at, bit, 0..s.single.len());
        let v = verify_now(&bytes, &s.trust);
        prop_assert!(v.signer().is_none());
        prop_assert!(decide_fresh(&v).is_err());
    }

    /// With two signatures, a flip in the bundle fails both. (A flip in one
    /// signature's key ID turns it into an unknown key's, which is ignored
    /// while the other still verifies: that is the rotation rule.)
    #[test]
    fn any_bundle_bit_flip_fails_every_signature(at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let s = sample();
        let bytes = flip(&s.dual, &at, bit, 6..6 + bundle_bytes(1).len());
        let v = verify_now(&bytes, &s.trust);
        prop_assert!(v.signer().is_none());
        prop_assert!(decide_fresh(&v).is_err());
    }

    #[test]
    fn the_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(env) = Envelope::decode(&bytes, &BundleLimits::DEFAULT) {
            prop_assert_eq!(env.encode(), bytes.clone());
        }
        let _ = verify_now(&bytes, &sample().trust);
    }
}
