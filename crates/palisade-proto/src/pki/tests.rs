// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;

use proptest::prelude::*;

use super::crypto::{self, PrivateKey, Rng};
use super::trust_set::{MAX_KEYS, MAX_PINS, MAX_SIGNATURES, MAX_VERSION_STEP};
use super::*;
use crate::events::{Sha256Hex, Timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ts(s: &str) -> Timestamp {
    Timestamp::from_str(s).unwrap()
}

/// 2026-11-24T00:00:00Z, the tests' "now".
fn now() -> Timestamp {
    ts("2026-11-24T00:00:00.000000Z")
}

fn plus(t: Timestamp, micros: i64) -> Timestamp {
    Timestamp::from_unix_micros(t.unix_micros() + micros).unwrap()
}

const SECOND: i64 = 1_000_000;
const MINUTE: i64 = 60 * SECOND;
const DAY: i64 = 86_400 * SECOND;

/// A year around `now()`.
fn year() -> Validity {
    Validity::new(plus(now(), -180 * DAY), plus(now(), 180 * DAY)).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A signer holding the root, two trust-set keys, a policy key (ECDSA) and
/// an unlock key (Ed25519).
struct Fixture {
    signer: SoftwareSigner,
    root: Kid,
    t1: Kid,
    t2: Kid,
    policy: Kid,
    unlock: Kid,
}

impl Fixture {
    fn new() -> Self {
        let mut signer = SoftwareSigner::new();
        let p384 = SignatureAlgorithm::EcdsaP384Sha384;
        let root = signer.generate(KeyPurpose::RootCa, p384).unwrap();
        let t1 = signer.generate(KeyPurpose::TrustSet, p384).unwrap();
        let t2 = signer.generate(KeyPurpose::TrustSet, p384).unwrap();
        let policy = signer.generate(KeyPurpose::PolicySigning, p384).unwrap();
        let unlock = signer
            .generate(KeyPurpose::UnlockToken, SignatureAlgorithm::Ed25519)
            .unwrap();
        Self {
            signer,
            root,
            t1,
            t2,
            policy,
            unlock,
        }
    }

    fn public(&self, kid: Kid) -> PublicKey {
        self.signer.public_key(&kid).unwrap()
    }

    fn listed(&self, kid: Kid, validity: Validity) -> TrustedKey {
        let purpose = self.signer.purpose(&kid).unwrap();
        let public = self.public(kid);
        let alg = match public.key_type() {
            KeyType::P384 => SignatureAlgorithm::EcdsaP384Sha384,
            KeyType::Ed25519 => SignatureAlgorithm::Ed25519,
        };
        TrustedKey::new(public, purpose, alg, KeyStatus::Active, validity).unwrap()
    }

    /// A set at `version`, issued at `issued_at`, listing `trust` keys plus
    /// the policy and unlock keys and one server pin.
    fn set(&self, version: u64, issued_at: Timestamp, trust: &[Kid]) -> TrustSet {
        let mut set = TrustSet::new(
            version,
            issued_at,
            &[
                SignatureAlgorithm::EcdsaP384Sha384,
                SignatureAlgorithm::Ed25519,
            ],
        )
        .unwrap();
        for kid in trust {
            set.add_trust_key(self.listed(*kid, year())).unwrap();
        }
        set.add_policy_key(self.listed(self.policy, year()))
            .unwrap();
        set.add_unlock_key(self.listed(self.unlock, year()))
            .unwrap();
        set.add_server_pin(Sha256Hex::from_bytes([7; 32])).unwrap();
        set
    }

    fn sign(&self, set: &TrustSet, kids: &[Kid]) -> Vec<u8> {
        SignedTrustSet::sign(set, &self.signer, kids)
            .unwrap()
            .encode()
    }

    fn anchor(&self) -> TrustAnchor {
        TrustAnchor::new(self.public(self.root), SkewTolerance::DEFAULT).unwrap()
    }

    /// An anchor that has accepted version 1, root-signed, listing `t1`.
    fn anchor_at_v1(&self) -> TrustAnchor {
        let mut anchor = self.anchor();
        let v1 = self.sign(&self.set(1, now(), &[self.t1]), &[self.root]);
        anchor.accept(&v1, now()).unwrap();
        anchor
    }
}

// ---------------------------------------------------------------------------
// Known-answer vectors from an independent implementation
// ---------------------------------------------------------------------------

/// A P-384 `SubjectPublicKeyInfo`, generated with the OpenSSL command-line
/// tool (`genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384`, then
/// `pkey -pubout -outform DER`).
const KAT_P384_SPKI: &str = "3076301006072a8648ce3d020106052b8104002203620004de495437b1bac58c26f5a3fb80bcebb2194848f88f3fc10bac9a05d3a8827a1cbf18920cafa4d80d3ade4bcaed58096176621003288dd13007138fe8c399fad1068f72d3a7c0c29a3a86c217122572ff3c1f73a793449e77f141d5133c9fdcc9";
/// Its SHA-256 (`dgst -sha256`).
const KAT_P384_SPKI_SHA256: &str =
    "9415f6e9651246eca130fb05c0f9c108c74d6aefebe5e18f7cef6b1a9a127d0e";
/// An ECDSA P-384 SHA-384 signature by that key (`dgst -sha384 -sign`) over
/// `palisade-trustset-v1\0known answer payload`, converted from DER to
/// `r ‖ s`.
const KAT_P384_SIG: &str = "0ec2bed45b9d40521ee71c5c803da2cc386c55969d2eb72d71dba040b10d99ea3cef1334217caaf7b6a871e58276e16d644b90c12108f96a9198fe31b7e514559e889f2769f11d0d5fdc1c173491dd1d43c69bfafb765c031635e6123b3aebec";
/// An Ed25519 `SubjectPublicKeyInfo` from the same tool.
const KAT_ED25519_SPKI: &str =
    "302a300506032b65700321003d3d20bac4e3ccb22f5e1f5f114f6aca1771b4477d344d166a93bcf7e5468e46";
const KAT_ED25519_SPKI_SHA256: &str =
    "68cc65613934a9185ab3fd67b46d2709abf3fcb681ae680478120966f8d828cf";
/// An Ed25519 signature (`pkeyutl -sign -rawin`) over the same message.
const KAT_ED25519_SIG: &str = "366d4e94aec8c20727f0d3ca9d748b410a8c71775c263139342e21afeef4affb9190f3a5aada7fa713f4820d4b7dc82af625df68deb8c725c3c882a1564c0308";
const KAT_PAYLOAD: &[u8] = b"known answer payload";

#[test]
fn kid_is_the_first_16_bytes_of_the_spki_sha256() {
    for (spki, digest) in [
        (KAT_P384_SPKI, KAT_P384_SPKI_SHA256),
        (KAT_ED25519_SPKI, KAT_ED25519_SPKI_SHA256),
    ] {
        let key = PublicKey::from_spki_der(&hex(spki)).unwrap();
        assert_eq!(key.spki_sha256().to_string(), digest);
        assert_eq!(key.kid().to_string(), &digest[..32]);
        assert_eq!(Kid::of_spki(&hex(spki)), key.kid());
        assert_eq!(spki_sha256(&hex(spki)).to_string(), digest);
    }
}

#[test]
fn independent_signatures_verify_and_only_in_their_domain() {
    let cases = [
        (
            KAT_P384_SPKI,
            SignatureAlgorithm::EcdsaP384Sha384,
            KAT_P384_SIG,
        ),
        (
            KAT_ED25519_SPKI,
            SignatureAlgorithm::Ed25519,
            KAT_ED25519_SIG,
        ),
    ];
    for (spki, alg, sig) in cases {
        let key = PublicKey::from_spki_der(&hex(spki)).unwrap();
        let sig = hex(sig);
        assert!(key.verify(alg, Domain::TrustSet, KAT_PAYLOAD, &sig));
        // threat: T-signer-02. The same bytes under another prefix fail.
        assert!(!key.verify(alg, Domain::Policy, KAT_PAYLOAD, &sig));
        assert!(!key.verify(alg, Domain::Unlock, KAT_PAYLOAD, &sig));
        assert!(!key.verify(alg, Domain::TrustSet, b"other payload", &sig));
        let mut flipped = sig.clone();
        flipped[10] ^= 1;
        assert!(!key.verify(alg, Domain::TrustSet, KAT_PAYLOAD, &flipped));
        // Wrong length is refused before verification.
        assert!(!key.verify(alg, Domain::TrustSet, KAT_PAYLOAD, &sig[1..]));
    }
    // The algorithm must fit the key.
    let p384 = PublicKey::from_spki_der(&hex(KAT_P384_SPKI)).unwrap();
    assert!(!p384.verify(
        SignatureAlgorithm::Ed25519,
        Domain::TrustSet,
        KAT_PAYLOAD,
        &hex(KAT_ED25519_SIG)
    ));
}

#[test]
fn domain_prefixes_are_distinct_and_nul_terminated() {
    for domain in Domain::ALL {
        let prefix = domain.prefix();
        assert_eq!(prefix.last(), Some(&0));
        assert_eq!(&prefix[..prefix.len() - 1], domain.label().as_bytes());
        for other in Domain::ALL {
            if other != domain {
                assert!(!other.prefix().starts_with(prefix));
            }
        }
    }
    assert!(Domain::TrustSet.signed_by(KeyPurpose::RootCa));
    assert!(Domain::TrustSet.signed_by(KeyPurpose::TrustSet));
    assert!(!Domain::TrustSet.signed_by(KeyPurpose::PolicySigning));
    assert!(Domain::Policy.signed_by(KeyPurpose::PolicySigning));
    assert!(!Domain::Policy.signed_by(KeyPurpose::RootCa));
    assert!(Domain::Unlock.signed_by(KeyPurpose::UnlockToken));
    assert!(!Domain::Unlock.signed_by(KeyPurpose::TrustSet));
}

// ---------------------------------------------------------------------------
// Key inventory
// ---------------------------------------------------------------------------

#[test]
fn kid_text_form_is_strict() {
    let kid = Kid::from_str("9415f6e9651246eca130fb05c0f9c108").unwrap();
    assert_eq!(kid.to_string(), "9415f6e9651246eca130fb05c0f9c108");
    for bad in [
        "",
        "9415F6E9651246ECA130FB05C0F9C108",
        "9415f6e9651246eca130fb05c0f9c10",
        "9415f6e9651246eca130fb05c0f9c1080",
        "9415f6e9651246eca130fb05c0f9c10g",
    ] {
        assert_eq!(Kid::from_str(bad), Err(KeyError::InvalidKid), "{bad}");
    }
}

#[test]
fn public_key_encodings_are_strict() {
    let p384 = hex(KAT_P384_SPKI);
    let ed = hex(KAT_ED25519_SPKI);
    assert_eq!(
        PublicKey::from_spki_der(&p384).unwrap().key_type(),
        KeyType::P384
    );
    assert_eq!(
        PublicKey::from_spki_der(&ed).unwrap().key_type(),
        KeyType::Ed25519
    );

    let mut compressed = p384.clone();
    compressed[23] = 0x02;
    let mut extra = p384.clone();
    extra.push(0);
    let mut other_curve = p384.clone();
    other_curve[19] = 0x23; // secp521r1's last OID byte
    for bad in [
        Vec::new(),
        p384[..p384.len() - 1].to_vec(),
        compressed,
        extra,
        other_curve,
        ed[..ed.len() - 1].to_vec(),
    ] {
        assert_eq!(
            PublicKey::from_spki_der(&bad),
            Err(KeyError::UnsupportedPublicKey)
        );
    }
}

#[test]
fn labels_and_codes_round_trip_and_are_unique() {
    fn check<T: Copy + PartialEq + std::fmt::Debug + std::fmt::Display + FromStr>(
        all: &[T],
        code: fn(T) -> u8,
        from_code: fn(u8) -> Option<T>,
    ) where
        T::Err: std::fmt::Debug,
    {
        let mut codes: Vec<u8> = all.iter().map(|v| code(*v)).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        assert!(!codes.contains(&0), "code 0 is reserved");
        for v in all {
            assert_eq!(from_code(code(*v)), Some(*v));
            assert_eq!(T::from_str(&v.to_string()).ok(), Some(*v));
        }
        assert!(T::from_str("nope").is_err());
    }
    check(KeyPurpose::ALL, KeyPurpose::code, KeyPurpose::from_code);
    check(
        KeyAlgorithm::ALL,
        KeyAlgorithm::code,
        KeyAlgorithm::from_code,
    );
    check(
        SignatureAlgorithm::ALL,
        SignatureAlgorithm::code,
        SignatureAlgorithm::from_code,
    );
    check(KeyBackend::ALL, KeyBackend::code, KeyBackend::from_code);
    check(KeyStatus::ALL, KeyStatus::code, KeyStatus::from_code);
    assert_eq!(
        KeyPurpose::ALL
            .iter()
            .map(|p| p.label())
            .collect::<Vec<_>>(),
        [
            "root-ca",
            "issuing-ca",
            "server-tls",
            "trust-set",
            "policy-signing",
            "update-signing",
            "unlock-token",
            "escrow",
            "audit-chain"
        ]
    );
}

#[test]
fn every_status_transition_matches_the_table() {
    use KeyStatus::{Active, Compromised, Pending, Retired, Retiring};
    let legal = [
        (Pending, Active),
        (Pending, Retired),
        (Pending, Compromised),
        (Active, Retiring),
        (Active, Compromised),
        (Retiring, Retired),
        (Retiring, Active),
        (Retiring, Compromised),
        (Retired, Compromised),
    ];
    for from in KeyStatus::ALL {
        for to in KeyStatus::ALL {
            assert_eq!(
                from.can_become(*to),
                legal.contains(&(*from, *to)),
                "{from} -> {to}"
            );
        }
    }
    // Only active signs; active and retiring verify.
    for s in KeyStatus::ALL {
        assert_eq!(s.signs(), *s == Active);
        assert_eq!(s.verifies(), matches!(s, Active | Retiring));
    }
}

#[test]
fn purposes_allow_only_their_algorithms() {
    use KeyAlgorithm::{EcdhP384, EcdsaP384Sha384, Ed25519};
    for purpose in KeyPurpose::ALL {
        let allowed: Vec<KeyAlgorithm> = KeyAlgorithm::ALL
            .iter()
            .copied()
            .filter(|a| purpose.allows(*a))
            .collect();
        let expected: &[KeyAlgorithm] = match purpose {
            KeyPurpose::PolicySigning | KeyPurpose::UnlockToken => &[EcdsaP384Sha384, Ed25519],
            KeyPurpose::Escrow => &[EcdhP384],
            _ => &[EcdsaP384Sha384],
        };
        assert_eq!(allowed, expected, "{purpose}");
    }
}

#[test]
fn key_record_lifecycle() {
    let key = PublicKey::from_spki_der(&hex(KAT_P384_SPKI)).unwrap();
    let ed = PublicKey::from_spki_der(&hex(KAT_ED25519_SPKI)).unwrap();
    let validity = year();
    let created = plus(now(), -DAY);

    assert_eq!(
        KeyRecord::new(
            ed.clone(),
            KeyPurpose::RootCa,
            KeyAlgorithm::Ed25519,
            created,
            validity,
            KeyBackend::File
        ),
        Err(KeyError::AlgorithmNotAllowed {
            purpose: KeyPurpose::RootCa,
            algorithm: KeyAlgorithm::Ed25519
        })
    );
    assert_eq!(
        KeyRecord::new(
            ed,
            KeyPurpose::PolicySigning,
            KeyAlgorithm::EcdsaP384Sha384,
            created,
            validity,
            KeyBackend::File
        ),
        Err(KeyError::KeyTypeMismatch)
    );

    let mut record = KeyRecord::new(
        key.clone(),
        KeyPurpose::PolicySigning,
        KeyAlgorithm::EcdsaP384Sha384,
        created,
        validity,
        KeyBackend::Pkcs11,
    )
    .unwrap();
    assert_eq!(record.kid(), key.kid());
    assert_eq!(record.status(), KeyStatus::Pending);
    assert_eq!(record.backend(), KeyBackend::Pkcs11);
    assert_eq!(record.created_at(), created);
    assert!(!record.can_sign(now()));

    record.transition(KeyStatus::Active).unwrap();
    assert!(record.can_sign(now()));
    assert!(!record.can_sign(plus(validity.not_after(), 1)));
    assert!(!record.can_sign(plus(validity.not_before(), -1)));

    record.transition(KeyStatus::Retiring).unwrap();
    assert!(!record.can_sign(now()));

    // The escrow key is an encryption key and never signs.
    let mut escrow = KeyRecord::new(
        key.clone(),
        KeyPurpose::Escrow,
        KeyAlgorithm::EcdhP384,
        created,
        validity,
        KeyBackend::Kms,
    )
    .unwrap();
    escrow.transition(KeyStatus::Active).unwrap();
    assert!(!escrow.can_sign(now()));
    assert_eq!(KeyAlgorithm::EcdhP384.signature(), None);
    assert_eq!(
        KeyAlgorithm::EcdsaP384Sha384.signature(),
        Some(SignatureAlgorithm::EcdsaP384Sha384)
    );
    assert_eq!(
        KeyAlgorithm::Ed25519.signature(),
        Some(SignatureAlgorithm::Ed25519)
    );
    record.transition(KeyStatus::Retired).unwrap();
    assert_eq!(
        record.transition(KeyStatus::Active),
        Err(KeyError::IllegalTransition {
            from: KeyStatus::Retired,
            to: KeyStatus::Active
        })
    );
    assert_eq!(record.status(), KeyStatus::Retired);
    record.transition(KeyStatus::Compromised).unwrap();
    for to in KeyStatus::ALL {
        assert!(record.transition(*to).is_err());
    }
}

#[test]
fn certificate_binding_needs_serial_and_key() {
    // threat: T-ca-02
    let enrolled = hex(KAT_P384_SPKI);
    let other = hex(KAT_ED25519_SPKI);
    let binding = CertificateBinding::new(&[0x01, 0x02], &enrolled).unwrap();
    assert!(binding.matches(&[0x01, 0x02], &enrolled));
    assert!(
        !binding.matches(&[0x01, 0x02], &other),
        "reused serial, new key"
    );
    assert!(!binding.matches(&[0x01, 0x03], &enrolled));
    assert_eq!(binding.spki_sha256().to_string(), KAT_P384_SPKI_SHA256);
    assert_eq!(
        CertificateBinding::new(&[], &enrolled),
        Err(KeyError::InvalidSerial)
    );
    assert_eq!(
        CertificateBinding::new(&[1; 21], &enrolled),
        Err(KeyError::InvalidSerial)
    );
    assert!(CertificateBinding::new(&[1; 20], &enrolled).is_ok());
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

#[test]
fn validity_skew_edges() {
    let window = Validity::new(now(), plus(now(), DAY)).unwrap();
    let skew = SkewTolerance::DEFAULT;
    let five = 5 * MINUTE;

    // Inside.
    assert_eq!(window.check(now(), SkewTolerance::ZERO), Ok(()));
    assert_eq!(
        window.check(window.not_after(), SkewTolerance::ZERO),
        Ok(())
    );
    // Early, by exactly the tolerance, and one microsecond more.
    assert_eq!(window.check(plus(now(), -five), skew), Ok(()));
    assert_eq!(
        window.check(plus(now(), -five - 1), skew),
        Err(TimeError::NotYetValid { not_before: now() })
    );
    // Late, by exactly the tolerance, and one microsecond more.
    let end = window.not_after();
    assert_eq!(window.check(plus(end, five), skew), Ok(()));
    assert_eq!(
        window.check(plus(end, five + 1), skew),
        Err(TimeError::Expired { not_after: end })
    );
    // Zero tolerance is exact.
    assert!(window.check(plus(now(), -1), SkewTolerance::ZERO).is_err());
    assert!(window.check(plus(end, 1), SkewTolerance::ZERO).is_err());
    assert!(!window.contains(plus(end, 1)));
    // A one-instant window is valid.
    let instant = Validity::new(now(), now()).unwrap();
    assert!(instant.contains(now()));
    // Extremes of the timestamp range do not overflow.
    let all = Validity::new(Timestamp::MIN, Timestamp::MAX).unwrap();
    assert_eq!(all.check(Timestamp::MIN, SkewTolerance::MAX), Ok(()));
    assert_eq!(all.check(Timestamp::MAX, SkewTolerance::MAX), Ok(()));
    let early = Validity::new(Timestamp::MIN, Timestamp::MIN).unwrap();
    assert!(early.check(Timestamp::MAX, SkewTolerance::MAX).is_err());
}

#[test]
fn validity_and_skew_constructors() {
    assert_eq!(
        Validity::new(plus(now(), 1), now()),
        Err(TimeError::EmptyWindow)
    );
    assert_eq!(SkewTolerance::default(), SkewTolerance::DEFAULT);
    assert_eq!(SkewTolerance::DEFAULT.as_micros(), 300 * SECOND);
    assert_eq!(
        SkewTolerance::new(Duration::from_secs(3600)),
        Ok(SkewTolerance::MAX)
    );
    assert_eq!(
        SkewTolerance::new(Duration::from_micros(3_600_000_001)),
        Err(TimeError::SkewTooLarge)
    );
    assert_eq!(
        SkewTolerance::new(Duration::MAX),
        Err(TimeError::SkewTooLarge)
    );
    assert_eq!(SkewTolerance::new(Duration::ZERO), Ok(SkewTolerance::ZERO));
}

#[test]
fn clocks() {
    assert_eq!(FixedClock(now()).now(), now());
    // The system clock is after this file was written.
    assert!(SystemClock.now() > ts("2026-01-01T00:00:00.000000Z"));
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

#[test]
fn software_signer_signs_and_verifies_both_algorithms() {
    let f = Fixture::new();
    for (kid, domain, alg, len) in [
        (
            f.policy,
            Domain::Policy,
            SignatureAlgorithm::EcdsaP384Sha384,
            96,
        ),
        (f.unlock, Domain::Unlock, SignatureAlgorithm::Ed25519, 64),
    ] {
        let sig = f.signer.sign(&kid, domain, b"payload").unwrap();
        assert_eq!(sig.kid(), kid);
        assert_eq!(sig.algorithm(), alg);
        assert_eq!(sig.bytes().len(), len);
        let public = f.public(kid);
        assert!(public.verify(alg, domain, b"payload", sig.bytes()));
        assert!(!public.verify(alg, domain, b"payloaD", sig.bytes()));
        assert!(!public.verify(alg, Domain::TrustSet, b"payload", sig.bytes()));
        // ECDSA signatures are randomised; both still verify.
        let again = f.signer.sign(&kid, domain, b"payload").unwrap();
        assert!(public.verify(alg, domain, b"payload", again.bytes()));
    }
}

#[test]
fn signer_refuses_cross_purpose_signing() {
    // threat: T-signer-06
    let f = Fixture::new();
    for (kid, purpose, domain) in [
        (f.policy, KeyPurpose::PolicySigning, Domain::TrustSet),
        (f.unlock, KeyPurpose::UnlockToken, Domain::TrustSet),
        (f.root, KeyPurpose::RootCa, Domain::Policy),
        (f.t1, KeyPurpose::TrustSet, Domain::Unlock),
    ] {
        assert_eq!(
            f.signer.sign(&kid, domain, b"x"),
            Err(SignerError::WrongPurpose { purpose, domain })
        );
    }
    let unknown = Kid::from_bytes([0; 16]);
    assert_eq!(
        f.signer.sign(&unknown, Domain::TrustSet, b"x"),
        Err(SignerError::UnknownKey(unknown))
    );
    assert!(f.signer.public_key(&unknown).is_none());
    // A trust set cannot be signed by the policy key.
    assert_eq!(
        SignedTrustSet::sign(&f.set(1, now(), &[f.t1]), &f.signer, &[f.policy]),
        Err(TrustSetError::Signer(SignerError::WrongPurpose {
            purpose: KeyPurpose::PolicySigning,
            domain: Domain::TrustSet
        }))
    );
}

#[test]
fn signer_generation_respects_purpose_algorithms() {
    let mut signer = SoftwareSigner::default();
    assert_eq!(
        signer.generate(KeyPurpose::RootCa, SignatureAlgorithm::Ed25519),
        Err(SignerError::Key(KeyError::AlgorithmNotAllowed {
            purpose: KeyPurpose::RootCa,
            algorithm: KeyAlgorithm::Ed25519
        }))
    );
    assert!(
        signer
            .generate(KeyPurpose::Escrow, SignatureAlgorithm::EcdsaP384Sha384)
            .is_err()
    );
    assert_eq!(signer.kids().count(), 0);
}

#[test]
fn pkcs8_import() {
    for alg in SignatureAlgorithm::ALL {
        let der = crypto::test_pkcs8(*alg);
        let mut signer = SoftwareSigner::new();
        let kid = signer
            .import_pkcs8(KeyPurpose::PolicySigning, *alg, &der)
            .unwrap();
        // The kid is derived from the imported key's own public half.
        let rng = Rng::new();
        let private = PrivateKey::from_pkcs8(*alg, &der, &rng).unwrap();
        let public =
            PublicKey::from_raw(alg.key_algorithm().key_type(), private.raw_public_key()).unwrap();
        assert_eq!(kid, public.kid());
        let sig = signer.sign(&kid, Domain::Policy, b"p").unwrap();
        assert!(public.verify(*alg, Domain::Policy, b"p", sig.bytes()));
        assert_eq!(
            signer.import_pkcs8(KeyPurpose::PolicySigning, *alg, &der),
            Err(SignerError::DuplicateKey(kid))
        );
        assert_eq!(signer.kids().collect::<Vec<_>>(), [kid]);
    }
    let mut signer = SoftwareSigner::new();
    let ed = crypto::test_pkcs8(SignatureAlgorithm::Ed25519);
    let p384 = crypto::test_pkcs8(SignatureAlgorithm::EcdsaP384Sha384);
    for (alg, der) in [
        (SignatureAlgorithm::EcdsaP384Sha384, ed.as_slice()),
        (SignatureAlgorithm::Ed25519, p384.as_slice()),
        (SignatureAlgorithm::EcdsaP384Sha384, &p384[..p384.len() - 1]),
        (SignatureAlgorithm::Ed25519, &[][..]),
    ] {
        assert_eq!(
            signer.import_pkcs8(KeyPurpose::PolicySigning, alg, der),
            Err(SignerError::BadKeyEncoding)
        );
    }
}

#[test]
fn debug_output_never_contains_key_material() {
    let der = crypto::test_pkcs8(SignatureAlgorithm::Ed25519);
    let mut signer = SoftwareSigner::new();
    let kid = signer
        .import_pkcs8(KeyPurpose::UnlockToken, SignatureAlgorithm::Ed25519, &der)
        .unwrap();
    let text = format!("{signer:?}");
    assert!(text.contains(&kid.to_string()));
    // No 8-byte run of the PKCS#8 document (which holds the seed) appears.
    let hex_der: String = der.iter().map(|b| format!("{b:02x}")).collect();
    for window in hex_der.as_bytes().chunks(16) {
        assert!(!text.contains(std::str::from_utf8(window).unwrap()));
    }
    let private = PrivateKey::from_pkcs8(SignatureAlgorithm::Ed25519, &der, &Rng::new()).unwrap();
    assert_eq!(format!("{private:?}"), "PrivateKey(..)");
}

#[test]
fn signature_length_is_checked() {
    let kid = Kid::from_bytes([1; 16]);
    assert_eq!(
        Signature::new(kid, SignatureAlgorithm::Ed25519, vec![0; 63]),
        Err(SignerError::BadSignatureLength)
    );
    assert_eq!(
        Signature::new(kid, SignatureAlgorithm::EcdsaP384Sha384, vec![0; 64]),
        Err(SignerError::BadSignatureLength)
    );
    assert!(Signature::new(kid, SignatureAlgorithm::EcdsaP384Sha384, vec![0; 96]).is_ok());
}

// ---------------------------------------------------------------------------
// Trust-set construction and encoding
// ---------------------------------------------------------------------------

#[test]
fn trust_set_round_trips_canonically() {
    let f = Fixture::new();
    let mut set = f.set(42, now(), &[f.t1, f.t2]);
    set.set_update_root(UpdateRootPointer {
        version: 9,
        sha256: Sha256Hex::from_bytes([3; 32]),
    });
    let bytes = set.encode().unwrap();
    let decoded = TrustSet::decode(&bytes).unwrap();
    assert_eq!(decoded, set);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert_eq!(decoded.trust_version(), 42);
    assert_eq!(decoded.issued_at(), now());
    assert_eq!(decoded.trust_keys().count(), 2);
    assert_eq!(decoded.policy_keys().count(), 1);
    assert_eq!(decoded.unlock_keys().count(), 1);
    assert_eq!(decoded.server_pins().count(), 1);
    assert_eq!(decoded.update_root().unwrap().version, 9);
    assert_eq!(
        decoded.algorithms().collect::<Vec<_>>(),
        [
            SignatureAlgorithm::EcdsaP384Sha384,
            SignatureAlgorithm::Ed25519
        ]
    );

    let signed = SignedTrustSet::sign(&set, &f.signer, &[f.t2, f.root, f.t1]).unwrap();
    let envelope = signed.encode();
    let again = SignedTrustSet::decode(&envelope).unwrap();
    assert_eq!(again, signed);
    assert_eq!(again.encode(), envelope);
    assert_eq!(again.payload(), bytes.as_slice());
    let kids: Vec<Kid> = again.signatures().iter().map(Signature::kid).collect();
    let mut sorted = kids.clone();
    sorted.sort();
    assert_eq!(kids, sorted, "signatures are stored ascending by kid");
    assert_eq!(
        SignedTrustSet::from_parts(bytes.clone(), again.signatures().to_vec()).unwrap(),
        again
    );
}

#[test]
fn trust_set_construction_rules() {
    let f = Fixture::new();
    let algs = [SignatureAlgorithm::EcdsaP384Sha384];
    assert_eq!(
        TrustSet::new(0, now(), &algs),
        Err(TrustSetError::ZeroVersion)
    );
    assert_eq!(
        TrustSet::new(1, now(), &[]),
        Err(TrustSetError::NoAlgorithms)
    );
    let mut set = TrustSet::new(1, now(), &algs).unwrap();
    assert_eq!(set.encode(), Err(TrustSetError::NoTrustKeys));

    // Each list holds only its own purposes.
    assert_eq!(
        set.add_trust_key(f.listed(f.policy, year())),
        Err(TrustSetError::WrongList {
            list: "trust keys",
            purpose: KeyPurpose::PolicySigning
        })
    );
    assert!(set.add_policy_key(f.listed(f.t1, year())).is_err());
    assert!(set.add_unlock_key(f.listed(f.policy, year())).is_err());
    // The Ed25519 unlock key needs Ed25519 in the algorithm list.
    assert_eq!(
        set.add_unlock_key(f.listed(f.unlock, year())),
        Err(TrustSetError::AlgorithmNotListed(
            SignatureAlgorithm::Ed25519
        ))
    );
    // A key appears once across all lists.
    set.add_trust_key(f.listed(f.t1, year())).unwrap();
    assert_eq!(
        set.add_trust_key(f.listed(f.t1, year())),
        Err(TrustSetError::DuplicateKey(f.t1))
    );
    let pin = Sha256Hex::from_bytes([1; 32]);
    set.add_server_pin(pin).unwrap();
    assert_eq!(
        set.add_server_pin(pin),
        Err(TrustSetError::DuplicatePin(pin))
    );
    assert!(set.encode().is_ok());

    // Only active and retiring keys may be listed.
    for status in [
        KeyStatus::Pending,
        KeyStatus::Retired,
        KeyStatus::Compromised,
    ] {
        assert_eq!(
            TrustedKey::new(
                f.public(f.t2),
                KeyPurpose::TrustSet,
                SignatureAlgorithm::EcdsaP384Sha384,
                status,
                year()
            ),
            Err(TrustSetError::StatusNotTrusted(status))
        );
    }
    // Purpose, algorithm and key type must agree.
    assert!(
        TrustedKey::new(
            f.public(f.t2),
            KeyPurpose::TrustSet,
            SignatureAlgorithm::Ed25519,
            KeyStatus::Active,
            year()
        )
        .is_err()
    );
    assert!(
        TrustedKey::new(
            f.public(f.unlock),
            KeyPurpose::UnlockToken,
            SignatureAlgorithm::EcdsaP384Sha384,
            KeyStatus::Active,
            year()
        )
        .is_err()
    );

    // Signing needs 1 to MAX_SIGNATURES distinct keys.
    assert_eq!(
        SignedTrustSet::sign(&set, &f.signer, &[]),
        Err(TrustSetError::SignatureCount)
    );
    assert_eq!(
        SignedTrustSet::sign(&set, &f.signer, &[f.root, f.root]),
        Err(TrustSetError::DuplicateKey(f.root))
    );
    assert_eq!(
        SignedTrustSet::sign(&set, &f.signer, &[f.root; MAX_SIGNATURES + 1]),
        Err(TrustSetError::SignatureCount)
    );
}

#[test]
fn list_limits() {
    let mut set = TrustSet::new(1, now(), &[SignatureAlgorithm::EcdsaP384Sha384]).unwrap();
    for i in 0..MAX_PINS {
        let mut pin = [0u8; 32];
        pin[0] = u8::try_from(i).unwrap();
        set.add_server_pin(Sha256Hex::from_bytes(pin)).unwrap();
    }
    assert_eq!(
        set.add_server_pin(Sha256Hex::from_bytes([0xff; 32])),
        Err(TrustSetError::TooMany("server pins"))
    );
    let keys = key_pool();
    for key in keys.iter().take(MAX_KEYS) {
        set.add_policy_key(policy_key(key)).unwrap();
    }
    assert_eq!(
        set.add_policy_key(policy_key(&keys[MAX_KEYS])),
        Err(TrustSetError::TooMany("policy keys"))
    );
    set.add_trust_key(trust_key(&keys[MAX_KEYS + 1])).unwrap();
    let bytes = set.encode().unwrap();
    assert!(bytes.len() <= super::trust_set::MAX_PAYLOAD_LEN);
    assert_eq!(TrustSet::decode(&bytes).unwrap(), set);
}

#[test]
fn decoder_rejects_non_canonical_payloads() {
    let f = Fixture::new();
    let mut set = f.set(1, now(), &[f.t1]);
    set.add_server_pin(Sha256Hex::from_bytes([9; 32])).unwrap();
    let bytes = set.encode().unwrap();

    // Every truncation, and any trailing byte.
    for len in 0..bytes.len() {
        assert!(TrustSet::decode(&bytes[..len]).is_err(), "prefix {len}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(TrustSet::decode(&longer), Err(DecodeError::TrailingBytes));

    // Unknown version.
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert_eq!(
        TrustSet::decode(&v2),
        Err(DecodeError::UnsupportedVersion(2))
    );

    // trust_version 0.
    let mut zero = bytes.clone();
    zero[1..9].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        TrustSet::decode(&zero),
        Err(DecodeError::Set(TrustSetError::ZeroVersion))
    );

    // Out-of-range timestamp.
    let mut far = bytes.clone();
    far[9..17].copy_from_slice(&i64::MAX.to_be_bytes());
    assert_eq!(TrustSet::decode(&far), Err(DecodeError::InvalidTimestamp));

    // Algorithms out of order (the list is [1, 2] at offsets 18 and 19).
    assert_eq!(bytes[17], 2);
    let mut swapped = bytes.clone();
    swapped.swap(18, 19);
    assert_eq!(
        TrustSet::decode(&swapped),
        Err(DecodeError::NotAscending("algorithms"))
    );
    let mut dup = bytes.clone();
    dup[19] = 1;
    assert!(TrustSet::decode(&dup).is_err());
    let mut unknown = bytes.clone();
    unknown[19] = 9;
    assert_eq!(
        TrustSet::decode(&unknown),
        Err(DecodeError::UnknownCode("signature algorithm"))
    );

    // Pins out of order: find both pins and swap them.
    let a = find(&bytes, &[7; 32]);
    let b = find(&bytes, &[9; 32]);
    assert_eq!(b, a + 32);
    let mut pins = bytes.clone();
    pins[a..a + 32].copy_from_slice(&[9; 32]);
    pins[b..b + 32].copy_from_slice(&[7; 32]);
    assert_eq!(
        TrustSet::decode(&pins),
        Err(DecodeError::NotAscending("server pins"))
    );
    let mut dup_pin = bytes.clone();
    dup_pin[b..b + 32].copy_from_slice(&[7; 32]);
    assert_eq!(
        TrustSet::decode(&dup_pin),
        Err(DecodeError::NotAscending("server pins"))
    );

    // A listed key's status changed to retired.
    let key_at = 20; // n_trust at 20, first key's purpose at 21
    assert_eq!(bytes[key_at], 1);
    let mut retired = bytes.clone();
    retired[key_at + 2] = KeyStatus::Retired.code();
    assert_eq!(
        TrustSet::decode(&retired),
        Err(DecodeError::Set(TrustSetError::StatusNotTrusted(
            KeyStatus::Retired
        )))
    );
    // A policy-signing purpose in the trust list.
    let mut wrong = bytes.clone();
    wrong[key_at + 1] = KeyPurpose::PolicySigning.code();
    assert!(matches!(
        TrustSet::decode(&wrong),
        Err(DecodeError::Set(TrustSetError::WrongList { .. }))
    ));
    // An empty trust list.
    let mut none = bytes.clone();
    none[key_at] = 0;
    assert_eq!(
        TrustSet::decode(&none),
        Err(DecodeError::BadCount("trust keys"))
    );
    // A bad update-root flag.
    let mut flag = bytes.clone();
    *flag.last_mut().unwrap() = 2;
    assert_eq!(
        TrustSet::decode(&flag),
        Err(DecodeError::UnknownCode("update root presence"))
    );
    // Oversized input is refused before parsing.
    assert_eq!(
        TrustSet::decode(&vec![1; super::trust_set::MAX_PAYLOAD_LEN + 1]),
        Err(DecodeError::TooLong)
    );
}

#[test]
fn decoder_rejects_non_canonical_envelopes() {
    let f = Fixture::new();
    let set = f.set(1, now(), &[f.t1]);
    let envelope = f.sign(&set, &[f.root, f.t1]);
    for len in 0..envelope.len() {
        assert!(SignedTrustSet::decode(&envelope[..len]).is_err());
    }
    let mut longer = envelope.clone();
    longer.push(0);
    assert_eq!(
        SignedTrustSet::decode(&longer),
        Err(DecodeError::TrailingBytes)
    );

    let signed = SignedTrustSet::decode(&envelope).unwrap();
    let payload_len = signed.payload().len();
    let sigs_at = 1 + 4 + payload_len;
    assert_eq!(envelope[sigs_at], 2);
    // Swap the two signatures so they are out of order.
    let sig_len = 16 + 1 + 96;
    let first = envelope[sigs_at + 1..sigs_at + 1 + sig_len].to_vec();
    let second = envelope[sigs_at + 1 + sig_len..].to_vec();
    let mut swapped = envelope[..=sigs_at].to_vec();
    swapped.extend_from_slice(&second);
    swapped.extend_from_slice(&first);
    assert_eq!(
        SignedTrustSet::decode(&swapped),
        Err(DecodeError::NotAscending("signatures"))
    );
    // No signatures.
    let mut none = envelope[..=sigs_at].to_vec();
    none[sigs_at] = 0;
    assert_eq!(
        SignedTrustSet::decode(&none),
        Err(DecodeError::BadCount("signatures"))
    );
    // Payload length 0 and over the limit.
    let mut empty = envelope.clone();
    empty[1..5].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(SignedTrustSet::decode(&empty), Err(DecodeError::Truncated));
    let mut huge = envelope.clone();
    huge[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(SignedTrustSet::decode(&huge), Err(DecodeError::TooLong));
    let oversized = vec![1; super::trust_set::MAX_ENVELOPE_LEN + 1];
    assert_eq!(
        SignedTrustSet::decode(&oversized),
        Err(DecodeError::TooLong)
    );
    // A non-canonical payload inside a well-formed envelope.
    let mut bad_payload = envelope.clone();
    bad_payload[5] = 2;
    assert_eq!(
        SignedTrustSet::decode(&bad_payload),
        Err(DecodeError::UnsupportedVersion(2))
    );
    // from_parts sorts, then applies the same rules.
    let sigs = signed.signatures();
    assert!(
        SignedTrustSet::from_parts(
            signed.payload().to_vec(),
            vec![sigs[1].clone(), sigs[0].clone()]
        )
        .is_ok()
    );
    assert_eq!(
        SignedTrustSet::from_parts(
            signed.payload().to_vec(),
            vec![sigs[0].clone(), sigs[0].clone()]
        ),
        Err(DecodeError::NotAscending("signatures"))
    );
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

// ---------------------------------------------------------------------------
// The agent acceptance rule
// ---------------------------------------------------------------------------

#[test]
fn first_trust_set_must_be_signed_by_the_pinned_root() {
    let f = Fixture::new();
    let set = f.set(1, now(), &[f.t1]);
    let mut anchor = f.anchor();
    assert_eq!(anchor.trust_version(), 0);
    assert!(anchor.current().is_none());

    // The trust-set key is not trusted yet, even though the set lists it.
    let self_endorsed = f.sign(&set, &[f.t1]);
    assert_eq!(
        anchor.accept(&self_endorsed, now()),
        Err(Rejection::NoTrustedSignature)
    );
    assert_eq!(anchor.trust_version(), 0);

    let root_signed = f.sign(&set, &[f.root]);
    let accepted = anchor.accept(&root_signed, now()).unwrap();
    assert_eq!(accepted, &set);
    assert_eq!(anchor.trust_version(), 1);
    assert_eq!(anchor.pinned_root(), &f.public(f.root));
}

#[test]
fn chained_endorsement_and_rotation_of_the_trust_set_key() {
    let f = Fixture::new();
    let mut anchor = f.anchor_at_v1();

    // v2 is signed by t1, which v1 endorsed. It rotates to t2.
    let v2 = f.sign(&f.set(2, plus(now(), 1), &[f.t2]), &[f.t1]);
    anchor.accept(&v2, plus(now(), 1)).unwrap();
    assert_eq!(anchor.trust_version(), 2);

    // t1 is no longer trusted.
    let v3_old = f.sign(&f.set(3, plus(now(), 2), &[f.t2]), &[f.t1]);
    assert_eq!(
        anchor.accept(&v3_old, plus(now(), 2)),
        Err(Rejection::NoTrustedSignature)
    );
    // t2 is, and the root always is.
    let v3 = f.sign(&f.set(3, plus(now(), 2), &[f.t2]), &[f.t2]);
    anchor.accept(&v3, plus(now(), 2)).unwrap();
    let v4 = f.sign(&f.set(4, plus(now(), 3), &[f.t1]), &[f.root]);
    anchor.accept(&v4, plus(now(), 3)).unwrap();
    assert_eq!(anchor.trust_version(), 4);
}

#[test]
fn dual_signed_set_is_accepted_on_both_sides_of_a_rotation() {
    let f = Fixture::new();
    let set = f.set(5, plus(now(), 1), &[f.t2]);
    let envelope = f.sign(&set, &[f.t1, f.t2]);

    let mut knows_t1 = f.anchor_at_v1();
    knows_t1.accept(&envelope, plus(now(), 1)).unwrap();

    let current = f.set(1, now(), &[f.t2]);
    let mut knows_t2 =
        TrustAnchor::with_current(f.public(f.root), current, SkewTolerance::DEFAULT).unwrap();
    knows_t2.accept(&envelope, plus(now(), 1)).unwrap();
}

#[test]
fn rollback_and_replay_are_rejected() {
    let f = Fixture::new();
    let v1 = f.sign(&f.set(1, now(), &[f.t1]), &[f.root]);
    let mut anchor = f.anchor();
    anchor.accept(&v1, now()).unwrap();

    // Replaying the same set.
    assert_eq!(
        anchor.accept(&v1, now()),
        Err(Rejection::NotNewer {
            current: 1,
            offered: 1
        })
    );
    let v3 = f.sign(&f.set(3, plus(now(), 1), &[f.t1]), &[f.root]);
    anchor.accept(&v3, plus(now(), 1)).unwrap();
    // An older, validly root-signed set.
    let v2 = f.sign(&f.set(2, plus(now(), 2), &[f.t1]), &[f.root]);
    assert_eq!(
        anchor.accept(&v2, plus(now(), 2)),
        Err(Rejection::NotNewer {
            current: 3,
            offered: 2
        })
    );
    assert_eq!(anchor.trust_version(), 3);
}

#[test]
fn version_fast_forward_is_capped() {
    let f = Fixture::new();
    let mut anchor = f.anchor_at_v1();
    let too_far = f.sign(&f.set(2 + MAX_VERSION_STEP, now(), &[f.t1]), &[f.t1]);
    assert_eq!(
        anchor.accept(&too_far, now()),
        Err(Rejection::VersionJump {
            current: 1,
            offered: 2 + MAX_VERSION_STEP
        })
    );
    let max = f.sign(&f.set(u64::MAX, now(), &[f.t1]), &[f.root]);
    assert!(matches!(
        anchor.accept(&max, now()),
        Err(Rejection::VersionJump { .. })
    ));
    let edge = f.sign(&f.set(1 + MAX_VERSION_STEP, now(), &[f.t1]), &[f.t1]);
    anchor.accept(&edge, now()).unwrap();
    assert_eq!(anchor.trust_version(), 1 + MAX_VERSION_STEP);
}

#[test]
fn wrong_or_bad_signatures_are_rejected() {
    let f = Fixture::new();
    let mut anchor = f.anchor_at_v1();
    let set = f.set(2, now(), &[f.t1]);

    // Signed by a key from another deployment.
    let mut stranger = SoftwareSigner::new();
    let other_root = stranger
        .generate(KeyPurpose::RootCa, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let foreign = SignedTrustSet::sign(&set, &stranger, &[other_root])
        .unwrap()
        .encode();
    assert_eq!(
        anchor.accept(&foreign, now()),
        Err(Rejection::NoTrustedSignature)
    );

    // A trusted key's signature with one byte flipped, even alongside a
    // valid root signature.
    let signed = SignedTrustSet::sign(&set, &f.signer, &[f.root, f.t1]).unwrap();
    let mut sigs = signed.signatures().to_vec();
    let i = sigs.iter().position(|s| s.kid() == f.t1).unwrap();
    let mut bytes = sigs[i].bytes().to_vec();
    bytes[0] ^= 0x80;
    sigs[i] = Signature::new(f.t1, SignatureAlgorithm::EcdsaP384Sha384, bytes).unwrap();
    let tampered = SignedTrustSet::from_parts(signed.payload().to_vec(), sigs)
        .unwrap()
        .encode();
    assert_eq!(
        anchor.accept(&tampered, now()),
        Err(Rejection::BadSignature(f.t1))
    );

    // A valid signature over a different payload.
    let other_payload = f.set(2, plus(now(), -1), &[f.t1]).encode().unwrap();
    let moved = SignedTrustSet::from_parts(
        other_payload,
        SignedTrustSet::sign(&set, &f.signer, &[f.t1])
            .unwrap()
            .signatures()
            .to_vec(),
    )
    .unwrap()
    .encode();
    assert_eq!(
        anchor.accept(&moved, now()),
        Err(Rejection::BadSignature(f.t1))
    );

    // Unknown extra signers are ignored when a trusted one verifies.
    let mut both = SoftwareSigner::new();
    let extra = both
        .generate(KeyPurpose::TrustSet, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let payload = set.encode().unwrap();
    let mut sigs = SignedTrustSet::sign(&set, &f.signer, &[f.t1])
        .unwrap()
        .signatures()
        .to_vec();
    sigs.push(both.sign(&extra, Domain::TrustSet, &payload).unwrap());
    let with_extra = SignedTrustSet::from_parts(payload, sigs).unwrap().encode();
    anchor.accept(&with_extra, now()).unwrap();
    assert_eq!(anchor.trust_version(), 2);
}

#[test]
fn a_signature_from_another_domain_does_not_count() {
    // threat: T-signer-02. Build a root key outside the signer so it can
    // sign a policy-domain message, which `Signer` itself refuses.
    let f = Fixture::new();
    let rng = Rng::new();
    let root = PrivateKey::generate(SignatureAlgorithm::EcdsaP384Sha384, &rng).unwrap();
    let root_public = PublicKey::from_raw(KeyType::P384, root.raw_public_key()).unwrap();
    let mut anchor = TrustAnchor::new(root_public.clone(), SkewTolerance::DEFAULT).unwrap();

    let payload = f.set(1, now(), &[f.t1]).encode().unwrap();
    let wrong_domain = root.sign(&rng, &Domain::Policy.message(&payload)).unwrap();
    let sig = Signature::new(
        root_public.kid(),
        SignatureAlgorithm::EcdsaP384Sha384,
        wrong_domain,
    )
    .unwrap();
    let envelope = SignedTrustSet::from_parts(payload.clone(), vec![sig])
        .unwrap()
        .encode();
    assert_eq!(
        anchor.accept(&envelope, now()),
        Err(Rejection::BadSignature(root_public.kid()))
    );

    let right = root
        .sign(&rng, &Domain::TrustSet.message(&payload))
        .unwrap();
    let sig = Signature::new(
        root_public.kid(),
        SignatureAlgorithm::EcdsaP384Sha384,
        right,
    )
    .unwrap();
    let envelope = SignedTrustSet::from_parts(payload, vec![sig])
        .unwrap()
        .encode();
    anchor.accept(&envelope, now()).unwrap();
}

#[test]
fn algorithm_claims_must_match_the_trusted_key() {
    let f = Fixture::new();
    let anchor = f.anchor_at_v1();
    let payload = f.set(2, now(), &[f.t1]).encode().unwrap();
    for kid in [f.root, f.t1] {
        let sig = Signature::new(kid, SignatureAlgorithm::Ed25519, vec![0; 64]).unwrap();
        let envelope = SignedTrustSet::from_parts(payload.clone(), vec![sig])
            .unwrap()
            .encode();
        assert_eq!(
            anchor.check(&envelope, now()),
            Err(Rejection::AlgorithmNotAccepted(SignatureAlgorithm::Ed25519))
        );
    }
}

/// `envelope` with one extra signature appended.
fn with_extra_signature(envelope: &[u8], extra: Signature) -> Vec<u8> {
    let signed = SignedTrustSet::decode(envelope).unwrap();
    let mut sigs = signed.signatures().to_vec();
    sigs.push(extra);
    SignedTrustSet::from_parts(signed.payload().to_vec(), sigs)
        .unwrap()
        .encode()
}

#[test]
fn a_mislabelled_signature_by_a_known_key_rejects_even_beside_a_valid_one() {
    let f = Fixture::new();
    let anchor = f.anchor_at_v1();
    let good = f.sign(&f.set(2, now(), &[f.t1]), &[f.t1]);
    // A bogus Ed25519 claim under the pinned root, next to a valid t1
    // signature.
    let bogus_root = Signature::new(f.root, SignatureAlgorithm::Ed25519, vec![0; 64]).unwrap();
    assert_eq!(
        anchor.check(&with_extra_signature(&good, bogus_root), now()),
        Err(Rejection::AlgorithmNotAccepted(SignatureAlgorithm::Ed25519))
    );
    // The same under the other way round: valid root, bogus t1 claim.
    let by_root = f.sign(&f.set(2, now(), &[f.t1]), &[f.root]);
    let bogus_t1 = Signature::new(f.t1, SignatureAlgorithm::Ed25519, vec![0; 64]).unwrap();
    assert_eq!(
        anchor.check(&with_extra_signature(&by_root, bogus_t1), now()),
        Err(Rejection::AlgorithmNotAccepted(SignatureAlgorithm::Ed25519))
    );
}

#[test]
fn a_bad_signature_by_an_expired_known_key_still_rejects() {
    let f = Fixture::new();
    let window = Validity::new(plus(now(), -2 * DAY), plus(now(), -DAY)).unwrap();
    let mut v1 = TrustSet::new(
        1,
        plus(now(), -3 * DAY),
        &[SignatureAlgorithm::EcdsaP384Sha384],
    )
    .unwrap();
    v1.add_trust_key(f.listed(f.t1, window)).unwrap();
    let anchor = TrustAnchor::with_current(f.public(f.root), v1, SkewTolerance::DEFAULT).unwrap();

    let set = f.set(2, now(), &[f.t2]);
    let signed = SignedTrustSet::sign(&set, &f.signer, &[f.root, f.t1]).unwrap();
    // Untampered: t1 is expired but its signature verifies; the root's
    // carries the set.
    assert!(anchor.check(&signed.encode(), now()).is_ok());
    // Tampered t1 signature: rejected although t1 is outside its window.
    let mut sigs = signed.signatures().to_vec();
    let i = sigs.iter().position(|s| s.kid() == f.t1).unwrap();
    let mut bytes = sigs[i].bytes().to_vec();
    bytes[5] ^= 1;
    sigs[i] = Signature::new(f.t1, SignatureAlgorithm::EcdsaP384Sha384, bytes).unwrap();
    let tampered = SignedTrustSet::from_parts(signed.payload().to_vec(), sigs)
        .unwrap()
        .encode();
    assert_eq!(
        anchor.check(&tampered, now()),
        Err(Rejection::BadSignature(f.t1))
    );
}

#[test]
fn the_first_out_of_window_signer_is_reported() {
    let f = Fixture::new();
    let early = Validity::new(plus(now(), -3 * DAY), plus(now(), -2 * DAY)).unwrap();
    let late = Validity::new(plus(now(), -2 * DAY), plus(now(), -DAY)).unwrap();
    let mut v1 = TrustSet::new(
        1,
        plus(now(), -4 * DAY),
        &[SignatureAlgorithm::EcdsaP384Sha384],
    )
    .unwrap();
    v1.add_trust_key(f.listed(f.t1, early)).unwrap();
    v1.add_trust_key(f.listed(f.t2, late)).unwrap();
    let anchor = TrustAnchor::with_current(f.public(f.root), v1, SkewTolerance::DEFAULT).unwrap();
    let envelope = f.sign(&f.set(2, now(), &[f.t1]), &[f.t1, f.t2]);
    // Signatures are in kid order, so the first reported is the lower kid.
    let first = f.t1.min(f.t2);
    let window = if first == f.t1 { early } else { late };
    assert_eq!(
        anchor.check(&envelope, now()),
        Err(Rejection::SignerNotValid(
            first,
            TimeError::Expired {
                not_after: window.not_after()
            }
        ))
    );
}

#[test]
fn anchor_refuses_a_current_set_without_trust_keys() {
    let f = Fixture::new();
    let empty = TrustSet::new(1, now(), &[SignatureAlgorithm::EcdsaP384Sha384]).unwrap();
    assert_eq!(
        TrustAnchor::with_current(f.public(f.root), empty, SkewTolerance::DEFAULT).err(),
        Some(TrustSetError::NoTrustKeys)
    );
}

#[test]
fn signing_key_validity_allows_skew_and_no_more() {
    let f = Fixture::new();
    let window = Validity::new(plus(now(), -DAY), now()).unwrap();
    let mut v1 = TrustSet::new(
        1,
        plus(now(), -3 * DAY),
        &[SignatureAlgorithm::EcdsaP384Sha384],
    )
    .unwrap();
    v1.add_trust_key(f.listed(f.t1, window)).unwrap();
    let anchor = TrustAnchor::with_current(f.public(f.root), v1, SkewTolerance::DEFAULT).unwrap();
    let v2 = f.sign(&f.set(2, plus(now(), -DAY), &[f.t1]), &[f.t1]);

    // Expired, but within the 5-minute tolerance.
    assert!(anchor.check(&v2, plus(now(), 5 * MINUTE)).is_ok());
    // One microsecond beyond it.
    assert_eq!(
        anchor.check(&v2, plus(now(), 5 * MINUTE + 1)),
        Err(Rejection::SignerNotValid(
            f.t1,
            TimeError::Expired { not_after: now() }
        ))
    );
    // Not yet valid, beyond the tolerance. The set's issue time is valid.
    let early = plus(now(), -DAY - 5 * MINUTE - 1);
    let v2_early = f.sign(&f.set(2, plus(early, -DAY), &[f.t1]), &[f.t1]);
    assert_eq!(
        anchor.check(&v2_early, early),
        Err(Rejection::SignerNotValid(
            f.t1,
            TimeError::NotYetValid {
                not_before: plus(now(), -DAY)
            }
        ))
    );
    // The pinned root has no window: still accepted long after.
    let much_later = plus(now(), 3650 * DAY);
    let by_root = f.sign(&f.set(2, much_later, &[f.t2]), &[f.root]);
    assert!(anchor.check(&by_root, much_later).is_ok());
    // An expired key is reported only when nothing trusted verifies.
    let both = f.sign(&f.set(2, much_later, &[f.t2]), &[f.root, f.t1]);
    assert!(anchor.check(&both, much_later).is_ok());
}

#[test]
fn issue_time_rules() {
    let f = Fixture::new();
    let mut anchor = f.anchor_at_v1();
    let skew = 5 * MINUTE;

    // Stamped in the future, beyond the tolerance.
    let future = f.sign(&f.set(2, plus(now(), skew + 1), &[f.t1]), &[f.t1]);
    assert_eq!(anchor.check(&future, now()), Err(Rejection::IssuedInFuture));
    // Within the tolerance.
    let near = f.sign(&f.set(2, plus(now(), skew), &[f.t1]), &[f.t1]);
    assert!(anchor.check(&near, now()).is_ok());
    // Older than the current set.
    let older = f.sign(&f.set(2, plus(now(), -1), &[f.t1]), &[f.t1]);
    assert_eq!(
        anchor.accept(&older, now()),
        Err(Rejection::IssuedBeforeCurrent)
    );
    // The same issue time is allowed (two publications in one microsecond).
    let same = f.sign(&f.set(2, now(), &[f.t1]), &[f.t1]);
    anchor.accept(&same, now()).unwrap();
}

#[test]
fn rejection_leaves_the_anchor_unchanged() {
    let f = Fixture::new();
    let mut anchor = f.anchor_at_v1();
    let before = anchor.current().cloned();
    assert!(matches!(
        anchor.accept(b"\x01garbage", now()),
        Err(Rejection::Malformed(_))
    ));
    assert!(anchor.accept(&[], now()).is_err());
    let stale = f.sign(&f.set(1, now(), &[f.t2]), &[f.root]);
    assert!(anchor.accept(&stale, now()).is_err());
    assert_eq!(anchor.current().cloned(), before);
}

#[test]
fn anchor_requires_a_p384_root() {
    let ed = PublicKey::from_spki_der(&hex(KAT_ED25519_SPKI)).unwrap();
    assert_eq!(
        TrustAnchor::new(ed, SkewTolerance::DEFAULT).err(),
        Some(TrustSetError::Key(KeyError::KeyTypeMismatch))
    );
}

// ---------------------------------------------------------------------------
// Verifying other domains against a trust set
// ---------------------------------------------------------------------------

#[test]
fn trust_set_verifies_policy_and_unlock_signatures() {
    let f = Fixture::new();
    let set = f.set(1, now(), &[f.t1]);
    let skew = SkewTolerance::DEFAULT;

    let policy_sig = f.signer.sign(&f.policy, Domain::Policy, b"bundle").unwrap();
    assert_eq!(
        set.verify(Domain::Policy, b"bundle", &policy_sig, now(), skew)
            .unwrap()
            .kid(),
        f.policy
    );
    assert_eq!(
        set.verify(Domain::Policy, b"other", &policy_sig, now(), skew),
        Err(VerifyError::BadSignature)
    );
    // The policy key is not an unlock or trust key.
    assert_eq!(
        set.verify(Domain::Unlock, b"bundle", &policy_sig, now(), skew),
        Err(VerifyError::UnknownKey(f.policy))
    );
    assert_eq!(
        set.verify(Domain::TrustSet, b"bundle", &policy_sig, now(), skew),
        Err(VerifyError::UnknownKey(f.policy))
    );
    let unlock_sig = f.signer.sign(&f.unlock, Domain::Unlock, b"token").unwrap();
    assert!(
        set.verify(Domain::Unlock, b"token", &unlock_sig, now(), skew)
            .is_ok()
    );
    // Expired key.
    let later = plus(year().not_after(), 5 * MINUTE + 1);
    assert!(matches!(
        set.verify(Domain::Unlock, b"token", &unlock_sig, later, skew),
        Err(VerifyError::Time(TimeError::Expired { .. }))
    ));
    // Algorithm claim that is not the key's.
    let lie = Signature::new(f.policy, SignatureAlgorithm::Ed25519, vec![0; 64]).unwrap();
    assert_eq!(
        set.verify(Domain::Policy, b"bundle", &lie, now(), skew),
        Err(VerifyError::AlgorithmMismatch)
    );
    // A set that does not accept Ed25519 refuses Ed25519 signatures.
    let mut p384_only = TrustSet::new(1, now(), &[SignatureAlgorithm::EcdsaP384Sha384]).unwrap();
    p384_only.add_trust_key(f.listed(f.t1, year())).unwrap();
    let ed_claim = Signature::new(f.t1, SignatureAlgorithm::Ed25519, vec![0; 64]).unwrap();
    assert_eq!(
        p384_only.verify(Domain::TrustSet, b"x", &ed_claim, now(), skew),
        Err(VerifyError::AlgorithmNotAccepted(
            SignatureAlgorithm::Ed25519
        ))
    );
    assert_eq!(
        p384_only.verify(Domain::Unlock, b"token", &unlock_sig, now(), skew),
        Err(VerifyError::UnknownKey(f.unlock))
    );
}

#[test]
fn server_pins() {
    let ca = hex(KAT_P384_SPKI);
    let mut set = TrustSet::new(1, now(), &[SignatureAlgorithm::EcdsaP384Sha384]).unwrap();
    assert!(!set.pins(&ca));
    set.add_server_pin(spki_sha256(&ca)).unwrap();
    assert!(set.pins(&ca));
    assert!(!set.pins(&hex(KAT_ED25519_SPKI)));
}

#[test]
fn errors_display() {
    let kid = Kid::from_bytes([0xab; 16]);
    for text in [
        Rejection::NoTrustedSignature.to_string(),
        Rejection::BadSignature(kid).to_string(),
        Rejection::NotNewer {
            current: 3,
            offered: 2,
        }
        .to_string(),
        Rejection::VersionJump {
            current: 1,
            offered: u64::MAX,
        }
        .to_string(),
        Rejection::Malformed(DecodeError::Truncated).to_string(),
        TrustSetError::WrongList {
            list: "trust keys",
            purpose: KeyPurpose::Escrow,
        }
        .to_string(),
        SignerError::WrongPurpose {
            purpose: KeyPurpose::PolicySigning,
            domain: Domain::TrustSet,
        }
        .to_string(),
        KeyError::IllegalTransition {
            from: KeyStatus::Retired,
            to: KeyStatus::Active,
        }
        .to_string(),
        TimeError::Expired { not_after: now() }.to_string(),
        VerifyError::UnknownKey(kid).to_string(),
    ] {
        assert!(!text.is_empty());
    }
    assert_eq!(
        Rejection::NotNewer {
            current: 3,
            offered: 2
        }
        .to_string(),
        "trust version 2 is not newer than the current 3"
    );
    assert_eq!(
        SignerError::WrongPurpose {
            purpose: KeyPurpose::PolicySigning,
            domain: Domain::TrustSet
        }
        .to_string(),
        "a policy-signing key may not sign palisade-trustset-v1"
    );
    assert_eq!(format!("{kid:?}"), "Kid(abababababababababababababababab)");
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Pre-generated public keys, so property tests do not run key generation
/// per case. P-384 keys first, then Ed25519 keys.
fn key_pool() -> &'static [PublicKey] {
    static POOL: OnceLock<Vec<PublicKey>> = OnceLock::new();
    POOL.get_or_init(|| {
        let rng = Rng::new();
        let mut keys = Vec::new();
        for (alg, n) in [
            (SignatureAlgorithm::EcdsaP384Sha384, MAX_KEYS + 8),
            (SignatureAlgorithm::Ed25519, 8),
        ] {
            for _ in 0..n {
                let private = PrivateKey::generate(alg, &rng).unwrap();
                keys.push(
                    PublicKey::from_raw(alg.key_algorithm().key_type(), private.raw_public_key())
                        .unwrap(),
                );
            }
        }
        keys
    })
}

fn trust_key(key: &PublicKey) -> TrustedKey {
    TrustedKey::new(
        key.clone(),
        KeyPurpose::TrustSet,
        SignatureAlgorithm::EcdsaP384Sha384,
        KeyStatus::Active,
        year(),
    )
    .unwrap()
}

fn policy_key(key: &PublicKey) -> TrustedKey {
    let alg = match key.key_type() {
        KeyType::P384 => SignatureAlgorithm::EcdsaP384Sha384,
        KeyType::Ed25519 => SignatureAlgorithm::Ed25519,
    };
    TrustedKey::new(
        key.clone(),
        KeyPurpose::PolicySigning,
        alg,
        KeyStatus::Retiring,
        year(),
    )
    .unwrap()
}

prop_compose! {
    fn arb_set()(
        version in 1u64..,
        issued in Timestamp::MIN.unix_micros()..=Timestamp::MAX.unix_micros(),
        n_trust in 1usize..4,
        n_policy in 0usize..4,
        n_ed in 0usize..3,
        pins in proptest::collection::btree_set(any::<[u8; 32]>(), 0..4),
        update in proptest::option::of((any::<u64>(), any::<[u8; 32]>())),
    ) -> TrustSet {
        let keys = key_pool();
        let mut set = TrustSet::new(
            version,
            Timestamp::from_unix_micros(issued).unwrap(),
            &[SignatureAlgorithm::EcdsaP384Sha384, SignatureAlgorithm::Ed25519],
        )
        .unwrap();
        for key in &keys[..n_trust] {
            set.add_trust_key(trust_key(key)).unwrap();
        }
        for key in &keys[n_trust..n_trust + n_policy] {
            set.add_policy_key(policy_key(key)).unwrap();
        }
        let ed = &keys[MAX_KEYS + 8..];
        for key in &ed[..n_ed] {
            set.add_unlock_key(
                TrustedKey::new(
                    key.clone(),
                    KeyPurpose::UnlockToken,
                    SignatureAlgorithm::Ed25519,
                    KeyStatus::Active,
                    year(),
                )
                .unwrap(),
            )
            .unwrap();
        }
        for pin in pins {
            set.add_server_pin(Sha256Hex::from_bytes(pin)).unwrap();
        }
        if let Some((version, sha)) = update {
            set.set_update_root(UpdateRootPointer {
                version,
                sha256: Sha256Hex::from_bytes(sha),
            });
        }
        set
    }
}

/// One envelope signed by a fixed root, for mutation tests.
fn sample_envelope() -> &'static (Vec<u8>, PublicKey) {
    static SAMPLE: OnceLock<(Vec<u8>, PublicKey)> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        let f = Fixture::new();
        let mut set = f.set(1, now(), &[f.t1, f.t2]);
        set.set_update_root(UpdateRootPointer {
            version: 1,
            sha256: Sha256Hex::from_bytes([5; 32]),
        });
        (f.sign(&set, &[f.root, f.t1]), f.public(f.root))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000)
    ))]

    #[test]
    fn valid_sets_round_trip(set in arb_set()) {
        let bytes = set.encode().unwrap();
        let decoded = TrustSet::decode(&bytes).unwrap();
        prop_assert_eq!(decoded.encode().unwrap(), bytes);
        prop_assert_eq!(decoded, set);
    }

    #[test]
    fn decoders_never_panic_on_random_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = TrustSet::decode(&bytes);
        let _ = SignedTrustSet::decode(&bytes);
    }

    /// Any change to a signed envelope is either refused or decodes to
    /// something that re-encodes to the changed bytes (so it is canonical),
    /// and an agent never accepts it unless the payload is untouched.
    #[test]
    fn mutated_envelopes_are_canonical_or_rejected(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), 1u8..), 1..4),
        cut in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let (envelope, root) = sample_envelope();
        let mut bytes = envelope.clone();
        for (at, mask) in &flips {
            let i = at.index(bytes.len());
            bytes[i] ^= mask;
        }
        if let Some(cut) = cut {
            bytes.truncate(cut.index(bytes.len()));
        }
        if let Ok(signed) = SignedTrustSet::decode(&bytes) {
            prop_assert_eq!(signed.encode(), bytes.clone());
        }
        let mut anchor = TrustAnchor::new(root.clone(), SkewTolerance::DEFAULT).unwrap();
        if anchor.accept(&bytes, now()).is_ok() {
            // Only the signature region may differ, and the root's
            // signature must still be intact.
            let original = SignedTrustSet::decode(envelope).unwrap();
            let accepted = SignedTrustSet::decode(&bytes).unwrap();
            prop_assert_eq!(original.payload(), accepted.payload());
        }
    }
}
