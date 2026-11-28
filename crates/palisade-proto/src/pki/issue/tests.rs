//! Issuance tests. Every chain is checked by an independent verifier, the
//! WebPKI verifier rustls uses for the server's mTLS, and every field by
//! `palisade-fileid`'s strict X.509 parser.

// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::str::FromStr;
use std::sync::Arc;

use palisade_fileid::authenticode::{CertSummary, Curve, DigestAlgorithm, KeyAlgorithm};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{CertificateError, Error as TlsError, RootCertStore};

use super::*;
use crate::events::{HostId, TenantId, Uuid7};
use crate::pki::{KeyPurpose, SignatureAlgorithm, SoftwareSigner};

const SECOND: i64 = 1_000_000;
const DAY: i64 = 86_400 * SECOND;

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

fn window(from_days: i64, to_days: i64) -> Validity {
    Validity::new(plus(now(), from_days * DAY), plus(now(), to_days * DAY)).unwrap()
}

fn unix(t: Timestamp) -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(
        u64::try_from(t.unix_micros() / SECOND).unwrap(),
    ))
}

fn device_id() -> HostId {
    HostId(Uuid7::from_str("019a0000-0000-7000-8000-000000000001").unwrap())
}

fn tenant_id() -> TenantId {
    TenantId(Uuid7::from_str("019a0000-0000-7000-8000-0000000000aa").unwrap())
}

fn dns(names: &[&str]) -> Vec<DnsName> {
    names.iter().map(|n| n.parse().unwrap()).collect()
}

/// A root, an issuing CA and the keys of three leaves.
struct Pki {
    signer: SoftwareSigner,
    root: CaCertificate,
    issuing: CaCertificate,
    device_key: PublicKey,
    relay_key: PublicKey,
    server_key: PublicKey,
}

impl Pki {
    fn new() -> Self {
        let mut signer = SoftwareSigner::new();
        let root_kid = signer
            .generate(KeyPurpose::RootCa, SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap();
        let issuing_kid = signer
            .generate(KeyPurpose::IssuingCa, SignatureAlgorithm::EcdsaP384Sha384)
            .unwrap();
        let root = CaCertificate::self_signed_root(
            &signer,
            &root_kid,
            "Palisade Test Root",
            window(-10, 3650),
        )
        .unwrap();
        let issuing_key = signer.public_key(&issuing_kid).unwrap();
        let issuing = CaCertificate::issuing_ca(
            &signer,
            &root,
            &issuing_key,
            "Palisade Test Issuing CA 1",
            window(-5, 1000),
        )
        .unwrap();
        let device_key = leaf_key(&mut signer);
        let relay_key = leaf_key(&mut signer);
        let server_key = leaf_key(&mut signer);
        Self {
            signer,
            root,
            issuing,
            device_key,
            relay_key,
            server_key,
        }
    }

    fn device(&self) -> LeafCertificate {
        LeafCertificate::device(
            &self.signer,
            &self.issuing,
            &self.device_key,
            device_id(),
            tenant_id(),
            window(-1, 29),
        )
        .unwrap()
    }

    fn relay(&self) -> LeafCertificate {
        LeafCertificate::relay(
            &self.signer,
            &self.issuing,
            &self.relay_key,
            device_id(),
            tenant_id(),
            &dns(&["relay.example.org"]),
            window(-1, 90),
        )
        .unwrap()
    }

    fn server(&self) -> LeafCertificate {
        LeafCertificate::server(
            &self.signer,
            &self.issuing,
            &self.server_key,
            &dns(&["palisade.example.org", "palisade"]),
            window(-1, 365),
        )
        .unwrap()
    }
}

/// A P-384 key whose private half the test never uses: certificates only
/// need the public key. Generated as a trust-set key so the signer holds a
/// real key pair.
fn leaf_key(signer: &mut SoftwareSigner) -> PublicKey {
    let kid = signer
        .generate(KeyPurpose::ServerTls, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    signer.public_key(&kid).unwrap()
}

fn roots(anchors: &[&[u8]]) -> Arc<RootCertStore> {
    let mut store = RootCertStore::empty();
    for der in anchors {
        store.add(CertificateDer::from(der.to_vec())).unwrap();
    }
    Arc::new(store)
}

/// Verifies `leaf` as a TLS client certificate (the server's mTLS check)
/// with `crls`, at `at`.
fn verify_client(
    anchors: &[&[u8]],
    leaf: &[u8],
    intermediates: &[&[u8]],
    crls: &[Vec<u8>],
    at: Timestamp,
) -> Result<(), TlsError> {
    let mut builder =
        WebPkiClientVerifier::builder_with_provider(roots(anchors), Arc::new(default_provider()));
    if !crls.is_empty() {
        builder = builder
            .with_crls(
                crls.iter()
                    .map(|c| CertificateRevocationListDer::from(c.clone())),
            )
            .enforce_revocation_expiration();
    }
    let verifier = builder.build().unwrap();
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.to_vec()))
        .collect();
    verifier
        .verify_client_cert(&CertificateDer::from(leaf.to_vec()), &inter, unix(at))
        .map(|_| ())
}

/// Verifies `leaf` as a TLS server certificate for `name`.
fn verify_server(
    anchors: &[&[u8]],
    leaf: &[u8],
    intermediates: &[&[u8]],
    name: &str,
    at: Timestamp,
) -> Result<(), TlsError> {
    let verifier =
        WebPkiServerVerifier::builder_with_provider(roots(anchors), Arc::new(default_provider()))
            .build()
            .unwrap();
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.to_vec()))
        .collect();
    verifier
        .verify_server_cert(
            &CertificateDer::from(leaf.to_vec()),
            &inter,
            &ServerName::try_from(name.to_owned()).unwrap(),
            &[],
            unix(at),
        )
        .map(|_| ())
}

fn cert_error(e: TlsError) -> CertificateError {
    match e {
        TlsError::InvalidCertificate(c) => c,
        other => panic!("expected a certificate error, got {other:?}"),
    }
}

fn summary(der: &[u8]) -> CertSummary {
    CertSummary::from_der(der).unwrap()
}

fn ekus(c: &CertSummary) -> Vec<String> {
    c.extended_key_usage
        .as_ref()
        .map(|v| v.iter().map(|e| e.oid.to_string()).collect())
        .unwrap_or_default()
}

const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

// ---------------------------------------------------------------------------
// The hierarchy
// ---------------------------------------------------------------------------

#[test]
fn hierarchy_verifies_with_webpki() {
    let pki = Pki::new();
    let root = pki.root.der();
    let issuing = pki.issuing.der();
    verify_client(&[root], pki.device().der(), &[issuing], &[], now()).unwrap();
    verify_client(&[root], pki.relay().der(), &[issuing], &[], now()).unwrap();
    verify_server(
        &[root],
        pki.relay().der(),
        &[issuing],
        "relay.example.org",
        now(),
    )
    .unwrap();
    for name in ["palisade.example.org", "palisade"] {
        verify_server(&[root], pki.server().der(), &[issuing], name, now()).unwrap();
    }
    // Without the issuing CA there is no path.
    assert_eq!(
        cert_error(verify_client(&[root], pki.device().der(), &[], &[], now()).unwrap_err()),
        CertificateError::UnknownIssuer
    );
}

#[test]
fn ca_certificates_carry_the_profile() {
    let pki = Pki::new();
    let root = summary(pki.root.der());
    assert!(root.is_self_signed);
    assert_eq!(root.subject.common_name(), Some("Palisade Test Root"));
    assert_eq!(root.subject.der, root.issuer.der);
    let bc = root.basic_constraints.unwrap();
    assert!(bc.ca);
    assert_eq!(bc.path_len, Some(1));
    let ku = root.key_usage.unwrap();
    assert_eq!(
        ku.names().collect::<Vec<_>>(),
        ["key_cert_sign", "crl_sign"]
    );
    assert_eq!(root.public_key_alg, KeyAlgorithm::Ec(Curve::P384));
    assert_eq!(
        root.sig_alg,
        palisade_fileid::authenticode::SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha384)
    );
    assert_eq!(root.serial.len(), 32, "16-byte serial");
    assert_eq!(root.serial, hex(pki.root.serial()));
    assert_eq!(
        root.spki_sha256,
        pki.root.public_key().spki_sha256().to_string()
    );
    let ski = root.subject_key_id.clone().unwrap();
    assert_eq!(ski.len(), 40);
    assert!(
        pki.root
            .public_key()
            .spki_sha256()
            .to_string()
            .starts_with(&ski)
    );
    assert!(pki.root.kid().to_string().starts_with(&ski[..32]));

    let issuing = summary(pki.issuing.der());
    assert!(!issuing.is_self_signed);
    assert_eq!(issuing.issuer.der, root.subject.der);
    assert_eq!(issuing.authority_key_id, Some(ski));
    assert_eq!(issuing.basic_constraints.unwrap().path_len, Some(0));
    assert_eq!(
        issuing.not_before,
        pki.issuing.validity().not_before().unix_micros() / SECOND
    );
    assert_eq!(
        issuing.not_after,
        pki.issuing.validity().not_after().unix_micros() / SECOND
    );
    assert!(issuing.unhandled_critical_extensions.is_empty());
    assert_eq!(pki.issuing.purpose(), KeyPurpose::IssuingCa);
    assert_eq!(pki.issuing.name(), "Palisade Test Issuing CA 1");
}

#[test]
fn leaves_carry_their_profile() {
    let pki = Pki::new();
    let issuing = summary(pki.issuing.der());

    let device = pki.device();
    assert_eq!(device.profile(), LeafProfile::Device);
    let d = summary(device.der());
    assert_eq!(
        d.subject.common_name(),
        Some("019a0000-0000-7000-8000-000000000001")
    );
    assert_eq!(ekus(&d), [CLIENT_AUTH]);
    assert!(!d.basic_constraints.unwrap().ca);
    assert_eq!(
        d.key_usage.unwrap().names().collect::<Vec<_>>(),
        ["digital_signature"]
    );
    assert_eq!(d.authority_key_id, issuing.subject_key_id);
    assert_eq!(d.spki_sha256, pki.device_key.spki_sha256().to_string());
    assert_eq!(d.serial, hex(device.serial()));
    let uris = san_uris(device.der());
    assert_eq!(
        uris,
        [
            "urn:palisade:device:019a0000-0000-7000-8000-000000000001",
            "urn:palisade:tenant:019a0000-0000-7000-8000-0000000000aa",
        ]
    );

    let relay = summary(pki.relay().der());
    assert_eq!(ekus(&relay), [SERVER_AUTH, CLIENT_AUTH]);
    assert_eq!(
        san_uris(pki.relay().der()),
        [
            "urn:palisade:relay:019a0000-0000-7000-8000-000000000001",
            "urn:palisade:tenant:019a0000-0000-7000-8000-0000000000aa",
        ]
    );

    let server = summary(pki.server().der());
    assert_eq!(ekus(&server), [SERVER_AUTH]);
    assert_eq!(server.subject.common_name(), Some("palisade.example.org"));
    assert!(san_uris(pki.server().der()).is_empty());
}

/// The URIs in the subject alternative name, found by scanning for the
/// `[6]` (uniformResourceIdentifier) tag. Enough for these fixed layouts.
fn san_uris(der: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < der.len() {
        if der[i] == 0x86 && der[i + 1] < 0x80 {
            let len = usize::from(der[i + 1]);
            if let Some(bytes) = der.get(i + 2..i + 2 + len)
                && let Ok(s) = std::str::from_utf8(bytes)
                && s.starts_with("urn:palisade:")
            {
                out.push(s.to_owned());
                i += 2 + len;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn extended_key_usage_keeps_devices_out_of_server_roles() {
    // T-ca-07: a device certificate cannot authenticate a server.
    let pki = Pki::new();
    let e = verify_server(
        &[pki.root.der()],
        pki.device().der(),
        &[pki.issuing.der()],
        "palisade.example.org",
        now(),
    )
    .unwrap_err();
    assert!(
        matches!(
            cert_error(e),
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
        ),
        "device certificate accepted as a server certificate"
    );
    // And a server certificate cannot authenticate a device.
    let e = verify_client(
        &[pki.root.der()],
        pki.server().der(),
        &[pki.issuing.der()],
        &[],
        now(),
    )
    .unwrap_err();
    assert!(matches!(
        cert_error(e),
        CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. }
    ));
}

#[test]
fn validity_is_enforced_by_the_verifier() {
    let pki = Pki::new();
    let device = pki.device();
    let (root, issuing) = (pki.root.der(), pki.issuing.der());
    let nb = device.validity().not_before();
    let na = device.validity().not_after();
    verify_client(&[root], device.der(), &[issuing], &[], nb).unwrap();
    verify_client(&[root], device.der(), &[issuing], &[], na).unwrap();
    assert!(matches!(
        cert_error(
            verify_client(&[root], device.der(), &[issuing], &[], plus(na, SECOND)).unwrap_err()
        ),
        CertificateError::Expired | CertificateError::ExpiredContext { .. }
    ));
    assert!(matches!(
        cert_error(
            verify_client(&[root], device.der(), &[issuing], &[], plus(nb, -SECOND)).unwrap_err()
        ),
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
    ));
}

#[test]
fn times_are_rounded_down_to_whole_seconds() {
    let pki = Pki::new();
    let v = Validity::new(plus(now(), 1_500_000), plus(now(), DAY + 999_999)).unwrap();
    let cert = LeafCertificate::server(&pki.signer, &pki.issuing, &pki.server_key, &dns(&["a"]), v)
        .unwrap();
    assert_eq!(cert.validity().not_before(), plus(now(), SECOND));
    assert_eq!(cert.validity().not_after(), plus(now(), DAY));
    let s = summary(cert.der());
    assert_eq!(s.not_before, now().unix_micros() / SECOND + 1);
    // Before 1970 rounds towards the past as well.
    let (_, early) = x509_time(Timestamp::from_unix_micros(-1).unwrap()).unwrap();
    assert_eq!(early.unix_micros(), -SECOND);
}

#[test]
fn serials_are_fresh_and_sixteen_bytes() {
    let pki = Pki::new();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let c = pki.device();
        assert_eq!(c.serial().len(), 16);
        assert_eq!(c.serial()[0] & 0xc0, 0x40, "positive, no leading zero");
        assert!(seen.insert(c.serial().to_vec()));
    }
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[test]
fn a_child_never_outlives_its_issuer() {
    let pki = Pki::new();
    let late = Validity::new(now(), pki.issuing.validity().not_after()).unwrap();
    LeafCertificate::server(
        &pki.signer,
        &pki.issuing,
        &pki.server_key,
        &dns(&["a"]),
        late,
    )
    .unwrap();
    let too_late = Validity::new(now(), plus(pki.issuing.validity().not_after(), SECOND)).unwrap();
    assert_eq!(
        LeafCertificate::server(
            &pki.signer,
            &pki.issuing,
            &pki.server_key,
            &dns(&["a"]),
            too_late
        ),
        Err(IssueError::OutlivesIssuer)
    );
    let too_early =
        Validity::new(plus(pki.issuing.validity().not_before(), -SECOND), now()).unwrap();
    assert_eq!(
        LeafCertificate::server(
            &pki.signer,
            &pki.issuing,
            &pki.server_key,
            &dns(&["a"]),
            too_early
        ),
        Err(IssueError::OutlivesIssuer)
    );
    let key = leaf_key(&mut Pki::new().signer);
    assert_eq!(
        CaCertificate::issuing_ca(&pki.signer, &pki.root, &key, "x", window(0, 4000)),
        Err(IssueError::OutlivesIssuer)
    );
}

#[test]
fn device_lifetime_is_capped() {
    let pki = Pki::new();
    let issue = |v| {
        LeafCertificate::device(
            &pki.signer,
            &pki.issuing,
            &pki.device_key,
            device_id(),
            tenant_id(),
            v,
        )
    };
    issue(window(0, MAX_DEVICE_LIFETIME_DAYS)).unwrap();
    assert_eq!(
        issue(Validity::new(now(), plus(now(), MAX_DEVICE_LIFETIME_DAYS * DAY + 1)).unwrap()),
        Err(IssueError::LifetimeTooLong)
    );
}

#[test]
fn only_the_right_ca_signs_each_kind() {
    let pki = Pki::new();
    // Leaves come from the issuing CA, never straight from the root.
    assert_eq!(
        LeafCertificate::device(
            &pki.signer,
            &pki.root,
            &pki.device_key,
            device_id(),
            tenant_id(),
            window(0, 1)
        ),
        Err(IssueError::WrongIssuer {
            expected: KeyPurpose::IssuingCa,
            actual: KeyPurpose::RootCa
        })
    );
    // An issuing CA cannot create another issuing CA.
    assert_eq!(
        CaCertificate::issuing_ca(
            &pki.signer,
            &pki.issuing,
            &pki.device_key,
            "x",
            window(0, 1)
        ),
        Err(IssueError::WrongIssuer {
            expected: KeyPurpose::RootCa,
            actual: KeyPurpose::IssuingCa
        })
    );
    // A root must be made from a root-ca key.
    let issuing_kid = pki.issuing.kid();
    assert_eq!(
        CaCertificate::self_signed_root(&pki.signer, &issuing_kid, "x", window(0, 1)),
        Err(IssueError::WrongPurpose {
            expected: KeyPurpose::RootCa,
            actual: Some(KeyPurpose::IssuingCa)
        })
    );
    // A signer that does not hold the CA key cannot issue.
    let other = SoftwareSigner::new();
    assert_eq!(
        LeafCertificate::server(
            &other,
            &pki.issuing,
            &pki.server_key,
            &dns(&["a"]),
            window(0, 1)
        ),
        Err(IssueError::WrongPurpose {
            expected: KeyPurpose::IssuingCa,
            actual: None
        })
    );
    assert_eq!(
        revocation_list(&other, &pki.root, 1, now(), plus(now(), DAY), &[]),
        Err(IssueError::WrongPurpose {
            expected: KeyPurpose::RootCa,
            actual: None
        })
    );
    // A CA's own key is never certified as its child.
    let issuing_key = pki.issuing.public_key().clone();
    assert_eq!(
        LeafCertificate::server(
            &pki.signer,
            &pki.issuing,
            &issuing_key,
            &dns(&["a"]),
            window(0, 1)
        ),
        Err(IssueError::SameKey)
    );
    let root_key = pki.root.public_key().clone();
    assert_eq!(
        CaCertificate::issuing_ca(&pki.signer, &pki.root, &root_key, "x", window(0, 1)),
        Err(IssueError::SameKey)
    );
}

#[test]
fn bad_names_and_keys_are_refused() {
    let mut pki = Pki::new();
    let root_kid = pki.root.kid();
    for bad in ["", "   ", "tab\there", &"x".repeat(MAX_NAME_LEN + 1)] {
        assert_eq!(
            CaCertificate::self_signed_root(&pki.signer, &root_kid, bad, window(0, 1)),
            Err(IssueError::BadName),
            "{bad:?}"
        );
    }
    CaCertificate::self_signed_root(
        &pki.signer,
        &root_kid,
        &"é".repeat(MAX_NAME_LEN),
        window(0, 1),
    )
    .unwrap();
    assert_eq!(
        LeafCertificate::server(
            &pki.signer,
            &pki.issuing,
            &pki.server_key,
            &[],
            window(0, 1)
        ),
        Err(IssueError::NoNames)
    );
    let many: Vec<DnsName> = (0..=MAX_DNS_NAMES)
        .map(|i| format!("h{i}").parse().unwrap())
        .collect();
    assert_eq!(
        LeafCertificate::server(
            &pki.signer,
            &pki.issuing,
            &pki.server_key,
            &many,
            window(0, 1)
        ),
        Err(IssueError::TooManyNames)
    );
    LeafCertificate::server(
        &pki.signer,
        &pki.issuing,
        &pki.server_key,
        &many[..MAX_DNS_NAMES],
        window(0, 1),
    )
    .unwrap();
    assert_eq!(
        LeafCertificate::relay(
            &pki.signer,
            &pki.issuing,
            &pki.relay_key,
            device_id(),
            tenant_id(),
            &[],
            window(0, 1)
        ),
        Err(IssueError::NoNames)
    );
    // Certificates are P-384 only.
    let ed_kid = pki
        .signer
        .generate(KeyPurpose::PolicySigning, SignatureAlgorithm::Ed25519)
        .unwrap();
    let ed = pki.signer.public_key(&ed_kid).unwrap();
    assert_eq!(
        LeafCertificate::server(&pki.signer, &pki.issuing, &ed, &dns(&["a"]), window(0, 1)),
        Err(IssueError::UnsupportedSubjectKey)
    );
    assert_eq!(
        CaCertificate::issuing_ca(&pki.signer, &pki.root, &ed, "x", window(0, 1)),
        Err(IssueError::UnsupportedSubjectKey)
    );
}

#[test]
fn signer_refuses_x509_for_other_purposes_and_non_der() {
    let pki = Pki::new();
    let policy = {
        let mut s = SoftwareSigner::new();
        let kid = s
            .generate(
                KeyPurpose::PolicySigning,
                SignatureAlgorithm::EcdsaP384Sha384,
            )
            .unwrap();
        (s, kid)
    };
    assert_eq!(
        policy.0.sign_x509(&policy.1, &[0x30, 0x00]),
        Err(SignerError::NotACertificateKey(KeyPurpose::PolicySigning))
    );
    // A domain message never passes for X.509, so a CA key cannot be made
    // to sign one through this path (T-signer-02).
    for domain in crate::pki::Domain::ALL {
        assert_eq!(
            pki.signer.sign_x509(&pki.root.kid(), domain.prefix()),
            Err(SignerError::NotX509)
        );
    }
    assert_eq!(
        pki.signer.sign_x509(&pki.root.kid(), &[]),
        Err(SignerError::NotX509)
    );
    let unknown = Kid::from_bytes([7; 16]);
    assert_eq!(
        pki.signer.sign_x509(&unknown, &[0x30, 0x00]),
        Err(SignerError::UnknownKey(unknown))
    );
    // And the signature is a DER ECDSA-Sig-Value that verifies.
    let sig = pki
        .signer
        .sign_x509(&pki.root.kid(), &[0x30, 0x00])
        .unwrap();
    assert!(crypto::verify_p384_der(
        pki.root.public_key().raw(),
        &[0x30, 0x00],
        &sig
    ));
    assert!(!crypto::verify_p384_der(
        pki.root.public_key().raw(),
        &[0x30, 0x01],
        &sig
    ));
    assert!(
        IssueError::Signer(SignerError::NotX509)
            .to_string()
            .contains("not a DER X.509")
    );
}

#[test]
fn signer_failure_is_reported_not_hidden() {
    /// A signer that holds keys but fails every X.509 signature.
    struct Broken(SoftwareSigner);
    impl Signer for Broken {
        fn public_key(&self, kid: &Kid) -> Option<PublicKey> {
            self.0.public_key(kid)
        }
        fn purpose(&self, kid: &Kid) -> Option<KeyPurpose> {
            self.0.purpose(kid)
        }
        fn sign(
            &self,
            kid: &Kid,
            domain: crate::pki::Domain,
            payload: &[u8],
        ) -> Result<crate::pki::Signature, SignerError> {
            self.0.sign(kid, domain, payload)
        }
        fn sign_x509(&self, _: &Kid, _: &[u8]) -> Result<Vec<u8>, SignerError> {
            Err(SignerError::Failed("hsm offline"))
        }
    }
    let mut s = SoftwareSigner::new();
    let kid = s
        .generate(KeyPurpose::RootCa, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let broken = Broken(s);
    assert_eq!(
        CaCertificate::self_signed_root(&broken, &kid, "r", window(0, 1)),
        Err(IssueError::Signer(SignerError::Failed("hsm offline")))
    );
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn revoked_intermediate_is_refused() {
    let pki = Pki::new();
    let device = pki.device();
    let (root, issuing) = (pki.root.der(), pki.issuing.der());
    // An empty root list and an empty issuing-CA list: everything verifies.
    let root_crl =
        revocation_list(&pki.signer, &pki.root, 1, now(), plus(now(), 7 * DAY), &[]).unwrap();
    let issuing_crl =
        revocation_list(&pki.signer, &pki.issuing, 1, now(), plus(now(), DAY), &[]).unwrap();
    let crls = [root_crl, issuing_crl.clone()];
    verify_client(
        &[root],
        device.der(),
        &[issuing],
        &crls,
        plus(now(), SECOND),
    )
    .unwrap();

    // The root revokes the issuing CA: every leaf under it is refused.
    let revoked_ca = revocation_list(
        &pki.signer,
        &pki.root,
        2,
        now(),
        plus(now(), 7 * DAY),
        &[Revoked {
            serial: pki.issuing.serial().to_vec(),
            revoked_at: now(),
            reason: Some(RevocationReason::CaCompromise),
        }],
    )
    .unwrap();
    let crls = [revoked_ca, issuing_crl];
    for leaf in [device.der(), pki.relay().der()] {
        assert_eq!(
            cert_error(
                verify_client(&[root], leaf, &[issuing], &crls, plus(now(), SECOND)).unwrap_err()
            ),
            CertificateError::Revoked
        );
    }
}

#[test]
fn revoked_leaf_is_refused_and_others_pass() {
    let pki = Pki::new();
    let revoked = pki.device();
    let other = pki.device();
    let root_crl =
        revocation_list(&pki.signer, &pki.root, 1, now(), plus(now(), DAY), &[]).unwrap();
    let issuing_crl = revocation_list(
        &pki.signer,
        &pki.issuing,
        7,
        now(),
        plus(now(), DAY),
        &[
            Revoked {
                serial: revoked.serial().to_vec(),
                revoked_at: now(),
                reason: Some(RevocationReason::KeyCompromise),
            },
            Revoked {
                serial: vec![1],
                revoked_at: now(),
                reason: Some(RevocationReason::Superseded),
            },
            Revoked {
                serial: vec![2],
                revoked_at: now(),
                reason: Some(RevocationReason::CessationOfOperation),
            },
            Revoked {
                serial: vec![3],
                revoked_at: now(),
                reason: Some(RevocationReason::CaCompromise),
            },
            Revoked {
                serial: vec![4],
                revoked_at: now(),
                reason: None,
            },
        ],
    )
    .unwrap();
    let crls = [root_crl, issuing_crl];
    let (root, issuing) = (pki.root.der(), pki.issuing.der());
    assert_eq!(
        cert_error(
            verify_client(
                &[root],
                revoked.der(),
                &[issuing],
                &crls,
                plus(now(), SECOND)
            )
            .unwrap_err()
        ),
        CertificateError::Revoked
    );
    verify_client(&[root], other.der(), &[issuing], &crls, plus(now(), SECOND)).unwrap();
}

#[test]
fn revocation_list_is_signed_by_its_issuer() {
    let pki = Pki::new();
    // A list for the same issuer name but signed by another key is
    // refused, so the device fails verification (fail closed).
    let foreign = Pki::new();
    let forged = revocation_list(
        &foreign.signer,
        &foreign.issuing,
        1,
        now(),
        plus(now(), DAY),
        &[],
    )
    .unwrap();
    let root_crl =
        revocation_list(&pki.signer, &pki.root, 1, now(), plus(now(), DAY), &[]).unwrap();
    let e = verify_client(
        &[pki.root.der()],
        pki.device().der(),
        &[pki.issuing.der()],
        &[root_crl, forged],
        plus(now(), SECOND),
    )
    .unwrap_err();
    assert!(matches!(e, TlsError::InvalidCertRevocationList(_)), "{e:?}");
    // With no list at all for the issuing CA, the status is unknown, which
    // also fails closed.
    let root_crl =
        revocation_list(&pki.signer, &pki.root, 1, now(), plus(now(), DAY), &[]).unwrap();
    let e = verify_client(
        &[pki.root.der()],
        pki.device().der(),
        &[pki.issuing.der()],
        &[root_crl],
        plus(now(), SECOND),
    )
    .unwrap_err();
    assert_eq!(cert_error(e), CertificateError::UnknownRevocationStatus);
}

#[test]
fn expired_revocation_list_fails_closed() {
    let pki = Pki::new();
    let root_crl =
        revocation_list(&pki.signer, &pki.root, 1, now(), plus(now(), DAY), &[]).unwrap();
    let issuing_crl =
        revocation_list(&pki.signer, &pki.issuing, 1, now(), plus(now(), DAY), &[]).unwrap();
    let e = verify_client(
        &[pki.root.der()],
        pki.device().der(),
        &[pki.issuing.der()],
        &[root_crl, issuing_crl],
        plus(now(), 2 * DAY),
    )
    .unwrap_err();
    assert!(matches!(
        cert_error(e),
        CertificateError::ExpiredRevocationList
            | CertificateError::ExpiredRevocationListContext { .. }
    ));
}

#[test]
fn revocation_list_inputs_are_checked() {
    let pki = Pki::new();
    let list = |this, next, revoked: &[Revoked]| {
        revocation_list(&pki.signer, &pki.issuing, 1, this, next, revoked)
    };
    assert_eq!(list(now(), now(), &[]), Err(IssueError::BadCrlWindow));
    // Sub-second differences vanish when rounded.
    assert_eq!(
        list(now(), plus(now(), SECOND - 1), &[]),
        Err(IssueError::BadCrlWindow)
    );
    assert_eq!(
        list(
            plus(pki.issuing.validity().not_before(), -SECOND),
            now(),
            &[]
        ),
        Err(IssueError::BadCrlWindow)
    );
    assert_eq!(
        list(now(), plus(pki.issuing.validity().not_after(), SECOND), &[]),
        Err(IssueError::BadCrlWindow)
    );
    for serial in [vec![], vec![1; 21]] {
        assert_eq!(
            list(
                now(),
                plus(now(), DAY),
                &[Revoked {
                    serial,
                    revoked_at: now(),
                    reason: None
                }]
            ),
            Err(IssueError::BadSerial)
        );
    }
    list(
        now(),
        plus(now(), DAY),
        &[Revoked {
            serial: vec![0xff; 20],
            revoked_at: now(),
            reason: None,
        }],
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Root rotation
// ---------------------------------------------------------------------------

#[test]
fn cross_signed_root_bridges_old_and_new_hierarchies() {
    let mut old = Pki::new();
    let old_device = old.device();
    let mut signer = std::mem::take(&mut old.signer);
    let new_root_kid = signer
        .generate(KeyPurpose::RootCa, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let new_root = CaCertificate::self_signed_root(
        &signer,
        &new_root_kid,
        "Palisade Test Root 2",
        window(-1, 7300),
    )
    .unwrap();
    let new_issuing_kid = signer
        .generate(KeyPurpose::IssuingCa, SignatureAlgorithm::EcdsaP384Sha384)
        .unwrap();
    let new_issuing_key = signer.public_key(&new_issuing_kid).unwrap();
    let new_issuing = CaCertificate::issuing_ca(
        &signer,
        &new_root,
        &new_issuing_key,
        "Palisade Test Issuing CA 2",
        window(-1, 1000),
    )
    .unwrap();
    let device = LeafCertificate::device(
        &signer,
        &new_issuing,
        &old.device_key,
        device_id(),
        tenant_id(),
        window(0, 30),
    )
    .unwrap();
    let cross =
        CaCertificate::cross_signed(&signer, &old.root, &new_root, window(-1, 3000)).unwrap();
    assert_eq!(cross.purpose(), KeyPurpose::RootCa);
    assert_eq!(cross.kid(), new_root.kid());
    assert_eq!(cross.name(), new_root.name());
    let c = summary(cross.der());
    assert_eq!(c.subject.der, summary(new_root.der()).subject.der);
    assert_eq!(c.issuer.der, summary(old.root.der()).subject.der);
    assert_eq!(c.subject_key_id, summary(new_root.der()).subject_key_id);
    assert_eq!(c.basic_constraints.unwrap().path_len, Some(1));

    let at = plus(now(), SECOND);
    // An agent that pins only the new root.
    verify_client(
        &[new_root.der()],
        device.der(),
        &[new_issuing.der()],
        &[],
        at,
    )
    .unwrap();
    // An agent that still pins only the old root needs the cross-certificate.
    assert_eq!(
        cert_error(
            verify_client(
                &[old.root.der()],
                device.der(),
                &[new_issuing.der()],
                &[],
                at
            )
            .unwrap_err()
        ),
        CertificateError::UnknownIssuer
    );
    verify_client(
        &[old.root.der()],
        device.der(),
        &[new_issuing.der(), cross.der()],
        &[],
        at,
    )
    .unwrap();
    // The old hierarchy still verifies against the old root during overlap.
    verify_client(
        &[old.root.der()],
        old_device.der(),
        &[old.issuing.der()],
        &[],
        at,
    )
    .unwrap();

    // Cross-signing needs two different roots.
    assert_eq!(
        CaCertificate::cross_signed(&signer, &old.root, &old.root, window(0, 1)),
        Err(IssueError::SameKey)
    );
    assert_eq!(
        CaCertificate::cross_signed(&signer, &old.issuing, &new_root, window(0, 1)),
        Err(IssueError::WrongIssuer {
            expected: KeyPurpose::RootCa,
            actual: KeyPurpose::IssuingCa
        })
    );
    assert_eq!(
        CaCertificate::cross_signed(&signer, &old.root, &new_issuing, window(0, 1)),
        Err(IssueError::WrongIssuer {
            expected: KeyPurpose::RootCa,
            actual: KeyPurpose::IssuingCa
        })
    );
}

// ---------------------------------------------------------------------------
// Encodings and messages
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_signatures_are_minimal_der() {
    // r with its high bit set gains a zero; s with leading zeros loses them.
    let mut fixed = [0u8; 96];
    fixed[0] = 0x80;
    fixed[47] = 1;
    fixed[94] = 0x01;
    fixed[95] = 0x02;
    let der = crypto::ecdsa_fixed_to_der(&fixed);
    assert_eq!(&der[..4], &[0x30, 49 + 2 + 4, 0x02, 49]);
    assert_eq!(der[4], 0x00);
    assert_eq!(der[5], 0x80);
    assert_eq!(&der[der.len() - 4..], &[0x02, 2, 0x01, 0x02]);
    // An all-zero half is the INTEGER 0.
    let zero = crypto::ecdsa_fixed_to_der(&[0u8; 96]);
    assert_eq!(zero, [0x30, 6, 0x02, 1, 0x00, 0x02, 1, 0x00]);
}

#[test]
fn errors_and_debug_name_no_key_material() {
    let pki = Pki::new();
    let debug = format!("{:?} {:?}", pki.root, pki.device());
    assert!(debug.contains("root-ca"), "{debug}");
    assert!(debug.contains("Device"), "{debug}");
    for e in [
        IssueError::WrongPurpose {
            expected: KeyPurpose::RootCa,
            actual: None,
        },
        IssueError::WrongPurpose {
            expected: KeyPurpose::RootCa,
            actual: Some(KeyPurpose::IssuingCa),
        },
        IssueError::WrongIssuer {
            expected: KeyPurpose::RootCa,
            actual: KeyPurpose::IssuingCa,
        },
        IssueError::SameKey,
        IssueError::UnsupportedSubjectKey,
        IssueError::BadName,
        IssueError::NoNames,
        IssueError::TooManyNames,
        IssueError::OutlivesIssuer,
        IssueError::LifetimeTooLong,
        IssueError::BadCrlWindow,
        IssueError::BadSerial,
        IssueError::TimeOutOfRange,
        IssueError::Signer(SignerError::NotACertificateKey(KeyPurpose::Escrow)),
        IssueError::Encoding,
    ] {
        assert!(!e.to_string().is_empty());
    }
    assert!(
        SignerError::NotACertificateKey(KeyPurpose::Escrow)
            .to_string()
            .contains("escrow")
    );
}
