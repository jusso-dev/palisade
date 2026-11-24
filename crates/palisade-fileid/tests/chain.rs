//! Certificate parsing, chain building, signer trust and identity tests
//! (#49).
//!
//! The certificates in `fixtures/chain` were made by `generate.sh` there,
//! with throwaway test CAs. `expected.txt` holds reference values for each
//! one (thumbprints, TBS hashes, serial), computed by Python's hashlib from
//! the DER, independently of this crate.

// Test code: helpers may unwrap or index, since a failure should fail
// loudly.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::HashMap;

use common::*;
use palisade_fileid::authenticode::{
    AnchorSource, AttributeKind, CertOrigin, CertSummary, CertificateError, ChainIssue, ChainPath,
    Curve, DigestAlgorithm, IdentityIssue, KeyAlgorithm, MAX_CHAIN_LENGTH,
    MAX_EMBEDDED_CERTIFICATES, NameSource, ObjectId, OsRuleRoot, SignatureAlgorithm,
    SignatureReport, TrustConfig, UntrustedReason, VerifyOptions, build_chain, eku, evaluate_trust,
    verify_pe,
};
use palisade_fileid::pe;
use palisade_fileid::pe::version::{FileVersionQuad, VersionField};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain");

fn der(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}.der")).unwrap()
}

fn cert(name: &str) -> CertSummary {
    CertSummary::from_der(&der(name)).unwrap()
}

/// `name -> [sha1, sha256, tbs under own digest, tbs sha256, serial]`.
fn expected() -> HashMap<String, Vec<String>> {
    std::fs::read_to_string(format!("{FIXTURES}/expected.txt"))
        .unwrap()
        .lines()
        .map(|line| {
            let mut parts = line.split(' ').map(str::to_owned);
            let name = parts.next().unwrap();
            (name, parts.collect())
        })
        .collect()
}

fn config(anchors: &[&str]) -> TrustConfig {
    let mut config = TrustConfig::new();
    for a in anchors {
        config.add_anchor(*a, &der(a)).unwrap();
    }
    config
}

fn chain_of(names: &[&str]) -> Vec<Vec<u8>> {
    names.iter().map(|n| der(n)).collect()
}

fn subjects(report: &palisade_fileid::authenticode::ChainReport, path: &ChainPath) -> Vec<String> {
    path.certs
        .iter()
        .map(|i| {
            report.certificates[*i]
                .cert
                .subject
                .common_name()
                .unwrap_or("")
                .to_owned()
        })
        .collect()
}

// --- Certificate attributes. -----------------------------------------------

#[test]
fn thumbprints_tbs_hashes_and_serials_match_independent_values() {
    let expected = expected();
    assert!(expected.len() >= 40, "{}", expected.len());
    for (name, values) in &expected {
        let c = cert(name);
        assert_eq!(c.sha1_thumbprint, values[0], "{name}");
        assert_eq!(c.sha256_thumbprint, values[1], "{name}");
        assert_eq!(c.tbs_hash.as_deref(), Some(values[2].as_str()), "{name}");
        assert_eq!(c.tbs_hash_sha256, values[3], "{name}");
        assert_eq!(c.serial, values[4], "{name}");
    }
}

#[test]
fn tbs_hash_uses_the_certificates_own_digest() {
    for (name, alg, len) in [
        ("leaf-sha1", DigestAlgorithm::Sha1, 40),
        ("leaf", DigestAlgorithm::Sha256, 64),
        ("leaf-sha384", DigestAlgorithm::Sha384, 96),
        ("leaf-sha512", DigestAlgorithm::Sha512, 128),
        ("ecc-leaf", DigestAlgorithm::Sha384, 96),
    ] {
        let c = cert(name);
        assert_eq!(c.tbs_hash_alg, Some(alg), "{name}");
        assert_eq!(c.tbs_hash.unwrap().len(), len, "{name}");
        assert_eq!(c.tbs_hash_sha256.len(), 64, "{name}");
    }
}

#[test]
fn rich_leaf_attributes() {
    let c = cert("leaf");
    assert_eq!(c.version, 3);
    assert_eq!(
        c.sig_alg,
        SignatureAlgorithm::RsaPkcs1(DigestAlgorithm::Sha256)
    );
    assert_eq!(
        (c.public_key_alg.clone(), c.key_bits),
        (KeyAlgorithm::Rsa, Some(2048))
    );
    assert!(c.not_before < c.not_after);
    assert!(!c.is_self_signed);

    // Subject: ordered RDNs, typed components, canonical rendering.
    let s = &c.subject;
    let order: Vec<Option<AttributeKind>> = s.attributes().map(|a| a.kind).collect();
    assert_eq!(
        order,
        [
            AttributeKind::Country,
            AttributeKind::State,
            AttributeKind::Locality,
            AttributeKind::Organization,
            AttributeKind::OrganizationalUnit,
            AttributeKind::CommonName,
            AttributeKind::Email,
            AttributeKind::SerialNumber,
            AttributeKind::BusinessCategory,
            AttributeKind::JurisdictionCountry,
        ]
        .map(Some)
    );
    assert_eq!(s.common_name(), Some("Palisade Test Publisher"));
    assert_eq!(s.organization(), Some("Palisade Tests, Pty"));
    let value = |k| s.first(k).unwrap().value.as_str();
    assert_eq!(value(AttributeKind::Locality), "Melbourne");
    assert_eq!(value(AttributeKind::State), "Victoria");
    assert_eq!(value(AttributeKind::Country), "AU");
    assert_eq!(value(AttributeKind::Email), "signing@example.test");
    assert_eq!(value(AttributeKind::SerialNumber), "12345");
    assert_eq!(
        value(AttributeKind::BusinessCategory),
        "Private Organization"
    );
    assert_eq!(value(AttributeKind::JurisdictionCountry), "AU");
    assert_eq!(
        s.canonical,
        "OID.1.3.6.1.4.1.311.60.2.1.3=AU, OID.2.5.4.15=Private Organization, \
         SERIALNUMBER=12345, E=signing@example.test, CN=Palisade Test Publisher, OU=Signing, \
         O=\"Palisade Tests, Pty\", L=Melbourne, S=Victoria, C=AU"
    );
    assert_eq!(s.to_string(), s.canonical);
    // The raw DER is kept, and is what the issuer field of a child matches.
    assert_eq!(cert("leaf").issuer.der, cert("inter").subject.der);
    assert_eq!(c.issuer.canonical, "CN=Palisade Chain CA, O=Palisade Tests");

    // Extensions.
    let bc = c.basic_constraints.unwrap();
    assert!(!bc.ca);
    assert_eq!(
        c.key_usage.unwrap().names().collect::<Vec<_>>(),
        ["digital_signature", "non_repudiation"]
    );
    let ekus: Vec<(String, Option<&str>)> = c
        .extended_key_usage
        .as_ref()
        .unwrap()
        .iter()
        .map(|e| (e.oid.to_string(), e.name))
        .collect();
    assert_eq!(
        ekus,
        [
            ("1.3.6.1.5.5.7.3.3".to_owned(), Some("Code Signing")),
            (
                "1.3.6.1.4.1.311.10.3.13".to_owned(),
                Some("Lifetime Signing")
            ),
            (
                "1.3.6.1.4.1.311.61.1.1".to_owned(),
                Some("Kernel Mode Code Signing")
            ),
            ("1.2.3.4.5.6".to_owned(), None),
        ]
    );
    assert!(c.has_eku(&eku::LIFETIME_SIGNING.id()));
    assert!(!c.has_eku(&eku::TIME_STAMPING.id()));
    assert_eq!(
        c.certificate_policies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["1.2.3.4", "2.23.140.1.3"]
    );
    assert_eq!(
        c.crl_distribution_points,
        ["http://crl.example.test/ca.crl"]
    );
    assert_eq!(c.ocsp_urls, ["http://ocsp.example.test"]);
    assert_eq!(c.ca_issuers_urls, ["http://ca.example.test/ca.crt"]);
    let inter = cert("inter");
    assert_eq!(c.authority_key_id, inter.subject_key_id);
    assert_eq!(c.subject_key_id.as_ref().unwrap().len(), 40);
    assert!(c.unhandled_critical_extensions.is_empty());
}

#[test]
fn ca_attributes_and_self_signed_roots() {
    let inter = cert("inter");
    let bc = inter.basic_constraints.unwrap();
    assert!(bc.ca);
    assert_eq!(bc.path_len, Some(0));
    assert_eq!(
        inter.key_usage.unwrap().names().collect::<Vec<_>>(),
        ["key_cert_sign", "crl_sign"]
    );
    assert_eq!(inter.extended_key_usage, None);
    assert!(cert("root").is_self_signed);
    assert!(cert("leaf-self-signed").is_self_signed);
    assert!(cert("ecc-root").is_self_signed);
    // Self-issued but not self-signed: same name, another key's signature.
    assert!(!cert("cross-root").is_self_signed);
    assert_eq!(cert("cross-root").subject.der, cert("root").subject.der);
}

#[test]
fn ecc_and_other_key_types() {
    let leaf = cert("ecc-leaf");
    assert_eq!(leaf.public_key_alg, KeyAlgorithm::Ec(Curve::P256));
    assert_eq!(leaf.key_bits, Some(256));
    assert_eq!(
        leaf.sig_alg,
        SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha384)
    );
    let root = cert("ecc-root");
    assert_eq!(root.public_key_alg, KeyAlgorithm::Ec(Curve::P384));
    // The #48 Ed25519 fixture.
    let ed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode/ed25519-leaf.der"
    ))
    .unwrap();
    let ed = CertSummary::from_der(&ed).unwrap();
    assert_eq!(ed.public_key_alg, KeyAlgorithm::Ed25519);
}

#[test]
fn utf8_names_and_organization_only_subjects() {
    let c = cert("leaf-o-only");
    assert_eq!(c.subject.common_name(), None);
    assert_eq!(c.subject.organization(), Some("Palisade Tésts"));
    assert_eq!(c.subject.canonical, "O=Palisade Tésts, C=AU");
}

#[test]
fn pem_export_matches_openssl() {
    let pem = std::fs::read_to_string(format!("{FIXTURES}/leaf.pem.txt")).unwrap();
    assert_eq!(cert("leaf").pem(), pem);
}

#[test]
fn json_export_has_stable_field_names() {
    let c = cert("leaf");
    let json: serde_json::Value = serde_json::to_value(&c).unwrap();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut want = vec![
        "version",
        "serial",
        "subject",
        "issuer",
        "not_before",
        "not_after",
        "sig_alg",
        "public_key_alg",
        "key_bits",
        "sha1_thumbprint",
        "sha256_thumbprint",
        "spki_sha256",
        "tbs_hash",
        "tbs_hash_alg",
        "tbs_hash_sha256",
        "subject_key_id",
        "authority_key_id",
        "basic_constraints",
        "key_usage",
        "extended_key_usage",
        "certificate_policies",
        "crl_distribution_points",
        "ocsp_urls",
        "ca_issuers_urls",
        "is_self_signed",
        "unhandled_critical_extensions",
        "der",
    ];
    let mut got = keys.clone();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want);
    assert_eq!(json["sig_alg"], serde_json::json!({"rsa_pkcs1": "sha256"}));
    assert_eq!(json["public_key_alg"], "rsa");
    assert_eq!(json["tbs_hash_alg"], "sha256");
    assert_eq!(json["subject"]["canonical"], c.subject.canonical);
    assert_eq!(
        json["key_usage"],
        serde_json::json!(["digital_signature", "non_repudiation"])
    );
    assert_eq!(
        json["extended_key_usage"][0],
        serde_json::json!({
            "oid": "1.3.6.1.5.5.7.3.3",
            "name": "Code Signing",
            "os_policy_value": "01082B06010505070303",
        })
    );
    assert_eq!(json["certificate_policies"][1], "2.23.140.1.3");
    assert_eq!(json["subject"]["rdns"][0][0]["kind"], "country");
    let pem_body: String = c
        .pem()
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    assert_eq!(json["der"], pem_body);
}

// --- Malformed certificates. -----------------------------------------------

/// Header length and content length of the element at `at`.
fn header(der: &[u8], at: usize) -> (usize, usize) {
    let first = der[at + 1];
    if first < 0x80 {
        (2, first as usize)
    } else {
        let n = (first & 0x7f) as usize;
        let len = der[at + 2..at + 2 + n]
            .iter()
            .fold(0_usize, |a, b| (a << 8) | *b as usize);
        (2 + n, len)
    }
}

/// The offset of the first occurrence of `needle`.
fn find(der: &[u8], needle: &[u8]) -> usize {
    der.windows(needle.len()).position(|w| w == needle).unwrap()
}

#[test]
fn malformed_certificates_are_rejected() {
    let good = der("leaf");
    // Trailing data after the certificate.
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        CertSummary::from_der(&trailing),
        Err(CertificateError::Asn1(_))
    ));
    // Truncated.
    assert!(
        CertificateError::Asn1(palisade_fileid::authenticode::Asn1Error {
            kind: palisade_fileid::authenticode::Asn1ErrorKind::Truncated,
            offset: 0
        }) == CertSummary::from_der(&good[..good.len() - 1]).unwrap_err()
    );
    // The leaf's keyUsage extension is critical: OID 2.5.29.15, then the
    // `critical` BOOLEAN TRUE.
    let ku_critical = find(&good, &[0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff]) + 5;
    let invalid_at = |offset| {
        CertificateError::Asn1(palisade_fileid::authenticode::Asn1Error {
            kind: palisade_fileid::authenticode::Asn1ErrorKind::InvalidValue,
            offset,
        })
    };
    // A `critical` BOOLEAN that is not DER (0x01 instead of 0xff).
    let mut bad_bool = good.clone();
    bad_bool[ku_critical + 2] = 0x01;
    assert_eq!(
        CertSummary::from_der(&bad_bool).unwrap_err(),
        invalid_at(ku_critical)
    );
    // `critical` explicitly FALSE: DER omits a DEFAULT value.
    let mut explicit_false = good.clone();
    explicit_false[ku_critical + 2] = 0x00;
    assert_eq!(
        CertSummary::from_der(&explicit_false).unwrap_err(),
        invalid_at(ku_critical)
    );
    // basicConstraints `cA` explicitly FALSE. `inter` encodes
    // `SEQUENCE { cA TRUE, pathLen 0 }` inside the extension's OCTET STRING.
    let inter = der("inter");
    let bc = find(&inter, &[0x06, 0x03, 0x55, 0x1d, 0x13]);
    let ca =
        bc + find(
            &inter[bc..],
            &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
        ) + 2;
    let mut ca_false = inter.clone();
    ca_false[ca + 2] = 0x00;
    assert_eq!(
        CertSummary::from_der(&ca_false).unwrap_err(),
        invalid_at(ca)
    );
    // An unknown version (v4).
    let at = find(&good, &[0xa0, 0x03, 0x02, 0x01, 0x02]);
    let mut v4 = good.clone();
    v4[at + 4] = 0x03;
    assert_eq!(
        CertSummary::from_der(&v4).unwrap_err(),
        CertificateError::UnsupportedVersion(4)
    );
    // The outer and inner signature algorithms disagree.
    let sha256_rsa = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    ];
    let mut mismatch = good.clone();
    let last = mismatch
        .windows(sha256_rsa.len())
        .rposition(|w| w == sha256_rsa)
        .unwrap();
    mismatch[last + sha256_rsa.len() - 1] = 0x0c;
    assert_eq!(
        CertSummary::from_der(&mismatch).unwrap_err(),
        CertificateError::SignatureAlgorithmMismatch
    );
    // A duplicated extension: certificatePolicies (2.5.29.32) renamed to
    // extKeyUsage (2.5.29.37), which the leaf already has.
    let policies = find(&good, &[0x06, 0x03, 0x55, 0x1d, 0x20]);
    let mut dup = good.clone();
    dup[policies + 4] = 0x25;
    assert_eq!(
        CertSummary::from_der(&dup).unwrap_err(),
        CertificateError::DuplicateExtension(ObjectId::from_dotted("2.5.29.37").unwrap())
    );
    // Extensions in a v2 certificate.
    let version = find(&good, &[0xa0, 0x03, 0x02, 0x01, 0x02]);
    let mut v2_ext = good.clone();
    v2_ext[version + 4] = 0x01;
    assert_eq!(
        CertSummary::from_der(&v2_ext).unwrap_err(),
        CertificateError::FieldNotAllowed
    );
    // An explicit v1 version: DER omits the DEFAULT, so this is not DER.
    let mut explicit_v1 = good.clone();
    explicit_v1[version + 4] = 0x00;
    assert_eq!(
        CertSummary::from_der(&explicit_v1).unwrap_err(),
        invalid_at(version)
    );
}

#[test]
fn unknown_critical_extensions_are_recorded() {
    let c = cert("inter-name-constraints");
    assert_eq!(
        c.unhandled_critical_extensions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["2.5.29.30"]
    );
}

// --- Chain building. -------------------------------------------------------

#[test]
fn leaf_only() {
    let report = build_chain(&chain_of(&["leaf"]), 0, &TrustConfig::new()).unwrap();
    assert_eq!(report.as_provided.certs, [0]);
    assert_eq!((report.pca, report.root_as_provided), (None, None));
    assert!(report.intermediates.is_empty());
    assert!(!report.chain_complete);
    assert_eq!(report.anchor_source, AnchorSource::None);
    assert_eq!(report.anchored_to, None);
}

#[test]
fn leaf_and_intermediate() {
    let report = build_chain(&chain_of(&["leaf", "inter"]), 0, &TrustConfig::new()).unwrap();
    assert_eq!(
        subjects(&report, &report.as_provided),
        ["Palisade Test Publisher", "Palisade Chain CA"]
    );
    assert_eq!(report.intermediates, [1]);
    assert_eq!(report.pca, Some(1));
    assert_eq!(report.root_as_provided, None);
    assert!(!report.chain_complete);
    assert_eq!(report.pca_cert().unwrap().tbs_hash, cert("inter").tbs_hash);
}

#[test]
fn full_chain_in_any_order_anchored_by_policy() {
    // Blob order root, leaf, intermediate; the signer is index 1.
    let certs = chain_of(&["root", "leaf", "inter"]);
    let report = build_chain(&certs, 1, &config(&["root"])).unwrap();
    assert_eq!(report.leaf, 0);
    assert_eq!(report.certificates[0].origin, CertOrigin::Embedded(1));
    assert_eq!(
        subjects(&report, &report.as_provided),
        [
            "Palisade Test Publisher",
            "Palisade Chain CA",
            "Palisade Chain Root"
        ]
    );
    assert!(report.as_provided.complete && !report.as_provided.anchored);
    assert_eq!(
        report.pca_cert().unwrap().subject.common_name(),
        Some("Palisade Chain CA")
    );
    assert_eq!(
        report.root_cert().unwrap().subject.common_name(),
        Some("Palisade Chain Root")
    );
    assert_eq!(report.full_chain.certs, report.as_provided.certs);
    assert!(report.full_chain.anchored && report.chain_complete);
    assert_eq!(report.anchor_source, AnchorSource::Policy);
    let anchor = report.anchored_to.unwrap();
    assert_eq!((anchor.index, anchor.label.as_str()), (0, "root"));
    assert_eq!(anchor.sha256_thumbprint, cert("root").sha256_thumbprint);
    // The embedded root is recognised as the anchor.
    assert_eq!(
        report.certificates[report.full_chain.certs[2]].anchor,
        Some(0)
    );
    assert!(report.issues.is_empty(), "{:?}", report.issues);
}

#[test]
fn policy_anchors_and_intermediates_complete_a_short_chain() {
    let mut cfg = config(&["root"]);
    cfg.add_intermediate(&der("inter")).unwrap();
    let report = build_chain(&chain_of(&["leaf"]), 0, &cfg).unwrap();
    // Nothing is provided above the leaf...
    assert_eq!(report.as_provided.certs, [0]);
    assert_eq!(report.pca, None);
    // ...but the full chain uses policy certificates.
    assert_eq!(report.full_chain.certs.len(), 3);
    let origins: Vec<CertOrigin> = report
        .full_chain
        .certs
        .iter()
        .map(|i| report.certificates[*i].origin)
        .collect();
    assert_eq!(
        origins,
        [
            CertOrigin::Embedded(0),
            CertOrigin::PolicyIntermediate(0),
            CertOrigin::PolicyAnchor(0)
        ]
    );
    assert!(report.chain_complete);
    assert_eq!(report.anchor_source, AnchorSource::Policy);
}

#[test]
fn an_intermediate_can_be_the_anchor() {
    let report = build_chain(&chain_of(&["leaf", "inter"]), 0, &config(&["inter"])).unwrap();
    assert_eq!(report.full_chain.certs, [0, 1]);
    assert!(report.full_chain.anchored);
    assert_eq!(report.pca, Some(1));
}

#[test]
fn cross_signed_paths_are_all_recorded() {
    // The root is also cross-signed by a second root. Both are embedded.
    let certs = chain_of(&["leaf", "inter", "cross-root", "root", "root2"]);
    let report = build_chain(&certs, 0, &config(&["root2"])).unwrap();
    // As provided: two complete paths; the shorter (to the self-signed
    // root) is chosen, the cross-signed one is the alternative.
    assert_eq!(
        subjects(&report, &report.as_provided),
        [
            "Palisade Test Publisher",
            "Palisade Chain CA",
            "Palisade Chain Root"
        ]
    );
    assert_eq!(report.as_provided_alternatives.len(), 1);
    assert_eq!(
        subjects(&report, &report.as_provided_alternatives[0]),
        [
            "Palisade Test Publisher",
            "Palisade Chain CA",
            "Palisade Chain Root",
            "Palisade Second Root"
        ]
    );
    // Only root2 is trusted, so the longer path is the full chain. An
    // anchored full chain lists only anchored alternatives; the path to the
    // untrusted self-signed root is in `as_provided`.
    assert_eq!(report.full_chain.certs.len(), 4);
    assert!(report.full_chain.anchored);
    assert!(report.alternatives.iter().all(|p| p.anchored));
    assert!(report.as_provided.complete && !report.as_provided.anchored);
    // With both trusted, the shortest anchored path wins.
    let both = build_chain(&certs, 0, &config(&["root", "root2"])).unwrap();
    assert_eq!(both.full_chain.certs.len(), 3);
    assert_eq!(both.anchored_to.unwrap().label, "root");
}

#[test]
fn forged_issuer_name_with_the_wrong_key_is_not_a_link() {
    // The leaf names "Palisade Chain CA" as its issuer, but a different key
    // signed it. Neither has key identifiers, so only the signature check
    // can tell.
    let certs = chain_of(&["leaf-forged", "inter", "root"]);
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    assert_eq!(report.as_provided.certs, [0]);
    assert_eq!(report.full_chain.certs, [0]);
    assert!(!report.chain_complete);
    assert_eq!(report.anchor_source, AnchorSource::None);
    assert!(
        report.issues.contains(&ChainIssue::SignatureInvalid {
            child: 0,
            issuer: 1
        }),
        "{:?}",
        report.issues
    );
}

#[test]
fn key_identifier_mismatch_is_not_a_link() {
    // `inter-rekeyed` has the intermediate's name but another key, so its
    // subject key identifier differs from the leaf's authority key
    // identifier. It is rejected before any signature check; the real
    // intermediate links.
    let certs = chain_of(&["leaf", "inter-rekeyed", "inter"]);
    let report = build_chain(&certs, 0, &TrustConfig::new()).unwrap();
    assert_eq!(report.as_provided.certs, [0, 2]);
    assert!(report.as_provided_alternatives.is_empty());
    assert!(
        report.issues.contains(&ChainIssue::KeyIdMismatch {
            child: 0,
            issuer: 1
        }),
        "{:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| matches!(i, ChainIssue::SignatureInvalid { .. })),
        "{:?}",
        report.issues
    );
}

#[test]
fn issuers_must_be_cas_with_cert_sign_and_path_room() {
    // Not a CA.
    let r = build_chain(
        &chain_of(&["leaf-under-not-ca", "inter-not-ca", "root"]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert_eq!(r.full_chain.certs, [0]);
    assert!(
        r.issues.contains(&ChainIssue::IssuerNotCa { issuer: 1 }),
        "{:?}",
        r.issues
    );
    // pathlen 0 on `inter`, with a sub-CA below it.
    let r = build_chain(
        &chain_of(&["leaf-too-deep", "inter-sub", "inter", "root"]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert_eq!(r.full_chain.certs, [0, 1]);
    assert!(!r.chain_complete);
    assert!(
        r.issues
            .contains(&ChainIssue::PathLengthExceeded { issuer: 2 }),
        "{:?}",
        r.issues
    );
    // A critical extension this crate does not process (name constraints).
    let r = build_chain(
        &chain_of(&[
            "leaf-under-name-constraints",
            "inter-name-constraints",
            "root",
        ]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert_eq!(r.full_chain.certs, [0]);
    assert!(
        r.issues
            .iter()
            .any(|i| matches!(i, ChainIssue::UnhandledCriticalExtension { cert: 1, .. }))
    );
    // ...unless the policy trusts it as an anchor.
    let r = build_chain(
        &chain_of(&["leaf-under-name-constraints", "inter-name-constraints"]),
        0,
        &config(&["inter-name-constraints"]),
    )
    .unwrap();
    assert!(r.full_chain.anchored);
}

#[test]
fn loops_are_detected() {
    let certs = chain_of(&["leaf-loop", "loop-a", "loop-b"]);
    let report = build_chain(&certs, 0, &TrustConfig::new()).unwrap();
    assert_eq!(report.as_provided.certs, [0, 1, 2]);
    assert!(!report.chain_complete);
    assert!(
        report.issues.contains(&ChainIssue::Loop { cert: 1 }),
        "{:?}",
        report.issues
    );
}

#[test]
fn depth_is_capped() {
    // A root, eleven intermediates and a leaf: 13 certificates.
    let mut names: Vec<String> = (0..=12).rev().map(|i| format!("depth-{i:02}")).collect();
    names.rotate_left(0);
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let report = build_chain(&chain_of(&refs), 0, &config(&["depth-00"])).unwrap();
    assert_eq!(report.as_provided.certs.len(), MAX_CHAIN_LENGTH);
    assert!(!report.chain_complete);
    assert!(report.issues.contains(&ChainIssue::TooLong));
    // Ten certificates fit: depth-03 as the anchor makes a 10-long path.
    let report = build_chain(&chain_of(&refs), 0, &config(&["depth-03"])).unwrap();
    assert_eq!(report.full_chain.certs.len(), 10);
    assert!(report.full_chain.anchored);
}

#[test]
fn hostile_certificate_sets_hit_the_work_limit_and_fail_closed() {
    // `leaf-forged` names "Palisade Chain CA" as its issuer and has no key
    // identifier, so every certificate with that subject is a candidate
    // whose signature must be checked. Checks are cached per key, so the
    // copies of `inter` each get a different key (one modulus bit flipped).
    // One signature's set stays under the per-build budget; ten signatures
    // carrying such sets exhaust the file-wide one, and the later ones are
    // cut short, failing closed.
    let inter = der("inter");
    let modulus = find(&inter, &[0x02, 0x82, 0x01, 0x01, 0x00]) + 5;
    let mut certs = vec![der("leaf-forged")];
    for i in 0..MAX_EMBEDDED_CERTIFICATES - 1 {
        let mut c = inter.clone();
        c[modulus + 8 + i / 8] ^= 1 << (i % 8);
        certs.push(c);
    }
    let one = build_chain(&certs, 0, &TrustConfig::new()).unwrap();
    assert_eq!(one.full_chain.certs, [0]);
    assert!(!one.issues.contains(&ChainIssue::WorkLimitReached));
    assert!(one.issues.len() <= palisade_fileid::authenticode::MAX_CHAIN_ISSUES + 5);
    assert!(one.issues.contains(&ChainIssue::IssuesTruncated));

    let base = signed(&p7("leaf-inter-root"));
    let sigs: Vec<_> = (0..10)
        .map(|_| {
            with_certs(
                &base,
                certs.clone(),
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha256,
            )
        })
        .collect();
    let trust = evaluate_trust(&report_of(sigs), &TrustConfig::new(), None);
    assert_eq!(trust.primary, None);
    let last = trust.signers.last().unwrap().chain.as_ref().unwrap();
    assert_eq!(last.full_chain.certs, [0]);
    assert!(
        last.issues.contains(&ChainIssue::WorkLimitReached),
        "{:?}",
        last.issues
    );
}

#[test]
fn copies_of_one_key_cost_one_check() {
    // 150 copies of `inter` that differ only in their signature bits share
    // a key, so the forged leaf's signature is checked against it once.
    let mut certs = vec![der("leaf-forged")];
    for i in 0..150 {
        let mut c = der("inter");
        let at = c.len() - 1 - (i / 8);
        c[at] ^= 1 << (i % 8);
        certs.push(c);
    }
    let report = build_chain(&certs, 0, &TrustConfig::new()).unwrap();
    assert!(!report.issues.contains(&ChainIssue::WorkLimitReached));
    let invalid = report
        .issues
        .iter()
        .filter(|i| matches!(i, ChainIssue::SignatureInvalid { .. }))
        .count();
    assert_eq!(invalid, 1, "{:?}", report.issues);
}

#[test]
fn untrusted_certificates_cannot_spend_the_trust_budget() {
    // As many certificates as a signature keeps, all claiming the root as
    // their issuer (copies of the real intermediate with one signature bit
    // flipped, so each needs its own check with the root's key), placed
    // ahead of the real intermediate. Trust is still decided.
    let inter = der("inter");
    let decoys = MAX_EMBEDDED_CERTIFICATES - 2;
    let mut certs = vec![der("leaf")];
    for i in 0..decoys {
        let mut c = inter.clone();
        let at = c.len() - 1 - (i / 8);
        c[at] ^= 1 << (i % 8);
        certs.push(c);
    }
    certs.push(inter.clone());
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    assert!(!report.issues.contains(&ChainIssue::WorkLimitReached));
    assert_eq!(
        report.pca_cert().unwrap().sha256_thumbprint,
        cert("inter").sha256_thumbprint
    );
    // The same with the intermediate only in policy.
    let mut cfg = config(&["root"]);
    cfg.add_intermediate(&inter).unwrap();
    let report = build_chain(&certs[..=decoys], 0, &cfg).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    // Distinct keys under the intermediate's name (the untrusted search's
    // worst case) do not affect trust either.
    let modulus = find(&inter, &[0x02, 0x82, 0x01, 0x01, 0x00]) + 5;
    let mut keyed = vec![der("leaf")];
    for i in 0..decoys {
        let mut c = inter.clone();
        c[modulus + 8 + i / 8] ^= 1 << (i % 8);
        keyed.push(c);
    }
    keyed.push(inter);
    let report = build_chain(&keyed, 0, &config(&["root"])).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
}

#[test]
fn certificates_beyond_the_limit_are_ignored() {
    // The signer is always used; the rest are capped.
    let mut certs = vec![der("inter"); MAX_EMBEDDED_CERTIFICATES + 5];
    for (i, c) in certs.iter_mut().enumerate() {
        let at = c.len() - 1 - (i / 8);
        c[at] ^= 1 << (i % 8);
    }
    certs.push(der("leaf"));
    let signer = certs.len() - 1;
    let report = build_chain(&certs, signer, &config(&["root"])).unwrap();
    assert_eq!(report.certificates[0].origin, CertOrigin::Embedded(signer));
    assert!(report.issues.contains(&ChainIssue::TooManyCertificates));
    assert!(
        report
            .certificates
            .iter()
            .filter(|c| matches!(c.origin, CertOrigin::Embedded(_)))
            .count()
            <= MAX_EMBEDDED_CERTIFICATES
    );
}

#[test]
fn decoys_cannot_starve_trust_with_rekeyed_cas() {
    // Policy holds two trusted CAs with the same name and different keys
    // (`inter` and `inter-rekeyed`, both issued by the root). Decoy leaves
    // claiming that name as their issuer are checked against both keys,
    // which is the most a file can make the trust walk do. The real leaf's
    // link still verifies.
    let mut cfg = config(&["root"]);
    cfg.add_intermediate(&der("inter-rekeyed")).unwrap();
    cfg.add_intermediate(&der("inter")).unwrap();
    let mut certs = vec![der("leaf")];
    let forged = der("leaf-forged");
    for i in 0..MAX_EMBEDDED_CERTIFICATES - 1 {
        let mut c = forged.clone();
        let at = c.len() - 1 - (i / 8);
        c[at] ^= 1 << (i % 8);
        certs.push(c);
    }
    let report = build_chain(&certs, 0, &cfg).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    assert!(!report.issues.contains(&ChainIssue::WorkLimitReached));
}

#[test]
fn file_certificates_cannot_starve_trust_with_many_same_name_anchors() {
    // Policy trusts 67 CAs named "Palisade Chain CA": 66 copies of `inter`
    // with distinct keys (one modulus bit flipped), then `inter` itself,
    // the only one whose key verifies the leaf. The file adds 63
    // certificates with that name as both subject and issuer, so each is a
    // candidate child of every anchor (rejected by key identifier, but
    // only after a candidate step). They take 63 of every anchor's steps:
    // on one shared step count they would use up all 4096 before the last
    // anchor is reached. Added certificates spend only their own pool, so
    // the leaf is still checked against every anchor.
    let inter = der("inter");
    let modulus = find(&inter, &[0x02, 0x82, 0x01, 0x01, 0x00]) + 5;
    let mut cfg = TrustConfig::new();
    let copies = 66;
    for i in 0..copies {
        let mut c = inter.clone();
        c[modulus + 8 + i / 8] ^= 1 << (i % 8);
        cfg.add_anchor(format!("copy {i}"), &c).unwrap();
    }
    cfg.add_anchor("inter", &inter).unwrap();
    let mut certs = vec![der("leaf")];
    for i in 0..MAX_EMBEDDED_CERTIFICATES - 1 {
        certs.push(clone_with_issuer(&inter, &inter, i as u8));
    }
    let candidates = (copies + 1) * (MAX_EMBEDDED_CERTIFICATES - 1);
    assert!(candidates > 4096, "{candidates}");
    let report = build_chain(&certs, 0, &cfg).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    assert_eq!(report.anchored_to.as_ref().unwrap().index, copies);
    // The added certificates' own pool ran out, and the report says so.
    assert!(report.issues.contains(&ChainIssue::WorkLimitReached));
}

/// `template` with `extension` (a DER `Extension`) appended to its
/// extensions. The signature is left as it is, so it no longer verifies:
/// only usable as an anchor, whose own signature is never relied on.
fn with_extra_extension(template: &[u8], extension: &[u8]) -> Vec<u8> {
    let tlv = |tag: u8, content: &[u8]| {
        let mut out = vec![tag];
        out.extend(encode_len(content.len()));
        out.extend_from_slice(content);
        out
    };
    let (h, _) = header(template, 0);
    let (th, tl) = header(template, h);
    let mut kids = Vec::new();
    let mut at = h + th;
    while at < h + th + tl {
        let (kh, kl) = header(template, at);
        kids.push(template[at..at + kh + kl].to_vec());
        at += kh + kl;
    }
    let last = kids.last_mut().unwrap();
    assert_eq!(last[0], 0xa3);
    let (eh, _) = header(last, 0);
    let (sh, sl) = header(last, eh);
    let mut list = last[eh + sh..eh + sh + sl].to_vec();
    list.extend_from_slice(extension);
    *last = tlv(0xa3, &tlv(0x30, &list));
    let tbs = tlv(0x30, &kids.concat());
    tlv(0x30, &[tbs.as_slice(), &template[h + th + tl..]].concat())
}

#[test]
fn the_chosen_chain_prefers_a_path_that_permits_code_signing() {
    // Two anchors with the intermediate's subject and key: the first
    // restricted to TLS server use, the second (`inter`) unrestricted.
    // Both are anchored paths of the same length; the one that permits
    // code signing is chosen, so the signer is trusted and the restricted
    // path is only an alternative.
    let eku_server_auth = [
        0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06,
        0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
    ];
    let restricted = with_extra_extension(&der("inter"), &eku_server_auth);
    let parsed = CertSummary::from_der(&restricted).unwrap();
    assert!(!parsed.permits_eku(&eku::CODE_SIGNING.id()));
    assert_eq!(parsed.spki_sha256, cert("inter").spki_sha256);
    let mut cfg = TrustConfig::new();
    cfg.add_anchor("restricted", &restricted).unwrap();
    cfg.add_anchor("inter", &der("inter")).unwrap();

    let report = build_chain(&chain_of(&["leaf"]), 0, &cfg).unwrap();
    assert!(report.full_chain.anchored);
    assert_eq!(report.anchored_to.as_ref().unwrap().label, "inter");
    assert!(report.permits_code_signing());
    assert_eq!(report.alternatives.len(), 1);

    let base = signed(&p7("leaf-inter-root"));
    let sig = with_certs(
        &base,
        chain_of(&["leaf"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(&report_of(vec![sig]), &cfg, None);
    assert_eq!(trust.primary, Some(0), "{:?}", trust.signers[0].untrusted);
    assert!(trust.identity.is_some());
}

#[test]
fn os_rules_are_only_given_for_os_ci_compatible_signers() {
    // A trusted ECC chain with a PCA and a CN: every other identity string
    // is made, but the OS Publisher levels are not, because OS code
    // integrity would not honour them.
    let base = signed(&p7("leaf-inter-root"));
    let sig = with_certs(
        &base,
        chain_of(&["ecc-leaf", "ecc-inter"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(
        &report_of(vec![sig]),
        &config(&["ecc-root"]),
        Some(&version_info()),
    );
    let signer = trust.primary_signer().unwrap();
    assert!(signer.trusted, "{:?}", signer.untrusted);
    assert!(!signer.os_ci_compatible);
    assert!(signer.chain.as_ref().unwrap().pca.is_some());
    let id = trust.identity.unwrap();
    assert!(id.publisher_name.is_some() && id.publisher_product.is_some());
    assert_eq!(id.publisher_os_rule, None);
    assert_eq!(id.file_publisher_os_rule, None);
    assert_eq!(id.issues, [IdentityIssue::NotOsCiCompatible]);
}

#[test]
fn same_name_anchors_are_not_checked_against_each_other() {
    // `root` and `cross-root` share a subject. Both trusted, neither is
    // checked as the other's child, so no issue is recorded.
    let report = build_chain(
        &chain_of(&["leaf", "inter"]),
        0,
        &config(&["root", "cross-root"]),
    )
    .unwrap();
    assert!(report.full_chain.anchored);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
}

#[test]
fn an_embedded_copy_of_a_policy_intermediate_keeps_policy_priority() {
    // The policy intermediate is also embedded, behind 62 decoys that
    // claim the same issuer. It is still reached and trusted.
    let inter = der("inter");
    let mut certs = vec![der("leaf")];
    for i in 0..MAX_EMBEDDED_CERTIFICATES - 2 {
        let mut c = inter.clone();
        let at = c.len() - 1 - (i / 8);
        c[at] ^= 1 << (i % 8);
        certs.push(c);
    }
    certs.push(inter.clone());
    let mut cfg = config(&["root"]);
    cfg.add_intermediate(&inter).unwrap();
    let report = build_chain(&certs, 0, &cfg).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    let pca = report.pca.unwrap();
    assert!(matches!(
        report.certificates[pca].origin,
        CertOrigin::Embedded(_)
    ));
}

#[test]
fn unrelated_policy_entries_do_not_appear_in_reports() {
    // Policy holds another chain (the ECC root and CA) and a pinned
    // non-CA certificate: none is reachable from this leaf, so none is
    // checked, reported or listed.
    let mut cfg = config(&["root", "ecc-root", "leaf-pinned"]);
    cfg.add_intermediate(&der("ecc-inter")).unwrap();
    cfg.add_intermediate(&der("inter-name-constraints"))
        .unwrap();
    let report = build_chain(&chain_of(&["leaf", "inter"]), 0, &cfg).unwrap();
    assert!(report.full_chain.anchored);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert_eq!(report.certificates.len(), 3);
}

#[test]
fn self_issued_anchors_are_roots_even_if_their_self_signature_is_unchecked() {
    // A root whose own signature does not verify here (one bit flipped,
    // standing in for an algorithm that is not verified, such as MD5 or
    // P-521) is self-issued but not self-signed. Configured as the anchor
    // and embedded, it is still the root, not the PCA; and its own
    // signature algorithm is not counted.
    let mut root = der("root");
    let last = root.len() - 1;
    root[last] ^= 1;
    let summary = CertSummary::from_der(&root).unwrap();
    assert!(!summary.is_self_signed);
    let mut cfg = TrustConfig::new();
    cfg.add_anchor("root", &root).unwrap();
    let certs = vec![der("leaf"), der("inter"), root.clone()];
    let report = build_chain(&certs, 0, &cfg).unwrap();
    assert!(report.full_chain.anchored);
    assert_eq!(report.root_as_provided, Some(2));
    assert_eq!(report.pca, Some(1));
    assert_eq!(report.intermediates, [1]);
    // No false loop for the self-issued root.
    assert!(
        !report
            .issues
            .iter()
            .any(|i| matches!(i, ChainIssue::Loop { .. })),
        "{:?}",
        report.issues
    );
    assert!(report.cert_sig_algs_allowed(&[SignatureAlgorithm::RsaPkcs1(DigestAlgorithm::Sha256)]));
    // Appending the anchor to a [leaf, inter] file does not change the PCA.
    let short = build_chain(&chain_of(&["leaf", "inter"]), 0, &cfg).unwrap();
    assert_eq!(
        short.pca_cert().unwrap().tbs_hash,
        report.pca_cert().unwrap().tbs_hash
    );
}

#[test]
fn expired_intermediates_still_chain() {
    // Validity is #50's job; chains are built regardless.
    let certs = chain_of(&["leaf-expired-ca", "inter-expired", "root"]);
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    assert!(report.full_chain.anchored);
    assert!(report.pca_cert().unwrap().not_after < 1_100_000_000);
}

#[test]
fn self_signed_leaf() {
    let report = build_chain(&chain_of(&["leaf-self-signed"]), 0, &TrustConfig::new()).unwrap();
    assert_eq!(report.as_provided.certs, [0]);
    assert_eq!(report.root_as_provided, Some(0));
    assert_eq!(report.pca, None);
    assert!(report.chain_complete);
    assert_eq!(report.anchor_source, AnchorSource::None);
    let trusted = build_chain(
        &chain_of(&["leaf-self-signed"]),
        0,
        &config(&["leaf-self-signed"]),
    )
    .unwrap();
    assert!(trusted.full_chain.anchored);
}

#[test]
fn ecc_chains() {
    let certs = chain_of(&["ecc-leaf", "ecc-inter", "ecc-root"]);
    let report = build_chain(&certs, 0, &config(&["ecc-root"])).unwrap();
    assert_eq!(report.full_chain.certs, [0, 1, 2]);
    assert!(report.full_chain.anchored);
    assert!(!report.meets_min_key_bits(2048, 384));
    assert!(report.meets_min_key_bits(2048, 256));
}

#[test]
fn eku_constraints() {
    let certs = chain_of(&["leaf", "inter", "root"]);
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    let lifetime = eku::LIFETIME_SIGNING.id();
    assert!(report.leaf_has_eku(&lifetime));
    assert!(report.chain_has_eku(&lifetime));
    assert!(!report.leaf_has_eku(&eku::TIME_STAMPING.id()));
    assert!(report.permits_code_signing());
    // An issuer restricted to TLS server auth blocks code signing.
    let tls = build_chain(
        &chain_of(&["leaf-under-tls-ca", "inter-tls", "root"]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert!(tls.full_chain.anchored);
    assert!(tls.leaf_has_eku(&eku::CODE_SIGNING.id()));
    assert!(!tls.chain_has_eku(&eku::CODE_SIGNING.id()));
    assert!(!tls.permits_code_signing());
    // A TLS leaf does not permit code signing either.
    let leaf_tls = build_chain(
        &chain_of(&["leaf-tls", "inter", "root"]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert!(!leaf_tls.permits_code_signing());
    // Signature algorithms.
    let sha256 = SignatureAlgorithm::RsaPkcs1(DigestAlgorithm::Sha256);
    assert!(report.cert_sig_algs_allowed(std::slice::from_ref(&sha256)));
    let sha1 = build_chain(
        &chain_of(&["leaf-sha1", "inter", "root"]),
        0,
        &config(&["root"]),
    )
    .unwrap();
    assert!(!sha1.cert_sig_algs_allowed(&[sha256]));
}

#[test]
fn well_known_roots_resolve_by_tbs_hash() {
    let root = cert("root");
    let mut cfg = config(&["root"]);
    cfg.add_well_known_root(6, &root.tbs_hash.clone().unwrap().to_ascii_uppercase())
        .unwrap();
    assert_eq!(cfg.well_known_root_id(&root), Some(6));
    assert_eq!(cfg.well_known_root_id(&cert("inter")), None);
    let report = build_chain(&chain_of(&["leaf", "inter", "root"]), 0, &cfg).unwrap();
    assert_eq!(report.well_known_root_id, Some(6));
    // Without the root embedded, the policy anchor resolves it.
    let report = build_chain(&chain_of(&["leaf", "inter"]), 0, &cfg).unwrap();
    assert_eq!(report.well_known_root_id, Some(6));
    assert!(cfg.add_well_known_root(1, "abcd").is_err());
    assert!(cfg.add_well_known_root(1, &"zz".repeat(32)).is_err());
}

#[test]
fn unparseable_embedded_certificates_are_skipped() {
    let mut certs = chain_of(&["leaf", "inter"]);
    certs.insert(1, vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    let report = build_chain(&certs, 0, &TrustConfig::new()).unwrap();
    assert_eq!(report.pca, Some(1));
    assert_eq!(report.certificates[1].origin, CertOrigin::Embedded(2));
    assert!(matches!(
        report.issues[0],
        ChainIssue::UnparseableCertificate { embedded: 1, .. }
    ));
    // The signer itself must parse.
    assert!(build_chain(&certs, 1, &TrustConfig::new()).is_err());
    // Entries that fail to parse count against the limit too: the builder
    // stops after MAX_EMBEDDED_CERTIFICATES attempts, signer included.
    let mut junk = vec![der("leaf")];
    junk.extend(std::iter::repeat_n(
        vec![0x30, 0x00],
        3 * MAX_EMBEDDED_CERTIFICATES,
    ));
    let report = build_chain(&junk, 0, &TrustConfig::new()).unwrap();
    assert!(report.issues.contains(&ChainIssue::TooManyCertificates));
    let unparseable: Vec<usize> = report
        .issues
        .iter()
        .filter_map(|i| match i {
            ChainIssue::UnparseableCertificate { embedded, .. } => Some(*embedded),
            _ => None,
        })
        .collect();
    // Issues are capped, so only the first ones are listed, and none is
    // past the limit.
    assert!(!unparseable.is_empty());
    assert!(unparseable.iter().all(|i| *i < MAX_EMBEDDED_CERTIFICATES));
    assert!(build_chain(&certs, 9, &TrustConfig::new()).is_err());
}

#[test]
fn duplicate_certificates_are_used_once() {
    let certs = chain_of(&["inter", "leaf", "inter", "leaf", "root"]);
    let report = build_chain(&certs, 1, &config(&["root"])).unwrap();
    assert_eq!(report.certificates.len(), 3);
    assert_eq!(report.full_chain.certs, [0, 1, 2]);
    assert!(report.alternatives.is_empty());
}

#[test]
fn chain_reports_serialise() {
    let certs = chain_of(&["leaf", "inter", "root"]);
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["anchor_source"], "policy");
    assert_eq!(json["chain_complete"], true);
    assert_eq!(json["pca"], 1);
    assert_eq!(
        json["certificates"][0]["origin"],
        serde_json::json!({"embedded": 0})
    );
}

// --- Anchors are held to CA rules when they issue. --------------------------

#[test]
fn an_end_entity_anchor_cannot_issue() {
    // A pinned self-signed signer (CA:FALSE, no keyCertSign) is trusted as
    // itself...
    let cfg = config(&["leaf-pinned"]);
    let own = build_chain(&chain_of(&["leaf-pinned"]), 0, &cfg).unwrap();
    assert!(own.full_chain.anchored);
    // ...but a certificate signed with its key is not.
    let evil = build_chain(
        &chain_of(&["leaf-issued-by-pinned", "leaf-pinned"]),
        0,
        &cfg,
    )
    .unwrap();
    assert_eq!(evil.full_chain.certs, [0]);
    assert!(!evil.full_chain.anchored);
    assert!(
        evil.issues.contains(&ChainIssue::IssuerNotCa { issuer: 1 }),
        "{:?}",
        evil.issues
    );
    // The same with the pinned certificate only in policy.
    let evil = build_chain(&chain_of(&["leaf-issued-by-pinned"]), 0, &cfg).unwrap();
    assert!(!evil.full_chain.anchored);
}

#[test]
fn an_anchor_without_cert_sign_cannot_issue() {
    let cfg = config(&["root-no-cert-sign"]);
    let r = build_chain(&chain_of(&["leaf-under-no-cert-sign"]), 0, &cfg).unwrap();
    assert!(!r.full_chain.anchored);
    let anchor = r
        .certificates
        .iter()
        .position(|c| c.anchor == Some(0))
        .unwrap();
    assert!(
        r.issues
            .contains(&ChainIssue::IssuerKeyUsage { issuer: anchor }),
        "{:?}",
        r.issues
    );
}

#[test]
fn an_anchors_path_length_is_enforced() {
    // `inter` has pathlen 0. Trusted as an anchor, it still may not have a
    // CA below it.
    let r = build_chain(
        &chain_of(&["leaf-too-deep", "inter-sub", "inter"]),
        0,
        &config(&["inter"]),
    )
    .unwrap();
    assert!(!r.full_chain.anchored);
    assert!(
        r.issues
            .contains(&ChainIssue::PathLengthExceeded { issuer: 2 }),
        "{:?}",
        r.issues
    );
}

#[test]
fn critical_extension_exemption_is_for_anchors_only() {
    // As provided (no anchors in play), the name-constrained CA is not used
    // even if policy trusts it.
    let r = build_chain(
        &chain_of(&["leaf-under-name-constraints", "inter-name-constraints"]),
        0,
        &config(&["inter-name-constraints"]),
    )
    .unwrap();
    assert_eq!(r.as_provided.certs, [0]);
    assert!(r.full_chain.anchored);
    assert_eq!(r.full_chain.certs, [0, 1]);
}

// --- Version 1 and 2 certificates. ------------------------------------------

#[test]
fn version_1_and_2_certificates() {
    let root = cert("root-v1");
    assert_eq!(root.version, 1);
    assert!(root.is_self_signed);
    assert_eq!(root.basic_constraints, None);
    assert_eq!(root.extended_key_usage, None);
    let v2 = cert("leaf-v2");
    assert_eq!(v2.version, 2);
    assert_eq!(v2.subject.common_name(), Some("Palisade V2 Signer"));
    // A v1 root is a CA only as a configured anchor.
    let anchored = build_chain(&chain_of(&["leaf-v1"]), 0, &config(&["root-v1"])).unwrap();
    assert!(anchored.full_chain.anchored, "{:?}", anchored.issues);
    let anchored =
        build_chain(&chain_of(&["leaf-v2", "root-v1"]), 0, &config(&["root-v1"])).unwrap();
    assert!(anchored.full_chain.anchored, "{:?}", anchored.issues);
    let provided = build_chain(&chain_of(&["leaf-v1", "root-v1"]), 0, &TrustConfig::new()).unwrap();
    assert_eq!(provided.as_provided.certs, [0]);
    assert!(
        provided
            .issues
            .contains(&ChainIssue::IssuerNotCa { issuer: 1 })
    );
}

#[test]
fn unique_identifier_bit_strings_must_be_der() {
    let good = der("leaf-v2");
    // subjectUniqueID [2] = 04 f0: four unused bits, all zero.
    let at = find(&good, &[0x82, 0x02, 0x04, 0xf0]);
    let mut dirty = good.clone();
    dirty[at + 3] = 0xf1;
    assert!(CertSummary::from_der(&dirty).is_err());
    let mut too_many = good.clone();
    too_many[at + 2] = 0x08;
    assert!(CertSummary::from_der(&too_many).is_err());
}

// --- The embedded certificate set cannot steer the PCA or the search. -----

/// A certificate with `template`'s TBS fields (subject, key, extensions)
/// but `issuer_name`, signed by nobody: the attacker's copy of a real
/// intermediate, made without any CA key.
fn clone_with_issuer(template: &[u8], issuer_from: &[u8], serial: u8) -> Vec<u8> {
    // tbsCertificate children: [0] version, serial, sigAlg, issuer, ...
    let (h, _) = header(template, 0);
    let tbs_at = h;
    let (th, tl) = header(template, tbs_at);
    let mut kids = Vec::new();
    let mut at = tbs_at + th;
    while at < tbs_at + th + tl {
        let (kh, kl) = header(template, at);
        kids.push(template[at..at + kh + kl].to_vec());
        at += kh + kl;
    }
    // Replace the serial and the issuer.
    kids[1] = vec![0x02, 0x01, serial];
    let other_subject = {
        let (oh, _) = header(issuer_from, 0);
        let (ith, itl) = header(issuer_from, oh);
        let mut a = oh + ith;
        let mut found = Vec::new();
        let mut n = 0;
        while a < oh + ith + itl {
            let (kh, kl) = header(issuer_from, a);
            if n == 5 {
                found = issuer_from[a..a + kh + kl].to_vec();
            }
            n += 1;
            a += kh + kl;
        }
        found
    };
    kids[3] = other_subject;
    let tbs_content = kids.concat();
    let mut tbs = vec![0x30];
    tbs.extend(encode_len(tbs_content.len()));
    tbs.extend(tbs_content);
    // Keep the original signature algorithm and a junk signature.
    let rest_at = tbs_at + th + tl;
    let rest = &template[rest_at..];
    let content = [tbs.as_slice(), rest].concat();
    let mut out = vec![0x30];
    out.extend(encode_len(content.len()));
    out.extend(content);
    out
}

#[test]
fn injected_clones_of_the_intermediate_never_become_the_pca() {
    // The file carries the real chain, plus a copy of the intermediate
    // (same subject, key and key identifier, so the leaf's signature
    // verifies with it) that claims a self-signed attacker root as its
    // issuer, and that attacker root.
    let fake = clone_with_issuer(&der("inter"), &der("leaf-self-signed"), 0x77);
    let fake_summary = CertSummary::from_der(&fake).unwrap();
    assert_eq!(fake_summary.subject.der, cert("inter").subject.der);
    assert_eq!(fake_summary.spki_sha256, cert("inter").spki_sha256);
    let certs = vec![der("leaf"), fake, der("leaf-self-signed"), der("inter")];
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    assert!(report.full_chain.anchored);
    let pca = report.pca_cert().unwrap();
    assert_eq!(pca.sha256_thumbprint, cert("inter").sha256_thumbprint);
    assert_eq!(report.root_as_provided, None);
    // The PCA is on the full chain.
    assert!(report.full_chain.certs.contains(&report.pca.unwrap()));
}

#[test]
fn dead_end_clones_cannot_crowd_out_the_trusted_chain() {
    // Twenty clones of the intermediate, each naming a different missing
    // issuer, are dead ends. The real chain is still found, through the
    // embedded intermediate or the policy one.
    let mut certs = vec![der("leaf")];
    for i in 0..20_u8 {
        let mut fake = clone_with_issuer(&der("inter"), &der("leaf-self-signed"), i);
        // Make each claimed issuer distinct and absent: flip a byte of the
        // issuer CN.
        let cn = find(&fake, b"Palisade Self Signer");
        fake[cn] = b'A' + i;
        certs.push(fake);
    }
    certs.push(der("inter"));
    let report = build_chain(&certs, 0, &config(&["root"])).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    assert_eq!(
        report.pca_cert().unwrap().sha256_thumbprint,
        cert("inter").sha256_thumbprint
    );
    assert!(report.issues.contains(&ChainIssue::TooManyPaths));
    // With the intermediate only in policy.
    certs.pop();
    let mut cfg = config(&["root"]);
    cfg.add_intermediate(&der("inter")).unwrap();
    let report = build_chain(&certs, 0, &cfg).unwrap();
    assert!(report.full_chain.anchored, "{:?}", report.issues);
    assert_eq!(report.pca, None);
}

#[test]
fn empty_subjects_have_no_dn() {
    // Replace the leaf's subject with an empty Name. The certificate's
    // signature breaks, so trust it directly as an anchor.
    let leaf = der("leaf");
    let subject = cert("leaf").subject.der;
    let at = find(&leaf, &subject);
    let tbs_at = header(&leaf, 0).0;
    let (th, tl) = header(&leaf, tbs_at);
    let mut tbs = leaf[tbs_at + th..at].to_vec();
    tbs.extend([0x30, 0x00]);
    tbs.extend(&leaf[at + subject.len()..tbs_at + th + tl]);
    let mut tbs_der = vec![0x30];
    tbs_der.extend(encode_len(tbs.len()));
    tbs_der.extend(tbs);
    let content = [tbs_der.as_slice(), &leaf[tbs_at + th + tl..]].concat();
    let mut empty = vec![0x30];
    empty.extend(encode_len(content.len()));
    empty.extend(content);
    let c = CertSummary::from_der(&empty).unwrap();
    assert!(c.subject.rdns.is_empty());
    let base = signed(&p7("leaf-inter-root"));
    let sig = with_certs(
        &base,
        vec![empty.clone()],
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let mut cfg = TrustConfig::new();
    cfg.add_anchor("leaf", &empty).unwrap();
    let id = evaluate_trust(&report_of(vec![sig]), &cfg, None)
        .identity
        .unwrap();
    assert_eq!(id.publisher_dn, None);
    assert_eq!(id.publisher_name, None);
    assert!(id.issues.contains(&IdentityIssue::NoName));
}

#[test]
fn unparseable_signer_certificates_are_untrusted() {
    let base = signed(&p7("leaf-inter-root"));
    let mut bad = der("leaf");
    bad.push(0);
    assert!(CertSummary::from_der(&bad).is_err());
    let sig = with_certs(
        &base,
        vec![bad],
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(&report_of(vec![sig]), &config(&["root"]), None);
    assert!(matches!(
        trust.signers[0].untrusted.as_slice(),
        [UntrustedReason::SignerCertificate(_)]
    ));
    assert_eq!(trust.primary, None);
}

#[test]
fn earlier_untrusted_signatures_cannot_starve_later_trusted_ones() {
    // Ten signatures over certificate sets that each spend 63 untrusted
    // checks (one per distinct key a signature keeps), 630 in all, then a
    // trusted SHA-256 one. The file-wide budget (512) runs out before the
    // last, but trust for it is decided on its own budget.
    let base = signed(&p7("leaf-inter-root"));
    let inter = der("inter");
    let modulus = find(&inter, &[0x02, 0x82, 0x01, 0x01, 0x00]) + 5;
    let mut hostile = vec![der("leaf-forged")];
    for i in 0..150 {
        let mut c = inter.clone();
        c[modulus + 8 + i / 8] ^= 1 << (i % 8);
        hostile.push(c);
    }
    let hostile_sets = 10;
    let mut sigs: Vec<_> = (0..hostile_sets)
        .map(|_| {
            with_certs(
                &base,
                hostile.clone(),
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha256,
            )
        })
        .collect();
    sigs.push(with_certs(
        &base,
        chain_of(&["leaf", "inter"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    ));
    let trust = evaluate_trust(&report_of(sigs), &config(&["root"]), None);
    // The file-wide budget is spent: the last hostile set is cut short.
    let last_hostile = trust.signers[hostile_sets - 1].chain.as_ref().unwrap();
    assert!(
        last_hostile.issues.contains(&ChainIssue::WorkLimitReached),
        "{:?}",
        last_hostile.issues
    );
    assert_eq!(trust.primary, Some(hostile_sets));
    let chain = trust.signers[hostile_sets].chain.as_ref().unwrap();
    assert!(chain.full_chain.anchored, "{:?}", chain.issues);
    assert_eq!(
        chain.pca_cert().unwrap().sha256_thumbprint,
        cert("inter").sha256_thumbprint
    );
}

#[test]
fn well_known_root_comes_only_from_the_full_chain() {
    // The well-known root is embedded but the full chain anchors elsewhere
    // (root2 via the cross-certificate): no well-known ID.
    let mut cfg = config(&["root2"]);
    cfg.add_well_known_root(9, &cert("root").tbs_hash.unwrap())
        .unwrap();
    let certs = chain_of(&["leaf", "inter", "cross-root", "root"]);
    let r = build_chain(&certs, 0, &cfg).unwrap();
    assert!(r.full_chain.anchored);
    assert_eq!(r.well_known_root_id, None);
}

// --- Trust evaluation and identity. -----------------------------------------

fn p7(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}.p7")).unwrap()
}

fn entry(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(u32::try_from(data.len()).unwrap() + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

fn signed(blob: &[u8]) -> SignatureReport {
    let image = PeBuilder {
        certificate: Some(entry(blob)),
        ..PeBuilder::default()
    }
    .build();
    verify_pe(&image, &VerifyOptions::default()).unwrap()
}

fn version_info() -> pe::version::VersionInfo {
    let image = with_version(&VersionSpec {
        fixed: Some(fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![(0x0409, 0x04b0)],
    })
    .build();
    pe::parse(&image).unwrap().version_info.unwrap()
}

#[test]
fn untrusted_nested_signer_never_becomes_primary() {
    // A SHA-1 signature by chain A, with a nested SHA-256 signature by
    // chain B. Both are cryptographically valid; #48 alone picks the
    // SHA-256 one.
    let report = signed(&p7("dual-a-sha1-b-sha256"));
    assert_eq!(report.signatures.len(), 2);
    assert!(report.signatures.iter().all(|s| s.status.is_valid()));
    assert_eq!(report.primary, Some(1));

    // Only root A is trusted: the SHA-1 signature is primary.
    let trust = evaluate_trust(&report, &config(&["root-a"]), None);
    assert_eq!(trust.primary, Some(0));
    assert!(trust.signers[0].trusted);
    assert!(!trust.signers[1].trusted);
    assert_eq!(trust.signers[1].untrusted, [UntrustedReason::NoTrustAnchor]);
    let id = trust.identity.unwrap();
    assert_eq!(id.signature, 0);
    assert_eq!(id.publisher_name.unwrap().value, "Palisade Signer A");

    // Only root B: the nested one is primary.
    let trust = evaluate_trust(&report, &config(&["root-b"]), None);
    assert_eq!(trust.primary, Some(1));
    // Both: the stronger digest wins.
    let trust = evaluate_trust(&report, &config(&["root-a", "root-b"]), None);
    assert_eq!(trust.primary, Some(1));
    // Neither: no primary and no identity.
    let trust = evaluate_trust(&report, &TrustConfig::new(), None);
    assert_eq!((trust.primary, trust.identity), (None, None));
}

#[test]
fn identity_strings_for_a_trusted_signer() {
    let report = signed(&p7("leaf-inter-root"));
    let sig = &report.signatures[0];
    assert!(sig.status.is_valid(), "{sig:#?}");
    let version = version_info();
    let trust = evaluate_trust(&report, &config(&["root"]), Some(&version));
    let signer = trust.primary_signer().unwrap();
    assert!(signer.trusted, "{:?}", signer.untrusted);
    assert!(signer.os_ci_compatible);
    assert!(signer.meets_min_key_bits(2048, 256));
    assert!(!signer.meets_min_key_bits(3072, 256));
    let chain = signer.chain.as_ref().unwrap();
    // Embedded in the order leaf, root, intermediate; built leaf upwards.
    assert_eq!(
        subjects(chain, &chain.as_provided),
        [
            "Palisade Test Publisher",
            "Palisade Chain CA",
            "Palisade Chain Root"
        ]
    );
    let id = trust.identity.unwrap();
    let name = id.publisher_name.unwrap();
    assert_eq!(
        (name.value.as_str(), name.source),
        ("Palisade Test Publisher", NameSource::CommonName)
    );
    assert_eq!(id.publisher_dn, Some(cert("leaf").subject.canonical));
    assert_eq!(id.product_name.as_deref(), Some("Example Suite"));
    assert_eq!(
        id.publisher_product,
        Some((
            "Palisade Test Publisher".to_owned(),
            "Example Suite".to_owned()
        ))
    );
    let rule = id.publisher_os_rule.unwrap();
    assert_eq!(
        rule.root,
        OsRuleRoot::PcaTbsHash(cert("inter").tbs_hash.unwrap())
    );
    assert_eq!(rule.leaf_cn, "Palisade Test Publisher");
    let file = id.file_publisher_os_rule.unwrap();
    assert_eq!(file.publisher, rule);
    assert_eq!(file.file_name, "extool.exe");
    assert_eq!(file.file_name_field, VersionField::OriginalFileName);
    assert_eq!(file.min_version, FileVersionQuad(1, 2, 3, 4));
    assert!(id.issues.is_empty(), "{:?}", id.issues);
    assert_eq!(trust.vendor_hint, None);
    let json = serde_json::to_value(&file).unwrap();
    assert_eq!(json["file_name_field"], "OriginalFileName");
    assert_eq!(json["min_version"], "1.2.3.4");
}

#[test]
fn well_known_root_replaces_the_pca_in_os_rules() {
    let report = signed(&p7("leaf-inter-root"));
    let mut cfg = config(&["root"]);
    cfg.add_well_known_root(10, &cert("root").tbs_hash.unwrap())
        .unwrap();
    let trust = evaluate_trust(&report, &cfg, None);
    let id = trust.identity.unwrap();
    assert_eq!(
        id.publisher_os_rule.unwrap().root,
        OsRuleRoot::WellKnown(10)
    );
    assert!(id.issues.contains(&IdentityIssue::NoProductName));
    assert!(id.issues.contains(&IdentityIssue::NoFileNameOrVersion));
    assert_eq!(id.publisher_product, None);
}

#[test]
fn leaf_and_root_only_has_no_pca() {
    // The dual fixture's chains are leaf + root.
    let report = signed(&p7("dual-a-sha1-b-sha256"));
    let trust = evaluate_trust(&report, &config(&["root-b"]), Some(&version_info()));
    let chain = trust.primary_signer().unwrap().chain.as_ref().unwrap();
    assert_eq!(chain.pca, None);
    assert!(chain.root_as_provided.is_some());
    let id = trust.identity.unwrap();
    assert_eq!(id.publisher_os_rule, None);
    assert_eq!(id.file_publisher_os_rule, None);
    assert!(id.issues.contains(&IdentityIssue::NoPca));
    // Publisher plus product still works without a PCA.
    assert_eq!(
        id.publisher_product,
        Some(("Palisade Signer B".to_owned(), "Example Suite".to_owned()))
    );
}

#[test]
fn unsigned_files_get_an_unverified_vendor_hint() {
    let image = with_version(&VersionSpec {
        fixed: None,
        tables: vec![("040904B0", all_standard_strings())],
        translations: vec![],
    })
    .build();
    let info = pe::parse(&image).unwrap();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    let trust = evaluate_trust(&report, &config(&["root"]), info.version_info.as_ref());
    assert!(trust.signers.is_empty());
    assert_eq!((trust.primary, trust.identity.clone()), (None, None));
    let hint = trust.vendor_hint.unwrap();
    assert_eq!(hint.company_name, "Example Org");
    assert!(hint.unverified);
    // An untrusted signed file gets the hint too.
    let report = signed(&p7("leaf-inter-root"));
    let trust = evaluate_trust(&report, &TrustConfig::new(), info.version_info.as_ref());
    assert!(trust.vendor_hint.is_some() && trust.identity.is_none());
}

#[test]
fn invalid_signatures_are_never_trusted() {
    // Tamper with the image: the digest no longer matches.
    let blob = p7("leaf-inter-root");
    let mut image = PeBuilder {
        certificate: Some(entry(&blob)),
        ..PeBuilder::default()
    }
    .build();
    image[0x400] ^= 0xff; // the first byte of .text
    let report = verify_pe(
        &image,
        &VerifyOptions {
            tolerate_digest_mismatch: true,
        },
    )
    .unwrap();
    assert!(!report.signatures[0].status.is_valid());
    assert!(report.signatures[0].signer.is_some());
    let trust = evaluate_trust(&report, &config(&["root"]), None);
    assert_eq!(trust.primary, None);
    assert_eq!(trust.signers[0].untrusted, [UntrustedReason::NotValid]);
    assert!(trust.signers[0].chain.is_none());
}

/// `report`'s signature 0 with its embedded certificates replaced by
/// `certs` (signer first) and its digests set. The trust layer reads only
/// these fields, so this exercises it on certificates no fixture signature
/// carries.
fn with_certs(
    report: &SignatureReport,
    certs: Vec<Vec<u8>>,
    digest: DigestAlgorithm,
    signer_digest: DigestAlgorithm,
) -> palisade_fileid::authenticode::SignatureInfo {
    let mut sig = report.signatures[0].clone();
    sig.certs_in_blob = certs;
    sig.signer.as_mut().unwrap().signer_cert = 0;
    sig.digest_alg = Some(digest);
    sig.signer_digest_alg = Some(signer_digest);
    sig
}

fn report_of(sigs: Vec<palisade_fileid::authenticode::SignatureInfo>) -> SignatureReport {
    let mut report = signed(&p7("leaf-inter-root"));
    report.signatures = sigs
        .into_iter()
        .enumerate()
        .map(|(i, mut s)| {
            s.index = i;
            s
        })
        .collect();
    report
}

#[test]
fn organization_only_signer_identity() {
    let base = signed(&p7("leaf-inter-root"));
    let sig = with_certs(
        &base,
        chain_of(&["leaf-o-only", "inter"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(
        &report_of(vec![sig]),
        &config(&["root"]),
        Some(&version_info()),
    );
    let id = trust.identity.unwrap();
    let name = id.publisher_name.unwrap();
    assert_eq!(
        (name.value.as_str(), name.source),
        ("Palisade Tésts", NameSource::Organization)
    );
    assert_eq!(id.publisher_os_rule, None);
    assert_eq!(id.file_publisher_os_rule, None);
    assert!(
        id.issues.contains(&IdentityIssue::NoCommonName),
        "{:?}",
        id.issues
    );
    assert_eq!(
        id.publisher_product,
        Some(("Palisade Tésts".to_owned(), "Example Suite".to_owned()))
    );
}

#[test]
fn names_that_do_not_decode_exactly_are_not_identities() {
    let base = signed(&p7("leaf-inter-root"));
    let cn = b"Palisade Test Publisher";
    let at = find(&der("leaf"), cn);
    let trust_for = |leaf: Vec<u8>| {
        let sig = with_certs(
            &base,
            vec![leaf, der("inter")],
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha256,
        );
        // The edited leaf's signature no longer verifies, so trust it
        // directly as an anchor: the name logic is what is tested.
        let mut cfg = TrustConfig::new();
        cfg.add_anchor("leaf", &sig.certs_in_blob[0]).unwrap();
        evaluate_trust(&report_of(vec![sig]), &cfg, None)
    };
    // A PrintableString holding a non-ASCII byte: lossy.
    let mut lossy = der("leaf");
    lossy[at - 2] = 0x13;
    lossy[at] = 0xc0;
    let c = CertSummary::from_der(&lossy).unwrap();
    let attr = c.subject.first(AttributeKind::CommonName).unwrap();
    assert!(attr.lossy && !attr.is_clean());
    let id = trust_for(lossy).identity.unwrap();
    assert_eq!(id.publisher_name, None);
    assert_eq!(id.publisher_os_rule, None);
    assert_eq!(id.publisher_dn, None);
    assert!(id.issues.contains(&IdentityIssue::UnusableName));
    assert!(id.issues.contains(&IdentityIssue::UnusableDn));
    // A NUL is kept, makes the name unclean, and there is no fallback to O.
    let mut nul = der("leaf");
    nul[at + 8] = 0;
    let c = CertSummary::from_der(&nul).unwrap();
    let attr = c.subject.first(AttributeKind::CommonName).unwrap();
    assert_eq!(attr.value, "Palisade\0Test Publisher");
    assert!(!attr.is_clean());
    let id = trust_for(nul).identity.unwrap();
    assert_eq!(id.publisher_name, None);
    assert!(id.issues.contains(&IdentityIssue::UnusableName));
    // Blank: a CN of spaces.
    let mut blank = der("leaf");
    blank[at..at + cn.len()].fill(b' ');
    let c = CertSummary::from_der(&blank).unwrap();
    assert!(
        !c.subject
            .first(AttributeKind::CommonName)
            .unwrap()
            .is_clean()
    );
    let id = trust_for(blank).identity.unwrap();
    assert_eq!(id.publisher_name, None);
    assert!(id.issues.contains(&IdentityIssue::UnusableName));
}

#[test]
fn signers_restricted_from_code_signing_are_untrusted() {
    let base = signed(&p7("leaf-inter-root"));
    // A TLS-only issuer.
    let tls_ca = with_certs(
        &base,
        chain_of(&["leaf-under-tls-ca", "inter-tls"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    // A TLS server leaf: wrong EKU and no code signing.
    let tls_leaf = with_certs(
        &base,
        chain_of(&["leaf-tls", "inter"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    // A leaf whose key usage lacks digitalSignature: the sub-CA, used as a
    // signer (keyCertSign and cRLSign only).
    let no_ds = with_certs(
        &base,
        chain_of(&["inter-sub", "inter"]),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(
        &report_of(vec![tls_ca, tls_leaf, no_ds]),
        &config(&["root"]),
        None,
    );
    assert_eq!(trust.primary, None);
    assert_eq!(
        trust.signers[0].untrusted,
        [UntrustedReason::CodeSigningNotPermitted]
    );
    assert_eq!(
        trust.signers[1].untrusted,
        [UntrustedReason::CodeSigningNotPermitted]
    );
    assert_eq!(
        trust.signers[2].untrusted,
        [UntrustedReason::SignerKeyUsage]
    );
    assert!(
        trust
            .signers
            .iter()
            .all(|s| s.chain.as_ref().unwrap().full_chain.anchored)
    );
}

#[test]
fn primary_ranks_by_the_weaker_digest() {
    let base = signed(&p7("leaf-inter-root"));
    let certs = || chain_of(&["leaf", "inter"]);
    // SHA-256 image digest but a SHA-1 SignerInfo digest, then a full
    // SHA-256 signature: the second is stronger.
    let mixed = with_certs(
        &base,
        certs(),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha1,
    );
    let full = with_certs(
        &base,
        certs(),
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha256,
    );
    let trust = evaluate_trust(
        &report_of(vec![mixed.clone(), full.clone()]),
        &config(&["root"]),
        None,
    );
    assert_eq!(trust.primary, Some(1));
    // Equal strength: the first wins.
    let trust = evaluate_trust(
        &report_of(vec![full.clone(), full]),
        &config(&["root"]),
        None,
    );
    assert_eq!(trust.primary, Some(0));
    let trust = evaluate_trust(&report_of(vec![mixed]), &config(&["root"]), None);
    assert_eq!(trust.primary, Some(0));
}

#[test]
fn eku_values_for_os_policy() {
    let e = palisade_fileid::authenticode::Eku::new(
        ObjectId::from_dotted("1.3.6.1.4.1.311.10.3.5").unwrap(),
    );
    assert_eq!(e.name, Some("Hardware Driver Certification"));
    assert_eq!(e.os_policy_value().unwrap(), "010A2B0601040182370A0305");
}

// --- Properties. -------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Re-encoding a certificate (taking it apart into `tbsCertificate`,
    /// `signatureAlgorithm` and `signatureValue`, and encoding the SEQUENCE
    /// again; and separately, a PEM round trip) and re-parsing it gives the
    /// same TBS hash. The TBS hash never depends on anything outside
    /// `tbsCertificate`.
    #[test]
    fn tbs_hash_is_stable(index in 0_usize..64, flip in 0_usize..256) {
        let expected = expected();
        let mut names: Vec<&String> = expected.keys().collect();
        names.sort();
        let name = names[index % names.len()];
        let original = der(name);
        let a = CertSummary::from_der(&original).unwrap();
        // Re-encode from the parts.
        let (h, len) = header(&original, 0);
        let mut parts = Vec::new();
        let mut at = h;
        while at < h + len {
            let (ph, pl) = header(&original, at);
            parts.push(original[at..at + ph + pl].to_vec());
            at += ph + pl;
        }
        prop_assert_eq!(parts.len(), 3);
        let content = parts.concat();
        let mut reencoded = vec![0x30];
        reencoded.extend(encode_len(content.len()));
        reencoded.extend(content);
        prop_assert_eq!(&reencoded, &original);
        let r = CertSummary::from_der(&reencoded).unwrap();
        prop_assert_eq!(&a.tbs_hash, &r.tbs_hash);
        prop_assert_eq!(&a, &r);
        // Round trip through the PEM export.
        let body: String = a.pem().lines().filter(|l| !l.starts_with("-----")).collect();
        let decoded = decode_base64(&body);
        prop_assert_eq!(&decoded, &original);
        let b = CertSummary::from_der(&decoded).unwrap();
        prop_assert_eq!(&a.tbs_hash, &b.tbs_hash);
        prop_assert_eq!(&a.tbs_hash_sha256, &b.tbs_hash_sha256);
        // Changing a signature bit changes the thumbprint but not the TBS
        // hash.
        let mut changed = original.clone();
        let last = changed.len() - 1 - (flip % 32);
        changed[last] ^= 0x01;
        let c = CertSummary::from_der(&changed).unwrap();
        prop_assert_eq!(&a.tbs_hash, &c.tbs_hash);
        prop_assert_ne!(&a.sha256_thumbprint, &c.sha256_thumbprint);
    }

    /// No input panics the certificate parser or the chain builder.
    #[test]
    fn hostile_certificates_never_panic(
        index in 0_usize..64,
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
    ) {
        let expected = expected();
        let mut names: Vec<&String> = expected.keys().collect();
        names.sort();
        let mut bytes = der(names[index % names.len()]);
        for (at, value) in edits {
            let i = at % bytes.len();
            bytes[i] = value;
        }
        let _ = CertSummary::from_der(&bytes);
        let certs = vec![bytes, der("inter"), der("root")];
        let _ = build_chain(&certs, 0, &config(&["root"]));
    }
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn decode_base64(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    };
    let bytes: Vec<u8> = text.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let v = chunk.iter().enumerate().fold(0_u32, |acc, (i, c)| {
            acc | (u32::from(value(*c)) << (18 - 6 * i))
        });
        let n = chunk.len().saturating_sub(1);
        for i in 0..n {
            out.push((v >> (16 - 8 * i)) as u8);
        }
    }
    out
}
