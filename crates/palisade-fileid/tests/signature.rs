//! Authenticode signature parsing and verification tests (#48).
//!
//! The fixtures in `fixtures/authenticode` are PKCS#7 SignedData blobs made
//! by osslsigncode over `PeBuilder::default()`, with throwaway keys from a
//! test-only CA; `generate.sh` there documents and reproduces them. Only the
//! signatures are committed. Each test rebuilds the image and attaches a
//! signature as its certificate table, so a signature is checked against
//! the exact bytes it signed.
//!
//! Negative cases are made by editing a good signature here: the DER walker
//! below finds an element by path, and `replace` rewrites it and fixes every
//! enclosing length.

// Test code: fixture sizes are small constants, and helpers may unwrap or
// index, since a failure should fail loudly.
#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    Asn1ErrorKind, AuthenticodeStatus, BadSignature, CertificateTableError, Curve, DigestAlgorithm,
    InvalidReason, KeyAlgorithm, MAX_CERTIFICATE_ENTRIES, MAX_NESTING_DEPTH, MAX_SIGNATURES,
    MAX_WARNINGS, NonConformance, OsCiIssue, ReportWarning, SignatureAlgorithm, SignatureCheck,
    SignatureError, SignatureKind, SignatureReport, SignatureStatus, SignatureWarning,
    SignerIdentifier, SigningState, StatementType, TimestampKind, Unsupported, VerifyOptions,
    authenticode_hashes, verify_certificate_table, verify_pe, verify_signatures,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm};
use palisade_fileid::pe;
use proptest::prelude::*;
use sha2::{Digest as _, Sha256};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/authenticode");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// A `WIN_CERTIFICATE` entry: header, data, zero padding to 8 bytes.
fn entry(revision: u16, kind: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&revision.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

fn pkcs7_entry(data: &[u8]) -> Vec<u8> {
    entry(0x0200, 2, data)
}

/// The default image with `table` as its certificate table.
fn image_with_table(table: Vec<u8>) -> Vec<u8> {
    PeBuilder {
        certificate: Some(table),
        ..PeBuilder::default()
    }
    .build()
}

fn verify(image: &[u8]) -> SignatureReport {
    verify_pe(image, &VerifyOptions::default()).unwrap()
}

fn verify_blob(blob: &[u8]) -> SignatureReport {
    verify(&image_with_table(pkcs7_entry(blob)))
}

fn only(report: &SignatureReport) -> &palisade_fileid::authenticode::SignatureInfo {
    assert_eq!(report.signatures.len(), 1, "{report:#?}");
    &report.signatures[0]
}

// --- A small DER editor for building negative cases. -----------------------

/// Header length, content length.
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

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(encode_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// The offset of the element at `path`: each step is the index of a child
/// within the previous element.
fn locate(der: &[u8], path: &[usize]) -> usize {
    let mut at = 0;
    for &index in path {
        let (h, _) = header(der, at);
        let mut child = at + h;
        for _ in 0..index {
            let (ch, cl) = header(der, child);
            child += ch + cl;
        }
        at = child;
    }
    at
}

/// The whole encoding of the element at `path`.
fn element<'a>(der: &'a [u8], path: &[usize]) -> &'a [u8] {
    let at = locate(der, path);
    let (h, l) = header(der, at);
    &der[at..at + h + l]
}

/// Replaces the element at `path` with `new` (a whole encoding, or nothing
/// to delete it), fixing every enclosing length.
fn replace(der: &[u8], path: &[usize], new: &[u8]) -> Vec<u8> {
    if path.is_empty() {
        return new.to_vec();
    }
    let parent_path = &path[..path.len() - 1];
    let parent = element(der, parent_path);
    let (ph, _) = header(parent, 0);
    let start = locate(parent, &path[path.len() - 1..]);
    let (h, l) = header(parent, start);
    let mut content = parent[ph..start].to_vec();
    content.extend_from_slice(new);
    content.extend_from_slice(&parent[start + h + l..]);
    replace(der, parent_path, &tlv(parent[0], &content))
}

// Paths into an osslsigncode SignedData.
const SIGNED_DATA: [usize; 2] = [1, 0];
fn sd(rest: &[usize]) -> Vec<usize> {
    [&SIGNED_DATA[..], rest].concat()
}
/// SignedData children: version, digestAlgorithms, contentInfo,
/// certificates, signerInfos.
const SD_CONTENT_INFO: usize = 2;
const SD_CERTIFICATES: usize = 3;
const SD_SIGNER_INFOS: usize = 4;
/// SignerInfo children: version, sid, digestAlgorithm, [0] attributes,
/// signatureAlgorithm, signature, [1] unauthenticated.
const SI_ATTRS: usize = 3;
const SI_SIG_ALG: usize = 4;
const SI_SIGNATURE: usize = 5;
fn signer(rest: &[usize]) -> Vec<usize> {
    sd(&[&[SD_SIGNER_INFOS, 0][..], rest].concat())
}
/// SpcIndirectDataContent: contentInfo [2] -> [0] -> SEQUENCE.
fn indirect(rest: &[usize]) -> Vec<usize> {
    sd(&[&[SD_CONTENT_INFO, 1, 0][..], rest].concat())
}

// --- Valid signatures. -------------------------------------------------------

#[test]
fn rsa_sha256_signature_is_valid() {
    let blob = fixture("rsa2048-sha256.p7");
    let report = verify_blob(&blob);
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    assert_eq!(sig.signature_valid, SignatureCheck::Valid);
    assert_eq!(sig.digest_match, Some(true));
    assert_eq!(
        (sig.index, sig.total, sig.kind),
        (0, 1, SignatureKind::Embedded)
    );
    assert_eq!(sig.digest_alg, Some(DigestAlgorithm::Sha256));
    assert_eq!(sig.signer_digest_alg, Some(DigestAlgorithm::Sha256));
    assert_eq!(
        sig.sig_alg,
        Some(SignatureAlgorithm::RsaPkcs1(DigestAlgorithm::Sha256))
    );
    assert_eq!(sig.key_alg, Some(KeyAlgorithm::Rsa));
    assert_eq!(sig.key_bits, Some(2048));
    assert!(sig.os_ci_compatible());
    assert_eq!(sig.certs_in_blob.len(), 2);
    assert!(matches!(
        sig.signer_id,
        Some(SignerIdentifier::IssuerAndSerial { .. })
    ));
    let signer = sig.signer.as_ref().unwrap();
    assert_eq!(signer.program_name.as_deref(), Some("Palisade Test App"));
    assert_eq!(
        signer.more_info_url.as_deref(),
        Some("https://example.test/app")
    );
    assert_eq!(signer.statement_type, Some(StatementType::Individual));
    assert_eq!(signer.signing_time, Some(1_700_000_000));
    assert!(!sig.untrusted_signer_attrs);
    assert!(sig.page_hashes.is_none() && sig.timestamp_tokens.is_empty());
    assert_eq!(sig.warnings, []);
    assert_eq!(report.primary, Some(0));
    assert_eq!(report.signing_state, SigningState::Valid);
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].signature, Some(0));
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);

    // The signer certificate is the leaf, not the CA.
    let leaf = &sig.certs_in_blob[signer.signer_cert];
    assert!(leaf.windows(b"Signer".len()).any(|w| w == b"Signer"));
}

#[test]
fn signed_image_digest_is_the_authenticode_digest() {
    let image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    let info = pe::parse(&image).unwrap();
    let hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
    let report = verify_signatures(&image, &info, &VerifyOptions::default()).unwrap();
    assert_eq!(
        only(&report).signed_image_digest.as_deref(),
        Some(hashes.sha256().unwrap().as_bytes())
    );
    // And it is unchanged by the signature: the unsigned image hashes the same.
    let unsigned = PeBuilder::default().build();
    let bare = palisade_fileid::authenticode::hash_pe(&unsigned, AlgorithmSet::EMPTY).unwrap();
    assert_eq!(bare.sha256(), hashes.sha256());
}

#[test]
fn every_rsa_digest_verifies() {
    for (name, alg, statement) in [
        (
            "rsa2048-sha384-commercial.p7",
            DigestAlgorithm::Sha384,
            StatementType::Commercial,
        ),
        (
            "rsa2048-sha512.p7",
            DigestAlgorithm::Sha512,
            StatementType::Individual,
        ),
        (
            "rsa4096-sha256.p7",
            DigestAlgorithm::Sha256,
            StatementType::Individual,
        ),
    ] {
        let report = verify_blob(&fixture(name));
        let sig = only(&report);
        assert_eq!(sig.status, SignatureStatus::Valid, "{name}: {sig:#?}");
        assert_eq!(sig.digest_alg, Some(alg), "{name}");
        assert!(sig.os_ci_compatible(), "{name}");
        assert_eq!(
            sig.signer.as_ref().unwrap().statement_type,
            Some(statement),
            "{name}"
        );
    }
}

#[test]
fn ecdsa_p256_and_p384_verify_but_are_not_os_ci_compatible() {
    for (name, curve, bits) in [
        ("p256-sha256.p7", Curve::P256, 256),
        ("p384-sha384.p7", Curve::P384, 384),
    ] {
        let report = verify_blob(&fixture(name));
        let sig = only(&report);
        assert_eq!(sig.status, SignatureStatus::Valid, "{name}: {sig:#?}");
        assert!(matches!(sig.sig_alg, Some(SignatureAlgorithm::Ecdsa(_))));
        assert_eq!(sig.key_alg, Some(KeyAlgorithm::Ec(curve)));
        assert_eq!(sig.key_bits, Some(bits));
        assert!(!sig.os_ci_compatible());
        assert_eq!(
            sig.os_ci_issues,
            [OsCiIssue::NotRsa(KeyAlgorithm::Ec(curve))]
        );
        assert_eq!(report.signing_state, SigningState::Valid);
    }
}

#[test]
fn p521_is_unsupported_never_valid() {
    let report = verify_blob(&fixture("p521-sha512.p7"));
    let sig = only(&report);
    assert_eq!(
        sig.status,
        SignatureStatus::Unsupported(Unsupported::Curve(Curve::P521))
    );
    assert_eq!(
        sig.signature_valid,
        SignatureCheck::Unsupported(Unsupported::Curve(Curve::P521))
    );
    assert_eq!(sig.key_alg, Some(KeyAlgorithm::Ec(Curve::P521)));
    assert!(!sig.os_ci_compatible());
    assert!(sig.signer.is_none());
    assert_eq!(report.primary, None);
    assert!(matches!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::Signature(SignatureStatus::Unsupported(_)))
    ));
}

#[test]
fn rsa_over_4096_bits_verifies_but_is_not_os_ci_compatible() {
    let report = verify_blob(&fixture("rsa8192-sha256.p7"));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert_eq!(sig.key_bits, Some(8192));
    assert_eq!(sig.os_ci_issues, [OsCiIssue::RsaKeyTooLarge(8192)]);
}

#[test]
fn md5_is_weak_and_never_trusted() {
    let report = verify_blob(&fixture("rsa2048-md5.p7"));
    let sig = only(&report);
    assert_eq!(
        sig.status,
        SignatureStatus::WeakAlgorithm(DigestAlgorithm::Md5)
    );
    assert_eq!(sig.digest_alg, Some(DigestAlgorithm::Md5));
    // The digest does match: weak is reported regardless.
    assert_eq!(sig.digest_match, Some(true));
    assert!(
        sig.os_ci_issues
            .contains(&OsCiIssue::WeakDigest(DigestAlgorithm::Md5))
    );
    assert!(sig.signer.is_none());
    assert_eq!(report.primary, None);
}

#[test]
fn rsa_pss_verifies() {
    let blob = fixture("rsa2048-sha256.p7");
    let pss_sig = fixture("rsa2048-sha256.pss-signature");
    // RSASSA-PSS-params: SHA-256, MGF1-SHA-256, salt 32.
    let sha256_id = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let mgf1 = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08],
            ),
            sha256_id.clone(),
        ]
        .concat(),
    );
    let pss_oid = tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
    );
    let params = |salt: u8| {
        tlv(
            0x30,
            &[
                tlv(0xa0, &sha256_id),
                tlv(0xa1, &mgf1),
                tlv(0xa2, &tlv(0x02, &[salt])),
            ]
            .concat(),
        )
    };
    let with_pss = |salt: u8| {
        let alg = tlv(0x30, &[pss_oid.clone(), params(salt)].concat());
        let b = replace(&blob, &signer(&[SI_SIG_ALG]), &alg);
        replace(&b, &signer(&[SI_SIGNATURE]), &tlv(0x04, &pss_sig))
    };

    let report = verify_blob(&with_pss(32));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    assert_eq!(
        sig.sig_alg,
        Some(SignatureAlgorithm::RsaPss {
            digest: DigestAlgorithm::Sha256,
            mgf1_digest: DigestAlgorithm::Sha256,
            salt_len: 32
        })
    );

    // A salt length ring does not verify is unsupported, not valid.
    let report = verify_blob(&with_pss(20));
    assert_eq!(
        only(&report).status,
        SignatureStatus::Unsupported(Unsupported::PssParameters)
    );

    // A PSS signature labelled as PKCS#1 v1.5 fails.
    let b = replace(&blob, &signer(&[SI_SIGNATURE]), &tlv(0x04, &pss_sig));
    assert_eq!(
        only(&verify_blob(&b)).status,
        SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
    );
}

#[test]
fn ed25519_signer_is_unsupported() {
    let blob = fixture("rsa2048-sha256.p7");
    let ed_cert = fixture("ed25519-leaf.der");
    // Put the Ed25519 certificate first and point the SignerInfo at it.
    let certs = element(&blob, &sd(&[SD_CERTIFICATES]));
    let (h, _) = header(certs, 0);
    let mut content = ed_cert.clone();
    content.extend_from_slice(&certs[h..]);
    let b = replace(&blob, &sd(&[SD_CERTIFICATES]), &tlv(0xa0, &content));
    // tbsCertificate: [0] version, serial, sigalg, issuer.
    let issuer = element(&ed_cert, &[0, 3]).to_vec();
    let serial = element(&ed_cert, &[0, 1]).to_vec();
    let b = replace(&b, &signer(&[1]), &tlv(0x30, &[issuer, serial].concat()));
    let ed_alg = tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70]));
    let b = replace(&b, &signer(&[SI_SIG_ALG]), &ed_alg);
    let b = replace(&b, &signer(&[SI_SIGNATURE]), &tlv(0x04, &[0; 64]));

    let report = verify_blob(&b);
    let sig = only(&report);
    assert_eq!(sig.key_alg, Some(KeyAlgorithm::Ed25519));
    assert_eq!(sig.sig_alg, Some(SignatureAlgorithm::Ed25519));
    assert_eq!(
        sig.status,
        SignatureStatus::Unsupported(Unsupported::SignatureAlgorithm(SignatureAlgorithm::Ed25519))
    );
    assert_eq!(sig.os_ci_issues, [OsCiIssue::NotRsa(KeyAlgorithm::Ed25519)]);
    assert_eq!(report.primary, None);
}

// --- Nested and multiple signatures. ----------------------------------------

#[test]
fn dual_signed_reports_both_and_prefers_sha256() {
    let report = verify_blob(&fixture("rsa2048-sha1-nested-sha256.p7"));
    assert_eq!(report.signatures.len(), 2, "{report:#?}");
    let (outer, inner) = (&report.signatures[0], &report.signatures[1]);
    assert_eq!(
        (outer.index, outer.total, outer.kind, outer.depth),
        (0, 2, SignatureKind::Embedded, 0)
    );
    assert_eq!(
        (inner.index, inner.total, inner.kind, inner.depth),
        (1, 2, SignatureKind::Nested, 1)
    );
    assert_eq!(inner.parent, Some(0));
    assert_eq!(outer.digest_alg, Some(DigestAlgorithm::Sha1));
    assert_eq!(inner.digest_alg, Some(DigestAlgorithm::Sha256));
    assert!(
        outer.status.is_valid() && inner.status.is_valid(),
        "{report:#?}"
    );
    assert!(outer.warnings.contains(&SignatureWarning::Sha1Digest));
    assert_eq!(report.primary, Some(1));
    assert_eq!(report.signing_state, SigningState::Valid);
}

#[test]
fn multiple_entries_are_all_read() {
    let mut table = pkcs7_entry(&fixture("rsa2048-sha256.p7"));
    table.extend(pkcs7_entry(&fixture("p256-sha256.p7")));
    let report = verify(&image_with_table(table));
    assert_eq!(report.entries.len(), 2);
    assert_eq!(report.signatures.len(), 2);
    assert!(
        report
            .signatures
            .iter()
            .all(|s| s.status.is_valid() && s.total == 2)
    );
    assert_eq!(report.signatures[1].entry, 1);
    assert_eq!(report.entries[1].signature, Some(1));
    // Same strength, so the first wins.
    assert_eq!(report.primary, Some(0));
}

#[test]
fn primary_skips_invalid_signatures() {
    let mut table = pkcs7_entry(&fixture("p521-sha512.p7"));
    table.extend(pkcs7_entry(&fixture("rsa2048-sha512.p7")));
    let report = verify(&image_with_table(table));
    assert_eq!(report.primary, Some(1));
    assert_eq!(report.signing_state, SigningState::Valid);
}

/// Wraps `inner` (a ContentInfo) as a nested signature of `outer`.
fn nest(outer: &[u8], inner: &[u8]) -> Vec<u8> {
    let nested_oid = tlv(
        0x06,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01],
    );
    let attr = tlv(0x30, &[nested_oid, tlv(0x31, inner)].concat());
    let si = element(outer, &signer(&[]));
    let (h, _) = header(si, 0);
    let mut content = si[h..].to_vec();
    content.extend(tlv(0xa1, &attr));
    replace(outer, &signer(&[]), &tlv(0x30, &content))
}

#[test]
fn nesting_is_bounded_by_depth() {
    let leaf = fixture("rsa2048-sha256.p7");
    let mut blob = leaf.clone();
    for _ in 0..(MAX_NESTING_DEPTH as usize + 3) {
        blob = nest(&leaf, &blob);
    }
    let report = verify_blob(&blob);
    assert_eq!(report.signatures.len(), MAX_NESTING_DEPTH as usize + 1);
    let deepest = report.signatures.last().unwrap();
    assert_eq!(deepest.depth, MAX_NESTING_DEPTH);
    assert!(deepest.warnings.contains(&SignatureWarning::NestingTooDeep));
    assert!(report.signatures.iter().all(|s| s.status.is_valid()));
}

#[test]
fn signatures_are_bounded_in_total() {
    let leaf = fixture("rsa2048-sha256.p7");
    // One embedded signature carrying 40 nested ones, side by side.
    let nested_oid = tlv(
        0x06,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01],
    );
    let values: Vec<u8> = std::iter::repeat_n(leaf.clone(), 40).flatten().collect();
    let attr = tlv(0x30, &[nested_oid, tlv(0x31, &values)].concat());
    let si = element(&leaf, &signer(&[]));
    let (h, _) = header(si, 0);
    let mut content = si[h..].to_vec();
    content.extend(tlv(0xa1, &attr));
    let blob = replace(&leaf, &signer(&[]), &tlv(0x30, &content));
    let report = verify_blob(&blob);
    assert_eq!(report.signatures.len(), MAX_SIGNATURES);
    assert!(report.warnings.contains(&ReportWarning::TooManySignatures));
    assert!(report.signatures.iter().all(|s| s.total == MAX_SIGNATURES));
}

#[test]
fn entries_are_bounded() {
    let blob = fixture("rsa2048-sha256.p7");
    let table: Vec<u8> = std::iter::repeat_n(pkcs7_entry(&blob), MAX_CERTIFICATE_ENTRIES + 2)
        .flatten()
        .collect();
    let report = verify(&image_with_table(table));
    assert_eq!(report.entries.len(), MAX_CERTIFICATE_ENTRIES);
    assert!(report.warnings.contains(&ReportWarning::TooManyEntries));
}

// --- Other attributes. --------------------------------------------------------

#[test]
fn page_hashes_are_extracted() {
    let report = verify_blob(&fixture("rsa2048-page-hashes.p7"));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    let page = sig.page_hashes.as_ref().unwrap();
    assert_eq!(page.algorithm, HashAlgorithm::Sha256);
    let entries: Vec<(u32, &[u8])> = page.entries().collect();
    assert!(entries.len() >= 2);
    // The table starts at offset 0 and ends with a zero digest at the end
    // of the hashed data.
    assert_eq!(entries[0].0, 0);
    let (last_offset, last_digest) = *entries.last().unwrap();
    assert!(last_offset > 0 && last_digest.iter().all(|b| *b == 0));
    assert!(entries.windows(2).all(|w| w[0].0 < w[1].0));
}

#[test]
fn timestamp_tokens_are_kept_for_later() {
    let report = verify_blob(&fixture("rsa2048-timestamp.p7"));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert_eq!(sig.timestamp_tokens.len(), 1);
    assert_eq!(sig.timestamp_tokens[0].kind, TimestampKind::Rfc3161);
    assert_eq!(sig.timestamp_tokens[0].der[0], 0x30);
}

// --- Unsigned and table-level cases. -----------------------------------------

#[test]
fn unsigned_image() {
    let report = verify(&PeBuilder::default().build());
    assert_eq!(report.signing_state, SigningState::Unsigned);
    assert!(report.signatures.is_empty() && report.entries.is_empty());
    assert_eq!(report.primary, None);
}

#[test]
fn unknown_entries_are_recorded_and_skipped() {
    let mut table = entry(0x0200, 0x0001, b"X509....");
    table.extend(entry(0x0300, 0x0002, &fixture("rsa2048-sha256.p7")));
    let report = verify(&image_with_table(table));
    assert_eq!(report.entries.len(), 2);
    assert!(report.signatures.is_empty());
    assert_eq!(
        report.warnings,
        [
            ReportWarning::UnknownEntry { entry: 0 },
            ReportWarning::UnknownEntry { entry: 1 }
        ]
    );
    assert_eq!(report.signing_state, SigningState::Unsigned);
}

#[test]
fn revision_1_entries_are_read() {
    let report = verify(&image_with_table(entry(
        0x0100,
        2,
        &fixture("rsa2048-sha256.p7"),
    )));
    assert_eq!(only(&report).status, SignatureStatus::Valid);
}

#[test]
fn bad_entry_lengths_stop_the_walk() {
    for length in [0_u32, 7, 0x10_0000] {
        let mut table = pkcs7_entry(&fixture("rsa2048-sha256.p7"));
        table[..4].copy_from_slice(&length.to_le_bytes());
        let report = verify(&image_with_table(table));
        assert!(report.signatures.is_empty());
        assert!(matches!(
            report.signing_state,
            SigningState::Invalid(InvalidReason::CertificateTable(
                CertificateTableError::Malformed { .. }
            ))
        ));
    }
}

#[test]
fn hidden_data_is_flagged() {
    // Non-zero bytes after the last entry, too short to be another entry.
    let mut table = pkcs7_entry(&fixture("rsa2048-sha256.p7"));
    let tail = table.len() as u64;
    table.extend_from_slice(&[0xcc; 4]);
    let image = image_with_table(table);
    let table_offset = pe::parse(&image).unwrap().certificate_table.unwrap().offset;
    let report = verify(&image);
    assert_eq!(
        report.warnings,
        [ReportWarning::UnexpectedTableData {
            offset: table_offset + tail
        }]
    );
    assert_eq!(report.signing_state, SigningState::Valid);
    // Data inside the entry after the SignedData.
    let mut blob = fixture("rsa2048-sha256.p7");
    blob.extend_from_slice(b"hidden payload");
    let report = verify_blob(&blob);
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert!(sig.warnings.contains(&SignatureWarning::TrailingData {
        len: 14,
        all_zero: false
    }));
}

#[test]
fn rejected_certificate_table_makes_the_file_invalid() {
    let mut image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    let dir = PeBuilder::default().data_directory_offset(4);
    // Point the table into the headers.
    image[dir..dir + 4].copy_from_slice(&0x100_u32.to_le_bytes());
    let report = verify(&image);
    assert!(matches!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::CertificateTable(
            CertificateTableError::Rejected(_)
        ))
    ));
}

// --- Tampering. -----------------------------------------------------------------

#[test]
fn patched_image_reports_digest_mismatch() {
    let mut image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    image[0x400] ^= 0xff; // the first byte of .text
    let report = verify(&image);
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::DigestMismatch);
    assert_eq!(sig.signature_valid, SignatureCheck::Valid);
    assert_eq!(sig.digest_match, Some(false));
    assert!(sig.signer.is_none() && !sig.untrusted_signer_attrs);
    assert_eq!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::Signature(SignatureStatus::DigestMismatch))
    );
}

#[test]
fn tolerate_digest_mismatch_exposes_untrusted_attributes() {
    let mut image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    image[0x400] ^= 0xff;
    let options = VerifyOptions {
        tolerate_digest_mismatch: true,
    };
    let report = verify_pe(&image, &options).unwrap();
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::DigestMismatch);
    assert!(sig.untrusted_signer_attrs);
    assert_eq!(
        sig.signer.as_ref().unwrap().program_name.as_deref(),
        Some("Palisade Test App")
    );
    // Still invalid, still no primary, and audited.
    assert_eq!(report.primary, None);
    assert!(matches!(report.signing_state, SigningState::Invalid(_)));
    assert!(report.tolerate_digest_mismatch);
    assert_eq!(
        report.warnings,
        [ReportWarning::DigestMismatchTolerated { signature: 0 }]
    );

    // The knob never exposes the attributes of a bad signature.
    let blob = fixture("rsa2048-sha256.p7");
    let sig_at = signer(&[SI_SIGNATURE]);
    let mut bad = element(&blob, &sig_at).to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let bad = replace(&blob, &sig_at, &bad);
    let report = verify_pe(&image_with_table(pkcs7_entry(&bad)), &options).unwrap();
    let sig = only(&report);
    assert!(sig.signer.is_none() && !sig.untrusted_signer_attrs);
}

#[test]
fn signature_over_a_different_file_mismatches() {
    let other =
        PeBuilder::default().section(".data", vec![1, 2, 3], IMAGE_SCN_CNT_INITIALIZED_DATA);
    let image = PeBuilder {
        certificate: Some(pkcs7_entry(&fixture("rsa2048-sha256.p7"))),
        ..other
    }
    .build();
    assert_eq!(
        only(&verify(&image)).status,
        SignatureStatus::DigestMismatch
    );
}

#[test]
fn tampered_signature_is_invalid() {
    let blob = fixture("rsa2048-sha256.p7");
    let at = signer(&[SI_SIGNATURE]);
    let mut sig = element(&blob, &at).to_vec();
    let last = sig.len() - 1;
    sig[last] ^= 0x01;
    let report = verify_blob(&replace(&blob, &at, &sig));
    assert_eq!(
        only(&report).status,
        SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
    );
    assert!(only(&report).signer.is_none());
}

#[test]
fn changed_indirect_data_fails_the_message_digest() {
    let blob = fixture("rsa2048-sha256.p7");
    // Flip a byte of the signed image digest: the signer's messageDigest no
    // longer matches the indirect data.
    let at = indirect(&[1, 1]);
    let mut digest = element(&blob, &at).to_vec();
    digest[5] ^= 0xff;
    let report = verify_blob(&replace(&blob, &at, &digest));
    assert_eq!(
        only(&report).status,
        SignatureStatus::BadSignature(BadSignature::MessageDigestMismatch)
    );
}

#[test]
fn reordered_authenticated_attributes_break_the_signature() {
    let blob = fixture("rsa2048-sha256.p7");
    let attrs = element(&blob, &signer(&[SI_ATTRS]));
    let (h, _) = header(attrs, 0);
    let mut children = Vec::new();
    let mut at = h;
    while at < attrs.len() {
        let (ch, cl) = header(attrs, at);
        children.push(attrs[at..at + ch + cl].to_vec());
        at += ch + cl;
    }
    children.swap(0, 1);
    let reordered = tlv(0xa0, &children.concat());
    let report = verify_blob(&replace(&blob, &signer(&[SI_ATTRS]), &reordered));
    assert_eq!(
        only(&report).status,
        SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
    );
}

#[test]
fn swapped_signer_certificate() {
    let blob = fixture("rsa2048-sha256.p7");
    let other = fixture("rsa4096-sha256.p7");
    // Replace the certificates with another signer's: no certificate matches.
    let certs = element(&other, &sd(&[SD_CERTIFICATES])).to_vec();
    let report = verify_blob(&replace(&blob, &sd(&[SD_CERTIFICATES]), &certs));
    assert_eq!(
        only(&report).status,
        SignatureStatus::BadSignature(BadSignature::SignerCertificateNotFound)
    );
    // Point the SignerInfo at the other signer's certificate: the key is wrong.
    let b = replace(&blob, &sd(&[SD_CERTIFICATES]), &certs);
    let sid = element(&other, &signer(&[1])).to_vec();
    let report = verify_blob(&replace(&b, &signer(&[1]), &sid));
    let sig = only(&report);
    assert_eq!(
        sig.status,
        SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
    );
    assert_eq!(sig.key_bits, Some(4096));
}

// --- Malformed input. --------------------------------------------------------------

fn malformed(report: &SignatureReport) -> &SignatureError {
    match &only(report).status {
        SignatureStatus::Malformed(e) => e,
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn truncated_blobs_are_malformed() {
    let blob = fixture("rsa2048-sha256.p7");
    for len in [0, 1, 2, 10, 100, blob.len() / 2, blob.len() - 1] {
        let report = verify_blob(&blob[..len]);
        if len == 0 {
            // An empty entry: nothing to parse, still a signature attempt.
            assert!(matches!(
                only(&report).status,
                SignatureStatus::Malformed(_)
            ));
            continue;
        }
        let e = malformed(&report);
        assert!(
            matches!(e, SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::Truncated),
            "{len}: {e:?}"
        );
        assert!(matches!(report.signing_state, SigningState::Invalid(_)));
    }
}

#[test]
fn ber_indefinite_length_is_rejected() {
    let blob = fixture("rsa2048-sha256.p7");
    // Re-encode the outer SEQUENCE with an indefinite length.
    let (h, _) = header(&blob, 0);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&blob[h..]);
    ber.extend_from_slice(&[0, 0]);
    let e = malformed(&verify_blob(&ber)).clone();
    assert!(matches!(e, SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::IndefiniteLength));
}

#[test]
fn oversized_length_is_rejected() {
    let mut blob = fixture("rsa2048-sha256.p7");
    // The outer length claims 0x7fffff00 bytes.
    let (h, _) = header(&blob, 0);
    assert_eq!(h, 4);
    blob.splice(1..4, [0x84, 0x7f, 0xff, 0xff, 0x00]);
    let e = malformed(&verify_blob(&blob)).clone();
    assert!(matches!(e, SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::Truncated));
}

#[test]
fn structural_errors_are_typed() {
    let blob = fixture("rsa2048-sha256.p7");
    let data_oid = tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
    );
    assert!(matches!(
        malformed(&verify_blob(&replace(&blob, &[0], &data_oid))),
        SignatureError::NotSignedData(_)
    ));
    assert!(matches!(
        malformed(&verify_blob(&replace(
            &blob,
            &sd(&[SD_CONTENT_INFO, 0]),
            &data_oid
        ))),
        SignatureError::NotIndirectData(_)
    ));
    // Two SignerInfos.
    let si = element(&blob, &signer(&[])).to_vec();
    let two = tlv(0x31, &[si.clone(), si].concat());
    assert_eq!(
        malformed(&verify_blob(&replace(&blob, &sd(&[SD_SIGNER_INFOS]), &two))),
        &SignatureError::SignerCount(2)
    );
    // No SignerInfo.
    assert_eq!(
        malformed(&verify_blob(&replace(
            &blob,
            &sd(&[SD_SIGNER_INFOS]),
            &[0x31, 0x00]
        ))),
        &SignatureError::SignerCount(0)
    );
    // No authenticated attributes.
    assert_eq!(
        malformed(&verify_blob(&replace(&blob, &signer(&[SI_ATTRS]), &[]))),
        &SignatureError::MissingAuthenticatedAttributes
    );
    // A duplicated authenticated attribute.
    let attrs = element(&blob, &signer(&[SI_ATTRS]));
    let first = element(attrs, &[0]).to_vec();
    let (h, _) = header(attrs, 0);
    let dup = tlv(0xa0, &[first, attrs[h..].to_vec()].concat());
    assert!(matches!(
        malformed(&verify_blob(&replace(&blob, &signer(&[SI_ATTRS]), &dup))),
        SignatureError::DuplicateAttribute(_)
    ));
    // A signed image digest of the wrong length.
    let short = tlv(0x04, &[0; 31]);
    assert_eq!(
        malformed(&verify_blob(&replace(&blob, &indirect(&[1, 1]), &short))),
        &SignatureError::DigestLength
    );
    // A signature algorithm whose digest disagrees with the signer's.
    let sha1_rsa = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    assert_eq!(
        malformed(&verify_blob(&replace(
            &blob,
            &signer(&[SI_SIG_ALG]),
            &sha1_rsa
        ))),
        &SignatureError::InconsistentDigestAlgorithms
    );
}

#[test]
fn certificate_table_hash_is_checked_separately() {
    // verify_certificate_table with no image digests: never valid.
    let image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    let info = pe::parse(&image).unwrap();
    let mut hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
    hashes.digests.clear();
    let report = verify_certificate_table(&image, &info, &hashes, &VerifyOptions::default());
    assert_eq!(
        only(&report).status,
        SignatureStatus::Unsupported(Unsupported::ImageDigestUnavailable(DigestAlgorithm::Sha256))
    );
    assert_eq!(report.primary, None);
}

#[test]
fn indirect_data_digest_covers_the_content() {
    // Independent check of what messageDigest covers: SHA-256 of the
    // SpcIndirectDataContent's content octets.
    let blob = fixture("rsa2048-sha256.p7");
    let content = element(&blob, &indirect(&[]));
    let (h, _) = header(content, 0);
    let digest = Sha256::digest(&content[h..]);
    let attrs = element(&blob, &signer(&[SI_ATTRS]));
    assert!(attrs.windows(32).any(|w| w == digest.as_slice()));
}

// --- Round-1 review cases. ---------------------------------------------------

#[test]
fn warnings_stay_capped_with_trailing_data_and_nesting_limits() {
    let leaf = fixture("rsa2048-sha256.p7");
    // 40 distinct unknown authenticated attributes would overflow the cap;
    // they are unsigned additions here, so the signature breaks, which does
    // not matter for the warning list.
    let attrs = element(&leaf, &signer(&[SI_ATTRS]));
    let (h, _) = header(attrs, 0);
    let mut content = attrs[h..].to_vec();
    for i in 0..40_u8 {
        let oid = tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x00, i]);
        content.extend(tlv(0x30, &[oid, tlv(0x31, &[0x05, 0x00])].concat()));
    }
    let noisy = replace(&leaf, &signer(&[SI_ATTRS]), &tlv(0xa0, &content));
    // Too deep a nest under it, and data after it in the entry.
    let mut blob = noisy.clone();
    for _ in 0..(MAX_NESTING_DEPTH as usize + 2) {
        blob = nest(&noisy, &blob);
    }
    blob.extend_from_slice(b"hidden");
    let report = verify_blob(&blob);
    for sig in &report.signatures {
        assert!(
            sig.warnings.len() <= MAX_WARNINGS + 1,
            "{}",
            sig.warnings.len()
        );
        let truncated = sig
            .warnings
            .iter()
            .filter(|w| **w == SignatureWarning::WarningsTruncated)
            .count();
        assert_eq!(truncated, 1);
        assert_eq!(
            sig.warnings.last(),
            Some(&SignatureWarning::WarningsTruncated)
        );
    }
}

#[test]
fn short_or_corrupt_tables_are_malformed_not_unsigned() {
    for table in [
        vec![0_u8; 1],
        vec![0_u8; 7],
        vec![0xcc_u8; 5],
        vec![0_u8; 8],
    ] {
        let report = verify(&image_with_table(table.clone()));
        assert!(
            matches!(
                report.signing_state,
                SigningState::Invalid(InvalidReason::CertificateTable(
                    CertificateTableError::Malformed { .. }
                ))
            ),
            "{table:?}: {:?}",
            report.signing_state
        );
    }
    // An unknown entry, then a corrupt one: still not unsigned.
    let mut table = entry(0x0200, 0x0001, b"X509....");
    table.extend_from_slice(&3_u32.to_le_bytes());
    table.extend_from_slice(&[0; 4]);
    let report = verify(&image_with_table(table));
    assert!(matches!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::CertificateTable(
            CertificateTableError::Malformed { .. }
        ))
    ));
}

/// The rsa2048 leaf certificate of `rsa2048-sha256.p7` with its SPKI
/// algorithm changed to id-RSASSA-PSS, and the signer pointed at it. Only
/// the certificate's own signature (not checked here) is broken by this.
fn with_pss_restricted_key(blob: &[u8]) -> Vec<u8> {
    let certs = element(blob, &sd(&[SD_CERTIFICATES]));
    let leaf_index = (0..2)
        .find(|i| {
            let cert = element(certs, &[*i]);
            cert.windows(6).any(|w| w == b"Signer")
        })
        .unwrap();
    let cert = element(certs, &[leaf_index]).to_vec();
    // tbsCertificate children: [0] version, serial, sigalg, issuer, validity,
    // subject, spki. SPKI's AlgorithmIdentifier is [0, 6, 0].
    let pss = tlv(
        0x30,
        &tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
        ),
    );
    let cert = replace(&cert, &[0, 6, 0], &pss);
    replace(blob, &sd(&[SD_CERTIFICATES, leaf_index]), &cert)
}

#[test]
fn pss_restricted_keys_are_not_used_for_verification() {
    let blob = with_pss_restricted_key(&fixture("rsa2048-sha256.p7"));
    let report = verify_blob(&blob);
    let sig = only(&report);
    assert_eq!(sig.key_alg, Some(KeyAlgorithm::RsaPss));
    assert_eq!(
        sig.status,
        SignatureStatus::Unsupported(Unsupported::KeyAlgorithm(KeyAlgorithm::RsaPss))
    );
    assert!(sig.signer.is_none());
    assert_eq!(report.primary, None);
}

#[test]
fn malformed_der_in_the_pe_image_link_is_rejected() {
    let blob = fixture("rsa2048-sha256.p7");
    // SpcPeImageData is indirect [0] (SpcAttributeTypeAndOptionalValue) ->
    // [1] (the value SEQUENCE); its children are flags and [0] file.
    let file_at = indirect(&[0, 1, 1]);
    assert_eq!(element(&blob, &file_at)[0], 0xa0);
    // A [2] file link whose content is a truncated element.
    let bad = tlv(0xa0, &[0xa2, 0x05, 0x80, 0x01]);
    let report = verify_blob(&replace(&blob, &file_at, &bad));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::Truncated
    ));
    // Two links instead of one.
    let link = element(&blob, &[&file_at[..], &[0]].concat()).to_vec();
    let two = tlv(0xa0, &[link.clone(), link].concat());
    let report = verify_blob(&replace(&blob, &file_at, &two));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::TrailingData
    ));
}

#[test]
fn malformed_page_hash_moniker_is_rejected() {
    let blob = fixture("rsa2048-page-hashes.p7");
    // [0] file -> [1] moniker; append a stray element inside the moniker.
    let moniker_at = indirect(&[0, 1, 1, 0]);
    let moniker = element(&blob, &moniker_at);
    assert_eq!(moniker[0], 0xa1);
    let (h, _) = header(moniker, 0);
    let mut content = moniker[h..].to_vec();
    content.extend_from_slice(&[0x05, 0x00]);
    let report = verify_blob(&replace(&blob, &moniker_at, &tlv(0xa1, &content)));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::TrailingData
    ));
}

#[test]
fn subject_key_identifier_signers_are_matched() {
    let blob = fixture("rsa2048-sha256.p7");
    let certs = element(&blob, &sd(&[SD_CERTIFICATES]));
    let leaf = (0..2)
        .map(|i| element(certs, &[i]))
        .find(|c| c.windows(6).any(|w| w == b"Signer"))
        .unwrap();
    // The SKI is the only 20-byte OCTET STRING inside an OCTET STRING
    // following the 2.5.29.14 OID.
    let ski_oid = [0x06, 0x03, 0x55, 0x1d, 0x0e];
    let at = leaf.windows(5).position(|w| w == ski_oid).unwrap() + 5;
    let (wrapper_h, _) = header(leaf, at);
    let inner = at + wrapper_h;
    let (h, l) = header(leaf, inner);
    let ski = leaf[inner + h..inner + h + l].to_vec();
    assert_eq!(ski.len(), 20);

    let with_ski = |version: u8| {
        let b = replace(&blob, &signer(&[1]), &tlv(0x80, &ski));
        replace(&b, &signer(&[0]), &[0x02, 0x01, version])
    };
    let report = verify_blob(&with_ski(3));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    assert_eq!(
        sig.signer_id,
        Some(SignerIdentifier::SubjectKeyId(ski.clone()))
    );
    assert!(sig.warnings.is_empty());

    // Version 1 with a key identifier is reported.
    let report = verify_blob(&with_ski(1));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert_eq!(sig.warnings, [SignatureWarning::SignerVersionMismatch(1)]);

    // A key identifier no certificate has.
    let b = replace(&blob, &signer(&[1]), &tlv(0x80, &[0xab; 20]));
    let b = replace(&b, &signer(&[0]), &[0x02, 0x01, 3]);
    assert_eq!(
        only(&verify_blob(&b)).status,
        SignatureStatus::BadSignature(BadSignature::SignerCertificateNotFound)
    );
}

// --- Round-3 review cases. ---------------------------------------------------

#[test]
fn small_rsa_keys_verify_with_a_warning() {
    let report = verify_blob(&fixture("rsa1024-sha256.p7"));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid, "{sig:#?}");
    assert_eq!(sig.key_bits, Some(1024));
    assert_eq!(sig.warnings, [SignatureWarning::SmallRsaKey(1024)]);
    // OS code integrity has no lower bound to report; ADR 0008's floor is
    // a warning here and a policy decision later.
    assert!(sig.os_ci_compatible());
}

#[test]
fn non_conformant_images_are_never_valid() {
    // On a non-conformant layout the Authenticode digest is a best effort:
    // bytes can be moved across the certificate table without changing it.
    // So even an exact match with a sound signature is not `Valid`. The
    // digests here are the real ones; only the layout verdict differs.
    let image = image_with_table(pkcs7_entry(&fixture("rsa2048-sha256.p7")));
    let info = pe::parse(&image).unwrap();
    let mut hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
    hashes.status =
        AuthenticodeStatus::NonConformant(vec![NonConformance::CertificateTableMisaligned {
            offset: info.certificate_table.unwrap().offset,
        }]);
    let options = VerifyOptions {
        tolerate_digest_mismatch: true,
    };
    let report = verify_certificate_table(&image, &info, &hashes, &options);
    assert!(report.warnings.contains(&ReportWarning::NonConformantImage));
    let sig = only(&report);
    assert_eq!(sig.signature_valid, SignatureCheck::Valid);
    assert_eq!(sig.digest_match, Some(true));
    assert_eq!(sig.status, SignatureStatus::NonConformantImage);
    assert!(sig.signer.is_none() && !sig.untrusted_signer_attrs);
    assert_eq!(report.primary, None);
    assert_eq!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::Signature(
            SignatureStatus::NonConformantImage
        ))
    );

    // End to end: data appended after the table makes the image
    // non-conformant, and the signature is not valid.
    let mut appended = image.clone();
    appended.extend_from_slice(&[0; 8]);
    let report = verify(&appended);
    assert!(!report.image_status.is_conformant());
    assert!(!only(&report).status.is_valid());
    assert_eq!(
        report.signing_state,
        SigningState::Invalid(InvalidReason::Signature(only(&report).status.clone()))
    );
}

#[test]
fn signer_digest_listing_is_exact() {
    let blob = fixture("rsa2048-sha256.p7");
    let sha256 = element(&blob, &sd(&[1, 0])).to_vec();
    let unknown = |i: u8| {
        tlv(
            0x30,
            &tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x01, i]),
        )
    };
    // Many unknown digests before the signer's: still listed.
    let mut set: Vec<u8> = (0..40).flat_map(unknown).collect();
    set.extend_from_slice(&sha256);
    let report = verify_blob(&replace(&blob, &sd(&[1]), &tlv(0x31, &set)));
    let sig = only(&report);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert!(
        !sig.warnings
            .contains(&SignatureWarning::SignerDigestNotListed)
    );
    // Not listed at all.
    let report = verify_blob(&replace(&blob, &sd(&[1]), &tlv(0x31, &unknown(1))));
    assert!(
        only(&report)
            .warnings
            .contains(&SignatureWarning::SignerDigestNotListed)
    );
    // Invalid DER in the set.
    let report = verify_blob(&replace(&blob, &sd(&[1]), &tlv(0x31, &[0x30, 0x80, 0, 0])));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::IndefiniteLength
    ));
}

/// Inserts `crls` as the `[1]` element after the certificates.
fn with_crls(blob: &[u8], crls: &[u8]) -> Vec<u8> {
    let signed = element(blob, &SIGNED_DATA);
    let (h, _) = header(signed, 0);
    let certs = element(blob, &sd(&[SD_CERTIFICATES]));
    let certs_end = h + locate(signed, &[SD_CERTIFICATES]) - h + certs.len();
    let mut content = signed[h..certs_end].to_vec();
    content.extend_from_slice(&tlv(0xa1, crls));
    content.extend_from_slice(&signed[certs_end..]);
    replace(blob, &SIGNED_DATA, &tlv(0x30, &content))
}

#[test]
fn crls_must_be_valid_der() {
    let blob = fixture("rsa2048-sha256.p7");
    let good_crl = tlv(0x30, &tlv(0x30, &[0x02, 0x01, 0x01]));
    let report = verify_blob(&with_crls(&blob, &good_crl));
    assert_eq!(only(&report).status, SignatureStatus::Valid);
    let bad_crl = tlv(0x30, &[0x30, 0x03, 0x02, 0x05, 0x01]);
    let report = verify_blob(&with_crls(&blob, &bad_crl));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::Truncated
    ));
}

#[test]
fn pe_image_data_must_be_strict_der() {
    let blob = fixture("rsa2048-sha256.p7");
    let value = indirect(&[0, 1]);
    let flags_at = [&value[..], &[0]].concat();
    let file_at = [&value[..], &[1]].concat();
    let check = |b: Vec<u8>, kind: Asn1ErrorKind| {
        let report = verify_blob(&b);
        assert!(
            matches!(malformed(&report), SignatureError::Asn1(a) if a.kind == kind),
            "{:?}",
            only(&report).status
        );
    };
    // Unused flag bits that are not zero.
    check(
        replace(&blob, &flags_at, &[0x03, 0x02, 0x07, 0xff]),
        Asn1ErrorKind::InvalidValue,
    );
    // A [2] file link holding a truncated SpcString.
    check(
        replace(&blob, &file_at, &tlv(0xa0, &tlv(0xa2, &[0x80, 0x05]))),
        Asn1ErrorKind::Truncated,
    );
    // A [2] file link holding an indefinite-length element.
    check(
        replace(&blob, &file_at, &tlv(0xa0, &tlv(0xa2, &[0x30, 0x80, 0, 0]))),
        Asn1ErrorKind::IndefiniteLength,
    );
    // A [2] file link with an odd-length BMPString.
    check(
        replace(&blob, &file_at, &tlv(0xa0, &tlv(0xa2, &[0x80, 0x01, 0x41]))),
        Asn1ErrorKind::InvalidValue,
    );
    // An SpcLink form that does not exist.
    check(
        replace(&blob, &file_at, &tlv(0xa0, &[0x05, 0x00])),
        Asn1ErrorKind::UnexpectedTag {
            expected: 0xa1,
            found: 0x05,
        },
    );
    // A well-formed URL link parses. It changes the signed content, so the
    // message digest no longer matches, but it is not malformed.
    let report = verify_blob(&replace(
        &blob,
        &file_at,
        &tlv(0xa0, &tlv(0x80, b"https://x.test")),
    ));
    assert_eq!(
        only(&report).status,
        SignatureStatus::BadSignature(BadSignature::MessageDigestMismatch)
    );
}

#[test]
fn skipped_values_must_be_valid_der() {
    let blob = fixture("rsa2048-sha256.p7");
    // An unknown unauthenticated attribute with a truncated value.
    let oid = tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x02, 0x01]);
    let attr = tlv(0x30, &[oid, tlv(0x31, &[0x30, 0x02, 0x04, 0x09])].concat());
    let si = element(&blob, &signer(&[]));
    let (h, _) = header(si, 0);
    let mut content = si[h..].to_vec();
    content.extend(tlv(0xa1, &attr));
    let report = verify_blob(&replace(&blob, &signer(&[]), &tlv(0x30, &content)));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::Truncated
    ));
    // An unknown signature algorithm with indefinite-length parameters.
    let alg = tlv(
        0x30,
        &[
            tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x02, 0x02]),
            vec![0x30, 0x80, 0, 0],
        ]
        .concat(),
    );
    let report = verify_blob(&replace(&blob, &signer(&[SI_SIG_ALG]), &alg));
    assert!(matches!(
        malformed(&report),
        SignatureError::Asn1(a) if a.kind == Asn1ErrorKind::IndefiniteLength
    ));
}

#[test]
fn pss_parameter_edge_cases() {
    let blob = fixture("rsa2048-sha256.p7");
    let pss_oid = tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
    );
    let with_params = |params: Vec<u8>| {
        let alg = tlv(0x30, &[pss_oid.clone(), params].concat());
        verify_blob(&replace(&blob, &signer(&[SI_SIG_ALG]), &alg))
    };
    // An unknown mask function with non-digest parameters: unsupported.
    let mgf = tlv(
        0x30,
        &[
            tlv(0x06, &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x03, 0x01]),
            vec![0x02, 0x01, 0x05],
        ]
        .concat(),
    );
    let report = with_params(tlv(0x30, &tlv(0xa1, &mgf)));
    assert!(matches!(
        only(&report).status,
        SignatureStatus::Unsupported(Unsupported::SignatureAlgorithm(SignatureAlgorithm::Other(
            _
        )))
    ));
    // Truncated parameters: malformed.
    let report = with_params(tlv(0x30, &[0xa2, 0x03, 0x02, 0x05]));
    assert!(matches!(malformed(&report), SignatureError::Asn1(_)));
    // Missing parameters: malformed.
    let alg = tlv(0x30, &pss_oid);
    let report = verify_blob(&replace(&blob, &signer(&[SI_SIG_ALG]), &alg));
    assert_eq!(malformed(&report), &SignatureError::AlgorithmParameters);
}

#[test]
fn spki_parameters_are_checked() {
    let blob = fixture("rsa2048-sha256.p7");
    let certs = element(&blob, &sd(&[SD_CERTIFICATES]));
    let leaf_index = (0..2)
        .find(|i| element(certs, &[*i]).windows(6).any(|w| w == b"Signer"))
        .unwrap();
    let cert = element(certs, &[leaf_index]).to_vec();
    let rsa_oid = tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
    );
    let with_spki_alg = |alg: Vec<u8>| {
        let c = replace(&cert, &[0, 6, 0], &alg);
        verify_blob(&replace(&blob, &sd(&[SD_CERTIFICATES, leaf_index]), &c))
    };
    // rsaEncryption with absent parameters is accepted.
    let report = with_spki_alg(tlv(0x30, &rsa_oid));
    assert_eq!(only(&report).status, SignatureStatus::Valid);
    // With bogus parameters, the certificate cannot be the signer.
    let report = with_spki_alg(tlv(
        0x30,
        &[rsa_oid.clone(), vec![0x02, 0x01, 0x01]].concat(),
    ));
    let sig = only(&report);
    assert_eq!(
        sig.status,
        SignatureStatus::BadSignature(BadSignature::SignerCertificateNotFound)
    );
    assert!(
        sig.warnings
            .contains(&SignatureWarning::UnparseableCertificate(leaf_index))
    );
}

#[test]
fn fuzz_target_image_is_the_fixture_image() {
    // The fuzz target appends its input to `PeBuilder::default()` (through
    // the same module) and points the security directory at it. A valid
    // seed must stay valid that way, or the fuzzer never reaches `Valid`.
    let table = pkcs7_entry(&fixture("rsa2048-sha256.p7"));
    let mut image = PeBuilder::default().build();
    let at = image.len() as u32;
    image.extend_from_slice(&table);
    let dir = PeBuilder::default().data_directory_offset(4);
    image[dir..dir + 4].copy_from_slice(&at.to_le_bytes());
    image[dir + 4..dir + 8].copy_from_slice(&(table.len() as u32).to_le_bytes());
    let report = verify(&image);
    assert_eq!(report.signing_state, SigningState::Valid);
    assert_eq!(report.primary, Some(0));
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Random byte edits to a valid dual signature never panic, never break
    /// the documented bounds, and never produce a `Valid` signature that did
    /// not pass every check. (The fuzz target asserts the same, more deeply.)
    #[test]
    fn mutated_signatures_respect_invariants(
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let mut blob = fixture("rsa2048-sha1-nested-sha256.p7");
        for (at, value) in &edits {
            let i = at.index(blob.len());
            blob[i] = *value;
        }
        if truncate {
            blob.truncate(cut.index(blob.len()));
        }
        for tolerate in [false, true] {
            let options = VerifyOptions { tolerate_digest_mismatch: tolerate };
            let report = verify_pe(&image_with_table(pkcs7_entry(&blob)), &options).unwrap();
            prop_assert!(report.signatures.len() <= MAX_SIGNATURES);
            for (i, sig) in report.signatures.iter().enumerate() {
                prop_assert_eq!((sig.index, sig.total), (i, report.signatures.len()));
                prop_assert!(sig.depth <= MAX_NESTING_DEPTH);
                prop_assert!(sig.warnings.len() <= MAX_WARNINGS + 1);
                if sig.status.is_valid() {
                    prop_assert_eq!(&sig.signature_valid, &SignatureCheck::Valid);
                    prop_assert_eq!(sig.digest_match, Some(true));
                }
                if sig.signer.is_some() && !sig.status.is_valid() {
                    prop_assert!(tolerate && sig.status == SignatureStatus::DigestMismatch);
                    prop_assert!(sig.untrusted_signer_attrs);
                }
            }
            match report.primary {
                Some(p) => {
                    prop_assert!(report.signatures[p].status.is_valid());
                    prop_assert_eq!(&report.signing_state, &SigningState::Valid);
                }
                None => prop_assert!(report.signing_state != SigningState::Valid),
            }
        }
    }
}

/// Writes the unsigned image the fixtures sign, for `generate.sh`.
#[test]
#[ignore = "writes a file; run by tests/fixtures/authenticode/generate.sh"]
fn write_fixture_base_image() {
    let path =
        std::env::var_os("PALISADE_AUTHENTICODE_BASE").expect("set PALISADE_AUTHENTICODE_BASE");
    std::fs::write(path, PeBuilder::default().build()).unwrap();
}

/// Writes fuzz seeds for `authenticode_pkcs7`: each fixture as a
/// certificate table (one `WIN_CERTIFICATE` entry), plus a dual-entry table.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/authenticode_pkcs7" \
///     cargo test -p palisade-fileid --test signature -- --ignored write_pkcs7_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_pkcs7_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "p7") {
            let name = path.file_stem().unwrap().to_string_lossy().into_owned();
            let blob = std::fs::read(&path).unwrap();
            std::fs::write(dir.join(format!("seed-{name}")), pkcs7_entry(&blob)).unwrap();
        }
    }
    let mut both = pkcs7_entry(&fixture("rsa2048-sha256.p7"));
    both.extend(pkcs7_entry(&fixture("p256-sha256.p7")));
    std::fs::write(dir.join("seed-two-entries"), both).unwrap();
}
