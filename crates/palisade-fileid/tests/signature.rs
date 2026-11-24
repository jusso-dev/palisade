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
    Asn1ErrorKind, BadSignature, CertificateTableError, Curve, DigestAlgorithm, InvalidReason,
    KeyAlgorithm, MAX_CERTIFICATE_ENTRIES, MAX_NESTING_DEPTH, MAX_SIGNATURES, OsCiIssue,
    ReportWarning, SignatureAlgorithm, SignatureCheck, SignatureError, SignatureKind,
    SignatureReport, SignatureStatus, SignatureWarning, SignerIdentifier, SigningState,
    StatementType, TimestampKind, Unsupported, VerifyOptions, authenticode_hashes,
    verify_certificate_table, verify_pe, verify_signatures,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm};
use palisade_fileid::pe;
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
