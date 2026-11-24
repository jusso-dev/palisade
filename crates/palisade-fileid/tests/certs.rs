//! Certificate extraction tests (#49): `extract_certificates` over PE
//! images, cabinets, bare PKCS#7 and catalogs, and `CertificateBundle`.
//!
//! The cabinet in `fixtures/certs` is made by `generate.sh` there; the PKCS#7
//! blobs and catalogs are the chain and catalog fixtures.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    CabinetError, CertSelection, CertSummary, CertificateBundle, ExtractError, ExtractWarning,
    MAX_EXTRACT_NESTING, MAX_EXTRACTED_SIGNATURES, SignedFileKind, extract_certificates,
};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn read(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{path}")).unwrap()
}

fn cn(cert: &CertSummary) -> &str {
    cert.subject.common_name().unwrap_or("")
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

fn signed_pe(blob: &[u8]) -> Vec<u8> {
    PeBuilder {
        certificate: Some(entry(blob)),
        ..PeBuilder::default()
    }
    .build()
}

#[test]
fn a_signed_cabinet_gives_its_leaf_and_root() {
    let cab = read("certs/signed.cab");
    let all = extract_certificates(&cab, CertSelection::All).unwrap();
    assert_eq!(all.kind, SignedFileKind::Cabinet);
    assert_eq!(all.signatures, 1);
    // In the order the signature carries them.
    let mut names: Vec<&str> = all.certificates.iter().map(|c| cn(&c.cert)).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["Palisade Cabinet Test Root", "Palisade Cabinet Test Signer"]
    );
    assert!(all.warnings.is_empty(), "{:?}", all.warnings);

    let leaf = extract_certificates(&cab, CertSelection::Leaf).unwrap();
    assert_eq!(leaf.certificates.len(), 1);
    assert!(leaf.certificates[0].is_signer);
    assert_eq!(leaf.certificates[0].cert.der, read("certs/leaf.der"));

    let root = extract_certificates(&cab, CertSelection::Root).unwrap();
    assert_eq!(root.certificates.len(), 1);
    assert!(root.certificates[0].is_root);
    assert_eq!(root.certificates[0].cert.der, read("certs/root.der"));
}

#[test]
fn a_pe_image_gives_every_signature_including_nested() {
    // A SHA-1 signature by chain A with a nested SHA-256 one by chain B.
    let image = signed_pe(&read("chain/dual-a-sha1-b-sha256.p7"));
    let all = extract_certificates(&image, CertSelection::All).unwrap();
    assert_eq!(all.kind, SignedFileKind::PeImage);
    assert_eq!(all.signatures, 2);
    let leaves = extract_certificates(&image, CertSelection::Leaf).unwrap();
    assert_eq!(leaves.certificates.len(), 2);
    assert_eq!(
        leaves
            .certificates
            .iter()
            .map(|c| c.signature)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_ne!(
        leaves.certificates[0].cert.sha256_thumbprint,
        leaves.certificates[1].cert.sha256_thumbprint
    );
}

#[test]
fn a_bare_pkcs7_and_a_catalog_are_read_too() {
    let p7 = read("chain/leaf-inter-root.p7");
    let all = extract_certificates(&p7, CertSelection::All).unwrap();
    assert_eq!(all.kind, SignedFileKind::Pkcs7);
    assert_eq!(all.certificates.len(), 3);
    let root = extract_certificates(&p7, CertSelection::Root).unwrap();
    assert_eq!(
        root.certificates
            .iter()
            .map(|c| cn(&c.cert))
            .collect::<Vec<_>>(),
        ["Palisade Chain Root"]
    );
    let leaf = extract_certificates(&p7, CertSelection::Leaf).unwrap();
    assert_eq!(cn(&leaf.certificates[0].cert), "Palisade Test Publisher");

    let cat = read("catalog/v2-sha256.cat");
    let all = extract_certificates(&cat, CertSelection::All).unwrap();
    assert_eq!(all.kind, SignedFileKind::Pkcs7);
    let root = extract_certificates(&cat, CertSelection::Root).unwrap();
    assert_eq!(root.certificates[0].cert.der, read("catalog/ca.der"));
}

#[test]
fn unsigned_and_unknown_inputs_are_errors() {
    let unsigned = PeBuilder::default().build();
    assert_eq!(
        extract_certificates(&unsigned, CertSelection::All).unwrap_err(),
        ExtractError::Unsigned
    );
    assert_eq!(
        extract_certificates(b"plain text", CertSelection::All).unwrap_err(),
        ExtractError::UnknownFormat
    );
    assert_eq!(
        extract_certificates(&[], CertSelection::All).unwrap_err(),
        ExtractError::UnknownFormat
    );
    // A cabinet without a reserved area is unsigned.
    let mut cab = read("certs/signed.cab");
    let flags = u16::from_le_bytes([cab[30], cab[31]]) & !0x0004;
    cab[30..32].copy_from_slice(&flags.to_le_bytes());
    assert_eq!(
        extract_certificates(&cab, CertSelection::All).unwrap_err(),
        ExtractError::Unsigned
    );
}

#[test]
fn hostile_cabinets_fail_closed() {
    let cab = read("certs/signed.cab");
    // A cabinet longer than the file.
    let mut bad = cab.clone();
    bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        extract_certificates(&bad, CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::LengthMismatch { .. })
    ));
    // A signature inside the cabinet's own bytes (its declared length now
    // covers the signature).
    let mut bad = cab.clone();
    bad[8..12].copy_from_slice(&u32::try_from(cab.len()).unwrap().to_le_bytes());
    assert!(matches!(
        extract_certificates(&bad, CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::SignatureOutOfRange { .. })
    ));
    // A signature pointing past the end.
    let mut bad = cab.clone();
    bad[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        extract_certificates(&bad, CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::SignatureOutOfRange { .. })
    ));
    // A signature pointing into the header.
    let mut bad = cab.clone();
    bad[44..48].copy_from_slice(&0_u32.to_le_bytes());
    assert!(matches!(
        extract_certificates(&bad, CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::SignatureOutOfRange { .. })
    ));
    // Too small a reserved area.
    let mut bad = cab.clone();
    bad[36..38].copy_from_slice(&4_u16.to_le_bytes());
    assert_eq!(
        extract_certificates(&bad, CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::ReserveTooShort(4))
    );
    // Truncated.
    assert_eq!(
        extract_certificates(&cab[..20], CertSelection::All).unwrap_err(),
        ExtractError::Cabinet(CabinetError::Truncated)
    );
}

#[test]
fn a_corrupt_signature_is_an_error_and_bad_certificates_are_warnings() {
    let mut p7 = read("chain/leaf-inter-root.p7");
    let last = p7.len() - 1;
    p7.truncate(last);
    assert!(matches!(
        extract_certificates(&p7, CertSelection::All).unwrap_err(),
        ExtractError::Asn1(_)
    ));
    // Corrupt the first certificate's inner bytes, keeping every length:
    // the DER stays valid, but the certificate no longer parses as X.509.
    let p7 = read("chain/leaf-inter-root.p7");
    let at = p7
        .windows(4)
        .position(|w| w == [0xa0, 0x03, 0x02, 0x01])
        .unwrap();
    let mut bad = p7.clone();
    bad[at] = 0x04; // the [0] version tag becomes an OCTET STRING
    let out = extract_certificates(&bad, CertSelection::All).unwrap();
    assert!(
        out.warnings
            .iter()
            .any(|w| matches!(w, ExtractWarning::UnparseableCertificate { .. })),
        "{:?}",
        out.warnings
    );
    assert_eq!(out.certificates.len(), 2);
}

#[test]
fn bundles_hold_each_certificate_once() {
    let mut bundle = CertificateBundle::new();
    let cab = extract_certificates(&read("certs/signed.cab"), CertSelection::All).unwrap();
    assert_eq!(bundle.add(&cab), 2);
    assert_eq!(bundle.add(&cab), 0);
    let p7 = extract_certificates(&read("chain/leaf-inter-root.p7"), CertSelection::All).unwrap();
    assert_eq!(bundle.add(&p7), 3);
    assert_eq!(bundle.certificates().len(), 5);
    let pem = bundle.to_pem();
    assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 5);
    let files: Vec<(String, &[u8])> = bundle.der_files().collect();
    assert_eq!(files.len(), 5);
    for (name, der) in &files {
        assert_eq!(name.len(), 64 + 4);
        assert!(name.ends_with(".cer"));
        assert!(name[..64].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            CertSummary::from_der(der).unwrap().sha256_thumbprint,
            name[..64]
        );
    }
}

#[test]
fn extractions_serialise() {
    let out = extract_certificates(&read("certs/signed.cab"), CertSelection::Leaf).unwrap();
    let json = serde_json::to_value(&out).unwrap();
    assert_eq!(json["kind"], "cabinet");
    assert_eq!(json["certificates"][0]["is_signer"], true);
}

/// DER TLV.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A minimal SignedData ContentInfo with no certificates and one
/// SignerInfo, carrying `nested` as `szOID_NESTED_SIGNATURE` values.
fn signed_data_with(nested: Option<&[u8]>) -> Vec<u8> {
    let oid = |b: &[u8]| tlv(0x06, b);
    let sha256 = tlv(
        0x30,
        &[
            oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let sid = tlv(0x30, &[tlv(0x30, &[]), tlv(0x02, &[0x01])].concat());
    let mut info = [
        tlv(0x02, &[0x01]),
        sid,
        sha256.clone(),
        tlv(0xa0, &[]),
        sha256.clone(),
        tlv(0x04, &[0x00]),
    ]
    .concat();
    if let Some(child) = nested {
        let nested_oid = oid(&[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01]);
        let attr = tlv(0x30, &[nested_oid, tlv(0x31, child)].concat());
        info.extend(tlv(0xa1, &attr));
    }
    let sd = tlv(
        0x30,
        &[
            tlv(0x02, &[0x01]),
            tlv(0x31, &sha256),
            tlv(
                0x30,
                &oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]),
            ),
            tlv(0x31, &tlv(0x30, &info)),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[
            oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]),
            tlv(0xa0, &sd),
        ]
        .concat(),
    )
}

#[test]
fn nesting_is_bounded() {
    // Twelve signatures, each nested in the previous one: past the
    // nesting limit, so the deepest are not read.
    let mut blob = signed_data_with(None);
    for _ in 0..11 {
        blob = signed_data_with(Some(&blob));
    }
    let out = extract_certificates(&blob, CertSelection::All).unwrap();
    assert_eq!(out.signatures, MAX_EXTRACT_NESTING + 1);
    assert!(out.signatures <= MAX_EXTRACTED_SIGNATURES);
    assert!(out.warnings.contains(&ExtractWarning::LimitReached));
    // Forty levels: still only the first levels are read.
    let mut deep = signed_data_with(None);
    for _ in 0..40 {
        deep = signed_data_with(Some(&deep));
    }
    let out = extract_certificates(&deep, CertSelection::All).unwrap();
    assert_eq!(out.signatures, MAX_EXTRACT_NESTING + 1);
    // A short chain is read in full, with no warning but the missing
    // signer certificates.
    let mut blob = signed_data_with(None);
    blob = signed_data_with(Some(&blob));
    let out = extract_certificates(&blob, CertSelection::All).unwrap();
    assert_eq!(out.signatures, 2);
    assert!(!out.warnings.contains(&ExtractWarning::LimitReached));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mutated_inputs_never_panic(
        which in 0_usize..3,
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let mut data = match which {
            0 => read("certs/signed.cab"),
            1 => read("chain/leaf-inter-root.p7"),
            _ => signed_pe(&read("chain/dual-a-sha1-b-sha256.p7")),
        };
        for (i, b) in flips {
            let at = i.index(data.len());
            data[at] = b;
        }
        for sel in [CertSelection::All, CertSelection::Leaf, CertSelection::Root] {
            if let Ok(out) = extract_certificates(&data, sel) {
                prop_assert!(out.signatures <= MAX_EXTRACTED_SIGNATURES);
            }
        }
    }
}
