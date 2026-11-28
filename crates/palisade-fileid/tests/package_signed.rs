//! App package signatures made at test time (#333): the cases the signed
//! fixtures cannot reach, because they need a package signed **after** it
//! was changed, so that its digest matches and only the package checks can
//! reject it.
//!
//! [`PackageSigner`] signs a package the way the OS signing tool does:
//! `AppxSignature.p7x` is `PKCX` and an Authenticode SignedData whose
//! indirect data is `SPC_SIPINFO` with the package (or bundle) subject
//! type, over this crate's own [`signed_digest`]. Its key is a P-256 key
//! generated per run, and its certificate's subject is the test manifests'
//! publisher. Nothing here is trusted by anything outside the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

#[path = "common/appx.rs"]
mod appx;

use appx::*;
use palisade_fileid::authenticode::{DigestAlgorithm, SignatureStatus, Unsupported};
use palisade_fileid::package::blockmap::BlockMapError;
use palisade_fileid::package::zip::Archive;
use palisade_fileid::package::{
    DigestInputError, MAX_METADATA_SIZE, PackageSignatureIssue, PackageSignatureStatus,
    SIP_GUID_BUNDLE, SIP_GUID_PACKAGE, parse_package, signed_digest, signed_digest_checked,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest as _, Sha256};

// ---------------------------------------------------------------------------
// DER.

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn int(n: u32) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut content = bytes[skip..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in &arcs[2..] {
        let mut stack = vec![(*arc & 0x7f) as u8];
        let mut v = *arc >> 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        content.extend(stack.iter().rev());
    }
    tlv(0x06, &content)
}

fn utf8(s: &str) -> Vec<u8> {
    tlv(0x0c, s.as_bytes())
}

/// `O=Palisade Tests, CN=<cn>`, encoded O first, so it renders as
/// `CN=<cn>, O=Palisade Tests`: the manifests' publisher for the signer.
fn name(cn: &str) -> Vec<u8> {
    let rdn = |o: &str, v: &str| set(&[&seq(&[&oid(o), &utf8(v)])]);
    seq(&[&rdn("2.5.4.10", "Palisade Tests"), &rdn("2.5.4.3", cn)])
}

fn header_len(der: &[u8]) -> usize {
    if der[1] < 0x80 {
        2
    } else {
        2 + usize::from(der[1] & 0x7f)
    }
}

const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

fn alg(o: &str) -> Vec<u8> {
    seq(&[&oid(o)])
}

fn digest_alg() -> Vec<u8> {
    seq(&[&oid(SHA256), &tlv(0x05, &[])])
}

// ---------------------------------------------------------------------------
// The signer.

/// A per-run P-256 key with a self-signed code-signing certificate whose
/// subject is the manifests' publisher.
struct PackageSigner {
    rng: SystemRandom,
    key: EcdsaKeyPair,
    cert: Vec<u8>,
    subject: Vec<u8>,
}

impl PackageSigner {
    fn new(cn: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let subject = name(cn);
        let spki = seq(&[
            &seq(&[&oid("1.2.840.10045.2.1"), &oid("1.2.840.10045.3.1.7")]),
            &tlv(0x03, &[&[0][..], key.public_key().as_ref()].concat()),
        ]);
        let ski = Sha256::digest(key.public_key().as_ref())[..20].to_vec();
        let ext = |id: &str, critical: bool, value: &[u8]| {
            let crit = if critical {
                tlv(0x01, &[0xff])
            } else {
                Vec::new()
            };
            seq(&[&oid(id), &crit, &tlv(0x04, value)])
        };
        let tbs = seq(&[
            &tlv(0xa0, &int(2)),
            &int(7),
            &alg(ECDSA_SHA256),
            &subject,
            &seq(&[&tlv(0x17, b"200101000000Z"), &tlv(0x18, b"20991231000000Z")]),
            &subject,
            &spki,
            &tlv(
                0xa3,
                &seq(&[
                    &ext("2.5.29.15", true, &tlv(0x03, &[0x07, 0x80])),
                    &ext("2.5.29.37", false, &seq(&[&oid("1.3.6.1.5.5.7.3.3")])),
                    &ext("2.5.29.14", false, &tlv(0x04, &ski)),
                ]),
            ),
        ]);
        let sig = key.sign(&rng, &tbs).unwrap();
        let cert = seq(&[
            &tbs,
            &alg(ECDSA_SHA256),
            &tlv(0x03, &[&[0][..], sig.as_ref()].concat()),
        ]);
        Self {
            rng,
            key,
            cert,
            subject,
        }
    }

    /// `AppxSignature.p7x` over `digest` for subject type `guid`.
    fn p7x(&self, digest: &[u8], guid: [u8; 16]) -> Vec<u8> {
        let sip_info = seq(&[
            &int(0x0101_0000),
            &tlv(0x04, &guid),
            &int(0),
            &int(0),
            &int(0),
            &int(0),
            &int(0),
        ]);
        let data = seq(&[&oid("1.3.6.1.4.1.311.2.1.30"), &sip_info]);
        let indirect = seq(&[&data, &seq(&[&digest_alg(), &tlv(0x04, digest)])]);
        let message_digest = Sha256::digest(&indirect[header_len(&indirect)..]);
        let mut attrs = [
            seq(&[
                &oid("1.2.840.113549.1.9.3"),
                &set(&[&oid("1.3.6.1.4.1.311.2.1.4")]),
            ]),
            seq(&[
                &oid("1.2.840.113549.1.9.4"),
                &set(&[&tlv(0x04, &message_digest)]),
            ]),
        ];
        attrs.sort();
        let attrs_set = set(&attrs.iter().map(Vec::as_slice).collect::<Vec<_>>());
        let sig = self.key.sign(&self.rng, &attrs_set).unwrap();
        let mut signed_attrs = attrs_set.clone();
        signed_attrs[0] = 0xa0;
        let signer_info = seq(&[
            &int(1),
            &seq(&[&self.subject, &int(7)]),
            &digest_alg(),
            &signed_attrs,
            &alg(ECDSA_SHA256),
            &tlv(0x04, sig.as_ref()),
        ]);
        let sd = seq(&[
            &int(1),
            &set(&[&digest_alg()]),
            &seq(&[&oid("1.3.6.1.4.1.311.2.1.4"), &tlv(0xa0, &indirect)]),
            &tlv(0xa0, &self.cert),
            &set(&[&signer_info]),
        ]);
        let mut out = b"PKCX".to_vec();
        out.extend_from_slice(&seq(&[&oid("1.2.840.113549.1.7.2"), &tlv(0xa0, &sd)]));
        out
    }

    /// Signs the unsigned archive `files` (in `style`): computes the
    /// package digest with a placeholder signature member in place, then
    /// writes the real one. The digest leaves the signature member out, so
    /// the placeholder's size does not matter.
    fn sign(&self, files: &[File], style: &ZipStyle, bundle: bool) -> Vec<u8> {
        let guid = if bundle {
            SIP_GUID_BUNDLE
        } else {
            SIP_GUID_PACKAGE
        };
        let mut all = files.to_vec();
        all.push(File {
            name: "AppxSignature.p7x".into(),
            data: b"PKCX".to_vec(),
            deflate: false,
        });
        let draft = write_zip_with(&all, style);
        let digest = signed_digest(&Archive::parse(&draft).unwrap(), DigestAlgorithm::Sha256)
            .expect("the unsigned archive has a digest");
        all.last_mut().unwrap().data = self.p7x(&digest, guid);
        write_zip_with(&all, style)
    }
}

/// The publisher's CN in `PUBLISHER`.
const SIGNER_CN: &str = "Palisade Test Package Signer";

/// The archive members `builder` writes (payload, block map, content
/// types), without a signature.
fn unsigned(builder: &AppxBuilder) -> Vec<File> {
    let data = builder.build();
    let a = Archive::parse(&data).unwrap();
    a.members
        .iter()
        .map(|m| File {
            name: m.name.clone(),
            data: a.read(m).unwrap(),
            deflate: m.method == 8,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests.

#[test]
fn the_test_signer_makes_valid_package_signatures() {
    let signer = PackageSigner::new(SIGNER_CN);
    let data = signer.sign(
        &unsigned(&AppxBuilder::package()),
        &ZipStyle::packaging_tool(),
        false,
    );
    let id = parse_package(&data).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.issue, None, "{:?}", sig.report.signatures);
    assert_eq!(sig.report.signatures[0].status, SignatureStatus::Valid);
    assert!(id.signature_valid());
    assert_eq!(sig.status(), PackageSignatureStatus::Valid);

    // The same, signed by another publisher: rejected at package level,
    // with a digest that matches.
    let other = PackageSigner::new("Someone Else");
    let id = parse_package(&other.sign(
        &unsigned(&AppxBuilder::package()),
        &ZipStyle::packaging_tool(),
        false,
    ))
    .unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert!(matches!(
        sig.status(),
        PackageSignatureStatus::Rejected(PackageSignatureIssue::PublisherMismatch { .. })
    ));
    assert_eq!(sig.report.signatures[0].digest_match, Some(true));
}

#[test]
fn a_signed_block_map_must_cover_every_file() {
    // Signed after the block map left a file out, so the digest matches:
    // only the block map check can reject it.
    let signer = PackageSigner::new(SIGNER_CN);
    let mut skip = AppxBuilder::package();
    skip.blockmap_skip = Some("logo.png".into());
    let id =
        parse_package(&signer.sign(&unsigned(&skip), &ZipStyle::packaging_tool(), false)).unwrap();
    let sig = id.signature.as_ref().unwrap();
    // The signature itself verified against the digest before the package
    // check demoted it.
    assert_eq!(sig.report.signatures[0].digest_match, Some(true));
    assert_eq!(
        sig.issue,
        Some(PackageSignatureIssue::BlockMap(BlockMapError::Unlisted(
            "logo.png".into()
        )))
    );
    assert!(!id.signature_valid());
    assert_eq!(
        sig.report.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
    assert!(matches!(
        sig.status(),
        PackageSignatureStatus::Rejected(PackageSignatureIssue::BlockMap(_))
    ));
}

#[test]
fn a_signed_bundle_with_a_wrong_payload_offset_is_rejected() {
    let signer = PackageSigner::new(SIGNER_CN);
    let style = ZipStyle::packaging_tool();
    // Intact: valid.
    let bundle = AppxBuilder::bundle_for(&style);
    let id = parse_package(&signer.sign(&unsigned(&bundle), &style, true)).unwrap();
    assert!(
        id.signature_valid(),
        "{:?}",
        id.signature.as_ref().unwrap().issue
    );
    // The bundle manifest moves the first payload by one byte, and the
    // bundle is signed after that, so the digest matches.
    let mut moved = AppxBuilder::bundle_for(&style);
    let manifest = String::from_utf8(moved.bundle_manifest().to_vec()).unwrap();
    let at = manifest.find("Offset=\"").unwrap() + "Offset=\"".len();
    let end = at + manifest[at..].find('"').unwrap();
    let offset: u64 = manifest[at..end].parse().unwrap();
    let wrong = format!("{}{}{}", &manifest[..at], offset + 1, &manifest[end..]);
    moved
        .files
        .iter_mut()
        .find(|f| f.name == "AppxMetadata/AppxBundleManifest.xml")
        .unwrap()
        .data = wrong.into_bytes();
    let id = parse_package(&signer.sign(&unsigned(&moved), &style, true)).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.report.signatures[0].digest_match, Some(true));
    assert_eq!(
        sig.issue,
        Some(PackageSignatureIssue::BlockMap(BlockMapError::Size(
            "app_x64.msix".into()
        )))
    );
    assert!(!id.signature_valid());
}

#[test]
fn an_unreadable_digest_input_is_named() {
    let signer = PackageSigner::new(SIGNER_CN);
    let style = ZipStyle::packaging_tool();
    let files = unsigned(&AppxBuilder::package());
    let signed = signer.sign(&files, &style, false);

    // `[Content_Types].xml` over the limit, after signing: no digest, and
    // the issue names the part and its size.
    let mut big = files.clone();
    let ct = big
        .iter_mut()
        .find(|f| f.name == "[Content_Types].xml")
        .unwrap();
    let limit = usize::try_from(MAX_METADATA_SIZE).unwrap();
    ct.data = vec![b' '; limit + 1];
    big.push(File {
        name: "AppxSignature.p7x".into(),
        data: Archive::parse(&signed)
            .unwrap()
            .read(
                Archive::parse(&signed)
                    .unwrap()
                    .member("AppxSignature.p7x")
                    .unwrap(),
            )
            .unwrap(),
        deflate: false,
    });
    let data = write_zip_with(&big, &style);
    let a = Archive::parse(&data).unwrap();
    assert_eq!(
        signed_digest_checked(&a, DigestAlgorithm::Sha256),
        Err(DigestInputError::TooLarge(
            "[Content_Types].xml".into(),
            MAX_METADATA_SIZE + 1
        ))
    );
    let id = parse_package(&data).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(
        sig.issue,
        Some(PackageSignatureIssue::DigestInput(
            DigestInputError::TooLarge("[Content_Types].xml".into(), MAX_METADATA_SIZE + 1)
        ))
    );
    // The signature itself had no digest to check against.
    assert!(matches!(
        sig.report.signatures[0].status,
        SignatureStatus::Unsupported(Unsupported::ImageDigestUnavailable(_))
            | SignatureStatus::DigestMismatch
    ));
    assert!(!id.signature_valid());
    assert!(
        DigestInputError::TooLarge("x".into(), 1)
            .to_string()
            .contains("over the")
    );

    // A code integrity catalog whose deflated data is broken: unreadable.
    let mut cat = files.clone();
    cat.push(File {
        name: "AppxMetadata/CodeIntegrity.cat".into(),
        data: b"catalog bytes".to_vec(),
        deflate: true,
    });
    let broken_style = ZipStyle {
        raw_deflate: Some((
            "AppxMetadata/CodeIntegrity.cat".into(),
            // A stored block header claiming more bytes than follow.
            vec![0x01, 0xff, 0x00, 0x00, 0xff],
        )),
        ..ZipStyle::packaging_tool()
    };
    let data = write_zip_with(&cat, &broken_style);
    let a = Archive::parse(&data).unwrap();
    assert_eq!(
        signed_digest_checked(&a, DigestAlgorithm::Sha256),
        Err(DigestInputError::Unreadable(
            "AppxMetadata/CodeIntegrity.cat".into()
        ))
    );

    // A missing part is not an error, just no digest.
    let no_ct: Vec<File> = files
        .iter()
        .filter(|f| f.name != "[Content_Types].xml")
        .cloned()
        .collect();
    let a_data = write_zip_with(&no_ct, &style);
    let a = Archive::parse(&a_data).unwrap();
    assert_eq!(signed_digest_checked(&a, DigestAlgorithm::Sha256), Ok(None));
    // A hash method with no digest here (MD2 is never computed).
    let full = Archive::parse(&signed).unwrap();
    assert_eq!(
        signed_digest_checked(&full, DigestAlgorithm::Md2),
        Err(DigestInputError::HashMethod)
    );
    assert!(DigestInputError::HashMethod.to_string().contains("hash"));
    assert!(DigestInputError::EndRecords.to_string().contains("end"));
    assert!(
        DigestInputError::Unreadable("p".into())
            .to_string()
            .contains("cannot")
    );
}

#[test]
fn a_tampered_package_is_invalid_not_rejected() {
    // Changed after signing, with nothing wrong at package level: the
    // package status is `Invalid`, and the report says `DigestMismatch`.
    let signer = PackageSigner::new(SIGNER_CN);
    let style = ZipStyle::packaging_tool();
    let files = unsigned(&AppxBuilder::package());
    let signed = signer.sign(&files, &style, false);
    let a = Archive::parse(&signed).unwrap();
    let mut all: Vec<File> = a
        .members
        .iter()
        .map(|m| File {
            name: m.name.clone(),
            data: a.read(m).unwrap(),
            deflate: m.method == 8,
        })
        .collect();
    // Change a payload file and rebuild the block map to match, so the
    // block map check passes and only the digest fails.
    let payload: Vec<File> = all
        .iter()
        .filter(|f| {
            ![
                "AppxBlockMap.xml",
                "[Content_Types].xml",
                "AppxSignature.p7x",
            ]
            .contains(&f.name.as_str())
        })
        .cloned()
        .map(|mut f| {
            if f.name == "logo.png" {
                f.data.push(1);
            }
            f
        })
        .collect();
    let map = AppxBuilder {
        files: payload.clone(),
        blockmap_extra: String::new(),
        blockmap_skip: None,
    }
    .block_map();
    for f in &mut all {
        if f.name == "logo.png" {
            f.data.push(1);
        }
        if f.name == "AppxBlockMap.xml" {
            f.data = map.clone().into_bytes();
        }
    }
    let id = parse_package(&write_zip_with(&all, &style)).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.issue, None);
    assert_eq!(sig.status(), PackageSignatureStatus::Invalid);
    assert_eq!(
        sig.report.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
}
