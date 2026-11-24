//! Catalog files (#51): CTL parsing, catalog signatures, the catalog store
//! and member lookups.
//!
//! The unsigned catalogs are built here, byte by byte, by [`Ctl`]. The
//! signed fixtures in `tests/fixtures/catalog` are those same catalogs
//! signed by osslsigncode with throwaway test keys (`generate.sh` there);
//! [`fixture_ctls_are_the_builder_output`] checks that each fixture signs
//! exactly what the builder makes, so the fixtures have no content of
//! unknown origin.

#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use common::PeBuilder;
use palisade_fileid::authenticode::{
    BadSignature, DigestAlgorithm, SignatureError, SignatureKind, SignatureStatus,
    SignatureWarning, SigningState, TrustConfig, UntrustedReason, hash_pe,
};
use palisade_fileid::catalog::{
    CatalogError, CatalogSource, CatalogStatus, CatalogStoreBuilder, CtlError, CtlWarning,
    DigestKind, FileDigests, LoadError, MAX_ATTRIBUTES, MAX_CATALOG_SIZE, MAX_MATCHES, MAX_MEMBERS,
    MAX_NAME_VALUES, NameValue, NameValueData, StoreLimits, SubjectAlgorithm, parse_catalog,
    parse_ctl,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm, hash_bytes};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/catalog");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// ---------------------------------------------------------------------------
// DER building.

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

fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count().min(3);
    let mut content = bytes[skip..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().unwrap()).collect();
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut stack = vec![(arc & 0x7f) as u8];
        let mut v = arc >> 7;
        while v > 0 {
            stack.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        out.extend(stack.iter().rev());
    }
    tlv(0x06, &out)
}

fn bmp(text: &str) -> Vec<u8> {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    tlv(0x1e, &units)
}

/// UTF-16LE, NUL-terminated, as catalogs store text.
fn utf16z(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend([0, 0]);
    out
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

const CTL: &str = "1.3.6.1.4.1.311.10.1";
const CATALOG_LIST: &str = "1.3.6.1.4.1.311.12.1.1";
const MEMBER_V1: &str = "1.3.6.1.4.1.311.12.1.2";
const MEMBER_V2: &str = "1.3.6.1.4.1.311.12.1.3";
const SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const SPC_PE_IMAGE_DATA: &str = "1.3.6.1.4.1.311.2.1.15";
const SPC_CAB_DATA: &str = "1.3.6.1.4.1.311.2.1.25";
const CAT_NAMEVALUE: &str = "1.3.6.1.4.1.311.12.2.1";
const CAT_MEMBERINFO: &str = "1.3.6.1.4.1.311.12.2.2";
const SHA1: &str = "1.3.14.3.2.26";
const SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// The subject interface package GUIDs of PE images and flat files.
const PE_SIP: &str = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
const FLAT_SIP: &str = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
/// `CRYPTCAT_ATTR_AUTHENTICATED | NAMEASCII | DATAASCII`.
const TEXT_FLAGS: u32 = 0x1001_0001;

/// A `CAT_NAMEVALUE` value.
fn name_value(name: &str, flags: u32, value: &[u8]) -> Vec<u8> {
    seq(&[&bmp(name), &integer(flags), &octets(value)])
}

fn attribute(type_oid: &str, values: &[&[u8]]) -> Vec<u8> {
    seq(&[&oid(type_oid), &set(values)])
}

/// One catalog member.
#[derive(Clone)]
struct Member {
    tag: Vec<u8>,
    attributes: Vec<Vec<u8>>,
}

impl Member {
    /// A member as OS catalog tools write it: tag is the digest in uppercase hex,
    /// then the name-values, the indirect data and the member info.
    fn new(pe: bool, alg: &str, digest: &[u8], file: &str) -> Self {
        let data = if pe {
            // SpcPeImageData { flags, file [0] { [2] { [0] "" } } }
            let link = tlv(0xa0, &tlv(0xa2, &tlv(0x80, &[])));
            seq(&[&oid(SPC_PE_IMAGE_DATA), &seq(&[&[0x03, 0x01, 0x00], &link])])
        } else {
            seq(&[&oid(SPC_CAB_DATA), &tlv(0xa2, &tlv(0x80, &[]))])
        };
        let indirect = seq(&[&data, &seq(&[&seq(&[&oid(alg), &null()]), &octets(digest)])]);
        let info = seq(&[&bmp(if pe { PE_SIP } else { FLAT_SIP }), &integer(512)]);
        Self {
            tag: utf16z(&hex_upper(digest)),
            attributes: vec![
                attribute(
                    CAT_NAMEVALUE,
                    &[&name_value("File", TEXT_FLAGS, &utf16z(file))],
                ),
                attribute(
                    CAT_NAMEVALUE,
                    &[&name_value("OSAttr", TEXT_FLAGS, &utf16z("2:10.0"))],
                ),
                attribute(SPC_INDIRECT_DATA, &[&indirect]),
                attribute(CAT_MEMBERINFO, &[&info]),
            ],
        }
    }

    fn der(&self) -> Vec<u8> {
        let attrs: Vec<&[u8]> = self.attributes.iter().map(Vec::as_slice).collect();
        seq(&[&octets(&self.tag), &set(&attrs)])
    }
}

/// A certificate trust list.
#[derive(Clone)]
struct Ctl {
    prefix: Vec<u8>,
    usage: Vec<String>,
    subject_alg: String,
    members: Vec<Vec<u8>>,
    extensions: Option<Vec<u8>>,
}

impl Ctl {
    fn new(subject_alg: &str) -> Self {
        Self {
            prefix: Vec::new(),
            usage: vec![CATALOG_LIST.to_owned()],
            subject_alg: subject_alg.to_owned(),
            members: Vec::new(),
            extensions: None,
        }
    }

    fn member(mut self, member: &Member) -> Self {
        self.members.push(member.der());
        self
    }

    /// Catalog-wide name-value pairs, as CTL extensions.
    fn attributes(mut self, pairs: &[(&str, &str)]) -> Self {
        let exts: Vec<Vec<u8>> = pairs
            .iter()
            .map(|(n, v)| {
                seq(&[
                    &oid(CAT_NAMEVALUE),
                    &octets(&name_value(n, TEXT_FLAGS, &utf16z(v))),
                ])
            })
            .collect();
        let refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
        self.extensions = Some(seq(&refs));
        self
    }

    fn der(&self) -> Vec<u8> {
        let usage: Vec<Vec<u8>> = self.usage.iter().map(|u| oid(u)).collect();
        let usage_refs: Vec<&[u8]> = usage.iter().map(Vec::as_slice).collect();
        let members: Vec<&[u8]> = self.members.iter().map(Vec::as_slice).collect();
        let mut parts: Vec<Vec<u8>> = vec![
            self.prefix.clone(),
            seq(&usage_refs),
            octets(&[0x50; 16]),
            // 2023-11-14 22:13:20 UTC (1700000000).
            tlv(0x17, b"231114221320Z"),
            seq(&[&oid(&self.subject_alg), &null()]),
        ];
        if !self.members.is_empty() {
            parts.push(seq(&members));
        }
        if let Some(ext) = &self.extensions {
            parts.push(tlv(0xa0, ext));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        seq(&refs)
    }
}

/// An unsigned catalog: a SignedData around `ctl` with no signers, as
/// makecat writes before signing. osslsigncode signs it.
fn unsigned_catalog(ctl: &[u8]) -> Vec<u8> {
    let signed = seq(&[
        &integer(1),
        &set(&[]),
        &seq(&[&oid(CTL), &tlv(0xa0, ctl)]),
        &set(&[]),
    ]);
    seq(&[&oid("1.2.840.113549.1.7.2"), &tlv(0xa0, &signed)])
}

/// The bytes of the flat member in the fixtures.
const FLAT_MEMBER: &[u8] = b"Palisade catalog test: a flat (non-PE) member file.\n";

fn pe_member_image() -> Vec<u8> {
    PeBuilder::default().build()
}

fn digest(data: &[u8], alg: HashAlgorithm) -> Vec<u8> {
    hash_bytes(data, AlgorithmSet::from(alg))
        .get(alg)
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn authenticode(data: &[u8], alg: HashAlgorithm) -> Vec<u8> {
    hash_pe(data, AlgorithmSet::EMPTY)
        .unwrap()
        .get(alg)
        .unwrap()
        .as_bytes()
        .to_vec()
}

/// The CTL each fixture signs.
fn fixture_ctl(name: &str) -> Vec<u8> {
    let image = pe_member_image();
    let (alg, subject, hash) = match name {
        "v1-sha1" => (SHA1, MEMBER_V1, HashAlgorithm::Sha1),
        "v2-sha256" | "org-sha256" => (SHA256, MEMBER_V2, HashAlgorithm::Sha256),
        other => panic!("no fixture {other}"),
    };
    let pe = Member::new(true, alg, &authenticode(&image, hash), "palisade-test.exe");
    let flat = Member::new(false, alg, &digest(FLAT_MEMBER, hash), "palisade-test.txt");
    let os = if name == "org-sha256" {
        "Organisation"
    } else {
        "_v100_X64"
    };
    Ctl::new(subject)
        .member(&pe)
        .member(&flat)
        .attributes(&[("OS", os), ("HWID1", "palisade\\test")])
        .der()
}

const FIXTURE_NAMES: [&str; 3] = ["v1-sha1", "v2-sha256", "org-sha256"];

/// Writes the unsigned catalogs `generate.sh` signs.
///
/// ```sh
/// PALISADE_CATALOG_OUT=/tmp/dir cargo test -p palisade-fileid --test catalog \
///     -- --ignored --exact write_unsigned_catalogs
/// ```
#[test]
#[ignore = "writes files; run by tests/fixtures/catalog/generate.sh"]
fn write_unsigned_catalogs() {
    let dir = std::env::var_os("PALISADE_CATALOG_OUT").expect("set PALISADE_CATALOG_OUT");
    let dir = std::path::Path::new(&dir);
    for name in FIXTURE_NAMES {
        let path = dir.join(format!("{name}.unsigned.cat"));
        std::fs::write(path, unsigned_catalog(&fixture_ctl(name))).unwrap();
    }
}

/// Writes fuzz seeds for `fuzz_ctl`: every fixture and its unsigned form.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/fuzz_ctl" \
///     cargo test -p palisade-fileid --test catalog -- --ignored write_ctl_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_ctl_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for name in FIXTURE_NAMES {
        std::fs::write(
            dir.join(format!("seed-{name}")),
            fixture(&format!("{name}.cat")),
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("seed-{name}-unsigned")),
            unsigned_catalog(&fixture_ctl(name)),
        )
        .unwrap();
    }
}

// ---------------------------------------------------------------------------
// DER reading, to take fixtures apart.

/// `(header length, content length)` of the element at `at`.
fn header(der: &[u8], at: usize) -> (usize, usize) {
    let first = der[at + 1];
    if first < 0x80 {
        (2, usize::from(first))
    } else {
        let n = usize::from(first & 0x7f);
        let len = der[at + 2..at + 2 + n]
            .iter()
            .fold(0, |acc, b| (acc << 8) | usize::from(*b));
        (2 + n, len)
    }
}

/// The offset of the element reached by taking child `i` at each level.
fn locate(der: &[u8], path: &[usize]) -> usize {
    let mut at = 0;
    for &child in path {
        let (h, _) = header(der, at);
        let mut pos = at + h;
        for _ in 0..child {
            let (h, l) = header(der, pos);
            pos += h + l;
        }
        at = pos;
    }
    at
}

fn element<'a>(der: &'a [u8], path: &[usize]) -> &'a [u8] {
    let at = locate(der, path);
    let (h, l) = header(der, at);
    &der[at..at + h + l]
}

/// ContentInfo [1] → [0] → SignedData; encapContentInfo is its child 2,
/// whose [0] holds the CTL.
const CTL_PATH: [usize; 5] = [1, 0, 2, 1, 0];
const SIGNER_INFOS: [usize; 3] = [1, 0, 4];

fn anchors(name: &str) -> TrustConfig {
    let mut config = TrustConfig::new();
    config.add_anchor(name, &fixture(name)).unwrap();
    config
}

// ---------------------------------------------------------------------------
// Parsing and signatures.

#[test]
fn fixture_ctls_are_the_builder_output() {
    for name in FIXTURE_NAMES {
        let cat = fixture(&format!("{name}.cat"));
        let ctl = element(&cat, &CTL_PATH);
        assert_eq!(ctl, fixture_ctl(name).as_slice(), "{name}");
    }
}

#[test]
fn v1_catalog_parses_and_verifies() {
    let image = pe_member_image();
    let cat = parse_catalog(&fixture("v1-sha1.cat")).unwrap();
    assert_eq!(
        cat.ctl.subject_algorithm,
        SubjectAlgorithm::CatalogListMember
    );
    assert_eq!(cat.ctl.this_update, 1_700_000_000);
    assert_eq!(cat.ctl.list_identifier.as_deref(), Some(&[0x50; 16][..]));
    assert_eq!(cat.ctl.members.len(), 2);
    assert!(cat.ctl.warnings.is_empty(), "{:?}", cat.ctl.warnings);
    assert_eq!(cat.ctl.os_attr(), Some("_v100_X64"));
    assert_eq!(cat.ctl.attribute("hwid1"), Some("palisade\\test"));

    let pe = &cat.ctl.members[0];
    let d = pe.digest.as_ref().unwrap();
    assert_eq!(d.alg, DigestAlgorithm::Sha1);
    assert!(d.is_pe_image());
    assert_eq!(d.digest, authenticode(&image, HashAlgorithm::Sha1));
    assert_eq!(pe.tag, hex_upper(&d.digest));
    assert_eq!(pe.file_name(), Some("palisade-test.exe"));
    assert_eq!(pe.os_attr(), Some("2:10.0"));
    assert_eq!(pe.subject_guid.as_deref(), Some(PE_SIP));
    assert_eq!(pe.cert_version, Some(512));

    let flat = &cat.ctl.members[1];
    let d = flat.digest.as_ref().unwrap();
    assert!(!d.is_pe_image());
    assert_eq!(d.digest, digest(FLAT_MEMBER, HashAlgorithm::Sha1));
    assert_eq!(flat.subject_guid.as_deref(), Some(FLAT_SIP));

    let sig = cat.signature().unwrap();
    assert_eq!(sig.kind, SignatureKind::Catalog);
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert_eq!(sig.signer_digest_alg, Some(DigestAlgorithm::Sha1));
    assert!(sig.warnings.contains(&SignatureWarning::Sha1Digest));
    assert!(sig.os_ci_compatible());
    assert_eq!(
        sig.signer.as_ref().unwrap().signing_time,
        Some(1_700_000_000)
    );
    assert_eq!(cat.signatures.signing_state, SigningState::Valid);
    assert!(cat.signature_valid());
    assert!(cat.warnings.is_empty());
    assert_eq!(
        cat.id.as_bytes(),
        digest(&fixture("v1-sha1.cat"), HashAlgorithm::Sha256)
    );
    assert_eq!(
        cat.members_with_digest(DigestAlgorithm::Sha1, &d.digest)
            .count(),
        1
    );
}

#[test]
fn v2_catalog_parses_and_verifies() {
    let image = pe_member_image();
    let cat = parse_catalog(&fixture("v2-sha256.cat")).unwrap();
    assert_eq!(
        cat.ctl.subject_algorithm,
        SubjectAlgorithm::CatalogListMemberV2
    );
    let pe = cat.ctl.members[0].digest.as_ref().unwrap();
    assert_eq!(pe.alg, DigestAlgorithm::Sha256);
    assert_eq!(pe.digest, authenticode(&image, HashAlgorithm::Sha256));
    let sig = cat.signature().unwrap();
    assert_eq!(sig.status, SignatureStatus::Valid);
    assert_eq!(sig.signer_digest_alg, Some(DigestAlgorithm::Sha256));
    assert!(!sig.warnings.contains(&SignatureWarning::Sha1Digest));
}

#[test]
fn catalog_signer_trust_and_identity() {
    let cat = parse_catalog(&fixture("v2-sha256.cat")).unwrap();
    let untrusted = cat.trust(&TrustConfig::new());
    assert_eq!(untrusted.primary, None);
    assert_eq!(
        untrusted.signers[0].untrusted,
        [UntrustedReason::NoTrustAnchor]
    );
    assert!(untrusted.identity.is_none());

    let trusted = cat.trust(&anchors("ca.der"));
    assert_eq!(trusted.primary, Some(0));
    let name = trusted.identity.unwrap().publisher_name.unwrap();
    assert_eq!(name.value, "Palisade Test Catalog Signer");

    // The organisation catalog is signed under another root.
    let org = parse_catalog(&fixture("org-sha256.cat")).unwrap();
    assert_eq!(org.trust(&anchors("ca.der")).primary, None);
    assert_eq!(org.trust(&anchors("org-ca.der")).primary, Some(0));
}

#[test]
fn tampered_ctl_fails_the_message_digest() {
    let mut cat = fixture("v2-sha256.cat");
    // Change a byte of the PE member's digest inside the signed CTL.
    let ctl_at = locate(&cat, &CTL_PATH);
    let image = pe_member_image();
    let d = authenticode(&image, HashAlgorithm::Sha256);
    let pos = ctl_at
        + cat[ctl_at..]
            .windows(d.len())
            .position(|w| w == d.as_slice())
            .unwrap();
    cat[pos] ^= 1;
    let parsed = parse_catalog(&cat).unwrap();
    assert_eq!(
        parsed.signature().unwrap().status,
        SignatureStatus::BadSignature(BadSignature::MessageDigestMismatch)
    );
    assert!(!parsed.signature_valid());
    assert!(matches!(
        parsed.signatures.signing_state,
        SigningState::Invalid(_)
    ));
    assert!(parsed.signature().unwrap().signer.is_none());
}

#[test]
fn tampered_signature_fails() {
    let mut cat = fixture("v2-sha256.cat");
    let infos = locate(&cat, &SIGNER_INFOS);
    let (h, l) = header(&cat, infos);
    // The signature value is the last bytes of the only SignerInfo.
    let last = infos + h + l - 1;
    cat[last] ^= 0x55;
    let parsed = parse_catalog(&cat).unwrap();
    assert_eq!(
        parsed.signature().unwrap().status,
        SignatureStatus::BadSignature(BadSignature::SignatureInvalid)
    );
}

#[test]
fn content_type_attribute_must_name_ctl() {
    let mut cat = fixture("v2-sha256.cat");
    // The contentType attribute holds the CTL OID; the encapsulated one
    // comes first. Change the second occurrence to 1.3.6.1.4.1.311.10.2.
    let ctl_oid = oid(CTL);
    let first = cat
        .windows(ctl_oid.len())
        .position(|w| w == ctl_oid)
        .unwrap();
    let second = first
        + 1
        + cat[first + 1..]
            .windows(ctl_oid.len())
            .position(|w| w == ctl_oid)
            .unwrap();
    *cat.get_mut(second + ctl_oid.len() - 1).unwrap() = 0x02;
    assert!(matches!(
        parse_catalog(&cat),
        Err(CatalogError::Envelope(SignatureError::ContentTypeMismatch(
            _
        )))
    ));
}

#[test]
fn authenticode_and_catalog_envelopes_do_not_mix() {
    // A PE signature is not a catalog.
    let pe_sig = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode/rsa2048-sha256.p7"
    ))
    .unwrap();
    assert!(matches!(
        parse_catalog(&pe_sig),
        Err(CatalogError::Envelope(SignatureError::NotCatalog(_)))
    ));
    // A catalog in a PE certificate table is not an Authenticode signature.
    let cat = fixture("v2-sha256.cat");
    let mut entry = Vec::new();
    let len = (8 + cat.len()) as u32;
    entry.extend(len.to_le_bytes());
    entry.extend(0x0200_u16.to_le_bytes());
    entry.extend(0x0002_u16.to_le_bytes());
    entry.extend(&cat);
    while entry.len() % 8 != 0 {
        entry.push(0);
    }
    let image = PeBuilder {
        certificate: Some(entry),
        ..PeBuilder::default()
    }
    .build();
    let report = palisade_fileid::authenticode::verify_pe(&image, &Default::default()).unwrap();
    assert!(matches!(
        report.signatures[0].status,
        SignatureStatus::Malformed(SignatureError::NotIndirectData(_))
    ));
}

#[test]
fn unsigned_catalog_is_not_a_catalog_signature() {
    let unsigned = unsigned_catalog(&fixture_ctl("v2-sha256"));
    assert!(matches!(
        parse_catalog(&unsigned),
        Err(CatalogError::Envelope(SignatureError::SignerCount(0)))
    ));
}

#[test]
fn trailing_data_is_reported() {
    let mut cat = fixture("v1-sha1.cat");
    cat.extend([0, 0, 0]);
    let parsed = parse_catalog(&cat).unwrap();
    assert!(parsed.signature_valid());
    assert_eq!(
        parsed.warnings,
        [palisade_fileid::catalog::CatalogWarning::TrailingData { len: 3 }]
    );
}

#[test]
fn oversized_catalog_is_rejected() {
    let big = vec![0_u8; usize::try_from(MAX_CATALOG_SIZE).unwrap() + 1];
    assert_eq!(
        parse_catalog(&big),
        Err(CatalogError::TooLarge(MAX_CATALOG_SIZE + 1))
    );
}

// ---------------------------------------------------------------------------
// CTL decoding rules.

fn simple_member(alg: &str, digest: &[u8]) -> Member {
    Member::new(true, alg, digest, "a.exe")
}

fn ctl_error(ctl: &Ctl) -> CtlError {
    parse_ctl(&ctl.der()).unwrap_err()
}

#[test]
fn ctl_version_must_be_absent() {
    let mut ctl = Ctl::new(MEMBER_V2);
    ctl.prefix = integer(0);
    assert!(matches!(ctl_error(&ctl), CtlError::Asn1(_)));
    ctl.prefix = integer(1);
    assert_eq!(ctl_error(&ctl), CtlError::Version(1));
}

#[test]
fn ctl_must_be_a_catalog_list() {
    let mut ctl = Ctl::new(MEMBER_V2);
    ctl.usage = vec!["1.3.6.1.4.1.311.10.3.9".to_owned()];
    assert_eq!(ctl_error(&ctl), CtlError::NotCatalogList);
}

#[test]
fn empty_catalog_parses() {
    let ctl = parse_ctl(&Ctl::new(MEMBER_V2).der()).unwrap();
    assert!(ctl.members.is_empty());
    assert!(ctl.attributes.is_empty());
}

#[test]
fn member_attribute_rules() {
    let d = [0x11; 32];
    let base = simple_member(SHA256, &d);

    let mut twice = base.clone();
    twice.attributes.push(twice.attributes[2].clone());
    assert!(matches!(
        ctl_error(&Ctl::new(MEMBER_V2).member(&twice)),
        CtlError::DuplicateAttribute { member: 0, .. }
    ));

    let mut short = simple_member(SHA256, &[0x11; 31]);
    short.tag = utf16z("x");
    assert_eq!(
        ctl_error(&Ctl::new(MEMBER_V2).member(&short)),
        CtlError::DigestLength { member: 0 }
    );

    let mut two_values = base.clone();
    let indirect = element(&two_values.attributes[2], &[1, 0]).to_vec();
    two_values.attributes[2] = attribute(SPC_INDIRECT_DATA, &[&indirect, &indirect]);
    assert!(matches!(
        ctl_error(&Ctl::new(MEMBER_V2).member(&two_values)),
        CtlError::AttributeValueCount { member: 0, .. }
    ));

    let mut many = base.clone();
    for i in 0..MAX_ATTRIBUTES {
        many.attributes.push(attribute(
            CAT_NAMEVALUE,
            &[&name_value(&format!("n{i}"), 0, &[])],
        ));
    }
    assert_eq!(
        ctl_error(&Ctl::new(MEMBER_V2).member(&many)),
        CtlError::TooManyAttributes
    );
}

#[test]
fn member_warnings() {
    let d = [0x22; 32];
    let mut odd_tag = simple_member(SHA256, &d);
    odd_tag.tag = utf16z("not-a-digest");
    let mut no_digest = simple_member(SHA256, &d);
    no_digest.attributes.remove(2);
    let unknown = simple_member("1.2.3.4", &d);
    let mut extra = simple_member(SHA256, &d);
    extra
        .attributes
        .push(attribute("1.2.3.5", &[&octets(b"x")]));
    let ctl = parse_ctl(
        &Ctl::new(MEMBER_V2)
            .member(&odd_tag)
            .member(&no_digest)
            .member(&unknown)
            .member(&extra)
            .der(),
    )
    .unwrap();
    assert_eq!(ctl.members[0].tag, "not-a-digest");
    assert!(ctl.members[0].digest.is_some());
    assert!(ctl.members[1].digest.is_none());
    assert!(ctl.members[2].digest.is_none());
    assert!(
        ctl.warnings
            .contains(&CtlWarning::TagNotDigest { member: 0 })
    );
    assert!(ctl.warnings.contains(&CtlWarning::NoDigest { member: 1 }));
    assert!(
        ctl.warnings
            .iter()
            .any(|w| matches!(w, CtlWarning::UnknownDigest { member: 2, .. }))
    );
    assert!(
        ctl.warnings
            .iter()
            .any(|w| matches!(w, CtlWarning::UnknownAttribute(_)))
    );
}

#[test]
fn name_values_are_bounded_and_typed() {
    let d = [0x33; 32];
    let mut member = simple_member(SHA256, &d);
    member.attributes.push(attribute(
        CAT_NAMEVALUE,
        &[&name_value("Blob", NameValue::DATA_BASE64, &[1, 2, 3])],
    ));
    for i in 0..MAX_NAME_VALUES {
        member.attributes.push(attribute(
            CAT_NAMEVALUE,
            &[&name_value(&format!("n{i}"), TEXT_FLAGS, &utf16z("v"))],
        ));
    }
    let ctl = parse_ctl(&Ctl::new(MEMBER_V2).member(&member).der()).unwrap();
    let m = &ctl.members[0];
    assert_eq!(m.name_values.len(), MAX_NAME_VALUES);
    assert_eq!(m.name_values[2].value, NameValueData::Bytes(vec![1, 2, 3]));
    assert_eq!(m.name_values[2].text(), None);
    assert!(ctl.warnings.contains(&CtlWarning::TooManyNameValues));
}

#[test]
fn extension_rules() {
    let critical_unknown = seq(&[&oid("1.2.3.6"), &[0x01, 0x01, 0xff], &octets(&null())]);
    let mut ctl = Ctl::new(MEMBER_V2);
    ctl.extensions = Some(seq(&[&critical_unknown]));
    assert!(matches!(
        ctl_error(&ctl),
        CtlError::UnhandledCriticalExtension(_)
    ));

    // `critical` FALSE must not be encoded.
    let explicit_false = seq(&[&oid("1.2.3.6"), &[0x01, 0x01, 0x00], &octets(&null())]);
    ctl.extensions = Some(seq(&[&explicit_false]));
    assert!(matches!(ctl_error(&ctl), CtlError::Asn1(_)));

    let unknown = seq(&[&oid("1.2.3.6"), &octets(&null())]);
    ctl.extensions = Some(seq(&[&unknown]));
    let parsed = parse_ctl(&ctl.der()).unwrap();
    assert!(
        parsed
            .warnings
            .iter()
            .any(|w| matches!(w, CtlWarning::UnknownExtension(_)))
    );

    let many: Vec<Vec<u8>> = (0..=MAX_ATTRIBUTES).map(|_| unknown.clone()).collect();
    let refs: Vec<&[u8]> = many.iter().map(Vec::as_slice).collect();
    ctl.extensions = Some(seq(&refs));
    assert_eq!(ctl_error(&ctl), CtlError::TooManyAttributes);
}

#[test]
fn members_are_bounded() {
    // Minimal members (a tag only) past the limit: read up to it, the rest
    // checked as DER and dropped.
    let tiny = seq(&[&octets(&utf16z("A"))]);
    let mut ctl = Ctl::new(MEMBER_V2);
    ctl.members = vec![tiny; MAX_MEMBERS + 2];
    let parsed = parse_ctl(&ctl.der()).unwrap();
    assert_eq!(parsed.members.len(), MAX_MEMBERS);
    assert!(parsed.members_truncated);
}

#[test]
fn ctl_rejects_trailing_and_ber() {
    let mut der = Ctl::new(MEMBER_V2).der();
    der.push(0);
    assert!(matches!(parse_ctl(&der), Err(CtlError::Asn1(_))));
    let mut indefinite = Ctl::new(MEMBER_V2).der();
    indefinite[1] = 0x80;
    assert!(matches!(parse_ctl(&indefinite), Err(CtlError::Asn1(_))));
}

// ---------------------------------------------------------------------------
// The store and lookups.

fn system_store() -> palisade_fileid::catalog::CatalogStore {
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchors("ca.der"))
        .trust(CatalogSource::Policy, anchors("org-ca.der"));
    for (name, source) in [
        ("v1-sha1.cat", CatalogSource::System),
        ("v2-sha256.cat", CatalogSource::System),
        ("org-sha256.cat", CatalogSource::Policy),
    ] {
        let r = b.add_bytes(source, Some(name.into()), &fixture(name));
        assert_eq!((r.recorded, r.valid), (1, 1), "{name}: {r:?}");
    }
    b.build()
}

#[test]
fn pe_lookup_tries_authenticode_sha256_then_sha1() {
    let store = system_store();
    assert_eq!(store.records().len(), 3);
    assert_eq!(store.indexed_members(), 6);
    let digests = FileDigests::of_bytes(&pe_member_image());
    let result = store.lookup(&digests);
    assert!(!result.truncated);
    let got: Vec<(usize, DigestKind, bool)> = result
        .matches
        .iter()
        .map(|m| (m.catalog, m.matched_by, m.trusted()))
        .collect();
    // Trusted first, then by digest kind: v2 (SHA-256), the organisation
    // catalog (SHA-256, trusted under its own anchors), then v1 (SHA-1).
    assert_eq!(
        got,
        [
            (1, DigestKind::AuthenticodeSha256, true),
            (2, DigestKind::AuthenticodeSha256, true),
            (0, DigestKind::AuthenticodeSha1, true),
        ]
    );
    let m = &result.matches[0];
    assert_eq!(m.member, 0);
    assert_eq!(m.record.status, CatalogStatus::Valid);
    assert_eq!(m.record.os_attr.as_deref(), Some("_v100_X64"));
    let signer = m.signer.unwrap();
    assert_eq!(
        signer
            .identity
            .as_ref()
            .unwrap()
            .publisher_name
            .as_ref()
            .unwrap()
            .value,
        "Palisade Test Catalog Signer"
    );
    assert!(result.matches[2].matched_by.is_sha1());
    // The two system catalogs share a signer.
    assert_eq!(store.signers().len(), 2);
}

#[test]
fn flat_lookup_matches_only_flat_members() {
    let store = system_store();
    let result = store.lookup(&FileDigests::of_bytes(FLAT_MEMBER));
    let got: Vec<(usize, DigestKind)> = result
        .matches
        .iter()
        .map(|m| (m.catalog, m.matched_by))
        .collect();
    assert_eq!(
        got,
        [
            (1, DigestKind::FlatSha256),
            (2, DigestKind::FlatSha256),
            (0, DigestKind::FlatSha1),
        ]
    );
    assert!(result.matches.iter().all(|m| m.member == 1));

    // A PE member's Authenticode digest offered as a flat digest, and a
    // flat member's digest offered as an Authenticode one, match nothing.
    let image = pe_member_image();
    let crossed = FileDigests {
        flat_sha256: hash_pe(&image, AlgorithmSet::EMPTY)
            .unwrap()
            .get(HashAlgorithm::Sha256)
            .cloned(),
        authenticode_sha256: hash_bytes(FLAT_MEMBER, AlgorithmSet::SHA256)
            .get(HashAlgorithm::Sha256)
            .cloned(),
        ..FileDigests::default()
    };
    assert!(store.lookup(&crossed).matches.is_empty());
}

#[test]
fn changed_file_does_not_match() {
    let store = system_store();
    let mut image = pe_member_image();
    // A byte inside the first section's raw data.
    image[0x400] ^= 0xff;
    assert!(
        store
            .lookup(&FileDigests::of_bytes(&image))
            .matches
            .is_empty()
    );
    let mut flat = FLAT_MEMBER.to_vec();
    flat.push(b'!');
    assert!(
        store
            .lookup(&FileDigests::of_bytes(&flat))
            .matches
            .is_empty()
    );
}

#[test]
fn sources_are_separate_namespaces() {
    let store = system_store();
    let digests = FileDigests::of_bytes(&pe_member_image());
    let system = store.lookup_in(&digests, &[CatalogSource::System]);
    assert!(
        system
            .matches
            .iter()
            .all(|m| m.record.source == CatalogSource::System)
    );
    assert_eq!(system.matches.len(), 2);
    let policy = store.lookup_in(&digests, &[CatalogSource::Policy]);
    assert_eq!(policy.matches.len(), 1);
    assert!(policy.matches[0].trusted());

    // The organisation catalog loaded as a system catalog is untrusted:
    // the system anchors do not cover it.
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchors("ca.der"));
    b.add_bytes(CatalogSource::System, None, &fixture("org-sha256.cat"));
    let store = b.build();
    let result = store.lookup(&digests);
    assert_eq!(result.matches.len(), 1);
    assert!(!result.matches[0].trusted());
    assert!(result.matches[0].signer.unwrap().identity.is_none());
    assert_eq!(
        result.matches[0].signer.unwrap().trust.untrusted,
        [UntrustedReason::NoTrustAnchor]
    );
}

#[test]
fn signers_follow_the_trust_configuration_in_force() {
    // The same catalog signer, first under no anchors, then under its
    // root: the second catalog gets a new verdict, not the cached one.
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    b.add_bytes(CatalogSource::System, None, &fixture("v1-sha1.cat"));
    let mut b = b.trust(CatalogSource::System, anchors("ca.der"));
    b.add_bytes(CatalogSource::System, None, &fixture("v2-sha256.cat"));
    let store = b.build();
    assert!(!store.records()[0].trusted);
    assert!(store.records()[1].trusted);
    assert_eq!(store.signers().len(), 2);
}

#[test]
fn invalid_catalogs_are_recorded_not_indexed() {
    let mut tampered = fixture("v2-sha256.cat");
    let infos = locate(&tampered, &SIGNER_INFOS);
    let (h, l) = header(&tampered, infos);
    tampered[infos + h + l - 1] ^= 1;
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    let r = b.add_bytes(CatalogSource::System, None, &tampered);
    assert_eq!((r.recorded, r.valid), (1, 0));
    let r = b.add_bytes(CatalogSource::System, None, b"not a catalog");
    assert_eq!((r.recorded, r.valid), (1, 0));
    let store = b.build();
    assert_eq!(store.indexed_members(), 0);
    assert!(matches!(
        store.records()[0].status,
        CatalogStatus::InvalidSignature(SignatureStatus::BadSignature(
            BadSignature::SignatureInvalid
        ))
    ));
    assert!(matches!(
        store.records()[1].status,
        CatalogStatus::Unreadable(CatalogError::Envelope(_))
    ));
    assert_eq!(store.records()[0].member_count, 2);
    assert!(
        store
            .lookup(&FileDigests::of_bytes(&pe_member_image()))
            .matches
            .is_empty()
    );
}

#[test]
fn duplicates_are_skipped_per_namespace() {
    let cat = fixture("v2-sha256.cat");
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    assert_eq!(b.add_bytes(CatalogSource::System, None, &cat).recorded, 1);
    assert_eq!(b.add_bytes(CatalogSource::System, None, &cat).duplicates, 1);
    assert_eq!(b.add_bytes(CatalogSource::Policy, None, &cat).recorded, 1);
    assert_eq!(
        b.add_bytes(CatalogSource::Policy, None, b"junk").recorded,
        1
    );
    assert_eq!(
        b.add_bytes(CatalogSource::Policy, None, b"junk").duplicates,
        1
    );
    assert_eq!(b.build().records().len(), 3);
}

#[test]
fn store_limits_fail_closed() {
    let v1 = fixture("v1-sha1.cat");
    let v2 = fixture("v2-sha256.cat");

    let limits = StoreLimits {
        max_catalogs: 1,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    b.add_bytes(CatalogSource::System, None, &v1);
    let r = b.add_bytes(CatalogSource::System, None, &v2);
    assert_eq!(r.errors, [LoadError::CatalogLimit]);
    assert_eq!(b.build().records().len(), 1);

    let limits = StoreLimits {
        max_total_bytes: (v1.len() + v2.len() - 1) as u64,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    b.add_bytes(CatalogSource::System, None, &v1);
    assert_eq!(
        b.add_bytes(CatalogSource::System, None, &v2).errors,
        [LoadError::ByteLimit]
    );

    let limits = StoreLimits {
        max_catalog_size: (v1.len() - 1) as u64,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    let r = b.add_bytes(CatalogSource::System, None, &v1);
    assert!(matches!(r.errors[..], [LoadError::TooLarge { .. }]));
    let store = b.build();
    assert!(matches!(
        store.records()[0].status,
        CatalogStatus::Unreadable(CatalogError::TooLarge(_))
    ));
    assert_eq!(store.records()[0].id, None);

    let limits = StoreLimits {
        max_members: 3,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    b.add_bytes(CatalogSource::System, None, &v1);
    let r = b.add_bytes(CatalogSource::System, None, &v2);
    assert_eq!(r.errors, [LoadError::MemberLimit]);
    let store = b.build();
    assert_eq!(store.indexed_members(), 3);
    assert!(store.records()[1].index_truncated);
    assert_eq!(store.records()[1].indexed_members, 1);
    // The member past the limit (v2's flat member) is not found.
    let flat = store.lookup(&FileDigests::of_bytes(FLAT_MEMBER));
    assert!(flat.matches.iter().all(|m| m.catalog == 0));
}

#[test]
fn lookup_returns_at_most_max_matches() {
    // MAX_MATCHES + 1 distinct catalogs that list the same file: the same
    // signed CTL with different trailing bytes, so each has its own ID.
    let cat = fixture("v2-sha256.cat");
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    for i in 0..=MAX_MATCHES {
        let mut c = cat.clone();
        c.extend(std::iter::repeat_n(0, i + 1));
        assert_eq!(b.add_bytes(CatalogSource::System, None, &c).valid, 1);
    }
    let store = b.build();
    let result = store.lookup(&FileDigests::of_bytes(&pe_member_image()));
    assert_eq!(result.matches.len(), MAX_MATCHES);
    assert!(result.truncated);
}

#[test]
fn non_conformant_and_empty_files_offer_no_digest() {
    // Data after the certificate table makes the layout non-conformant.
    let mut entry = 16_u32.to_le_bytes().to_vec();
    entry.extend(0x0200_u16.to_le_bytes());
    entry.extend(0x0002_u16.to_le_bytes());
    entry.extend([0; 8]);
    let image = PeBuilder {
        certificate: Some(entry),
        overlay: vec![1, 2, 3, 4, 5, 6, 7, 8],
        ..PeBuilder::default()
    }
    .build();
    let authenticode = hash_pe(&image, AlgorithmSet::EMPTY).unwrap();
    assert!(!authenticode.status.is_conformant());
    let digests = FileDigests::from_hashes(Some(&authenticode), None);
    assert_eq!(digests, FileDigests::default());

    let empty = hash_bytes(&[], AlgorithmSet::SHA256 | AlgorithmSet::SHA1);
    assert_eq!(
        FileDigests::from_hashes(None, Some(&empty)),
        FileDigests::default()
    );
}

/// A fresh, empty directory under the system temp directory.
fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "palisade-fileid-catalog-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn directory_loading() {
    let root = temp_dir("dir");
    let guid = root.join("{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");
    std::fs::create_dir_all(guid.join("deeper")).unwrap();
    std::fs::write(guid.join("b.cat"), fixture("v1-sha1.cat")).unwrap();
    std::fs::write(guid.join("A.CAT"), fixture("v2-sha256.cat")).unwrap();
    std::fs::write(guid.join("copy.cat"), fixture("v2-sha256.cat")).unwrap();
    std::fs::write(guid.join("notes.txt"), b"not a catalog").unwrap();
    std::fs::write(guid.join("deeper").join("bad.cat"), b"garbage").unwrap();

    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchors("ca.der"));
    let r = b.add_dir(CatalogSource::System, &root);
    assert_eq!(r.recorded, 3, "{r:?}");
    assert_eq!(r.valid, 2);
    assert_eq!(r.duplicates, 1);
    assert_eq!(r.skipped, 1);
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let store = b.build();
    // Name order: A.CAT, b.cat (copy.cat is a duplicate), then deeper/.
    let names: Vec<String> = store
        .records()
        .iter()
        .map(|r| {
            r.path
                .as_ref()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["A.CAT", "b.cat", "bad.cat"]);
    assert_eq!(
        store
            .lookup(&FileDigests::of_bytes(&pe_member_image()))
            .matches
            .len(),
        2
    );

    // Depth: the catalogs one level down are read, the next level is not.
    let limits = StoreLimits {
        max_depth: 1,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    let r = b.add_dir(CatalogSource::System, &root);
    assert_eq!(r.recorded, 2);
    assert!(matches!(r.errors[..], [LoadError::DepthLimit(_)]));

    let limits = StoreLimits {
        max_dir_entries: 2,
        ..StoreLimits::default()
    };
    let mut b = CatalogStoreBuilder::new(limits);
    let r = b.add_dir(CatalogSource::System, &root);
    assert!(r.errors.contains(&LoadError::EntryLimit));

    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    let r = b.add_dir(CatalogSource::System, &root.join("missing"));
    assert!(matches!(r.errors[..], [LoadError::Io { .. }]));
    let r = b.add_file(CatalogSource::System, &guid);
    assert!(matches!(r.errors[..], [LoadError::NotAFile(_)]));
    std::fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_not_followed() {
    let root = temp_dir("links");
    let outside = temp_dir("links-outside");
    std::fs::write(outside.join("x.cat"), fixture("v2-sha256.cat")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("linked-dir")).unwrap();
    std::os::unix::fs::symlink(outside.join("x.cat"), root.join("linked.cat")).unwrap();
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    let r = b.add_dir(CatalogSource::System, &root);
    assert_eq!(r.recorded, 0, "{r:?}");
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::remove_dir_all(&outside).unwrap();
}

// ---------------------------------------------------------------------------
// Robustness.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_ctl(&data);
        let _ = parse_catalog(&data);
    }

    #[test]
    fn mutated_catalogs_never_panic_and_never_verify(
        which in 0..FIXTURE_NAMES.len(),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), 1_u8..=255), 1..4),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let original = fixture(&format!("{}.cat", FIXTURE_NAMES[which]));
        let mut data = original.clone();
        for (at, mask) in &flips {
            let i = at.index(data.len());
            data[i] ^= mask;
        }
        if truncate {
            data.truncate(cut.index(data.len()));
        }
        let mut b = CatalogStoreBuilder::new(StoreLimits::default());
        let r = b.add_bytes(CatalogSource::System, None, &data);
        prop_assert_eq!(r.recorded, 1);
        let store = b.build();
        // A changed catalog may still verify only if the change is outside
        // what is signed (the certificates, say); if it does, it signs the
        // original CTL, so it lists nothing new.
        if let Ok(cat) = parse_catalog(&data) {
            if cat.signature_valid() {
                prop_assert_eq!(&cat.ctl, &parse_catalog(&original).unwrap().ctl);
            }
        }
        let _ = store.lookup(&FileDigests::of_bytes(&pe_member_image()));
    }
}
