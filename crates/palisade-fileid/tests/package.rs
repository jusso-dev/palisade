//! App package identity (#53): the manifest, the publisher ID and package
//! family name, the block map, the package signature, bundles, and the
//! strict ZIP reader.
//!
//! Every package is built at test time by `common/appx.rs`. The signed
//! fixtures in `tests/fixtures/package` are builder output signed by
//! osslsigncode with throwaway test keys (see `generate.sh` there).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

#[path = "common/appx.rs"]
mod appx;

use appx::*;
use palisade_fileid::authenticode::{SignatureKind, SignatureStatus, TrustConfig, evaluate_trust};
use palisade_fileid::package::blockmap::BlockMapError;
use palisade_fileid::package::zip::{Archive, ZipError};
use palisade_fileid::package::{
    PackageError, PackageSignatureIssue, PackageVersion, parse_package, publisher_id,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/package");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// Publisher IDs the OS reports, from public documentation of well-known
/// packages and from the OS's own family names, with the publisher strings
/// they come from. The algorithm is easy to get subtly wrong (bit order,
/// padding, alphabet), so it is pinned here and checked again by an
/// independent computation in `publisher_ids.txt`.
const KNOWN: &[(&str, &str)] = &[
    (
        "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        "8wekyb3d8bbwe",
    ),
    (
        "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
        "cw5n1h2txyewy",
    ),
];

#[test]
fn publisher_ids_match_the_os() {
    for (publisher, id) in KNOWN {
        assert_eq!(publisher_id(publisher), *id, "{publisher}");
    }
}

#[test]
fn publisher_ids_match_the_independent_vectors() {
    // `publisher_ids.txt`: publisher, a tab, the ID, computed by
    // `publisher_ids.py` with the standard library only.
    let text = std::fs::read_to_string(format!("{FIXTURES}/publisher_ids.txt")).unwrap();
    let mut n = 0;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (publisher, id) = line.split_once('\t').unwrap();
        assert_eq!(publisher_id(publisher), id, "{publisher:?}");
        assert_eq!(id.len(), 13);
        n += 1;
    }
    assert!(n >= 50, "{n} vectors");
}

#[test]
fn reads_package_identity() {
    let id = parse_package(&fixture("app-signed.msix")).unwrap();
    assert_eq!(id.name, "Palisade.TestApp");
    assert_eq!(id.publisher_dn, PUBLISHER);
    assert_eq!(id.publisher_id, publisher_id(PUBLISHER));
    assert_eq!(id.pfn, format!("Palisade.TestApp_{}", id.publisher_id));
    assert_eq!(
        id.full_name,
        format!("Palisade.TestApp_1.2.3.4_x64__{}", id.publisher_id)
    );
    assert_eq!(id.version, PackageVersion(1, 2, 3, 4));
    assert_eq!(id.arch, "x64");
    assert_eq!(id.resource_id, "");
    assert_eq!(id.display_name.as_deref(), Some("Palisade Test App"));
    assert_eq!(id.publisher_display_name.as_deref(), Some("Palisade Tests"));
    assert!(!id.is_bundle && !id.is_framework);
    assert_eq!(id.apps.len(), 1);
    let app = &id.apps[0];
    assert_eq!(app.id.as_deref(), Some("App"));
    assert_eq!(app.executable.as_deref(), Some("app/tool.exe"));
    assert_eq!(
        app.entry_point.as_deref(),
        Some("Windows.FullTrustApplication")
    );
    let caps: Vec<_> = id
        .capabilities
        .iter()
        .map(|c| (c.name.as_str(), c.is_restricted()))
        .collect();
    assert_eq!(
        caps,
        vec![
            ("internetClient", false),
            ("runFullTrust", true),
            ("webcam", false)
        ]
    );
    assert!(id.runs_full_trust());
    let alias = id
        .extensions
        .iter()
        .find(|e| e.category == "windows.appExecutionAlias")
        .unwrap();
    assert_eq!(alias.aliases, vec!["palisade-tool.exe"]);
    assert_eq!(alias.application.as_deref(), Some("App"));
    assert!(
        id.extensions
            .iter()
            .any(|e| e.category == "windows.fullTrustProcess"
                && e.executable.as_deref() == Some("app/helper.exe"))
    );
    let fam = id
        .dependencies
        .iter()
        .find(|d| d.kind == "TargetDeviceFamily")
        .unwrap();
    assert_eq!(fam.name, "Windows.Desktop");
    assert_eq!(fam.min_version.as_deref(), Some("10.0.17763.0"));
    assert_eq!(fam.max_version_tested.as_deref(), Some("10.0.22621.0"));
    assert!(
        id.dependencies
            .iter()
            .any(|d| d.kind == "PackageDependency" && d.name == "Palisade.Framework")
    );
}

#[test]
fn signed_package_verifies() {
    let id = parse_package(&fixture("app-signed.msix")).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.issue, None);
    let s = &sig.report.signatures[0];
    assert_eq!(s.kind, SignatureKind::Package);
    assert_eq!(s.status, SignatureStatus::Valid);
    assert_eq!(s.digest_match, Some(true));
    assert!(id.signature_valid());
    // Trusted only under the test root.
    assert!(
        evaluate_trust(&sig.report, &TrustConfig::new(), None)
            .primary
            .is_none()
    );
    let mut config = TrustConfig::new();
    config
        .add_anchor("package test root", &fixture("ca.der"))
        .unwrap();
    assert!(evaluate_trust(&sig.report, &config, None).primary.is_some());
    // The unsigned package parses to the same identity, unsigned.
    let unsigned = parse_package(&fixture("app.msix")).unwrap();
    assert!(unsigned.signature.is_none());
    assert_eq!(unsigned.pfn, id.pfn);
}

#[test]
fn committed_unsigned_packages_are_the_builder_output() {
    assert_eq!(fixture("app.msix"), AppxBuilder::package().build());
    assert_eq!(fixture("bundle.msixbundle"), AppxBuilder::bundle().build());
}

#[test]
fn publisher_mismatch_is_invalid() {
    let id = parse_package(&fixture("other-publisher.msix")).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert!(matches!(
        &sig.issue,
        Some(PackageSignatureIssue::PublisherMismatch { signer, publisher })
            if signer.starts_with("CN=Someone Else") && publisher == PUBLISHER
    ));
    assert!(!id.signature_valid());
    assert!(sig.report.primary.is_none());
}

// DER, to nest one package signature inside another.

fn der_header(der: &[u8], at: usize) -> (usize, usize) {
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

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
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

/// `der` with the element at `path` (child indexes, level by level)
/// replaced by `f` of it.
fn der_edit(der: &[u8], path: &[usize], f: &dyn Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let Some((&first, rest)) = path.split_first() else {
        return f(der);
    };
    let (h, l) = der_header(der, 0);
    let body = &der[h..h + l];
    let mut out = Vec::new();
    let (mut pos, mut index) = (0, 0);
    while pos < body.len() {
        let (ch, cl) = der_header(body, pos);
        let child = &body[pos..pos + ch + cl];
        if index == first {
            out.extend(der_edit(child, rest, f));
        } else {
            out.extend_from_slice(child);
        }
        pos += ch + cl;
        index += 1;
    }
    der_tlv(der[0], &out)
}

/// The signature `PKCX` + ContentInfo of a package.
fn p7x(data: &[u8]) -> Vec<u8> {
    let a = Archive::parse(data).unwrap();
    a.read(a.member("AppxSignature.p7x").unwrap()).unwrap()
}

/// `outer` (a signed package) with `inner`'s signature nested in its
/// SignerInfo as an `szOID_NESTED_SIGNATURE` unauthenticated attribute,
/// which the outer signature does not cover.
fn nest(outer: &[u8], inner: &[u8]) -> Vec<u8> {
    let outer_sig = p7x(outer);
    let inner_ci = p7x(inner)[4..].to_vec();
    // 1.3.6.1.4.1.311.2.4.1
    let oid = der_tlv(
        0x06,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01],
    );
    let attr = der_tlv(0x30, &[oid, der_tlv(0x31, &inner_ci)].concat());
    let unsigned = der_tlv(0xa1, &attr);
    // ContentInfo -> [0] (child 1) -> SignedData (its only child) ->
    // signerInfos (the last child) -> the only SignerInfo.
    let ci = &outer_sig[4..];
    let children = |der: &[u8]| -> Vec<(usize, usize)> {
        let (h, l) = der_header(der, 0);
        let mut out = Vec::new();
        let mut pos = h;
        while pos < h + l {
            let (ch, cl) = der_header(der, pos);
            out.push((pos, ch + cl));
            pos += ch + cl;
        }
        out
    };
    let (explicit_at, explicit_len) = children(ci)[1];
    let explicit = &ci[explicit_at..explicit_at + explicit_len];
    let (sd_at, sd_len) = children(explicit)[0];
    let sd = &explicit[sd_at..sd_at + sd_len];
    let signer_infos = children(sd).len() - 1;
    let new_ci = der_edit(ci, &[1, 0, signer_infos, 0], &|si| {
        let (h, l) = der_header(si, 0);
        let mut body = si[h..h + l].to_vec();
        body.extend_from_slice(&unsigned);
        der_tlv(si[0], &body)
    });
    let mut new_sig = b"PKCX".to_vec();
    new_sig.extend(new_ci);
    let mut files = members(outer);
    files.last_mut().unwrap().data = new_sig;
    // Rewriting the archive re-deflates every member, which changes the
    // records the signature covers; so keep the outer bytes and swap only
    // the signature member, stored, at the end.
    replace_signature(outer, &files.last().unwrap().data)
}

/// `signed` with its last member (the signature) replaced by `sig`, stored;
/// every other record is kept byte for byte.
fn replace_signature(signed: &[u8], sig: &[u8]) -> Vec<u8> {
    let a = Archive::parse(signed).unwrap();
    let last = a.members.last().unwrap();
    let mut out = signed[..last.local_offset as usize].to_vec();
    let mut central = Vec::new();
    for m in &a.members[..a.members.len() - 1] {
        central.extend_from_slice(a.central_bytes(m));
    }
    let offset = out.len() as u32;
    let name = last.name.as_bytes();
    let crc = crc32(sig);
    out.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
    out.extend_from_slice(&20_u16.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&[0, 0, 0x21, 0x58]);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(sig);
    central.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
    central.extend_from_slice(&45_u16.to_le_bytes());
    central.extend_from_slice(&20_u16.to_le_bytes());
    central.extend_from_slice(&[0, 0, 0, 0]);
    central.extend_from_slice(&[0, 0, 0x21, 0x58]);
    central.extend_from_slice(&crc.to_le_bytes());
    central.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    central.extend_from_slice(&(sig.len() as u32).to_le_bytes());
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&[0; 12]);
    central.extend_from_slice(&offset.to_le_bytes());
    central.extend_from_slice(name);
    let cd = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    let n = a.members.len() as u16;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes());
    out
}

#[test]
fn every_valid_signer_must_be_the_publisher() {
    let outer = fixture("app-signed.msix");
    // The signature swapped in unchanged still verifies (the helper keeps
    // every covered byte).
    let same = replace_signature(&outer, &p7x(&outer));
    assert!(parse_package(&same).unwrap().signature_valid());

    // A nested signature by another publisher: whichever signature trust
    // evaluation picks, the identity must not be vouched for by it.
    let id = parse_package(&nest(&outer, &fixture("other-publisher.msix"))).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.report.signatures.len(), 2);
    assert!(
        matches!(
            &sig.issue,
            Some(PackageSignatureIssue::PublisherMismatch { signer, .. })
                if signer.starts_with("CN=Someone Else")
        ),
        "{:?}",
        sig.issue
    );
    assert!(!id.signature_valid());
    assert!(sig.report.signatures.iter().all(|s| !s.status.is_valid()));
    let mut config = TrustConfig::new();
    config
        .add_anchor("package test root", &fixture("ca.der"))
        .unwrap();
    assert!(evaluate_trust(&sig.report, &config, None).primary.is_none());

    // Nested by the same publisher: both valid, and the identity holds.
    let id = parse_package(&nest(&outer, &fixture("app-sha384.msix"))).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.report.signatures.len(), 2);
    assert!(id.signature_valid(), "{:?}", sig.issue);
    assert!(sig.report.signatures.iter().all(|s| s.status.is_valid()));
}

#[test]
fn bundles() {
    let id = parse_package(&fixture("bundle-signed.msixbundle")).unwrap();
    assert!(id.is_bundle);
    assert_eq!(id.name, "Palisade.TestBundle");
    assert_eq!(id.version, PackageVersion(2, 0, 0, 0));
    assert_eq!(
        id.pfn,
        format!("Palisade.TestBundle_{}", publisher_id(PUBLISHER))
    );
    assert_eq!(id.members.len(), 2);
    let m = &id.members[0];
    assert_eq!(
        (m.kind.as_str(), m.arch.as_str(), m.file_name.as_str()),
        ("application", "x64", "app_x64.msix")
    );
    assert_eq!((m.offset, m.size), (Some(100), Some(32)));
    assert_eq!(id.members[1].resource_id, "en-us");
    assert!(
        id.signature_valid(),
        "{:?}",
        id.signature.as_ref().map(|s| &s.issue)
    );
    assert_eq!(
        id.signature.as_ref().unwrap().report.signatures[0].kind,
        SignatureKind::Package
    );
}

/// Flips one bit of the first occurrence of `needle`.
fn tamper(data: &[u8], needle: &[u8]) -> Vec<u8> {
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut out = data.to_vec();
    out[at] ^= 0x01;
    out
}

#[test]
fn tampering_is_never_valid() {
    let data = fixture("app-signed.msix");
    // Any byte of a stored file: the records the signature covers change,
    // so the digest no longer matches (the block map would not either).
    let id = parse_package(&tamper(&data, b"synthetic tool")).unwrap();
    assert_eq!(
        id.signature.as_ref().unwrap().report.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
    assert!(!id.signature_valid());
    // A deflated file whose compressed bytes change no longer inflates
    // to its CRC, so the block map check fails too.
    let a = Archive::parse(&data).unwrap();
    let big = a.member("assets/big.bin").unwrap();
    let mut bad = data.clone();
    bad[(big.data_offset + 100) as usize] ^= 0x10;
    assert!(!parse_package(&bad).unwrap().signature_valid());
    // The same file changed with its CRC and block map recomputed: the
    // block map's hash in the signed digest no longer matches.
    let mut files = members(&data);
    files[1].data = b"MZ synthetic tooL, not a real PE".to_vec();
    let rebuilt = rebuild(&files, true);
    let id = parse_package(&rebuilt).unwrap();
    assert!(!id.signature_valid());
}

/// The members of a signed package, decompressed, in order.
fn members(data: &[u8]) -> Vec<File> {
    let a = Archive::parse(data).unwrap();
    a.members
        .iter()
        .map(|m| File {
            name: m.name.clone(),
            data: a.read(m).unwrap(),
            deflate: m.method == 8,
        })
        .collect()
}

/// Writes `files` again; with `fix_blockmap`, the block map is rebuilt for
/// the payload files first.
fn rebuild(files: &[File], fix_blockmap: bool) -> Vec<u8> {
    let mut files = files.to_vec();
    if fix_blockmap {
        let payload: Vec<File> = files
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
            .collect();
        let map = AppxBuilder {
            files: payload,
            blockmap_extra: String::new(),
            blockmap_skip: None,
        }
        .block_map();
        for f in &mut files {
            if f.name == "AppxBlockMap.xml" {
                f.data = map.clone().into_bytes();
            }
        }
    }
    write_zip(&files)
}

#[test]
fn a_moved_signature_does_not_verify() {
    let data = fixture("app-signed.msix");
    // Written again from its own members with the same content but
    // different deflate encoding: the signature covers the records as
    // stored, so it no longer verifies.
    let same = rebuild(&members(&data), false);
    assert_ne!(same, data);
    let id = parse_package(&same).unwrap();
    assert!(!id.signature_valid());
    assert_eq!(
        id.signature.as_ref().unwrap().report.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
    // Onto a different package (one stored file changed, block map
    // rebuilt to match), the digest does not match.
    let mut files = members(&data);
    files[3].data.push(9);
    let id = parse_package(&rebuild(&files, true)).unwrap();
    assert!(!id.signature_valid());
    assert!(id.signature.as_ref().unwrap().issue.is_none());
    assert_eq!(
        id.signature.as_ref().unwrap().report.signatures[0].status,
        SignatureStatus::DigestMismatch
    );
    // A PE signature in its place is malformed for a package.
    let pe = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode/rsa2048-sha256.p7"
    ))
    .unwrap();
    let with_sig = |sig: Vec<u8>| {
        let mut files = members(&data);
        files.last_mut().unwrap().data = sig;
        rebuild(&files, false)
    };
    let mut prefixed = b"PKCX".to_vec();
    prefixed.extend_from_slice(&pe);
    let id = parse_package(&with_sig(prefixed)).unwrap();
    let s = &id.signature.as_ref().unwrap().report.signatures[0];
    assert!(
        matches!(s.status, SignatureStatus::Malformed(_)),
        "{:?}",
        s.status
    );
    // Without the PKCX prefix it is not a package signature at all.
    let id = parse_package(&with_sig(pe)).unwrap();
    assert_eq!(
        id.signature.as_ref().unwrap().issue,
        Some(PackageSignatureIssue::BadContainer)
    );
    // The signature must be the last member.
    let mut files = members(&data);
    let sig = files.pop().unwrap();
    files.insert(0, sig);
    let id = parse_package(&write_zip(&files)).unwrap();
    assert_eq!(
        id.signature.as_ref().unwrap().issue,
        Some(PackageSignatureIssue::NotLast)
    );
}

#[test]
fn block_map_must_cover_every_file() {
    // A block map that leaves a file out.
    let mut skip = AppxBuilder::package();
    skip.blockmap_skip = Some("logo.png".into());
    let archive_bytes = skip.build();
    let archive = Archive::parse(&archive_bytes).unwrap();
    let map = palisade_fileid::package::blockmap::parse(
        &archive
            .read(archive.member("AppxBlockMap.xml").unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        palisade_fileid::package::blockmap::verify(&map, &archive),
        Err(BlockMapError::Unlisted(n)) if n == "logo.png"
    ));
    // In a signed package: a block map with a file left out.
    let mut files = members(&fixture("app-signed.msix"));
    let map_at = files
        .iter()
        .position(|f| f.name == "AppxBlockMap.xml")
        .unwrap();
    files[map_at].data = skip.block_map().into_bytes();
    let id = parse_package(&write_zip(&files)).unwrap();
    assert!(!id.signature_valid());
}

#[test]
fn part_names_compare_as_opc_compares_them() {
    // Special parts are found whatever their case or percent-encoding.
    let mut both = AppxBuilder::package();
    both.files.push(File {
        name: "AppxMetadata/appxbundlemanifest.xml".into(),
        data: AppxBuilder::bundle().files[0].data.clone(),
        deflate: false,
    });
    assert_eq!(
        parse_package(&both.build()).unwrap_err(),
        PackageError::NotPackage
    );
    let mut escaped = AppxBuilder::package();
    escaped.files.push(File {
        name: "AppxMetadata/%41ppxBundleManifest.xml".into(),
        data: AppxBuilder::bundle().files[0].data.clone(),
        deflate: false,
    });
    assert_eq!(
        parse_package(&escaped.build()).unwrap_err(),
        PackageError::NotPackage
    );
    // A lower-case signature part is still the signature.
    let mut files = members(&fixture("app-signed.msix"));
    files.last_mut().unwrap().name = "appxsignature.p7x".into();
    let id = parse_package(&write_zip(&files)).unwrap();
    assert!(id.signature.is_some());
    // Escaped traversal, separators and NUL are refused like plain ones.
    for name in [
        "a/%2e%2e/b.exe",
        "%2ftool.exe",
        "a%5cb.exe",
        "a%00b.exe",
        "bad%2",
    ] {
        let mut b = AppxBuilder::package();
        b.files[1].name = name.into();
        assert!(
            matches!(
                Archive::parse(&b.build()).unwrap_err(),
                ZipError::BadName(_)
            ),
            "{name}"
        );
    }
    // Two spellings of one part are a duplicate.
    let mut dup = AppxBuilder::package();
    dup.files.push(File {
        name: "app/tool%2Eexe".into(),
        data: vec![1],
        deflate: false,
    });
    assert!(matches!(
        Archive::parse(&dup.build()).unwrap_err(),
        ZipError::DuplicateName(_)
    ));
}

#[test]
fn empty_deflated_files_verify_in_the_block_map() {
    let mut b = AppxBuilder::package();
    b.files.push(File {
        name: "empty.txt".into(),
        data: Vec::new(),
        deflate: true,
    });
    let data = b.build();
    let archive = Archive::parse(&data).unwrap();
    let map = palisade_fileid::package::blockmap::parse(
        &archive
            .read(archive.member("AppxBlockMap.xml").unwrap())
            .unwrap(),
    )
    .unwrap();
    palisade_fileid::package::blockmap::verify(&map, &archive).unwrap();
}

#[test]
fn manifest_sections_appear_once() {
    let twice = manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").replace(
        "<Capabilities>",
        "<Capabilities></Capabilities><Capabilities>",
    );
    let mut b = AppxBuilder::package();
    b.files[0].data = twice.into_bytes();
    assert!(matches!(
        parse_package(&b.build()).unwrap_err(),
        PackageError::Manifest(palisade_fileid::package::ManifestError::Duplicate(
            "Capabilities"
        ))
    ));
    // A namespace declaration with a reference is refused rather than
    // bound differently from a normalising reader.
    let escaped = manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").replace(
        "windows10/restrictedcapabilities",
        "windows10/&#x72;estrictedcapabilities",
    );
    let mut b = AppxBuilder::package();
    b.files[0].data = escaped.into_bytes();
    assert!(matches!(
        parse_package(&b.build()).unwrap_err(),
        PackageError::Manifest(_)
    ));
}

#[test]
fn zip_differentials_are_refused() {
    let data = AppxBuilder::package().build();
    // An archive comment.
    let mut comment = data.clone();
    let n = comment.len();
    comment[n - 2] = 3;
    comment.extend_from_slice(b"abc");
    assert_eq!(Archive::parse(&comment).unwrap_err(), ZipError::EndRecord);
    // Data before the first local header.
    let mut prefixed = vec![0_u8; 16];
    prefixed.extend_from_slice(&data);
    assert!(Archive::parse(&prefixed).is_err());
    // Two members whose names differ only in case.
    let mut dup = AppxBuilder::package();
    dup.files.push(File {
        name: "LOGO.PNG".into(),
        data: vec![1],
        deflate: false,
    });
    assert!(matches!(
        Archive::parse(&dup.build()).unwrap_err(),
        ZipError::DuplicateName(_)
    ));
    // A path traversal name.
    let mut trav = AppxBuilder::package();
    trav.files[1].name = "../tool.exe".into();
    assert!(matches!(
        Archive::parse(&trav.build()).unwrap_err(),
        ZipError::BadName(_)
    ));
    // Truncation anywhere fails.
    for cut in [10, data.len() / 2, data.len() - 1] {
        assert!(Archive::parse(&data[..cut]).is_err(), "cut at {cut}");
    }
    // A central entry that disagrees with its local header (the stored
    // compressed size of the first member, in the central directory).
    let a = Archive::parse(&data).unwrap();
    let first = &a.members[0];
    let mut bad = data.clone();
    let at = first.central_raw.0 + 20;
    bad[at] ^= 1;
    assert!(Archive::parse(&bad).is_err());
}

#[test]
fn manifests_are_strict() {
    let mut doctype = AppxBuilder::package();
    doctype.files[0].data = br#"<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x "y">]><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="A.B.C" Publisher="CN=x" Version="1.0.0.0"/></Package>"#.to_vec();
    assert!(matches!(
        parse_package(&doctype.build()).unwrap_err(),
        PackageError::Manifest(_)
    ));
    // Bad versions, names and duplicate identities.
    for manifest in [
        manifest("Palisade.TestApp", PUBLISHER, "1.2.3", "x64"),
        manifest("ab", PUBLISHER, "1.2.3.4", "x64"),
        manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "sparc"),
        manifest("Palisade.TestApp", "", "1.2.3.4", "x64"),
        manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").replace(
            "<Properties>",
            "<Identity Name=\"Other.App\" Publisher=\"CN=x\" Version=\"1.0.0.0\"/><Properties>",
        ),
    ] {
        let mut b = AppxBuilder::package();
        b.files[0].data = manifest.into_bytes();
        assert!(parse_package(&b.build()).is_err());
    }
    // Neither manifest, or both.
    let mut none = AppxBuilder::package();
    none.files.remove(0);
    assert_eq!(
        parse_package(&none.build()).unwrap_err(),
        PackageError::NotPackage
    );
    let mut both = AppxBuilder::bundle();
    both.files.push(AppxBuilder::package().files[0].clone());
    assert_eq!(
        parse_package(&both.build()).unwrap_err(),
        PackageError::NotPackage
    );
    // A foreign-prefixed Name attribute is not the identity's Name.
    let spoof = manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").replace(
        "<Identity Name=\"Palisade.TestApp\"",
        "<Identity xmlns:z=\"urn:z\" z:Name=\"Evil.App\" Name=\"Palisade.TestApp\"",
    );
    let mut b = AppxBuilder::package();
    b.files[0].data = spoof.into_bytes();
    assert_eq!(parse_package(&b.build()).unwrap().name, "Palisade.TestApp");
}

const DESCRIPTORS: ZipStyle = ZipStyle {
    descriptors: true,
    zip64: false,
};
const ZIP64: ZipStyle = ZipStyle {
    descriptors: true,
    zip64: true,
};

#[test]
fn descriptor_and_zip64_layouts_verify() {
    for (name, style) in [("app-desc.msix", DESCRIPTORS), ("app-zip64.msix", ZIP64)] {
        let unsigned = AppxBuilder::package().build_with(style);
        let a = Archive::parse(&unsigned).unwrap();
        assert_eq!(a.zip64, style.zip64, "{name}");
        assert_eq!(parse_package(&unsigned).unwrap().name, "Palisade.TestApp");
        let id = parse_package(&fixture(name)).unwrap();
        assert!(
            id.signature_valid(),
            "{name}: {:?}",
            id.signature
                .as_ref()
                .map(|s| (&s.issue, &s.report.signatures[0].status))
        );
        assert_eq!(
            fixture(&name.replace(".msix", "-unsigned.msix")),
            unsigned,
            "{name}"
        );
    }
    // A data descriptor without its signature is refused.
    let mut bad = AppxBuilder::package().build_with(DESCRIPTORS);
    let sig = 0x0807_4b50_u32.to_le_bytes();
    let at = bad.windows(4).position(|w| w == sig).unwrap();
    bad[at] = 0;
    assert!(Archive::parse(&bad).is_err());
    // An extra field other than one ZIP64 block in a central entry is
    // refused.
    let mut extra = AppxBuilder::package().build();
    let a = Archive::parse(&extra).unwrap();
    let first = a.members[0].central_raw.0;
    extra[first + 30] = 4;
    assert!(Archive::parse(&extra).is_err());
}

#[test]
#[ignore = "writes files; run by tests/fixtures/package/generate.sh"]
fn write_unsigned_packages() {
    let dir = std::env::var_os("PALISADE_PACKAGE_OUT").expect("set PALISADE_PACKAGE_OUT");
    let dir = std::path::Path::new(&dir);
    std::fs::write(dir.join("app.msix"), AppxBuilder::package().build()).unwrap();
    std::fs::write(dir.join("bundle.msixbundle"), AppxBuilder::bundle().build()).unwrap();
    std::fs::write(
        dir.join("app-desc-unsigned.msix"),
        AppxBuilder::package().build_with(DESCRIPTORS),
    )
    .unwrap();
    std::fs::write(
        dir.join("app-zip64-unsigned.msix"),
        AppxBuilder::package().build_with(ZIP64),
    )
    .unwrap();
}

#[test]
#[ignore = "writes files; run by cargo xtask fuzz"]
fn write_package_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for name in [
        "app.msix",
        "app-signed.msix",
        "bundle-signed.msixbundle",
        "other-publisher.msix",
    ] {
        std::fs::write(dir.join(format!("seed-{name}")), fixture(name)).unwrap();
    }
    std::fs::write(
        dir.join("seed-manifest.xml"),
        manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64"),
    )
    .unwrap();
}

#[test]
fn unmapped_parts_are_bounded() {
    // `[Content_Types].xml` is not in the block map; one that inflates past
    // the metadata limit is not hashed, so the signature cannot verify,
    // and parsing stays fast.
    let mut files = members(&fixture("app-signed.msix"));
    let ct = files
        .iter_mut()
        .find(|f| f.name == "[Content_Types].xml")
        .unwrap();
    ct.data = vec![b' '; palisade_fileid::package::MAX_METADATA_SIZE as usize + 1];
    let start = std::time::Instant::now();
    let id = parse_package(&write_zip(&files)).unwrap();
    assert!(!id.signature_valid());
    assert!(start.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn round_two_review_cases() {
    // Escaped `/` or `\` inside a segment, and `%+` escapes, are refused.
    for name in [
        "a%2fb.exe",
        "AppxMetadata%2FCodeIntegrity.cat",
        "a%5Cb.exe",
        "app/%+9tool.exe",
    ] {
        let mut b = AppxBuilder::package();
        b.files[1].name = name.into();
        assert!(
            matches!(
                Archive::parse(&b.build()).unwrap_err(),
                ZipError::BadName(_)
            ),
            "{name}"
        );
    }

    // Block sizes that overflow when summed are a mismatch, not a panic.
    let mut b = AppxBuilder::package();
    b.blockmap_extra = String::new();
    let data = b.build();
    let archive = Archive::parse(&data).unwrap();
    let map_xml = String::from_utf8(
        archive
            .read(archive.member("AppxBlockMap.xml").unwrap())
            .unwrap(),
    )
    .unwrap();
    // big.bin has three blocks; give them sizes that wrap.
    let mut n = 0;
    let patched: String = map_xml
        .split("<Block ")
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                return part.to_owned();
            }
            let inside_big = map_xml
                .split("<Block ")
                .take(i)
                .collect::<String>()
                .rsplit("<File ")
                .next()
                .unwrap()
                .contains("assets\\big.bin");
            if inside_big {
                n += 1;
                let size = if n == 1 { u64::MAX } else { 1 };
                format!("<Block Size=\"{size}\" {part}")
            } else {
                format!("<Block {part}")
            }
        })
        .collect();
    assert_eq!(n, 3);
    let map = palisade_fileid::package::blockmap::parse(patched.as_bytes()).unwrap();
    assert!(palisade_fileid::package::blockmap::verify(&map, &archive).is_err());

    // Extra data after a ZIP64 block, or a ZIP64 block nothing calls for,
    // is refused.
    let zip64 = AppxBuilder::package().build_with(ZIP64);
    let a = Archive::parse(&zip64).unwrap();
    let first = &a.members[0];
    let (at, len) = first.central_raw;
    let name_len = u16::from_le_bytes([zip64[at + 28], zip64[at + 29]]) as usize;
    let extra_len = u16::from_le_bytes([zip64[at + 30], zip64[at + 31]]) as usize;
    assert_eq!(extra_len, 28);
    let extra_end = at + 46 + name_len + extra_len;
    let mut trailing = zip64[..extra_end].to_vec();
    trailing.extend_from_slice(&[0xfe, 0xca, 0, 0]);
    trailing.extend_from_slice(&zip64[extra_end..]);
    // Fix the extra length, the central directory size and offsets.
    trailing[at + 30] = 32;
    let _ = len;
    assert!(Archive::parse(&trailing).is_err());
    let plain = AppxBuilder::package().build();
    let a = Archive::parse(&plain).unwrap();
    let (at, _) = a.members[0].central_raw;
    assert_eq!(plain[at + 30], 0);
}

#[test]
fn many_namespaces_parse_quickly() {
    let mut doc = String::from("<r xmlns=\"urn:root\">");
    for i in 0..5000 {
        doc.push_str(&format!(
            "<p{i}:a xmlns:p{i}=\"urn:{}{i}\"/>",
            "x".repeat(900)
        ));
    }
    doc.push_str("</r>");
    let start = std::time::Instant::now();
    palisade_fileid::package::xml::parse(doc.as_bytes()).unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
}
