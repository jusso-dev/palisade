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
    // Any byte of a stored file: the block map no longer matches.
    let id = parse_package(&tamper(&data, b"synthetic tool")).unwrap();
    assert!(matches!(
        id.signature.as_ref().unwrap().issue,
        Some(PackageSignatureIssue::BlockMap(_))
    ));
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

#[test]
#[ignore = "writes files; run by tests/fixtures/package/generate.sh"]
fn write_unsigned_packages() {
    let dir = std::env::var_os("PALISADE_PACKAGE_OUT").expect("set PALISADE_PACKAGE_OUT");
    let dir = std::path::Path::new(&dir);
    std::fs::write(dir.join("app.msix"), AppxBuilder::package().build()).unwrap();
    std::fs::write(dir.join("bundle.msixbundle"), AppxBuilder::bundle().build()).unwrap();
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
