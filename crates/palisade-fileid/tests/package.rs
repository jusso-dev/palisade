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
use palisade_fileid::package::blockmap::NS as BLOCK_MAP;
use palisade_fileid::package::manifest::ns::FOUNDATION;
use palisade_fileid::package::zip::{Archive, ZipError};
use palisade_fileid::package::{
    PackageError, PackageSignatureIssue, PackageVersion, parse_package, publisher_id, signed_digest,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/package");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// Publisher IDs the OS reports for two well-known publishers, from public
/// documentation of well-known packages and from the OS's own family names:
/// `os_publisher_ids.txt`, which `publisher_ids.py` checks too. The algorithm is easy to get subtly
/// wrong (bit order, padding, alphabet), so it is pinned here, and checked
/// again by that script's independent computation of every vector.
const KNOWN_IDS: [&str; 2] = ["8wekyb3d8bbwe", "cw5n1h2txyewy"];

#[test]
fn publisher_ids_match_the_os() {
    let text = std::fs::read_to_string(format!("{FIXTURES}/os_publisher_ids.txt")).unwrap();
    let known: Vec<(&str, &str)> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.split_once('\t').unwrap())
        .collect();
    assert_eq!(known.iter().map(|k| k.1).collect::<Vec<_>>(), KNOWN_IDS);
    for (publisher, id) in known {
        assert_eq!(publisher_id(publisher), id, "{publisher}");
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
    // ZIP64 end records, as the OS signing tool writes them.
    let cd = out.len() as u64;
    out.extend_from_slice(&central);
    let rec = out.len() as u64;
    let n = a.members.len() as u64;
    out.extend_from_slice(&0x0606_4b50_u32.to_le_bytes());
    out.extend_from_slice(&44_u64.to_le_bytes());
    out.extend_from_slice(&45_u16.to_le_bytes());
    out.extend_from_slice(&45_u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(central.len() as u64).to_le_bytes());
    out.extend_from_slice(&cd.to_le_bytes());
    out.extend_from_slice(&0x0706_4b50_u32.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&rec.to_le_bytes());
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&[0xff; 12]);
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
    let signed = fixture("bundle-signed.msixbundle");
    let a = Archive::parse(&signed).unwrap();
    let x64 = a.member("app_x64.msix").unwrap();
    assert_eq!((m.offset, m.size), (Some(x64.data_offset), Some(x64.size)));
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
    write_zip_with(&files, &ZipStyle::packaging_tool())
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
    let id = parse_package(&write_zip_with(&files, &ZipStyle::packaging_tool())).unwrap();
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
    let id = parse_package(&write_zip_with(&files, &ZipStyle::packaging_tool())).unwrap();
    assert!(!id.signature_valid());
    assert_ne!(
        id.signature.as_ref().unwrap().issue,
        Some(PackageSignatureIssue::NotZip64)
    );
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
    let id = parse_package(&write_zip_with(&files, &ZipStyle::packaging_tool())).unwrap();
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
    doctype.files[0].data = format!(r#"<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x "y">]><Package xmlns="{FOUNDATION}"><Identity Name="A.B.C" Publisher="CN=x" Version="1.0.0.0"/></Package>"#).into_bytes();
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

fn descriptors() -> ZipStyle {
    ZipStyle {
        descriptors: true,
        ..ZipStyle::default()
    }
}

fn zip64() -> ZipStyle {
    ZipStyle {
        descriptors: true,
        zip64: true,
        ..ZipStyle::default()
    }
}

#[test]
fn descriptor_and_zip64_layouts_verify() {
    // Each layout reads; signed, a ZIP64 one verifies and a classic one is
    // never valid (`NotZip64`: the OS rejects a signed classic archive,
    // whatever its digest).
    for (name, style, valid) in [
        ("app-desc.msix", descriptors(), false),
        ("app-classic.msix", ZipStyle::default(), false),
        ("app-zip64.msix", zip64(), true),
    ] {
        let unsigned = AppxBuilder::package().build_with(&style);
        let a = Archive::parse(&unsigned).unwrap();
        assert_eq!(a.zip64, style.zip64, "{name}");
        assert_eq!(parse_package(&unsigned).unwrap().name, "Palisade.TestApp");
        let id = parse_package(&fixture(name)).unwrap();
        let why = id
            .signature
            .as_ref()
            .map(|s| (s.issue.clone(), s.report.signatures[0].status.clone()));
        assert_eq!(id.signature_valid(), valid, "{name}: {why:?}");
        if !valid {
            assert_eq!(
                id.signature.as_ref().unwrap().issue,
                Some(PackageSignatureIssue::NotZip64),
                "{name}"
            );
        }
        assert_eq!(
            fixture(&name.replace(".msix", "-unsigned.msix")),
            unsigned,
            "{name}"
        );
    }
    // A data descriptor without its signature is refused.
    let mut bad = AppxBuilder::package().build_with(&descriptors());
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
    std::fs::write(
        dir.join("app-classic-unsigned.msix"),
        AppxBuilder::package().build_classic(),
    )
    .unwrap();
    std::fs::write(dir.join("bundle.msixbundle"), AppxBuilder::bundle().build()).unwrap();
    std::fs::write(
        dir.join("app-desc-unsigned.msix"),
        AppxBuilder::package().build_with(&descriptors()),
    )
    .unwrap();
    std::fs::write(
        dir.join("app-zip64-unsigned.msix"),
        AppxBuilder::package().build_with(&zip64()),
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
    let id = parse_package(&write_zip_with(&files, &ZipStyle::packaging_tool())).unwrap();
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
    let patched = with_block_sizes(&map_xml, "assets\\big.bin", &[u64::MAX, 1, 1]);
    let map = palisade_fileid::package::blockmap::parse(patched.as_bytes()).unwrap();
    assert!(palisade_fileid::package::blockmap::verify(&map, &archive).is_err());

    // Extra data: the builder writes it with every length and offset
    // consistent, so only the extra-field rules can refuse it.
    let unknown = [0xfe, 0xca, 0, 0];
    let zip64_block = {
        let mut v = vec![1, 0, 8, 0];
        v.extend_from_slice(&0_u64.to_le_bytes());
        v
    };
    let check = |style: ZipStyle, ok: bool, what: &str| {
        let data = AppxBuilder::package().build_with(&style);
        assert_eq!(Archive::parse(&data).is_ok(), ok, "{what}");
    };
    check(zip64(), true, "plain ZIP64");
    // A block after the central ZIP64 block.
    check(
        ZipStyle {
            central_extra_tail: unknown.to_vec(),
            ..zip64()
        },
        false,
        "trailing central block",
    );
    // A central block that nothing calls for.
    check(
        ZipStyle {
            central_extra_tail: unknown.to_vec(),
            ..ZipStyle::default()
        },
        false,
        "unneeded central block",
    );
    check(
        ZipStyle {
            central_extra_tail: zip64_block.clone(),
            ..ZipStyle::default()
        },
        false,
        "unneeded central ZIP64 block",
    );
    // Local extra data: none is allowed with a data descriptor, and
    // without one only a needed ZIP64 block (never needed here).
    check(
        ZipStyle {
            local_extra: zip64_block.clone(),
            ..descriptors()
        },
        false,
        "local ZIP64 block with a descriptor",
    );
    check(
        ZipStyle {
            local_extra: zip64_block,
            ..ZipStyle::default()
        },
        false,
        "unneeded local ZIP64 block",
    );
    check(
        ZipStyle {
            local_extra: unknown.to_vec(),
            ..ZipStyle::default()
        },
        false,
        "local unknown block",
    );
}

#[test]
fn the_block_map_total_is_capped() {
    // A block map whose files add up to more than a package may hold is
    // refused before anything is inflated. The archive is the real test
    // package; only the map's sizes (and block counts) are changed, so the
    // size checks fail later than the total does.
    let data = AppxBuilder::package().build();
    let archive = Archive::parse(&data).unwrap();
    let huge = palisade_fileid::package::MAX_PACKAGE_SIZE / 2 + 1;
    let blocks = huge.div_ceil(65536);
    let mut xml = format!(
        "<BlockMap xmlns=\"{BLOCK_MAP}\" HashMethod=\"http://www.w3.org/2001/04/xmlenc#sha256\">",
    );
    let hash = "A".repeat(43) + "=";
    for name in ["AppxManifest.xml", "app\\tool.exe"] {
        xml.push_str(&format!(
            "<File Name=\"{name}\" Size=\"{huge}\" LfhSize=\"30\">"
        ));
        for _ in 0..blocks {
            xml.push_str(&format!("<Block Hash=\"{hash}\"/>"));
        }
        xml.push_str("</File>");
    }
    xml.push_str("</BlockMap>");
    let start = std::time::Instant::now();
    let map = palisade_fileid::package::blockmap::parse(xml.as_bytes()).unwrap();
    assert!(matches!(
        palisade_fileid::package::blockmap::verify(&map, &archive),
        Err(BlockMapError::Size(s)) if s == "(total)"
    ));
    assert!(start.elapsed() < std::time::Duration::from_secs(10));
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

/// `map_xml` with the `Size` of each block of `file` (as the map writes its
/// name) replaced by `sizes`, in order; blocks without one gain one.
fn with_block_sizes(map_xml: &str, file: &str, sizes: &[u64]) -> String {
    let start = map_xml.find(&format!("Name=\"{file}\"")).unwrap();
    let end = start + map_xml[start..].find("</File>").unwrap();
    let mut body = String::new();
    let mut n = 0;
    for (i, part) in map_xml[start..end].split("<Block ").enumerate() {
        if i == 0 {
            body.push_str(part);
            continue;
        }
        let hash_at = part.find("Hash=").unwrap();
        let hash_end = hash_at + part[hash_at + 6..].find('"').unwrap() + 7;
        let close = part.find("/>").unwrap();
        body.push_str(&format!(
            "<Block {} Size=\"{}\"{}",
            &part[hash_at..hash_end],
            sizes[n],
            &part[close..]
        ));
        n += 1;
    }
    assert_eq!(n, sizes.len(), "{file}");
    format!("{}{body}{}", &map_xml[..start], &map_xml[end..])
}

fn block_map_of(archive: &Archive<'_>) -> palisade_fileid::package::blockmap::BlockMap {
    palisade_fileid::package::blockmap::parse(
        &archive
            .read(archive.member("AppxBlockMap.xml").unwrap())
            .unwrap(),
    )
    .unwrap()
}

// The tests below pin the archive shapes the OS packaging tool writes, each
// taken from its open-source implementation (the msix-packaging SDK,
// `src/msix/pack` and `src/msix/unpack`), and check that the same shape
// with a byte changed is still refused.

#[test]
fn the_packaging_tool_zip64_layout_reads() {
    // `ZipObjectWriter::Close` writes ZIP64 end records and a classic end
    // record of markers only ("Because we only use zip64"), whose disk
    // numbers the `EndCentralDirectoryRecord` constructor leaves at 0 in
    // that SDK but the OS tool writes as `0xffff`: osslsigncode's
    // `appx.c` notes "packaging tool writes FFFFs here", and the SDK's own
    // reader (`EndCentralDirectoryRecord::Read`) accepts 0 or `0xffff` for
    // both, as long as they are equal. `ZipObjectWriter::EndFile` writes a
    // data descriptor with 8-byte sizes (`DataDescriptor`: "8 bytes
    // (zip64)") whether or not the entry has a ZIP64 extra field, and
    // central entries only carry that field when a value does not fit.
    let tool = ZipStyle::packaging_tool();
    let data = AppxBuilder::package().build_with(&tool);
    let a = Archive::parse(&data).unwrap();
    assert!(a.zip64);
    assert!(a.members.iter().all(|m| !m.has_zip64_extra));
    let id = parse_package(&data).unwrap();
    assert_eq!(id.name, "Palisade.TestApp");
    palisade_fileid::package::blockmap::verify(&block_map_of(&a), &a).unwrap();

    // Disk numbers: both the marker or both 0; never one of each, never
    // any other value, and never the marker without ZIP64 records.
    let eocd = data.len() - 22;
    let disks = |d: u16, cd: u16| {
        let mut x = data.clone();
        x[eocd + 4..eocd + 6].copy_from_slice(&d.to_le_bytes());
        x[eocd + 6..eocd + 8].copy_from_slice(&cd.to_le_bytes());
        Archive::parse(&x).map(|_| ())
    };
    assert!(disks(0, 0).is_ok());
    assert!(disks(0xffff, 0xffff).is_ok());
    for (d, cd) in [(0xffff, 0), (0, 0xffff), (1, 1), (0xfffe, 0xfffe)] {
        assert_eq!(disks(d, cd), Err(ZipError::MultiDisk), "{d:#x} {cd:#x}");
    }
    let classic = AppxBuilder::package().build_with(&ZipStyle {
        disk_marker: true,
        ..descriptors()
    });
    assert_eq!(Archive::parse(&classic).unwrap_err(), ZipError::MultiDisk);
    // The ZIP64 record's own disk numbers must still be 0.
    let rec = data.len() - 22 - 20 - 56;
    let mut x = data.clone();
    x[rec + 16] = 1;
    x[rec + 20] = 1;
    assert_eq!(Archive::parse(&x).unwrap_err(), ZipError::MultiDisk);

    // Descriptor width follows the entry's ZIP version: 4.5, 8-byte sizes
    // (the packaging tool); 2.0, 4-byte sizes, in a ZIP64 archive too (the
    // OS signing tool rewrites archives so: ZIP64 end records, version 2.0,
    // 16-byte descriptors). Both read.
    for (style, what) in [
        (
            ZipStyle {
                narrow_descriptors: true,
                ..ZipStyle::packaging_tool()
            },
            "version 2.0, 4-byte sizes, ZIP64 archive (the signing tool)",
        ),
        (
            ZipStyle {
                wide_descriptors: true,
                ..descriptors()
            },
            "version 4.5, 8-byte sizes, classic archive",
        ),
    ] {
        let x = AppxBuilder::package().build_with(&style);
        let a = Archive::parse(&x).unwrap_or_else(|e| panic!("{what}: {e}"));
        palisade_fileid::package::blockmap::verify(&block_map_of(&a), &a).unwrap();
    }
    // The width the version does not call for is refused, in every layout:
    // the sizes read at the wrong width do not match, or the next record is
    // not where it should be.
    for (style, what) in [
        (ZipStyle::packaging_tool(), "version 2.0 with 8-byte sizes"),
        (
            ZipStyle {
                narrow_descriptors: true,
                ..ZipStyle::packaging_tool()
            },
            "version 4.5 with 4-byte sizes, ZIP64",
        ),
        (descriptors(), "version 4.5 with 4-byte sizes"),
        (
            ZipStyle {
                wide_descriptors: true,
                ..descriptors()
            },
            "version 2.0 with 8-byte sizes, classic",
        ),
    ] {
        let x = AppxBuilder::package().build_with(&ZipStyle {
            version_mismatch: true,
            ..style
        });
        assert!(
            matches!(Archive::parse(&x), Err(ZipError::LocalHeader(_))),
            "{what}"
        );
    }
    // A ZIP64 extra field with version 2.0 (and so 4-byte sizes) is
    // refused: the extra field needs 4.5.
    let x = AppxBuilder::package().build_with(&ZipStyle {
        narrow_descriptors: true,
        ..zip64()
    });
    assert!(matches!(Archive::parse(&x), Err(ZipError::LocalHeader(_))));
    // The OS signing tool's rewrite of ZIP64 extras (seen on CI): 4-byte
    // sizes with the uncompressed size 0. The values must match the central
    // entry, so it is refused.
    let mut x = AppxBuilder::package().build_with(&ZipStyle {
        narrow_descriptors: true,
        ..ZipStyle::packaging_tool()
    });
    let a = Archive::parse(&x).unwrap();
    let m = a.member("AppxManifest.xml").unwrap();
    let d = (m.data_offset + m.compressed_size) as usize;
    x[d + 12..d + 16].copy_from_slice(&[0; 4]);
    assert!(matches!(Archive::parse(&x), Err(ZipError::LocalHeader(_))));
    // A descriptor size changed by one is refused.
    let a = Archive::parse(&data).unwrap();
    let m = a.member("app/tool.exe").unwrap();
    let mut x = data.clone();
    let d = (m.data_offset + m.compressed_size) as usize;
    x[d + 8] ^= 1;
    assert!(Archive::parse(&x).is_err());
}

#[test]
fn the_packaging_tool_deflate_and_block_sizes_verify() {
    // `DeflateStream::Write` compresses every 64 KiB block with
    // `Z_FULL_FLUSH` and ends the stream with `Z_FINISH`, an empty final
    // block (`03 00`); `BlockMapWriter::AddBlock` records each block's
    // flushed size. So the block sizes sum to the compressed size less
    // two, which the OS reader accepts, as it does sizes that sum to the
    // compressed size exactly (`AppxPackageObject::VerifyFile`: "case 1"
    // and "case 2", nothing else).
    let data = AppxBuilder::package().build();
    let a = Archive::parse(&data).unwrap();
    let big = a.member("assets/big.bin").unwrap();
    let raw = a.raw_data(big);
    assert_eq!(&raw[raw.len() - 6..], &[0, 0, 0xff, 0xff, 3, 0]);
    let map_xml =
        String::from_utf8(a.read(a.member("AppxBlockMap.xml").unwrap()).unwrap()).unwrap();
    let (_, sizes) = deflate_blocks(&a.read(big).unwrap());
    let sizes: Vec<u64> = sizes.iter().map(|&s| s as u64).collect();
    assert_eq!(sizes.iter().sum::<u64>() + 2, big.compressed_size);
    let check = |sizes: &[u64]| {
        let xml = with_block_sizes(&map_xml, "assets\\big.bin", sizes);
        let map = palisade_fileid::package::blockmap::parse(xml.as_bytes()).unwrap();
        palisade_fileid::package::blockmap::verify(&map, &a)
    };
    check(&sizes).unwrap();
    // The final block counted in the last block: also the OS's case 1.
    let mut exact = sizes.clone();
    *exact.last_mut().unwrap() += 2;
    check(&exact).unwrap();
    // Anything else is refused: one or three bytes off, either way.
    for (delta, up) in [(1, true), (1, false), (3, true), (3, false)] {
        let mut off = sizes.clone();
        off[0] = if up { off[0] + delta } else { off[0] - delta };
        assert!(
            matches!(check(&off), Err(BlockMapError::Size(_))),
            "{delta} {up}"
        );
    }
    // A deflated file whose blocks give no sizes, or only some, is
    // refused: the OS reader reads a missing size as 64 KiB, which never
    // fits a compressed file this size.
    let mut unsized_map = String::new();
    let at = map_xml.find("Name=\"assets\\big.bin\"").unwrap();
    let end = at + map_xml[at..].find("</File>").unwrap();
    unsized_map.push_str(&map_xml[..at]);
    let file = &map_xml[at..end];
    let first_block = file.find("<Block ").unwrap();
    unsized_map.push_str(&file[..first_block]);
    for part in file[first_block..].split("<Block ").skip(1) {
        let hash_at = part.find("Hash=").unwrap();
        let hash_end = hash_at + part[hash_at + 6..].find('"').unwrap() + 7;
        unsized_map.push_str(&format!("<Block {}/>", &part[hash_at..hash_end]));
    }
    unsized_map.push_str(&map_xml[end..]);
    let map = palisade_fileid::package::blockmap::parse(unsized_map.as_bytes()).unwrap();
    assert!(matches!(
        palisade_fileid::package::blockmap::verify(&map, &a),
        Err(BlockMapError::Size(_))
    ));

    // A member that ends on its last full flush, with no final block, is
    // not a complete DEFLATE stream and is refused. (The SDK's own writer
    // always ends the stream; its only such members are in its negative
    // test packages.)
    let cut = AppxBuilder::package().build_with(&ZipStyle {
        no_final_block: true,
        ..ZipStyle::default()
    });
    let a = Archive::parse(&cut).unwrap();
    assert!(matches!(
        a.read(a.member("assets/big.bin").unwrap()),
        Err(ZipError::Corrupt(_))
    ));
}

#[test]
fn bundle_payloads_are_checked_against_the_bundle_manifest() {
    // `AppxBundleWriter` adds the payload packages stored and without
    // block map entries, so a bundle's block map lists the bundle manifest
    // only, and its reader requires exactly that (`AppxPackageObject`:
    // "Block map contains invalid files", "Packages cannot be compressed",
    // and the bundle manifest's `Size` must be the member's). The bundle
    // manifest gives each payload's `Offset` (where its data starts) and
    // `Size` (`BundleManifestSchema`: both required).
    use palisade_fileid::package::blockmap::{Payload, verify, verify_bundle};
    let b = AppxBuilder::bundle();
    let data = b.build();
    let a = Archive::parse(&data).unwrap();
    let map = block_map_of(&a);
    assert_eq!(map.files.len(), 1);
    let id = parse_package(&data).unwrap();
    assert!(id.is_bundle);
    let payloads: Vec<Payload<'_>> = id
        .members
        .iter()
        .map(|m| Payload {
            file_name: &m.file_name,
            offset: m.offset,
            size: m.size,
        })
        .collect();
    verify_bundle(&map, &a, &payloads).unwrap();
    // As a package's block map it does not cover the payloads.
    assert!(matches!(verify(&map, &a), Err(BlockMapError::Unlisted(_))));
    // The payloads are real packages that parse on their own.
    for m in &id.members {
        let inner = a.read(a.member(&m.file_name).unwrap()).unwrap();
        assert_eq!(parse_package(&inner).unwrap().name, "Palisade.TestBundle");
    }

    let with = |f: &dyn Fn(&mut Payload<'_>)| {
        let mut p = payloads.clone();
        f(&mut p[0]);
        verify_bundle(&map, &a, &p)
    };
    // Wrong offset or size, or none given.
    for bad in [
        with(&|p| p.offset = p.offset.map(|o| o + 1)),
        with(&|p| p.offset = None),
        with(&|p| p.size = p.size.map(|s| s - 1)),
        with(&|p| p.size = None),
    ] {
        assert!(matches!(bad, Err(BlockMapError::Size(_))), "{bad:?}");
    }
    // A payload listed twice, or listed but not in the archive (a flat
    // bundle, whose packages are separate files, is not verified here).
    let mut twice = payloads.clone();
    twice.push(payloads[0]);
    assert!(matches!(
        verify_bundle(&map, &a, &twice),
        Err(BlockMapError::Duplicate(_))
    ));
    let mut extra = payloads.clone();
    extra.push(Payload {
        file_name: "missing.msix",
        offset: Some(1),
        size: Some(1),
    });
    assert!(matches!(
        verify_bundle(&map, &a, &extra),
        Err(BlockMapError::Unlisted(_))
    ));
    // A member the bundle manifest does not list.
    assert!(matches!(
        verify_bundle(&map, &a, &payloads[..1]),
        Err(BlockMapError::Unlisted(_))
    ));
    // A compressed payload, even at the right place and size.
    let mut deflated = b.clone();
    deflated.files[0].deflate = true;
    let d = deflated.build();
    let da = Archive::parse(&d).unwrap();
    let dp: Vec<Payload<'_>> = da
        .members
        .iter()
        .take(2)
        .map(|m| Payload {
            file_name: &m.name,
            offset: Some(m.data_offset),
            size: Some(m.size),
        })
        .collect();
    assert!(matches!(
        verify_bundle(&block_map_of(&da), &da, &dp),
        Err(BlockMapError::Size(_))
    ));
    // A block map that lists a payload too, or a file besides the bundle
    // manifest.
    let mut listed = b.clone();
    listed.blockmap_extra = format!(
        "<File Name=\"app_x64.msix\" Size=\"{}\" LfhSize=\"42\"><Block Hash=\"{}\"/></File>",
        payloads[0].size.unwrap(),
        "A".repeat(43) + "="
    );
    let l = listed.build();
    let la = Archive::parse(&l).unwrap();
    assert!(verify_bundle(&block_map_of(&la), &la, &payloads).is_err());

    // Through parse_package: a signed bundle with one payload byte changed
    // fails the signature, and with the bundle manifest's offset changed
    // (block map and digest left alone) fails too.
    let signed = fixture("bundle-signed.msixbundle");
    assert!(parse_package(&signed).unwrap().signature_valid());
    let sa = Archive::parse(&signed).unwrap();
    let x64 = sa.member("app_x64.msix").unwrap();
    let mut flipped = signed.clone();
    flipped[(x64.data_offset + 40) as usize] ^= 1;
    assert!(!parse_package(&flipped).unwrap().signature_valid());
}

#[test]
fn a_signed_classic_archive_is_never_valid() {
    // osslsigncode signs a classic (non-ZIP64) archive with a digest of
    // that archive, which this crate's digest reproduces; the OS rejects it
    // (Windows CI: TRUST_E_BAD_DIGEST, HashMismatch), while the OS signing
    // tool, given the same input, writes ZIP64 end records and signs that.
    // So a signed classic archive is refused however its digest matches.
    let classic = fixture("app-classic.msix");
    let a = Archive::parse(&classic).unwrap();
    assert!(!a.zip64);
    let id = parse_package(&classic).unwrap();
    let sig = id.signature.as_ref().unwrap();
    assert_eq!(sig.issue, Some(PackageSignatureIssue::NotZip64));
    assert!(!id.signature_valid());
    assert!(sig.report.signatures.iter().all(|s| !s.status.is_valid()));
    // The digest itself still matches what osslsigncode signed: the
    // refusal is the container, not the hash.
    let blob = p7x(&classic);
    let ours = signed_digest(&a, palisade_fileid::authenticode::DigestAlgorithm::Sha256).unwrap();
    assert!(blob.windows(ours.len()).any(|w| w == ours.as_slice()));
    // The same package, signed by the same tool in ZIP64, verifies.
    assert!(
        parse_package(&fixture("app-signed.msix"))
            .unwrap()
            .signature_valid()
    );
    // The signed ZIP64 package with its ZIP64 end records removed (the
    // central directory and classic end record kept, rewritten to plain
    // values): never valid.
    let z = fixture("app-signed.msix");
    let za = Archive::parse(&z).unwrap();
    let cd = za.central_offset as usize;
    let cd_end = za.central_end as usize;
    let n = za.members.len() as u16;
    let mut stripped = z[..cd_end].to_vec();
    stripped.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    stripped.extend_from_slice(&[0; 4]);
    stripped.extend_from_slice(&n.to_le_bytes());
    stripped.extend_from_slice(&n.to_le_bytes());
    stripped.extend_from_slice(&((cd_end - cd) as u32).to_le_bytes());
    stripped.extend_from_slice(&(cd as u32).to_le_bytes());
    stripped.extend_from_slice(&0_u16.to_le_bytes());
    let id = parse_package(&stripped).unwrap();
    assert_eq!(
        id.signature.as_ref().unwrap().issue,
        Some(PackageSignatureIssue::NotZip64)
    );
}
