//! Windows Installer package identity (#53): container parsing, tables,
//! summary information, patches, transforms, merge modules, embedded
//! content, the content hash, the normalised hash and signatures.
//!
//! Every package is built at test time by `common/msi.rs`. The signed
//! fixtures in `tests/fixtures/installer` are builder output signed by
//! osslsigncode with throwaway test keys (see `generate.sh` there).

#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

#[path = "common/msi.rs"]
mod msi;

use msi::*;
use palisade_fileid::authenticode::{
    SignatureKind, SignatureStatus, SigningState, TrustConfig, evaluate_trust,
};
use palisade_fileid::installer::cfb::CfbError;
use palisade_fileid::installer::{
    CLSID_DATABASE, CustomActionKind, InstallerError, InstallerKind, InstallerWarning,
    MAX_INVENTORY_ROWS, NormalisedHashStrength, parse_installer, transform_validation,
};
use palisade_fileid::pe::version::FileVersionQuad;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/installer");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

const PRODUCT_CODE: &str = "{6E2F4F1A-0C9B-4C1E-9D3F-8A7B6C5D4E3F}";
const UPGRADE_CODE: &str = "{A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D}";

/// The base product every test starts from. `generate.sh` signs exactly
/// this package (`write_unsigned_installers`).
fn product() -> MsiBuilder {
    let mut b = MsiBuilder::product(&[
        ("ProductCode", PRODUCT_CODE),
        ("UpgradeCode", UPGRADE_CODE),
        ("ProductName", "Palisade Test Product"),
        ("ProductVersion", "1.2.3"),
        ("Manufacturer", "Palisade Tests"),
        ("ProductLanguage", "1033"),
        ("ALLUSERS", "1"),
        ("MSIINSTALLPERUSER", "0"),
        ("ARPSYSTEMCOMPONENT", "1"),
    ]);
    b.table(
        "Binary",
        &[("Name", key_col(72)), ("Data", BINARY)],
        vec![
            vec![s("SetupHelper"), Cell::Stream],
            vec![s("Icon"), Cell::Stream],
        ],
    );
    b.stream(
        "Binary.SetupHelper",
        b"MZ synthetic helper, not a real PE".to_vec(),
    );
    b.stream("Binary.Icon", vec![7; 5000]);
    b.table(
        "CustomAction",
        &[
            ("Action", key_col(72)),
            ("Type", I2),
            ("Source", str_col(72, true)),
            ("Target", str_col(255, true)),
        ],
        vec![
            vec![
                s("RunHelperDll"),
                Cell::Int(1 | 0x400 | 0x800),
                s("SetupHelper"),
                s("Entry"),
            ],
            vec![
                s("RunHelperExe"),
                Cell::Int(2),
                s("SetupHelper"),
                s("/quiet"),
            ],
            vec![s("RunScript"), Cell::Int(6), s("SetupHelper"), Cell::Null],
            vec![
                s("RunInstalledExe"),
                Cell::Int(18),
                s("helper.exe"),
                Cell::Null,
            ],
            vec![
                s("RunDirExe"),
                Cell::Int(34),
                s("INSTALLDIR"),
                s("tool.exe"),
            ],
            vec![s("RunPropExe"), Cell::Int(50), s("TOOL"), s("/x")],
            vec![s("SetProp"), Cell::Int(51), s("A"), s("B")],
        ],
    );
    b.table(
        "Media",
        &[
            ("DiskId", KEY_I2),
            ("LastSequence", I4),
            ("DiskPrompt", str_col(64, true)),
            ("Cabinet", str_col(255, true)),
            ("VolumeLabel", str_col(32, true)),
            ("Source", str_col(72, true)),
        ],
        vec![
            vec![
                Cell::Int(1),
                Cell::Int(3),
                Cell::Null,
                s("#data1.cab"),
                Cell::Null,
                Cell::Null,
            ],
            vec![
                Cell::Int(2),
                Cell::Int(4),
                Cell::Null,
                s("external.cab"),
                Cell::Null,
                Cell::Null,
            ],
        ],
    );
    b.stream("data1.cab", b"MSCF synthetic cabinet".to_vec());
    b
}

#[test]
fn reads_product_identity() {
    let id = parse_installer(&product().build()).unwrap();
    assert_eq!(id.kind, InstallerKind::Msi);
    assert_eq!(id.clsid, CLSID_DATABASE);
    assert_eq!(id.codepage, Some(1252));
    let p = &id.properties;
    assert_eq!(p.product_code.as_ref().unwrap().text, PRODUCT_CODE);
    assert!(p.product_code.as_ref().unwrap().well_formed);
    assert_eq!(
        p.upgrade_code.as_ref().unwrap().canonical().unwrap(),
        UPGRADE_CODE
    );
    assert_eq!(p.product_name.as_deref(), Some("Palisade Test Product"));
    assert_eq!(p.product_version_text.as_deref(), Some("1.2.3"));
    assert_eq!(id.product_version(), Some(FileVersionQuad(1, 2, 3, 0)));
    assert_eq!(p.manufacturer.as_deref(), Some("Palisade Tests"));
    assert_eq!(p.product_language.as_deref(), Some("1033"));
    assert_eq!(p.all_users.as_deref(), Some("1"));
    assert_eq!(p.install_per_user.as_deref(), Some("0"));
    assert_eq!(p.arp_system_component.as_deref(), Some("1"));
    assert_eq!(
        id.package_code.as_ref().unwrap().text,
        "{0B7A6E71-5D0A-4C55-9A0E-1E6C2A3B4C5D}"
    );
    let sm = &id.summary;
    assert_eq!(sm.platform(), Some("x64"));
    assert_eq!(sm.languages(), vec![1033]);
    assert_eq!(sm.page_count, Some(500));
    assert_eq!(sm.word_count, Some(2));
    assert_eq!(sm.security, Some(2));
    assert_eq!(sm.title.as_deref(), Some("Installation Database"));
    assert_eq!(sm.app_name.as_deref(), Some("Palisade test builder"));
    assert!(sm.created.is_some() && sm.last_saved.is_some());
    assert!(id.signature.is_none());
    assert!(!id.signature_valid());
    assert_eq!(id.normalised_strength, NormalisedHashStrength::Medium);
    assert!(id.warnings.is_empty(), "{:?}", id.warnings);
}

#[test]
fn three_byte_string_references_and_utf8() {
    let mut b = product();
    b.long_refs = true;
    b.codepage = 65001;
    b.tables[0].rows.push(vec![s("Comments"), s("caf\u{e9}")]);
    let id = parse_installer(&b.build()).unwrap();
    assert_eq!(id.properties.product_code.unwrap().text, PRODUCT_CODE);
    assert_eq!(id.codepage, Some(65001));
    assert!(id.warnings.is_empty(), "{:?}", id.warnings);
}

#[test]
fn inventories_embedded_content() {
    let id = parse_installer(&product().build()).unwrap();
    let e = &id.embedded;
    assert_eq!(e.binaries.len(), 2);
    let helper = e.binaries.iter().find(|b| b.name == "SetupHelper").unwrap();
    assert_eq!(helper.size, Some(34));
    let icon = e.binaries.iter().find(|b| b.name == "Icon").unwrap();
    assert_eq!(icon.size, Some(5000));
    let kinds: Vec<_> = e
        .custom_actions
        .iter()
        .map(|c| (c.action.as_str(), c.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("RunHelperDll", CustomActionKind::Dll),
            ("RunHelperExe", CustomActionKind::Exe),
            ("RunScript", CustomActionKind::VbScript),
            ("RunInstalledExe", CustomActionKind::Exe),
            ("RunDirExe", CustomActionKind::Exe),
            ("RunPropExe", CustomActionKind::Exe),
            ("SetProp", CustomActionKind::Other),
        ]
    );
    assert!(e.custom_actions[0].no_impersonate);
    assert_eq!(e.custom_actions[3].source_bits, 0x10);
    assert_eq!(e.custom_actions[4].source_bits, 0x20);
    assert_eq!(e.custom_actions[5].source_bits, 0x30);
    assert!(!e.custom_actions[6].is_executable_content());
    assert!(e.has_executable_actions());
    assert_eq!(e.cabinets.len(), 1);
    assert_eq!(e.cabinets[0].name, "data1.cab");
    assert_eq!(e.cabinets[0].size, Some(22));
}

#[test]
fn merge_module_patch_and_transform_kinds() {
    let mut m = product();
    m.table(
        "ModuleSignature",
        &[
            ("ModuleID", key_col(72)),
            ("Language", KEY_I2),
            ("Version", str_col(32, false)),
        ],
        vec![vec![s("Palisade.Module.1"), Cell::Int(1033), s("1.0.0")]],
    );
    assert_eq!(
        parse_installer(&m.build()).unwrap().kind,
        InstallerKind::Msm
    );

    let patch_code = "{11111111-2222-3333-4444-555555555555}";
    let obsoleted = "{66666666-7777-8888-9999-AAAAAAAAAAAA}";
    let mut p = MsiBuilder {
        clsid: CLSID_PATCH,
        ..MsiBuilder::default()
    };
    p.table(
        "MsiPatchMetadata",
        &[
            ("Company", 0x3d48),
            ("Property", key_col(72)),
            ("Value", str_col(0, false)),
        ],
        vec![
            vec![Cell::Null, s("Classification"), s("Update")],
            vec![Cell::Null, s("DisplayName"), s("Test patch")],
            vec![Cell::Null, s("ManufacturerName"), s("Palisade Tests")],
            vec![
                Cell::Null,
                s("TargetProductName"),
                s("Palisade Test Product"),
            ],
        ],
    );
    p.summary_prop(
        7,
        Prop::Str(format!(
            "{PRODUCT_CODE};{{BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}}"
        )),
    );
    p.summary_prop(8, Prop::Str(":t1;:#t1".into()));
    p.summary_prop(9, Prop::Str(format!("{patch_code}{obsoleted}")));
    let id = parse_installer(&p.build()).unwrap();
    assert_eq!(id.kind, InstallerKind::Msp);
    assert!(id.package_code.is_none());
    let info = id.patch.as_ref().unwrap();
    assert_eq!(info.patch_code.as_ref().unwrap().text, patch_code);
    assert_eq!(info.obsoletes.len(), 1);
    assert_eq!(info.obsoletes[0].text, obsoleted);
    assert_eq!(id.patch_targets().len(), 2);
    assert_eq!(id.patch_targets()[0].text, PRODUCT_CODE);
    assert_eq!(info.transforms, vec![":t1", ":#t1"]);
    assert_eq!(info.classification.as_deref(), Some("Update"));
    assert_eq!(info.display_name.as_deref(), Some("Test patch"));
    assert_eq!(info.manufacturer_name.as_deref(), Some("Palisade Tests"));
    assert_eq!(
        info.target_product_name.as_deref(),
        Some("Palisade Test Product")
    );

    let mut t = MsiBuilder {
        clsid: CLSID_TRANSFORM,
        ..MsiBuilder::default()
    };
    t.summary_prop(7, Prop::Str("x64;1033".into()));
    t.summary_prop(
        9,
        Prop::Str(format!(
            "{PRODUCT_CODE}1.2.3;{PRODUCT_CODE}1.2.4;{UPGRADE_CODE}"
        )),
    );
    let flags = transform_validation::PRODUCT
        | transform_validation::LANGUAGE
        | transform_validation::UPGRADE_CODE;
    // Validation flags in the upper word, suppressed errors in the lower.
    t.summary_prop(16, Prop::I4(((flags << 16) | 0x20).cast_signed()));
    let id = parse_installer(&t.build()).unwrap();
    assert_eq!(id.kind, InstallerKind::Mst);
    let info = id.transform.as_ref().unwrap();
    assert_eq!(
        info.target_product_code.as_ref().unwrap().text,
        PRODUCT_CODE
    );
    assert_eq!(info.target_version.as_deref(), Some("1.2.3"));
    assert_eq!(info.upgraded_version.as_deref(), Some("1.2.4"));
    assert_eq!(info.upgrade_code.as_ref().unwrap().text, UPGRADE_CODE);
    assert_eq!(info.validation, flags);
    assert_eq!(info.error_conditions, 0x20);
}

#[test]
fn rejects_non_installers() {
    let mut b = product();
    b.clsid = [0x11; 16];
    assert_eq!(
        parse_installer(&b.build()).unwrap_err(),
        InstallerError::NotInstaller
    );
    assert!(matches!(
        parse_installer(b"not a compound file at all, just text").unwrap_err(),
        InstallerError::Container(CfbError::NotCompoundFile)
    ));
}

#[test]
fn normalised_hash_ignores_timestamps_only() {
    let base = product();
    let a = base.build();
    let mut later = base.clone();
    later.summary_prop(12, Prop::Time(0x01dc_1234_5678_9abc));
    later.summary_prop(13, Prop::Time(0x01dc_1234_5678_9abd));
    later.summary_prop(11, Prop::Time(0x01dc_0000_0000_0002));
    later.summary_prop(10, Prop::Time(42));
    // Directory-entry times too.
    later.extra.push(Node::Stream {
        name: "\u{5}DocumentSummaryInformation".encode_utf16().collect(),
        data: b"doc summary, ignored".to_vec(),
        times: [9; 16],
    });
    let b = later.build();
    assert_ne!(a, b);
    let ia = parse_installer(&a).unwrap();
    let ib = parse_installer(&b).unwrap();
    assert_ne!(ia.flat_sha256, ib.flat_sha256);
    assert_eq!(ia.normalised_sha256, ib.normalised_sha256);

    // Anything else changes it: a property value, the package code, a
    // stream's bytes.
    let mut other = base.clone();
    other.tables[0].rows[3] = vec![s("ProductVersion"), s("1.2.4")];
    assert_ne!(
        parse_installer(&other.build()).unwrap().normalised_sha256,
        ia.normalised_sha256
    );
    let mut code = base.clone();
    code.summary_prop(
        9,
        Prop::Str("{0B7A6E71-5D0A-4C55-9A0E-1E6C2A3B4C5E}".into()),
    );
    assert_ne!(
        parse_installer(&code.build()).unwrap().normalised_sha256,
        ia.normalised_sha256
    );
    let mut cab = base.clone();
    cab.streams.last_mut().unwrap().1[0] ^= 1;
    assert_ne!(
        parse_installer(&cab.build()).unwrap().normalised_sha256,
        ia.normalised_sha256
    );
}

#[test]
fn normalised_hash_is_pinned() {
    // The algorithm is a documented Palisade identity: changing it changes
    // every stored rule. This pins it for the base product.
    let id = parse_installer(&product().build()).unwrap();
    assert_eq!(id.normalised_sha256.to_string(), PINNED_NORMALISED);
}

/// Computed independently by `fixtures/installer/normalised.py` from the
/// same builder output (`write_unsigned_installers`).
const PINNED_NORMALISED: &str = include_str!("fixtures/installer/product.normalised.txt");

// ---------------------------------------------------------------------------
// Container hardening.

/// The sector of the first directory sector, and so on, of a builder file.
fn header_u32(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn set_u32(data: &mut [u8], at: usize, v: u32) {
    data[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn rejects_fat_loops_and_shared_sectors() {
    let base = product().build();
    // Point the directory chain's FAT entry back at itself.
    let mut looped = base.clone();
    let dir = header_u32(&base, 0x30);
    let fat_sector = header_u32(&base, 0x4c);
    let fat_at = 512 * (fat_sector as usize + 1) + 4 * dir as usize;
    set_u32(&mut looped, fat_at, dir);
    assert!(matches!(
        parse_installer(&looped).unwrap_err(),
        InstallerError::Container(CfbError::SharedSector(_))
    ));

    // The mini FAT start pointing at the directory sector: two owners.
    let mut shared = base.clone();
    set_u32(&mut shared, 0x3c, dir);
    assert!(matches!(
        parse_installer(&shared).unwrap_err(),
        InstallerError::Container(CfbError::SharedSector(_))
    ));

    // A FAT sector number past the end.
    let mut out = base.clone();
    set_u32(&mut out, 0x4c, 10_000);
    assert!(matches!(
        parse_installer(&out).unwrap_err(),
        InstallerError::Container(CfbError::SectorOutOfRange(_))
    ));

    // Truncation anywhere in the body fails, never a partial parse.
    for cut in [513, 1024, base.len() / 2, base.len() - 1] {
        let r = parse_installer(&base[..cut]);
        assert!(r.is_err(), "cut at {cut}");
    }
}

#[test]
fn rejects_directory_cycles_and_duplicate_names() {
    let base = product().build();
    let dir = header_u32(&base, 0x30) as usize;
    let dir_at = 512 * (dir + 1);
    // Entry 1's right sibling pointing at entry 1.
    let mut cyc = base.clone();
    set_u32(&mut cyc, dir_at + 128 + 0x48, 1);
    assert!(matches!(
        parse_installer(&cyc).unwrap_err(),
        InstallerError::Container(CfbError::DirectoryCycle(1))
    ));
    // The root's child pointing at the root.
    let mut root = base.clone();
    set_u32(&mut root, dir_at + 0x4c, 0);
    assert!(matches!(
        parse_installer(&root).unwrap_err(),
        InstallerError::Container(CfbError::DirectoryCycle(0))
    ));

    // Two streams whose names differ only in case.
    let mut dup = product();
    dup.extra.push(Node::stream("Extra", vec![1]));
    dup.extra.push(Node::stream("EXTRA", vec![2]));
    assert_eq!(
        parse_installer(&dup.build()).unwrap_err(),
        InstallerError::Container(CfbError::DuplicateName)
    );
}

#[test]
fn bad_tables_are_warnings_not_identity() {
    // A Property table stream that is not a whole number of rows.
    let mut b = product();
    let mut cfb = b.cfb();
    let name = encode_name("Property", true);
    for n in &mut cfb.children {
        if let Node::Stream { name: nm, data, .. } = n {
            if *nm == name {
                data.push(0);
            }
        }
    }
    let id = parse_installer(&cfb.build()).unwrap();
    assert!(id.properties.product_code.is_none());
    assert!(
        id.warnings
            .iter()
            .any(|w| matches!(w, InstallerWarning::Table(_)))
    );

    // A string pool that does not match its data: no table can be read.
    b.extra.clear();
    let mut cfb = b.cfb();
    let pool = encode_name("_StringData", true);
    for n in &mut cfb.children {
        if let Node::Stream { name: nm, data, .. } = n {
            if *nm == pool {
                data.push(b'x');
            }
        }
    }
    let id = parse_installer(&cfb.build()).unwrap();
    assert!(id.properties.product_code.is_none());
    assert!(id.embedded.custom_actions.is_empty());

    // A malformed summary is reported, and covered by the normalised hash.
    let mut bad = product();
    bad.summary = None;
    bad.extra
        .push(Node::stream("\u{5}SummaryInformation", b"junk".to_vec()));
    let id = parse_installer(&bad.build()).unwrap();
    assert!(
        id.warnings
            .iter()
            .any(|w| matches!(w, InstallerWarning::Summary(_)))
    );
    assert!(id.package_code.is_none());
}

// ---------------------------------------------------------------------------
// Signatures.

const SIGNED: &[&str] = &["product-sha256.msi", "product-sha1.msi", "product-dse.msi"];

#[test]
fn signed_fixtures_verify() {
    for name in SIGNED {
        let data = fixture(name);
        let id = parse_installer(&data).unwrap();
        let report = id.signature.as_ref().unwrap();
        assert_eq!(report.signatures.len(), 1, "{name}");
        let sig = &report.signatures[0];
        assert_eq!(sig.kind, SignatureKind::Msi, "{name}");
        assert_eq!(sig.status, SignatureStatus::Valid, "{name}");
        assert_eq!(sig.digest_match, Some(true), "{name}");
        assert!(id.signature_valid(), "{name}");
        assert_eq!(report.signing_state, SigningState::Valid);
        // The fixture is the builder's product with only the signature
        // streams added, so the normalised hash is unchanged.
        assert_eq!(
            id.normalised_sha256.to_string(),
            PINNED_NORMALISED,
            "{name}"
        );
        assert_eq!(
            id.properties.product_code.as_ref().unwrap().text,
            PRODUCT_CODE
        );
    }
}

#[test]
fn signer_is_trusted_only_under_its_root() {
    let id = parse_installer(&fixture("product-sha256.msi")).unwrap();
    let report = id.signature.unwrap();
    let untrusted = evaluate_trust(&report, &TrustConfig::new(), None);
    assert!(untrusted.primary.is_none());
    let root = fixture("ca.der");
    let mut config = TrustConfig::new();
    config.add_anchor("installer test root", &root).unwrap();
    let trusted = evaluate_trust(&report, &config, None);
    assert!(trusted.primary.is_some());
}

/// Flips one bit of the first occurrence of `needle` in a signed fixture.
fn tamper(data: &[u8], needle: &[u8]) -> Vec<u8> {
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut out = data.to_vec();
    out[at] ^= 0x20;
    out
}

#[test]
fn tampered_content_is_never_valid() {
    for name in SIGNED {
        let data = fixture(name);
        // A property value, a binary stream, and the cabinet.
        for needle in [
            &b"Palisade Test Product"[..],
            b"synthetic helper",
            b"synthetic cabinet",
        ] {
            let bad = tamper(&data, needle);
            let id = parse_installer(&bad).unwrap();
            let sig = &id.signature.as_ref().unwrap().signatures[0];
            assert_eq!(sig.status, SignatureStatus::DigestMismatch, "{name}");
            assert!(!id.signature_valid());
        }
    }
}

#[test]
fn tampered_metadata_fails_the_ex_check() {
    // `product-dse.msi` carries MsiDigitalSignatureEx: changing a
    // directory entry's times (which the content hash ignores) must fail.
    let data = fixture("product-dse.msi");
    let cfb_dir = header_u32(&data, 0x30) as usize;
    let mut bad = data.clone();
    // Entry 1's creation time.
    bad[512 * (cfb_dir + 1) + 128 + 0x64] ^= 1;
    let id = parse_installer(&bad).unwrap();
    let sig = &id.signature.as_ref().unwrap().signatures[0];
    assert_eq!(sig.status, SignatureStatus::DigestMismatch);
    assert!(!id.signature_valid());

    // The same change to a package without the Ex stream does not touch
    // its signature.
    let plain = fixture("product-sha256.msi");
    let dir = header_u32(&plain, 0x30) as usize;
    let mut moved = plain.clone();
    moved[512 * (dir + 1) + 128 + 0x64] ^= 1;
    assert!(parse_installer(&moved).unwrap().signature_valid());
}

#[test]
fn a_pe_signature_is_not_an_installer_signature() {
    // An Authenticode PE signature (SPC_PE_IMAGE_DATA) in the signature
    // stream is malformed for an installer.
    let pe_sig = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/authenticode/rsa2048-sha256.p7"
    ))
    .unwrap();
    let mut b = product();
    b.extra.push(Node::stream("\u{5}DigitalSignature", pe_sig));
    let id = parse_installer(&b.build()).unwrap();
    let sig = &id.signature.as_ref().unwrap().signatures[0];
    assert!(
        matches!(sig.status, SignatureStatus::Malformed(_)),
        "{:?}",
        sig.status
    );
    assert!(!id.signature_valid());

    // Junk, too.
    let mut j = product();
    j.extra.push(Node::stream(
        "\u{5}DigitalSignature",
        vec![0x30, 0x03, 1, 2, 3],
    ));
    assert!(!parse_installer(&j.build()).unwrap().signature_valid());

    // A storage of that name is ignored with a warning, never "signed".
    let mut st = product();
    st.extra.push(Node::Storage {
        name: "\u{5}DigitalSignature".encode_utf16().collect(),
        clsid: [0; 16],
        times: [0; 16],
        children: vec![],
    });
    let id = parse_installer(&st.build()).unwrap();
    assert!(id.signature.is_none());
    assert!(id.warnings.contains(&InstallerWarning::SignatureNotStream));

    // An Ex stream with no signature is reported.
    let mut ex = product();
    ex.extra
        .push(Node::stream("\u{5}MsiDigitalSignatureEx", vec![0; 32]));
    let id = parse_installer(&ex.build()).unwrap();
    assert!(id.signature.is_none());
    assert!(id.warnings.contains(&InstallerWarning::OrphanSignatureEx));
}

#[test]
fn signature_moved_onto_another_package_fails() {
    // The signature of the base product, copied onto a different product.
    let data = fixture("product-sha256.msi");
    let cf = palisade_fileid::installer::cfb::CompoundFile::parse(&data).unwrap();
    let sig_entry = cf
        .root
        .child(&"\u{5}DigitalSignature".encode_utf16().collect::<Vec<_>>())
        .unwrap();
    let der = cf.stream(sig_entry);
    let mut other = product();
    other.tables[0].rows[2] = vec![s("ProductName"), s("Another Product")];
    other.extra.push(Node::stream("\u{5}DigitalSignature", der));
    let id = parse_installer(&other.build()).unwrap();
    assert_eq!(
        id.signature.as_ref().unwrap().signatures[0].status,
        SignatureStatus::DigestMismatch
    );
}

// ---------------------------------------------------------------------------
// Fixture writers (ignored).

/// Writes the unsigned packages `generate.sh` signs, to
/// `PALISADE_INSTALLER_OUT`.
#[test]
#[ignore = "writes files; run by tests/fixtures/installer/generate.sh"]
fn write_unsigned_installers() {
    let dir = std::env::var_os("PALISADE_INSTALLER_OUT").expect("set PALISADE_INSTALLER_OUT");
    let dir = std::path::Path::new(&dir);
    std::fs::write(dir.join("product.msi"), product().build()).unwrap();
}

/// Writes fuzz seeds for `fuzz_msi_tables` to `PALISADE_FUZZ_SEED_DIR`.
#[test]
#[ignore = "writes files; run by cargo xtask fuzz"]
fn write_installer_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("seed-product"), product().build()).unwrap();
    let mut long = product();
    long.long_refs = true;
    std::fs::write(dir.join("seed-long-refs"), long.build()).unwrap();
    let mut patch = MsiBuilder {
        clsid: CLSID_PATCH,
        ..MsiBuilder::default()
    };
    patch.summary_prop(
        9,
        Prop::Str("{11111111-2222-3333-4444-555555555555}".into()),
    );
    std::fs::write(dir.join("seed-patch"), patch.build()).unwrap();
    for name in SIGNED {
        std::fs::write(dir.join(format!("seed-{name}")), fixture(name)).unwrap();
    }
}

#[test]
fn non_ascii_patch_and_transform_codes_do_not_panic() {
    // Revision numbers are attacker-controlled text: a multi-byte
    // character at the 38-byte GUID boundary must not split a character.
    for clsid in [CLSID_PATCH, CLSID_TRANSFORM] {
        let mut b = MsiBuilder {
            clsid,
            codepage: 65001,
            ..MsiBuilder::default()
        };
        let text = format!("{}\u{e9}{}", "x".repeat(37), "y".repeat(40));
        b.summary_prop(1, Prop::I2(-535)); // 65001 as a signed 16-bit value
        b.summary_prop(9, Prop::Str(text));
        let id = parse_installer(&b.build()).unwrap();
        if clsid == CLSID_PATCH {
            assert!(!id.patch.unwrap().patch_code.unwrap().well_formed);
        } else {
            assert!(
                !id.transform
                    .unwrap()
                    .target_product_code
                    .unwrap()
                    .well_formed
            );
        }
    }
}

#[test]
fn committed_unsigned_product_is_the_builder_output() {
    // `installer_os.rs` signs this file with the OS; it must be exactly
    // what the builder makes, which the signed fixtures also sign.
    assert_eq!(fixture("product.msi"), product().build());
}

// ---------------------------------------------------------------------------
// Round 1 review: differentials and limits.

#[test]
fn special_stream_names_compare_case_insensitively() {
    // A valid DSE-signed package whose Ex stream is renamed in case only:
    // the OS still treats it as the metadata hash, so it must still be
    // checked, and tampering with metadata must still fail.
    let data = fixture("product-dse.msi");
    let cf = palisade_fileid::installer::cfb::CompoundFile::parse(&data).unwrap();
    let ex = cf
        .root
        .children
        .iter()
        .find(|c| c.is_named("\u{5}MsiDigitalSignatureEx"))
        .unwrap();
    let dir = header_u32(&data, 0x30) as usize;
    let entry_at = 512 * (dir + 1) + 128 * ex.id as usize;
    let mut renamed = data.clone();
    // The last character, `x`, becomes `X`.
    let last = entry_at + 2 * (ex.name.len() - 1);
    assert_eq!(renamed[last], b'x');
    renamed[last] = b'X';
    assert!(parse_installer(&renamed).unwrap().signature_valid());
    renamed[entry_at - 128 * ex.id as usize + 128 + 0x64] ^= 1;
    assert!(!parse_installer(&renamed).unwrap().signature_valid());

    // A case-renamed signature stream is still the signature.
    let mut upper = fixture("product-sha256.msi");
    let dir2 = header_u32(&upper, 0x30) as usize;
    let cf2 = palisade_fileid::installer::cfb::CompoundFile::parse(&upper).unwrap();
    let sig2 = cf2
        .root
        .children
        .iter()
        .find(|c| c.is_named("\u{5}DigitalSignature"))
        .unwrap();
    let at2 = 512 * (dir2 + 1) + 128 * sig2.id as usize + 2;
    assert_eq!(upper[at2], b'D');
    upper[at2 + 2] = b'I';
    let id = parse_installer(&upper).unwrap();
    assert!(id.signature.is_some());
    assert!(id.signature_valid());
}

#[test]
fn unencoded_decoy_tables_are_ignored() {
    // A stream named with the table prefix but not compressed decodes to
    // the same text as the real `Property` table; the installer never
    // opens it, so it must not shadow the real one.
    let mut b = product();
    let mut decoy = Vec::new();
    // One row of (Property, Value) references to strings 1 and 1: any
    // non-zero bytes would do.
    decoy.extend_from_slice(&[1, 0, 1, 0]);
    b.extra.push(Node::raw_stream(
        "\u{4840}Property".encode_utf16().collect(),
        decoy,
    ));
    let id = parse_installer(&b.build()).unwrap();
    assert_eq!(id.properties.product_code.unwrap().text, PRODUCT_CODE);
    assert_eq!(
        id.properties.product_name.as_deref(),
        Some("Palisade Test Product")
    );
}

#[test]
fn duplicate_pool_strings_do_not_hide_tables() {
    // `CustomAction` appears in the pool twice; `_Tables` and `_Columns`
    // use the second copy. The schema must still be found by text.
    let mut b = product();
    b.prefix_strings = vec!["CustomAction".into()];
    let id = parse_installer(&b.build()).unwrap();
    assert_eq!(id.embedded.custom_actions.len(), 7, "{:?}", id.warnings);
}

#[test]
fn long_strings_round_trip_through_the_builder() {
    let mut b = product();
    b.long_refcount = 9;
    let big = "x".repeat(70_000);
    b.tables[0].rows.push(vec![s("Comments"), s(&big)]);
    // A property after the long string must still read correctly.
    b.tables[0]
        .rows
        .push(vec![s("Manufacturer2"), s("after the long one")]);
    let id = parse_installer(&b.build()).unwrap();
    assert_eq!(id.properties.product_code.unwrap().text, PRODUCT_CODE);
    assert!(id.warnings.is_empty(), "{:?}", id.warnings);
}

#[test]
fn illegal_names_trailing_data_and_oversized_tables() {
    // `/` in a name would let two trees share a normalised hash.
    let mut slash = product();
    slash.extra.push(Node::stream("a/b", vec![1]));
    assert!(matches!(
        parse_installer(&slash.build()).unwrap_err(),
        InstallerError::Container(CfbError::BadDirectoryEntry(_))
    ));

    // Bytes after the last sector are reported and change nothing else.
    let signed = fixture("product-sha256.msi");
    let mut appended = signed.clone();
    appended.extend_from_slice(&[0x41; 600]);
    let a = parse_installer(&appended).unwrap();
    let b = parse_installer(&signed).unwrap();
    assert!(a.warnings.contains(&InstallerWarning::TrailingData(600)));
    assert!(
        !b.warnings
            .iter()
            .any(|w| matches!(w, InstallerWarning::TrailingData(_)))
    );
    assert_eq!(a.normalised_sha256, b.normalised_sha256);

    // A `_Tables` stream with more rows than the limit is refused from its
    // size, before its rows are allocated.
    let mut cfb = product().cfb();
    let name = encode_name("_Tables", true);
    for n in &mut cfb.children {
        if let Node::Stream { name: nm, data, .. } = n {
            if *nm == name {
                data.resize(2 * 5000, 1);
            }
        }
    }
    let id = parse_installer(&cfb.build()).unwrap();
    assert!(id.properties.product_code.is_none());
    assert!(
        id.warnings
            .iter()
            .any(|w| matches!(w, InstallerWarning::Table(_)))
    );
}

#[test]
fn inventory_is_capped() {
    let mut b = product();
    let rows: Vec<_> = (0..MAX_INVENTORY_ROWS + 1)
        .map(|i| vec![s(&format!("B{i}")), Cell::Null])
        .collect();
    b.tables[1].rows = rows;
    let id = parse_installer(&b.build()).unwrap();
    assert_eq!(id.embedded.binaries.len(), MAX_INVENTORY_ROWS);
    assert!(
        id.warnings
            .contains(&InstallerWarning::InventoryTruncated("Binary"))
    );
}

#[test]
fn malformed_summary_still_counts_in_the_normalised_hash() {
    let mut a = product();
    a.summary = None;
    a.extra.push(Node::stream(
        "\u{5}SummaryInformation",
        b"junk one".to_vec(),
    ));
    let mut b = a.clone();
    b.extra = vec![Node::stream(
        "\u{5}SummaryInformation",
        b"junk two".to_vec(),
    )];
    let mut none = product();
    none.summary = None;
    let (ia, ib, inone) = (
        parse_installer(&a.build()).unwrap(),
        parse_installer(&b.build()).unwrap(),
        parse_installer(&none.build()).unwrap(),
    );
    assert_ne!(ia.normalised_sha256, ib.normalised_sha256);
    assert_ne!(ia.normalised_sha256, inone.normalised_sha256);
}

/// The directory entry of root child `name` (exact name), as `(file offset
/// of the entry, start sector, size)`.
fn root_entry(data: &[u8], name: &str) -> (usize, u32, u64) {
    let cf = palisade_fileid::installer::cfb::CompoundFile::parse(data).unwrap();
    let e = cf
        .root
        .children
        .iter()
        .find(|c| c.name.iter().copied().eq(name.encode_utf16()))
        .unwrap();
    let dir = header_u32(data, 0x30) as usize;
    let at = 512 * (dir + 1) + 128 * e.id as usize;
    (at, header_u32(data, at + 0x74), e.size)
}

#[test]
fn chain_tails_must_end_exactly() {
    let base = product().build();
    let fat_sector = header_u32(&base, 0x4c) as usize;
    let fat_at = |s: u32| 512 * (fat_sector + 1) + 4 * s as usize;

    // A big stream (`Binary.Icon`, 5000 bytes, 10 sectors): point its last
    // FAT entry back at its first sector instead of ENDOFCHAIN.
    let icon = encode_name("Binary.Icon", false);
    let icon: String = String::from_utf16(&icon).unwrap();
    let (_, start, size) = root_entry(&base, &icon);
    assert!(size >= 4096);
    let last = start + (size.div_ceil(512) as u32) - 1;
    assert_eq!(header_u32(&base, fat_at(last)), 0xffff_fffe);
    let mut looped = base.clone();
    set_u32(&mut looped, fat_at(last), start);
    assert!(matches!(
        parse_installer(&looped).unwrap_err(),
        InstallerError::Container(CfbError::ChainTooLong)
    ));
    // Marked free instead: also refused.
    let mut free = base.clone();
    set_u32(&mut free, fat_at(last), 0xffff_ffff);
    assert!(parse_installer(&free).is_err());

    // A mini stream chain whose last mini FAT entry points at another
    // stream's mini sector.
    let minifat_sector = header_u32(&base, 0x3c) as usize;
    let (_, mstart, msize) = root_entry(&base, "\u{5}SummaryInformation");
    assert!(msize < 4096);
    let mlast = mstart + (msize.div_ceil(64) as u32) - 1;
    let mf_at = 512 * (minifat_sector + 1) + 4 * mlast as usize;
    assert_eq!(header_u32(&base, mf_at), 0xffff_fffe);
    let mut shared = base.clone();
    set_u32(&mut shared, mf_at, 0);
    assert!(matches!(
        parse_installer(&shared).unwrap_err(),
        InstallerError::Container(CfbError::ChainTooLong)
    ));

    // A DIFAT chain the header says is longer than the FAT needs.
    let mut difat = base.clone();
    set_u32(&mut difat, 0x48, 1);
    assert!(parse_installer(&difat).is_err());
}

#[test]
fn version_4_files_and_extended_difat() {
    // 4096-byte sectors: the same identity and normalised hash.
    let mut v4 = product();
    v4.cfb_version = 4;
    let data = v4.build();
    assert_eq!(u16::from_le_bytes([data[0x1a], data[0x1b]]), 4);
    let id = parse_installer(&data).unwrap();
    assert_eq!(id.properties.product_code.unwrap().text, PRODUCT_CODE);
    assert_eq!(id.normalised_sha256.to_string(), PINNED_NORMALISED);
    assert!(id.warnings.is_empty(), "{:?}", id.warnings);

    // More than 109 FAT sectors (over 109 * 128 sectors of 512 bytes, about
    // 7 MiB), so the FAT is listed by DIFAT sectors too.
    let mut big = product();
    big.stream("Big.cab", vec![0x5a; 7_400_000]);
    let data = big.build();
    assert!(u32::from_le_bytes(data[0x48..0x4c].try_into().unwrap()) >= 1);
    let id = parse_installer(&data).unwrap();
    assert_eq!(id.properties.product_code.unwrap().text, PRODUCT_CODE);
    // A DIFAT chain that does not end is refused.
    let difat = header_u32(&data, 0x44) as usize;
    let mut bad = data.clone();
    set_u32(&mut bad, 512 * (difat + 1) + 508, difat as u32);
    assert!(parse_installer(&bad).is_err());
}

// ---------------------------------------------------------------------------
// Round 2 review.

#[test]
fn empty_names_are_refused() {
    let mut b = product();
    b.extra.push(Node::Storage {
        name: Vec::new(),
        clsid: [1; 16],
        times: [0; 16],
        children: vec![Node::stream("x", vec![1])],
    });
    assert!(matches!(
        parse_installer(&b.build()).unwrap_err(),
        InstallerError::Container(CfbError::BadDirectoryEntry(_))
    ));
}

#[test]
fn storages_with_special_names_are_hashed() {
    // Content under a storage named like a skipped stream changes both the
    // normalised hash and the content hash (what a signature covers).
    let storage = |data: u8| Node::Storage {
        name: "\u{5}DocumentSummaryInformation".encode_utf16().collect(),
        clsid: [0; 16],
        times: [0; 16],
        children: vec![Node::stream("hidden", vec![data; 10])],
    };
    for name in [
        "\u{5}DocumentSummaryInformation",
        "\u{5}SummaryInformation",
        "\u{5}DigitalSignature",
        "\u{5}MsiDigitalSignatureEx",
    ] {
        let with = |data: u8| {
            let mut b = product();
            if name == "\u{5}SummaryInformation" {
                b.summary = None;
            }
            let Node::Storage {
                clsid,
                times,
                children,
                ..
            } = storage(data)
            else {
                unreachable!()
            };
            b.extra.push(Node::Storage {
                name: name.encode_utf16().collect(),
                clsid,
                times,
                children,
            });
            parse_installer(&b.build()).unwrap()
        };
        let (a, b) = (with(1), with(2));
        assert_ne!(a.normalised_sha256, b.normalised_sha256, "{name:?}");
        assert_ne!(a.content_sha256, b.content_sha256, "{name:?}");
    }
}

#[test]
fn oversized_signature_streams_are_never_valid() {
    let data = fixture("product-dse.msi");
    let cf = palisade_fileid::installer::cfb::CompoundFile::parse(&data).unwrap();
    let get = |n: &str| cf.stream(cf.root.children.iter().find(|c| c.is_named(n)).unwrap());
    let sig = get("\u{5}DigitalSignature");
    let ex = get("\u{5}MsiDigitalSignatureEx");
    assert_eq!(ex.len(), 32);
    // An Ex stream longer than any digest.
    let mut b = product();
    b.extra
        .push(Node::stream("\u{5}DigitalSignature", sig.clone()));
    let mut long_ex = ex.clone();
    long_ex.extend_from_slice(&[0; 40]);
    b.extra
        .push(Node::stream("\u{5}MsiDigitalSignatureEx", long_ex));
    let id = parse_installer(&b.build()).unwrap();
    assert!(id.warnings.contains(&InstallerWarning::SignatureTooLarge));
    assert!(!id.signature_valid());
    assert!(id.signature.is_some());

    // A signature stream over the limit.
    let mut big = product();
    let mut huge = sig;
    huge.resize(
        palisade_fileid::installer::MAX_SIGNATURE_SIZE as usize + 1,
        0,
    );
    big.extra.push(Node::stream("\u{5}DigitalSignature", huge));
    let id = parse_installer(&big.build()).unwrap();
    assert!(id.warnings.contains(&InstallerWarning::SignatureTooLarge));
    assert!(!id.signature_valid());

    // An oversized summary is hashed (streamed) rather than parsed.
    let mut s1 = product();
    s1.summary = None;
    s1.extra.push(Node::stream(
        "\u{5}SummaryInformation",
        vec![1; palisade_fileid::installer::MAX_SUMMARY_SIZE as usize + 1],
    ));
    let mut s2 = s1.clone();
    s2.extra = vec![Node::stream(
        "\u{5}SummaryInformation",
        vec![2; palisade_fileid::installer::MAX_SUMMARY_SIZE as usize + 1],
    )];
    let (a, b) = (
        parse_installer(&s1.build()).unwrap(),
        parse_installer(&s2.build()).unwrap(),
    );
    assert!(
        a.warnings
            .iter()
            .any(|w| matches!(w, InstallerWarning::Summary(_)))
    );
    assert_ne!(a.normalised_sha256, b.normalised_sha256);
}
