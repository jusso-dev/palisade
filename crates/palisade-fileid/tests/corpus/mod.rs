//! The test fixture corpus (#25): every fixture built from Rust at test
//! time, on any OS, with nothing taken from outside the repository.
//!
//! `cargo xtask fixtures` writes it to `target/fixtures/` (through the
//! ignored `write_fixture_corpus` test), `cargo xtask golden` checks its
//! hashes against `testdata/golden/fixtures.txt`, and the tests in
//! `tests/fixture_corpus.rs` parse every fixture with this crate and check the
//! properties each one was built to have.
//!
//! - PE32 and PE32+ executables and DLLs, for x64 and ARM64 (and x86),
//!   each with a version resource naming the fixture.
//! - A throwaway test PKI: a root CA, an intermediate and RSA-3072 leaves,
//!   plus an ECDSA P-256 leaf, an expired leaf, a leaf revoked in a CRL, a
//!   leaf with the wrong extended key usage and a self-signed leaf.
//! - Signed PEs: embedded Authenticode, dual signed (a nested signature),
//!   tampered after signing, a truncated certificate table, and one with a
//!   page hash table; and a signed catalog with the unsigned PE it lists.
//! - A malformed corpus: zero length, truncated headers, overlapping
//!   sections, an absurd section count, a recursive resource directory and
//!   a huge `SizeOfImage`.
//! - Benign scripts: `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf` and
//!   `.hta`, each only printing or writing a marker.
//!
//! Every fixture is benign: the code sections hold a `ret` and filler
//! bytes, and the scripts print a marker. No real malware, no antivirus
//! test strings, no third-party binaries.
//!
//! RSA keys and signatures are deterministic, so the corpus is the same on
//! every run and every OS, except the ECDSA-signed fixture, whose
//! signature is random by nature; its golden entry records only its kind.

#![allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::unwrap_used,
    clippy::expect_used
)]

pub mod der;
pub mod pki;
pub mod sign;

use std::collections::BTreeMap;

use crate::common::{self, PeBuilder};
use palisade_fileid::authenticode::page_hash_table;
use palisade_fileid::hash::HashAlgorithm;
use palisade_fileid::pe;
use pki::{Cert, Key, Role, Spec};
use sign::{
    SIGNING_TIME, Signer, authenticode_sha256, signed_catalog, signed_data, win_certificate,
};

/// IMAGE_FILE_MACHINE values.
pub const MACHINE_X86: u16 = 0x014c;
pub const MACHINE_X64: u16 = 0x8664;
pub const MACHINE_ARM64: u16 = 0xaa64;

/// What a fixture is, for the tests that check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A valid unsigned PE.
    Pe,
    /// A PE with an embedded signature that verifies.
    Signed,
    /// A PE whose signature verifies but the image changed after signing.
    Tampered,
    /// A PE whose certificate table is cut short.
    TruncatedSignature,
    /// A file that is not a valid PE at all, or a broken one.
    Malformed,
    /// A benign script.
    Script,
    /// A DER certificate or CRL from the test PKI.
    Pki,
    /// A signed catalog (`.cat`) and the unsigned member file it lists.
    Catalog,
}

/// One fixture: its file name and bytes, and what it should be.
pub struct Fixture {
    pub name: &'static str,
    pub kind: Kind,
    pub bytes: Vec<u8>,
    /// Whether the bytes are the same on every run (golden-hashable).
    pub deterministic: bool,
}

/// Times, relative to the fixed signing time.
const YEAR: i64 = 365 * 86_400;
const NOT_BEFORE: i64 = SIGNING_TIME - YEAR;
const NOT_AFTER: i64 = SIGNING_TIME + 10 * YEAR;

/// The test PKI. Built once per corpus.
pub struct Pki {
    pub root_key: Key,
    pub root: Cert,
    pub inter_key: Key,
    pub inter: Cert,
    pub leaf_key: Key,
    pub leaf: Cert,
    pub leaf2_key: Key,
    pub leaf2: Cert,
    pub expired: Cert,
    pub revoked: Cert,
    pub wrong_eku: Cert,
    pub self_signed: Cert,
    pub crl: Vec<u8>,
}

/// The serial of the leaf the CRL revokes.
pub const REVOKED_SERIAL: u64 = 0x5005;

impl Pki {
    pub fn new() -> Self {
        let root_key = Key::rsa("root", 3072);
        let root = pki::issue(
            &Spec {
                cn: "Palisade Test Root",
                serial: 0x1001,
                not_before: NOT_BEFORE,
                not_after: NOT_AFTER + YEAR,
                role: Role::Ca,
                key: &root_key,
            },
            None,
        );
        let inter_key = Key::rsa("intermediate", 3072);
        let inter = pki::issue(
            &Spec {
                cn: "Palisade Test Intermediate",
                serial: 0x2002,
                not_before: NOT_BEFORE,
                not_after: NOT_AFTER,
                role: Role::Ca,
                key: &inter_key,
            },
            Some((&root, &root_key)),
        );
        let leaf_key = Key::rsa("leaf", 3072);
        let leaf_spec = |cn, serial, nb, na, role, key| Spec {
            cn,
            serial,
            not_before: nb,
            not_after: na,
            role,
            key,
        };
        let under_inter = |s: &Spec<'_>| pki::issue(s, Some((&inter, &inter_key)));
        let leaf = under_inter(&leaf_spec(
            "Palisade Test Publisher",
            0x3003,
            NOT_BEFORE,
            NOT_AFTER,
            Role::CodeSigning,
            &leaf_key,
        ));
        let leaf2_key = Key::rsa("leaf-2", 3072);
        let leaf2 = under_inter(&leaf_spec(
            "Palisade Test Publisher Two",
            0x3004,
            NOT_BEFORE,
            NOT_AFTER,
            Role::CodeSigning,
            &leaf2_key,
        ));
        // The same key as `leaf` under other certificates, so only the
        // certificate differs between these fixtures.
        let expired = under_inter(&leaf_spec(
            "Palisade Test Expired",
            0x4004,
            NOT_BEFORE - 3 * YEAR,
            NOT_BEFORE - YEAR,
            Role::CodeSigning,
            &leaf_key,
        ));
        let revoked = under_inter(&leaf_spec(
            "Palisade Test Revoked",
            REVOKED_SERIAL,
            NOT_BEFORE,
            NOT_AFTER,
            Role::CodeSigning,
            &leaf_key,
        ));
        let wrong_eku = under_inter(&leaf_spec(
            "Palisade Test Server",
            0x6006,
            NOT_BEFORE,
            NOT_AFTER,
            Role::ServerAuth,
            &leaf_key,
        ));
        let self_signed = pki::issue(
            &leaf_spec(
                "Palisade Test Self-Signed",
                0x7007,
                NOT_BEFORE,
                NOT_AFTER,
                Role::CodeSigning,
                &leaf_key,
            ),
            None,
        );
        let crl = pki::crl(
            (&inter, &inter_key),
            SIGNING_TIME,
            NOT_AFTER,
            &[(REVOKED_SERIAL, SIGNING_TIME - 86_400)],
        );
        Self {
            root_key,
            root,
            inter_key,
            inter,
            leaf_key,
            leaf,
            leaf2_key,
            leaf2,
            expired,
            revoked,
            wrong_eku,
            self_signed,
            crl,
        }
    }
}

/// The version resource every PE fixture carries: `name` as its original
/// file name, with the product, company and version the tests check.
fn versioned(mut b: PeBuilder, name: &str) -> PeBuilder {
    let strings = vec![
        common::string("CompanyName", "Palisade Tests"),
        common::string("FileDescription", "Palisade test fixture"),
        common::string("FileVersion", "1.2.3.4"),
        common::string("InternalName", name.split('.').next().unwrap()),
        common::string("OriginalFilename", name),
        common::string("ProductName", "Palisade Fixtures"),
        common::string("ProductVersion", "1.2.0.0"),
    ];
    let version = common::VersionSpec {
        fixed: Some(common::fixed_info((1, 2, 3, 4), (1, 2, 0, 0))),
        tables: vec![("040904B0", strings)],
        translations: vec![(0x0409, 0x04b0)],
    };
    b.resources = vec![common::Leaf {
        type_id: 16,
        name_id: 1,
        lang: 0x0409,
        data: version.build(),
    }];
    b
}

/// A PE fixture for a machine and bitness, as an executable or a DLL.
pub fn pe(name: &str, machine: u16, pe32_plus: bool, dll: bool) -> PeBuilder {
    let base = match (pe32_plus, dll) {
        (true, false) => PeBuilder::default(),
        (true, true) => PeBuilder::dll(),
        (false, false) => PeBuilder::pe32(),
        (false, true) => PeBuilder {
            characteristics: 0x2102,
            entry_point: 0,
            ..PeBuilder::pe32()
        },
    };
    versioned(PeBuilder { machine, ..base }, name)
}

/// The unsigned PE fixtures: `(name, builder)`.
pub fn pe_matrix() -> Vec<(&'static str, PeBuilder)> {
    vec![
        (
            "pe32plus-x64.exe",
            pe("pe32plus-x64.exe", MACHINE_X64, true, false),
        ),
        (
            "pe32plus-x64.dll",
            pe("pe32plus-x64.dll", MACHINE_X64, true, true),
        ),
        (
            "pe32plus-arm64.exe",
            pe("pe32plus-arm64.exe", MACHINE_ARM64, true, false),
        ),
        (
            "pe32plus-arm64.dll",
            pe("pe32plus-arm64.dll", MACHINE_ARM64, true, true),
        ),
        (
            "pe32-x86.exe",
            pe("pe32-x86.exe", MACHINE_X86, false, false),
        ),
        ("pe32-x86.dll", pe("pe32-x86.dll", MACHINE_X86, false, true)),
    ]
}

/// `image` with `table` as its certificate table.
fn with_table(b: &PeBuilder, table: Vec<u8>) -> Vec<u8> {
    PeBuilder {
        certificate: Some(table),
        ..b.clone()
    }
    .build()
}

/// `b` signed by `signer`, optionally with nested signatures.
fn signed(b: &PeBuilder, signer: &Signer<'_>, nested: &[&Signer<'_>]) -> Vec<u8> {
    let unsigned = b.build();
    let digest = authenticode_sha256(&unsigned);
    let nested: Vec<Vec<u8>> = nested
        .iter()
        .map(|s| signed_data(s, &digest, None, &[]))
        .collect();
    with_table(
        b,
        win_certificate(&signed_data(signer, &digest, None, &nested)),
    )
}

/// The SHA-256 page hash table of `b` as signed (the certificate table is
/// excluded from it, so it can be computed before signing).
fn page_table(b: &PeBuilder) -> Vec<u8> {
    let image = b.build();
    let info = pe::parse(&image).unwrap();
    page_hash_table(&image, &info, HashAlgorithm::Sha256)
        .unwrap()
        .table
}

/// The malformed corpus: `(name, bytes)`.
pub fn malformed() -> Vec<(&'static str, Vec<u8>)> {
    let good = PeBuilder::default().build();
    let mut out = vec![
        ("malformed-zero-length.bin", Vec::new()),
        ("malformed-mz-only.exe", b"MZ".to_vec()),
        // Cut inside the optional header.
        (
            "malformed-truncated-headers.exe",
            good[..common::OPT_OFFSET + 16].to_vec(),
        ),
    ];
    // Two sections at the same file range.
    let mut overlap = PeBuilder::default()
        .section(
            ".data",
            vec![0x11; 0x100],
            common::IMAGE_SCN_CNT_INITIALIZED_DATA,
        )
        .build();
    let table = PeBuilder::default().section_table_offset();
    let first_raw = u32::from_le_bytes(overlap[table + 20..table + 24].try_into().unwrap());
    overlap[table + 40 + 20..table + 40 + 24].copy_from_slice(&first_raw.to_le_bytes());
    out.push(("malformed-overlapping-sections.exe", overlap));
    // NumberOfSections = 0xffff.
    let mut many = good.clone();
    many[common::COFF_OFFSET + 2..common::COFF_OFFSET + 4]
        .copy_from_slice(&0xffff_u16.to_le_bytes());
    out.push(("malformed-absurd-section-count.exe", many));
    // SizeOfImage = 0xffff_f000.
    let mut huge = good.clone();
    let soi = common::OPT_OFFSET + 56;
    huge[soi..soi + 4].copy_from_slice(&0xffff_f000_u32.to_le_bytes());
    out.push(("malformed-huge-size-of-image.exe", huge));
    // A resource directory whose only entry points back at itself.
    let mut dir = vec![0_u8; 24];
    dir[14..16].copy_from_slice(&1_u16.to_le_bytes());
    dir[16..20].copy_from_slice(&16_u32.to_le_bytes());
    dir[20..24].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
    let b = PeBuilder::default().section(".rsrc", dir, common::IMAGE_SCN_CNT_INITIALIZED_DATA);
    let mut recursive = b.build();
    let rva = common::SECTION_ALIGNMENT * 2;
    let at = b.data_directory_offset(2);
    recursive[at..at + 4].copy_from_slice(&rva.to_le_bytes());
    recursive[at + 4..at + 8].copy_from_slice(&24_u32.to_le_bytes());
    out.push(("malformed-recursive-resources.exe", recursive));
    out
}

/// Benign script fixtures: each prints or writes the marker
/// `PALISADE-FIXTURE` and does nothing else.
pub fn scripts() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("script.ps1", b"# Palisade test fixture (benign).\r\nWrite-Output 'PALISADE-FIXTURE'\r\n"),
        ("script.bat", b"@echo off\r\nrem Palisade test fixture (benign).\r\necho PALISADE-FIXTURE\r\n"),
        ("script.cmd", b"@echo off\r\nrem Palisade test fixture (benign).\r\necho PALISADE-FIXTURE\r\n"),
        ("script.vbs", b"' Palisade test fixture (benign).\r\nWScript.Echo \"PALISADE-FIXTURE\"\r\n"),
        ("script.js", b"// Palisade test fixture (benign).\r\nWScript.Echo(\"PALISADE-FIXTURE\");\r\n"),
        (
            "script.wsf",
            b"<?xml version=\"1.0\"?>\r\n<!-- Palisade test fixture (benign). -->\r\n<job id=\"fixture\">\r\n  <script language=\"JScript\">WScript.Echo(\"PALISADE-FIXTURE\");</script>\r\n</job>\r\n",
        ),
        (
            "script.hta",
            b"<html>\r\n<!-- Palisade test fixture (benign). -->\r\n<head><title>PALISADE-FIXTURE</title><hta:application id=\"fixture\" /></head>\r\n<body>PALISADE-FIXTURE</body>\r\n</html>\r\n",
        ),
    ]
}

/// A version 2 catalog CTL with one PE member (`digest`, SHA-256), as
/// catalog tools write it.
pub fn catalog_ctl(digest: &[u8], file: &str) -> Vec<u8> {
    use der::*;
    let utf16z = |t: &str| -> Vec<u8> {
        let mut v: Vec<u8> = t.encode_utf16().flat_map(u16::to_le_bytes).collect();
        v.extend([0, 0]);
        v
    };
    let bmp = |t: &str| {
        tlv(
            0x1e,
            &t.encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<u8>>(),
        )
    };
    let attr = |id: &str, value: &[u8]| seq(&[&oid(id), &set(&[value])]);
    let name_value = |n: &str, v: &str| seq(&[&bmp(n), &int(0x1001_0001), &octets(&utf16z(v))]);
    // SpcIndirectData { SpcPeImageData, DigestInfo }.
    let link = tlv(0xa0, &tlv(0xa2, &tlv(0x80, &[])));
    let data = seq(&[
        &oid("1.3.6.1.4.1.311.2.1.15"),
        &seq(&[&[0x03, 0x01, 0x00], &link]),
    ]);
    let indirect = seq(&[&data, &seq(&[&alg(pki::OID_SHA256), &octets(digest)])]);
    let info = seq(&[&bmp("{C689AAB8-8E78-11D0-8C47-00C04FC295EE}"), &int(512)]);
    let member = seq(&[
        &octets(digest),
        &set(&[
            &attr("1.3.6.1.4.1.311.12.2.1", &name_value("File", file)),
            &attr("1.3.6.1.4.1.311.2.1.4", &indirect),
            &attr("1.3.6.1.4.1.311.12.2.2", &info),
        ]),
    ]);
    seq(&[
        &seq(&[&oid("1.3.6.1.4.1.311.12.1.1")]),
        &octets(&[0x50; 16]),
        &time(SIGNING_TIME),
        &alg("1.3.6.1.4.1.311.12.1.3"),
        &seq(&[&member]),
    ])
}

/// Every fixture, in name order.
pub fn corpus() -> Vec<Fixture> {
    let pki = Pki::new();
    let mut out = Vec::new();
    let mut push = |name, kind, bytes, deterministic| {
        out.push(Fixture {
            name,
            kind,
            bytes,
            deterministic,
        });
    };
    for (name, b) in pe_matrix() {
        push(name, Kind::Pe, b.build(), true);
    }

    let chain: [&Cert; 2] = [&pki.inter, &pki.root];
    let leaf = Signer {
        leaf: &pki.leaf,
        key: &pki.leaf_key,
        chain: &chain,
    };
    let base = pe("signed.exe", MACHINE_X64, true, false);
    push("signed.exe", Kind::Signed, signed(&base, &leaf, &[]), true);

    let leaf2 = Signer {
        leaf: &pki.leaf2,
        key: &pki.leaf2_key,
        chain: &chain,
    };
    let dual = pe("signed-dual.exe", MACHINE_X64, true, false);
    push(
        "signed-dual.exe",
        Kind::Signed,
        signed(&dual, &leaf, &[&leaf2]),
        true,
    );

    let ph = pe("signed-page-hashes.exe", MACHINE_X64, true, false);
    let table = page_table(&ph);
    let digest = authenticode_sha256(&ph.build());
    push(
        "signed-page-hashes.exe",
        Kind::Signed,
        with_table(
            &ph,
            win_certificate(&signed_data(&leaf, &digest, Some(&table), &[])),
        ),
        true,
    );

    // Same signature, one byte of code changed after signing.
    let mut tampered = signed(
        &pe("signed-tampered.exe", MACHINE_X64, true, false),
        &leaf,
        &[],
    );
    tampered[common::SIZE_OF_HEADERS as usize + 1] ^= 0xff;
    push("signed-tampered.exe", Kind::Tampered, tampered, true);

    // The certificate table claims more bytes than the file has.
    let trunc_b = pe("signed-truncated.exe", MACHINE_X64, true, false);
    let full = signed(&trunc_b, &leaf, &[]);
    let cut = full.len() - 64;
    push(
        "signed-truncated.exe",
        Kind::TruncatedSignature,
        full[..cut].to_vec(),
        true,
    );

    for (name, cert) in [
        ("signed-expired.exe", &pki.expired),
        ("signed-revoked.exe", &pki.revoked),
        ("signed-wrong-eku.exe", &pki.wrong_eku),
    ] {
        let s = Signer {
            leaf: cert,
            key: &pki.leaf_key,
            chain: &chain,
        };
        push(
            name,
            Kind::Signed,
            signed(&pe(name, MACHINE_X64, true, false), &s, &[]),
            true,
        );
    }
    let self_signed = Signer {
        leaf: &pki.self_signed,
        key: &pki.leaf_key,
        chain: &[],
    };
    push(
        "signed-self-signed.exe",
        Kind::Signed,
        signed(
            &pe("signed-self-signed.exe", MACHINE_X64, true, false),
            &self_signed,
            &[],
        ),
        true,
    );

    // An ECDSA P-256 leaf under the same intermediate (random signatures).
    let ec_key = Key::p256();
    let ec_leaf = pki::issue(
        &Spec {
            cn: "Palisade Test ECDSA Publisher",
            serial: 0x8008,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            role: Role::CodeSigning,
            key: &ec_key,
        },
        Some((&pki.inter, &pki.inter_key)),
    );
    let ec = Signer {
        leaf: &ec_leaf,
        key: &ec_key,
        chain: &chain,
    };
    push(
        "signed-ecdsa-p256.exe",
        Kind::Signed,
        signed(
            &pe("signed-ecdsa-p256.exe", MACHINE_X64, true, false),
            &ec,
            &[],
        ),
        false,
    );

    // A catalog listing `catalog-member.exe` by its SHA-256 Authenticode
    // digest. The member itself is unsigned: it is catalog-signed.
    let member = pe("catalog-member.exe", MACHINE_X64, true, false).build();
    let ctl = catalog_ctl(&authenticode_sha256(&member), "catalog-member.exe");
    push("catalog-member.exe", Kind::Catalog, member, true);
    push(
        "catalog.cat",
        Kind::Catalog,
        signed_catalog(&leaf, &ctl),
        true,
    );

    for (name, bytes) in malformed() {
        push(name, Kind::Malformed, bytes, true);
    }
    for (name, bytes) in scripts() {
        push(name, Kind::Script, bytes.to_vec(), true);
    }
    for (name, der) in [
        ("pki-root.der", pki.root.der.clone()),
        ("pki-intermediate.der", pki.inter.der.clone()),
        ("pki-leaf.der", pki.leaf.der.clone()),
        ("pki-intermediate.crl", pki.crl.clone()),
    ] {
        push(name, Kind::Pki, der, true);
    }
    out.sort_by_key(|f| f.name);
    out
}

/// `name -> bytes`, for tests that look fixtures up.
pub fn by_name(corpus: &[Fixture]) -> BTreeMap<&'static str, &Fixture> {
    corpus.iter().map(|f| (f.name, f)).collect()
}
