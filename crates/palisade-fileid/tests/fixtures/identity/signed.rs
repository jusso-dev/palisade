//! The signed files of the file identity corpus (#55), built at test time.
//!
//! Nothing signed is committed (`docs/testing.md#fixtures`): these are made
//! from the corpus's synthetic images with the fixture corpus's pure-Rust
//! signer (`tests/corpus`), whose RSA keys come from a deterministic RNG.
//! So every run makes the same bytes, and `manifest.yaml` pins their
//! digests. Those digests are not this crate's own word: `generate.sh`
//! writes these files out and computes them with shasum, openssl and
//! osslsigncode, and verifies every signature with osslsigncode, and
//! `corpus_matches_the_manifest` fails if a file here stops matching them.

use std::collections::BTreeMap;

use crate::corpus::pki::{self, Cert, Key, Role, Spec};
use crate::corpus::sign::signed_data_sha1;
use crate::corpus::sign::{
    Signer, authenticode_sha256, signed_catalog, signed_data, win_certificate,
};
use crate::corpus::{authenticode_sha1, catalog_ctl_for};

/// 2020-01-01T00:00:00Z.
const Y2020: i64 = 1_577_836_800;
/// 2021-01-01T00:00:00Z.
const Y2021: i64 = 1_609_459_200;
/// 2050-01-01T00:00:00Z.
const Y2050: i64 = 2_524_608_000;
/// 2025-01-01T00:00:00Z and 2027-01-01T00:00:00Z: the CRL's window.
const Y2025: i64 = 1_735_689_600;
const Y2027: i64 = 1_798_761_600;

/// The serial of the corpus signer the CRL revokes.
pub const REVOKED_SERIAL: u64 = 0x0c05;

/// The corpus PKI: one root, and leaves for the corpus vendor, the corpus
/// "OS", a signer valid only in 2020, a revoked signer, and a self-signed
/// rogue.
pub struct CorpusPki {
    pub root_key: Key,
    pub root: Cert,
    pub vendor_key: Key,
    pub vendor: Cert,
    pub os_key: Key,
    pub os: Cert,
    pub expired: Cert,
    pub revoked: Cert,
    pub rogue_key: Key,
    pub rogue: Cert,
}

impl CorpusPki {
    pub fn new() -> Self {
        let root_key = Key::rsa("identity corpus root", 2048);
        let root = pki::issue(
            &Spec {
                cn: "Palisade Corpus Root",
                serial: 0x0c01,
                not_before: Y2020,
                not_after: Y2050,
                role: Role::Ca,
                key: &root_key,
            },
            None,
        );
        let leaf = |cn, serial, not_before, not_after, key: &Key| {
            pki::issue(
                &Spec {
                    cn,
                    serial,
                    not_before,
                    not_after,
                    role: Role::CodeSigning,
                    key,
                },
                Some((&root, &root_key)),
            )
        };
        let vendor_key = Key::rsa("identity corpus vendor", 2048);
        let vendor = leaf("Palisade Corpus Vendor", 0x0c02, Y2020, Y2050, &vendor_key);
        let os_key = Key::rsa("identity corpus os", 2048);
        // The OS signer names a CRL distribution point (never fetched), so a
        // policy that requires revocation answers asks about it.
        let os = pki::issue_with_crl_dp(
            &Spec {
                cn: "Palisade Corpus OS Signer",
                serial: 0x0c03,
                not_before: Y2020,
                not_after: Y2050,
                role: Role::CodeSigning,
                key: &os_key,
            },
            Some((&root, &root_key)),
            "http://crl.example.test/corpus.crl",
        );
        // The OS signer's key under a certificate valid in 2020 only, so a
        // catalog it signed without a timestamp has expired by now.
        let expired = leaf("Palisade Corpus OS Signer", 0x0c04, Y2020, Y2021, &os_key);
        // The vendor's key under a certificate the CRL revokes.
        let revoked = leaf(
            "Palisade Corpus Vendor",
            REVOKED_SERIAL,
            Y2020,
            Y2050,
            &vendor_key,
        );
        let rogue_key = Key::rsa("identity corpus rogue", 2048);
        let rogue = pki::issue(
            &Spec {
                cn: "Palisade Corpus Rogue",
                serial: 0x0c06,
                not_before: Y2020,
                not_after: Y2050,
                role: Role::CodeSigning,
                key: &rogue_key,
            },
            None,
        );
        Self {
            root_key,
            root,
            vendor_key,
            vendor,
            os_key,
            os,
            expired,
            revoked,
            rogue_key,
            rogue,
        }
    }

    /// The CA's CRL for 2025 to 2027: revokes [`REVOKED_SERIAL`] since 2024
    /// for key compromise.
    pub fn crl(&self) -> Vec<u8> {
        pki::crl(
            (&self.root, &self.root_key),
            Y2025,
            Y2027,
            &[(REVOKED_SERIAL, Y2025 - 86_400)],
        )
    }
}

/// `image` (a PE) with `pkcs7` as its certificate table, the PE checksum
/// left as the image has it (Authenticode does not cover it).
fn with_signature(image: &[u8], pkcs7: &[u8]) -> Vec<u8> {
    let table = win_certificate(pkcs7);
    let mut out = image.to_vec();
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    let at = u32::try_from(out.len()).unwrap();
    let len = u32::try_from(table.len()).unwrap();
    out.extend_from_slice(&table);
    // IMAGE_DIRECTORY_ENTRY_SECURITY: the file offset and size.
    let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe + 24;
    let magic = u16::from_le_bytes(out[opt..opt + 2].try_into().unwrap());
    let dirs = opt + if magic == 0x20b { 112 } else { 96 };
    out[dirs + 32..dirs + 36].copy_from_slice(&at.to_le_bytes());
    out[dirs + 36..dirs + 40].copy_from_slice(&len.to_le_bytes());
    out
}

fn sign(image: &[u8], leaf: &Cert, key: &Key, chain: &[&Cert]) -> Vec<u8> {
    let digest = authenticode_sha256(image);
    let signer = Signer { leaf, key, chain };
    with_signature(image, &signed_data(&signer, &digest, None, &[]))
}

/// Every generated corpus file, by its `file` name in `manifest.yaml`,
/// built from `unsigned` (the synthetic corpus files by generator name).
pub fn generated(unsigned: &BTreeMap<&'static str, Vec<u8>>) -> BTreeMap<&'static str, Vec<u8>> {
    let p = CorpusPki::new();
    let root: [&Cert; 1] = [&p.root];
    let mut m = BTreeMap::new();
    let tool = &unsigned["tool"];
    m.insert(
        "signed-tool.exe",
        sign(tool, &p.vendor, &p.vendor_key, &root),
    );
    m.insert(
        "signed-tool-v2.exe",
        sign(&unsigned["tool-v2"], &p.vendor, &p.vendor_key, &root),
    );
    m.insert(
        "signed-powershell.exe",
        sign(&unsigned["powershell"], &p.os, &p.os_key, &root),
    );
    m.insert(
        "rogue-signed.exe",
        sign(&unsigned["plain"], &p.rogue, &p.rogue_key, &[]),
    );
    // One code byte changed after signing.
    let mut tampered = m["signed-tool.exe"].clone();
    tampered[1025] ^= 0x01;
    m.insert("tampered-tool.exe", tampered);
    // The tool signed with SHA-1 throughout (content and signer digests).
    let sha1 = signed_data_sha1(
        &Signer {
            leaf: &p.vendor,
            key: &p.vendor_key,
            chain: &root,
        },
        &authenticode_sha1(tool),
    );
    m.insert("sha1-signed-tool.exe", with_signature(tool, &sha1));
    // The tool signed by the vendor's revoked certificate.
    m.insert(
        "revoked-signed-tool.exe",
        sign(tool, &p.revoked, &p.vendor_key, &root),
    );
    // Catalogs, by the OS signer: the plain image by its Authenticode
    // SHA-256 and the flat member by its flat SHA-256; and the same list
    // signed by the OS signer's 2020-only certificate, without a
    // timestamp, for the `driver` image.
    let os_signer = Signer {
        leaf: &p.os,
        key: &p.os_key,
        chain: &root,
    };
    let ctl = catalog_ctl_for(&[
        (authenticode_sha256(&unsigned["plain"]), "plain.exe", true),
        (sha256(&unsigned["flat-member"]), "palisade-test.txt", false),
    ]);
    m.insert("corpus.cat", signed_catalog(&os_signer, &ctl));
    let expired_signer = Signer {
        leaf: &p.expired,
        key: &p.os_key,
        chain: &root,
    };
    let ctl = catalog_ctl_for(&[(authenticode_sha256(&unsigned["driver"]), "driver.sys", true)]);
    m.insert("expired.cat", signed_catalog(&expired_signer, &ctl));
    m.insert("ca.der", p.root.der.clone());
    m.insert("ca-2025-2027.crl", p.crl());
    m
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    Sha256::digest(data).to_vec()
}
