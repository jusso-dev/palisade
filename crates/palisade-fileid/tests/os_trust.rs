//! The OS trust-verification differential (#48): every signature fixture
//! is attached to the synthetic image, written to disk, and verified both
//! by this crate and by the OS. Runs only on Windows with `os-trust`, so
//! on the Windows CI runners.
//!
//! The fixtures are signed by a test-only CA the OS does not trust, so a
//! sound signature comes back from the OS as an untrusted chain, which
//! [`OsVerdict::ChainNotTrusted`] counts as intact.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

mod common;

use std::fs::File;
use std::path::{Path, PathBuf};

use common::PeBuilder;
use palisade_fileid::authenticode::{
    CrossCheck, OsTrustResult, OsVerdict, Outcome, SignatureReport, SignatureStatus, VerifyOptions,
    cross_check, verify_pe,
};
use palisade_fileid::win::trust::verify_file;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/authenticode");

/// Every PKCS#7 fixture.
const SIGNED: &[&str] = &[
    "p256-sha256.p7",
    "p384-sha384.p7",
    "p521-sha512.p7",
    "rsa1024-sha256.p7",
    "rsa2048-md5.p7",
    "rsa2048-page-hashes.p7",
    "rsa2048-sha1-nested-sha256.p7",
    "rsa2048-sha256.p7",
    "rsa2048-sha384-commercial.p7",
    "rsa2048-sha512.p7",
    "rsa2048-timestamp.p7",
    "rsa4096-sha256.p7",
    "rsa8192-sha256.p7",
];

/// A directory this test created, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("palisade-os-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    Scratch(dir)
}

/// A `WIN_CERTIFICATE` entry holding `blob`, padded to 8 bytes.
fn pkcs7_entry(blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(blob.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(blob);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

fn signed_image(fixture: &str) -> Vec<u8> {
    let blob = std::fs::read(format!("{FIXTURES}/{fixture}")).unwrap();
    PeBuilder {
        certificate: Some(pkcs7_entry(&blob)),
        ..PeBuilder::default()
    }
    .build()
}

/// Writes `image` as `name.exe` in `dir`, verifies it both ways and
/// compares.
fn both(dir: &Path, name: &str, image: &[u8]) -> (SignatureReport, OsTrustResult, CrossCheck) {
    let path = dir.join(format!("{name}.exe"));
    std::fs::write(&path, image).unwrap();
    let report = verify_pe(image, &VerifyOptions::default()).unwrap();
    let file = File::open(&path).unwrap();
    let os = verify_file(&file, &path).unwrap();
    let check = cross_check(&report, &os);
    (report, os, check)
}

#[test]
fn unsigned_image() {
    let dir = scratch("unsigned");
    let (report, os, check) = both(&dir.0, "unsigned", &PeBuilder::default().build());
    assert!(report.signatures.is_empty());
    assert_eq!(os.signatures[0].verdict(), OsVerdict::NoSignature, "{os:?}");
    assert!(check.agrees(), "{check:#?}");
}

#[test]
fn valid_signature_has_an_untrusted_chain() {
    let dir = scratch("valid");
    let (report, os, check) = both(&dir.0, "valid", &signed_image("rsa2048-sha256.p7"));
    assert_eq!(report.signatures[0].status, SignatureStatus::Valid);
    assert_eq!(
        os.signatures[0].verdict(),
        OsVerdict::ChainNotTrusted,
        "{os:?}"
    );
    assert_eq!(os.secondary_count, 0);
    assert_eq!(check.comparisons[0].outcome, Outcome::Agree);
    assert!(check.agrees(), "{check:#?}");
}

#[test]
fn patched_image_is_rejected_by_both() {
    let dir = scratch("patched");
    let mut image = signed_image("rsa2048-sha256.p7");
    image[0x400] ^= 0xff; // the first byte of .text
    let (report, os, check) = both(&dir.0, "patched", &image);
    assert_eq!(report.signatures[0].status, SignatureStatus::DigestMismatch);
    assert_eq!(os.signatures[0].verdict(), OsVerdict::Broken, "{os:?}");
    assert!(check.agrees(), "{check:#?}");
}

#[test]
fn dual_signed_image_has_one_secondary_signature() {
    let dir = scratch("dual");
    let (report, os, check) = both(
        &dir.0,
        "dual",
        &signed_image("rsa2048-sha1-nested-sha256.p7"),
    );
    assert_eq!(report.signatures.len(), 2);
    assert_eq!(os.secondary_count, 1, "{os:?}");
    assert_eq!(os.signatures.len(), 2);
    assert!(!check.secondary_count_differs);
    assert_eq!(
        check
            .comparisons
            .iter()
            .map(|c| c.outcome)
            .collect::<Vec<_>>(),
        [Outcome::Agree, Outcome::Agree],
        "{check:#?}"
    );
}

/// The corpus differential: across every fixture, this crate never finds a
/// signature valid that the OS finds broken, and the two agree on how
/// many signatures the OS reads.
#[test]
fn corpus_differential() {
    let dir = scratch("corpus");
    for fixture in SIGNED {
        let name = fixture.trim_end_matches(".p7");
        let (_, os, check) = both(&dir.0, name, &signed_image(fixture));
        assert_eq!(
            check.rust_accepts_os_rejects().count(),
            0,
            "{fixture}: {os:?} {check:#?}"
        );
        assert!(!check.secondary_count_differs, "{fixture}: {check:#?}");
        assert!(
            !check
                .comparisons
                .iter()
                .any(|c| matches!(c.outcome, Outcome::OnlyOs | Outcome::OnlyRust)),
            "{fixture}: {check:#?}"
        );
    }
}
