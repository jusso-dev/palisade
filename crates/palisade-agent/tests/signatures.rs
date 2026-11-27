//! The agent's `SignatureVerifier` (#29) against `palisade_fileid`'s test
//! fixtures: the synthetic PE image its tests build (`tests/common`), the
//! Authenticode signatures made over it (`fixtures/authenticode`), and the
//! catalogs that list it (`fixtures/catalog`). No binary is checked in
//! here; the image is built at test time. Runs on every OS.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

#[path = "../../palisade-fileid/tests/common/mod.rs"]
mod common;

use common::PeBuilder;
use palisade_agent::platform::{FileidSignatures, SignatureSettings};
use palisade_core::platform::{
    ErrorKind, MonotonicTime, SignatureSource, SignatureVerifier, UtcTime,
};
use palisade_core::test_util::MockClock;
use palisade_fileid::authenticode::{
    CertSelection, RevocationSet, TrustConfig, ValidityPolicy, VerificationError,
    extract_certificates, hash_pe,
};
use palisade_fileid::catalog::{
    CatalogSource, CatalogStore, CatalogStoreBuilder, LoadError, LoadReport, StoreLimits,
    ValidityOptions,
};
use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm, hash_bytes};

/// `with_catalogs` for a store whose one load reported no errors.
trait WithCatalogs {
    fn with_catalogs_ok(self, store: CatalogStore) -> Self;
}

impl<C: palisade_core::platform::Clock> WithCatalogs for FileidSignatures<C> {
    fn with_catalogs_ok(self, store: CatalogStore) -> Self {
        self.with_catalogs(store, [&LoadReport::default()])
    }
}

const FILEID: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../palisade-fileid/tests/fixtures"
);

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!("{FILEID}/{path}")).unwrap()
}

/// 2026-01-01T00:00:00Z, in seconds.
const Y2026: i64 = 1_767_225_600;
/// 2030-01-01T00:00:00Z, in seconds: inside every fixture's validity.
const Y2030: i64 = 1_893_456_000;

fn clock(secs: i64) -> MockClock {
    MockClock::new(UtcTime(secs * 1_000_000), MonotonicTime(0))
}

/// The default synthetic image, with `pkcs7` as its one
/// `WIN_CERTIFICATE` (revision 2.0, PKCS#7), padded to 8 bytes.
fn signed_image(pkcs7: &[u8]) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&(u32::try_from(pkcs7.len()).unwrap() + 8).to_le_bytes());
    entry.extend_from_slice(&0x0200_u16.to_le_bytes());
    entry.extend_from_slice(&2_u16.to_le_bytes());
    entry.extend_from_slice(pkcs7);
    while entry.len() % 8 != 0 {
        entry.push(0);
    }
    PeBuilder {
        certificate: Some(entry),
        ..PeBuilder::default()
    }
    .build()
}

/// The self-signed root that a fixture signature carries.
fn embedded_root(pkcs7: &[u8]) -> Vec<u8> {
    let found = extract_certificates(&signed_image(pkcs7), CertSelection::All).unwrap();
    found
        .certificates
        .into_iter()
        .find(|c| c.is_root)
        .unwrap()
        .cert
        .der
}

fn anchored(label: &str, der: &[u8]) -> TrustConfig {
    let mut t = TrustConfig::new();
    t.add_anchor(label, der).unwrap();
    t
}

/// A scratch directory, removed when dropped.
struct Dir(std::path::PathBuf);

impl Dir {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("palisade-agent-sig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn an_embedded_signature_is_ok_only_under_a_trusted_root() {
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let dir = Dir::new("embedded");
    let path = dir.write("signed.exe", &signed_image(&pkcs7));

    // Nothing trusted: the signature is reported, its chain too, but it is
    // not Ok.
    let untrusted = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2030));
    let r = untrusted.embedded(&path).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].source, SignatureSource::Embedded);
    assert_ne!(r[0].status, VerificationError::Ok);

    let settings = SignatureSettings {
        trust: anchored("test root", &embedded_root(&pkcs7)),
        ..SignatureSettings::default()
    };
    let trusted = FileidSignatures::with_clock(settings, clock(Y2030));
    let r = trusted.embedded(&path).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status, VerificationError::Ok, "{r:#?}");
    assert_eq!(r[0].chain.len(), 2, "{r:#?}");
    assert!(r[0].chain[0].subject.contains("Signer"), "{r:#?}");
    assert_eq!(r[0].chain[0].issuer, r[0].chain[1].subject);
    assert_ne!(r[0].chain[0].sha256, [0; 32]);
    assert_eq!(r[0].signing_time, None);
}

#[test]
fn a_tampered_image_is_not_ok() {
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let mut image = signed_image(&pkcs7);
    // A byte of the .text section, which the Authenticode digest covers.
    image[0x401] ^= 0xFF;
    let dir = Dir::new("tampered");
    let path = dir.write("tampered.exe", &image);
    let settings = SignatureSettings {
        trust: anchored("test root", &embedded_root(&pkcs7)),
        ..SignatureSettings::default()
    };
    let v = FileidSignatures::with_clock(settings, clock(Y2030));
    let r = v.embedded(&path).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status, VerificationError::InvalidHash, "{r:#?}");
}

#[test]
fn unsigned_files_and_bad_paths() {
    let v = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2030));
    let dir = Dir::new("unsigned");
    let plain = dir.write("plain.exe", &PeBuilder::default().build());
    assert!(v.embedded(&plain).unwrap().is_empty());
    let text = dir.write("notes.txt", b"not a PE file");
    assert!(v.embedded(&text).unwrap().is_empty());

    let missing = dir.0.join("missing.exe");
    assert_eq!(
        v.embedded(missing.to_str().unwrap()).unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        v.embedded("relative.exe").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        v.embedded(dir.0.to_str().unwrap()).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    // Too large to read is an error, never "unsigned".
    let small = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2030))
        .with_max_file_size(16);
    assert_eq!(
        small.embedded(&plain).unwrap_err().kind(),
        ErrorKind::TooLarge
    );
}

fn catalog_store(name: &str, judged: bool, now: i64) -> CatalogStore {
    let root = fixture("catalog/validity-root.der");
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchored("catalog root", &root));
    if judged {
        b = b.validity(ValidityOptions {
            policy: ValidityPolicy::default(),
            revocation: RevocationSet::new(),
            tsa_trust: anchored("tsa root", &fixture("catalog/validity-tsa-root.der")),
            now,
            clock_floor: None,
        });
    }
    let r = b.add_bytes(
        CatalogSource::System,
        None,
        &fixture(&format!("catalog/{name}")),
    );
    assert_eq!(r.valid, 1, "{r:?}");
    b.build()
}

#[test]
fn catalog_lookups() {
    let dir = Dir::new("catalog");
    let member = dir.write("member.exe", &PeBuilder::default().build());
    let other = dir.write("other.exe", b"MZ but listed nowhere");
    let settings = || SignatureSettings::default();

    // No store: unsupported, never "not catalog-signed".
    let none = FileidSignatures::with_clock(settings(), clock(Y2026));
    assert_eq!(
        none.catalog(&member).unwrap_err().kind(),
        ErrorKind::Unsupported
    );

    // A trusted, timestamped catalog, judged: Ok, with its chain and the
    // trusted signing time.
    let v = FileidSignatures::with_clock(settings(), clock(Y2026)).with_catalogs_ok(catalog_store(
        "v2-expired-timestamped.cat",
        true,
        Y2026,
    ));
    let found = v.catalog(&member).unwrap().unwrap();
    assert_eq!(found.source, SignatureSource::Catalog);
    assert_eq!(found.status, VerificationError::Ok, "{found:#?}");
    assert!(!found.chain.is_empty());
    assert_eq!(found.signing_time, Some(UtcTime(1_609_459_200 * 1_000_000)));
    assert_eq!(v.catalog(&other).unwrap(), None);

    // Expired without a timestamp: listed, not Ok.
    let v = FileidSignatures::with_clock(settings(), clock(Y2026)).with_catalogs_ok(catalog_store(
        "v2-expired.cat",
        true,
        Y2026,
    ));
    let found = v.catalog(&member).unwrap().unwrap();
    assert_eq!(found.status, VerificationError::Expired);

    // Trusted but never judged: not Ok.
    let v = FileidSignatures::with_clock(settings(), clock(Y2026)).with_catalogs_ok(catalog_store(
        "v2-expired-timestamped.cat",
        false,
        Y2026,
    ));
    let found = v.catalog(&member).unwrap().unwrap();
    assert_ne!(found.status, VerificationError::Ok);
}

#[test]
fn a_sha1_catalog_match_is_weak() {
    let ca = fixture("catalog/ca.der");
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchored("ca", &ca))
        .validity(ValidityOptions {
            policy: ValidityPolicy::default(),
            revocation: RevocationSet::new(),
            tsa_trust: TrustConfig::new(),
            now: Y2030,
            clock_floor: None,
        });
    let r = b.add_bytes(CatalogSource::System, None, &fixture("catalog/v1-sha1.cat"));
    assert_eq!(r.valid, 1, "{r:?}");
    let v = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2030))
        .with_catalogs(b.build(), [&r]);
    let dir = Dir::new("sha1");
    let member = dir.write("member.exe", &PeBuilder::default().build());
    let found = v.catalog(&member).unwrap().unwrap();
    assert_eq!(found.status, VerificationError::WeakHashAlgorithm);
}

/// `rsa2048-sha256` with its root trusted.
fn trusted_settings(pkcs7: &[u8]) -> SignatureSettings {
    SignatureSettings {
        trust: anchored("test root", &embedded_root(pkcs7)),
        ..SignatureSettings::default()
    }
}

#[test]
fn a_file_revoked_by_its_flat_hash_is_revoked_on_both_paths() {
    // Review B1: the catalog path ignored revocation of the file itself.
    let member = PeBuilder::default().build();
    let flat = hash_bytes(&member, AlgorithmSet::SHA256);
    let mut revocation = RevocationSet::new();
    revocation.add_file_hash(flat.get(HashAlgorithm::Sha256).unwrap().clone());
    let settings = SignatureSettings {
        revocation,
        ..SignatureSettings::default()
    };
    let dir = Dir::new("revoked-catalog");
    let path = dir.write("member.exe", &member);
    let v = FileidSignatures::with_clock(settings, clock(Y2026)).with_catalogs_ok(catalog_store(
        "v2-expired-timestamped.cat",
        true,
        Y2026,
    ));
    let found = v.catalog(&path).unwrap().unwrap();
    assert_eq!(found.status, VerificationError::RevokedByHash, "{found:#?}");
}

#[test]
fn a_file_revoked_by_its_authenticode_hash_is_revoked() {
    // Review M1: only flat hashes were checked.
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let image = signed_image(&pkcs7);
    let authenticode = hash_pe(&image, AlgorithmSet::EMPTY).unwrap();
    let dir = Dir::new("revoked-authenticode");
    let path = dir.write("signed.exe", &image);
    for alg in [HashAlgorithm::Sha256, HashAlgorithm::Sha1] {
        let mut settings = trusted_settings(&pkcs7);
        settings
            .revocation
            .add_file_hash(authenticode.get(alg).unwrap().clone());
        let v = FileidSignatures::with_clock(settings, clock(Y2030));
        let r = v.embedded(&path).unwrap();
        assert_eq!(
            r[0].status,
            VerificationError::RevokedByHash,
            "{alg:?}: {r:#?}"
        );
    }
    // The catalog path matches the Authenticode digests too.
    let member = PeBuilder::default().build();
    let image_hash = hash_pe(&member, AlgorithmSet::EMPTY).unwrap();
    let mut revocation = RevocationSet::new();
    revocation.add_file_hash(image_hash.get(HashAlgorithm::Sha256).unwrap().clone());
    let v = FileidSignatures::with_clock(
        SignatureSettings {
            revocation,
            ..SignatureSettings::default()
        },
        clock(Y2026),
    )
    .with_catalogs_ok(catalog_store("v2-expired-timestamped.cat", true, Y2026));
    let member_path = dir.write("member.exe", &member);
    assert_eq!(
        v.catalog(&member_path).unwrap().unwrap().status,
        VerificationError::RevokedByHash
    );
}

#[test]
fn an_embedded_sha1_signature_is_weak() {
    // Review M2: an SHA-1-only embedded signature was Ok, while the same
    // on the catalog path was WeakHashAlgorithm (ADR 0008).
    let pkcs7 = fixture("page_hash/default-sha1.p7");
    let dir = Dir::new("sha1-embedded");
    let path = dir.write("sha1.exe", &signed_image(&pkcs7));
    let v = FileidSignatures::with_clock(trusted_settings(&pkcs7), clock(Y2030));
    let r = v.embedded(&path).unwrap();
    assert_eq!(r.len(), 1, "{r:#?}");
    assert_eq!(r[0].status, VerificationError::WeakHashAlgorithm, "{r:#?}");
}

#[test]
fn an_incomplete_catalog_store_makes_a_miss_inconclusive() {
    // Review m6: a catalog that could not be loaded may be the one that
    // lists the file.
    let dir = Dir::new("incomplete");
    let other = dir.write("other.exe", b"MZ but listed nowhere");
    let complete = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2026))
        .with_catalogs_ok(catalog_store("v2-expired-timestamped.cat", true, Y2026));
    assert_eq!(complete.catalog(&other).unwrap(), None);
    let failed = LoadReport {
        errors: vec![LoadError::ByteLimit],
        ..LoadReport::default()
    };
    let truncated = LoadReport {
        errors_truncated: true,
        ..LoadReport::default()
    };
    for report in [failed, truncated] {
        let v = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2026))
            .with_catalogs(
                catalog_store("v2-expired-timestamped.cat", true, Y2026),
                [&LoadReport::default(), &report],
            );
        assert_eq!(v.catalog(&other).unwrap_err().kind(), ErrorKind::TooLarge);
    }
    // An unreadable catalog in the store.
    let mut b = CatalogStoreBuilder::new(StoreLimits::default());
    let r = b.add_bytes(CatalogSource::System, None, b"not a catalog");
    let v = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2026))
        .with_catalogs(b.build(), [&r]);
    assert_eq!(v.catalog(&other).unwrap_err().kind(), ErrorKind::TooLarge);
}

#[test]
fn a_malformed_pe_is_not_unsigned() {
    // Review m9.
    let v = FileidSignatures::with_clock(SignatureSettings::default(), clock(Y2030));
    let dir = Dir::new("malformed");
    // `MZ`, but not a PE image.
    let truncated = dir.write("truncated.exe", b"MZ\x90\x00 too short to be a PE image");
    let r = v.embedded(&truncated).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].status, VerificationError::MalformedSignature);
    // A certificate table entry that is not a WIN_CERTIFICATE.
    let garbage = PeBuilder {
        certificate: Some(vec![0xFF; 16]),
        ..PeBuilder::default()
    }
    .build();
    let path = dir.write("garbage.exe", &garbage);
    let r = v.embedded(&path).unwrap();
    assert_eq!(r.len(), 1, "{r:#?}");
    assert_eq!(r[0].status, VerificationError::MalformedSignature, "{r:#?}");
}

#[test]
fn fileid_signatures_meet_the_contract() {
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let dir = Dir::new("contract");
    let signed = dir.write("signed.exe", &signed_image(&pkcs7));
    let plain = dir.write("plain.exe", &PeBuilder::default().build());
    let missing = dir.0.join("missing.exe");
    let missing = missing.to_str().unwrap();
    let v = FileidSignatures::with_clock(trusted_settings(&pkcs7), clock(Y2030));
    palisade_core::test_util::contract::signatures(&v, &signed, &plain, missing).unwrap();
    // `PeBuilder::default()` is the fixture catalog's member, so with the
    // store the unsigned file is another image.
    let other = dir.write(
        "other.exe",
        &PeBuilder {
            timestamp: 0x6000_0001,
            ..PeBuilder::default()
        }
        .build(),
    );
    // Judged in 2030, inside the embedded signer's validity.
    let with_store = FileidSignatures::with_clock(trusted_settings(&pkcs7), clock(Y2030))
        .with_catalogs_ok(catalog_store("v2-expired-timestamped.cat", true, Y2026));
    palisade_core::test_util::contract::signatures(&with_store, &signed, &other, missing).unwrap();
}

#[test]
fn an_unknown_certificate_entry_is_malformed_not_unsigned() {
    // CodeRabbit on #323: an entry whose revision fileid does not know is
    // skipped, which left a signed image whose entry was altered reading
    // as unsigned.
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let mut entry = Vec::new();
    entry.extend_from_slice(&(u32::try_from(pkcs7.len()).unwrap() + 8).to_le_bytes());
    entry.extend_from_slice(&0x0300_u16.to_le_bytes());
    entry.extend_from_slice(&2_u16.to_le_bytes());
    entry.extend_from_slice(&pkcs7);
    while entry.len() % 8 != 0 {
        entry.push(0);
    }
    let image = PeBuilder {
        certificate: Some(entry),
        ..PeBuilder::default()
    }
    .build();
    let dir = Dir::new("unknown-entry");
    let path = dir.write("altered.exe", &image);
    let v = FileidSignatures::with_clock(trusted_settings(&pkcs7), clock(Y2030));
    let r = v.embedded(&path).unwrap();
    assert_eq!(r.len(), 1, "{r:#?}");
    assert_eq!(r[0].status, VerificationError::MalformedSignature, "{r:#?}");
    // An image with no certificate table at all is still unsigned.
    let plain = dir.write("plain.exe", &PeBuilder::default().build());
    assert!(v.embedded(&plain).unwrap().is_empty());
}

#[cfg(windows)]
#[test]
fn a_named_stream_on_a_directory_is_read() {
    // CodeRabbit on #323: a directory's named data stream reports the
    // directory attribute, so it was refused before either path read it.
    let pkcs7 = fixture("authenticode/rsa2048-sha256.p7");
    let dir = Dir::new("dir-stream");
    let folder = dir.0.join("folder");
    std::fs::create_dir(&folder).unwrap();
    let stream = format!("{}:payload", folder.to_str().unwrap());
    std::fs::write(&stream, signed_image(&pkcs7)).unwrap();
    let v = FileidSignatures::with_clock(trusted_settings(&pkcs7), clock(Y2030));
    let r = v.embedded(&stream).unwrap();
    assert_eq!(r.len(), 1, "{r:#?}");
    assert_eq!(r[0].status, VerificationError::Ok, "{r:#?}");
    // The directory itself is still refused.
    let err = v.embedded(folder.to_str().unwrap()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
}
