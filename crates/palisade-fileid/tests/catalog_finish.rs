//! Catalog-signed files, the remainder of #51: catalog signatures under the
//! validity checks (#50), lookup settings, the persistent index and
//! catalog authoring.
//!
//! The fixtures are those of `tests/catalog.rs` (`fixtures/catalog`,
//! `generate.sh`) and the fixed-date validity catalogs made by
//! `fixtures/catalog/generate-validity.sh`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::PeBuilder;
use palisade_fileid::authenticode::{
    ExpiryPolicy, RevocationSet, TimeValidity, TrustConfig, ValidityPolicy, VerificationError,
};
use palisade_fileid::catalog::{
    AuthorError, CatalogEntry, CatalogIndex, CatalogLookup, CatalogScope, CatalogSettings,
    CatalogSource, CatalogStoreBuilder, EntryKind, FileDigests, IndexError, IndexState, LoadError,
    LookupSkipped, StoreLimits, ValidityOptions, build_catalog, parse_ctl,
};
use palisade_fileid::fsctx::path::normalize_win32;
use palisade_fileid::hash::{AlgorithmSet, Digest, HashAlgorithm, MacKey, hash_bytes};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/catalog");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

fn anchors(name: &str) -> TrustConfig {
    let mut config = TrustConfig::new();
    config.add_anchor(name, &fixture(name)).unwrap();
    config
}

const Y2021: i64 = 1_609_459_200;
const Y2026: i64 = 1_767_225_600;

fn pe_member() -> Vec<u8> {
    PeBuilder::default().build()
}

/// The text member of the fixture catalogs (see tests/catalog.rs).
const FLAT_MEMBER: &[u8] = b"Palisade catalog test: a flat (non-PE) member file.\n";

fn options(now: i64, policy: ValidityPolicy, revocation: RevocationSet) -> ValidityOptions {
    ValidityOptions {
        policy,
        revocation,
        tsa_trust: anchors("validity-tsa-root.der"),
        now,
        clock_floor: None,
    }
}

fn load(name: &str, options: Option<ValidityOptions>) -> palisade_fileid::catalog::CatalogStore {
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchors("validity-root.der"));
    if let Some(o) = options {
        b = b.validity(o);
    }
    let r = b.add_bytes(CatalogSource::System, None, &fixture(name));
    assert_eq!(r.valid, 1, "{r:?}");
    b.build()
}

// --- Catalog signatures under the #50 checks -------------------------------

#[test]
fn a_timestamped_catalog_stays_valid_after_its_signer_expires() {
    let store = load(
        "v2-expired-timestamped.cat",
        Some(options(
            Y2026,
            ValidityPolicy::default(),
            RevocationSet::new(),
        )),
    );
    let record = &store.records()[0];
    assert!(record.trusted);
    let v = record.validity.as_ref().unwrap();
    assert_eq!(v.error, VerificationError::Ok, "{v:#?}");
    assert_eq!(v.time_validity, Some(TimeValidity::ValidTimestamped));
    assert_eq!(v.signing_time, Some(Y2021));
    assert!(record.usable());
    let m = &store.lookup(&FileDigests::of_bytes(&pe_member())).matches[0];
    assert!(m.usable() && m.trusted());
}

#[test]
fn an_untimestamped_catalog_expires_with_its_signer() {
    let store = load(
        "v2-expired.cat",
        Some(options(
            Y2026,
            ValidityPolicy::default(),
            RevocationSet::new(),
        )),
    );
    let record = &store.records()[0];
    assert!(record.trusted);
    assert_eq!(
        record.validity.as_ref().unwrap().error,
        VerificationError::Expired
    );
    assert!(!record.usable());
    // Still listed, ranked below usable catalogs, and not usable.
    let m = &store.lookup(&FileDigests::of_bytes(&pe_member())).matches[0];
    assert!(m.trusted() && !m.usable());
    // While the signer was valid, it passes.
    let store = load(
        "v2-expired.cat",
        Some(options(
            Y2021,
            ValidityPolicy::default(),
            RevocationSet::new(),
        )),
    );
    assert!(store.records()[0].usable());
    // Under Strict, even the timestamp does not help once expired.
    let strict = ValidityPolicy {
        expiry_policy: ExpiryPolicy::Strict,
        ..ValidityPolicy::default()
    };
    let store = load(
        "v2-expired-timestamped.cat",
        Some(options(Y2026, strict, RevocationSet::new())),
    );
    assert_eq!(
        store.records()[0].validity.as_ref().unwrap().error,
        VerificationError::Expired
    );
}

#[test]
fn a_catalog_can_be_revoked_by_its_signer_or_its_hash() {
    let signer = {
        let cat = palisade_fileid::catalog::parse_catalog(&fixture("v2-expired-timestamped.cat"))
            .unwrap();
        let sig = cat.signature().unwrap();
        palisade_fileid::authenticode::CertSummary::from_der(
            &sig.certs_in_blob[sig.signer.as_ref().unwrap().signer_cert],
        )
        .unwrap()
    };
    // The signer's certificate, revoked with no date: revoked whatever the
    // timestamp says.
    let mut revocation = RevocationSet::new();
    revocation.add_certificate(palisade_fileid::authenticode::RevokedCertificate {
        cert: palisade_fileid::authenticode::CertificateMatch::Sha256Thumbprint(
            signer.sha256_thumbprint,
        ),
        revoked_at: None,
        reason: palisade_fileid::authenticode::RevocationReason::KeyCompromise,
        source: palisade_fileid::authenticode::RevocationSource::Policy,
    });
    let store = load(
        "v2-expired-timestamped.cat",
        Some(options(Y2026, ValidityPolicy::default(), revocation)),
    );
    assert_eq!(
        store.records()[0].validity.as_ref().unwrap().error,
        VerificationError::Revoked
    );
    assert!(!store.records()[0].usable());
    // The catalog file itself, by its SHA-256.
    let id = hash_bytes(&fixture("v2-expired-timestamped.cat"), AlgorithmSet::SHA256)
        .get(HashAlgorithm::Sha256)
        .cloned()
        .unwrap();
    let mut revocation = RevocationSet::new();
    revocation.add_file_hash(id);
    let store = load(
        "v2-expired-timestamped.cat",
        Some(options(Y2026, ValidityPolicy::default(), revocation)),
    );
    assert_eq!(
        store.records()[0].validity.as_ref().unwrap().error,
        VerificationError::RevokedByHash
    );
}

#[test]
fn without_validity_options_no_catalog_is_usable() {
    let store = load("v2-expired-timestamped.cat", None);
    let record = &store.records()[0];
    assert!(record.trusted && record.validity.is_none() && !record.usable());
}

// --- Settings ---------------------------------------------------------------

fn system_and_policy_store() -> palisade_fileid::catalog::CatalogStore {
    let mut b = CatalogStoreBuilder::new(StoreLimits::default())
        .trust(CatalogSource::System, anchors("ca.der"))
        .trust(CatalogSource::Policy, anchors("org-ca.der"));
    b.add_bytes(CatalogSource::System, None, &fixture("v2-sha256.cat"));
    b.add_bytes(CatalogSource::Policy, None, &fixture("org-sha256.cat"));
    b.build()
}

#[test]
fn settings_scope_disable_and_skip_lookups() {
    let store = system_and_policy_store();
    let digests = FileDigests::of_bytes(&pe_member());
    let all = CatalogSettings::default();
    assert_eq!(
        store
            .lookup_with(&digests, &all, None)
            .done()
            .unwrap()
            .matches
            .len(),
        2
    );
    let system = CatalogSettings {
        catalog_scope: CatalogScope::System,
        ..CatalogSettings::default()
    };
    let only = store.lookup_with(&digests, &system, None).done().unwrap();
    assert_eq!(only.matches.len(), 1);
    assert_eq!(only.matches[0].record.source, CatalogSource::System);
    let with_driver = CatalogSettings {
        catalog_scope: CatalogScope::SystemAndDriverStore,
        ..CatalogSettings::default()
    };
    assert_eq!(
        store
            .lookup_with(&digests, &with_driver, None)
            .done()
            .unwrap()
            .matches
            .len(),
        1
    );
    let off = CatalogSettings {
        catalog_lookup_enabled: false,
        ..CatalogSettings::default()
    };
    assert_eq!(
        store.lookup_with(&digests, &off, None),
        CatalogLookup::Skipped(LookupSkipped::Disabled)
    );
    // A skipped path, whatever its spelling.
    let skip = CatalogSettings {
        skip_catalog_for_paths: vec![normalize_win32(r"C:\Build\Out").unwrap()],
        ..CatalogSettings::default()
    };
    let under = normalize_win32(r"c:\BUILD\out\.\tool.exe").unwrap();
    let other = normalize_win32(r"C:\Build\Output\tool.exe").unwrap();
    assert_eq!(
        store.lookup_with(&digests, &skip, Some(&under)),
        CatalogLookup::Skipped(LookupSkipped::PathExcluded(0))
    );
    assert_eq!(
        store
            .lookup_with(&digests, &skip, Some(&other))
            .done()
            .unwrap()
            .matches
            .len(),
        2
    );
}

#[test]
fn a_full_member_index_stops_the_directory_walk() {
    let root = std::env::temp_dir().join(format!("palisade-cat-members-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(root.join("a.cat"), fixture("v2-sha256.cat")).unwrap();
    std::fs::write(root.join("b").join("c.cat"), fixture("v1-sha1.cat")).unwrap();
    // The first catalog fills the member index (2 members).
    let mut b = CatalogStoreBuilder::new(StoreLimits {
        max_members: 2,
        ..StoreLimits::default()
    });
    let r = b.add_dir(CatalogSource::System, &root);
    assert_eq!(r.recorded, 1, "{r:?}");
    assert_eq!(r.errors, [LoadError::MemberLimit]);
    std::fs::remove_dir_all(&root).unwrap();
}

// --- The persistent index ----------------------------------------------------

fn key() -> MacKey {
    MacKey::new(&[7; 32]).unwrap()
}

#[test]
fn the_index_answers_like_the_store_and_round_trips() {
    let store = system_and_policy_store();
    let mut index = CatalogIndex::from_store(&store);
    assert_eq!(index.state(), IndexState::Building);
    assert_eq!(index.indexed_members(), store.indexed_members());
    for data in [pe_member(), FLAT_MEMBER.to_vec(), b"absent".to_vec()] {
        let digests = FileDigests::of_bytes(&data);
        let from_store: Vec<(usize, bool)> = store
            .lookup(&digests)
            .matches
            .iter()
            .map(|m| (m.catalog, m.trusted()))
            .collect();
        let from_index: Vec<(usize, bool)> = index
            .lookup(&digests)
            .iter()
            .map(|m| (m.catalog, m.record.trusted))
            .collect();
        assert_eq!(from_store, from_index);
    }
    index.finish_build();
    let bytes = index.encode(&key());
    let back = CatalogIndex::decode(&bytes, &key()).unwrap();
    assert_eq!(back, index);
    assert_eq!(back.state(), IndexState::Ready);
    // The record keeps the signer's publisher.
    assert_eq!(
        back.catalogs()[0].publisher.as_deref(),
        Some("Palisade Test Catalog Signer")
    );
}

#[test]
fn a_tampered_or_foreign_index_is_rejected() {
    let index = CatalogIndex::from_store(&system_and_policy_store());
    let bytes = index.encode(&key());
    for at in [0, 5, bytes.len() / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert_eq!(
            CatalogIndex::decode(&bad, &key()).unwrap_err(),
            IndexError::BadMac
        );
    }
    let other = MacKey::new(&[8; 32]).unwrap();
    assert_eq!(
        CatalogIndex::decode(&bytes, &other).unwrap_err(),
        IndexError::BadMac
    );
    assert_eq!(
        CatalogIndex::decode(&[], &key()).unwrap_err(),
        IndexError::BadMac
    );
    // Another format version (validly tagged): rebuild.
    let mut body = bytes[..bytes.len() - 32].to_vec();
    body[4] = palisade_fileid::catalog::INDEX_FORMAT + 1;
    let resigned = resign(&body);
    assert!(matches!(
        CatalogIndex::decode(&resigned, &key()).unwrap_err(),
        IndexError::Rebuild { .. }
    ));
    // Validly tagged but truncated content: malformed, rebuild.
    let short = resign(&bytes[..bytes.len() - 32 - 3]);
    assert_eq!(
        CatalogIndex::decode(&short, &key()).unwrap_err(),
        IndexError::Malformed
    );
}

/// `body` with a valid tag under [`key`]: an index another writer made
/// with the agent's key, so the checks after the tag are what decide.
fn resign(body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend(hmac_helper::tag(&[7; 32], body));
    out
}

/// HMAC-SHA-256, written out with the crate's own SHA-256, so the tests do
/// not need a MAC dependency of their own.
mod hmac_helper {
    use palisade_fileid::hash::{AlgorithmSet, HashAlgorithm, hash_bytes};

    fn sha256(data: &[u8]) -> Vec<u8> {
        hash_bytes(data, AlgorithmSet::SHA256)
            .get(HashAlgorithm::Sha256)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut k = [0_u8; 64];
        k[..32].copy_from_slice(key);
        let inner: Vec<u8> = k
            .iter()
            .map(|b| b ^ 0x36)
            .chain(data.iter().copied())
            .collect();
        let inner = sha256(&inner);
        let outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).chain(inner).collect();
        sha256(&outer).try_into().unwrap()
    }
}

#[test]
fn the_index_reports_building_until_finished() {
    let store = system_and_policy_store();
    let mut index = CatalogIndex::from_store(&store);
    let absent = FileDigests::of_bytes(b"not in any catalog");
    let settings = CatalogSettings::default();
    assert_eq!(
        index.lookup_with(&absent, &settings, None),
        CatalogLookup::Indeterminate
    );
    // A hit is a hit, even while building.
    let hit = FileDigests::of_bytes(&pe_member());
    assert_eq!(
        index
            .lookup_with(&hit, &settings, None)
            .done()
            .unwrap()
            .len(),
        2
    );
    index.finish_build();
    assert_eq!(
        index.lookup_with(&absent, &settings, None),
        CatalogLookup::Done(Vec::new())
    );
}

#[test]
fn the_index_follows_catalogs_added_changed_and_removed() {
    let root = std::env::temp_dir().join(format!("palisade-cat-index-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("a.cat");
    std::fs::write(&path, fixture("v2-sha256.cat")).unwrap();
    let load = |p: &std::path::Path| {
        let mut b = CatalogStoreBuilder::new(StoreLimits::default())
            .trust(CatalogSource::System, anchors("ca.der"));
        b.add_file(CatalogSource::System, p);
        b.build()
    };
    let mut index = CatalogIndex::from_store(&load(&path));
    index.finish_build();
    let pe = FileDigests::of_bytes(&pe_member());
    assert_eq!(index.lookup(&pe).len(), 1);
    // The same catalog again: not added twice.
    assert_eq!(index.merge(&load(&path)), 0);
    // Changed: the v1 catalog replaces it at the same path.
    std::fs::write(&path, fixture("v1-sha1.cat")).unwrap();
    assert_eq!(index.remove_path(&path), 1);
    assert_eq!(index.merge(&load(&path)), 1);
    let now = index.lookup(&pe);
    assert_eq!(now.len(), 1);
    assert!(now[0].relies_on_sha1());
    // Removed.
    assert_eq!(index.remove_path(&path), 1);
    assert!(index.lookup(&pe).is_empty());
    assert_eq!(index.indexed_members(), 0);
    // A removed catalog is not written, and the round trip keeps working.
    let back = CatalogIndex::decode(&index.encode(&key()), &key()).unwrap();
    assert!(back.catalogs().is_empty());
    // The original can come back.
    std::fs::write(&path, fixture("v2-sha256.cat")).unwrap();
    assert_eq!(index.merge(&load(&path)), 1);
    assert_eq!(index.lookup(&pe).len(), 1);
    std::fs::remove_dir_all(&root).unwrap();
}

// --- Authoring --------------------------------------------------------------

fn sha256(data: &[u8]) -> Digest {
    hash_bytes(data, AlgorithmSet::SHA256)
        .get(HashAlgorithm::Sha256)
        .cloned()
        .unwrap()
}

#[test]
fn an_authored_catalog_reads_back_member_for_member() {
    let pe = FileDigests::of_bytes(&pe_member());
    let entries = vec![
        CatalogEntry::from_digests("tool.exe", &pe).unwrap(),
        CatalogEntry {
            kind: EntryKind::Flat,
            digest: sha256(FLAT_MEMBER),
            file_name: "readme.txt".into(),
        },
        // A duplicate, which is dropped.
        CatalogEntry::from_digests("copy-of-tool.exe", &pe).unwrap(),
    ];
    assert_eq!(entries[0].kind, EntryKind::PeImage);
    let ctl = build_catalog(&entries, "Example App 1.0", "2:10.0", 1_700_000_000).unwrap();
    assert_eq!(ctl.members, 2);
    let parsed = parse_ctl(&ctl.der).unwrap();
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    assert_eq!(parsed.this_update, 1_700_000_000);
    assert_eq!(parsed.os_attr(), Some("2:10.0"));
    assert_eq!(
        parsed.subject_algorithm,
        palisade_fileid::catalog::SubjectAlgorithm::CatalogListMemberV2
    );
    assert_eq!(parsed.members.len(), 2);
    for m in &parsed.members {
        let d = m.digest.as_ref().unwrap();
        assert!(m.tag.is_digest(&d.digest));
        assert_eq!(m.os_attr(), Some("2:10.0"));
        if d.is_pe_image() {
            assert_eq!(
                d.digest,
                pe.authenticode_sha256.as_ref().unwrap().as_bytes()
            );
        } else {
            assert_eq!(d.digest, sha256(FLAT_MEMBER).as_bytes());
            assert_eq!(m.file_name(), Some("readme.txt"));
        }
    }
    // Any order of the same files gives the same bytes.
    let forward = build_catalog(&entries[..2], "Example App 1.0", "2:10.0", 1_700_000_000).unwrap();
    let swapped = build_catalog(
        &[entries[1].clone(), entries[0].clone()],
        "Example App 1.0",
        "2:10.0",
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(forward, swapped);
    // A duplicate keeps its first recording's name.
    let dup_first = build_catalog(&[entries[2].clone(), entries[0].clone()], "n", "o", 0).unwrap();
    let parsed = parse_ctl(&dup_first.der).unwrap();
    assert_eq!(parsed.members[0].file_name(), Some("copy-of-tool.exe"));
}

#[test]
fn authoring_refuses_what_it_cannot_write_faithfully() {
    let good = CatalogEntry {
        kind: EntryKind::Flat,
        digest: sha256(b"x"),
        file_name: "x.txt".into(),
    };
    assert_eq!(
        build_catalog(&[], "n", "o", 0).unwrap_err(),
        AuthorError::Empty
    );
    let sha1 = CatalogEntry {
        digest: hash_bytes(b"x", AlgorithmSet::SHA1)
            .get(HashAlgorithm::Sha1)
            .cloned()
            .unwrap(),
        ..good.clone()
    };
    assert_eq!(
        build_catalog(&[good.clone(), sha1], "n", "o", 0).unwrap_err(),
        AuthorError::NotSha256 { entry: 1 }
    );
    for bad in ["", "a\u{0}b", "line\nbreak", &"x".repeat(2000)] {
        let e = CatalogEntry {
            file_name: bad.to_owned(),
            ..good.clone()
        };
        assert!(matches!(
            build_catalog(&[e], "n", "o", 0).unwrap_err(),
            AuthorError::BadText { entry: Some(0), .. }
        ));
        assert!(matches!(
            build_catalog(std::slice::from_ref(&good), bad, "o", 0).unwrap_err(),
            AuthorError::BadText { entry: None, .. }
        ));
    }
    let as_pe = CatalogEntry {
        kind: EntryKind::PeImage,
        ..good.clone()
    };
    assert_eq!(
        build_catalog(&[good, as_pe], "n", "o", 0).unwrap_err(),
        AuthorError::ConflictingKinds { entry: 1 }
    );
    // An empty file has no identity to list.
    assert!(CatalogEntry::from_digests("empty", &FileDigests::of_bytes(&[])).is_none());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn authored_catalogs_always_read_back(
        files in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 1..64), "[a-zA-Z0-9 ._-]{1,40}"),
            1..24,
        ),
    ) {
        let entries: Vec<CatalogEntry> = files
            .iter()
            .map(|(data, name)| CatalogEntry {
                kind: EntryKind::Flat,
                digest: sha256(data),
                file_name: name.clone(),
            })
            .collect();
        let ctl = build_catalog(&entries, "Prop", "2:10.0", 1_700_000_000).unwrap();
        let parsed = parse_ctl(&ctl.der).unwrap();
        prop_assert_eq!(parsed.members.len(), ctl.members);
        prop_assert!(parsed.warnings.is_empty());
        let mut digests: Vec<Vec<u8>> = entries.iter().map(|e| e.digest.as_bytes().to_vec()).collect();
        digests.sort();
        digests.dedup();
        let got: Vec<Vec<u8>> = parsed
            .members
            .iter()
            .map(|m| m.digest.as_ref().unwrap().digest.clone())
            .collect();
        prop_assert_eq!(got, digests);
    }

    #[test]
    fn mutated_indexes_never_decode_or_panic(at in any::<prop::sample::Index>(), flip in 1_u8..) {
        let bytes = CatalogIndex::from_store(&system_and_policy_store()).encode(&key());
        let mut bad = bytes.clone();
        let i = at.index(bad.len());
        bad[i] ^= flip;
        prop_assert!(CatalogIndex::decode(&bad, &key()).is_err());
    }

    #[test]
    fn resigned_garbage_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut data = b"PCI1".to_vec();
        data.push(palisade_fileid::catalog::INDEX_FORMAT);
        data.extend(body);
        let _ = CatalogIndex::decode(&resign(&data), &key());
    }
}

#[test]
fn the_encoded_index_costs_a_fixed_amount_per_member() {
    // An SHA-256 member costs 41 bytes on disk (digest, catalog, member,
    // kind): 4,194,304 of them (the default store limit) take about 172 MB,
    // inside the 200 MB on-disk budget (#51). Check the per-member cost by
    // loading one catalog under two member limits.
    let encoded = |max_members: usize| {
        let mut b = CatalogStoreBuilder::new(StoreLimits {
            max_members,
            ..StoreLimits::default()
        })
        .trust(CatalogSource::System, anchors("ca.der"));
        b.add_bytes(CatalogSource::System, None, &fixture("v2-sha256.cat"));
        let index = CatalogIndex::from_store(&b.build());
        (index.indexed_members(), index.encode(&key()).len())
    };
    let (one, one_len) = encoded(1);
    let (two, two_len) = encoded(2);
    assert_eq!((one, two), (1, 2));
    assert_eq!(two_len - one_len, 41);
}
