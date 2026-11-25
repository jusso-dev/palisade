//! Catalog-signed OS files on a real Windows install (#51). Windows only.
//!
//! The test loads the OS catalog store (`System32\catroot`) into a
//! [`CatalogStore`], builds the persistent index from it, and checks that
//! the PE files in `System32` that carry **no embedded signature** are
//! listed by a catalog whose signature verifies. It prints what it measured
//! (catalogs, members, load time, index size), so the acceptance figures
//! on a stock image can be read off a CI log.
//!
//! The OS trust store is not consulted, so nothing here is *trusted*: this
//! checks parsing, signature verification and lookup against what the OS
//! itself ships. CI runs it on its Windows runners, where the catalog store
//! must exist: under CI (`CI` is set) a missing store fails the test. On a
//! machine without one it says so and passes.

#![cfg(windows)]
#![allow(clippy::unwrap_used, clippy::cast_precision_loss)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use palisade_fileid::authenticode::{SigningState, VerifyOptions, verify_pe};
use palisade_fileid::catalog::{
    CatalogIndex, CatalogSource, CatalogStatus, CatalogStoreBuilder, FileDigests, StoreLimits,
};
use palisade_fileid::hash::MacKey;

fn system32() -> PathBuf {
    let root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32")
}

/// Up to `max` PE files directly in `dir`, in name order.
fn pe_files(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("exe") || x.eq_ignore_ascii_case("dll"))
        })
        .collect();
    files.sort();
    files.truncate(max);
    files
}

#[test]
fn system32_files_without_embedded_signatures_resolve_to_catalogs() {
    let catroot = system32().join("catroot");
    if !catroot.is_dir() {
        assert!(
            std::env::var_os("CI").is_none(),
            "no OS catalog store at {} on this CI runner",
            catroot.display()
        );
        eprintln!("skipped: no OS catalog store here");
        return;
    }

    let start = Instant::now();
    let mut builder = CatalogStoreBuilder::new(StoreLimits::default());
    let report = builder.add_dir(CatalogSource::System, &catroot);
    let store = builder.build();
    let load = start.elapsed();
    let valid = store
        .records()
        .iter()
        .filter(|r| r.status == CatalogStatus::Valid)
        .count();
    let start = Instant::now();
    let index = CatalogIndex::from_store(&store);
    let encoded = index.encode(&MacKey::new(&[1; 32]).unwrap());
    let build = start.elapsed();
    eprintln!(
        "catroot: {} catalogs ({} valid, {} errors), {} members indexed, loaded in {:.1}s; \
         index {} bytes, built and encoded in {:.1}s",
        store.records().len(),
        valid,
        report.errors.len(),
        store.indexed_members(),
        load.as_secs_f64(),
        encoded.len(),
        build.as_secs_f64(),
    );
    assert!(
        valid > 0,
        "no catalog in {} verified: {report:?}",
        catroot.display()
    );
    // Most OS catalogs must parse and verify; any that do not are listed.
    let unusable: Vec<String> = store
        .records()
        .iter()
        .filter(|r| r.status != CatalogStatus::Valid)
        .take(20)
        .map(|r| format!("{:?}: {:?}", r.path, r.status))
        .collect();
    let share = valid as f64 / store.records().len().max(1) as f64;
    assert!(
        share >= 0.99,
        "only {share:.4} of OS catalogs verify; e.g. {unusable:#?}"
    );

    // System32 PE files with no embedded signature.
    let mut candidates = 0_usize;
    let mut resolved = 0_usize;
    let mut missing = Vec::new();
    for path in pe_files(&system32(), 400) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(report) = verify_pe(&bytes, &VerifyOptions::default()) else {
            continue;
        };
        if report.signing_state != SigningState::Unsigned {
            continue;
        }
        candidates += 1;
        let found = store
            .lookup(&FileDigests::of_bytes(&bytes))
            .matches
            .iter()
            .any(|m| m.record.status == CatalogStatus::Valid);
        if found {
            resolved += 1;
        } else if missing.len() < 20 {
            missing.push(path.display().to_string());
        }
    }
    eprintln!("System32: {resolved} of {candidates} files without embedded signatures resolved");
    assert!(
        candidates >= 5,
        "too few unsigned System32 PE files to judge ({candidates})"
    );
    let share = resolved as f64 / candidates as f64;
    assert!(
        share >= 0.99,
        "only {resolved} of {candidates} resolved to a catalog; e.g. {missing:#?}"
    );
    // The index answers the same.
    for path in pe_files(&system32(), 20) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let digests = FileDigests::of_bytes(&bytes);
        let a: Vec<usize> = store
            .lookup(&digests)
            .matches
            .iter()
            .map(|m| m.catalog)
            .collect();
        let b: Vec<usize> = index.lookup(&digests).iter().map(|m| m.catalog).collect();
        assert_eq!(a, b, "{}", path.display());
    }
}
