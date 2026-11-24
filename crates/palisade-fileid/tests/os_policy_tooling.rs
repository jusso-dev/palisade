//! Checks the Authenticode and page hash values against the OS code
//! integrity policy tooling (#47). Windows only.
//!
//! The test writes synthetic images to a temporary directory, runs
//! `tests/fixtures/page_hash/os-policy-hashes.ps1` over it (which calls the
//! OS policy cmdlets), and compares every hash rule the tooling emits with
//! [`authenticode_hashes`]: the SHA-1 and SHA-256 Authenticode hashes, and
//! the SHA-1 and SHA-256 "page hash" values. CI runs it on its Windows
//! runners. Where the cmdlets are not installed it says so and passes.

#![cfg(windows)]
// Test code: helpers may unwrap, since a failure should fail loudly.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use common::*;
use palisade_fileid::authenticode::authenticode_hashes;
use palisade_fileid::hash::AlgorithmSet;
use palisade_fileid::pe;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/page_hash/os-policy-hashes.ps1"
);
const PAGE_HASH_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/page_hash");

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn pkcs7_entry(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

/// The images checked, by file name.
fn images() -> Vec<(&'static str, Vec<u8>)> {
    let multi = PeBuilder::default()
        .section(".data", pattern(9000, 7), IMAGE_SCN_CNT_INITIALIZED_DATA)
        .section(".bss", Vec::new(), IMAGE_SCN_CNT_INITIALIZED_DATA)
        .section(".tls", pattern(100, 3), IMAGE_SCN_CNT_INITIALIZED_DATA);
    let signature = std::fs::read(format!("{PAGE_HASH_FIXTURES}/multi-sha256.p7")).unwrap();
    vec![
        ("palisade-default.exe", PeBuilder::default().build()),
        ("palisade-dll.dll", PeBuilder::dll().build()),
        (
            "palisade-pe32.exe",
            PeBuilder::pe32()
                .section(".data", pattern(8192, 1), IMAGE_SCN_CNT_INITIALIZED_DATA)
                .build(),
        ),
        // An unsigned image whose length is not a multiple of 8: the
        // Authenticode hash includes the signer's zero padding.
        (
            "palisade-odd.exe",
            PeBuilder {
                overlay: vec![0xaa, 0xbb, 0xcc],
                ..PeBuilder::default()
            }
            .build(),
        ),
        // The multi-section image, signed with page hashes: the certificate
        // table and its directory entry must not change any value.
        (
            "palisade-signed.exe",
            PeBuilder {
                certificate: Some(pkcs7_entry(&signature)),
                ..multi
            }
            .build(),
        ),
    ]
}

/// Which value a rule's friendly name ends with.
const KINDS: [&str; 4] = [
    " Hash Page Sha256",
    " Hash Page Sha1",
    " Hash Sha256",
    " Hash Sha1",
];

#[test]
fn hashes_match_os_policy_tooling() {
    let dir = std::env::temp_dir().join(format!("palisade-os-tooling-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut expected: BTreeMap<(String, &str), String> = BTreeMap::new();
    for (name, image) in images() {
        std::fs::write(dir.join(name), &image).unwrap();
        let info = pe::parse(&image).unwrap();
        let hashes = authenticode_hashes(&image, &info, AlgorithmSet::EMPTY).unwrap();
        assert!(hashes.status.is_conformant(), "{name}");
        let values = [
            hashes.page_sha256().unwrap().to_string(),
            hashes.page_sha1().unwrap().to_string(),
            hashes.sha256().unwrap().to_string(),
            hashes.sha1().unwrap().to_string(),
        ];
        for (kind, value) in KINDS.iter().zip(values) {
            expected.insert((name.to_owned(), kind), value);
        }
    }

    let out: PathBuf = dir.join("rules.txt");
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            SCRIPT,
        ])
        .arg("-Dir")
        .arg(&dir)
        .arg("-Out")
        .arg(&out)
        .status()
        .unwrap();
    if status.code() == Some(3) {
        eprintln!("skipped: the OS code integrity policy cmdlets are not installed here");
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    assert!(status.success(), "{status}");

    let rules = std::fs::read_to_string(&out).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    // Every rule for one of our files must carry our value. The tooling
    // emits rules for user and kernel mode, and may merge rules whose hash
    // is the same (two images here share a header page), so each value is
    // also checked as a set per kind.
    let mut seen_values: BTreeSet<(&str, String)> = BTreeSet::new();
    for line in rules.lines().filter(|l| !l.trim().is_empty()) {
        let (friendly, hash) = line.split_once('\t').unwrap();
        let hash = hash.trim().to_ascii_lowercase();
        let Some(kind) = KINDS.iter().find(|k| friendly.ends_with(*k)) else {
            continue;
        };
        if let Some(name) = expected
            .keys()
            .map(|(n, _)| n)
            .find(|n| friendly.contains(n.as_str()))
        {
            assert_eq!(
                expected[&(name.clone(), *kind)],
                hash,
                "{friendly}; tooling output:\n{rules}"
            );
        }
        seen_values.insert((kind, hash));
    }
    let wanted: BTreeSet<(&str, String)> = expected
        .iter()
        .map(|((_, kind), value)| (*kind, value.clone()))
        .collect();
    assert!(
        wanted.is_subset(&seen_values),
        "missing from the tooling output: {:?}\n{rules}",
        wanted.difference(&seen_values).collect::<Vec<_>>()
    );
}
