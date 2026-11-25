//! Checks app package identity against the OS (#53). Windows only.
//!
//! The test runs `tests/fixtures/package/os-package-identity.ps1`, which
//! asks the OS package identity API for the family name of a package from
//! each publisher in `publisher_ids.txt`, and the OS signature check for
//! the signed fixtures and tampered copies. It compares the OS family names
//! with [`publisher_id`], and the OS verdicts with
//! [`PackageIdentity::signature_valid`]. CI runs it on its Windows runners,
//! where both are always present: under CI a missing component fails the
//! test. On a developer machine without them it says so and passes.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::process::Command;

use palisade_fileid::package::{PackageIdentity, parse_package, publisher_id};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/package");
const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/package/os-package-identity.ps1"
);

#[test]
fn identity_and_signatures_match_the_os() {
    let dir = std::env::temp_dir().join(format!("palisade-os-package-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let vectors = std::fs::read_to_string(format!("{FIXTURES}/publisher_ids.txt")).unwrap();
    let publishers: Vec<&str> = vectors
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(p, _)| p))
        .collect();
    let list = dir.join("publishers.txt");
    std::fs::write(&list, publishers.join("\n")).unwrap();

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for name in [
        "app-signed.msix",
        "bundle-signed.msixbundle",
        "other-publisher.msix",
    ] {
        files.push((
            name.into(),
            std::fs::read(format!("{FIXTURES}/{name}")).unwrap(),
        ));
    }
    // A signed package with one byte of a stored file changed.
    let mut tampered = files[0].1.clone();
    let needle = b"synthetic tool";
    let at = tampered
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    tampered[at] ^= 1;
    files.push(("tampered.msix".into(), tampered));
    let mut ours: BTreeMap<String, PackageIdentity> = BTreeMap::new();
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
        ours.insert(name.clone(), parse_package(data).unwrap());
    }

    let out = dir.join("os.txt");
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            SCRIPT,
        ])
        .arg("-Publishers")
        .arg(&list)
        .arg("-Dir")
        .arg(&dir)
        .arg("-Out")
        .arg(&out)
        .status()
        .unwrap();
    if status.code() == Some(3) {
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            std::env::var_os("CI").is_none(),
            "the OS package identity API is missing on this CI runner"
        );
        eprintln!("skipped: the OS package identity API is not available here");
        return;
    }
    assert!(status.success(), "{status}");
    let text = std::fs::read_to_string(&out).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let text = text.trim_start_matches('\u{feff}');

    let mut pfns = 0;
    let mut sigs: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, '\t');
        let (Some(kind), Some(key), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("bad line {line:?}");
        };
        let value = value.trim_end();
        match kind {
            "PFN" => {
                assert_eq!(
                    value,
                    format!("Palisade.Probe_{}", publisher_id(key)),
                    "publisher {key:?}"
                );
                pfns += 1;
            }
            "SIG" => {
                sigs.insert(key.into(), value.into());
            }
            _ => panic!("bad line {line:?}"),
        }
    }
    assert_eq!(pfns, publishers.len(), "{text}");
    // The test root is not trusted here, so a signature the OS finds intact
    // reports success or a chain error (an untrusted root, a chain it
    // cannot build); any other code is a broken or unverifiable package.
    // Whether this API also compares the signer with the manifest's
    // publisher is not documented, so for the other-publisher package only
    // our verdict (invalid) is asserted; its OS code is still required.
    let intact_codes = [0_u32, 0x800b_0109, 0x800b_010a];
    for (name, id) in &ours {
        let code = sigs
            .get(name)
            .and_then(|c| u32::from_str_radix(c, 16).ok())
            .unwrap_or_else(|| panic!("{name}: {text}"));
        if name == "other-publisher.msix" {
            assert!(!id.signature_valid());
            continue;
        }
        assert_eq!(
            id.signature_valid(),
            intact_codes.contains(&code),
            "{name}: OS {code:#010x}\n{text}"
        );
    }
}
