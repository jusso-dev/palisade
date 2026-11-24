//! Checks installer package identity against the OS installer API (#53).
//! Windows only.
//!
//! The test writes the builder's test product (unsigned, and the signed
//! fixtures, plus a tampered copy) to a temporary directory, runs
//! `tests/fixtures/installer/os-installer-properties.ps1` over it (which
//! opens each package with the OS installer automation object and checks
//! its signature with the OS), and compares ProductCode, UpgradeCode,
//! ProductName, ProductVersion, Manufacturer, ProductLanguage, the
//! PackageCode and the template with [`parse_installer`], and whether the
//! OS finds each signature's content hash intact with
//! [`InstallerIdentity::signature_valid`]. CI runs it on its Windows
//! runners, where the API is always present: under CI a missing API fails
//! the test. On a developer machine without it it says so and passes.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::process::Command;

use palisade_fileid::installer::{InstallerIdentity, parse_installer};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/installer");
const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/installer/os-installer-properties.ps1"
);
const SIGN_SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/installer/os-sign-installer.ps1"
);

/// Runs a PowerShell script; `None` when it reports (exit 3) that what it
/// needs is missing.
fn powershell(script: &str, args: &[(&str, &std::path::Path)]) -> Option<()> {
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script,
    ]);
    for (name, value) in args {
        cmd.arg(name).arg(value);
    }
    let status = cmd.status().unwrap();
    if status.code() == Some(3) {
        assert!(
            std::env::var_os("CI").is_none(),
            "{script} found the OS component it needs missing on this CI runner"
        );
        eprintln!("skipped: {script} reports a missing OS component");
        return None;
    }
    assert!(status.success(), "{script}: {status}");
    Some(())
}

fn ours(id: &InstallerIdentity) -> BTreeMap<&'static str, String> {
    let p = &id.properties;
    let mut m = BTreeMap::new();
    let mut put = |k, v: Option<&str>| {
        if let Some(v) = v {
            m.insert(k, v.to_owned());
        }
    };
    put(
        "ProductCode",
        p.product_code.as_ref().map(|g| g.text.as_str()),
    );
    put(
        "UpgradeCode",
        p.upgrade_code.as_ref().map(|g| g.text.as_str()),
    );
    put("ProductName", p.product_name.as_deref());
    put("ProductVersion", p.product_version_text.as_deref());
    put("Manufacturer", p.manufacturer.as_deref());
    put("ProductLanguage", p.product_language.as_deref());
    put("PID7", id.summary.template.as_deref());
    put("PID9", id.summary.revision.as_deref());
    m
}

#[test]
fn identity_matches_the_os_installer_api() {
    let dir = std::env::temp_dir().join(format!("palisade-os-installer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for name in ["product-sha256.msi", "product-sha1.msi", "product-dse.msi"] {
        files.push((
            name.into(),
            std::fs::read(format!("{FIXTURES}/{name}")).unwrap(),
        ));
    }
    // A signed package with one byte of a stream changed.
    let signed = files[0].1.clone();
    let needle = b"synthetic cabinet";
    let at = signed
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut tampered = signed;
    tampered[at] ^= 0x20;
    files.push(("tampered.msi".into(), tampered));

    let mut expected: BTreeMap<String, (BTreeMap<&str, String>, bool)> = BTreeMap::new();
    for (name, data) in &files {
        std::fs::write(dir.join(name), data).unwrap();
        let id = parse_installer(data).unwrap();
        expected.insert(name.clone(), (ours(&id), id.signature_valid()));
    }

    let out = dir.join("os.txt");
    if powershell(SCRIPT, &[("-Dir", &dir), ("-Out", &out)]).is_none() {
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let text = std::fs::read_to_string(&out).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let text = text.trim_start_matches('\u{feff}');

    let mut os: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, '\t');
        let (Some(file), Some(field), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("bad line {line:?}");
        };
        os.entry(file.into())
            .or_default()
            .insert(field.into(), value.trim_end().into());
    }
    for (name, (fields, valid)) in &expected {
        let theirs = os
            .get(name)
            .unwrap_or_else(|| panic!("{name} missing:\n{text}"));
        for (field, value) in fields {
            assert_eq!(theirs.get(*field), Some(value), "{name} {field}:\n{text}");
        }
        // The OS reports UnknownError (untrusted test root) when the hash
        // verifies, and HashMismatch when it does not.
        let os_status = theirs.get("Signature").map(String::as_str);
        assert_eq!(
            *valid,
            os_status != Some("HashMismatch"),
            "{name}: ours {valid}, OS {os_status:?}\n{text}"
        );
        assert!(os_status.is_some(), "{name} is signed:\n{text}");
    }
}

#[test]
fn verifies_a_signature_the_os_made() {
    let dir = std::env::temp_dir().join(format!("palisade-os-sign-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The unsigned test product: the signed fixtures with the signature
    // removed is exactly the builder output `generate.sh` signs.
    let unsigned = dir.join("unsigned.msi");
    let signed = dir.join("os-signed.msi");
    std::fs::write(&unsigned, unsigned_product()).unwrap();
    if powershell(SIGN_SCRIPT, &[("-In", &unsigned), ("-Out", &signed)]).is_none() {
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let data = std::fs::read(&signed).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let id = parse_installer(&data).unwrap();
    let report = id
        .signature
        .as_ref()
        .expect("the OS wrote a signature stream");
    let sig = &report.signatures[0];
    assert_eq!(
        sig.status,
        palisade_fileid::authenticode::SignatureStatus::Valid,
        "{sig:?}"
    );
    assert!(id.signature_valid());
    let before = parse_installer(&unsigned_product()).unwrap();
    assert_eq!(id.normalised_sha256, before.normalised_sha256);
    assert_eq!(id.content_sha256, before.content_sha256);

    // One byte changed after the OS signed it.
    let needle = b"synthetic cabinet";
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut bad = data;
    bad[at] ^= 0x20;
    assert!(!parse_installer(&bad).unwrap().signature_valid());
}

/// The test product, unsigned, as `tests/installer.rs` builds it.
fn unsigned_product() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/installer/product.msi"
    ))
    .unwrap()
}
