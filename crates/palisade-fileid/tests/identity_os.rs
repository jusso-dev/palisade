//! Differential test of the file identity record against OS tooling (#55),
//! over OS binaries read in place. Windows only.
//!
//! `fixtures/identity/os-reference.ps1` asks the OS for each file's SHA-256, its
//! signature status, type and signer, and its version resource, and this
//! test compares those with [`identify`]. Nothing is copied: the files are
//! the runner's own. The OS trusts its own root store, while this test
//! trusts nothing, so the comparison is of what both can see:
//!
//! - the flat SHA-256, `OriginalFilename`, `CompanyName` and the fixed file
//!   version are equal;
//! - a file the OS reports as embedded-signed has a cryptographically valid
//!   embedded signature here, with the same signer certificate;
//! - a file the OS reports as catalog-signed has no embedded signature here
//!   (its catalog is found when the OS catalog root is given, which the
//!   corpus test does not depend on).

#![cfg(windows)]
// Test code: a failure should fail loudly.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::Path;
use std::process::Command;

use palisade_fileid::identity::{EmbeddedState, IdentityContext, Tiers, identify};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/identity/os-reference.ps1"
);

/// OS files present on every supported Windows version.
const FILES: &[&str] = &[
    r"System32\notepad.exe",
    r"System32\cmd.exe",
    r"System32\kernel32.dll",
    r"System32\ntdll.dll",
    r"System32\WindowsPowerShell\v1.0\powershell.exe",
    r"System32\drivers\null.sys",
    r"explorer.exe",
];

#[test]
fn identity_matches_os_tooling() {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let paths: Vec<String> = FILES
        .iter()
        .map(|f| format!(r"{windir}\{f}"))
        .filter(|p| Path::new(p).is_file())
        .collect();
    assert!(paths.len() >= 4, "too few OS files found: {paths:?}");
    let out = std::env::temp_dir().join(format!("palisade-os-ref-{}.txt", std::process::id()));
    // A parent PowerShell 7 (as on CI runners) leaves its module path in
    // the environment, which stops Windows PowerShell loading its own
    // built-in modules (`Get-FileHash`); let it use its default.
    let status = Command::new("powershell.exe")
        .env_remove("PSModulePath")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            SCRIPT,
            "-Out",
        ])
        .arg(&out)
        .args(&paths)
        .status()
        .unwrap();
    assert!(status.success(), "{status}");
    let text = std::fs::read_to_string(&out).unwrap();
    std::fs::remove_file(&out).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "the OS checks these files at the real time, so this test does too"
    )]
    let now = std::time::SystemTime::now();
    let ctx = IdentityContext::untrusted(
        i64::try_from(now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap(),
    );
    let mut checked = 0;
    for line in text
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}'))
        .filter(|l| !l.is_empty())
    {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 8, "{line}");
        let (path, sha256, status, kind, thumb, original, version, company) =
            (f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
        let id = identify(Path::new(path), Tiers::EXECUTION, &ctx).unwrap();
        let h = id.hashes.computed().unwrap();
        assert_eq!(h.sha256.as_deref(), Some(sha256), "{path}");
        let v = id.version();
        assert_eq!(
            v.and_then(|v| v.original_file_name.as_deref())
                .unwrap_or(""),
            original,
            "{path}"
        );
        assert_eq!(
            v.and_then(|v| v.company_name.as_deref()).unwrap_or(""),
            company,
            "{path}"
        );
        if let Some(q) = v.and_then(|v| v.file_version_quad.as_deref()) {
            assert_eq!(q, version, "{path}");
        }
        let state = id.signing_state.computed().unwrap();
        let sigs = id.signatures.computed().unwrap();
        if status == "Valid" && kind == "Authenticode" {
            assert_eq!(state.embedded, EmbeddedState::Valid, "{path}");
            let leaf = sigs
                .iter()
                .filter(|s| s.status == "valid")
                .filter_map(|s| s.chain.as_ref()?.leaf.as_ref())
                .map(|c| c.sha1_thumbprint.as_str())
                .collect::<Vec<_>>();
            assert!(leaf.contains(&thumb), "{path}: {leaf:?} vs {thumb}");
        } else if status == "Valid" && kind == "Catalog" {
            assert_eq!(state.embedded, EmbeddedState::Unsigned, "{path}");
        }
        assert!(h.authenticode.computed().unwrap().conformant, "{path}");
        assert_eq!(id.masquerade.score, 0, "{path}: {:?}", id.masquerade);
        checked += 1;
    }
    assert_eq!(checked, paths.len());
}
