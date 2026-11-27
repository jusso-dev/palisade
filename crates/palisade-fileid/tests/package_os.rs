//! Checks app package identity and signatures against the OS (#53).
//! Windows only.
//!
//! [`identity_and_signatures_match_the_os`] runs
//! `tests/fixtures/package/os-package-identity.ps1`, which asks the OS
//! package identity API for the family name of a package from each
//! publisher in `os_publisher_ids.txt` and `publisher_ids.txt`, and the OS
//! signature check for the signed fixtures and tampered copies. It compares the OS family names
//! with [`publisher_id`], and the OS verdicts with
//! [`PackageIdentity::signature_valid`]. The script also asks the OS about
//! each package by other routes (`DIAG` lines: with a file handle, the
//! subject type the OS assigns, the OS packaging API's reader, and the
//! signature cmdlet); a failure prints them all.
//!
//! [`sdk_packages_match_the_os`] has the OS SDK's own packaging and signing
//! tools build and sign a package and a bundle
//! (`os-sdk-package.ps1`), then requires this crate and the OS to agree
//! on them, intact and with one byte changed.
//!
//! CI runs both on its Windows runners, where the APIs and the SDK are
//! present: under CI a missing component fails the test. On a developer
//! machine without them it says so and passes.

#![cfg(windows)]
#![allow(clippy::unwrap_used)]

#[path = "common/appx.rs"]
mod appx;
mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use palisade_fileid::package::zip::Archive;
use palisade_fileid::package::{
    PackageIdentity, PackageVersion, full_name, parse_package, publisher_id,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/package");

/// The OS result codes of a signature it found intact: success, or a chain
/// error (the test roots are not trusted here: an untrusted root, a chain
/// it cannot build). Any other code is a broken or unverifiable package.
const INTACT: [u32; 3] = [0, 0x800b_0109, 0x800b_010a];

/// A scratch directory, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("palisade-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs a script under Windows PowerShell; `false` when it reports (exit 3)
/// that a component it needs is missing, which fails the test under CI.
fn powershell(script: &str, args: &[(&str, &Path)]) -> bool {
    let mut cmd = Command::new("powershell.exe");
    // A parent PowerShell 7 (as on CI runners) leaves its module path in
    // the environment, which stops Windows PowerShell loading its own
    // modules; let it use its default.
    cmd.env_remove("PSModulePath");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
    ]);
    cmd.arg(format!("{FIXTURES}/{script}"));
    for (name, value) in args {
        cmd.arg(name).arg(value);
    }
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.code() == Some(3) {
        assert!(
            std::env::var_os("CI").is_none(),
            "{script}: a component it needs is missing on this CI runner: {text}"
        );
        eprintln!("skipped: {script}: {text}");
        return false;
    }
    assert!(out.status.success(), "{script}: {}\n{text}", out.status);
    true
}

/// The OS's answers from `os-package-identity.ps1`, by kind.
#[derive(Default)]
struct OsAnswers {
    text: String,
    pfn: Vec<(String, String)>,
    full: Vec<(String, String)>,
    sig: BTreeMap<String, u32>,
}

impl OsAnswers {
    fn code(&self, name: &str) -> u32 {
        *self
            .sig
            .get(name)
            .unwrap_or_else(|| panic!("no OS result for {name}:\n{}", self.text))
    }
}

/// Writes `files` to a scratch directory and asks the OS about them (and
/// the family names of `publishers`). `None` if the OS APIs are missing.
fn ask_os(publishers: &[&str], files: &[(String, Vec<u8>)]) -> Option<OsAnswers> {
    let dir = Scratch::new("os-package");
    let list = dir.0.join("publishers.txt");
    std::fs::write(&list, publishers.join("\n")).unwrap();
    for (name, data) in files {
        std::fs::write(dir.0.join(name), data).unwrap();
    }
    let out = dir.0.join("os.txt");
    if !powershell(
        "os-package-identity.ps1",
        &[("-Publishers", &list), ("-Dir", &dir.0), ("-Out", &out)],
    ) {
        return None;
    }
    let text = std::fs::read_to_string(&out).unwrap();
    let text = text.trim_start_matches('\u{feff}').to_owned();
    let mut answers = OsAnswers::default();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.splitn(3, '\t');
        let (Some(kind), Some(key), Some(value)) = (parts.next(), parts.next(), parts.next())
        else {
            panic!("bad line {line:?}");
        };
        let (key, value) = (key.to_owned(), value.trim_end().to_owned());
        match kind {
            "PFN" => answers.pfn.push((key, value)),
            "FULL" => answers.full.push((key, value)),
            "SIG" => {
                let code =
                    u32::from_str_radix(&value, 16).unwrap_or_else(|_| panic!("bad line {line:?}"));
                answers.sig.insert(key, code);
            }
            "DIAG" => {}
            _ => panic!("bad line {line:?}"),
        }
    }
    answers.text = text;
    Some(answers)
}

/// A copy of `data` with one byte of the first occurrence of `needle`
/// changed.
fn tamper(data: &[u8], needle: &[u8]) -> Vec<u8> {
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    let mut out = data.to_vec();
    out[at] ^= 1;
    out
}

#[test]
fn identity_and_signatures_match_the_os() {
    // The OS-reported publishers, then the independent vectors.
    let mut vectors = std::fs::read_to_string(format!("{FIXTURES}/os_publisher_ids.txt")).unwrap();
    vectors.push_str(&std::fs::read_to_string(format!("{FIXTURES}/publisher_ids.txt")).unwrap());
    let publishers: Vec<&str> = vectors
        .lines()
        .filter_map(|l| l.split_once('\t').map(|(p, _)| p))
        .collect();

    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for name in [
        "app-signed.msix",
        "app-zip64.msix",
        "bundle-signed.msixbundle",
        "other-publisher.msix",
    ] {
        files.push((
            name.into(),
            std::fs::read(format!("{FIXTURES}/{name}")).unwrap(),
        ));
    }
    // A signed package with one byte of a stored file changed.
    files.push((
        "tampered.msix".into(),
        tamper(&files[0].1, b"synthetic tool"),
    ));
    let ours: BTreeMap<String, PackageIdentity> = files
        .iter()
        .map(|(name, data)| (name.clone(), parse_package(data).unwrap()))
        .collect();

    let Some(os) = ask_os(&publishers, &files) else {
        return;
    };
    let text = &os.text;
    assert_eq!(os.pfn.len(), publishers.len(), "{text}");
    for (publisher, family) in &os.pfn {
        assert_eq!(
            family,
            &format!("Palisade.Probe_{}", publisher_id(publisher)),
            "publisher {publisher:?}"
        );
    }
    assert_eq!(os.full.len(), 2, "{text}");
    let pid = publisher_id(publishers[0]);
    let v = PackageVersion(1, 2, 3, 4);
    for (key, value) in &os.full {
        let want = match key.as_str() {
            "x64" => full_name("Palisade.Probe", v, "x64", "", &pid),
            // A bundle: neutral, resource ID `~`, as parse_package reports
            // for bundles.
            _ => full_name("Palisade.Probe", v, "", "~", &pid),
        };
        assert_eq!(value, &want, "{key}");
    }
    // Whether this API also compares the signer with the manifest's
    // publisher is not documented, so for the other-publisher package only
    // our verdict (invalid) is asserted; its OS code is still required.
    for (name, id) in &ours {
        let code = os.code(name);
        if name == "other-publisher.msix" {
            assert!(!id.signature_valid());
            continue;
        }
        assert_eq!(
            id.signature_valid(),
            INTACT.contains(&code),
            "{name}: OS {code:#010x}\n{text}"
        );
    }
}

#[test]
fn sdk_packages_match_the_os() {
    let dir = Scratch::new("os-sdk-package");
    let layout = dir.0.join("layout");
    std::fs::create_dir_all(layout.join("assets")).unwrap();
    std::fs::write(
        layout.join("AppxManifest.xml"),
        appx::sdk_manifest("Palisade.SdkProbe", "__PUBLISHER__", "1.2.3.4", "x64"),
    )
    .unwrap();
    // A stored file (the PNG), and one big enough to be deflated in more
    // than one 64 KiB block.
    std::fs::write(layout.join("logo.png"), appx::PNG).unwrap();
    std::fs::write(
        layout.join("tool.exe"),
        common::PeBuilder::default().build(),
    )
    .unwrap();
    let big: Vec<u8> = (0..150_000_u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(layout.join("assets").join("big.bin"), &big).unwrap();
    let out = dir.0.join("out");
    std::fs::create_dir_all(&out).unwrap();
    if !powershell(
        "os-sdk-package.ps1",
        &[("-Layout", &layout), ("-Out", &out)],
    ) {
        return;
    }
    let tools = std::fs::read_to_string(out.join("sdk.txt")).unwrap();
    let app = std::fs::read(out.join("sdk-app.msix")).unwrap();
    let bundle = std::fs::read(out.join("sdk-bundle.msixbundle")).unwrap();

    // One byte changed: of the stored PNG, of the deflated file, of the
    // bundle's payload package (which the tool puts first). Found without
    // this crate's reader, so the OS is asked even if it refuses them.
    let mut deflated = app.clone();
    deflated[local_data(&app, "assets/big.bin") + 100] ^= 0x10;
    let mut payload = bundle.clone();
    payload[local_data(&bundle, "sdk-app_x64.msix") + 200] ^= 1;
    let files: Vec<(String, Vec<u8>)> = vec![
        ("sdk-app.msix".into(), app.clone()),
        ("sdk-bundle.msixbundle".into(), bundle.clone()),
        ("sdk-stored.msix".into(), tamper(&app, b"IDAT")),
        ("sdk-deflated.msix".into(), deflated),
        ("sdk-payload.msixbundle".into(), payload),
    ];
    let Some(os) = ask_os(&[], &files) else {
        return;
    };
    let text = format!("{tools}\n{}", os.text);
    for (name, data) in &files {
        let code = os.code(name);
        let intact = name == "sdk-app.msix" || name == "sdk-bundle.msixbundle";
        // The OS must recognise the SDK's own packages as intact; if it
        // does not, agreeing that both are rejected would prove nothing.
        assert_eq!(
            INTACT.contains(&code),
            intact,
            "{name}: OS {code:#010x}\n{text}"
        );
        let ours = parse_package(data).map(|id| {
            let why = id.signature.as_ref().map(|s| {
                (
                    s.issue.clone(),
                    s.report.signatures.first().map(|x| x.status.clone()),
                )
            });
            (id.signature_valid(), why)
        });
        assert_eq!(
            ours.as_ref().is_ok_and(|(valid, _)| *valid),
            intact,
            "{name}: ours {ours:?}, OS {code:#010x}\n{text}"
        );
    }
    let id = parse_package(&app).unwrap();
    assert_eq!(id.name, "Palisade.SdkProbe");
    assert!(parse_package(&bundle).unwrap().is_bundle);
    // The archive shape the tool wrote, for the record.
    let a = Archive::parse(&app).unwrap();
    eprintln!(
        "sdk-app.msix: zip64 {}, members {}, ZIP64 extra fields {}",
        a.zip64,
        a.members.len(),
        a.members.iter().filter(|m| m.has_zip64_extra).count()
    );
}

/// Where the data of the member called `name` starts, from its local
/// header alone.
fn local_data(data: &[u8], name: &str) -> usize {
    let name = name.as_bytes();
    let at = (30..data.len())
        .find(|&i| {
            data[i..].starts_with(name)
                && data[i - 30..i - 26] == [0x50, 0x4b, 0x03, 0x04]
                && usize::from(u16::from_le_bytes([data[i - 4], data[i - 3]])) == name.len()
        })
        .unwrap_or_else(|| panic!("no local header for {}", String::from_utf8_lossy(name)));
    at + name.len() + usize::from(u16::from_le_bytes([data[at - 2], data[at - 1]]))
}
