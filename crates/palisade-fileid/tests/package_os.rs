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
//! [`the_os_signer_computes_our_digest`] has the OS SDK's signing tool sign
//! packages this crate's test builder lays out in each archive shape, and
//! requires the digest that tool signs to equal [`signed_digest`] tag by
//! tag, and the OS's verdict to equal ours.
//!
//! CI runs them on its Windows runners, where the APIs and the SDK are
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

use appx::{AppxBuilder, PUBLISHER, ZipStyle, sdk_manifest};
use palisade_fileid::authenticode::DigestAlgorithm;
use palisade_fileid::package::manifest::ns::{DESKTOP, UAP3};
use palisade_fileid::package::zip::Archive;
use palisade_fileid::package::{
    PackageIdentity, PackageVersion, full_name, parse_package, publisher_id, signed_digest,
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
        "app-desc.msix",
        "app-classic.msix",
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

/// The tagged digest entries (`AXPC`, `AXCD`, ...) of a package signature:
/// the indirect data's digest, found by its `APPX` prefix.
fn signature_digest(p7x: &[u8], len: usize) -> Option<Vec<([u8; 4], Vec<u8>)>> {
    let at = p7x.windows(8).position(|w| w == b"APPXAXPC")? + 4;
    let mut out = Vec::new();
    let mut rest = &p7x[at..];
    while rest.len() >= 4 + len
        && [b"AXPC", b"AXCD", b"AXCT", b"AXBM", b"AXCI"]
            .iter()
            .any(|t| rest[..4] == t[..])
    {
        out.push((rest[..4].try_into().unwrap(), rest[4..4 + len].to_vec()));
        rest = &rest[4 + len..];
    }
    Some(out)
}

/// `[tag, digest]` pairs of [`signed_digest`].
fn our_digest(archive: &Archive<'_>) -> Vec<([u8; 4], Vec<u8>)> {
    signed_digest(archive, DigestAlgorithm::Sha256)
        .map(|d| {
            d[4..]
                .chunks(36)
                .map(|c| (c[..4].try_into().unwrap(), c[4..].to_vec()))
                .collect()
        })
        .unwrap_or_default()
}

fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_os_signer_computes_our_digest() {
    // The SDK probe's files and manifest (which the OS packaging tool
    // accepts), with the test identity, laid out by the test builder.
    let mut b = AppxBuilder::package();
    b.files[0].data = sdk_manifest("Palisade.TestApp", PUBLISHER, "1.2.3.4", "x64").into_bytes();
    b.files[1].name = "tool.exe".into();
    b.files[1].data = common::PeBuilder::default().build();
    let layouts: Vec<(&str, Vec<u8>)> = vec![
        ("plain.msix", b.build()),
        (
            "descriptors.msix",
            b.build_with(&ZipStyle {
                descriptors: true,
                ..ZipStyle::default()
            }),
        ),
        (
            "zip64-extras.msix",
            b.build_with(&ZipStyle {
                descriptors: true,
                zip64: true,
                ..ZipStyle::default()
            }),
        ),
        (
            "tool-layout.msix",
            b.build_with(&ZipStyle::packaging_tool()),
        ),
        ("bundle.msixbundle", AppxBuilder::bundle().build()),
        // The plain layout with a manifest the OS manifest validator
        // refuses (an extension `Executable` without `EntryPoint`, as the
        // fixtures had before), to tell a refused manifest from a refused
        // signature.
        ("plain-bad-manifest.msix", {
            let mut bad = b.clone();
            bad.files[0].data = sdk_manifest_with_bare_extension(&bad.files[0].data);
            bad.build()
        }),
        // The committed unsigned fixtures, signed by the OS tool instead of
        // osslsigncode.
        (
            "fixture-app.msix",
            std::fs::read(format!("{FIXTURES}/app.msix")).unwrap(),
        ),
        // The committed ZIP64 fixture's layout (data descriptors, ZIP64
        // extra fields), and the classic one, as the OS tool signs them.
        (
            "fixture-zip64.msix",
            std::fs::read(format!("{FIXTURES}/app-zip64-unsigned.msix")).unwrap(),
        ),
        (
            "fixture-classic.msix",
            std::fs::read(format!("{FIXTURES}/app-classic-unsigned.msix")).unwrap(),
        ),
        (
            "fixture-bundle.msixbundle",
            std::fs::read(format!("{FIXTURES}/bundle.msixbundle")).unwrap(),
        ),
    ];
    let dir = Scratch::new("os-sign-layouts");
    for (name, data) in &layouts {
        std::fs::write(dir.0.join(name), data).unwrap();
    }
    let subject = PathBuf::from(PUBLISHER);
    if !powershell(
        "os-sdk-sign.ps1",
        &[("-Dir", &dir.0), ("-Subject", &subject)],
    ) {
        return;
    }
    let log = std::fs::read_to_string(dir.0.join("sign.txt")).unwrap();
    let log = log.trim_start_matches('\u{feff}').to_owned();

    // Every layout signed, the signer's digest beside ours, tag by tag.
    let mut report = String::new();
    let mut problems = 0;
    // Every file the tool signed, whether this crate reads it or not: the
    // OS is asked about each, so a refusal here is compared with its
    // verdict too.
    let mut signed: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, _) in &layouts {
        let line = log
            .lines()
            .find(|l| l.split('\t').nth(1) == Some(*name))
            .unwrap_or_else(|| panic!("{name} missing from the signing log:\n{log}"));
        if line.starts_with("REFUSED") {
            report.push_str(&format!("{line}\n"));
            problems += 1;
            continue;
        }
        let data = std::fs::read(dir.0.join(name)).unwrap();
        signed.push(((*name).to_owned(), data.clone()));
        let archive = match Archive::parse(&data) {
            Ok(a) => a,
            Err(e) => {
                report.push_str(&format!(
                    "{name}: signed by the OS tool, refused here: {e}\n"
                ));
                let before = &layouts.iter().find(|(n, _)| n == name).unwrap().1;
                report.push_str(&format!("{name}: before signing:\n{}", zip_dump(before)));
                report.push_str(&format!("{name}: after signing:\n{}", zip_dump(&data)));
                // A refusal is a problem only if the OS accepts the file;
                // the verdicts are compared below.
                continue;
            }
        };
        let theirs = archive
            .member("AppxSignature.p7x")
            .and_then(|m| archive.read(m).ok())
            .and_then(|p| signature_digest(&p, 32));
        let ours = our_digest(&archive);
        let Some(theirs) = theirs else {
            report.push_str(&format!(
                "{name}: no digest found in the OS tool's signature\n"
            ));
            problems += 1;
            continue;
        };
        let tags = |v: &[([u8; 4], Vec<u8>)]| {
            v.iter()
                .map(|(t, _)| String::from_utf8_lossy(t).into_owned())
                .collect::<Vec<_>>()
        };
        if tags(&theirs) != tags(&ours) {
            report.push_str(&format!(
                "{name}: tags differ: OS {:?}, ours {:?}\n",
                tags(&theirs),
                tags(&ours)
            ));
            problems += 1;
        }
        for ((tag, t), (_, o)) in theirs.iter().zip(&ours) {
            if t != o {
                problems += 1;
            }
            report.push_str(&format!(
                "{name}: {} {} OS {} ours {}\n",
                String::from_utf8_lossy(tag),
                if t == o { "same" } else { "DIFFERS" },
                hex(t),
                hex(o)
            ));
        }
    }
    // The OS's verdict on what its own signer made, beside ours.
    if let Some(os) = ask_os(&[], &signed) {
        report.push_str(&os.text);
        report.push('\n');
        for (name, data) in &signed {
            let code = os.code(name);
            let ours = parse_package(data).map(|id| id.signature_valid());
            // Refused here or signature not valid: both are "not valid".
            let agree = ours.as_ref().is_ok_and(|v| *v) == INTACT.contains(&code);
            if !agree {
                problems += 1;
            }
            report.push_str(&format!(
                "{name}: OS {code:#010x}, ours {ours:?}{}\n",
                if agree { "" } else { " DISAGREE" }
            ));
        }
    }
    eprintln!("{log}\n{report}");
    assert_eq!(problems, 0, "{log}\n{report}");
}

/// `manifest` (an [`sdk_manifest`]) with an app execution alias extension
/// that names an `Executable` but no `EntryPoint`, which the OS manifest
/// validator refuses.
fn sdk_manifest_with_bare_extension(manifest: &[u8]) -> Vec<u8> {
    String::from_utf8(manifest.to_vec())
        .unwrap()
        .replace(
            "xmlns:rescap=",
            &format!("xmlns:uap3=\"{UAP3}\" xmlns:desktop=\"{DESKTOP}\" xmlns:rescap="),
        )
        .replace(
            "IgnorableNamespaces=\"uap rescap\"",
            "IgnorableNamespaces=\"uap uap3 desktop rescap\"",
        )
        .replace(
            "</Application>",
            "<Extensions><uap3:Extension Category=\"windows.appExecutionAlias\" Executable=\"tool.exe\"><uap3:AppExecutionAlias><desktop:ExecutionAlias Alias=\"palisade-probe.exe\"/></uap3:AppExecutionAlias></uap3:Extension></Extensions></Application>",
        )
        .into_bytes()
}

/// The raw ZIP records of `data`, for a failure report: the end records,
/// then for each central entry its fields and extra field, its local
/// header's fields and extra field, and the bytes between its data and the
/// next record (its data descriptor, if any). Read at fixed offsets, so it
/// works on archives this crate's reader refuses. Offsets in a test
/// package are small, so the casts are exact.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn zip_dump(data: &[u8]) -> String {
    let get = |at: usize, n: usize| data.get(at..at.saturating_add(n)).unwrap_or_default();
    let u16_at =
        |at: usize| usize::from(u16::from_le_bytes(get(at, 2).try_into().unwrap_or([0; 2])));
    let u32_at = |at: usize| u32::from_le_bytes(get(at, 4).try_into().unwrap_or([0; 4]));
    let u64_at = |at: usize| u64::from_le_bytes(get(at, 8).try_into().unwrap_or([0; 8]));
    let Some(eocd) = data.windows(4).rposition(|w| w == [0x50, 0x4b, 0x05, 0x06]) else {
        return "  no end record\n".into();
    };
    let mut out = format!("  end record at {eocd}: {}\n", hex(get(eocd, 22)));
    let mut cd = u32_at(eocd + 16) as usize;
    if eocd >= 20 && get(eocd - 20, 4) == [0x50, 0x4b, 0x06, 0x07] {
        let rec = u64_at(eocd - 12) as usize;
        out.push_str(&format!("  ZIP64 locator: {}\n", hex(get(eocd - 20, 20))));
        out.push_str(&format!("  ZIP64 record at {rec}: {}\n", hex(get(rec, 56))));
        cd = u64_at(rec + 48) as usize;
    }
    let mut entries = Vec::new();
    let mut at = cd;
    while u32_at(at) == 0x0201_4b50 && entries.len() < 64 {
        let (nl, el, cl) = (u16_at(at + 28), u16_at(at + 30), u16_at(at + 32));
        let extra = get(at + 46 + nl, el);
        let mut local = u64::from(u32_at(at + 42));
        let mut csize = u64::from(u32_at(at + 20));
        if extra.len() >= 4 && extra[..2] == [1, 0] {
            // The ZIP64 fields, in order, for the 32-bit fields marked.
            let mut p = 4;
            let mut next = || {
                let v = extra
                    .get(p..p + 8)
                    .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                p += 8;
                v
            };
            if u32_at(at + 24) == u32::MAX {
                next();
            }
            if u32_at(at + 20) == u32::MAX {
                csize = next();
            }
            if u32_at(at + 42) == u32::MAX {
                local = next();
            }
        }
        entries.push((at, nl, extra, local as usize, csize as usize));
        at += 46 + nl + el + cl;
    }
    for (i, &(c, nl, extra, local, csize)) in entries.iter().enumerate() {
        let name = String::from_utf8_lossy(get(c + 46, nl));
        out.push_str(&format!(
            "  {name}: central {} extra [{}]\n",
            hex(get(c + 4, 42)),
            hex(extra)
        ));
        let (lnl, lel) = (u16_at(local + 26), u16_at(local + 28));
        let data_at = local + 30 + lnl + lel;
        let end = data_at + csize;
        let following = entries.get(i + 1).map_or(cd, |e| e.3);
        out.push_str(&format!(
            "    local at {local}: {} extra [{}] then after the data ({} bytes to the next record): {}\n",
            hex(get(local + 4, 26)),
            hex(get(local + 30 + lnl, lel)),
            following as i64 - end as i64,
            hex(get(end, following.saturating_sub(end).min(32)))
        ));
    }
    out
}
