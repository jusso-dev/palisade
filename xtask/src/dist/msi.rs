//! The Windows Installer package: fetches the pinned WiX toolset, builds
//! `Palisade-<version>-<arch>.msi` from `packaging/wix/` and validates it
//! with the standard ICE suite.
//!
//! WiX is pinned to [`WIX_VERSION`], downloaded once into `<target dir>/wix/` and
//! checked against [`WIX_SHA256`] before anything in it runs. It needs only
//! the .NET runtime, which the hosted Windows runners have. Version 5 is
//! the last major version under its plain open-source licence; later
//! versions ask every user to accept an additional licence agreement, which
//! CI must not accept on the maintainer's behalf (docs/packaging.md).
//!
//! The package uses no WiX extension and no custom action code: services,
//! service SIDs and ACLs are all standard Windows Installer 5 tables. The
//! custom actions set properties, and one runs the operating system's own
//! service-control tool to set the recovery actions, which the installer's
//! failure-actions table cannot set (docs/packaging.md#installer-package).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest as _, Sha256};

use super::os_ids;
use super::version::Version;
use super::{Target, hex};

/// The pinned WiX toolset version.
pub const WIX_VERSION: &str = "5.0.2";
/// SHA-256 of `wix.5.0.2.nupkg` from the package registry.
pub const WIX_SHA256: &str = "f30ef0c74e2a986126539c5780be93ac24e8136eaf723b1937b26272703ae173";
/// Where the package is downloaded from.
pub fn wix_url() -> String {
    format!("https://api.nuget.org/v3-flatcontainer/wix/{WIX_VERSION}/wix.{WIX_VERSION}.nupkg")
}

/// The WiX sources, relative to the repository root.
pub const SOURCES: &[&str] = &["packaging/wix/Palisade.wxs", "packaging/wix/UI.wxs"];
/// The install, upgrade and removal checks CI runs on the package.
#[cfg(test)]
const SMOKE_TEST: &str = "packaging/wix/smoke-test.ps1";
/// The licence text the installer shows.
pub const LICENSE_RTF: &str = "packaging/wix/License.rtf";

/// The public properties the package accepts on the `msiexec` command line,
/// with what each one does. `docs/packaging.md` documents the same list,
/// and a test keeps the two and `Palisade.wxs` in step.
pub const PUBLIC_PROPERTIES: &[(&str, &str)] = &[
    ("SERVER_URL", "HTTPS base URL of the management server"),
    (
        "ENROLL_TOKEN",
        "enrolment token; hidden from installer logs",
    ),
    ("GROUP_KEY", "policy group to join at enrolment"),
    ("PROXY", "proxy for agent traffic"),
    (
        "MODE",
        "initial mode: audit (default), monitor, learning, enforce or disabled",
    ),
    ("NO_TRAY", "1: do not start the user notifier at sign-in"),
    ("SKIP_ENROLL", "1: offline install, no server"),
    (
        "ALLOW_UNINSTALL",
        "uninstall authorisation for uninstall protection (#18); hidden from installer logs",
    ),
    (
        "ADD_TO_PATH",
        "1: add the install folder (pal.exe) to the system PATH",
    ),
];

/// Properties the installer must never write to its log.
pub const HIDDEN_PROPERTIES: &[&str] = &["ENROLL_TOKEN", "ALLOW_UNINSTALL"];

/// The values `MODE` accepts: the snake_case names of `palisade_core::Mode`.
pub const MODES: &[&str] = &["disabled", "monitor", "audit", "learning", "enforce"];

/// The registry key the package writes its settings to, under `HKLM`, and
/// the service name `palisade-agent` registers with. A test checks both
/// against `Palisade.wxs` and the agent.
#[cfg(test)]
const SETTINGS_KEY: &str = r"SOFTWARE\Palisade\Agent";
#[cfg(test)]
const SERVICE_NAME: &str = "PalisadeAgent";

/// One upgrade code per architecture, the same for every version, so a
/// newer package of the same architecture replaces an older one.
pub const fn upgrade_code(target: Target) -> &'static str {
    match target {
        Target::WindowsArm64 => "06ECC7D9-0C25-4082-91E3-084C9E576B52",
        _ => "A6722ABB-D54B-4029-811E-2B651EECD0C7",
    }
}

/// The WiX `-arch` value.
const fn wix_arch(target: Target) -> &'static str {
    match target {
        Target::WindowsArm64 => "arm64",
        _ => "x64",
    }
}

/// The package file name.
pub fn file_name(target: Target, version: &Version) -> String {
    format!("Palisade-{version}-{}.msi", target.arch())
}

/// What [`build`] packages.
pub struct Inputs<'a> {
    pub target: Target,
    pub version: &'a Version,
    /// The folder with the three executables.
    pub bin_dir: &'a Path,
    pub out_dir: &'a Path,
    /// Cargo's target directory, for the WiX download and work files.
    pub target_dir: &'a Path,
}

/// The `-d` preprocessor variables for `wix build`.
pub fn defines(root: &Path, inputs: &Inputs<'_>) -> Result<Vec<(String, String)>, String> {
    Ok(vec![
        ("MsiVersion".to_owned(), inputs.version.msi()?),
        ("SemVer".to_owned(), inputs.version.to_string()),
        (
            "UpgradeCode".to_owned(),
            upgrade_code(inputs.target).to_owned(),
        ),
        ("BinDir".to_owned(), inputs.bin_dir.display().to_string()),
        ("RepoRoot".to_owned(), root.display().to_string()),
        (
            "LicenseRtf".to_owned(),
            root.join(LICENSE_RTF).display().to_string(),
        ),
        ("RunKey".to_owned(), os_ids::RUN_KEY.to_owned()),
    ])
}

/// Problems with the package sources that WiX would not catch: a public
/// property that is not declared `Secure` (so it would not reach the
/// installation), a secret that is not `Hidden` (so it would be logged),
/// or a `MODE` value the sources do not accept.
pub fn check_sources(wxs: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, _) in PUBLIC_PROPERTIES {
        let decl = if HIDDEN_PROPERTIES.contains(name) {
            format!(r#"<Property Id="{name}" Secure="yes" Hidden="yes" />"#)
        } else {
            format!(r#"<Property Id="{name}" Secure="yes" />"#)
        };
        if !wxs.contains(&decl) {
            problems.push(format!("{}: must declare {decl}", SOURCES[0]));
        }
    }
    if wxs.matches("Hidden=\"yes\"").count() != HIDDEN_PROPERTIES.len() {
        problems.push(format!(
            "{}: exactly {} must be Hidden",
            SOURCES[0],
            HIDDEN_PROPERTIES.join(", ")
        ));
    }
    for mode in MODES {
        if !wxs.contains(&format!("MODE = &quot;{mode}&quot;")) {
            problems.push(format!("{}: the MODE check must accept {mode}", SOURCES[0]));
        }
    }
    problems
}

/// Builds and validates the package. Returns its path.
pub fn build(root: &Path, inputs: &Inputs<'_>) -> Result<PathBuf, String> {
    let wxs = std::fs::read_to_string(root.join(SOURCES[0]))
        .map_err(|e| format!("cannot read {}: {e}", SOURCES[0]))?;
    let problems = check_sources(&wxs);
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }
    let wix = ensure_wix(inputs.target_dir)?;
    let work = inputs
        .target_dir
        .join(inputs.target.triple())
        .join("wix-work");
    std::fs::create_dir_all(&work).map_err(|e| format!("cannot create {}: {e}", work.display()))?;
    let msi = inputs
        .out_dir
        .join(file_name(inputs.target, inputs.version));
    let pdb = work.join("Palisade.wixpdb");

    let mut command = dotnet(&wix);
    command
        .arg("build")
        .args(["-arch", wix_arch(inputs.target)])
        .arg("-intermediatefolder")
        .arg(&work)
        .arg("-pdb")
        .arg(&pdb)
        .arg("-o")
        .arg(&msi);
    for (name, value) in defines(root, inputs)? {
        command.arg("-d").arg(format!("{name}={value}"));
    }
    for source in SOURCES {
        command.arg(root.join(source));
    }
    run(command, "wix build")?;

    // The standard ICE suite; any error fails the build.
    let mut validate = dotnet(&wix);
    validate
        .args(["msi", "validate", "-intermediatefolder"])
        .arg(&work)
        .arg("-pdb")
        .arg(&pdb)
        .arg(&msi);
    run(validate, "wix msi validate")?;
    println!("dist: {} built and passed ICE validation", msi.display());
    Ok(msi)
}

fn dotnet(wix_dll: &Path) -> Command {
    let mut command = Command::new("dotnet");
    command
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .arg(wix_dll);
    command
}

fn run(mut command: Command, what: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|e| format!("cannot run {what} (is the .NET runtime installed?): {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} failed"))
    }
}

/// The path of `wix.dll` in the pinned toolset, downloading and verifying
/// it first if needed.
fn ensure_wix(target_dir: &Path) -> Result<PathBuf, String> {
    let dir = target_dir.join("wix").join(WIX_VERSION);
    let dll = dir.join("tools").join("net6.0").join("any").join("wix.dll");
    let stamp = dir.join(".verified");
    if dll.is_file() && std::fs::read_to_string(&stamp).is_ok_and(|s| s.trim() == WIX_SHA256) {
        return Ok(dll);
    }
    if dir.exists() {
        std::fs::remove_dir_all(&dir)
            .map_err(|e| format!("cannot clear {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let package = dir.with_file_name(format!("wix-{WIX_VERSION}.nupkg"));
    println!("dist: downloading WiX {WIX_VERSION}");
    let system = windows_tool_dir();
    run(
        {
            let mut c = Command::new(system.join("curl.exe"));
            c.args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--output",
            ])
            .arg(&package)
            .arg(wix_url());
            c
        },
        "curl",
    )?;
    let data =
        std::fs::read(&package).map_err(|e| format!("cannot read {}: {e}", package.display()))?;
    let digest = hex(&Sha256::digest(&data));
    if digest != WIX_SHA256 {
        let _ = std::fs::remove_file(&package);
        return Err(format!(
            "the WiX {WIX_VERSION} package has SHA-256 {digest}, expected {WIX_SHA256}; not using it"
        ));
    }
    // The package is a ZIP archive; the system tar reads it.
    run(
        {
            let mut c = Command::new(system.join("tar.exe"));
            c.arg("-xf").arg(&package).arg("-C").arg(&dir);
            c
        },
        "tar",
    )?;
    let _ = std::fs::remove_file(&package);
    if !dll.is_file() {
        return Err(format!("{} is missing from the WiX package", dll.display()));
    }
    std::fs::write(&stamp, WIX_SHA256)
        .map_err(|e| format!("cannot write {}: {e}", stamp.display()))?;
    Ok(dll)
}

/// `%SystemRoot%\System32`, where Windows ships `curl.exe` and `tar.exe`.
/// Named in full so another `curl` or `tar` on `PATH` is never used.
fn windows_tool_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    fn source(name: &str) -> String {
        std::fs::read_to_string(repo().join(name)).unwrap()
    }

    #[test]
    fn every_public_property_is_declared_secure() {
        let wxs = source(SOURCES[0]);
        for (name, _) in PUBLIC_PROPERTIES {
            let hidden = HIDDEN_PROPERTIES.contains(name);
            let decl = if hidden {
                format!(r#"<Property Id="{name}" Secure="yes" Hidden="yes" />"#)
            } else {
                format!(r#"<Property Id="{name}" Secure="yes" />"#)
            };
            assert!(wxs.contains(&decl), "Palisade.wxs must declare: {decl}");
        }
        assert_eq!(
            wxs.matches("Hidden=\"yes\"").count(),
            HIDDEN_PROPERTIES.len()
        );
    }

    #[test]
    fn docs_list_every_public_property() {
        let docs = source("docs/packaging.md");
        for (name, _) in PUBLIC_PROPERTIES {
            assert!(
                docs.contains(&format!("| `{name}` |")),
                "docs/packaging.md: {name}"
            );
        }
    }

    #[test]
    fn mode_values_are_the_core_mode_names() {
        let core = source("crates/palisade-core/src/mode.rs");
        let body = core
            .split("pub enum Mode {")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        let variants: Vec<String> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("///") && !l.is_empty())
            .map(|l| l.trim_end_matches(',').to_ascii_lowercase())
            .collect();
        assert_eq!(variants, MODES);
        let wxs = source(SOURCES[0]);
        for mode in MODES {
            assert!(
                wxs.contains(&format!("MODE = &quot;{mode}&quot;")),
                "{mode}"
            );
        }
    }

    /// A verbose installer log records every registry value, file and
    /// command line the package writes, hidden or not, so the secrets must
    /// not be used anywhere but in their declaration.
    #[test]
    fn hidden_properties_are_never_written_or_copied() {
        let wxs = source(SOURCES[0]);
        for name in HIDDEN_PROPERTIES {
            assert_eq!(wxs.matches(name).count(), 1, "{name} must only be declared");
        }
    }

    #[test]
    fn service_and_settings_names_match_the_agent() {
        let wxs = source(SOURCES[0]);
        assert!(wxs.contains(&format!(r#"<ServiceInstall Name="{SERVICE_NAME}""#)));
        assert!(wxs.contains(&format!(r#"<ServiceControl Name="{SERVICE_NAME}""#)));
        let agent = source("crates/palisade-agent/src/service.rs");
        assert!(agent.contains(&format!(
            r#"pub const SERVICE_NAME: &str = "{SERVICE_NAME}";"#
        )));
        let key = format!(r#"Key="{SETTINGS_KEY}""#);
        assert!(wxs.matches(&key).count() >= 10, "{key}");
        let cli = source("crates/palisade-agent/src/cli.rs");
        assert!(
            cli.contains("--service"),
            "the service is registered with --service"
        );
        assert!(wxs.contains(r#"Arguments="--service""#));
    }

    #[test]
    fn package_names_and_codes() {
        let v = Version::parse("0.2.0-rc.1").unwrap();
        assert_eq!(
            file_name(Target::WindowsX64, &v),
            "Palisade-0.2.0-rc.1-x64.msi"
        );
        assert_eq!(
            file_name(Target::WindowsArm64, &v),
            "Palisade-0.2.0-rc.1-arm64.msi"
        );
        assert_ne!(
            upgrade_code(Target::WindowsX64),
            upgrade_code(Target::WindowsArm64)
        );
        let inputs = Inputs {
            target: Target::WindowsArm64,
            version: &v,
            bin_dir: Path::new("b"),
            out_dir: Path::new("o"),
            target_dir: Path::new("t"),
        };
        let d = defines(Path::new("r"), &inputs).unwrap();
        assert!(d.contains(&("MsiVersion".to_owned(), "0.2.0".to_owned())));
        assert!(d.contains(&(
            "UpgradeCode".to_owned(),
            upgrade_code(Target::WindowsArm64).to_owned()
        )));
        // Every variable the sources use is defined.
        let used: String = SOURCES.iter().map(|s| source(s)).collect();
        let names: Vec<&str> = d.iter().map(|(n, _)| n.as_str()).collect();
        for part in used.split("$(var.").skip(1) {
            let name = part.split(')').next().unwrap();
            assert!(names.contains(&name), "undefined WiX variable {name}");
        }
    }

    #[test]
    fn the_licence_dialog_carries_the_disclaimer_and_both_licences() {
        let rtf = source(LICENSE_RTF);
        let plain = rtf.replace('\n', " ");
        assert!(plain.contains(
            "Palisade is an educational, personal-development project. It is not a replacement for \
             commercial application control products and comes with no support or warranty. Do not \
             rely on it to protect production systems."
        ));
        assert!(plain.contains("Apache License, Version 2.0"));
        assert!(plain.contains("MIT"));
    }

    #[test]
    fn os_identifiers_stay_in_one_file() {
        for path in SOURCES.iter().chain([&LICENSE_RTF, &SMOKE_TEST]) {
            let text = source(path).to_ascii_lowercase();
            assert!(
                !text.contains("currentversion"),
                "{path}: use $(var.RunKey)"
            );
        }
    }
}
