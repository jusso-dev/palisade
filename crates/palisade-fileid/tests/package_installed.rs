//! Installed packages against a package the OS really installed (#333).
//! Windows with `os-trust` only.
//!
//! [`a_signed_test_package_is_listed_mapped_and_aliased`] lays out a small
//! package with an app execution alias. `os-install-package.ps1` then
//! packs and signs it with the OS SDK's tools, trusts the throwaway
//! certificate in the machine's TrustedPeople store, and installs it for
//! the current user. The test checks that:
//!
//! - every user's listing (`win::package_manager`) and the current user's
//!   (`win::packages`) both hold it, with a consistent identity, its
//!   install folder, the developer signature kind, not a stub, and the
//!   current user among its users;
//! - the executable inside it maps to it (`owner_of`), and a file outside
//!   it does not;
//! - its app execution alias, read as a reparse point, resolves to its
//!   executable, and a forged target does not.
//!
//! Installing a package changes the machine, so the test runs only when
//! `PALISADE_INSTALL_TEST_PACKAGE` is set: CI's `installed-package` job
//! sets it on a disposable, elevated runner. It removes the package and
//! the certificate afterwards, whatever happened.

#![cfg(all(windows, feature = "os-trust"))]
#![allow(clippy::unwrap_used)]

#[path = "common/appx.rs"]
mod appx;
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use palisade_fileid::package::installed::{
    AliasError, InstalledPackages, InstalledSignatureKind, OwnerLookup,
};
use palisade_fileid::win::{links, package_manager, packages};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/package");
/// The test package's name.
const NAME: &str = "Palisade.InstalledProbe";
/// Its app execution alias.
const ALIAS: &str = "palisade-installed-probe.exe";

/// A folder for the test, removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Removes the package and the certificate when dropped.
struct Installed;

impl Drop for Installed {
    fn drop(&mut self) {
        let _ = script(&["-Action", "remove", "-Name", NAME]);
    }
}

/// Runs `os-install-package.ps1` with `args`: its exit code and output.
fn script(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new("powershell.exe")
        // A parent PowerShell 7 leaves its module path in the environment,
        // which stops Windows PowerShell loading its own modules.
        .env_remove("PSModulePath")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(format!("{FIXTURES}/os-install-package.ps1"))
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// The test package's manifest: [`appx::sdk_manifest`] with an app
/// execution alias for its one application.
fn manifest() -> String {
    use palisade_fileid::package::manifest::ns::{DESKTOP, UAP3};
    appx::sdk_manifest(NAME, "__PUBLISHER__", "1.0.0.0", "neutral")
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
            &format!(
                "<Extensions><uap3:Extension Category=\"windows.appExecutionAlias\" Executable=\"tool.exe\" EntryPoint=\"Windows.FullTrustApplication\"><uap3:AppExecutionAlias><desktop:ExecutionAlias Alias=\"{ALIAS}\"/></uap3:AppExecutionAlias></uap3:Extension></Extensions></Application>"
            ),
        )
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| {
            l.trim_start_matches('\u{feff}')
                .strip_prefix(&format!("{key}\t"))
        })
        .unwrap_or_else(|| panic!("no {key} in {text}"))
        .trim()
}

/// The final path of `path`. Opened for its attributes only, as the agent
/// opens files: `WindowsApps` lets a standard user read attributes of the
/// package folder but not its data, so `File::open` is refused there.
/// Backup semantics let the folder itself be opened.
fn final_path(path: &Path) -> palisade_fileid::fsctx::NormalizedPath {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(0x7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    links::final_path_of(&file).unwrap()
}

#[test]
fn a_signed_test_package_is_listed_mapped_and_aliased() {
    if std::env::var_os("PALISADE_INSTALL_TEST_PACKAGE").is_none() {
        eprintln!("skipped: set PALISADE_INSTALL_TEST_PACKAGE to install a test package");
        return;
    }
    let dir = Scratch(
        std::env::temp_dir().join(format!("palisade-installed-package-{}", std::process::id())),
    );
    let _ = std::fs::remove_dir_all(&dir.0);
    let layout = dir.0.join("layout");
    std::fs::create_dir_all(&layout).unwrap();
    std::fs::write(layout.join("AppxManifest.xml"), manifest()).unwrap();
    std::fs::write(layout.join("logo.png"), appx::PNG).unwrap();
    std::fs::write(
        layout.join("tool.exe"),
        common::PeBuilder::default().build(),
    )
    .unwrap();
    let out = dir.0.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let _cleanup = Installed;
    let (code, text) = script(&[
        "-Action",
        "install",
        "-Name",
        NAME,
        "-Layout",
        layout.to_str().unwrap(),
        "-Out",
        out.to_str().unwrap(),
        "-Alias",
        ALIAS,
    ]);
    assert_eq!(code, Some(0), "{text}");
    let report = std::fs::read_to_string(out.join("installed.txt")).unwrap();
    let full_name = field(&report, "FULLNAME").to_owned();
    let location = PathBuf::from(field(&report, "LOCATION"));
    let alias_path = PathBuf::from(field(&report, "ALIAS"));
    let family = full_name.split('_').next().unwrap().to_owned()
        + "_"
        + full_name.rsplit('_').next().unwrap();
    eprintln!("installed {full_name} in {}", location.display());

    // Every user's listing, and the current user's.
    let all = package_manager::all_users_packages().unwrap();
    let of_family = package_manager::all_users_packages_of_family(&family).unwrap();
    let mine = packages::packages_of_family(&family).unwrap();
    for (what, list) in [
        ("all users", &all),
        ("family", &of_family),
        ("current user", &mine),
    ] {
        let p = list
            .packages
            .iter()
            .find(|p| p.full_name.eq_ignore_ascii_case(&full_name))
            .unwrap_or_else(|| panic!("{what}: {full_name} not listed"));
        assert!(p.is_consistent(), "{what}: {p:?}");
        assert_eq!(p.name, NAME, "{what}");
        assert!(
            !p.is_framework && !p.is_bundle && !p.is_resource_package,
            "{what}: {p:?}"
        );
        assert_eq!(
            p.signature_kind,
            InstalledSignatureKind::Developer,
            "{what}: {p:?}"
        );
        assert_eq!(p.applications.len(), 1, "{what}: {p:?}");
        assert_eq!(
            p.install_location.as_ref().map(|l| l.match_key()),
            Some(final_path(&location).match_key()),
            "{what}"
        );
    }
    // Only the package manager knows the stub flag and the users.
    let p = of_family
        .packages
        .iter()
        .find(|p| p.full_name == full_name)
        .unwrap();
    assert_eq!(p.is_stub, Some(false));
    let me = field(&report, "USER").to_owned();
    assert!(p.users.contains(&me), "{me} not in {:?}", p.users);
    let p = mine
        .packages
        .iter()
        .find(|p| p.full_name == full_name)
        .unwrap();
    assert_eq!(p.is_stub, None);

    // The executable inside maps to the package; a file outside does not.
    let exe = final_path(&location.join("tool.exe"));
    for list in [&all, &mine] {
        match list.owner_of(&exe) {
            OwnerLookup::Owned(o) => assert_eq!(o.full_name, full_name),
            other => panic!("{other:?}"),
        }
    }
    let outside = final_path(&layout.join("tool.exe"));
    assert!(matches!(
        all.owner_of(&outside),
        OwnerLookup::NotOwned { .. }
    ));

    // The alias resolves to the executable, through both listings.
    let link = links::open_link_itself(&alias_path).unwrap();
    let reparse = links::read_reparse(&link).unwrap().unwrap();
    let alias = reparse.app_exec_link().unwrap();
    assert!(alias.package_family_name.eq_ignore_ascii_case(&family));
    let target = packages::resolve_alias_for_current_user(alias)
        .unwrap()
        .unwrap();
    assert_eq!(target.package.full_name, full_name);
    // The same file, possibly spelled with a `\\?\` prefix and with its
    // case-sensitive directories checked: compare what rules match.
    assert_eq!(target.executable.match_key(), exe.match_key());
    let resolved = palisade_fileid::package::installed::resolve_alias(alias, &all).unwrap();
    assert_eq!(resolved.package.full_name, full_name);
    let mut forged = alias.clone();
    forged.target_path = outside.to_win32_string();
    assert_eq!(
        packages::resolve_alias_for_current_user(&forged).unwrap(),
        Err(AliasError::TargetMismatch)
    );
    assert!(no_other(&all, &full_name));
}

/// The package is listed once.
fn no_other(all: &InstalledPackages, full_name: &str) -> bool {
    all.packages
        .iter()
        .filter(|p| p.full_name.eq_ignore_ascii_case(full_name))
        .count()
        == 1
}
