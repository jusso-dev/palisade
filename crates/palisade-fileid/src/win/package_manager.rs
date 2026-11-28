//! Every user's installed packages, from the package manager's WinRT
//! interface (#333).
//!
//! The flat app-model API that [`super::packages`] uses sees only the
//! calling user's packages, and says nothing of stub packages or of which
//! users have a package. [`all_users_packages`] asks the package manager
//! (`PackageManager.FindPackages`, `FindUsers`) instead, which needs
//! administrator rights; the agent runs as SYSTEM.
//!
//! What each record holds, and where it comes from:
//!
//! - the full name, the framework, resource, bundle and stub flags, the
//!   signature kind and the install folder come from the OS;
//! - the users are the SIDs `FindUsers` lists for the full name, with the
//!   package installed (not only staged) for them, sorted;
//! - the identity and the applications come from the installed manifest,
//!   read with this crate's bounded parser, and the record is kept only if
//!   the full name they give is the one the OS reported
//!   ([`super::packages`] does the same).
//!
//! A package that cannot be read is left out and the result marked
//! `incomplete`, so a caller never takes "not listed" for "not installed"
//! (ADR 0018). The enumeration is bounded: past [`MAX_PACKAGES`] packages,
//! or [`MAX_USERS`] users of one package, it stops and says so.
//!
//! This module has no `unsafe` code: the `windows` crate's projection
//! holds the calls.

#![forbid(unsafe_code)]

use std::io;

use windows::ApplicationModel::{Package, PackageSignatureKind};
use windows::Management::Deployment::{PackageInstallState, PackageManager};
use windows::core::HSTRING;

use crate::fsctx::Sid;
use crate::package::installed::{InstalledPackage, InstalledPackages, InstalledSignatureKind};

/// The most packages listed. A machine has a few hundred to a few
/// thousand.
pub const MAX_PACKAGES: usize = 16_384;
/// The most users listed for one package.
pub const MAX_USERS: usize = 4_096;

/// The signature kind for the package manager's `PackageSignatureKind`.
fn signature_kind(kind: PackageSignatureKind) -> InstalledSignatureKind {
    match kind {
        PackageSignatureKind::None => InstalledSignatureKind::None,
        PackageSignatureKind::Developer => InstalledSignatureKind::Developer,
        PackageSignatureKind::Enterprise => InstalledSignatureKind::Enterprise,
        PackageSignatureKind::Store => InstalledSignatureKind::Store,
        PackageSignatureKind::System => InstalledSignatureKind::System,
        _ => InstalledSignatureKind::Unknown,
    }
}

fn os_err(e: &windows::core::Error) -> io::Error {
    io::Error::other(e.message())
}

/// Every package installed for any user, with its users and stub flag.
/// See the module documentation. Fails if the package manager cannot be
/// reached or refuses the enumeration (without administrator rights).
pub fn all_users_packages() -> io::Result<InstalledPackages> {
    let manager = PackageManager::new().map_err(|e| os_err(&e))?;
    let found = manager.FindPackages().map_err(|e| os_err(&e))?;
    Ok(collect(&manager, found))
}

/// The packages of `family` installed for any user. As
/// [`all_users_packages`], for one family.
pub fn all_users_packages_of_family(family: &str) -> io::Result<InstalledPackages> {
    let manager = PackageManager::new().map_err(|e| os_err(&e))?;
    let found = manager
        .FindPackagesByPackageFamilyName(&HSTRING::from(family))
        .map_err(|e| os_err(&e))?;
    Ok(collect(&manager, found))
}

fn collect(
    manager: &PackageManager,
    found: impl IntoIterator<Item = Package>,
) -> InstalledPackages {
    let mut out = InstalledPackages::default();
    for package in found {
        if out.packages.len() >= MAX_PACKAGES {
            out.incomplete = true;
            break;
        }
        match read_package(manager, &package) {
            Some((p, users_complete)) => {
                out.incomplete |= !users_complete;
                out.packages.push(p);
            }
            None => out.incomplete = true,
        }
    }
    out
}

/// One package's record, and whether its user list is complete. `None` if
/// it cannot be read or its manifest is not its own.
fn read_package(manager: &PackageManager, package: &Package) -> Option<(InstalledPackage, bool)> {
    let full_name = package.Id().ok()?.FullName().ok()?.to_string_lossy();
    let folder = package.InstalledPath().ok()?.to_string_lossy();
    let mut p = super::packages::from_install_folder(&full_name, &folder)?;
    p.signature_kind = package
        .SignatureKind()
        .map_or(InstalledSignatureKind::Unknown, signature_kind);
    // A flag the OS cannot report keeps what the manifest said.
    p.is_framework |= package.IsFramework().unwrap_or(false);
    p.is_resource_package |= package.IsResourcePackage().unwrap_or(false);
    p.is_bundle = package.IsBundle().unwrap_or(p.is_bundle);
    p.is_stub = package.IsStub().ok();
    let (users, complete) = users_of(manager, &full_name);
    p.users = users;
    Some((p, complete))
}

/// The SIDs of the users `full_name` is installed for, sorted, and whether
/// the list is complete. A user whose SID does not parse, or whose state
/// cannot be read, makes it incomplete.
fn users_of(manager: &PackageManager, full_name: &str) -> (Vec<String>, bool) {
    let Ok(found) = manager.FindUsers(&HSTRING::from(full_name)) else {
        return (Vec::new(), false);
    };
    let mut users = Vec::new();
    let mut complete = true;
    for info in found {
        if users.len() >= MAX_USERS {
            complete = false;
            break;
        }
        let (Ok(sid), Ok(state)) = (info.UserSecurityId(), info.InstallState()) else {
            complete = false;
            continue;
        };
        if state != PackageInstallState::Installed {
            continue;
        }
        match sid.to_string_lossy().parse::<Sid>() {
            Ok(sid) => users.push(sid.to_string()),
            Err(_) => complete = false,
        }
    }
    users.sort();
    users.dedup();
    (users, complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_kinds_map() {
        for (os, ours) in [
            (PackageSignatureKind::None, InstalledSignatureKind::None),
            (
                PackageSignatureKind::Developer,
                InstalledSignatureKind::Developer,
            ),
            (
                PackageSignatureKind::Enterprise,
                InstalledSignatureKind::Enterprise,
            ),
            (PackageSignatureKind::Store, InstalledSignatureKind::Store),
            (PackageSignatureKind::System, InstalledSignatureKind::System),
            (PackageSignatureKind(99), InstalledSignatureKind::Unknown),
        ] {
            assert_eq!(signature_kind(os), ours);
        }
    }

    /// The runners run tests elevated, and every image has system
    /// packages: the list is not empty, every record is consistent, and
    /// some package is installed for some user.
    #[test]
    fn every_users_packages_are_listed() {
        let all = all_users_packages().unwrap();
        eprintln!(
            "{} packages, incomplete: {}",
            all.packages.len(),
            all.incomplete
        );
        assert!(!all.packages.is_empty());
        assert!(all.packages.iter().all(InstalledPackage::is_consistent));
        assert!(all.packages.iter().all(|p| p.is_stub.is_some()));
        assert!(all.packages.iter().any(|p| !p.users.is_empty()));
        for p in &all.packages {
            assert!(p.users.windows(2).all(|w| w[0] < w[1]), "{p:?}");
            assert!(p.users.iter().all(|u| u.starts_with("S-1-")), "{p:?}");
        }
        // The family query agrees with the full list.
        let one = &all.packages[0];
        let family = all_users_packages_of_family(&one.family_name).unwrap();
        assert!(
            family.packages.iter().any(|p| p.full_name == one.full_name),
            "{family:?}"
        );
        let none = all_users_packages_of_family("Palisade.NotInstalled_0000000000000").unwrap();
        assert!(none.packages.is_empty() && !none.incomplete);
    }
}
