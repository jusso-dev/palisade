//! Installed packages from the OS (#333), for the portable model in
//! [`crate::package::installed`].
//!
//! [`packages_of_family`] lists the packages of one family installed for
//! the **current user**, through the flat app-model API
//! (`FindPackagesByPackageFamily`, `GetPackagePathByFullName`,
//! `GetStagedPackageOrigin`):
//!
//! - the full name and the framework, resource and bundle flags come from
//!   the OS;
//! - the install folder comes from the OS, and is turned into a final path
//!   (links resolved) before it is used;
//! - the identity (name, publisher, version, architecture, resource ID) and
//!   the applications come from the installed `AppxManifest.xml`, read
//!   with this crate's bounded parser. The record is kept only if the full
//!   name those give is exactly the one the OS reported, so a manifest that
//!   does not belong to the package is never believed.
//!
//! [`resolve_alias_for_current_user`] checks an app execution alias against
//! the packages of the family it claims. Enumerating every package for
//! every user needs the package manager's WinRT interface, which this
//! module does not use; that is still open in #333.

#![forbid(unsafe_code)]

use std::io;
use std::path::Path;

use super::sys;
use crate::fsctx::reparse::AppExecLink;
use crate::package::installed::{
    AliasError, InstalledPackage, InstalledPackages, InstalledSignatureKind, ResolvedAlias,
    resolve_alias,
};
use crate::package::manifest::parse_package_manifest;

/// `PACKAGE_FILTER_HEAD | DIRECT | RESOURCE | BUNDLE | OPTIONAL`: every
/// package of the family the user has.
const FILTERS: u32 = 0x10 | 0x20 | 0x40 | 0x80 | 0x2_0000;
/// `PACKAGE_PROPERTY_FRAMEWORK`.
const PROP_FRAMEWORK: u32 = 0x1;
/// `PACKAGE_PROPERTY_RESOURCE`.
const PROP_RESOURCE: u32 = 0x2;
/// `PACKAGE_PROPERTY_BUNDLE`.
const PROP_BUNDLE: u32 = 0x4;
/// The largest installed manifest read: as for a package file.
const MAX_MANIFEST: u64 = crate::package::MAX_METADATA_SIZE;

/// The signature kind for a `PackageOrigin_*` value.
const fn signature_kind(origin: i32) -> InstalledSignatureKind {
    match origin {
        1 | 4 => InstalledSignatureKind::None,
        2 => InstalledSignatureKind::System,
        3 => InstalledSignatureKind::Store,
        5 => InstalledSignatureKind::Developer,
        6 => InstalledSignatureKind::Enterprise,
        _ => InstalledSignatureKind::Unknown,
    }
}

/// The packages of `family` installed for the current user. A package
/// whose folder or manifest cannot be read, or whose manifest does not
/// give the OS's full name, is left out and the result marked
/// `incomplete`.
pub fn packages_of_family(family: &str) -> io::Result<InstalledPackages> {
    let mut out = InstalledPackages::default();
    for (full_name, props) in sys::packages_by_family(family, FILTERS)? {
        match read_package(&full_name, props) {
            Some(p) => out.packages.push(p),
            None => out.incomplete = true,
        }
    }
    Ok(out)
}

fn read_package(full_name: &str, props: u32) -> Option<InstalledPackage> {
    let folder = sys::package_path(full_name).ok()?;
    let location = super::fsctx::final_path(Path::new(&folder)).ok()?;
    let manifest_path = Path::new(&folder).join("AppxManifest.xml");
    let bytes = read_bounded(&manifest_path)?;
    let m = parse_package_manifest(&bytes).ok()?;
    let id = &m.identity;
    let mut p = InstalledPackage::from_identity(
        &id.name,
        &id.publisher,
        id.version,
        &id.arch,
        &id.resource_id,
    );
    // The manifest must be this package's: its identity gives exactly the
    // full name the OS reported (ASCII case aside, as the OS compares).
    if !p.full_name.eq_ignore_ascii_case(full_name) {
        return None;
    }
    p.install_location = Some(location);
    p.signature_kind =
        sys::package_origin(full_name).map_or(InstalledSignatureKind::Unknown, signature_kind);
    p.is_framework = props & PROP_FRAMEWORK != 0 || m.is_framework;
    p.is_resource_package = props & PROP_RESOURCE != 0 || m.is_resource_package;
    p.is_bundle = props & PROP_BUNDLE != 0;
    p.applications = m.applications;
    Some(p)
}

fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut out = Vec::new();
    f.take(MAX_MANIFEST + 1).read_to_end(&mut out).ok()?;
    (u64::try_from(out.len()).ok()? <= MAX_MANIFEST).then_some(out)
}

/// An app execution alias resolved against the packages of the family it
/// claims, installed for the current user: the package and the checked
/// executable path, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasTarget {
    /// The package that provides the alias.
    pub package: InstalledPackage,
    /// The application's `Id`.
    pub app_id: Option<String>,
    /// The executable, inside the package's install folder.
    pub executable: crate::fsctx::NormalizedPath,
}

impl From<ResolvedAlias<'_>> for AliasTarget {
    fn from(r: ResolvedAlias<'_>) -> Self {
        Self {
            package: r.package.clone(),
            app_id: r.application.id.clone(),
            executable: r.executable,
        }
    }
}

/// Resolves `alias` for the current user: see [`resolve_alias`]. `Err` of
/// [`io::Error`] if the OS could not be asked; `Ok(Err(_))` if it was, and
/// the alias does not check out.
pub fn resolve_alias_for_current_user(
    alias: &AppExecLink,
) -> io::Result<Result<AliasTarget, AliasError>> {
    let installed = packages_of_family(&alias.package_family_name)?;
    Ok(resolve_alias(alias, &installed).map(AliasTarget::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_map_to_signature_kinds() {
        assert_eq!(signature_kind(0), InstalledSignatureKind::Unknown);
        assert_eq!(signature_kind(1), InstalledSignatureKind::None);
        assert_eq!(signature_kind(2), InstalledSignatureKind::System);
        assert_eq!(signature_kind(3), InstalledSignatureKind::Store);
        assert_eq!(signature_kind(4), InstalledSignatureKind::None);
        assert_eq!(signature_kind(5), InstalledSignatureKind::Developer);
        assert_eq!(signature_kind(6), InstalledSignatureKind::Enterprise);
        assert_eq!(signature_kind(99), InstalledSignatureKind::Unknown);
    }

    #[test]
    fn a_family_that_is_not_installed_is_empty() {
        let p = packages_of_family("Palisade.NotInstalled_0000000000000").unwrap();
        assert!(p.packages.is_empty());
        assert!(!p.incomplete);
    }

    /// The package manager's alias (`winget.exe`), if the image has it:
    /// read as a reparse point and resolved against the OS. Skipped, with a
    /// note, on an image without it.
    #[test]
    fn a_real_alias_resolves() {
        let Some(local) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let [vendor, apps] = crate::package::os_ids::ALIAS_DIR;
        let aliases = Path::new(&local).join(vendor).join(apps);
        let Ok(entries) = std::fs::read_dir(&aliases) else {
            eprintln!("no {}: skipped", aliases.display());
            return;
        };
        let mut tried = 0;
        for e in entries.flatten() {
            let path = e.path();
            // The package manager's own alias: present on the CI images,
            // and its target is its package's declared executable.
            if !path
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("winget.exe"))
            {
                continue;
            }
            let Ok(link) = super::super::links::open_link_itself(&path) else {
                continue;
            };
            let Ok(Some(r)) = super::super::links::read_reparse(&link) else {
                continue;
            };
            let Some(alias) = r.app_exec_link() else {
                continue;
            };
            tried += 1;
            let resolved = resolve_alias_for_current_user(alias).unwrap();
            let target = resolved.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(target.package.contains(&target.executable));
            assert!(
                target
                    .package
                    .family_name
                    .eq_ignore_ascii_case(&alias.package_family_name)
            );
            // A forged target in the same alias does not resolve.
            let mut forged = alias.clone();
            forged.target_path = r"C:\Windows\System32\cmd.exe".into();
            assert_eq!(
                resolve_alias_for_current_user(&forged).unwrap(),
                Err(AliasError::TargetMismatch)
            );
        }
        eprintln!("{tried} app execution aliases resolved");
    }
}
