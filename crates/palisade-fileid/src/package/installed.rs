//! Installed packages (#333): the model the Windows backend fills, mapping
//! an executable to the installed package that owns it, and resolving an
//! app execution alias against it.
//!
//! Everything here is pure, so it is tested on every OS. The OS reads
//! (enumerating packages, their install folders and manifests) are in
//! `palisade_fileid::win::packages`, behind the `os-trust` feature.
//!
//! # Trust
//!
//! An [`InstalledPackage`] is only as good as its source. The Windows
//! backend fills the identity from the OS's own package records, not from
//! anything a user can write, and reads the applications from the
//! installed manifest. An install folder is a claim about where the
//! package's files live: an executable is mapped to a package only when its
//! **final path** (links resolved) is inside that folder, compared through
//! [`crate::fsctx::NormalizedPath::starts_with`], so a junction or a
//! case-sensitive folder cannot make another file look like the package's.
//!
//! An app execution alias ([`crate::fsctx::reparse::AppExecLink`]) is
//! entirely its creator's claim. [`resolve_alias`] accepts it only when
//! every claim checks out against the installed packages: a package of
//! that family is installed, the app user model ID names that family and
//! one of its applications, and the target path is that application's
//! executable inside the package's install folder. Anything else is an
//! [`AliasError`], never a guess (ADR 0018).

#![forbid(unsafe_code)]

use std::fmt;

use super::identity::{PackageVersion, family_name, full_name, publisher_id};
use super::manifest::Application;
use crate::fsctx::NormalizedPath;
use crate::fsctx::reparse::AppExecLink;

/// How a package was signed, as the OS records it for an installed
/// package (`PackageOrigin` and the `SignatureKind` of the package
/// manager).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InstalledSignatureKind {
    /// Not signed (a development registration).
    None,
    /// Signed by a developer certificate.
    Developer,
    /// Signed by an enterprise certificate (line of business).
    Enterprise,
    /// Signed by the store.
    Store,
    /// Part of the OS.
    System,
    /// The OS did not say, or said something this crate does not know.
    Unknown,
}

/// One installed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    /// The package full name, as the OS reports it.
    pub full_name: String,
    /// The package family name.
    pub family_name: String,
    /// `Identity@Name`.
    pub name: String,
    /// `Identity@Publisher`.
    pub publisher: String,
    /// The 13-character publisher ID.
    pub publisher_id: String,
    /// The version.
    pub version: PackageVersion,
    /// The architecture, lowercased (`neutral` for none).
    pub arch: String,
    /// The resource ID; empty when none.
    pub resource_id: String,
    /// The install folder, as a final path. `None` if the OS gave none
    /// (a package being removed, say): such a package owns no file.
    pub install_location: Option<NormalizedPath>,
    /// How the package was signed.
    pub signature_kind: InstalledSignatureKind,
    /// A framework package.
    pub is_framework: bool,
    /// A bundle.
    pub is_bundle: bool,
    /// A stub package (installed as a placeholder for the full app).
    /// `None` when the source cannot tell (the flat OS API does not say).
    pub is_stub: Option<bool>,
    /// A resource package.
    pub is_resource_package: bool,
    /// The SIDs of the users it is installed for, as strings. Empty when
    /// the enumeration could not tell (a per-user enumeration lists only
    /// the current user).
    pub users: Vec<String>,
    /// The applications from the installed manifest. Empty if the manifest
    /// could not be read, and then no alias resolves to the package.
    pub applications: Vec<Application>,
}

impl InstalledPackage {
    /// A package with identity fields filled from the parts, the publisher
    /// ID, family name and full name derived as the OS derives them, and
    /// everything else empty.
    #[must_use]
    pub fn from_identity(
        name: &str,
        publisher: &str,
        version: PackageVersion,
        arch: &str,
        resource_id: &str,
    ) -> Self {
        let pid = publisher_id(publisher);
        Self {
            full_name: full_name(name, version, arch, resource_id, &pid),
            family_name: family_name(name, &pid),
            name: name.to_owned(),
            publisher: publisher.to_owned(),
            publisher_id: pid,
            version,
            arch: if arch.is_empty() {
                "neutral".to_owned()
            } else {
                arch.to_ascii_lowercase()
            },
            resource_id: resource_id.to_owned(),
            install_location: None,
            signature_kind: InstalledSignatureKind::Unknown,
            is_framework: false,
            is_bundle: false,
            is_stub: None,
            is_resource_package: false,
            users: Vec::new(),
            applications: Vec::new(),
        }
    }

    /// Whether the identity fields agree with each other: the publisher ID,
    /// family name and full name are what the name, publisher, version,
    /// architecture and resource ID give. A record that fails this was not
    /// filled consistently and must not be trusted.
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        let pid = publisher_id(&self.publisher);
        pid == self.publisher_id
            && family_name(&self.name, &pid) == self.family_name
            && full_name(
                &self.name,
                self.version,
                &self.arch,
                &self.resource_id,
                &pid,
            ) == self.full_name
    }

    /// Whether `path` (a final path) is inside the install folder.
    #[must_use]
    pub fn contains(&self, path: &NormalizedPath) -> bool {
        self.install_location
            .as_ref()
            .is_some_and(|root| path.starts_with(root))
    }

    /// The application whose `Id` is `app_id`, ASCII case-insensitively as
    /// the OS compares application IDs.
    #[must_use]
    pub fn application(&self, app_id: &str) -> Option<&Application> {
        self.applications.iter().find(|a| {
            a.id.as_deref()
                .is_some_and(|id| id.eq_ignore_ascii_case(app_id))
        })
    }
}

/// The installed packages, as one enumeration saw them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstalledPackages {
    /// The packages.
    pub packages: Vec<InstalledPackage>,
    /// True if the enumeration stopped early or skipped packages it could
    /// not read, so a package that is not listed may still be installed.
    pub incomplete: bool,
}

/// Why an executable has no owning package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerLookup<'a> {
    /// The one package whose install folder holds the path.
    Owned(&'a InstalledPackage),
    /// No listed package holds it. With an incomplete enumeration this is
    /// not proof that none does.
    NotOwned {
        /// The enumeration was incomplete.
        incomplete: bool,
    },
    /// More than one package's install folder holds it (nested folders, or
    /// two records for one folder): no single owner can be named.
    Ambiguous(Vec<&'a InstalledPackage>),
}

impl InstalledPackages {
    /// The installed package that owns the executable at `final_path`:
    /// the one whose install folder holds it. Only consistent records
    /// ([`InstalledPackage::is_consistent`]) count.
    ///
    /// `final_path` must be the opened file's final path (links resolved),
    /// never a name as written.
    #[must_use]
    pub fn owner_of(&self, final_path: &NormalizedPath) -> OwnerLookup<'_> {
        let hits: Vec<&InstalledPackage> = self
            .packages
            .iter()
            .filter(|p| p.is_consistent() && p.contains(final_path))
            .collect();
        match hits.as_slice() {
            [] => OwnerLookup::NotOwned {
                incomplete: self.incomplete,
            },
            [one] => OwnerLookup::Owned(one),
            _ => OwnerLookup::Ambiguous(hits),
        }
    }

    /// The installed packages of `family`, ASCII case-insensitively.
    pub fn by_family<'a>(&'a self, family: &'a str) -> impl Iterator<Item = &'a InstalledPackage> {
        self.packages
            .iter()
            .filter(move |p| p.is_consistent() && p.family_name.eq_ignore_ascii_case(family))
    }
}

/// Why an app execution alias did not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AliasError {
    /// The app user model ID is not `<family>!<app id>`, or names a
    /// different family from the alias's own.
    BadAppUserModelId,
    /// No installed package has the alias's family name.
    NotInstalled {
        /// The enumeration was incomplete, so it may be installed.
        incomplete: bool,
    },
    /// No package of the family has an application with the alias's app ID.
    NoSuchApplication,
    /// The target path cannot be normalised.
    BadTarget,
    /// The target path is not the application's executable in the package's
    /// install folder.
    TargetMismatch,
    /// More than one installed package of the family matches.
    Ambiguous,
}

impl fmt::Display for AliasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadAppUserModelId => {
                f.write_str("the app user model ID does not match the alias")
            }
            Self::NotInstalled { incomplete: false } => {
                f.write_str("no installed package has the alias's family name")
            }
            Self::NotInstalled { incomplete: true } => f.write_str(
                "no listed package has the alias's family name (the list is incomplete)",
            ),
            Self::NoSuchApplication => f.write_str("the package has no such application"),
            Self::BadTarget => f.write_str("the alias's target is not a valid path"),
            Self::TargetMismatch => {
                f.write_str("the alias's target is not the application's executable")
            }
            Self::Ambiguous => f.write_str("more than one installed package matches the alias"),
        }
    }
}

impl std::error::Error for AliasError {}

/// An app execution alias checked against the installed packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAlias<'a> {
    /// The package that provides it.
    pub package: &'a InstalledPackage,
    /// The application.
    pub application: &'a Application,
    /// The executable, inside the package's install folder.
    pub executable: NormalizedPath,
}

/// Resolves the app execution alias `alias` against `installed`: see the
/// module documentation. The alias resolves only if every claim it makes
/// checks out.
pub fn resolve_alias<'a>(
    alias: &AppExecLink,
    installed: &'a InstalledPackages,
) -> Result<ResolvedAlias<'a>, AliasError> {
    let (aumid_family, app_id) = alias
        .app_user_model_id
        .split_once('!')
        .ok_or(AliasError::BadAppUserModelId)?;
    if app_id.is_empty()
        || app_id.contains('!')
        || !aumid_family.eq_ignore_ascii_case(&alias.package_family_name)
    {
        return Err(AliasError::BadAppUserModelId);
    }
    let target =
        crate::fsctx::normalize_win32(&alias.target_path).map_err(|_| AliasError::BadTarget)?;
    let family: Vec<&'a InstalledPackage> = installed
        .packages
        .iter()
        .filter(|p| {
            p.is_consistent()
                && p.family_name
                    .eq_ignore_ascii_case(&alias.package_family_name)
        })
        .collect();
    if family.is_empty() {
        return Err(AliasError::NotInstalled {
            incomplete: installed.incomplete,
        });
    }
    let mut with_app = false;
    let mut found: Vec<ResolvedAlias<'a>> = Vec::new();
    for package in family {
        let Some(application) = package.application(app_id) else {
            continue;
        };
        with_app = true;
        let Some(root) = &package.install_location else {
            continue;
        };
        let Some(executable) = application
            .executable
            .as_deref()
            .and_then(|e| join(root, e))
        else {
            continue;
        };
        if same_path(&target, &executable) && target.starts_with(root) {
            found.push(ResolvedAlias {
                package,
                application,
                executable,
            });
        }
    }
    match found.len() {
        0 if with_app => Err(AliasError::TargetMismatch),
        0 => Err(AliasError::NoSuchApplication),
        1 => found.pop().ok_or(AliasError::Ambiguous),
        _ => Err(AliasError::Ambiguous),
    }
}

/// `root` joined with the manifest-relative `rel` (`\` or `/` separated).
/// `None` if `rel` is absolute, climbs out (`..`), or the result does not
/// normalise.
fn join(root: &NormalizedPath, rel: &str) -> Option<NormalizedPath> {
    let parts: Vec<&str> = rel.split(['\\', '/']).collect();
    if rel.is_empty()
        || rel.contains(':')
        || parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return None;
    }
    let mut text = root.to_win32_string();
    for p in parts {
        if !text.ends_with('\\') {
            text.push('\\');
        }
        text.push_str(p);
    }
    let joined = crate::fsctx::normalize_win32(&text).ok()?;
    joined.starts_with(root).then_some(joined)
}

/// Whether two paths are the same, by [`NormalizedPath::starts_with`] both
/// ways (so case sensitivity read for either applies).
fn same_path(a: &NormalizedPath, b: &NormalizedPath) -> bool {
    a.components().len() == b.components().len() && a.starts_with(b) && b.starts_with(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsctx::normalize_win32;

    const PUBLISHER: &str = "CN=Palisade Test Package Signer, O=Palisade Tests";

    fn app(id: &str, exe: &str) -> Application {
        Application {
            id: Some(id.to_owned()),
            executable: Some(exe.to_owned()),
            entry_point: None,
        }
    }

    fn package(name: &str, version: PackageVersion, folder: &str) -> InstalledPackage {
        let mut p = InstalledPackage::from_identity(name, PUBLISHER, version, "x64", "");
        p.install_location = Some(normalize_win32(folder).unwrap());
        p.applications = vec![app("App", r"bin\tool.exe")];
        p
    }

    fn installed() -> InstalledPackages {
        InstalledPackages {
            packages: vec![
                package(
                    "Palisade.Tool",
                    PackageVersion(1, 0, 0, 0),
                    r"C:\Program Files\WindowsApps\Palisade.Tool_1.0.0.0_x64__abc",
                ),
                package(
                    "Palisade.Other",
                    PackageVersion(2, 0, 0, 0),
                    r"C:\Program Files\WindowsApps\Palisade.Other_2.0.0.0_x64__abc",
                ),
            ],
            incomplete: false,
        }
    }

    fn alias(family: &str, aumid: &str, target: &str) -> AppExecLink {
        AppExecLink {
            version: 3,
            package_family_name: family.to_owned(),
            app_user_model_id: aumid.to_owned(),
            target_path: target.to_owned(),
            extra: Vec::new(),
        }
    }

    #[test]
    fn identity_is_derived_and_checked() {
        let p = InstalledPackage::from_identity(
            "Palisade.Tool",
            PUBLISHER,
            PackageVersion(1, 2, 3, 4),
            "X64",
            "",
        );
        assert_eq!(p.arch, "x64");
        assert_eq!(p.family_name, format!("Palisade.Tool_{}", p.publisher_id));
        assert!(p.full_name.starts_with("Palisade.Tool_1.2.3.4_x64__"));
        assert!(p.is_consistent());
        let neutral =
            InstalledPackage::from_identity("A", PUBLISHER, PackageVersion(1, 0, 0, 0), "", "");
        assert_eq!(neutral.arch, "neutral");
        assert!(neutral.is_consistent());
        // A record whose family name does not follow from its identity.
        let mut forged = p.clone();
        forged.family_name = "Palisade.Tool_8wekyb3d8bbwe".into();
        assert!(!forged.is_consistent());
        let mut forged = p;
        forged.publisher = "CN=Someone Else".into();
        assert!(!forged.is_consistent());
    }

    #[test]
    fn executables_map_to_their_package() {
        let all = installed();
        let exe = normalize_win32(
            r"C:\Program Files\WindowsApps\Palisade.Tool_1.0.0.0_x64__abc\bin\tool.exe",
        )
        .unwrap();
        match all.owner_of(&exe) {
            OwnerLookup::Owned(p) => assert_eq!(p.name, "Palisade.Tool"),
            other => panic!("{other:?}"),
        }
        // Case-insensitively on an ordinary folder.
        let lower = normalize_win32(
            r"c:\program files\windowsapps\palisade.tool_1.0.0.0_x64__abc\BIN\TOOL.EXE",
        )
        .unwrap();
        assert!(matches!(all.owner_of(&lower), OwnerLookup::Owned(_)));
        // A sibling folder whose name only starts the same.
        let sibling = normalize_win32(
            r"C:\Program Files\WindowsApps\Palisade.Tool_1.0.0.0_x64__abcd\tool.exe",
        )
        .unwrap();
        assert_eq!(
            all.owner_of(&sibling),
            OwnerLookup::NotOwned { incomplete: false }
        );
        // An incomplete list says so.
        let partial = InstalledPackages {
            incomplete: true,
            ..all.clone()
        };
        assert_eq!(
            partial.owner_of(&sibling),
            OwnerLookup::NotOwned { incomplete: true }
        );
        // Two packages claiming one folder: ambiguous, never the first.
        let mut twice = all.clone();
        let mut copy = twice.packages[0].clone();
        copy.version = PackageVersion(1, 0, 0, 1);
        copy.full_name = full_name(
            &copy.name,
            copy.version,
            &copy.arch,
            &copy.resource_id,
            &copy.publisher_id,
        );
        twice.packages.push(copy);
        assert!(matches!(twice.owner_of(&exe), OwnerLookup::Ambiguous(v) if v.len() == 2));
        // An inconsistent record owns nothing.
        let mut forged = all.clone();
        forged.packages[0].family_name = "Forged_abc".into();
        assert_eq!(
            forged.owner_of(&exe),
            OwnerLookup::NotOwned { incomplete: false }
        );
        // A package with no install folder owns nothing.
        let mut nowhere = all;
        nowhere.packages[0].install_location = None;
        assert_eq!(
            nowhere.owner_of(&exe),
            OwnerLookup::NotOwned { incomplete: false }
        );
    }

    #[test]
    fn aliases_resolve_only_when_every_claim_checks_out() {
        let all = installed();
        let tool = &all.packages[0];
        let fam = tool.family_name.clone();
        let target = r"C:\Program Files\WindowsApps\Palisade.Tool_1.0.0.0_x64__abc\bin\tool.exe";
        let good = alias(&fam, &format!("{fam}!App"), target);
        let r = resolve_alias(&good, &all).unwrap();
        assert_eq!(r.package.name, "Palisade.Tool");
        assert_eq!(r.application.id.as_deref(), Some("App"));
        assert_eq!(r.executable.match_key().unwrap(), target.to_uppercase());
        // App IDs and families compare ignoring ASCII case.
        let loud = alias(
            &fam.to_uppercase(),
            &format!("{}!app", fam.to_uppercase()),
            target,
        );
        assert!(resolve_alias(&loud, &all).is_ok());

        // Each claim that does not check out.
        let cases = [
            (
                alias(&fam, "no-bang", target),
                AliasError::BadAppUserModelId,
            ),
            (
                alias(&fam, &format!("{fam}!"), target),
                AliasError::BadAppUserModelId,
            ),
            (
                alias(&fam, &format!("{fam}!App!x"), target),
                AliasError::BadAppUserModelId,
            ),
            (
                alias(&fam, "Other_abc!App", target),
                AliasError::BadAppUserModelId,
            ),
            (
                alias("Missing_abc", "Missing_abc!App", target),
                AliasError::NotInstalled { incomplete: false },
            ),
            (
                alias(&fam, &format!("{fam}!Nope"), target),
                AliasError::NoSuchApplication,
            ),
            (
                alias(&fam, &format!("{fam}!App"), r"C:\Users\Public\tool.exe"),
                AliasError::TargetMismatch,
            ),
            (
                alias(
                    &fam,
                    &format!("{fam}!App"),
                    r"C:\Program Files\WindowsApps\Palisade.Other_2.0.0.0_x64__abc\bin\tool.exe",
                ),
                AliasError::TargetMismatch,
            ),
            (
                alias(&fam, &format!("{fam}!App"), "relative\\tool.exe"),
                AliasError::BadTarget,
            ),
        ];
        for (a, want) in cases {
            assert_eq!(resolve_alias(&a, &all), Err(want.clone()), "{a:?}");
            assert!(!want.to_string().is_empty());
        }
        // An incomplete list says the package may still be installed.
        let partial = InstalledPackages {
            incomplete: true,
            ..all.clone()
        };
        assert_eq!(
            resolve_alias(&alias("Missing_abc", "Missing_abc!App", target), &partial),
            Err(AliasError::NotInstalled { incomplete: true })
        );
        assert!(
            AliasError::NotInstalled { incomplete: true }
                .to_string()
                .contains("incomplete")
        );

        // Two versions of the family both providing it: ambiguous.
        let mut twice = all.clone();
        let mut v2 = tool.clone();
        v2.version = PackageVersion(1, 0, 0, 1);
        v2.full_name = full_name(&v2.name, v2.version, &v2.arch, "", &v2.publisher_id);
        twice.packages.push(v2);
        assert_eq!(resolve_alias(&good, &twice), Err(AliasError::Ambiguous));

        // A package of the family without an install folder: its app is
        // known, but the target cannot be checked.
        let mut nowhere = all;
        nowhere.packages[0].install_location = None;
        assert_eq!(
            resolve_alias(&good, &nowhere),
            Err(AliasError::TargetMismatch)
        );
    }

    #[test]
    fn manifest_executables_cannot_climb_out() {
        let root = normalize_win32(r"C:\Apps\P").unwrap();
        assert!(join(&root, r"bin\a.exe").is_some());
        assert!(join(&root, "bin/a.exe").is_some());
        for bad in [
            "",
            r"..\a.exe",
            r"bin\..\..\a.exe",
            r"C:\a.exe",
            r"\a.exe",
            r"bin\\a.exe",
            r".\a.exe",
        ] {
            assert_eq!(join(&root, bad), None, "{bad}");
        }
        // An application with a climbing executable never resolves.
        let mut all = installed();
        all.packages[0].applications = vec![app("App", r"..\evil.exe")];
        let fam = all.packages[0].family_name.clone();
        let a = alias(
            &fam,
            &format!("{fam}!App"),
            r"C:\Program Files\WindowsApps\evil.exe",
        );
        assert_eq!(resolve_alias(&a, &all), Err(AliasError::TargetMismatch));
        // An application with no executable never resolves either.
        all.packages[0].applications = vec![Application {
            id: Some("App".into()),
            executable: None,
            entry_point: None,
        }];
        assert_eq!(resolve_alias(&a, &all), Err(AliasError::TargetMismatch));
    }
}
