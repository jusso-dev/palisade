//! `AppxManifest.xml` and `AppxMetadata/AppxBundleManifest.xml`.
//!
//! Elements are matched by namespace URI and local name, so the prefix a
//! manifest uses does not matter. The package schema namespaces are listed
//! in [`ns`]; the "foundation" namespace (2010) and its successors carry
//! `Package`, `Identity`, `Properties`, `Applications`, `Capabilities`,
//! `Extensions` and `Dependencies`; the others add capability and extension
//! vocabularies, which are recorded with their namespace.

#![forbid(unsafe_code)]

use std::fmt;

use super::identity::PackageVersion;
use super::xml::{self, Element, XmlError};

/// Namespace URIs.
pub mod ns {
    /// The foundation namespace (the default in every package manifest).
    pub const FOUNDATION: &str = "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
    /// The 2010 package namespace, used by older packages.
    pub const APPX_2010: &str = "http://schemas.microsoft.com/appx/2010/manifest";
    /// The 2013 package namespace (Windows 8.1 packages).
    pub const APPX_2013: &str = "http://schemas.microsoft.com/appx/2013/manifest";
    /// The universal application platform namespace.
    pub const UAP: &str = "http://schemas.microsoft.com/appx/manifest/uap/windows10";
    /// Restricted capabilities.
    pub const RESCAP: &str =
        "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities";
    /// Desktop extensions.
    pub const DESKTOP: &str = "http://schemas.microsoft.com/appx/manifest/desktop/windows10";
    /// Bundle manifests (2013).
    pub const BUNDLE_2013: &str = "http://schemas.microsoft.com/appx/2013/bundle";
    /// Bundle manifests (2016 extensions).
    pub const BUNDLE_2016: &str = "http://schemas.microsoft.com/appx/2016/bundle";

    /// The namespaces whose `Package` element is a package manifest.
    pub const PACKAGE: [&str; 3] = [FOUNDATION, APPX_2010, APPX_2013];
    /// The namespaces whose `Bundle` element is a bundle manifest.
    pub const BUNDLE: [&str; 1] = [BUNDLE_2013];
    /// Namespaces whose `Bundle` children may also come from.
    pub const BUNDLE_ANY: [&str; 2] = [BUNDLE_2013, BUNDLE_2016];
}

/// Element and attribute values longer than this are refused.
pub const MAX_VALUE: usize = 4096;
/// The most applications, capabilities, extensions, dependencies or bundle
/// members kept.
pub const MAX_ITEMS: usize = 1024;

/// Why a manifest could not be used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ManifestError {
    /// The XML was refused.
    Xml(XmlError),
    /// The root is not a package (or bundle) manifest.
    NotManifest,
    /// No `Identity`, or more than one.
    Identity,
    /// A required identity attribute is missing or invalid.
    Attribute(&'static str),
    /// More than [`MAX_ITEMS`] of something.
    TooMany(&'static str),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(e) => e.fmt(f),
            Self::NotManifest => f.write_str("not a package manifest"),
            Self::Identity => f.write_str("the manifest must have exactly one Identity"),
            Self::Attribute(a) => write!(f, "Identity@{a} is missing or invalid"),
            Self::TooMany(what) => write!(f, "more than {MAX_ITEMS} {what}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// The `Identity` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `Name`.
    pub name: String,
    /// `Publisher`: the publisher DN string exactly as written.
    pub publisher: String,
    /// `Version`.
    pub version: PackageVersion,
    /// `ProcessorArchitecture`, lowercased; empty when absent (neutral).
    pub arch: String,
    /// `ResourceId`; empty when absent.
    pub resource_id: String,
}

/// One application.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Application {
    /// `Id`.
    pub id: Option<String>,
    /// `Executable`, relative to the package root.
    pub executable: Option<String>,
    /// `EntryPoint`.
    pub entry_point: Option<String>,
}

/// One capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// The namespace URI of the element.
    pub ns: String,
    /// The element's local name (`Capability`, `DeviceCapability`).
    pub element: String,
    /// `Name`.
    pub name: String,
}

impl Capability {
    /// Whether it is a restricted capability (`rescap:`).
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        self.ns == ns::RESCAP
    }
}

/// One extension (`Extension` element anywhere in the manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The namespace URI of the element.
    pub ns: String,
    /// `Category`, such as `windows.fullTrustProcess`,
    /// `windows.appExecutionAlias`, `windows.service`, `windows.comServer`.
    pub category: String,
    /// `Executable`, when present.
    pub executable: Option<String>,
    /// For an app execution alias: the alias file names.
    pub aliases: Vec<String>,
    /// The application `Id` it belongs to, if it is under one.
    pub application: Option<String>,
}

/// One dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// `TargetDeviceFamily` or `PackageDependency`.
    pub kind: String,
    /// `Name`.
    pub name: String,
    /// `Publisher` (package dependencies).
    pub publisher: Option<String>,
    /// `MinVersion`.
    pub min_version: Option<String>,
    /// `MaxVersionTested` (device families).
    pub max_version_tested: Option<String>,
}

/// A parsed package manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifest {
    /// The identity.
    pub identity: Identity,
    /// `Properties/DisplayName`.
    pub display_name: Option<String>,
    /// `Properties/PublisherDisplayName`.
    pub publisher_display_name: Option<String>,
    /// `Properties/Framework` is `true`.
    pub is_framework: bool,
    /// `Properties/ResourcePackage` is `true`.
    pub is_resource_package: bool,
    /// Applications.
    pub applications: Vec<Application>,
    /// Capabilities.
    pub capabilities: Vec<Capability>,
    /// Extensions.
    pub extensions: Vec<Extension>,
    /// Dependencies.
    pub dependencies: Vec<Dependency>,
}

impl PackageManifest {
    /// Whether the package declares the restricted `runFullTrust`
    /// capability.
    #[must_use]
    pub fn runs_full_trust(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.is_restricted() && c.name == "runFullTrust")
    }
}

/// One package listed in a bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMember {
    /// `Type`: `application` or `resource`.
    pub kind: String,
    /// `Version`.
    pub version: Option<PackageVersion>,
    /// `Architecture`, lowercased.
    pub arch: String,
    /// `ResourceId`.
    pub resource_id: String,
    /// `FileName`: the member's name in the bundle.
    pub file_name: String,
    /// `Offset`: where the member's data starts in the bundle file.
    pub offset: Option<u64>,
    /// `Size`.
    pub size: Option<u64>,
}

/// A parsed bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleManifest {
    /// The bundle identity (no architecture or resource ID).
    pub identity: Identity,
    /// The packages it lists.
    pub members: Vec<BundleMember>,
}

fn value(e: &Element, name: &'static str) -> Result<Option<String>, ManifestError> {
    match e.attr(name) {
        Some(v) if v.len() > MAX_VALUE => Err(ManifestError::Attribute(name)),
        Some(v) => Ok(Some(v.to_owned())),
        None => Ok(None),
    }
}

/// Identity names: 3 to 50 characters of `[A-Za-z0-9.-]`.
fn valid_name(n: &str) -> bool {
    (3..=50).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn identity(e: &Element, bundle: bool) -> Result<Identity, ManifestError> {
    let name = value(e, "Name")?
        .filter(|n| valid_name(n))
        .ok_or(ManifestError::Attribute("Name"))?;
    let publisher = value(e, "Publisher")?
        .filter(|p| !p.is_empty())
        .ok_or(ManifestError::Attribute("Publisher"))?;
    let version = value(e, "Version")?
        .as_deref()
        .and_then(PackageVersion::parse)
        .ok_or(ManifestError::Attribute("Version"))?;
    let arch = if bundle {
        String::new()
    } else {
        let a = value(e, "ProcessorArchitecture")?.unwrap_or_default();
        let lower = a.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "" | "x86" | "x64" | "arm" | "arm64" | "x86a64" | "neutral"
        ) {
            return Err(ManifestError::Attribute("ProcessorArchitecture"));
        }
        if lower == "neutral" {
            String::new()
        } else {
            lower
        }
    };
    let resource_id = if bundle {
        String::new()
    } else {
        value(e, "ResourceId")?.unwrap_or_default()
    };
    if resource_id.len() > 30
        || !resource_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(ManifestError::Attribute("ResourceId"));
    }
    Ok(Identity {
        name,
        publisher,
        version,
        arch,
        resource_id,
    })
}

fn the_identity(root: &Element, nss: &[&str], bundle: bool) -> Result<Identity, ManifestError> {
    let mut ids = root.children_named(nss, "Identity");
    let first = ids.next().ok_or(ManifestError::Identity)?;
    if ids.next().is_some() {
        return Err(ManifestError::Identity);
    }
    identity(first, bundle)
}

fn push<T>(list: &mut Vec<T>, item: T, what: &'static str) -> Result<(), ManifestError> {
    if list.len() >= MAX_ITEMS {
        return Err(ManifestError::TooMany(what));
    }
    list.push(item);
    Ok(())
}

/// Parses `AppxManifest.xml`.
pub fn parse_package_manifest(data: &[u8]) -> Result<PackageManifest, ManifestError> {
    let root = xml::parse(data).map_err(ManifestError::Xml)?;
    if root.name != "Package" || !ns::PACKAGE.contains(&root.ns.as_str()) {
        return Err(ManifestError::NotManifest);
    }
    let fnd = [root.ns.as_str()];
    let identity = the_identity(&root, &fnd, false)?;
    let props = root.child(&fnd, "Properties");
    let text = |name: &str| {
        props
            .and_then(|p| p.child(&fnd, name))
            .map(|e| e.text.trim().to_owned())
            .filter(|t| !t.is_empty() && t.len() <= MAX_VALUE)
    };
    let flag = |name: &str| text(name).is_some_and(|t| t.eq_ignore_ascii_case("true"));
    let mut out = PackageManifest {
        identity,
        display_name: text("DisplayName"),
        publisher_display_name: text("PublisherDisplayName"),
        is_framework: flag("Framework"),
        is_resource_package: flag("ResourcePackage"),
        applications: Vec::new(),
        capabilities: Vec::new(),
        extensions: Vec::new(),
        dependencies: Vec::new(),
    };
    if let Some(apps) = root.child(&fnd, "Applications") {
        for app in apps.children_named(&fnd, "Application") {
            let a = Application {
                id: value(app, "Id")?,
                executable: value(app, "Executable")?,
                entry_point: value(app, "EntryPoint")?,
            };
            let app_id = a.id.clone();
            push(&mut out.applications, a, "applications")?;
            collect_extensions(app, app_id.as_deref(), &mut out.extensions)?;
        }
    }
    collect_extensions(&root, None, &mut out.extensions)?;
    if let Some(caps) = root.child(&fnd, "Capabilities") {
        for c in &caps.children {
            if let Some(name) = value(c, "Name")? {
                let cap = Capability {
                    ns: c.ns.clone(),
                    element: c.name.clone(),
                    name,
                };
                push(&mut out.capabilities, cap, "capabilities")?;
            }
        }
    }
    if let Some(deps) = root.child(&fnd, "Dependencies") {
        for d in &deps.children {
            let Some(name) = value(d, "Name")? else {
                continue;
            };
            let dep = Dependency {
                kind: d.name.clone(),
                name,
                publisher: value(d, "Publisher")?,
                min_version: value(d, "MinVersion")?,
                max_version_tested: value(d, "MaxVersionTested")?,
            };
            push(&mut out.dependencies, dep, "dependencies")?;
        }
    }
    Ok(out)
}

/// Every `Extension` directly under an `Extensions` child of `parent`.
fn collect_extensions(
    parent: &Element,
    app: Option<&str>,
    out: &mut Vec<Extension>,
) -> Result<(), ManifestError> {
    for exts in parent.children.iter().filter(|c| c.name == "Extensions") {
        for e in exts.children.iter().filter(|c| c.name == "Extension") {
            let Some(category) = value(e, "Category")? else {
                continue;
            };
            let mut aliases = Vec::new();
            for d in e.descendants() {
                if d.name == "ExecutionAlias" {
                    if let Some(a) = value(d, "Alias")? {
                        push(&mut aliases, a, "aliases")?;
                    }
                }
            }
            let ext = Extension {
                ns: e.ns.clone(),
                category,
                executable: value(e, "Executable")?,
                aliases,
                application: app.map(str::to_owned),
            };
            push(out, ext, "extensions")?;
        }
    }
    Ok(())
}

/// Parses `AppxMetadata/AppxBundleManifest.xml`.
pub fn parse_bundle_manifest(data: &[u8]) -> Result<BundleManifest, ManifestError> {
    let root = xml::parse(data).map_err(ManifestError::Xml)?;
    if root.name != "Bundle" || !ns::BUNDLE.contains(&root.ns.as_str()) {
        return Err(ManifestError::NotManifest);
    }
    let identity = the_identity(&root, &ns::BUNDLE_ANY, true)?;
    let mut members = Vec::new();
    if let Some(packages) = root.child(&ns::BUNDLE_ANY, "Packages") {
        for p in packages.children_named(&ns::BUNDLE_ANY, "Package") {
            let Some(file_name) = value(p, "FileName")? else {
                continue;
            };
            let num = |n: &'static str| -> Result<Option<u64>, ManifestError> {
                value(p, n)?
                    .map(|v| v.parse::<u64>().map_err(|_| ManifestError::Attribute(n)))
                    .transpose()
            };
            let m = BundleMember {
                kind: value(p, "Type")?.unwrap_or_else(|| "application".into()),
                version: value(p, "Version")?
                    .as_deref()
                    .and_then(PackageVersion::parse),
                arch: value(p, "Architecture")?
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                resource_id: value(p, "ResourceId")?.unwrap_or_default(),
                file_name,
                offset: num("Offset")?,
                size: num("Size")?,
            };
            push(&mut members, m, "bundle members")?;
        }
    }
    Ok(BundleManifest { identity, members })
}
