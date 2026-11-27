//! Identifiers that Windows itself defines and requires byte for byte.
//!
//! Package manifests, bundle manifests and block maps are only recognised
//! in fixed XML namespaces, and those namespace URIs contain the operating
//! system vendor's name, which `docs/NAMING.md` otherwise keeps out of the
//! repository. Like `xtask/src/dist/os_ids.rs`, this is the only file in
//! the crate that holds them, so the banned-terms check can allow exactly
//! one path. Everything else, tests included, uses these constants.

/// The foundation namespace (the default in every package manifest).
pub const FOUNDATION: &str = "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
/// The 2010 package namespace, used by older packages.
pub const APPX_2010: &str = "http://schemas.microsoft.com/appx/2010/manifest";
/// The 2013 package namespace (Windows 8.1 packages).
pub const APPX_2013: &str = "http://schemas.microsoft.com/appx/2013/manifest";
/// The universal application platform namespace.
pub const UAP: &str = "http://schemas.microsoft.com/appx/manifest/uap/windows10";
/// The universal application platform namespace, version 3 (app
/// execution aliases).
pub const UAP3: &str = "http://schemas.microsoft.com/appx/manifest/uap/windows10/3";
/// Restricted capabilities.
pub const RESCAP: &str =
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities";
/// Desktop extensions.
pub const DESKTOP: &str = "http://schemas.microsoft.com/appx/manifest/desktop/windows10";
/// Bundle manifests (2013).
pub const BUNDLE_2013: &str = "http://schemas.microsoft.com/appx/2013/bundle";
/// Bundle manifests (2016 extensions).
pub const BUNDLE_2016: &str = "http://schemas.microsoft.com/appx/2016/bundle";
/// The block map namespace.
pub const BLOCK_MAP: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
