//! The application manifest (`RT_MANIFEST`, #45): requested execution
//! level, UI access, auto-elevation, DPI awareness, assembly identity and
//! supported OS GUIDs.
//!
//! The manifest is untrusted XML. [`parse_manifest`] uses `quick-xml`, a
//! streaming parser that never expands entities defined in a DTD: only the
//! five predefined entities and character references are resolved, and
//! anything else is an error. A document with a `<!DOCTYPE>` is rejected
//! outright, so no entity definition is ever read. Input size, nesting
//! depth, element count and string lengths are bounded
//! ([`MAX_MANIFEST_SIZE`], [`MAX_DEPTH`], [`MAX_ELEMENTS`],
//! [`MAX_VALUE_LEN`]).
//!
//! Elements are matched by local name, ignoring namespace prefixes, and
//! values are compared ASCII case-insensitively where the OS does
//! (`requireAdministrator`, `true`). The first occurrence of each setting
//! wins.
//!
//! [`requires_elevation`] is the #45 heuristic for whether starting the
//! file will ask for administrator rights.

#![forbid(unsafe_code)]

use std::fmt;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// Manifests larger than this are not parsed.
pub const MAX_MANIFEST_SIZE: usize = 256 * 1024;
/// The deepest element nesting accepted.
pub const MAX_DEPTH: usize = 32;
/// At most this many elements are read.
pub const MAX_ELEMENTS: usize = 4096;
/// Attribute values and text longer than this many bytes are cut off.
pub const MAX_VALUE_LEN: usize = 1024;
/// At most this many `supportedOS` GUIDs are kept.
pub const MAX_SUPPORTED_OS: usize = 64;

/// The `requestedExecutionLevel` `level`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExecutionLevel {
    /// `asInvoker`: runs with the caller's token.
    AsInvoker,
    /// `highestAvailable`: elevates if the user can.
    HighestAvailable,
    /// `requireAdministrator`: always asks for administrator rights.
    RequireAdministrator,
    /// Any other value, as written.
    Other(String),
}

impl ExecutionLevel {
    fn parse(value: &str) -> Self {
        if value.eq_ignore_ascii_case("asInvoker") {
            Self::AsInvoker
        } else if value.eq_ignore_ascii_case("highestAvailable") {
            Self::HighestAvailable
        } else if value.eq_ignore_ascii_case("requireAdministrator") {
            Self::RequireAdministrator
        } else {
            Self::Other(value.to_owned())
        }
    }
}

/// The manifest's `assemblyIdentity`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AssemblyIdentity {
    /// `name`.
    pub name: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `processorArchitecture`.
    pub processor_architecture: Option<String>,
    /// `publicKeyToken`.
    pub public_key_token: Option<String>,
    /// `type`.
    pub kind: Option<String>,
}

/// What [`parse_manifest`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// `requestedExecutionLevel` `level`.
    pub execution_level: Option<ExecutionLevel>,
    /// `requestedExecutionLevel` `uiAccess`.
    pub ui_access: Option<bool>,
    /// The `autoElevate` setting.
    pub auto_elevate: Option<bool>,
    /// The `dpiAware` setting, as written (`true`, `per monitor`, ...).
    pub dpi_aware: Option<String>,
    /// The `dpiAwareness` setting, as written.
    pub dpi_awareness: Option<String>,
    /// The first `assemblyIdentity` (the manifest's own, not a
    /// dependency's).
    pub identity: Option<AssemblyIdentity>,
    /// `supportedOS` `Id` GUIDs, in document order, at most
    /// [`MAX_SUPPORTED_OS`].
    pub supported_os: Vec<String>,
    /// A limit was reached, so some of the document was not read.
    pub truncated: bool,
}

/// Why a manifest could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestError {
    /// Larger than [`MAX_MANIFEST_SIZE`].
    TooLarge(usize),
    /// Not valid UTF-8 (after any UTF-8 byte order mark), or UTF-16, which
    /// is not supported.
    NotUtf8,
    /// It has a `<!DOCTYPE>`, which manifests never need and which could
    /// define entities.
    DocType,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The XML is malformed, or uses an undefined entity.
    Xml(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(n) => write!(f, "manifest of {n} bytes is over the limit"),
            Self::NotUtf8 => f.write_str("manifest is not UTF-8"),
            Self::DocType => f.write_str("manifest has a DOCTYPE"),
            Self::TooDeep => f.write_str("manifest is nested too deeply"),
            Self::Xml(e) => write!(f, "manifest is not well-formed XML: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Cuts `s` to at most [`MAX_VALUE_LEN`] bytes, on a character boundary.
fn bounded(mut s: String) -> String {
    if s.len() > MAX_VALUE_LEN {
        let mut end = MAX_VALUE_LEN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

fn local_name(e: &BytesStart<'_>) -> Vec<u8> {
    e.local_name().as_ref().to_vec()
}

/// The unescaped value of attribute `name` (local name, ASCII
/// case-insensitive).
fn attr(e: &BytesStart<'_>, name: &str) -> Result<Option<String>, ManifestError> {
    for a in e.attributes() {
        let a = a.map_err(|err| ManifestError::Xml(err.to_string()))?;
        if a.key
            .local_name()
            .as_ref()
            .eq_ignore_ascii_case(name.as_bytes())
        {
            // Only the five predefined entities resolve (one level deep);
            // anything else is an error.
            let v = a
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|err| ManifestError::Xml(err.to_string()))?;
            return Ok(Some(bounded(v.into_owned())));
        }
    }
    Ok(None)
}

fn parse_bool(value: &str) -> Option<bool> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("true") {
        Some(true)
    } else if v.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// Which text-valued setting the current element holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TextField {
    AutoElevate,
    DpiAware,
    DpiAwareness,
}

/// Parses a manifest resource.
pub fn parse_manifest(data: &[u8]) -> Result<Manifest, ManifestError> {
    if data.len() > MAX_MANIFEST_SIZE {
        return Err(ManifestError::TooLarge(data.len()));
    }
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        return Err(ManifestError::NotUtf8);
    }
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let text = std::str::from_utf8(data).map_err(|_| ManifestError::NotUtf8)?;
    let mut reader = Reader::from_str(text);
    let config = reader.config_mut();
    config.trim_text(true);
    config.check_end_names = true;

    let mut out = Manifest::default();
    let mut depth = 0_usize;
    let mut elements = 0_usize;
    let mut text_field: Option<TextField> = None;
    let mut text = String::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|e| ManifestError::Xml(e.to_string()))?;
        match event {
            Event::DocType(_) => return Err(ManifestError::DocType),
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                elements += 1;
                if elements > MAX_ELEMENTS {
                    out.truncated = true;
                    break;
                }
                if !empty {
                    depth += 1;
                    if depth > MAX_DEPTH {
                        return Err(ManifestError::TooDeep);
                    }
                }
                element(e, &mut out)?;
                if !empty {
                    text_field = match local_name(e).as_slice() {
                        b"autoElevate" => Some(TextField::AutoElevate),
                        b"dpiAware" => Some(TextField::DpiAware),
                        b"dpiAwareness" => Some(TextField::DpiAwareness),
                        _ => None,
                    };
                    text.clear();
                }
            }
            Event::Text(t) => {
                if text_field.is_some() && text.len() < MAX_VALUE_LEN {
                    let raw = t.decode().map_err(|e| ManifestError::Xml(e.to_string()))?;
                    let resolved = quick_xml::escape::unescape(&raw)
                        .map_err(|e| ManifestError::Xml(e.to_string()))?;
                    text.push_str(&resolved);
                }
            }
            Event::GeneralRef(r) => {
                // Only character references and the five predefined
                // entities are accepted; anything else is undefined.
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    Ok(None) => {
                        let name = r.decode().map_err(|e| ManifestError::Xml(e.to_string()))?;
                        quick_xml::escape::resolve_predefined_entity(&name)
                            .ok_or_else(|| {
                                ManifestError::Xml(format!("undefined entity &{name};"))
                            })?
                            .to_owned()
                    }
                    Err(e) => return Err(ManifestError::Xml(e.to_string())),
                };
                if text_field.is_some() && text.len() < MAX_VALUE_LEN {
                    text.push_str(&resolved);
                }
            }
            Event::End(_) => {
                depth = depth.saturating_sub(1);
                if let Some(field) = text_field.take() {
                    let value = bounded(text.trim().to_owned());
                    match field {
                        TextField::AutoElevate => {
                            if out.auto_elevate.is_none() {
                                out.auto_elevate = parse_bool(&value);
                            }
                        }
                        TextField::DpiAware => {
                            out.dpi_aware.get_or_insert(value);
                        }
                        TextField::DpiAwareness => {
                            out.dpi_awareness.get_or_insert(value);
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out)
}

fn element(e: &BytesStart<'_>, out: &mut Manifest) -> Result<(), ManifestError> {
    match local_name(e).as_slice() {
        b"requestedExecutionLevel" => {
            if out.execution_level.is_none() {
                out.execution_level = attr(e, "level")?.map(|v| ExecutionLevel::parse(v.trim()));
                out.ui_access = attr(e, "uiAccess")?.and_then(|v| parse_bool(&v));
            }
        }
        b"assemblyIdentity" => {
            if out.identity.is_none() {
                out.identity = Some(AssemblyIdentity {
                    name: attr(e, "name")?,
                    version: attr(e, "version")?,
                    processor_architecture: attr(e, "processorArchitecture")?,
                    public_key_token: attr(e, "publicKeyToken")?,
                    kind: attr(e, "type")?,
                });
            }
        }
        b"supportedOS" => {
            if let Some(id) = attr(e, "Id")? {
                if out.supported_os.len() < MAX_SUPPORTED_OS {
                    out.supported_os.push(id);
                } else {
                    out.truncated = true;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Why [`requires_elevation`] decided as it did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElevationReason {
    /// The manifest requests `requireAdministrator`.
    RequireAdministrator,
    /// The manifest requests `highestAvailable`, which elevates for an
    /// administrator. Reported, but not counted as requiring elevation.
    HighestAvailable,
    /// The manifest requests `asInvoker` (or another level), so no
    /// installer heuristic applies.
    ManifestAsInvoker,
    /// There is no execution level in a manifest, and the file name
    /// contains this installer word.
    InstallerFileName(&'static str),
    /// There is no execution level in a manifest, and this version field
    /// mentions installing.
    InstallerVersionInfo(&'static str),
    /// Nothing suggests elevation.
    None,
}

/// The #45 elevation heuristic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elevation {
    /// Whether starting the file is expected to ask for administrator
    /// rights.
    pub requires_elevation: bool,
    /// Why.
    pub reason: ElevationReason,
}

/// The words in a file name that the OS installer detection looks for.
const INSTALLER_WORDS: [&str; 4] = ["setup", "install", "update", "patch"];

/// Whether starting a file is expected to ask for administrator rights:
/// true if its manifest requests `requireAdministrator`, or if it has no
/// requested execution level and the installer heuristics match (its file
/// name contains setup, install, update or patch, or its version info
/// mentions installing). The OS applies the installer heuristics only to
/// 32-bit images without an execution level; the caller decides whether
/// that applies.
///
/// `version_fields` are `(field name, value)` pairs, such as
/// `("FileDescription", "Foo Installer")`.
#[must_use]
pub fn requires_elevation(
    manifest: Option<&Manifest>,
    file_name: Option<&str>,
    version_fields: &[(&'static str, &str)],
) -> Elevation {
    match manifest.and_then(|m| m.execution_level.as_ref()) {
        Some(ExecutionLevel::RequireAdministrator) => {
            return Elevation {
                requires_elevation: true,
                reason: ElevationReason::RequireAdministrator,
            };
        }
        Some(ExecutionLevel::HighestAvailable) => {
            return Elevation {
                requires_elevation: false,
                reason: ElevationReason::HighestAvailable,
            };
        }
        Some(_) => {
            return Elevation {
                requires_elevation: false,
                reason: ElevationReason::ManifestAsInvoker,
            };
        }
        None => {}
    }
    if let Some(name) = file_name {
        let lower = name.to_lowercase();
        if let Some(word) = INSTALLER_WORDS.iter().find(|w| lower.contains(*w)) {
            return Elevation {
                requires_elevation: true,
                reason: ElevationReason::InstallerFileName(word),
            };
        }
    }
    for (field, value) in version_fields {
        if value.to_lowercase().contains("install") {
            return Elevation {
                requires_elevation: true,
                reason: ElevationReason::InstallerVersionInfo(field),
            };
        }
    }
    Elevation {
        requires_elevation: false,
        reason: ElevationReason::None,
    }
}
