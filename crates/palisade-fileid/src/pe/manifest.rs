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
//! Each setting is read only at its place in the manifest schema, by local
//! name (namespace prefixes are ignored):
//!
//! | Setting | Path |
//! |---|---|
//! | `requestedExecutionLevel` | `assembly/trustInfo/security/requestedPrivileges/requestedExecutionLevel` |
//! | `assemblyIdentity` (the manifest's own) | `assembly/assemblyIdentity` |
//! | `supportedOS` | `assembly/compatibility/application/supportedOS` |
//! | `autoElevate`, `dpiAware`, `dpiAwareness` | `assembly/application/windowsSettings/<name>` |
//!
//! So a dependency's `assemblyIdentity`, or a decoy setting placed anywhere
//! else, is never taken for the real one. The first occurrence at the right
//! place wins, whether it is written `<x/>` or `<x></x>`. Element and
//! attribute names are case-sensitive, as in XML; only unprefixed
//! attributes are read, as the manifest schema has no prefixed ones. Values
//! are trimmed, then compared ASCII case-insensitively where the OS does
//! (`requireAdministrator`, `true`). Text may be split by references,
//! comments or CDATA sections; it is joined before it is read, and leading
//! whitespace is dropped as it arrives, so padding cannot crowd a value
//! out.
//!
//! The whole document must be well formed: one root element, every element
//! closed, every element and attribute name a valid XML name, every
//! attribute well formed, unique and free of undefined entities, even on
//! elements whose settings are not read.
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
    /// `requestedExecutionLevel` `level`. `None` when there is no
    /// `requestedExecutionLevel`, or it has no `level`.
    pub execution_level: Option<ExecutionLevel>,
    /// `requestedExecutionLevel` `uiAccess`, from the same element as
    /// [`Self::execution_level`].
    pub ui_access: Option<bool>,
    /// The `autoElevate` setting.
    pub auto_elevate: Option<bool>,
    /// The `dpiAware` setting, as written (`true`, `per monitor`, ...).
    pub dpi_aware: Option<String>,
    /// The `dpiAwareness` setting, as written.
    pub dpi_awareness: Option<String>,
    /// The manifest's own `assemblyIdentity` (a direct child of the root
    /// `assembly`), never a dependency's.
    pub identity: Option<AssemblyIdentity>,
    /// `supportedOS` `Id` GUIDs, in document order, at most
    /// [`MAX_SUPPORTED_OS`].
    pub supported_os: Vec<String>,
    /// More than [`MAX_SUPPORTED_OS`] `supportedOS` entries; the rest were
    /// not kept.
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
    /// More than [`MAX_ELEMENTS`] elements. A manifest's settings can come
    /// after any number of others, so a cut-off manifest is not read at
    /// all rather than read in part.
    TooManyElements,
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
            Self::TooManyElements => f.write_str("manifest has too many elements"),
            Self::Xml(e) => write!(f, "manifest is not well-formed XML: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// `s` trimmed, then cut to at most [`MAX_VALUE_LEN`] bytes on a character
/// boundary. Trimming first means padding cannot push the value out.
fn bounded(s: &str) -> String {
    let mut s = s.trim().to_owned();
    if s.len() > MAX_VALUE_LEN {
        let mut end = MAX_VALUE_LEN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// Whether `name` is a valid XML name (with an optional `prefix:`). Names
/// are checked by the rules for their first and later characters; a
/// manifest's names are ASCII, so non-ASCII letters are accepted as the
/// XML 1.0 fifth edition does.
fn is_xml_name(name: &[u8]) -> bool {
    let start = |c: char| c.is_alphabetic() || c == '_' || c == ':' || !c.is_ascii();
    let rest = |c: char| start(c) || c.is_ascii_digit() || c == '-' || c == '.';
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let mut chars = name.chars();
    chars.next().is_some_and(start) && chars.all(rest)
}

/// Every attribute of `e`, checked: each must have a valid name and be
/// well formed, unique and free of undefined entities, whether or not it
/// is read. Returns the values of those in `wanted`, matched by exact name
/// and only when unprefixed, trimmed and bounded, in `wanted` order.
fn attrs<const N: usize>(
    e: &BytesStart<'_>,
    wanted: [&str; N],
) -> Result<[Option<String>; N], ManifestError> {
    if !is_xml_name(e.name().as_ref()) {
        return Err(ManifestError::Xml("invalid element name".into()));
    }
    let mut out: [Option<String>; N] = std::array::from_fn(|_| None);
    for a in e.attributes() {
        let a = a.map_err(|err| ManifestError::Xml(err.to_string()))?;
        if !is_xml_name(a.key.as_ref()) {
            return Err(ManifestError::Xml("invalid attribute name".into()));
        }
        // Only the five predefined entities resolve; anything else fails.
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| ManifestError::Xml(err.to_string()))?;
        // A prefixed attribute (`x:level`) is another attribute: never the
        // schema's `level`.
        if a.key.prefix().is_some() {
            continue;
        }
        if let Some(slot) = wanted
            .iter()
            .position(|w| a.key.as_ref() == w.as_bytes())
            .and_then(|i| out.get_mut(i))
        {
            *slot = Some(bounded(&value));
        }
    }
    Ok(out)
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

/// The open element path, by local name. Bounded by [`MAX_DEPTH`].
struct Path(Vec<Vec<u8>>);

impl Path {
    /// Whether the open elements, from the root, are exactly `names`.
    fn is(&self, names: &[&str]) -> bool {
        self.0.len() == names.len() && self.0.iter().zip(names).all(|(a, b)| a == b.as_bytes())
    }
}

const EXECUTION_LEVEL: [&str; 5] = [
    "assembly",
    "trustInfo",
    "security",
    "requestedPrivileges",
    "requestedExecutionLevel",
];
const IDENTITY: [&str; 2] = ["assembly", "assemblyIdentity"];
const SUPPORTED_OS: [&str; 4] = ["assembly", "compatibility", "application", "supportedOS"];
const WINDOWS_SETTINGS: [&str; 3] = ["assembly", "application", "windowsSettings"];

/// Appends a piece of a setting's text: leading whitespace is dropped while
/// nothing else has arrived, so padding cannot crowd the value out, and the
/// text never grows past one byte over [`MAX_VALUE_LEN`] (enough to know it
/// was cut).
fn append(text: &mut String, piece: &str) {
    let piece = if text.is_empty() {
        piece.trim_start()
    } else {
        piece
    };
    let room = (MAX_VALUE_LEN + 1).saturating_sub(text.len());
    let mut end = piece.len().min(room);
    while !piece.is_char_boundary(end) {
        end -= 1;
    }
    text.push_str(piece.get(..end).unwrap_or_default());
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
    // Text is kept as written and trimmed once it is joined, so whitespace
    // next to a reference survives.
    reader.config_mut().check_end_names = true;

    let mut out = Manifest::default();
    let mut path = Path(Vec::new());
    let mut elements = 0_usize;
    let mut roots = 0_usize;
    let mut seen_execution_level = false;
    // Which text settings were met, so the first wins however it is
    // written (`<x/>`, `<x></x>`, or a value that does not parse).
    let mut seen_text: Vec<TextField> = Vec::with_capacity(3);
    let mut text_field: Option<TextField> = None;
    let mut text = String::new();
    // Only whitespace may sit outside the root element.
    let outside = |path: &Path, t: &str| path.0.is_empty() && !t.trim().is_empty();
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
                    return Err(ManifestError::TooManyElements);
                }
                if path.0.is_empty() {
                    roots += 1;
                    if roots > 1 {
                        return Err(ManifestError::Xml("more than one root element".into()));
                    }
                }
                if path.0.len() >= MAX_DEPTH {
                    return Err(ManifestError::TooDeep);
                }
                path.0.push(e.local_name().as_ref().to_vec());
                element(e, &path, &mut out, &mut seen_execution_level)?;
                // Text belongs to a setting only directly inside it.
                text_field = None;
                if !empty {
                    let name = path.0.last().map(Vec::as_slice).unwrap_or_default();
                    let in_settings = path.0.len() == WINDOWS_SETTINGS.len() + 1
                        && path
                            .0
                            .iter()
                            .zip(WINDOWS_SETTINGS)
                            .all(|(a, b)| a == b.as_bytes());
                    text_field = match name {
                        _ if !in_settings => None,
                        b"autoElevate" => Some(TextField::AutoElevate),
                        b"dpiAware" => Some(TextField::DpiAware),
                        b"dpiAwareness" => Some(TextField::DpiAwareness),
                        _ => None,
                    }
                    .filter(|f| !seen_text.contains(f));
                    if let Some(f) = text_field {
                        seen_text.push(f);
                    }
                    text.clear();
                } else {
                    let name = path.0.last().map(Vec::as_slice).unwrap_or_default();
                    let in_settings = path.0.len() == WINDOWS_SETTINGS.len() + 1
                        && path
                            .0
                            .iter()
                            .zip(WINDOWS_SETTINGS)
                            .all(|(a, b)| a == b.as_bytes());
                    let field = match name {
                        _ if !in_settings => None,
                        b"autoElevate" => Some(TextField::AutoElevate),
                        b"dpiAware" => Some(TextField::DpiAware),
                        b"dpiAwareness" => Some(TextField::DpiAwareness),
                        _ => None,
                    };
                    if let Some(f) = field.filter(|f| !seen_text.contains(f)) {
                        seen_text.push(f);
                    }
                    path.0.pop();
                }
            }
            Event::Text(t) => {
                let raw = t.decode().map_err(|e| ManifestError::Xml(e.to_string()))?;
                if outside(&path, &raw) {
                    return Err(ManifestError::Xml("text outside the root element".into()));
                }
                if text_field.is_some() {
                    // References arrive as their own events, so the text is
                    // already plain.
                    append(&mut text, &raw);
                }
            }
            Event::CData(t) => {
                let raw = t.decode().map_err(|e| ManifestError::Xml(e.to_string()))?;
                if path.0.is_empty() {
                    return Err(ManifestError::Xml("CDATA outside the root element".into()));
                }
                if text_field.is_some() {
                    append(&mut text, &raw);
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
                if path.0.is_empty() {
                    return Err(ManifestError::Xml(
                        "reference outside the root element".into(),
                    ));
                }
                if text_field.is_some() {
                    append(&mut text, &resolved);
                }
            }
            Event::End(_) => {
                path.0.pop();
                if let Some(field) = text_field.take() {
                    let value = bounded(&text);
                    match field {
                        TextField::AutoElevate => out.auto_elevate = parse_bool(&value),
                        TextField::DpiAware => out.dpi_aware = Some(value),
                        TextField::DpiAwareness => out.dpi_awareness = Some(value),
                    }
                }
            }
            Event::Eof => {
                if !path.0.is_empty() {
                    return Err(ManifestError::Xml("an element is not closed".into()));
                }
                if roots == 0 {
                    return Err(ManifestError::Xml("no root element".into()));
                }
                break;
            }
            _ => {}
        }
    }
    Ok(out)
}

fn element(
    e: &BytesStart<'_>,
    path: &Path,
    out: &mut Manifest,
    seen_execution_level: &mut bool,
) -> Result<(), ManifestError> {
    if path.is(&EXECUTION_LEVEL) {
        let [level, ui_access] = attrs(e, ["level", "uiAccess"])?;
        // The first element decides, even if it lacks one of them.
        if !*seen_execution_level {
            *seen_execution_level = true;
            out.execution_level = level.map(|v| ExecutionLevel::parse(&v));
            out.ui_access = ui_access.and_then(|v| parse_bool(&v));
        }
    } else if path.is(&IDENTITY) {
        let [name, version, arch, token, kind] = attrs(
            e,
            [
                "name",
                "version",
                "processorArchitecture",
                "publicKeyToken",
                "type",
            ],
        )?;
        if out.identity.is_none() {
            out.identity = Some(AssemblyIdentity {
                name,
                version,
                processor_architecture: arch,
                public_key_token: token,
                kind,
            });
        }
    } else if path.is(&SUPPORTED_OS) {
        let [id] = attrs(e, ["Id"])?;
        if let Some(id) = id {
            if out.supported_os.len() < MAX_SUPPORTED_OS {
                out.supported_os.push(id);
            } else {
                out.truncated = true;
            }
        }
    } else {
        // Not read, but still checked.
        let _ = attrs(e, [])?;
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
    /// The manifest requests `asInvoker`, so no installer heuristic
    /// applies.
    ManifestAsInvoker,
    /// The manifest requests a level this parser does not recognise. The
    /// OS refuses to start such a file, so it is not treated as `asInvoker`;
    /// the installer heuristics still apply.
    UnknownLevel(String),
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
/// (or an unrecognised) requested execution level and the installer
/// heuristics match (its file
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
        Some(ExecutionLevel::AsInvoker) => {
            return Elevation {
                requires_elevation: false,
                reason: ElevationReason::ManifestAsInvoker,
            };
        }
        Some(ExecutionLevel::Other(level)) => {
            let heuristic = installer_heuristic(file_name, version_fields);
            return Elevation {
                requires_elevation: heuristic.is_some(),
                reason: heuristic.unwrap_or(ElevationReason::UnknownLevel(level.clone())),
            };
        }
        None => {}
    }
    match installer_heuristic(file_name, version_fields) {
        Some(reason) => Elevation {
            requires_elevation: true,
            reason,
        },
        None => Elevation {
            requires_elevation: false,
            reason: ElevationReason::None,
        },
    }
}

/// The installer heuristics: a file name with an installer word, or a
/// version field mentioning installing.
fn installer_heuristic(
    file_name: Option<&str>,
    version_fields: &[(&'static str, &str)],
) -> Option<ElevationReason> {
    if let Some(name) = file_name {
        let lower = name.to_lowercase();
        if let Some(word) = INSTALLER_WORDS.iter().find(|w| lower.contains(*w)) {
            return Some(ElevationReason::InstallerFileName(word));
        }
    }
    version_fields
        .iter()
        .find(|(_, value)| value.to_lowercase().contains("install"))
        .map(|(field, _)| ElevationReason::InstallerVersionInfo(field))
}
