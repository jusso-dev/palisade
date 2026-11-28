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
//! name (which namespace a name is in is not checked, but every prefix used
//! must be declared, so an undeclared prefix makes the manifest malformed):
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
//! Only XML 1.0 in UTF-8 is read (with at most one byte order mark); XML
//! 1.1 and UTF-16 manifests are errors. The whole document must be well formed: one root element, every element
//! closed, every element and attribute name a valid XML name, every
//! attribute well formed, unique and free of undefined entities, even on
//! elements whose settings are not read.
//!
//! [`requires_elevation`] is the #45 heuristic for whether starting the
//! file will ask for administrator rights.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
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
    /// Empty when the element is empty, written `<dpiAware/>` or
    /// `<dpiAware></dpiAware>`; `None` when there is none.
    pub dpi_aware: Option<String>,
    /// The `dpiAwareness` setting, as written, empty or `None` as for
    /// [`Self::dpi_aware`].
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
    /// Not valid UTF-8, or UTF-16, which is not supported.
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

/// XML 1.0 `S`: space, tab, carriage return and line feed only. Unicode
/// whitespace such as U+00A0 is ordinary text in XML.
const fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// `s` without leading and trailing XML whitespace.
fn xml_trim(s: &str) -> &str {
    s.trim_matches(is_xml_space)
}

/// `s` cut to at most [`MAX_VALUE_LEN`] bytes on a character boundary, and
/// whether anything was cut off. Not trimmed again afterwards: a cut value
/// is never read as a keyword, whatever its prefix looks like.
fn cut(s: &str) -> (String, bool) {
    if s.len() <= MAX_VALUE_LEN {
        return (s.to_owned(), false);
    }
    let mut end = MAX_VALUE_LEN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    (s.get(..end).unwrap_or_default().to_owned(), true)
}

/// A trimmed attribute or text value, and whether it was cut to
/// [`MAX_VALUE_LEN`].
struct Value {
    text: String,
    cut: bool,
}

impl Value {
    fn new(s: &str) -> Self {
        let (text, cut) = cut(xml_trim(s));
        Self { text, cut }
    }

    /// The value as a boolean; a cut value is never one.
    fn as_bool(&self) -> Option<bool> {
        if self.cut {
            None
        } else {
            parse_bool(&self.text)
        }
    }
}

/// Whether `name` is a qualified name as XML Namespaces defines it: an
/// `NCName`, or `NCName:NCName`. So no leading, trailing or second colon.
fn is_xml_name(name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let mut parts = name.split(':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(local), None, _) => is_ncname(local),
        (Some(prefix), Some(local), None) => is_ncname(prefix) && is_ncname(local),
        _ => false,
    }
}

/// Whether `name` is an XML `NCName` (a name without colons), by the XML
/// 1.0 fifth edition character classes.
fn is_ncname(name: &str) -> bool {
    let start = |c: char| {
        c.is_ascii_alphabetic()
            || c == '_'
            || matches!(c,
                '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
                | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
                | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
                | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
    };
    let rest = |c: char| {
        start(c)
            || c.is_ascii_digit()
            || c == '-'
            || c == '.'
            || matches!(c, '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
    };
    let mut chars = name.chars();
    chars.next().is_some_and(start) && chars.all(rest)
}

/// Checks the inside of a start tag (`name attr="v" ...`, without `<`,
/// `>` or a trailing `/`) against the XML 1.0 grammar: a valid name, then
/// attributes each preceded by whitespace, as `Name Eq AttValue`, with no
/// `<` in a value. The attribute parser in use is lenient about these, so
/// they are checked here first.
fn check_tag(raw: &[u8]) -> Result<(), ManifestError> {
    let tag = std::str::from_utf8(raw).map_err(|_| ManifestError::NotUtf8)?;
    let bad = |what: &str| Err(ManifestError::Xml(format!("malformed start tag: {what}")));
    let name_end = tag.find(is_xml_space).unwrap_or(tag.len());
    let (name, mut rest) = tag.split_at(name_end);
    if !is_xml_name(name.as_bytes()) {
        return bad("invalid element name");
    }
    loop {
        let trimmed = rest.trim_start_matches(is_xml_space);
        if trimmed.is_empty() {
            return Ok(());
        }
        if trimmed.len() == rest.len() {
            return bad("no whitespace before an attribute");
        }
        let eq = trimmed.find('=').unwrap_or(trimmed.len());
        let attr = trimmed
            .get(..eq)
            .unwrap_or_default()
            .trim_end_matches(is_xml_space);
        if !is_xml_name(attr.as_bytes()) {
            return bad("invalid attribute name");
        }
        let after = trimmed.get(eq..).unwrap_or_default();
        let Some(after) = after.strip_prefix('=') else {
            return bad("attribute without a value");
        };
        let after = after.trim_start_matches(is_xml_space);
        let Some(quote) = after.chars().next().filter(|q| matches!(q, '"' | '\'')) else {
            return bad("unquoted attribute value");
        };
        let body = after.get(1..).unwrap_or_default();
        let Some(close) = body.find(quote) else {
            return bad("unterminated attribute value");
        };
        let value = body.get(..close).unwrap_or_default();
        if value.contains('<') {
            return bad("`<` in an attribute value");
        }
        check_chars(value)?;
        rest = body.get(close + 1..).unwrap_or_default();
    }
}

/// Checks an XML declaration's content (`xml version="1.0" ...`) against
/// the grammar: `version`, then optionally `encoding`, then optionally
/// `standalone`, in that order, each once, with valid values.
///
/// Only XML 1.0 is accepted. XML 1.1 reads some characters differently
/// (NEL and LS are line ends, so `"\u{85}asInvoker"` would be `asInvoker`),
/// and reading a manifest differently from the OS could make a file look
/// less likely to elevate than it is, so an XML 1.1 manifest is an error.
fn check_decl(raw: &[u8]) -> Result<(), ManifestError> {
    let decl = std::str::from_utf8(raw).map_err(|_| ManifestError::NotUtf8)?;
    let bad = || Err(ManifestError::Xml("malformed XML declaration".into()));
    let Some(body) = decl.strip_prefix("xml") else {
        return bad();
    };
    check_tag(format!("x{body}").as_bytes())?;
    let mut order = Vec::new();
    let mut rest = body;
    loop {
        rest = rest.trim_start_matches(is_xml_space);
        if rest.is_empty() {
            break;
        }
        let eq = rest.find('=').unwrap_or(rest.len());
        let name = rest
            .get(..eq)
            .unwrap_or_default()
            .trim_end_matches(is_xml_space);
        let after = rest
            .get(eq + 1..)
            .unwrap_or_default()
            .trim_start_matches(is_xml_space);
        let quote = after.chars().next().unwrap_or('"');
        let body = after.get(1..).unwrap_or_default();
        let close = body.find(quote).unwrap_or(body.len());
        let value = body.get(..close).unwrap_or_default();
        let ok = match name {
            "version" => {
                if order.is_empty() && value == "1.1" {
                    return Err(ManifestError::Xml("XML 1.1 is not supported".into()));
                }
                order.is_empty() && value == "1.0"
            }
            "encoding" => {
                order == ["version"]
                    && (value.eq_ignore_ascii_case("UTF-8") || value.eq_ignore_ascii_case("UTF8"))
            }
            "standalone" => {
                matches!(order.as_slice(), ["version"] | ["version", "encoding"])
                    && matches!(value, "yes" | "no")
            }
            _ => false,
        };
        if !ok {
            if name == "encoding" && order == ["version"] {
                return Err(ManifestError::NotUtf8);
            }
            return bad();
        }
        order.push(name);
        rest = body.get(close + 1..).unwrap_or_default();
    }
    if order.first() == Some(&"version") {
        Ok(())
    } else {
        bad()
    }
}

/// Whether `c` is an XML 1.0 `Char`.
const fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
}

/// Fails if `text` has a character XML 1.0 does not allow.
fn check_chars(text: &str) -> Result<(), ManifestError> {
    if text.chars().all(is_xml_char) {
        Ok(())
    } else {
        Err(ManifestError::Xml("character not allowed in XML".into()))
    }
}

/// Every attribute of `e`, checked: each must have a valid name and be
/// well formed, unique and free of undefined entities, whether or not it
/// is read. Returns the values of those in `wanted`, matched by exact name
/// and only when unprefixed, trimmed and bounded, in `wanted` order.
fn attrs<const N: usize>(
    e: &BytesStart<'_>,
    wanted: [&str; N],
) -> Result<[Option<Value>; N], ManifestError> {
    check_tag(e.as_bytes())?;
    let mut out: [Option<Value>; N] = std::array::from_fn(|_| None);
    for a in e.attributes() {
        let a = a.map_err(|err| ManifestError::Xml(err.to_string()))?;
        if !is_xml_name(a.key.as_ref().as_bytes()) {
            return Err(ManifestError::Xml("invalid attribute name".into()));
        }
        // Only the five predefined entities resolve; anything else fails.
        let value = a
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| ManifestError::Xml(err.to_string()))?;
        check_chars(&value)?;
        // A prefixed attribute (`x:level`) is another attribute: never the
        // schema's `level`.
        if a.key.prefix().is_some() {
            continue;
        }
        if let Some(slot) = wanted
            .iter()
            .position(|w| a.key.as_ref() == *w)
            .and_then(|i| out.get_mut(i))
        {
            *slot = Some(Value::new(&value));
        }
    }
    Ok(out)
}

fn parse_bool(value: &str) -> Option<bool> {
    let v = xml_trim(value);
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

/// A setting's text, gathered across text, references and CDATA.
///
/// Leading XML whitespace is dropped. Whitespace after the value is held
/// back and kept only if more text follows it, so trailing padding is never
/// stored and never counts towards the cap. Anything that does not fit in
/// [`MAX_VALUE_LEN`] bytes is dropped and marks the text cut, so a cut is
/// always detected, wherever a character boundary falls.
#[derive(Default)]
struct Text {
    text: String,
    /// Whitespace seen after the last non-space character, not yet kept.
    pending: usize,
    pending_text: String,
    cut: bool,
}

impl Text {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn push(&mut self, piece: &str) {
        for c in piece.chars() {
            if self.cut {
                return;
            }
            if is_xml_space(c) {
                if !self.text.is_empty() {
                    self.pending = self.pending.saturating_add(1);
                    // Held whitespace is bounded like the text: past the
                    // cap it can only end up cut off anyway.
                    if self.pending_text.len() <= MAX_VALUE_LEN {
                        self.pending_text.push(c);
                    }
                }
                continue;
            }
            let needed = self
                .text
                .len()
                .saturating_add(self.pending)
                .saturating_add(c.len_utf8());
            if needed > MAX_VALUE_LEN {
                self.cut = true;
                return;
            }
            self.text.push_str(&self.pending_text);
            self.pending_text.clear();
            self.pending = 0;
            self.text.push(c);
        }
    }

    fn value(&self) -> Value {
        Value {
            text: self.text.clone(),
            cut: self.cut,
        }
    }
}

/// Parses a manifest resource.
pub fn parse_manifest(data: &[u8]) -> Result<Manifest, ManifestError> {
    if data.len() > MAX_MANIFEST_SIZE {
        return Err(ManifestError::TooLarge(data.len()));
    }
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        return Err(ManifestError::NotUtf8);
    }
    // One UTF-8 byte order mark is skipped by the reader itself. A second
    // one is then text outside the root element, and an error.
    let text = std::str::from_utf8(data).map_err(|_| ManifestError::NotUtf8)?;
    let mut reader = Reader::from_str(text);
    // Text is gathered as written (see `Text`), so whitespace next to a
    // reference survives.
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;

    let mut out = Manifest::default();
    let mut path = Path(Vec::new());
    // The namespace prefixes in scope, in step with `path`.
    let mut scopes = Scopes::default();
    let mut elements = 0_usize;
    let mut roots = 0_usize;
    // Anything read yet (for the declaration, which must come first).
    let mut seen_anything = false;
    let mut seen_execution_level = false;
    // Which text settings were met, so the first wins however it is
    // written (`<x/>`, `<x></x>`, or a value that does not parse).
    let mut seen_text: Vec<TextField> = Vec::with_capacity(3);
    let mut text_field: Option<TextField> = None;
    let mut text = Text::default();
    // Only whitespace may sit outside the root element.
    let outside = |path: &Path, t: &str| path.0.is_empty() && !t.chars().all(is_xml_space);
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
                bind_prefixes(e, &mut scopes)?;
                path.0.push(e.local_name().as_ref().as_bytes().to_vec());
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
                    // `<x/>` is the same as `<x></x>`: an empty value.
                    if let Some(f) = field.filter(|f| !seen_text.contains(f)) {
                        seen_text.push(f);
                        match f {
                            TextField::AutoElevate => out.auto_elevate = None,
                            TextField::DpiAware => out.dpi_aware = Some(String::new()),
                            TextField::DpiAwareness => out.dpi_awareness = Some(String::new()),
                        }
                    }
                    path.0.pop();
                    scopes.pop();
                }
            }
            Event::Text(t) => {
                let raw = t.xml10_content();
                check_chars(&raw)?;
                if raw.contains("]]>") {
                    return Err(ManifestError::Xml("`]]>` in character data".into()));
                }
                if outside(&path, &raw) {
                    return Err(ManifestError::Xml("text outside the root element".into()));
                }
                if text_field.is_some() {
                    // References arrive as their own events, so the text is
                    // already plain.
                    text.push(&raw);
                }
            }
            Event::CData(t) => {
                let raw = t.xml10_content();
                check_chars(&raw)?;
                if path.0.is_empty() {
                    return Err(ManifestError::Xml("CDATA outside the root element".into()));
                }
                if text_field.is_some() {
                    text.push(&raw);
                }
            }
            Event::GeneralRef(r) => {
                // Only character references and the five predefined
                // entities are accepted; anything else is undefined.
                let resolved = match r.resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => c.to_string(),
                    Ok(Some(_)) => {
                        return Err(ManifestError::Xml(
                            "character reference to a character XML does not allow".into(),
                        ));
                    }
                    Ok(None) => {
                        let name: &str = &r;
                        quick_xml::escape::resolve_predefined_entity(name)
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
                    text.push(&resolved);
                }
            }
            Event::End(_) => {
                path.0.pop();
                scopes.pop();
                if let Some(field) = text_field.take() {
                    let value = text.value();
                    match field {
                        TextField::AutoElevate => out.auto_elevate = value.as_bool(),
                        TextField::DpiAware => out.dpi_aware = Some(value.text),
                        TextField::DpiAwareness => out.dpi_awareness = Some(value.text),
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
            Event::Decl(d) => {
                // Only as the very first thing, with a valid version.
                if seen_anything {
                    return Err(ManifestError::Xml("misplaced XML declaration".into()));
                }
                check_decl(d.as_bytes())?;
            }
            Event::PI(pi) => {
                let target = pi.target();
                if target.eq_ignore_ascii_case("xml")
                    || !is_xml_name(target.as_bytes())
                    || target.contains(':')
                {
                    return Err(ManifestError::Xml("bad processing instruction".into()));
                }
                check_chars(&pi)?;
            }
            Event::Comment(c) => {
                check_chars(&c)?;
            }
        }
        seen_anything = true;
    }
    Ok(out)
}

/// The namespace prefixes in scope: how many open elements declare each
/// one, and what each open element declared, so closing it undoes exactly
/// that. Lookups are logarithmic, however many prefixes are declared.
#[derive(Default)]
struct Scopes {
    bound: BTreeMap<Vec<u8>, usize>,
    frames: Vec<Vec<Vec<u8>>>,
}

impl Scopes {
    fn push(&mut self, declared: Vec<Vec<u8>>) {
        for prefix in &declared {
            let count = self.bound.entry(prefix.clone()).or_insert(0);
            *count = count.saturating_add(1);
        }
        self.frames.push(declared);
    }

    fn pop(&mut self) {
        for prefix in self.frames.pop().unwrap_or_default() {
            if let Some(count) = self.bound.get_mut(&prefix) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.bound.remove(&prefix);
                }
            }
        }
    }

    fn is_bound(&self, prefix: &[u8]) -> bool {
        self.bound.contains_key(prefix)
    }
}

/// Records the namespace prefixes `e` declares (`xmlns:p="..."`) as a new
/// scope, then checks that its own prefix and its attributes' prefixes are
/// declared, as XML Namespaces requires. `xml` is always bound and `xmlns`
/// only declares. A name with an undeclared prefix is not namespace
/// well formed, so the manifest is an error rather than read by its local
/// name.
fn bind_prefixes(e: &BytesStart<'_>, scopes: &mut Scopes) -> Result<(), ManifestError> {
    let bad = |what: &str| Err(ManifestError::Xml(format!("namespace prefix: {what}")));
    let mut declared = Vec::new();
    let mut used = Vec::new();
    for a in e.attributes() {
        let a = a.map_err(|err| ManifestError::Xml(err.to_string()))?;
        let key = a.key.as_ref();
        if let Some(prefix) = key.strip_prefix("xmlns:") {
            // Undeclaring a prefix (`xmlns:p=""`) is not allowed in XML
            // Namespaces 1.0, and `xmlns` itself cannot be declared.
            if a.value.is_empty() || prefix == "xmlns" {
                return bad("bad declaration");
            }
            declared.push(prefix.as_bytes().to_vec());
        } else if let Some(prefix) = a.key.prefix() {
            used.push(prefix.as_ref().as_bytes().to_vec());
        }
    }
    scopes.push(declared);
    if let Some(prefix) = e.name().prefix() {
        used.push(prefix.as_ref().as_bytes().to_vec());
    }
    for prefix in used {
        if prefix == b"xmlns" {
            return bad("`xmlns` used as a prefix");
        }
        if prefix != b"xml" && !scopes.is_bound(&prefix) {
            return bad("undeclared");
        }
    }
    Ok(())
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
            // A cut level is kept as `Other`, never matched as a keyword.
            out.execution_level = level.map(|v| {
                if v.cut {
                    ExecutionLevel::Other(v.text)
                } else {
                    ExecutionLevel::parse(&v.text)
                }
            });
            out.ui_access = ui_access.and_then(|v| v.as_bool());
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
            let text = |v: Option<Value>| v.map(|v| v.text);
            out.identity = Some(AssemblyIdentity {
                name: text(name),
                version: text(version),
                processor_architecture: text(arch),
                public_key_token: text(token),
                kind: text(kind),
            });
        }
    } else if path.is(&SUPPORTED_OS) {
        let [id] = attrs(e, ["Id"])?;
        if let Some(id) = id {
            if out.supported_os.len() < MAX_SUPPORTED_OS {
                out.supported_os.push(id.text);
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
    /// A manifest is present but requests no execution level. The
    /// installer heuristics apply only when there is no manifest, so they
    /// are not used.
    ManifestWithoutLevel,
    /// The process manifest (ID 1) is present but could not be read or
    /// parsed, so what it requests is unknown. Treated as requiring
    /// elevation, and never decided from another manifest or from the
    /// installer heuristics.
    ManifestUnreadable,
    /// There is no manifest, and the file name contains this installer
    /// word.
    InstallerFileName(&'static str),
    /// There is no manifest, and this version field mentions installing.
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
/// manifest (or one with an unrecognised execution level) and the
/// installer heuristics match (its file name contains setup, install,
/// update or patch, or its version info mentions installing). A manifest
/// without an execution level is [`ElevationReason::ManifestWithoutLevel`]
/// and is not counted. `manifest` is the parsed process manifest, or
/// `None` when there is none; a process manifest that is present but
/// cannot be read is decided by [`super::PeInfo::requires_elevation`]
/// ([`ElevationReason::ManifestUnreadable`]), never passed as `None`. The
/// OS applies the installer heuristics only to 32-bit images; the caller
/// decides whether that applies.
///
/// `version_fields` are `(field name, value)` pairs, such as
/// `("FileDescription", "Foo Installer")`.
#[must_use]
pub fn requires_elevation(
    manifest: Option<&Manifest>,
    file_name: Option<&str>,
    version_fields: &[(&'static str, &str)],
) -> Elevation {
    let Some(manifest) = manifest else {
        return match installer_heuristic(file_name, version_fields) {
            Some(reason) => Elevation {
                requires_elevation: true,
                reason,
            },
            None => Elevation {
                requires_elevation: false,
                reason: ElevationReason::None,
            },
        };
    };
    match &manifest.execution_level {
        Some(ExecutionLevel::RequireAdministrator) => Elevation {
            requires_elevation: true,
            reason: ElevationReason::RequireAdministrator,
        },
        Some(ExecutionLevel::HighestAvailable) => Elevation {
            requires_elevation: false,
            reason: ElevationReason::HighestAvailable,
        },
        Some(ExecutionLevel::AsInvoker) => Elevation {
            requires_elevation: false,
            reason: ElevationReason::ManifestAsInvoker,
        },
        Some(ExecutionLevel::Other(level)) => {
            let heuristic = installer_heuristic(file_name, version_fields);
            Elevation {
                requires_elevation: heuristic.is_some(),
                reason: heuristic.unwrap_or(ElevationReason::UnknownLevel(level.clone())),
            }
        }
        None => Elevation {
            requires_elevation: false,
            reason: ElevationReason::ManifestWithoutLevel,
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

#[cfg(test)]
mod tests {
    use super::Scopes;

    #[test]
    fn a_prefix_declared_twice_stays_bound_until_both_close() {
        let mut scopes = Scopes::default();
        scopes.push(vec![b"x".to_vec()]);
        scopes.push(vec![b"x".to_vec(), b"y".to_vec()]);
        assert!(scopes.is_bound(b"x") && scopes.is_bound(b"y"));
        scopes.pop();
        assert!(scopes.is_bound(b"x") && !scopes.is_bound(b"y"));
        scopes.pop();
        assert!(!scopes.is_bound(b"x"));
        // Popping past the root is harmless.
        scopes.pop();
        assert!(!scopes.is_bound(b"x"));
    }
}
