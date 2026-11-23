//! The YAML policy language (#190): human-authored YAML over the same model
//! and JSON Schema as the JSON form.
//!
//! A YAML policy file holds the same [`PolicyDocument`] as the JSON form, with
//! the same field names, and the JSON Schema in `schemas/policy/v1.json`
//! validates both. JSON text is also accepted, since it is a subset of YAML.
//!
//! ```
//! use palisade_policy::dsl;
//!
//! let yaml = "\
//! schema_version: 1.0.0
//! policy:
//!   id: 01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f
//!   name: Example
//!   revision: 1
//!   mode: audit
//! ";
//! let loaded = dsl::from_str(yaml).unwrap();
//! assert_eq!(loaded.document.policy.name, "Example");
//! let written = dsl::to_string(&loaded.document).unwrap();
//! assert_eq!(dsl::from_str(&written).unwrap().document, loaded.document);
//! ```
//!
//! # Reading untrusted input
//!
//! Reading is strict, so a file means the same thing to every tool that
//! reads it, and hostile input cannot exhaust memory or the stack:
//!
//! - **YAML 1.2 only.** A `%YAML` directive for another version, `%TAG`
//!   and reserved directives are rejected.
//! - **No anchors, aliases, tags or merge keys** (`&a`, `*a`, `!t`, `<<`).
//!   Without aliases a document cannot expand ("billion laughs"), and
//!   without tags no value is typed by a directive in the file.
//! - **Duplicate keys are an error**, in every map, including keys that are
//!   only spelled differently (`a` and `"a"`).
//! - **Unknown fields are an error**, as in the JSON form.
//! - **No implicit type changes between YAML versions.** A plain (unquoted)
//!   scalar is typed once, by the rules below, and a scalar that YAML 1.1
//!   and YAML 1.2 readers type differently is an error that asks for quotes.
//!   So `country: NO` (the "Norway problem": a boolean in YAML 1.1) and
//!   `version: 010` (octal in YAML 1.1) are rejected rather than misread.
//! - **Plain scalars are never converted to the field's type.** `revision:
//!   "1"` and `values: [1.0]` are type errors, as they are in JSON: a field
//!   that wants text needs text, and the error says to quote the value.
//! - **No characters outside the YAML 1.2 printable set**, and no raw
//!   U+0085, U+2028 or U+2029, which YAML 1.1 reads as line breaks. All of
//!   them can be written as escapes in double-quoted strings.
//! - **Limits** on input size, nesting depth and node count ([`Limits`]),
//!   so memory use is bounded by the node count and the input size, and
//!   stack use by the depth.
//!
//! Plain scalars are typed as follows: `null`, `Null`, `NULL`, `~` and the
//! empty scalar are null; `true` and `false` (also `True`, `TRUE`, `False`,
//! `FALSE`) are booleans; JSON numbers are numbers (integers if they have no
//! fraction or exponent); `yes`, `no`, `on`, `off`, `y`, `n` in any of their
//! YAML 1.1 spellings, and numbers in non-JSON forms (`+1`, `010`, `0x1f`,
//! `0o17`, `1_000`, `1:30`, `.5`, `1.`, `.inf`, `.nan`), are errors; anything
//! else is text. That includes dotted versions (`1.0.0`) and dates
//! (`2027-06-30`): the YAML 1.2 core schema has no timestamp type, and the
//! model has no date or floating-point fields, so a reader that typed these
//! differently would fail schema validation rather than silently read
//! another value. The writer quotes them anyway. Quoted and block scalars
//! are always text.
//!
//! # Writing
//!
//! [`to_string`] writes canonical block-style YAML: fields in schema order, a
//! 2-space indent, and a `yaml-language-server` header that names the
//! schema. Strings are quoted unless every YAML 1.1 and 1.2 reader reads
//! them back as the same text (so versions and dates are quoted), and
//! characters that are not printable, or
//! that some readers treat as line breaks, are escaped. Floating-point
//! numbers are never written, because the model has none.
//!
//! # Diagnostics
//!
//! Every error carries a 1-based line and column, where the column counts
//! Unicode scalar values (an input that is too large has no location). Load errors ([`YamlError`]) also carry the JSON
//! Pointer of the value when one is known. Validation findings keep their
//! stable [`ErrorCode`](crate::validate::ErrorCode) and JSON Pointer, and
//! [`YamlDocument::validate`] adds the location of the value they point to.

mod de;
mod emit;
mod parse;

use core::fmt;

use serde::Deserialize;

use crate::model::{PolicyDocument, SchemaVersion};
use crate::schema;
use crate::validate::{ValidatedPolicy, ValidationError};

pub use emit::WriteError;

/// The comment that associates a document with the JSON Schema in editors
/// that use the YAML language server. [`to_string`] writes it first.
pub const SCHEMA_HEADER: &str = "# yaml-language-server: $schema=https://raw.githubusercontent.com/jusso-dev/palisade/main/schemas/policy/v1.json\n";

/// Bounds on the input, checked while reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes of input.
    pub max_bytes: usize,
    /// Deepest nesting of sequences and maps. The root collection is level 1.
    pub max_depth: usize,
    /// Most nodes (scalars, sequences and maps, including keys).
    pub max_nodes: usize,
}

impl Limits {
    /// The defaults: 64 MiB, depth 128 (the JSON reader's recursion limit),
    /// and 4 million nodes. These fit 100,000 single-criterion rules, the
    /// model's rule limit, as [`to_string`] writes them (about 37 MB and 2.2
    /// million nodes); documents with larger rules need higher limits.
    pub const DEFAULT: Self = Self {
        max_bytes: 64 * 1024 * 1024,
        max_depth: 128,
        max_nodes: 4_000_000,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A position in the source: 1-based line and column. The column counts
/// Unicode scalar values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Location {
    /// The line, from 1.
    pub line: usize,
    /// The column, from 1.
    pub column: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}, column {}", self.line, self.column)
    }
}

/// What kind of problem stopped a YAML document from loading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum YamlErrorKind {
    /// The text is not well-formed YAML.
    Syntax,
    /// The input is larger, deeper or has more nodes than [`Limits`] allows.
    LimitExceeded,
    /// An anchor, alias, tag, merge key, `%TAG` directive or a YAML version
    /// other than 1.2.
    UnsupportedFeature,
    /// A map has the same key twice.
    DuplicateKey,
    /// A plain scalar that YAML 1.1 and YAML 1.2 readers type differently.
    AmbiguousScalar,
    /// The document does not match the model: an unknown field, a missing
    /// field, or a value of the wrong type.
    Mismatch,
    /// `schema_version` is missing or not a version string.
    MissingSchemaVersion,
    /// The document's major version is not one this reader implements. The
    /// same code as [`ErrorCode::UnsupportedSchemaVersion`](crate::validate::ErrorCode::UnsupportedSchemaVersion).
    UnsupportedSchemaVersion,
}

impl YamlErrorKind {
    /// The stable `snake_case` name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Syntax => "yaml_syntax",
            Self::LimitExceeded => "yaml_limit_exceeded",
            Self::UnsupportedFeature => "yaml_unsupported_feature",
            Self::DuplicateKey => "yaml_duplicate_key",
            Self::AmbiguousScalar => "yaml_ambiguous_scalar",
            Self::Mismatch => "model_mismatch",
            Self::MissingSchemaVersion => "missing_schema_version",
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
        }
    }
}

impl fmt::Display for YamlErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// A YAML document could not be loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YamlError {
    kind: YamlErrorKind,
    message: String,
    location: Option<Location>,
    pointer: Option<String>,
}

impl YamlError {
    pub(crate) fn new(kind: YamlErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            location: None,
            pointer: None,
        }
    }

    /// Sets the location, unless one is already set.
    pub(crate) fn at(mut self, location: Location) -> Self {
        self.location.get_or_insert(location);
        self
    }

    /// Replaces the location.
    pub(crate) fn relocate(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }

    /// The kind of problem.
    #[must_use]
    pub const fn kind(&self) -> YamlErrorKind {
        self.kind
    }

    /// A human-readable explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Where the problem is. Only an input that is too large has none.
    #[must_use]
    pub const fn location(&self) -> Option<Location> {
        self.location
    }

    /// The JSON Pointer (RFC 6901) of the value, for model mismatches.
    #[must_use]
    pub fn pointer(&self) -> Option<&str> {
        self.pointer.as_deref()
    }
}

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}]", self.kind)?;
        if let Some(location) = self.location {
            write!(f, " {location}")?;
        }
        if let Some(pointer) = &self.pointer {
            write!(f, " {}", if pointer.is_empty() { "/" } else { pointer })?;
        }
        write!(f, ": {}", self.message)
    }
}

impl std::error::Error for YamlError {}

impl From<de::DeError> for YamlError {
    fn from(e: de::DeError) -> Self {
        Self {
            kind: YamlErrorKind::Mismatch,
            message: e.message,
            location: e.location,
            pointer: e.pointer,
        }
    }
}

/// A finding with the location of the value it points to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located<E> {
    /// The finding.
    pub error: E,
    /// Where its value is in the source.
    pub location: Location,
}

impl<E: fmt::Display> fmt::Display for Located<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.location, self.error)
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for Located<E> {}

/// Maps JSON Pointers in one document to their place in the source.
#[derive(Clone, Debug)]
pub struct SourceMap {
    root: parse::Node,
}

impl SourceMap {
    /// The location of the value at `pointer` (RFC 6901). For a pointer to
    /// something absent, such as a missing field, it is the location of the
    /// nearest value that is present on the way to it.
    #[must_use]
    pub fn locate(&self, pointer: &str) -> Location {
        let mut node = &self.root;
        let tokens = pointer.strip_prefix('/').map(|p| p.split('/'));
        for token in tokens.into_iter().flatten() {
            let token = token.replace("~1", "/").replace("~0", "~");
            let child = match &node.value {
                parse::Value::Map(map) => map.get(&token).map(|e| &e.value),
                parse::Value::Seq(items) => token.parse::<usize>().ok().and_then(|i| items.get(i)),
                _ => None,
            };
            match child {
                Some(child) => node = child,
                None => break,
            }
        }
        node.location
    }

    /// Adds locations to validation findings.
    #[must_use]
    pub fn locate_all(&self, errors: Vec<ValidationError>) -> Vec<Located<ValidationError>> {
        errors
            .into_iter()
            .map(|error| Located {
                location: self.locate(&error.path),
                error,
            })
            .collect()
    }
}

/// A document read from YAML, with the source locations of its values.
#[derive(Clone, Debug)]
pub struct YamlDocument {
    /// The document.
    pub document: PolicyDocument,
    /// Where each value is in the source.
    pub source_map: SourceMap,
}

impl YamlDocument {
    /// Validates the document, as [`PolicyDocument::validate`] does, and
    /// adds the source location of every finding.
    ///
    /// # Errors
    ///
    /// Returns every finding if any has `error` severity.
    pub fn validate(self) -> Result<ValidatedPolicy, Vec<Located<ValidationError>>> {
        let Self {
            document,
            source_map,
        } = self;
        document
            .validate()
            .map_err(|errors| source_map.locate_all(errors))
    }
}

/// Reads one policy document from YAML (or JSON) with the default
/// [`Limits`].
///
/// # Errors
///
/// Returns [`YamlError`] if the input is not exactly one document that this
/// reader understands.
pub fn from_str(input: &str) -> Result<YamlDocument, YamlError> {
    from_str_with_limits(input, &Limits::DEFAULT)
}

/// Reads one policy document, with the given limits.
///
/// # Errors
///
/// Returns [`YamlError`] if the input is not exactly one document that this
/// reader understands.
pub fn from_str_with_limits(input: &str, limits: &Limits) -> Result<YamlDocument, YamlError> {
    document(single(parse::parse(input, limits)?)?)
}

/// The only document of a stream. `parse` never returns an empty stream.
fn single(roots: Vec<parse::Node>) -> Result<parse::Node, YamlError> {
    let mut roots = roots.into_iter();
    match (roots.next(), roots.next()) {
        (Some(root), None) => Ok(root),
        (_, Some(second)) => Err(YamlError::new(
            YamlErrorKind::UnsupportedFeature,
            "a second document starts here; use `from_str_all` to read a stream of documents",
        )
        .at(second.location)),
        (None, None) => Err(YamlError::new(
            YamlErrorKind::Syntax,
            "the input holds no YAML document",
        )
        .at(Location { line: 1, column: 1 })),
    }
}

/// Reads every document of a YAML stream (documents separated by `---`).
///
/// # Errors
///
/// Returns the first [`YamlError`], in source order.
pub fn from_str_all(input: &str, limits: &Limits) -> Result<Vec<YamlDocument>, YamlError> {
    parse::parse(input, limits)?
        .into_iter()
        .map(document)
        .collect()
}

/// Reads one YAML document into the JSON data model, with the same strict
/// rules as [`from_str`] but without checking it against the policy model.
/// The result can be checked with the JSON Schema.
///
/// # Errors
///
/// Returns [`YamlError`] if the input is not exactly one well-formed
/// document within the limits.
pub fn to_json_value(input: &str, limits: &Limits) -> Result<serde_json::Value, YamlError> {
    let root = single(parse::parse(input, limits)?)?;
    let path = de::Path::Root;
    Ok(serde_json::Value::deserialize(de::De {
        node: &root,
        path: &path,
    })?)
}

/// Builds the document from its tree, checking `schema_version` first as
/// [`PolicyDocument::from_json`] does.
fn document(root: parse::Node) -> Result<YamlDocument, YamlError> {
    let parse::Value::Map(map) = &root.value else {
        return Err(YamlError::new(
            YamlErrorKind::Mismatch,
            "a policy document is a map with `schema_version` and `policy`",
        )
        .at(root.location));
    };
    let version = map.get("schema_version");
    let parsed = version.and_then(|e| match &e.value.value {
        parse::Value::Str(s) => s.parse::<SchemaVersion>().ok(),
        _ => None,
    });
    let Some(parsed) = parsed else {
        return Err(YamlError::new(
            YamlErrorKind::MissingSchemaVersion,
            "missing or invalid `schema_version`",
        )
        .at(version.map_or(root.location, |e| e.value.location)));
    };
    if !parsed.is_readable_by(schema::CURRENT) {
        let mut error = YamlError::new(
            YamlErrorKind::UnsupportedSchemaVersion,
            format!(
                "unsupported schema version {parsed}: this reader implements {}",
                schema::CURRENT
            ),
        );
        if let Some(e) = version {
            error = error.at(e.value.location);
            error.pointer = Some("/schema_version".to_owned());
        }
        return Err(error);
    }
    let path = de::Path::Root;
    let document = PolicyDocument::deserialize(de::De {
        node: &root,
        path: &path,
    })?;
    Ok(YamlDocument {
        document,
        source_map: SourceMap { root },
    })
}

/// Writes a document as canonical YAML, starting with [`SCHEMA_HEADER`].
///
/// # Errors
///
/// Only fails if a value cannot be written as YAML, which the model's types
/// do not do.
pub fn to_string(document: &PolicyDocument) -> Result<String, WriteError> {
    emit::to_string(document, SCHEMA_HEADER)
}

impl PolicyDocument {
    /// Reads a document from YAML (or JSON) in strict mode. See
    /// [`crate::dsl`] for the rules, and [`dsl::from_str`](from_str) for a
    /// version that keeps source locations.
    ///
    /// # Errors
    ///
    /// Returns [`YamlError`] if the input is not a document this reader
    /// understands.
    pub fn from_yaml(input: &str) -> Result<Self, YamlError> {
        from_str(input).map(|d| d.document)
    }

    /// Writes the document as canonical YAML. See [`to_string`].
    ///
    /// # Errors
    ///
    /// Only fails if a value cannot be written as YAML, which the model's
    /// types do not do.
    pub fn to_yaml(&self) -> Result<String, WriteError> {
        to_string(self)
    }
}

#[cfg(test)]
mod tests;
