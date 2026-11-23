//! Semantic versions for document schemas.

use core::fmt;
use core::str::FromStr;

use crate::ParseError;

/// A schema version, `MAJOR.MINOR.PATCH`.
///
/// A minor version adds optional fields, and a major version is a breaking
/// change. A reader accepts any document with its own major version (see
/// [`SchemaVersion::is_readable_by`]).
///
/// The text form is strict: three decimal numbers without leading zeros,
/// signs, pre-release or build suffixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion {
    /// Incremented for breaking changes.
    pub major: u64,
    /// Incremented for additive, optional changes.
    pub minor: u64,
    /// Incremented for clarifications that change no document's meaning.
    pub patch: u64,
}

impl SchemaVersion {
    /// Builds a version from its parts.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Whether a reader that implements `reader` may read a document at this
    /// version: the major versions must be equal, and any minor is accepted.
    #[must_use]
    pub const fn is_readable_by(&self, reader: Self) -> bool {
        self.major == reader.major
    }
}

impl FromStr for SchemaVersion {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        const ERR: ParseError = ParseError("expected a version MAJOR.MINOR.PATCH");
        let mut parts = s.split('.');
        let mut next = || -> Result<u64, ParseError> {
            let part = parts.next().ok_or(ERR)?;
            let digits_only = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            if !digits_only || (part.len() > 1 && part.starts_with('0')) {
                return Err(ERR);
            }
            part.parse().map_err(|_| ERR)
        };
        let version = Self::new(next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(ERR);
        }
        Ok(version)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

crate::string_serde!(SchemaVersion, "a version MAJOR.MINOR.PATCH");

#[cfg(feature = "schema")]
impl schemars::JsonSchema for SchemaVersion {
    fn schema_name() -> alloc::borrow::Cow<'static, str> {
        "SchemaVersion".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A semantic version MAJOR.MINOR.PATCH, without pre-release or build suffixes.",
            "type": "string",
            "pattern": "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"
        })
    }
}
