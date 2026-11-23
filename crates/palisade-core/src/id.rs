//! Identifiers: UUIDv7 values in canonical lowercase form, and typed IDs.

use core::fmt;
use core::str::FromStr;

use crate::ParseError;

/// A UUID version 7, as used for every Palisade object ID.
///
/// The only accepted text form is the canonical one: 36 characters, lowercase
/// hexadecimal, hyphens at the standard positions. Uppercase, braces, URNs
/// and other UUID versions are rejected, so that each ID has exactly one
/// spelling and can be compared as text. Generating IDs needs a clock and a
/// random source, so it is left to the caller (the server, #10).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid7([u8; 16]);

impl Uuid7 {
    /// Wraps 16 bytes. Returns `None` unless the version is 7 and the variant
    /// is the RFC 9562 one (`10xx`).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        if bytes[6] >> 4 == 7 && bytes[8] >> 6 == 0b10 {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// The 16 bytes, in network order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl FromStr for Uuid7 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        const ERR: ParseError = ParseError("expected a UUIDv7 in canonical lowercase form");
        if s.len() != 36 {
            return Err(ERR);
        }
        let mut bytes = [0u8; 16];
        let mut nibble = 0usize;
        for (i, c) in s.bytes().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(ERR);
                }
                continue;
            }
            let value = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => return Err(ERR),
            };
            // 36 bytes minus 4 hyphens leaves exactly 32 digits, so this is in range.
            let byte = bytes.get_mut(nibble / 2).ok_or(ERR)?;
            *byte |= if nibble % 2 == 0 { value << 4 } else { value };
            nibble += 1;
        }
        Self::from_bytes(bytes).ok_or(ERR)
    }
}

impl fmt::Display for Uuid7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid7({self})")
    }
}

crate::string_serde!(Uuid7, "a UUIDv7 in canonical lowercase form");

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Uuid7 {
    fn schema_name() -> alloc::borrow::Cow<'static, str> {
        "Uuid7".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "A UUID version 7 in canonical lowercase form.",
            "type": "string",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        })
    }
}

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        pub struct $name(pub Uuid7);

        impl From<Uuid7> for $name {
            fn from(id: Uuid7) -> Self {
                Self(id)
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, ParseError> {
                s.parse().map(Self)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

typed_id!(
    /// The stable ID of a policy.
    PolicyId
);
typed_id!(
    /// The stable ID of a rule set.
    RuleSetId
);
typed_id!(
    /// The stable ID of a rule. It is never reused, even after the rule is deleted.
    RuleId
);
