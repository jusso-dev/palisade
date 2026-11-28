#![doc = include_str!("../README.md")]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod codeintegrity;
mod id;
mod mode;
mod object;
pub mod path;
pub mod platform;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod upcase;
mod verification;
mod version;

use core::fmt;

pub use id::{PolicyId, RuleId, RuleSetId, Uuid7};
pub use mode::Mode;
pub use object::{ObjectType, ScriptKind};
pub use verification::VerificationError;
pub use version::SchemaVersion;

/// A value could not be parsed from its text form.
///
/// The message is static, so parsing never allocates and the type works in
/// `no_std` builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(&'static str);

impl ParseError {
    /// What was expected.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl core::error::Error for ParseError {}

/// Implements serde for a type through its `Display` and `FromStr` impls, so
/// the text form has exactly one definition.
macro_rules! string_serde {
    ($ty:ty, $expecting:literal) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;
                impl serde::de::Visitor<'_> for Visitor {
                    type Value = $ty;
                    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        f.write_str($expecting)
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$ty, E> {
                        v.parse()
                            .map_err(|e: $crate::ParseError| E::custom(e.message()))
                    }
                }
                deserializer.deserialize_str(Visitor)
            }
        }
    };
}
pub(crate) use string_serde;

#[cfg(test)]
mod tests;
