//! `%NAME%` environment-variable expansion, as Windows does it.

use alloc::string::String;
use core::fmt;

/// The longest expansion accepted, in characters: the Windows limit for an
/// environment block value.
pub const MAX_EXPANDED_CHARS: usize = 32_767;

/// An expansion failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandError {
    /// The result would be longer than [`MAX_EXPANDED_CHARS`].
    TooLong,
}

impl fmt::Display for ExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "the expansion is longer than {MAX_EXPANDED_CHARS} characters"
            ),
        }
    }
}

impl core::error::Error for ExpandError {}

/// Replaces each `%NAME%` in `input` with `lookup(NAME)`.
///
/// The rules, which the Windows implementation and the mocks share:
///
/// - The text between a `%` and the next `%` is a name. A name that
///   `lookup` does not know is left as written, `%NAME%`, and scanning
///   continues after its closing `%`.
/// - `%%` (an empty name) and a `%` with no closing `%` are left as written.
/// - Values are inserted literally: a `%` inside a value is not expanded
///   again, so a user-controlled variable cannot pull in another one.
///
/// Names are passed to `lookup` exactly as written; case-insensitive lookup
/// is the caller's (the [`Environment`](super::Environment) implementation's)
/// job.
///
/// # Errors
///
/// [`ExpandError::TooLong`] if the result exceeds [`MAX_EXPANDED_CHARS`].
pub fn expand_env_vars(
    input: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, ExpandError> {
    let mut out = String::new();
    let mut chars = 0usize;
    let mut push = |out: &mut String, s: &str| {
        chars = chars.saturating_add(s.chars().count());
        if chars > MAX_EXPANDED_CHARS {
            return Err(ExpandError::TooLong);
        }
        out.push_str(s);
        Ok(())
    };
    let mut rest = input;
    while let Some(start) = rest.find('%') {
        let (before, from_percent) = rest.split_at(start);
        push(&mut out, before)?;
        let after = from_percent.get(1..).unwrap_or_default();
        let Some(end) = after.find('%') else {
            // No closing `%`: the rest is literal.
            push(&mut out, from_percent)?;
            return Ok(out);
        };
        let name = after.get(..end).unwrap_or_default();
        let value = if name.is_empty() { None } else { lookup(name) };
        if let Some(value) = value {
            push(&mut out, &value)?;
        } else {
            push(&mut out, "%")?;
            push(&mut out, name)?;
            push(&mut out, "%")?;
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    push(&mut out, rest)?;
    Ok(out)
}
