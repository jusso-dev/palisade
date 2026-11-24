//! Name normalisation for matching version-info fields (#45).
//!
//! Version strings come from the file, so the same name can arrive padded,
//! with odd spacing or in another Unicode form. [`NormalizedName`] keeps
//! the original and gives two match forms:
//!
//! - [`NormalizedName::normalized`]: NUL padding stripped, trimmed, inner
//!   whitespace runs collapsed to one space, then Unicode NFC.
//! - [`NormalizedName::folded`]: that, case-folded the way the OS compares
//!   names case-insensitively: each character maps to its simple upper-case
//!   form ([`crate::fsctx::fold_case`], the same folding path rules use).
//!
//! Rules match on the folded form; reports show the original.

#![forbid(unsafe_code)]

use unicode_normalization::UnicodeNormalization;

use crate::fsctx::fold_case;

/// A version-info string with its match forms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedName {
    original: String,
    normalized: String,
    folded: String,
}

impl NormalizedName {
    /// Normalises `original`.
    #[must_use]
    pub fn new(original: &str) -> Self {
        let unpadded = original.trim_end_matches('\0');
        let mut collapsed = String::with_capacity(unpadded.len());
        for word in unpadded.split(|c: char| c.is_whitespace() || c == '\0') {
            if word.is_empty() {
                continue;
            }
            if !collapsed.is_empty() {
                collapsed.push(' ');
            }
            collapsed.push_str(word);
        }
        let normalized: String = collapsed.nfc().collect();
        let folded = fold_case(&normalized);
        Self {
            original: original.to_owned(),
            normalized,
            folded,
        }
    }

    /// The string as the file has it.
    #[must_use]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Trimmed, whitespace-collapsed, NFC.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.normalized
    }

    /// [`Self::normalized`], case-folded for case-insensitive matching.
    #[must_use]
    pub fn folded(&self) -> &str {
        &self.folded
    }

    /// Whether `other` matches this name case-insensitively, as the OS
    /// would compare them.
    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.folded == Self::new(other).folded
    }
}
