//! What a trace may say about the facts it read (#41, #18).
//!
//! A trace leaves the agent, so it follows the privacy settings when it is
//! built, never afterwards. Nothing unredacted is ever held in a
//! [`Trace`](super::Trace).
//!
//! - **Object facts** (hashes, signers, version resources) are written by
//!   default, because "why not allowed?" needs them.
//! - **Paths** are written by default, after redaction. They can be
//!   withheld.
//! - **Context facts** (user, device, session) are withheld by default.
//! - A withheld value becomes a reference: its field, and a keyed digest
//!   (HMAC-SHA-256 under [`Privacy::digest_key`]) if a key is set, so two
//!   traces can be compared without revealing the value. With no key, the
//!   value is simply omitted.
//! - Every value that is written first passes the [`Redactor`]: each match
//!   of a redaction pattern is replaced with `[redacted]`. Command lines
//!   (#7) will pass the same redactor when they become facts.
//! - Every written value is cut to [`MAX_VALUE_CHARS`] characters.

use hmac::{KeyInit, Mac};
use regex_automata::meta::Regex;
use serde::Serialize;
use sha2::Sha256;

use crate::model::{Field, FieldClass};

/// The most characters of one value a trace writes.
pub const MAX_VALUE_CHARS: usize = 128;

/// The most values of one fact a trace writes.
pub const MAX_VALUES: usize = 4;

/// The most redaction patterns.
pub const MAX_REDACTION_PATTERNS: usize = 64;

/// The text that replaces a redacted match.
pub const REDACTED: &str = "[redacted]";

/// The longest redaction pattern, in bytes.
pub const MAX_PATTERN_BYTES: usize = 4096;

/// The most memory one compiled redaction pattern may use, in bytes.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

/// Patterns whose matches are removed from every value a trace writes.
/// Patterns use the same linear-time engine as policy regular expressions
/// (RE2 syntax; no look-around or backreferences), unanchored and
/// case-insensitive.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    patterns: Vec<Regex>,
}

/// A redaction pattern did not compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactionError {
    /// The index of the pattern.
    pub index: usize,
    /// What is wrong with it.
    pub message: String,
}

impl core::fmt::Display for RedactionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "redaction pattern {}: {}", self.index, self.message)
    }
}

impl std::error::Error for RedactionError {}

impl Redactor {
    /// No patterns: values are written as they are.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Compiles redaction patterns.
    ///
    /// # Errors
    ///
    /// Returns the first pattern that does not compile, is too large, or
    /// is past [`MAX_REDACTION_PATTERNS`].
    pub fn new<S: AsRef<str>>(patterns: &[S]) -> Result<Self, RedactionError> {
        if patterns.len() > MAX_REDACTION_PATTERNS {
            return Err(RedactionError {
                index: MAX_REDACTION_PATTERNS,
                message: format!("at most {MAX_REDACTION_PATTERNS} patterns"),
            });
        }
        let mut out = Vec::with_capacity(patterns.len());
        for (index, p) in patterns.iter().enumerate() {
            if p.as_ref().len() > MAX_PATTERN_BYTES {
                return Err(RedactionError {
                    index,
                    message: format!("at most {MAX_PATTERN_BYTES} bytes"),
                });
            }
            let mut b = Regex::builder();
            b.configure(
                Regex::config()
                    .nfa_size_limit(Some(PATTERN_SIZE_LIMIT))
                    .hybrid_cache_capacity(PATTERN_SIZE_LIMIT)
                    .backtrack(false),
            );
            b.syntax(regex_automata::util::syntax::Config::new().case_insensitive(true));
            let re = b.build(p.as_ref()).map_err(|e| RedactionError {
                index,
                message: e.to_string(),
            })?;
            out.push(re);
        }
        Ok(Self { patterns: out })
    }

    /// `text` with every match of every pattern replaced by [`REDACTED`].
    /// Every pattern is matched against the original text, and overlapping
    /// or adjacent matches are merged, so one pattern can never hide part of
    /// a secret from another, and no pattern ever sees a marker. Empty
    /// matches remove nothing.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut spans: Vec<(usize, usize)> = self
            .patterns
            .iter()
            .flat_map(|re| re.find_iter(text).map(|m| (m.start(), m.end())))
            .filter(|(start, end)| start < end)
            .collect();
        if spans.is_empty() {
            return text.to_owned();
        }
        spans.sort_unstable();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let mut current: Option<(usize, usize)> = None;
        for (start, end) in spans {
            match current {
                Some((s, e)) if start <= e => current = Some((s, e.max(end))),
                Some((s, e)) => {
                    out.push_str(&text[last..s]);
                    out.push_str(REDACTED);
                    last = e;
                    current = Some((start, end));
                }
                None => current = Some((start, end)),
            }
        }
        if let Some((s, e)) = current {
            out.push_str(&text[last..s]);
            out.push_str(REDACTED);
            last = e;
        }
        out.push_str(&text[last..]);
        out
    }
}

/// The privacy settings a trace is built under. Its `Debug` form never
/// shows the digest key.
#[derive(Clone)]
pub struct Privacy {
    /// Write hashes, signers and version resources. Default `true`.
    pub reveal_object_facts: bool,
    /// Write paths, after redaction. Default `true`.
    pub reveal_paths: bool,
    /// Write user, device and session facts. Default `false`.
    pub reveal_context: bool,
    /// The key of the digest written for a withheld value. `None`: the
    /// value is omitted with no digest.
    pub digest_key: Option<[u8; 32]>,
    /// Applied to every value written.
    pub redactor: Redactor,
}

impl Privacy {
    /// The defaults: object facts and paths written, context withheld, no
    /// digest key and no redaction patterns.
    pub const DEFAULT: Self = Self {
        reveal_object_facts: true,
        reveal_paths: true,
        reveal_context: false,
        digest_key: None,
        redactor: Redactor::none(),
    };

    /// Whether values of `field` are written.
    #[must_use]
    pub const fn reveals(&self, field: Field) -> bool {
        if field.is_context() {
            self.reveal_context
        } else if matches!(field.class(), FieldClass::Path | FieldClass::FileName) {
            self.reveal_paths
        } else {
            self.reveal_object_facts
        }
    }

    /// The digest of a withheld value: `hmac-sha256:` and 64 hex digits of
    /// HMAC-SHA-256 over the field name, a zero byte and the value.
    #[must_use]
    pub fn digest(&self, field: Field, value: &str) -> Option<String> {
        let key = self.digest_key?;
        let mut mac = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&key).ok()?;
        mac.update(super::record::field_name(field).as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = String::from("hmac-sha256:");
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        Some(out)
    }

    /// A value as the trace writes it: redacted, then cut to
    /// [`MAX_VALUE_CHARS`]. The flag says whether it was cut.
    #[must_use]
    pub fn text(&self, value: &str) -> (String, bool) {
        clip(&self.redactor.redact(value))
    }
}

impl core::fmt::Debug for Privacy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Privacy")
            .field("reveal_object_facts", &self.reveal_object_facts)
            .field("reveal_paths", &self.reveal_paths)
            .field("reveal_context", &self.reveal_context)
            .field("digest_key", &self.digest_key.map(|_| "[set]"))
            .field("redactor", &self.redactor)
            .finish()
    }
}

impl Default for Privacy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// `value` cut to [`MAX_VALUE_CHARS`] characters, and whether it was cut.
pub(crate) fn clip(value: &str) -> (String, bool) {
    match value.char_indices().nth(MAX_VALUE_CHARS) {
        Some((end, _)) => (format!("{}…", &value[..end]), true),
        None => (value.to_owned(), false),
    }
}

/// What the trace says about one fact of the subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Observed {
    /// The field, as a document writes it.
    pub field: String,
    /// Whether the fact was known. An unknown fact has no values.
    pub known: bool,
    /// The values, if the privacy settings reveal the field: redacted and
    /// cut. A signature that is not trusted is followed by its status in
    /// parentheses.
    pub values: Vec<String>,
    /// The values are withheld by the privacy settings.
    pub withheld: bool,
    /// The keyed digests of the withheld values, if a key is set.
    pub digests: Vec<String>,
    /// Some values were cut, or more than [`MAX_VALUES`] were left out.
    pub truncated: bool,
}

impl Observed {
    /// Builds what the trace says about `field`, given its raw values
    /// (`None` if the fact is unknown).
    pub(crate) fn new(field: Field, raw: Option<Vec<String>>, privacy: &Privacy) -> Self {
        let name = super::record::field_name(field);
        let Some(raw) = raw else {
            return Self {
                field: name,
                known: false,
                values: Vec::new(),
                withheld: false,
                digests: Vec::new(),
                truncated: false,
            };
        };
        let mut truncated = raw.len() > MAX_VALUES;
        let raw = &raw[..raw.len().min(MAX_VALUES)];
        if privacy.reveals(field) {
            let values = raw
                .iter()
                .map(|v| {
                    let (text, cut) = privacy.text(v);
                    truncated |= cut;
                    text
                })
                .collect();
            Self {
                field: name,
                known: true,
                values,
                withheld: false,
                digests: Vec::new(),
                truncated,
            }
        } else {
            Self {
                field: name,
                known: true,
                values: Vec::new(),
                withheld: true,
                digests: raw
                    .iter()
                    .filter_map(|v| privacy.digest(field, v))
                    .collect(),
                truncated,
            }
        }
    }
}
