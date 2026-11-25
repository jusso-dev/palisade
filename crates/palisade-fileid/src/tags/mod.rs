//! Content tagging (#44, feature `content-rules`).
//!
//! [`scan`] looks for byte patterns in a file and attaches string tags such
//! as `installer:scripted-setup` or `archive:embedded-pe`. Tags come from
//! two rule sets:
//!
//! - **The built-in set** ([`BUILTIN_TAGS`]), which is read-only. It
//!   recognises common installer engines, self-extracting archives,
//!   embedded executables and archives, compiled scripts and the standard
//!   anti-malware test file. Its tags cannot be redefined.
//! - **The organisation's rules** ([`RuleSetSource`]), carried in policy.
//!   A rule is a list of masked byte patterns (hex with nibble wildcards,
//!   text or wide text), each with a location (anywhere, at an offset, in a
//!   range, in a PE image's appended data or in the file's tail), and a
//!   condition (any, all, or at least N of them).
//!
//! # A pattern language, not a rule engine
//!
//! The rules are deliberately less expressive than a general pattern rule
//! language: no regular expressions, no gaps of variable length, no loops,
//! no arithmetic over the file and no modules. Every pattern has a fixed
//! length of at most [`MAX_PATTERN_LEN`] bytes, so checking it costs at
//! most that many comparisons. Patterns that are not at a fixed offset are
//! found through their longest exact run of bytes (an "atom", at least
//! [`MIN_ATOM_LEN`] bytes) with one multi-pattern automaton
//! (`aho-corasick`), in a single linear pass. So a scan's cost is linear in
//! the bytes scanned plus the candidate checks, and both are capped by
//! [`ScanLimits`].
//!
//! The rule format can be targeted by a front end for a general rule
//! syntax later. A YARA-syntax front end through the `yara-x` crate was
//! considered and not adopted: every release from 1.22 needs a newer Rust
//! than the workspace's minimum (1.94), and the last one that builds on
//! 1.94 brings in a WebAssembly compiler and about 110 more crates, with 37
//! build scripts (one generating code at build time), and takes the
//! workspace from 8 to 22 crates in more than one version, over the limit
//! of 10 (docs/dependencies.md).
//!
//! # Never a stall, never an error
//!
//! Tagging must not hold up identity, so a scan has a hard budget:
//!
//! - Files larger than [`ScanLimits::max_file_size`] (32 MiB by default)
//!   are scanned in part: the first `max_file_size` bytes and the last
//!   [`TAIL_SCAN_LEN`]. The report then has [`CONTENT_SCAN_PARTIAL`].
//! - Scanning stops once [`ScanLimits::max_scan_bytes`] bytes have been
//!   read, [`ScanLimits::max_match_steps`] pattern comparisons have been
//!   made, or [`ScanLimits::timeout`] (2 s by default) has passed. The
//!   report then has [`CONTENT_SCAN_TIMEOUT`].
//! - A read error ends the scan with [`CONTENT_SCAN_ERROR`].
//!
//! None of these is an error: [`scan`] always returns a [`TagReport`].
//! Tags found before the scan stopped are kept, because each is positive
//! evidence on its own. A missing tag is never evidence of absence when
//! the report has a status tag. Callers should treat such a file as not
//! fully inspected and fail conservative: a rule that requires a tag
//! should not be satisfied by its absence.
//!
//! The scan runs in the calling thread. The agent runs it off the identity
//! hot path, in a separate worker, after a file's identity is established
//! (#4, #59, #60). The budget bounds each call; the worker's own
//! scheduling, queueing and cancellation are the agent's.
//!
//! # Rule sets in policy
//!
//! A [`RuleSetSource`] is plain data (`serde`). It has a version, and
//! [`ContentRules::rules_digest`] is a SHA-256 over a canonical encoding of
//! it, so the policy bundle (#43) can record exactly which rules were in
//! force. The rule set has no signature of its own: it is part of the
//! policy bundle, whose signature (#225) covers it.

#![forbid(unsafe_code)]

mod builtin;
mod pattern;
mod rules;
mod scan;

use std::io::{self, Cursor, Read, Seek};
use std::time::Duration;

pub use builtin::{
    ARCHIVE_EMBEDDED_ARCHIVE, ARCHIVE_EMBEDDED_PE, ARCHIVE_SELF_EXTRACTING_7Z,
    ARCHIVE_SELF_EXTRACTING_CAB, ARCHIVE_SELF_EXTRACTING_ZIP, BUILTIN_TAGS, BUILTIN_VERSION,
    INSTALLER_BUNDLE_BOOTSTRAPPER, INSTALLER_MSI_WRAPPER, INSTALLER_SCRIPTED_SETUP,
    INSTALLER_SETUP_LOADER, INSTALLER_SETUP_STREAM, SCRIPT_COMPILED_AUTOMATION,
    SCRIPT_FROZEN_PYTHON, TEST_MALWARE_TEST_FILE,
};
pub use rules::{
    Condition, Location, PatternSource, RuleError, RuleErrorKind, RuleSetSource, RuleSource,
    StringSource,
};

/// At most this many organisation rules.
pub const MAX_RULES: usize = 256;
/// At most this many strings over all organisation rules.
pub const MAX_STRINGS: usize = 1024;
/// At most this many strings in one rule.
pub const MAX_STRINGS_PER_RULE: usize = 32;
/// The longest pattern, in bytes.
pub const MAX_PATTERN_LEN: usize = 256;
/// The shortest run of exact bytes a pattern needs, unless it is at a fixed
/// offset.
pub const MIN_ATOM_LEN: usize = 2;
/// The longest tag, in bytes.
pub const MAX_TAG_LEN: usize = 96;
/// The largest [`Location::Tail`], and how much of the end of a file over
/// [`ScanLimits::max_file_size`] is scanned.
pub const TAIL_SCAN_LEN: u64 = 1024 * 1024;

/// The scan stopped at a limit of [`ScanLimits`] other than the file size.
pub const CONTENT_SCAN_TIMEOUT: &str = "content_scan_timeout";
/// The file is over [`ScanLimits::max_file_size`], so only its start and
/// its tail were scanned.
pub const CONTENT_SCAN_PARTIAL: &str = "content_scan_partial";
/// The reader failed.
pub const CONTENT_SCAN_ERROR: &str = "content_scan_error";

/// The per-file budget of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Files over this size are scanned in part ([`CONTENT_SCAN_PARTIAL`]).
    /// Default 32 MiB.
    pub max_file_size: u64,
    /// The most bytes read, counting the PE header probe and the overlap
    /// between chunks. Default 40 MiB, which covers a full scan of a file
    /// of `max_file_size`.
    pub max_scan_bytes: u64,
    /// The most candidate checks and pattern byte comparisons. Default
    /// 64 Mi.
    pub max_match_steps: u64,
    /// The most wall-clock time, checked between chunks and every few
    /// thousand candidate checks. Default 2 s. `None` turns it off, so a
    /// scan's result depends only on its input (for tests and fuzzing).
    pub timeout: Option<Duration>,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size: 32 * 1024 * 1024,
            max_scan_bytes: 40 * 1024 * 1024,
            max_match_steps: 64 * 1024 * 1024,
            timeout: Some(Duration::from_secs(2)),
        }
    }
}

/// The built-in rules and, optionally, the organisation's, compiled.
///
/// Compiling checks every limit, so a scan with a compiled set cannot fail.
/// The value is `Send` and `Sync`, so one compiled set can serve every
/// worker.
#[derive(Debug, Clone)]
pub struct ContentRules {
    compiled: rules::Compiled,
    rules_version: Option<u64>,
    rules_digest: Option<[u8; 32]>,
}

impl ContentRules {
    /// Compiles the built-in rules, plus `org` if given.
    ///
    /// # Errors
    ///
    /// A rule over a limit, with a bad tag or pattern, or reusing a tag.
    pub fn new(org: Option<&RuleSetSource>) -> Result<Self, RuleError> {
        Ok(Self {
            compiled: rules::compile(&builtin::rules(), org)?,
            rules_version: org.map(|o| o.version),
            rules_digest: org.map(rules::digest),
        })
    }

    /// The organisation rule set's version, if one was given.
    #[must_use]
    pub const fn rules_version(&self) -> Option<u64> {
        self.rules_version
    }

    /// SHA-256 over a canonical encoding of the organisation rule set, if
    /// one was given. Rule sets that match the same bytes in the same
    /// places have the same digest, however their hex is written.
    #[must_use]
    pub const fn rules_digest(&self) -> Option<[u8; 32]> {
        self.rules_digest
    }

    /// Every tag a scan can report from a rule, built-in first.
    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.compiled.rules.iter().map(|r| r.tag.as_str())
    }
}

/// How a scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanStatus {
    /// Every byte was scanned.
    Complete,
    /// The file is over [`ScanLimits::max_file_size`]; only its start and
    /// tail were scanned.
    Partial,
    /// A budget of [`ScanLimits`] ran out.
    Timeout,
    /// The reader failed.
    ReadError(io::ErrorKind),
}

impl ScanStatus {
    /// The status tag added to [`TagReport::tags`], if any.
    #[must_use]
    pub const fn tag(self) -> Option<&'static str> {
        match self {
            Self::Complete => None,
            Self::Partial => Some(CONTENT_SCAN_PARTIAL),
            Self::Timeout => Some(CONTENT_SCAN_TIMEOUT),
            Self::ReadError(_) => Some(CONTENT_SCAN_ERROR),
        }
    }
}

/// The result of [`scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagReport {
    /// The tags, in rule order (built-in first), then the status tag, if
    /// any.
    pub tags: Vec<String>,
    /// How the scan ended.
    pub status: ScanStatus,
    /// [`BUILTIN_VERSION`].
    pub builtin_version: u16,
    /// [`ContentRules::rules_version`].
    pub rules_version: Option<u64>,
    /// [`ContentRules::rules_digest`].
    pub rules_digest: Option<[u8; 32]>,
    /// The file length, as the reader reported it.
    pub file_size: u64,
    /// The PE headers parsed, so rules with
    /// [`RuleSource::require_pe`] applied.
    pub is_pe: bool,
    /// Bytes read.
    pub bytes_scanned: u64,
    /// Candidate checks and pattern byte comparisons made.
    pub match_steps: u64,
}

impl TagReport {
    /// Whether the report has `tag`.
    #[must_use]
    pub fn has(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// Scans a file for content tags. Never fails and never exceeds `limits`;
/// see the [module documentation](self). The reader is left at an
/// unspecified position.
pub fn scan<R: Read + Seek + ?Sized>(
    reader: &mut R,
    rules: &ContentRules,
    limits: &ScanLimits,
) -> TagReport {
    scan::run(reader, rules, limits)
}

/// [`scan`] over bytes held in memory.
#[must_use]
pub fn scan_bytes(data: &[u8], rules: &ContentRules, limits: &ScanLimits) -> TagReport {
    scan(&mut Cursor::new(data), rules, limits)
}
