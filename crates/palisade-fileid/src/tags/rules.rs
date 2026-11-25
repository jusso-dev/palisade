//! Rule sources, as policy carries them, and their compiled form.
//!
//! A [`RuleSetSource`] is plain data (`serde`), so the policy bundle can
//! carry it in whatever encoding it uses. [`compile`] checks every limit
//! and turns it into the matcher tables the scanner uses.

#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::pattern::Pattern;
use super::{MAX_RULES, MAX_STRINGS, MAX_STRINGS_PER_RULE, MAX_TAG_LEN, TAIL_SCAN_LEN};

/// A versioned set of organisation rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSource {
    /// The rule set version, reported with every result
    /// ([`TagReport::rules_version`](super::TagReport::rules_version)).
    pub version: u64,
    /// The rules, at most [`MAX_RULES`].
    pub rules: Vec<RuleSource>,
}

/// One rule: when its condition holds, the file gets its tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSource {
    /// The tag: two to four segments of lowercase ASCII letters, digits and
    /// `-`, joined by `:` (`installer:in-house`), at most [`MAX_TAG_LEN`]
    /// bytes. It must not be a built-in tag.
    pub tag: String,
    /// The rule applies only to a PE image (one that
    /// [`filetype::classify`](crate::filetype::classify) would call
    /// [`FileKind::Pe`](crate::filetype::FileKind::Pe)).
    #[serde(default)]
    pub require_pe: bool,
    /// The rule applies only to files of at most this many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<u64>,
    /// The rule does not apply to a file that starts with this pattern.
    /// It is checked before anything else is scanned. If it cannot be
    /// checked (the file ended early, or the budget ran out first), the
    /// rule is not reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unless_start: Option<PatternSource>,
    /// The strings, 1 to [`MAX_STRINGS_PER_RULE`].
    pub strings: Vec<StringSource>,
    /// How many of the strings must be found.
    #[serde(default)]
    pub condition: Condition,
}

/// A pattern and where it may be found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringSource {
    /// What to look for.
    pub pattern: PatternSource,
    /// Where its first byte may be.
    #[serde(default)]
    pub location: Location,
}

/// What a string matches. Every pattern has a fixed length of at most
/// [`MAX_PATTERN_LEN`](super::MAX_PATTERN_LEN) bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PatternSource {
    /// Hex bytes, with `?` for a wildcard nibble and optional whitespace:
    /// `"4D 5A ?? 0?"`. Unless the string's location is
    /// [`Location::At`], it needs a run of at least [`MIN_ATOM_LEN`](super::MIN_ATOM_LEN) exact
    /// bytes, which the searcher looks for.
    Hex(String),
    /// The UTF-8 bytes of the text, exactly.
    Text(String),
    /// ASCII text as UTF-16LE.
    WideText(String),
    /// A PE image: `MZ`, then an `e_lfanew` of `0x40` to `0x400` that
    /// points at `PE\0\0`.
    PeImage,
}

/// Where a string's first byte may be, as a file offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Location {
    /// Anywhere in the scanned bytes.
    #[default]
    Anywhere,
    /// Exactly at this offset. Such a string needs no exact-byte run.
    At(u64),
    /// At this offset or later.
    From(u64),
    /// From `start` up to, but not including, `end`.
    Range {
        /// The first offset.
        start: u64,
        /// One past the last offset.
        end: u64,
    },
    /// In a PE image's appended data: at or after the end of the headers
    /// and of every section's raw data. A certificate table, if any, is
    /// not excluded. Never matches in a file that is not a PE image. A
    /// crafted image can declare section data or headers that cover its
    /// appended bytes, so that such a rule does not match them: a missing
    /// tag is never proof of absence.
    Overlay,
    /// In the last this many bytes of the file (1 to [`TAIL_SCAN_LEN`]).
    Tail(u64),
}

/// How many of a rule's strings must be found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Condition {
    /// At least one.
    #[default]
    Any,
    /// Every one.
    All,
    /// At least this many (1 to the number of strings).
    AtLeast(u32),
}

/// Why a rule set was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// The error is in the built-in rules, not the organisation's (a bug).
    pub builtin: bool,
    /// The index of the rule, if the error is in one.
    pub rule: Option<usize>,
    /// The index of the string in that rule, if the error is in one.
    pub string: Option<usize>,
    /// What is wrong.
    pub kind: RuleErrorKind,
}

/// What is wrong with a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleErrorKind {
    /// More than [`MAX_RULES`] rules, or more than [`MAX_STRINGS`] strings
    /// over all rules.
    TooManyRules,
    /// A rule has no strings.
    NoStrings,
    /// A rule has more than [`MAX_STRINGS_PER_RULE`] strings.
    TooManyStrings,
    /// The tag is not two to four `[a-z0-9-]` segments joined by `:`, or
    /// is longer than [`MAX_TAG_LEN`].
    BadTag,
    /// The tag is a built-in tag; the built-in set is read-only.
    ReservedTag,
    /// Two rules have the same tag.
    DuplicateTag,
    /// Hex text that is not pairs of hex digits or `?`.
    BadHex,
    /// A pattern of no bytes.
    EmptyPattern,
    /// A pattern longer than [`MAX_PATTERN_LEN`](super::MAX_PATTERN_LEN) bytes.
    PatternTooLong,
    /// Wide text that is not ASCII.
    WideNotAscii,
    /// A string that is not at a fixed offset has no run of
    /// [`MIN_ATOM_LEN`](super::MIN_ATOM_LEN) exact bytes.
    NoAtom,
    /// [`Condition::AtLeast`] of zero or of more than the strings.
    BadCondition,
    /// An empty [`Location::Range`], or a [`Location::Tail`] of zero or
    /// more than [`TAIL_SCAN_LEN`].
    BadLocation,
    /// The search automaton could not be built.
    TooLarge,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.builtin {
            f.write_str("built-in ")?;
        }
        f.write_str("content rule")?;
        if let Some(rule) = self.rule {
            write!(f, " {rule}")?;
        }
        if let Some(string) = self.string {
            write!(f, ", string {string}")?;
        }
        write!(f, ": {:?}", self.kind)
    }
}

impl std::error::Error for RuleError {}

/// What a compiled string matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Matcher {
    Bytes(Pattern),
    PeImage,
}

/// The lowest and highest `e_lfanew` a [`PatternSource::PeImage`] accepts.
const PE_IMAGE_LFANEW: std::ops::RangeInclusive<usize> = 0x40..=0x400;

impl Matcher {
    /// The most bytes a match can cover.
    pub(super) fn span(&self) -> usize {
        match self {
            Self::Bytes(p) => p.len(),
            Self::PeImage => *PE_IMAGE_LFANEW.end() + 4,
        }
    }

    /// The most comparisons one check costs.
    pub(super) fn cost(&self) -> u64 {
        match self {
            Self::Bytes(p) => u64::try_from(p.len()).unwrap_or(u64::MAX),
            Self::PeImage => 8,
        }
    }

    /// Whether a match starts at `at`. Bytes past the end of `buf` never
    /// match.
    pub(super) fn matches_at(&self, buf: &[u8], at: usize) -> bool {
        let Some(rest) = buf.get(at..) else {
            return false;
        };
        match self {
            Self::Bytes(p) => p.matches(rest),
            Self::PeImage => {
                let lfanew = rest
                    .get(0x3c..0x40)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_le_bytes)
                    .and_then(|v| usize::try_from(v).ok());
                rest.starts_with(b"MZ")
                    && lfanew.is_some_and(|e| {
                        PE_IMAGE_LFANEW.contains(&e) && rest.get(e..e + 4) == Some(&b"PE\0\0"[..])
                    })
            }
        }
    }

    /// The exact bytes the searcher looks for, and their offset in the
    /// pattern.
    fn atom(&self) -> Option<(usize, Vec<u8>)> {
        match self {
            Self::Bytes(p) => p.atom().map(|(at, bytes)| (at, bytes.to_vec())),
            Self::PeImage => Some((0, b"MZ".to_vec())),
        }
    }
}

/// A compiled string.
#[derive(Debug, Clone)]
pub(super) struct CompiledString {
    pub(super) matcher: Matcher,
    pub(super) location: Location,
}

/// A compiled rule. Its strings are `strings` in [`Compiled::strings`].
#[derive(Debug, Clone)]
pub(super) struct CompiledRule {
    pub(super) tag: String,
    pub(super) require_pe: bool,
    pub(super) max_file_size: Option<u64>,
    /// The index of the `unless_start` pattern in [`Compiled::prefixes`].
    pub(super) unless: Option<usize>,
    pub(super) strings: std::ops::Range<usize>,
    /// How many of `strings` must be found.
    pub(super) need: usize,
}

/// A string at a fixed offset, checked by the chunk that owns the offset.
#[derive(Debug, Clone, Copy)]
pub(super) struct Anchored {
    pub(super) start: u64,
    pub(super) string: usize,
}

/// Every rule, ready to scan with.
#[derive(Debug, Clone)]
pub(super) struct Compiled {
    pub(super) strings: Vec<CompiledString>,
    pub(super) rules: Vec<CompiledRule>,
    /// The searcher over the distinct atoms, if any string has one.
    pub(super) searcher: Option<aho_corasick::AhoCorasick>,
    /// For each atom (by searcher pattern ID): the strings that use it,
    /// with the atom's offset in each.
    pub(super) atom_users: Vec<Vec<(usize, usize)>>,
    /// Strings at a fixed offset, sorted by `start`.
    pub(super) anchored: Vec<Anchored>,
    /// The longest span of any string (at least 1).
    pub(super) window: usize,
    /// The `unless_start` patterns. They are checked against the start of
    /// the file before anything else is scanned, so a rule is never
    /// reported with its filter unchecked.
    pub(super) prefixes: Vec<Matcher>,
    /// The longest span of any prefix pattern.
    pub(super) prefix_len: usize,
}

/// Compiles the built-in rules followed by the organisation's, checking
/// every limit.
pub(super) fn compile(
    builtin: &[RuleSource],
    org: Option<&RuleSetSource>,
) -> Result<Compiled, RuleError> {
    let org_rules = org.map_or(&[][..], |o| &o.rules[..]);
    if org_rules.len() > MAX_RULES {
        return Err(RuleError {
            builtin: false,
            rule: None,
            string: None,
            kind: RuleErrorKind::TooManyRules,
        });
    }
    let mut out = Compiled {
        strings: Vec::new(),
        rules: Vec::new(),
        searcher: None,
        atom_users: Vec::new(),
        anchored: Vec::new(),
        window: 1,
        prefixes: Vec::new(),
        prefix_len: 0,
    };
    let mut atoms: Vec<Vec<u8>> = Vec::new();
    let mut org_strings = 0_usize;
    let sources = builtin
        .iter()
        .enumerate()
        .map(|(i, r)| (true, i, r))
        .chain(org_rules.iter().enumerate().map(|(i, r)| (false, i, r)));
    for (is_builtin, index, rule) in sources {
        let err = |string, kind| RuleError {
            builtin: is_builtin,
            rule: Some(index),
            string,
            kind,
        };
        if !is_builtin {
            org_strings = org_strings.saturating_add(rule.strings.len());
            if org_strings > MAX_STRINGS {
                return Err(err(None, RuleErrorKind::TooManyRules));
            }
        }
        check_tag(&rule.tag).map_err(|kind| err(None, kind))?;
        if out.rules.iter().any(|r| r.tag == rule.tag) {
            let builtin_tag = builtin.iter().any(|b| b.tag == rule.tag);
            let kind = if builtin_tag && !is_builtin {
                RuleErrorKind::ReservedTag
            } else {
                RuleErrorKind::DuplicateTag
            };
            return Err(err(None, kind));
        }
        if !is_builtin && builtin.iter().any(|b| b.tag == rule.tag) {
            return Err(err(None, RuleErrorKind::ReservedTag));
        }
        if rule.strings.is_empty() {
            return Err(err(None, RuleErrorKind::NoStrings));
        }
        if rule.strings.len() > MAX_STRINGS_PER_RULE {
            return Err(err(None, RuleErrorKind::TooManyStrings));
        }
        let need = match rule.condition {
            Condition::Any => 1,
            Condition::All => rule.strings.len(),
            Condition::AtLeast(n) => usize::try_from(n)
                .ok()
                .filter(|n| (1..=rule.strings.len()).contains(n))
                .ok_or_else(|| err(None, RuleErrorKind::BadCondition))?,
        };
        let first = out.strings.len();
        for (si, s) in rule.strings.iter().enumerate() {
            let matcher = compile_pattern(&s.pattern).map_err(|kind| err(Some(si), kind))?;
            check_location(s.location).map_err(|kind| err(Some(si), kind))?;
            add_string(&mut out, &mut atoms, matcher, s.location)
                .map_err(|kind| err(Some(si), kind))?;
        }
        let strings = first..out.strings.len();
        let unless = match &rule.unless_start {
            Some(p) => {
                let matcher = compile_pattern(p).map_err(|kind| err(None, kind))?;
                out.prefix_len = out.prefix_len.max(matcher.span());
                out.prefixes.push(matcher);
                Some(out.prefixes.len() - 1)
            }
            None => None,
        };
        out.rules.push(CompiledRule {
            tag: rule.tag.clone(),
            require_pe: rule.require_pe,
            max_file_size: rule.max_file_size,
            unless,
            strings,
            need,
        });
    }
    out.anchored.sort_by_key(|a| (a.start, a.string));
    if !atoms.is_empty() {
        let searcher = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::Standard)
            .build(&atoms)
            .map_err(|_| RuleError {
                builtin: false,
                rule: None,
                string: None,
                kind: RuleErrorKind::TooLarge,
            })?;
        out.searcher = Some(searcher);
    }
    Ok(out)
}

/// Adds one compiled string: to the anchored list if it is at a fixed
/// offset, otherwise under its atom.
fn add_string(
    out: &mut Compiled,
    atoms: &mut Vec<Vec<u8>>,
    matcher: Matcher,
    location: Location,
) -> Result<(), RuleErrorKind> {
    let index = out.strings.len();
    let span = matcher.span();
    out.window = out.window.max(span);
    if let Location::At(start) = location {
        out.anchored.push(Anchored {
            start,
            string: index,
        });
    } else {
        let (offset, atom) = matcher.atom().ok_or(RuleErrorKind::NoAtom)?;
        let id = match atoms.iter().position(|a| *a == atom) {
            Some(id) => id,
            None => {
                atoms.push(atom);
                out.atom_users.push(Vec::new());
                atoms.len() - 1
            }
        };
        if let Some(users) = out.atom_users.get_mut(id) {
            users.push((index, offset));
        }
    }
    out.strings.push(CompiledString { matcher, location });
    Ok(())
}

fn compile_pattern(p: &PatternSource) -> Result<Matcher, RuleErrorKind> {
    Ok(match p {
        PatternSource::Hex(text) => Matcher::Bytes(Pattern::from_hex(text)?),
        PatternSource::Text(text) => Matcher::Bytes(Pattern::from_text(text, false)?),
        PatternSource::WideText(text) => Matcher::Bytes(Pattern::from_text(text, true)?),
        PatternSource::PeImage => Matcher::PeImage,
    })
}

fn check_location(location: Location) -> Result<(), RuleErrorKind> {
    match location {
        Location::Range { start, end } if start >= end => Err(RuleErrorKind::BadLocation),
        Location::Tail(n) if n == 0 || n > TAIL_SCAN_LEN => Err(RuleErrorKind::BadLocation),
        _ => Ok(()),
    }
}

/// Two to four segments of `[a-z0-9-]`, each 1 to 32 bytes, joined by `:`.
fn check_tag(tag: &str) -> Result<(), RuleErrorKind> {
    if tag.len() > MAX_TAG_LEN {
        return Err(RuleErrorKind::BadTag);
    }
    let segments: Vec<&str> = tag.split(':').collect();
    let ok = tag.len() <= MAX_TAG_LEN
        && (2..=4).contains(&segments.len())
        && segments.iter().all(|s| {
            (1..=32).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(RuleErrorKind::BadTag)
    }
}

/// SHA-256 over a canonical encoding of a rule set that compiled: the
/// same rules give the same digest however their hex is spaced or cased,
/// and any change to what they match gives a different one.
pub(super) fn digest(set: &RuleSetSource) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"palisade-content-rules-v1\0");
    h.update(set.version.to_le_bytes());
    len(&mut h, set.rules.len());
    for rule in &set.rules {
        len(&mut h, rule.tag.len());
        h.update(rule.tag.as_bytes());
        h.update([u8::from(rule.require_pe)]);
        opt_u64(&mut h, rule.max_file_size);
        match &rule.unless_start {
            Some(p) => {
                h.update([1]);
                pattern(&mut h, p);
            }
            None => h.update([0]),
        }
        len(&mut h, rule.strings.len());
        for s in &rule.strings {
            pattern(&mut h, &s.pattern);
            match s.location {
                Location::Anywhere => h.update([0]),
                Location::At(n) => tagged(&mut h, 1, &[n]),
                Location::From(n) => tagged(&mut h, 2, &[n]),
                Location::Range { start, end } => tagged(&mut h, 3, &[start, end]),
                Location::Overlay => h.update([4]),
                Location::Tail(n) => tagged(&mut h, 5, &[n]),
            }
        }
        match rule.condition {
            Condition::Any => h.update([0]),
            Condition::All => h.update([1]),
            Condition::AtLeast(n) => tagged(&mut h, 2, &[u64::from(n)]),
        }
    }
    h.finalize().into()
}

fn len(h: &mut Sha256, n: usize) {
    h.update(u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
}

fn opt_u64(h: &mut Sha256, v: Option<u64>) {
    match v {
        Some(v) => tagged(h, 1, &[v]),
        None => h.update([0]),
    }
}

fn tagged(h: &mut Sha256, tag: u8, values: &[u64]) {
    h.update([tag]);
    for v in values {
        h.update(v.to_le_bytes());
    }
}

/// A pattern by what it matches: the value and mask bytes.
fn pattern(h: &mut Sha256, p: &PatternSource) {
    match compile_pattern(p) {
        Ok(Matcher::Bytes(p)) => {
            h.update([0]);
            p.encode(h);
        }
        Ok(Matcher::PeImage) => h.update([1]),
        // Only rule sets that compiled are digested.
        Err(_) => h.update([0xff]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(tag: &str, strings: Vec<StringSource>) -> RuleSource {
        RuleSource {
            tag: tag.to_owned(),
            require_pe: false,
            max_file_size: None,
            unless_start: None,
            strings,
            condition: Condition::Any,
        }
    }

    fn hex(h: &str) -> StringSource {
        StringSource {
            pattern: PatternSource::Hex(h.to_owned()),
            location: Location::Anywhere,
        }
    }

    fn org(rules: Vec<RuleSource>) -> RuleSetSource {
        RuleSetSource { version: 7, rules }
    }

    fn compile_err(set: &RuleSetSource) -> RuleError {
        compile(&[], Some(set)).unwrap_err()
    }

    #[test]
    fn tags_are_checked() {
        for good in ["a:b", "installer:in-house", "a:b:c:d", "x1:2y"] {
            assert_eq!(check_tag(good), Ok(()), "{good}");
        }
        let long = format!("a:{}", "b".repeat(33));
        for bad in [
            "",
            "a",
            "A:b",
            "a:",
            ":b",
            "a::b",
            "a:b:c:d:e",
            "a_b:c",
            "a b:c",
            "a:é",
            &long,
        ] {
            assert_eq!(check_tag(bad), Err(RuleErrorKind::BadTag), "{bad}");
        }
    }

    #[test]
    fn limits_are_enforced() {
        let e = compile_err(&org(vec![rule("a:b", vec![])]));
        assert_eq!((e.rule, e.kind), (Some(0), RuleErrorKind::NoStrings));
        let many = vec![hex("41 42 43"); MAX_STRINGS_PER_RULE + 1];
        assert_eq!(
            compile_err(&org(vec![rule("a:b", many)])).kind,
            RuleErrorKind::TooManyStrings
        );
        let rules: Vec<_> = (0..=MAX_RULES)
            .map(|i| rule(&format!("a:r{i}"), vec![hex("41 42 43")]))
            .collect();
        assert_eq!(compile_err(&org(rules)).kind, RuleErrorKind::TooManyRules);
        let rules: Vec<_> = (0..MAX_RULES)
            .map(|i| {
                rule(
                    &format!("a:r{i}"),
                    vec![hex("41 42 43"); MAX_STRINGS_PER_RULE],
                )
            })
            .collect();
        const { assert!(MAX_RULES * MAX_STRINGS_PER_RULE > MAX_STRINGS) };
        assert_eq!(compile_err(&org(rules)).kind, RuleErrorKind::TooManyRules);
    }

    #[test]
    fn patterns_need_an_atom_unless_anchored() {
        let e = compile_err(&org(vec![rule("a:b", vec![hex("41"), hex("41 ?? 42")])]));
        assert_eq!((e.string, e.kind), (Some(0), RuleErrorKind::NoAtom));
        let at = StringSource {
            pattern: PatternSource::Hex("41".to_owned()),
            location: Location::At(5),
        };
        assert!(compile(&[], Some(&org(vec![rule("a:b", vec![at])]))).is_ok());
        let unless = RuleSource {
            unless_start: Some(PatternSource::Hex("4?".to_owned())),
            ..rule("a:b", vec![hex("41 42 43")])
        };
        assert!(compile(&[], Some(&org(vec![unless]))).is_ok());
    }

    #[test]
    fn conditions_and_locations_are_checked() {
        for (condition, ok) in [
            (Condition::AtLeast(0), false),
            (Condition::AtLeast(1), true),
            (Condition::AtLeast(2), true),
            (Condition::AtLeast(3), false),
            (Condition::All, true),
        ] {
            let r = RuleSource {
                condition,
                ..rule("a:b", vec![hex("41 42 43"), hex("44 45 46")])
            };
            let result = compile(&[], Some(&org(vec![r])));
            assert_eq!(result.is_ok(), ok, "{condition:?}");
            if !ok {
                assert_eq!(result.unwrap_err().kind, RuleErrorKind::BadCondition);
            }
        }
        for (location, ok) in [
            (Location::Range { start: 4, end: 4 }, false),
            (Location::Range { start: 4, end: 5 }, true),
            (Location::Tail(0), false),
            (Location::Tail(TAIL_SCAN_LEN), true),
            (Location::Tail(TAIL_SCAN_LEN + 1), false),
        ] {
            let s = StringSource {
                pattern: PatternSource::Hex("41 42 43".to_owned()),
                location,
            };
            let result = compile(&[], Some(&org(vec![rule("a:b", vec![s])])));
            assert_eq!(result.is_ok(), ok, "{location:?}");
        }
    }

    #[test]
    fn built_in_tags_are_read_only() {
        let builtin = [rule("installer:x", vec![hex("41 42 43")])];
        let e = compile(
            &builtin,
            Some(&org(vec![rule("installer:x", vec![hex("44 45 46")])])),
        )
        .unwrap_err();
        assert_eq!((e.builtin, e.kind), (false, RuleErrorKind::ReservedTag));
        let twice = org(vec![
            rule("a:b", vec![hex("41 42 43")]),
            rule("a:b", vec![hex("44 45 46")]),
        ]);
        let e = compile(&builtin, Some(&twice)).unwrap_err();
        assert_eq!((e.rule, e.kind), (Some(1), RuleErrorKind::DuplicateTag));
        assert!(e.to_string().contains("content rule 1"));
    }

    #[test]
    fn atoms_are_shared() {
        let set = org(vec![
            rule("a:b", vec![hex("41 42 43 ?? 01")]),
            rule("a:c", vec![hex("41 42 43 ?? 02"), hex("44 45 46")]),
        ]);
        let c = compile(&[], Some(&set)).unwrap();
        assert_eq!(c.atom_users.len(), 2);
        assert_eq!(c.atom_users[0], vec![(0, 0), (1, 0)]);
        assert_eq!(c.window, 5);
    }

    #[test]
    fn digest_is_canonical() {
        let a = org(vec![rule("a:b", vec![hex("4d5a 90")])]);
        let b = org(vec![rule("a:b", vec![hex("4D 5A 90")])]);
        let text = org(vec![rule(
            "a:b",
            vec![StringSource {
                pattern: PatternSource::Text("MZ\u{90}".to_owned()),
                location: Location::Anywhere,
            }],
        )]);
        assert_eq!(digest(&a), digest(&b));
        // "\u{90}" is two bytes in UTF-8, so this is a different pattern.
        assert_ne!(digest(&a), digest(&text));
        let mut changed = a.clone();
        changed.version = 8;
        assert_ne!(digest(&a), digest(&changed));
        let mut changed = a.clone();
        changed.rules[0].strings[0].location = Location::From(0);
        assert_ne!(digest(&a), digest(&changed));
        let mut changed = a.clone();
        changed.rules[0].require_pe = true;
        assert_ne!(digest(&a), digest(&changed));
        let mut changed = a.clone();
        changed.rules[0].condition = Condition::All;
        assert_ne!(digest(&a), digest(&changed));
    }

    #[test]
    fn pe_image_matcher() {
        let mut image = vec![0_u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(Matcher::PeImage.matches_at(&image, 0));
        assert!(!Matcher::PeImage.matches_at(&image, 1));
        assert!(!Matcher::PeImage.matches_at(&image[..0x83], 0), "cut short");
        image[0x3c..0x40].copy_from_slice(&0x20_u32.to_le_bytes());
        assert!(
            !Matcher::PeImage.matches_at(&image, 0),
            "e_lfanew too small"
        );
        image[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!Matcher::PeImage.matches_at(&image, 0));
        assert!(!Matcher::PeImage.matches_at(&image, usize::MAX));
    }
}
