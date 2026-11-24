//! Matching one criterion against the facts about one object (#31, #32).
//!
//! A [`Criterion`] is compiled once, when the policy is loaded, into a
//! [`CompiledCriterion`]: regular expressions and wildcards become
//! automata, and literal values are normalised and case-folded. Matching
//! then does no compilation and runs in time linear in the fact's length.
//!
//! # Three-valued results
//!
//! Every evaluation gives a [`Tri`]: `Match`, `NoMatch`, or `Unknown` when a
//! fact the criterion needs is missing or cannot be trusted. A negative
//! operator is the Kleene negation of its positive form, so a negated test
//! of an unknown fact is `Unknown`, never `Match`: "does not contain X" is
//! not satisfied by a value nobody computed. A whole tree combines these
//! results with the same logic, and a rule only matches on `Match`
//! ([`crate::condition`]), so `Unknown` never allows.
//!
//! # Several values
//!
//! A positive operator matches if **any** value matches. A negative
//! operator matches if **no** value matches: `not_contains [a, b]` means
//! the fact contains neither `a` nor `b`.
//!
//! # Comparing text
//!
//! Strings are compared after Unicode NFC normalisation, so composed and
//! decomposed spellings of one name are equal. Unless the criterion sets
//! `case_sensitive: true`, both sides are then folded with the Unicode
//! simple upper-case mapping: one character to one character, with no
//! locale rules, so the result does not depend on the machine's language.
//! This is how NTFS compares names: `i`, `I` and the dotless `ı` are equal
//! everywhere, and the dotted capital `İ` is distinct from all three. A
//! character whose upper case is several characters, such as `ß`, is left
//! as it is. Hash values are compared as hex digits in either case.
//!
//! # Paths
//!
//! Path facts and path values pass through the same lexical normalisation
//! ([`palisade_core::path`]). A path criterion evaluates to `Unknown` when
//! the path is missing, is not a drive or UNC path, or contains a short
//! (8.3) name the agent could not expand. A mapped network drive matches in
//! both its drive form and its UNC form ([`PathFact::alias`]).
//!
//! On `path.full` and `path.directory`:
//!
//! - `starts_with` ends at a component boundary: `C:\Tools` matches
//!   `C:\Tools\a.exe` but not `C:\ToolsX\a.exe`.
//! - A value may start with a path variable, such as `%PROGRAMFILES%\App`,
//!   for `equals`, `starts_with` and `wildcard` and their negations. The
//!   variable is expanded for this evaluation ([`PathVariables`]); a
//!   variable with no value makes the criterion `Unknown`.
//! - In wildcards, `*` matches any run of characters within one component
//!   (as a whole component it needs at least one character, so `C:\*`
//!   does not match the bare root `C:\`),
//!   `?` exactly one character other than `\`, and `**` any run of
//!   characters across components. As a whole component (`\**\`, a
//!   trailing `\**` or a leading `**\`), `**` matches zero or more whole
//!   components, so `C:\a\**` matches `C:\a` itself and everything below
//!   it, and `C:\a\**\b.exe` matches `C:\a\b.exe`. `[*]` and `[?]` match
//!   a literal `*` or `?`. A value written with `/` is read with `\`.
//! - An alternate data stream is its own object. On `path.full`, a value
//!   that does not name a stream never matches one, and a value that names
//!   a stream only matches streams: `C:\x\*` does not match
//!   `C:\x\a.txt:payload`, `C:\x\*:*` does, and `**:**` matches no plain
//!   file. A value names a stream when its last component has a `:` that is
//!   not a drive letter's. A regular expression never matches a stream. `path.directory`, `path.file_name` and
//!   `path.extension` describe the file that holds the stream.
//!
//! On every other string field, `*` and `**` match any run of characters,
//! and `?` matches one.
//!
//! **Path identity is only trusted where users cannot write.** In a rule
//! that lets an object run, trusts it or excludes it (an allow, and the
//! other actions with [`ActionKind::needs_identity`], #34), a positive
//! `path.*` test that would match evaluates to `Unknown`,
//! with the note [`Note::PathAclUnsafe`], unless the facts show that no
//! non-administrative principal can write the file or a directory above it.
//! `Unknown` rather than `NoMatch`, so that the test also fails closed under
//! negation.
//!
//! # Regular expressions
//!
//! `regex` and `not_regex` use a linear-time engine with RE2 semantics (a
//! lazy DFA with a PikeVM fallback; no backtracking).
//! Patterns are anchored at both ends and are case-insensitive unless
//! `case_sensitive: true`. Case-insensitive matching uses the engine's
//! Unicode simple case folding, which differs from the folding above for a
//! few characters (the dotless `ı` does not match `i` or `I`). On path
//! fields the fact is the normalised path, so write `\\` for each
//! separator. These constructs are not supported and are rejected when the
//! policy is validated:
//!
//! - look-around: `(?=…)`, `(?!…)`, `(?<=…)`, `(?<!…)`. Write the negative
//!   part as a second criterion with `not_regex`, in an `all` with the first.
//! - backreferences: `\1`, `\k<name>`.
//! - patterns whose compiled form exceeds [`REGEX_SIZE_LIMIT`].
//!
//! Path variables are not expanded inside regular expressions.
//!
//! # Versions
//!
//! A version is up to four dot-separated numbers, each at most 65535, with
//! missing parts read as zero: `10.0` equals `10.0.0.0`. Facts may also
//! separate the numbers with commas (`10, 0, 19041, 1`). A fact with a
//! non-numeric suffix (`10.0.19041.1 (release)`) is compared without it,
//! with the note [`Note::VersionSuffixStripped`]. A fact that is not a
//! version at all is `Unknown`, with [`Note::VersionUnparseable`], so it
//! never satisfies a version test in either direction. The bounds mean the
//! same in allow and deny rules: `version_between [min, max]` includes both.
//! On version fields, `equals` and `not_equals` compare versions too.
//!
//! # Signers
//!
//! A signer criterion looks at every signature on the object and matches
//! if any of them matches. Only signatures whose status is valid, valid
//! with an expired but timestamped certificate, or catalog-signed take
//! part: a revoked, untrusted, expired or digest-mismatched signature never
//! vouches for an object, and an unsigned object matches no signer.
//!
//! # Context
//!
//! Context criteria (#33) test the user, device and session in
//! [`EvalContext::context`] rather than the object. They follow the same
//! rules: a fact that was not collected is `Unknown`, and so is its
//! negation.
//!
//! - SIDs (`user.sid`, `user.primary_group`) are compared in canonical
//!   form: `s-1-5-32-544` equals `S-1-5-32-544`, and leading zeros are
//!   ignored. A SID fact that is not a SID is `Unknown`, with
//!   [`Note::FactMalformed`].
//! - Sets (`user.groups`, `device.groups`, `device.tags`) take `member_of`
//!   and `not_member_of`: `member_of` matches if the set holds any value,
//!   `not_member_of` if it holds none. Group members are SIDs or
//!   cloud-directory object IDs (GUIDs, in any case); a member of the fact
//!   that is neither is unknown, with [`Note::FactMalformed`], so it never
//!   lets `not_member_of` match. Tags are text, and case-insensitive unless
//!   `case_sensitive: true`.
//! - `user.name` is tested against both the account name (`DOMAIN\user`)
//!   and the user principal name, and matches if either does. A form that
//!   was not collected counts as `Unknown`, so a negative test only matches
//!   when both forms are known. Regular expressions are not allowed on it
//!   (#32); match principals by SID where you can.
//! - Yes-or-no facts take `is_true` and `is_false`, with no values.
//! - `session.type` takes `equals` and `not_equals` with the names
//!   `console`, `rdp`, `remote_shell`, `service`, `batch` and `network`.
//! - The other device and session facts are text or versions, compared as
//!   above.

use regex_automata::meta::Regex;
use unicode_normalization::UnicodeNormalization;

use palisade_core::path::{NormalizedPath, normalize};

use crate::context::{
    ContextFact, EvaluationContext, SessionType, normalize_principal, normalize_sid,
};
use crate::facts::{ObjectFacts, PathFact, PathVariable, PathVariables, SignerFact};
use crate::model::limits::MAX_VALUE_BYTES;
use crate::model::{ActionKind, Criterion, Field, FieldClass, Operator};

/// The most memory a compiled regular expression or wildcard may use, in
/// bytes. Larger patterns are rejected when the policy is validated.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The most regular expression values in one policy.
pub const MAX_REGEXES_PER_POLICY: usize = 2000;

/// A three-valued result, with Kleene logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Tri {
    /// The test failed.
    NoMatch = 0,
    /// The test passed.
    Match = 1,
    /// A fact the test needs is missing or cannot be trusted.
    Unknown = 2,
}

impl Tri {
    /// `Match` for `true`, `NoMatch` for `false`.
    #[must_use]
    pub const fn from_bool(b: bool) -> Self {
        if b { Self::Match } else { Self::NoMatch }
    }

    /// Kleene AND: `NoMatch` if either is `NoMatch`, else `Unknown` if
    /// either is `Unknown`, else `Match`.
    #[must_use]
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::NoMatch, _) | (_, Self::NoMatch) => Self::NoMatch,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Match, Self::Match) => Self::Match,
        }
    }

    /// Kleene OR: `Match` if either is `Match`, else `Unknown` if either is
    /// `Unknown`, else `NoMatch`.
    #[must_use]
    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Match, _) | (_, Self::Match) => Self::Match,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::NoMatch, Self::NoMatch) => Self::NoMatch,
        }
    }

    /// Kleene NOT: `Unknown` stays `Unknown`.
    #[must_use]
    pub const fn not(self) -> Self {
        match self {
            Self::NoMatch => Self::Match,
            Self::Match => Self::NoMatch,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// Something an evaluation noticed, for the decision trace (#41).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Note {
    /// A fact the criterion needs was not provided.
    FactMissing = 0,
    /// A path test in a rule that lets an object run, trusts it or excludes
    /// it matched a path that users may be able to write, or whose
    /// permissions are unknown.
    PathAclUnsafe = 1,
    /// The path contains a short (8.3) name the agent could not expand.
    ShortNameUnresolved = 2,
    /// The path is not a drive or UNC path, such as an unmapped device path.
    PathUnresolved = 3,
    /// A value names a path variable that has no value here.
    UnknownVariable = 4,
    /// A version fact is not a version.
    VersionUnparseable = 5,
    /// A version fact had a non-numeric suffix, which was ignored.
    VersionSuffixStripped = 6,
    /// The object has signatures, but none with a trusted status.
    SignerNotTrusted = 7,
    /// A fact is not in the form its field needs, such as a digest of the
    /// wrong length.
    FactMalformed = 8,
}

impl Note {
    /// Every note, in code order.
    pub const ALL: [Self; 9] = [
        Self::FactMissing,
        Self::PathAclUnsafe,
        Self::ShortNameUnresolved,
        Self::PathUnresolved,
        Self::UnknownVariable,
        Self::VersionUnparseable,
        Self::VersionSuffixStripped,
        Self::SignerNotTrusted,
        Self::FactMalformed,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FactMissing => "fact_missing",
            Self::PathAclUnsafe => "path_acl_unsafe",
            Self::ShortNameUnresolved => "short_name_unresolved",
            Self::PathUnresolved => "path_unresolved",
            Self::UnknownVariable => "unknown_variable",
            Self::VersionUnparseable => "version_unparseable",
            Self::VersionSuffixStripped => "version_suffix_stripped",
            Self::SignerNotTrusted => "signer_not_trusted",
            Self::FactMalformed => "fact_malformed",
        }
    }
}

/// A set of [`Note`]s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Notes(u16);

impl Notes {
    /// Adds a note.
    pub fn insert(&mut self, note: Note) {
        self.0 |= 1 << (note as u8);
    }

    /// Adds every note in `other`.
    pub fn extend(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Whether the set holds `note`.
    #[must_use]
    pub const fn contains(self, note: Note) -> bool {
        self.0 & (1 << (note as u8)) != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The notes in the set, in code order.
    pub fn iter(self) -> impl Iterator<Item = Note> {
        Note::ALL.into_iter().filter(move |n| self.contains(*n))
    }
}

/// The result of evaluating one criterion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Whether the criterion matched.
    pub result: Tri,
    /// What the evaluation noticed.
    pub notes: Notes,
}

/// What an evaluation needs besides the object's facts.
#[derive(Clone, Copy, Debug)]
pub struct EvalContext<'a> {
    /// The action of the rule the criterion belongs to. A rule that lets
    /// an object run, trusts it or excludes it
    /// ([`ActionKind::needs_identity`]) only trusts a path where users
    /// cannot write.
    pub action: ActionKind,
    /// The path variables, expanded for the user the process runs as.
    pub variables: &'a PathVariables,
    /// The user, device and session, for context criteria (#33).
    pub context: &'a EvaluationContext,
}

/// A version: four 16-bit parts, compared part by part.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub [u16; 4]);

impl Version {
    /// Reads a version written as 1 to 4 dot-separated decimal numbers,
    /// each at most 65535, with nothing else: the form a criterion value
    /// must have.
    #[must_use]
    pub fn parse_strict(s: &str) -> Option<Self> {
        if !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return None;
        }
        match Self::parse_fact(s)? {
            (version, false) => Some(version),
            (_, true) => None,
        }
    }

    /// Reads a version fact: leading white space is skipped, then 1 to 4
    /// numbers are read, separated by `.` or by `,` and optional spaces (as
    /// some version resources write them, `10, 0, 19041, 1`). Anything after
    /// them is ignored if it does not start with a digit, `.` or `,`.
    /// Returns the version and whether a suffix was ignored.
    #[must_use]
    pub fn parse_fact(s: &str) -> Option<(Self, bool)> {
        let mut parts = [0u16; 4];
        let mut rest = s.trim_start();
        for (i, part) in parts.iter_mut().enumerate() {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                return None;
            }
            *part = rest[..digits].parse().ok()?;
            rest = &rest[digits..];
            if i == 3 {
                break;
            }
            if let Some(after) = rest.strip_prefix('.') {
                rest = after;
            } else if let Some(after) = rest.strip_prefix(',') {
                rest = after.trim_start_matches(' ');
            } else {
                break;
            }
        }
        if rest.starts_with(|c: char| c.is_ascii_digit() || c == '.' || c == ',') {
            return None;
        }
        Some((Self(parts), !rest.is_empty()))
    }
}

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// Why a criterion could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    /// The index of the value at fault, or `None` for the criterion as a
    /// whole.
    pub value: Option<usize>,
    /// What is wrong.
    pub kind: CompileErrorKind,
}

/// What is wrong with a criterion that could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileErrorKind {
    /// The operator cannot be used on the field.
    OperatorFieldMismatch,
    /// The number of values is wrong for the operator.
    ValueCount,
    /// A value is not valid for the field, with the reason.
    InvalidValue(String),
    /// A regular expression uses look-around.
    RegexLookAround,
    /// A regular expression uses a backreference.
    RegexBackreference,
    /// A pattern compiles to more than [`REGEX_SIZE_LIMIT`] bytes.
    PatternTooLarge,
    /// A regular expression is not valid, with the parser's message.
    RegexSyntax(String),
    /// `case_sensitive` was set on a field that has no case, such as a
    /// hash, a version or a yes-or-no fact.
    CaseSensitivityNotApplicable,
}

impl core::fmt::Display for CompileErrorKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperatorFieldMismatch => f.write_str("the operator cannot be used on this field"),
            Self::ValueCount => f.write_str("wrong number of values for the operator"),
            Self::InvalidValue(why) => f.write_str(why),
            Self::RegexLookAround => f.write_str(
                "look-around is not supported, because the engine guarantees linear-time matching; \
                 put the positive part in a `regex` criterion and the excluded part in a `not_regex` \
                 criterion, both inside one `all`",
            ),
            Self::RegexBackreference => f.write_str(
                "backreferences are not supported, because the engine guarantees linear-time matching",
            ),
            Self::PatternTooLarge => write!(
                f,
                "the pattern compiles to more than {REGEX_SIZE_LIMIT} bytes; simplify it or split it into several values"
            ),
            Self::RegexSyntax(message) => write!(f, "invalid regular expression: {message}"),
            Self::CaseSensitivityNotApplicable => {
                f.write_str("`case_sensitive` does not apply: the field has no case to compare")
            }
        }
    }
}

/// A criterion ready to be matched. Build one with
/// [`CompiledCriterion::compile`].
#[derive(Clone, Debug)]
pub struct CompiledCriterion {
    field: Field,
    negated: bool,
    /// The positive form of the operator.
    operator: Operator,
    case_sensitive: bool,
    values: Values,
}

#[derive(Clone, Debug)]
enum Values {
    /// Lowercase hex digests, and their required length.
    Hash(Vec<String>, usize),
    /// NFC-normalised, case-folded literals.
    Text(Vec<String>),
    /// Literal path values, for `equals` and `starts_with` on path fields.
    PathLiteral(Vec<PathValue<String>>),
    /// Wildcard patterns on path fields.
    PathWildcard(Vec<PathValue<Regex>>),
    /// Wildcards on other fields, matched against the folded fact.
    Wildcard(Vec<Regex>),
    /// Regular expressions, matched against the NFC fact.
    Regex(Vec<Regex>),
    /// Versions to compare with.
    Version(Vec<Version>),
    /// One inclusive range.
    VersionRange(Version, Version),
    /// Canonical SIDs.
    Sid(Vec<String>),
    /// Canonical SIDs and object IDs, for `member_of` on a principal set.
    Principals(Vec<String>),
    /// NFC-normalised, case-folded tags, for `member_of` on a tag set.
    Tags(Vec<String>),
    /// Session types.
    Session(Vec<SessionType>),
    /// The value a yes-or-no fact must have.
    Bool(bool),
}

/// A value on `path.full` or `path.directory`.
#[derive(Clone, Debug)]
struct PathValue<T> {
    /// The variable the value starts with, if any.
    variable: Option<PathVariable>,
    /// The rest of the value: normalised and folded text, or a compiled
    /// pattern. After a variable it is empty or starts with `\`.
    rest: T,
    /// Whether the value names an alternate data stream.
    names_stream: bool,
}

impl CompiledCriterion {
    /// Compiles a criterion. Policy validation compiles every criterion, so
    /// a validated policy always compiles. Compiling also enforces the rules
    /// that validation checks on the criterion's shape, so a criterion that
    /// was never validated cannot compile past them: the operator must fit
    /// the field, the number of values must fit the operator, values are at
    /// most [`MAX_VALUE_BYTES`] bytes, and `case_sensitive` may only be set
    /// on a field with a case ([`FieldClass::has_case`]).
    ///
    /// # Errors
    ///
    /// Returns every problem found: one for the criterion as a whole, or one
    /// per value at fault.
    pub fn compile(c: &Criterion) -> Result<Self, Vec<CompileError>> {
        let whole = |kind| vec![CompileError { value: None, kind }];
        let class = c.field.class();
        if !c.operator.applies_to(class) {
            return Err(whole(CompileErrorKind::OperatorFieldMismatch));
        }
        let (min, max) = c.operator.value_count();
        if c.values.len() < min || c.values.len() > max {
            return Err(whole(CompileErrorKind::ValueCount));
        }
        // Checked before the default applies, so an explicit `false` is
        // rejected as well.
        if c.case_sensitive.is_some() && !class.has_case() {
            return Err(whole(CompileErrorKind::CaseSensitivityNotApplicable));
        }
        // Before any value is compiled, so an oversized pattern costs
        // nothing.
        let oversized: Vec<CompileError> = c
            .values
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                value_too_long(v).map(|why| CompileError {
                    value: Some(i),
                    kind: CompileErrorKind::InvalidValue(why),
                })
            })
            .collect();
        if !oversized.is_empty() {
            return Err(oversized);
        }
        let operator = c.operator.positive();
        let case_sensitive = c.case_sensitive.unwrap_or(false);
        let values = compile_values(c.field, operator, case_sensitive, &c.values)?;
        Ok(Self {
            field: c.field,
            negated: !c.operator.is_positive(),
            operator,
            case_sensitive,
            values,
        })
    }

    /// Checks one value against the criterion's field and operator, even
    /// when the operator does not fit the field or the number of values is
    /// wrong, so validation can report every bad value in one pass. This
    /// compiles the value, so a regular expression or wildcard costs its
    /// compilation. Checks that need several values together, such as the
    /// order of a `version_between` range, are left to [`Self::compile`].
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the value.
    pub fn check_value(c: &Criterion, value: &str) -> Result<(), CompileErrorKind> {
        let case_sensitive = c.case_sensitive.unwrap_or(false);
        compile_values(
            c.field,
            c.operator.positive(),
            case_sensitive,
            &[value.to_owned()],
        )
        .map(drop)
        .map_err(|mut errors| errors.remove(0).kind)
    }

    /// The field this criterion tests.
    #[must_use]
    pub const fn field(&self) -> Field {
        self.field
    }

    /// Evaluates the criterion against one object's facts.
    #[must_use]
    pub fn eval(&self, facts: &ObjectFacts, ctx: &EvalContext<'_>) -> Evaluation {
        let mut notes = Notes::default();
        let positive = self.eval_positive(facts, ctx, &mut notes);
        let result = if self.negated {
            positive.not()
        } else {
            positive
        };
        Evaluation { result, notes }
    }

    fn eval_positive(&self, facts: &ObjectFacts, ctx: &EvalContext<'_>, notes: &mut Notes) -> Tri {
        if self.field.is_context() {
            return match ctx.context.fact(self.field) {
                Some(fact) => self.eval_context(fact, notes),
                None => {
                    notes.insert(Note::FactMissing);
                    Tri::Unknown
                }
            };
        }
        match self.field {
            Field::SignerPublisher | Field::SignerIssuer | Field::SignerLeafThumbprint => {
                self.eval_signers(facts.signers.as_deref(), notes)
            }
            Field::PathFull | Field::PathDirectory | Field::PathFileName | Field::PathExtension => {
                let Some(path) = &facts.path else {
                    notes.insert(Note::FactMissing);
                    return Tri::Unknown;
                };
                let raw = self.eval_path(path, ctx, notes);
                // A path only identifies an object for a rule that lets it
                // run, trusts it or excludes it when users cannot replace
                // what is at that path.
                if raw == Tri::Match
                    && ctx.action.needs_identity()
                    && path.user_writable != Some(false)
                {
                    notes.insert(Note::PathAclUnsafe);
                    return Tri::Unknown;
                }
                raw
            }
            field => match facts.get(field) {
                Some(fact) => self.eval_value(fact, notes),
                None => {
                    notes.insert(Note::FactMissing);
                    Tri::Unknown
                }
            },
        }
    }

    fn eval_signers(&self, signers: Option<&[SignerFact]>, notes: &mut Notes) -> Tri {
        let Some(signers) = signers else {
            notes.insert(Note::FactMissing);
            return Tri::Unknown;
        };
        let mut result = Tri::NoMatch;
        let mut untrusted = false;
        for signer in signers {
            if !signer.status.is_trusted() {
                untrusted = true;
                continue;
            }
            let fact = match self.field {
                Field::SignerPublisher => signer.publisher.as_deref(),
                Field::SignerIssuer => signer.issuer.as_deref(),
                _ => signer.leaf_thumbprint_sha256.as_deref(),
            };
            result = result.or(match fact {
                Some(fact) => self.eval_value(fact, notes),
                None => {
                    notes.insert(Note::FactMissing);
                    Tri::Unknown
                }
            });
        }
        if result == Tri::NoMatch && untrusted {
            notes.insert(Note::SignerNotTrusted);
        }
        result
    }

    /// A fact about the user, device or session.
    fn eval_context(&self, fact: ContextFact<'_>, notes: &mut Notes) -> Tri {
        match (fact, &self.values) {
            (ContextFact::Bool(have), Values::Bool(want)) => Tri::from_bool(have == *want),
            (ContextFact::Session(have), Values::Session(want)) => {
                Tri::from_bool(want.contains(&have))
            }
            (ContextFact::Set(members), Values::Principals(want)) => {
                // A member that is neither a SID nor an object ID could be
                // any principal, so it is unknown rather than skipped: it
                // must not let `not_member_of` match.
                let mut result = Tri::NoMatch;
                for member in members {
                    if result == Tri::Match {
                        break;
                    }
                    result = result.or(match normalize_principal(member) {
                        Some(m) => Tri::from_bool(want.contains(&m)),
                        None => {
                            notes.insert(Note::FactMalformed);
                            Tri::Unknown
                        }
                    });
                }
                result
            }
            (ContextFact::Set(members), Values::Tags(want)) => Tri::from_bool(
                members
                    .iter()
                    .any(|m| want.contains(&fold(m, self.case_sensitive))),
            ),
            (ContextFact::Text(fact), Values::Sid(want)) => match normalize_sid(fact) {
                Some(have) => Tri::from_bool(want.contains(&have)),
                None => {
                    notes.insert(Note::FactMalformed);
                    Tri::Unknown
                }
            },
            (ContextFact::Names(account, upn), _) => {
                let mut result = Tri::NoMatch;
                for form in [account, upn] {
                    if result == Tri::Match {
                        break;
                    }
                    result = result.or(match form {
                        Some(name) => self.eval_value(name, notes),
                        None => {
                            notes.insert(Note::FactMissing);
                            Tri::Unknown
                        }
                    });
                }
                result
            }
            (ContextFact::Text(fact), _) => self.eval_value(fact, notes),
            // A fact of another shape than the field's values: the
            // collector produced something this field does not hold.
            _ => {
                notes.insert(Note::FactMalformed);
                Tri::Unknown
            }
        }
    }

    /// A hash, text or version fact.
    fn eval_value(&self, fact: &str, notes: &mut Notes) -> Tri {
        match &self.values {
            Values::Hash(values, hex_len) => {
                // A malformed digest is a fault in whoever computed it, not
                // evidence that the object differs.
                if fact.len() != *hex_len || !fact.bytes().all(|b| b.is_ascii_hexdigit()) {
                    notes.insert(Note::FactMalformed);
                    return Tri::Unknown;
                }
                Tri::from_bool(values.iter().any(|v| fact.eq_ignore_ascii_case(v)))
            }
            Values::Version(values) => match version_fact(fact, notes) {
                Some(have) => Tri::from_bool(values.iter().any(|want| match self.operator {
                    Operator::VersionGt => have > *want,
                    Operator::VersionGe => have >= *want,
                    Operator::VersionLt => have < *want,
                    Operator::VersionLe => have <= *want,
                    // `equals` and `version_eq`.
                    _ => have == *want,
                })),
                None => Tri::Unknown,
            },
            Values::VersionRange(min, max) => match version_fact(fact, notes) {
                Some(have) => Tri::from_bool(*min <= have && have <= *max),
                None => Tri::Unknown,
            },
            Values::Regex(patterns) => {
                let text: String = fact.nfc().collect();
                Tri::from_bool(patterns.iter().any(|p| p.is_match(&text)))
            }
            Values::Wildcard(patterns) => {
                let text = fold(fact, self.case_sensitive);
                Tri::from_bool(patterns.iter().any(|p| p.is_match(&text)))
            }
            Values::Text(values) => {
                let fact = fold(fact, self.case_sensitive);
                Tri::from_bool(values.iter().any(|v| self.text_op(&fact, v)))
            }
            // Only built for path fields, which `eval_path_form` handles,
            // and for context fields, which `eval_context` handles.
            Values::PathLiteral(_)
            | Values::PathWildcard(_)
            | Values::Sid(_)
            | Values::Principals(_)
            | Values::Tags(_)
            | Values::Session(_)
            | Values::Bool(_) => {
                notes.insert(Note::FactMalformed);
                Tri::Unknown
            }
        }
    }

    /// A text operator on folded text.
    fn text_op(&self, fact: &str, value: &str) -> bool {
        match self.operator {
            Operator::StartsWith => fact.starts_with(value),
            Operator::EndsWith => fact.ends_with(value),
            Operator::Contains => fact.contains(value),
            _ => fact == value,
        }
    }

    fn eval_path(&self, path: &PathFact, ctx: &EvalContext<'_>, notes: &mut Notes) -> Tri {
        if path.short_name_unresolved {
            notes.insert(Note::ShortNameUnresolved);
            return Tri::Unknown;
        }
        if !path.path.is_resolved() {
            notes.insert(Note::PathUnresolved);
            return Tri::Unknown;
        }
        let mut result = self.eval_path_form(&path.path, ctx, notes);
        if let Some(alias) = path.alias.as_ref().filter(|a| a.is_resolved()) {
            result = result.or(self.eval_path_form(alias, ctx, notes));
        }
        result
    }

    /// One spelling of the object's path.
    fn eval_path_form(
        &self,
        path: &NormalizedPath,
        ctx: &EvalContext<'_>,
        notes: &mut Notes,
    ) -> Tri {
        // A bare root (`C:\`) has no file name and no parent directory: a
        // test of either is unknown, so its negation cannot match.
        let bare_root = path.file_name().is_none();
        if bare_root && self.field != Field::PathFull {
            notes.insert(Note::FactMissing);
            return Tri::Unknown;
        }
        let raw = match self.field {
            // A file with no extension has the empty extension.
            Field::PathFileName => return self.eval_value(path.file_name().unwrap_or(""), notes),
            Field::PathExtension => return self.eval_value(path.extension().unwrap_or(""), notes),
            Field::PathDirectory => path.directory().unwrap_or(""),
            _ => path.as_str(),
        };
        // Only `path.full` can name a stream; on `path.directory` no value
        // or fact names one.
        let fact_stream = self.field == Field::PathFull && path.stream().is_some();
        match &self.values {
            Values::PathLiteral(values) => {
                let fact = fold(raw, self.case_sensitive);
                let mut result = Tri::NoMatch;
                for value in values {
                    // On `path.full`, a value that names a stream only
                    // matches streams, and one that does not only matches
                    // files.
                    if value.names_stream != fact_stream {
                        continue;
                    }
                    result = result.or(self.with_base(value.variable, ctx, notes, |base| {
                        let want = join(base, &value.rest);
                        match self.operator {
                            Operator::StartsWith => {
                                fact.strip_prefix(want.as_str()).is_some_and(|rest| {
                                    rest.is_empty()
                                        || rest.starts_with('\\')
                                        || want.ends_with('\\')
                                })
                            }
                            _ => fact == want,
                        }
                    }));
                }
                result
            }
            Values::PathWildcard(values) => {
                let fact = fold(raw, self.case_sensitive);
                let mut result = Tri::NoMatch;
                for value in values {
                    if value.names_stream != fact_stream {
                        continue;
                    }
                    result = result.or(self.with_base(value.variable, ctx, notes, |base| {
                        fact.strip_prefix(base).is_some_and(|rest| {
                            // A drive root (`C:\`) is the variable itself.
                            let rest = if rest == "\\" && base.len() == 2 && base.ends_with(':') {
                                ""
                            } else {
                                rest
                            };
                            value.rest.is_match(rest)
                        })
                    }));
                }
                result
            }
            // A regular expression cannot say whether it names a stream, so
            // on `path.full` it never matches one.
            Values::Regex(_) if fact_stream => Tri::NoMatch,
            // Text tests on `path.full` only count values that name a
            // stream when the fact is one, and only values that do not when
            // it is not.
            Values::Text(values) if self.field == Field::PathFull => {
                let fact = fold(raw, self.case_sensitive);
                Tri::from_bool(
                    values
                        .iter()
                        .any(|v| names_stream(v) == fact_stream && self.text_op(&fact, v)),
                )
            }
            _ => self.eval_value(raw, notes),
        }
    }

    /// Runs `test` with the folded expansion of `variable` (without a
    /// trailing separator), or with `""` when there is no variable. Matches
    /// if any expansion passes; `Unknown` if the variable has no value.
    fn with_base(
        &self,
        variable: Option<PathVariable>,
        ctx: &EvalContext<'_>,
        notes: &mut Notes,
        test: impl Fn(&str) -> bool,
    ) -> Tri {
        let Some(variable) = variable else {
            return Tri::from_bool(test(""));
        };
        let bases = ctx.variables.get(variable);
        if bases.is_empty() {
            notes.insert(Note::UnknownVariable);
            return Tri::Unknown;
        }
        Tri::from_bool(bases.iter().any(|base| {
            let base = fold(base.as_str().trim_end_matches('\\'), self.case_sensitive);
            test(&base)
        }))
    }
}

/// Whether a text value on a path names a stream: its last component (the
/// text after the last `\`) contains a `:`. A value that is only a drive
/// (`C:`) names none, and neither does `:\Program Files\`; `a.txt:s` and
/// `a:payload` do.
fn names_stream(v: &str) -> bool {
    let last = v.rsplit('\\').next().unwrap_or(v);
    let b = v.as_bytes();
    let only_drive = b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    !only_drive && last.contains(':')
}

/// `base` followed by `rest`, keeping the separator of a drive root:
/// `C:` and `""` give `C:\`.
fn join(base: &str, rest: &str) -> String {
    let mut out = String::with_capacity(base.len() + rest.len() + 1);
    out.push_str(base);
    out.push_str(rest);
    if rest.is_empty() && base.len() == 2 && base.ends_with(':') {
        out.push('\\');
    }
    out
}

/// Why a criterion value is too long, if it is: more than
/// [`MAX_VALUE_BYTES`] bytes. Validation reports the same message.
pub(crate) fn value_too_long(value: &str) -> Option<String> {
    (value.len() > MAX_VALUE_BYTES).then(|| {
        format!(
            "{} bytes; at most {MAX_VALUE_BYTES} are allowed",
            value.len()
        )
    })
}

/// Compiles the values of a criterion whose operator fits its field.
fn compile_values(
    field: Field,
    operator: Operator,
    case_sensitive: bool,
    values: &[String],
) -> Result<Values, Vec<CompileError>> {
    fn each<T>(
        values: &[String],
        f: impl Fn(&str) -> Result<T, CompileErrorKind>,
    ) -> Result<Vec<T>, Vec<CompileError>> {
        let mut out = Vec::with_capacity(values.len());
        let mut errors = Vec::new();
        for (i, v) in values.iter().enumerate() {
            match f(v) {
                Ok(t) => out.push(t),
                Err(kind) => errors.push(CompileError {
                    value: Some(i),
                    kind,
                }),
            }
        }
        if errors.is_empty() {
            Ok(out)
        } else {
            Err(errors)
        }
    }
    let invalid = |why: &str| CompileErrorKind::InvalidValue(why.to_owned());

    Ok(match field.class() {
        FieldClass::Hash { hex_len } => Values::Hash(
            each(values, |v| match normalize_hex(v) {
                Some(hex) if hex.len() == hex_len => Ok(hex),
                _ => Err(CompileErrorKind::InvalidValue(format!(
                    "expected {hex_len} hexadecimal digits, optionally after `0x`"
                ))),
            })?,
            hex_len,
        ),
        FieldClass::Version => {
            let versions = each(values, |v| {
                Version::parse_strict(v).ok_or_else(|| {
                    invalid(
                        "expected a version of 1 to 4 dot-separated numbers, each at most 65535",
                    )
                })
            })?;
            match (operator, versions.as_slice()) {
                (Operator::VersionBetween, [min, max]) => {
                    if min > max {
                        return Err(vec![CompileError {
                            value: Some(1),
                            kind: CompileErrorKind::InvalidValue(format!(
                                "the maximum {max} is below the minimum {min}"
                            )),
                        }]);
                    }
                    Values::VersionRange(*min, *max)
                }
                _ => Values::Version(versions),
            }
        }
        FieldClass::Sid => Values::Sid(each(values, |v| {
            normalize_sid(v).ok_or_else(|| invalid("expected a SID, such as `S-1-5-32-544`"))
        })?),
        FieldClass::PrincipalSet => Values::Principals(each(values, |v| {
            normalize_principal(v).ok_or_else(|| {
                invalid(
                    "expected a SID, such as `S-1-5-32-544`, or a directory object ID, such as `00000000-0000-0000-0000-000000000000`",
                )
            })
        })?),
        FieldClass::TagSet => Values::Tags(each(values, |v| Ok(fold(v, case_sensitive)))?),
        FieldClass::SessionType => Values::Session(each(values, |v| {
            SessionType::from_name(v).ok_or_else(|| {
                invalid("expected one of `console`, `rdp`, `remote_shell`, `service`, `batch`, `network`")
            })
        })?),
        // The operator alone says what the fact must be; the number of
        // values (none) is checked with the operator.
        FieldClass::Bool => Values::Bool(operator == Operator::IsTrue),
        _ if operator == Operator::Regex => Values::Regex(each(values, |v| {
            compile_regex(&v.nfc().collect::<String>(), case_sensitive)
        })?),
        FieldClass::Path => match operator {
            Operator::Wildcard => Values::PathWildcard(each(values, |v| {
                let (variable, text, names_stream) = path_value(v, true)?;
                let rest = wildcard_regex(&fold(&text, case_sensitive), true)?;
                Ok(PathValue {
                    variable,
                    rest,
                    names_stream,
                })
            })?),
            Operator::Equals | Operator::StartsWith => Values::PathLiteral(each(values, |v| {
                let (variable, text, names_stream) = path_value(v, false)?;
                Ok(PathValue {
                    variable,
                    rest: fold(&text, case_sensitive),
                    names_stream,
                })
            })?),
            // `ends_with` and `contains` test the text: the value is only
            // folded, with `/` read as `\`. They do not expand path
            // variables, so a value that names one is a mistake.
            _ => Values::Text(each(values, |v| {
                if let Some(name) = known_variable_anywhere(v) {
                    return Err(CompileErrorKind::InvalidValue(format!(
                        "`%{name}%` is only expanded by `equals`, `starts_with` and `wildcard`"
                    )));
                }
                Ok(fold(&v.replace('/', "\\"), case_sensitive))
            })?),
        },
        FieldClass::FileName | FieldClass::Text | FieldClass::PrincipalName => {
            let check = |v: &str| {
                if field == Field::PathExtension && v.starts_with('.') {
                    return Err(invalid("write the extension without its leading `.`"));
                }
                if matches!(field, Field::PathFileName | Field::PathExtension)
                    && v.contains(['\\', '/'])
                {
                    return Err(invalid("a file name cannot contain `\\` or `/`"));
                }
                Ok(fold(v, case_sensitive))
            };
            match operator {
                Operator::Wildcard => {
                    Values::Wildcard(each(values, |v| wildcard_regex(&check(v)?, false))?)
                }
                _ => Values::Text(each(values, check)?),
            }
        }
    })
}

/// Splits a value on `path.full` or `path.directory` into its variable and
/// the normalised rest, and reports whether it names a stream.
///
/// Without a variable, a literal must be a drive or UNC path; a wildcard
/// may be anything, such as `**\cmd.exe`. After a variable, the rest must
/// be empty or start with `\`, and must not contain `.` or `..` components,
/// which could climb out of the variable's directory.
fn path_value(
    v: &str,
    wildcard: bool,
) -> Result<(Option<PathVariable>, String, bool), CompileErrorKind> {
    let invalid = |why: String| CompileErrorKind::InvalidValue(why);
    let after_leading = variable_syntax(v).map_or(v, |(_, rest)| rest);
    if let Some(name) = known_variable_anywhere(after_leading) {
        return Err(invalid(format!(
            "`%{name}%` is only expanded at the start of a value"
        )));
    }
    let Some((name, rest)) = variable_syntax(v) else {
        // A wildcard drive (`?:\`, `*:\`) is read as a drive, under a
        // stand-in letter, so its `:` is not taken for a stream.
        let b = v.as_bytes();
        if wildcard
            && b.len() >= 2
            && matches!(b[0], b'?' | b'*')
            && b[1] == b':'
            && matches!(b.get(2), Some(b'\\' | b'/'))
        {
            let path = normalize(&format!("Q:\\{}", &v[2..]));
            let text = format!("{}{}", char::from(b[0]), &path.as_str()[1..]);
            return Ok((None, text, path.stream().is_some()));
        }
        let path = normalize(v);
        if !wildcard && !path.is_resolved() {
            return Err(invalid(
                "expected a full drive or UNC path, such as `C:\\Tools` or `\\\\server\\share`, or a path variable such as `%PROGRAMFILES%`".to_owned(),
            ));
        }
        let names_stream = path.stream().is_some();
        return Ok((None, path.as_str().to_owned(), names_stream));
    };
    let Some(variable) = PathVariable::from_name(name) else {
        return Err(invalid(format!("`%{name}%` is not a known path variable")));
    };
    let body = rest.trim_start_matches(['\\', '/']);
    if body.len() == rest.len() && !rest.is_empty() {
        return Err(invalid(format!(
            "`%{name}%` must be followed by `\\` or end the value"
        )));
    }
    // A stream-type suffix does not hide a `.` or `..` (`..::$DATA`).
    if body
        .split(['\\', '/'])
        .map(|part| part.split(':').next().unwrap_or(part))
        .any(|part| part == "." || part == "..")
    {
        return Err(invalid(
            "a value that starts with a path variable cannot contain `.` or `..` components"
                .to_owned(),
        ));
    }
    if body.is_empty() {
        return Ok((Some(variable), String::new(), false));
    }
    // Normalise under a stand-in root, so the rest is read as path
    // components and never as a UNC or device prefix.
    let path = normalize(&format!("C:\\{body}"));
    let text = match &path.as_str()[2..] {
        "\\" => String::new(),
        rest => rest.to_owned(),
    };
    Ok((Some(variable), text, path.stream().is_some()))
}

/// Parses a version fact, recording what was noticed.
fn version_fact(fact: &str, notes: &mut Notes) -> Option<Version> {
    match Version::parse_fact(fact) {
        Some((version, suffix)) => {
            if suffix {
                notes.insert(Note::VersionSuffixStripped);
            }
            Some(version)
        }
        None => {
            notes.insert(Note::VersionUnparseable);
            None
        }
    }
}

/// NFC-normalises `s`, then folds it with the simple upper-case mapping
/// unless `case_sensitive`.
#[must_use]
pub fn fold(s: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        s.nfc().collect()
    } else {
        s.nfc().map(simple_upper).collect()
    }
}

/// The Unicode simple upper-case mapping: `c` itself when its upper case is
/// not exactly one character.
fn simple_upper(c: char) -> char {
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

/// The first known path variable written anywhere in `value`, such as
/// `TEMP` in `\\%TEMP%\\`.
fn known_variable_anywhere(value: &str) -> Option<&str> {
    value.match_indices('%').find_map(|(i, _)| {
        let (name, _) = variable_syntax(&value[i..])?;
        PathVariable::from_name(name).map(|_| name)
    })
}

/// `%NAME%` at the start of `value`, where `NAME` is ASCII letters, digits
/// and `_`: the name and the rest of the value.
fn variable_syntax(value: &str) -> Option<(&str, &str)> {
    let body = value.strip_prefix('%')?;
    let end = body.find('%')?;
    let name = &body[..end];
    let valid = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    valid.then(|| (name, &body[end + 1..]))
}

/// The canonical form of a hash value: without a `0x` prefix, in lowercase.
/// `None` if the rest is not hexadecimal.
#[must_use]
pub fn normalize_hex(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| digits.to_ascii_lowercase())
}

/// The engine configuration: a linear-time engine (a lazy DFA backed by
/// a PikeVM, never a backtracker), with the size limits of #32.
fn engine() -> regex_automata::meta::Builder {
    let mut b = Regex::builder();
    b.configure(
        Regex::config()
            .nfa_size_limit(Some(REGEX_SIZE_LIMIT))
            .hybrid_cache_capacity(REGEX_SIZE_LIMIT)
            // Off explicitly, so a dependency that enables the bounded
            // backtracker through feature unification cannot turn it on.
            .backtrack(false),
    );
    b
}

fn build_error(e: &regex_automata::meta::BuildError) -> CompileErrorKind {
    if e.size_limit().is_some() {
        CompileErrorKind::PatternTooLarge
    } else {
        CompileErrorKind::RegexSyntax(e.to_string())
    }
}

/// Compiles a user's regular expression, anchored at both ends.
fn compile_regex(pattern: &str, case_sensitive: bool) -> Result<Regex, CompileErrorKind> {
    use regex_syntax::ast::ErrorKind;
    use regex_syntax::hir::{Hir, Look};

    // Parse first, and reject anything that does not parse on its own. The
    // anchors are added to the parsed tree, and the engine is built from
    // that tree, so no pattern text is ever joined to other text: no
    // pattern can escape the anchors (`a)|(?:b` is a syntax error), and
    // nothing is printed and parsed again.
    let hir = regex_syntax::ParserBuilder::new()
        .case_insensitive(!case_sensitive)
        .build()
        .parse(pattern)
        .map_err(|e| match &e {
            regex_syntax::Error::Parse(ast) => match ast.kind() {
                ErrorKind::UnsupportedLookAround => CompileErrorKind::RegexLookAround,
                ErrorKind::UnsupportedBackreference => CompileErrorKind::RegexBackreference,
                _ => CompileErrorKind::RegexSyntax(e.to_string()),
            },
            _ => CompileErrorKind::RegexSyntax(e.to_string()),
        })?;
    let anchored = Hir::concat(vec![Hir::look(Look::Start), hir, Hir::look(Look::End)]);
    engine()
        .build_from_hir(&anchored)
        .map_err(|e| build_error(&e))
}

/// One piece of a wildcard pattern.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    Literal(char),
    Separator,
    Star,
    DoubleStar,
    One,
}

fn tokens(pattern: &str, path: bool) -> Vec<Token> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '[' if matches!(chars.get(i + 1), Some('*' | '?'))
                && chars.get(i + 2) == Some(&']') =>
            {
                out.push(Token::Literal(chars[i + 1]));
                i += 3;
            }
            '*' => {
                let run = chars[i..].iter().take_while(|c| **c == '*').count();
                out.push(if run > 1 {
                    Token::DoubleStar
                } else {
                    Token::Star
                });
                i += run;
            }
            '?' => {
                out.push(Token::One);
                i += 1;
            }
            '\\' if path => {
                out.push(Token::Separator);
                i += 1;
            }
            c => {
                out.push(Token::Literal(c));
                i += 1;
            }
        }
    }
    out
}

/// Compiles a folded wildcard pattern to an anchored regular expression.
fn wildcard_regex(pattern: &str, path: bool) -> Result<Regex, CompileErrorKind> {
    let mut toks = tokens(pattern, path);
    if path {
        // `**\**` is the same as `**`: drop a whole-component `**` that
        // directly follows another.
        let mut i = 0;
        while i + 2 < toks.len() {
            let whole_first =
                toks[i] == Token::DoubleStar && (i == 0 || toks[i - 1] == Token::Separator);
            let whole_second = toks[i + 2] == Token::DoubleStar
                && matches!(toks.get(i + 3), None | Some(Token::Separator));
            if whole_first && toks[i + 1] == Token::Separator && whole_second {
                toks.drain(i + 1..i + 3);
            } else {
                i += 1;
            }
        }
    }
    let mut re = String::from(r"(?s)\A");
    let mut i = 0;
    while i < toks.len() {
        let next = toks.get(i + 1).copied();
        let after = toks.get(i + 2).copied();
        match toks[i] {
            // `\**\`: zero or more whole components.
            Token::Separator
                if path && next == Some(Token::DoubleStar) && after == Some(Token::Separator) =>
            {
                re.push_str(r"\\(?:.*\\)?");
                i += 3;
            }
            // A trailing `\**`: the directory itself or anything below it.
            Token::Separator if path && next == Some(Token::DoubleStar) && after.is_none() => {
                re.push_str(r"(?:\\.*)?");
                i += 2;
            }
            // A leading `**\`: any number of leading components.
            Token::DoubleStar if path && i == 0 && next == Some(Token::Separator) => {
                re.push_str(r"(?:.*\\)?");
                i += 2;
            }
            tok => {
                match tok {
                    Token::Separator => re.push_str(r"\\"),
                    // A `*` that is a whole component matches a component,
                    // which is never empty: `C:\*` does not match `C:\`.
                    Token::Star
                        if path
                            && (i == 0 || toks[i - 1] == Token::Separator)
                            && matches!(next, None | Some(Token::Separator)) =>
                    {
                        re.push_str(r"[^\\]+");
                    }
                    Token::Star if path => re.push_str(r"[^\\]*"),
                    Token::One if path => re.push_str(r"[^\\]"),
                    Token::Star | Token::DoubleStar => re.push_str(".*"),
                    Token::One => re.push('.'),
                    Token::Literal(c) => {
                        let mut buf = [0u8; 4];
                        re.push_str(&regex_syntax::escape(c.encode_utf8(&mut buf)));
                    }
                }
                i += 1;
            }
        }
    }
    re.push_str(r"\z");
    // The text is generated here, with every literal escaped.
    engine().build(&re).map_err(|e| build_error(&e))
}

#[cfg(test)]
mod tests;
