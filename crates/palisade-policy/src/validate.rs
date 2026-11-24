//! Semantic validation of a policy document (#30).
//!
//! [`PolicyDocument::validate`] collects every problem in one pass. Each
//! [`ValidationError`] has a stable [`ErrorCode`], a [`Severity`], the
//! JSON Pointer of the field (RFC 6901), and a message. A document with no
//! `error`-severity findings becomes a [`ValidatedPolicy`], which is the only
//! form later stages (compiler, evaluator) accept.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::model::limits::{
    MAX_CRITERIA_PER_RULE, MAX_NAME_CHARS, MAX_RULE_SETS_PER_POLICY, MAX_RULES_PER_POLICY,
    MAX_TAGS, MAX_TEXT_CHARS, MAX_TREE_DEPTH, MAX_VALUE_BYTES, MAX_VALUES_PER_CRITERION,
};
use crate::model::settings::{ADVANCED_KEY_MAX_BYTES, is_valid_advanced_key, ranges};
use crate::model::{
    Action, Criterion, EnforcementOverride, FieldClass, Match, Metadata, PolicyDocument,
    PrecedenceModel, Rule, RuleSetKind, Strength,
};
use crate::ops::{self, CompileErrorKind, CompiledCriterion, MAX_REGEXES_PER_POLICY};
use crate::schema;

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Informational.
    Info,
    /// Allowed, but probably a mistake or unsafe.
    Warning,
    /// The document is rejected.
    Error,
}

/// The stable code of a finding. The `snake_case` name is part of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    /// The schema version's major is not this reader's.
    UnsupportedSchemaVersion,
    /// A name is empty, too long, untrimmed, or contains control characters.
    InvalidName,
    /// A free-text field is too long or contains disallowed control characters.
    InvalidText,
    /// Two objects share one ID.
    DuplicateId,
    /// The policy references a rule set that is not in the document.
    UnknownRuleSet,
    /// The policy lists the same rule set twice.
    DuplicateRuleSetRef,
    /// The document holds more than the allowed number of rules.
    TooManyRules,
    /// The document holds or references more than the allowed number of rule sets.
    TooManyRuleSets,
    /// A rule's match tree holds more than the allowed number of criteria.
    TooManyCriteria,
    /// A rule's match tree is nested too deeply.
    TreeTooDeep,
    /// An `all` or `any` node has no children.
    EmptyGroup,
    /// A criterion has no values, or too many.
    InvalidValueCount,
    /// A criterion value is empty, too long, or not valid for its field.
    InvalidValue,
    /// The operator cannot be used on the field.
    OperatorFieldMismatch,
    /// `case_sensitive` was set on a field that has no case, such as a hash,
    /// a version or a SID.
    CaseSensitivityNotApplicable,
    /// A setting is outside its allowed range.
    SettingOutOfRange,
    /// An `advanced` key is not in the registry of known keys.
    UnknownAdvancedKey,
    /// An `advanced` key is not a well-formed identifier.
    InvalidAdvancedKey,
    /// `mandatory` is set on a rule set that is not a blocklist.
    MandatoryNotBlocklist,
    /// A mandatory blocklist contains a rule that does not deny.
    MandatoryRuleNotDeny,
    /// A rule in a mandatory blocklist is set never to be enforced.
    MandatoryRuleNotEnforced,
    /// A rule's `display_id` is not `R-` followed by 6 to 12 digits.
    InvalidDisplayId,
    /// An object type is listed twice in one rule.
    DuplicateObjectType,
    /// Too many tags, or a tag that is empty, too long, or repeated.
    InvalidTag,
    /// An allow rule's only identity is SHA-1 or MD5 (ADR 0008).
    WeakHashOnlyAllow,
    /// The `allow_wins` model is not recommended for Essential Eight (ADR 0004).
    AllowWinsNotRecommended,
    /// A rule can match without a positive identity criterion: an allow
    /// rule through negations or context alone, or any rule through context
    /// criteria alone (#33). The message names the criteria of one such way
    /// of matching.
    NoIdentityAnchor,
    /// A deny or audit rule can match on negations alone, which match
    /// almost every object (#32).
    NegationOnly,
    /// A regular expression uses look-around or a backreference, which the
    /// linear-time engine does not support (#32).
    UnsupportedRegex,
    /// A regular expression is not valid.
    InvalidRegex,
    /// A regular expression or wildcard compiles to more than the size
    /// limit (#32).
    PatternTooLarge,
    /// The policy holds more regular expressions than allowed (#32).
    TooManyRegexes,
    /// An allow rule's strongest guaranteed identity is weak, such as a
    /// file name or version-resource string (#31).
    WeakIdentity,
}

impl ErrorCode {
    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::InvalidName => "invalid_name",
            Self::InvalidText => "invalid_text",
            Self::DuplicateId => "duplicate_id",
            Self::UnknownRuleSet => "unknown_rule_set",
            Self::DuplicateRuleSetRef => "duplicate_rule_set_ref",
            Self::TooManyRules => "too_many_rules",
            Self::TooManyRuleSets => "too_many_rule_sets",
            Self::TooManyCriteria => "too_many_criteria",
            Self::TreeTooDeep => "tree_too_deep",
            Self::EmptyGroup => "empty_group",
            Self::InvalidValueCount => "invalid_value_count",
            Self::InvalidValue => "invalid_value",
            Self::OperatorFieldMismatch => "operator_field_mismatch",
            Self::CaseSensitivityNotApplicable => "case_sensitivity_not_applicable",
            Self::SettingOutOfRange => "setting_out_of_range",
            Self::UnknownAdvancedKey => "unknown_advanced_key",
            Self::InvalidAdvancedKey => "invalid_advanced_key",
            Self::MandatoryNotBlocklist => "mandatory_not_blocklist",
            Self::MandatoryRuleNotDeny => "mandatory_rule_not_deny",
            Self::MandatoryRuleNotEnforced => "mandatory_rule_not_enforced",
            Self::InvalidDisplayId => "invalid_display_id",
            Self::DuplicateObjectType => "duplicate_object_type",
            Self::InvalidTag => "invalid_tag",
            Self::WeakHashOnlyAllow => "weak_hash_only_allow",
            Self::AllowWinsNotRecommended => "allow_wins_not_recommended",
            Self::NoIdentityAnchor => "no_identity_anchor",
            Self::NegationOnly => "negation_only",
            Self::UnsupportedRegex => "unsupported_regex",
            Self::InvalidRegex => "invalid_regex",
            Self::PatternTooLarge => "pattern_too_large",
            Self::TooManyRegexes => "too_many_regexes",
            Self::WeakIdentity => "weak_identity",
        }
    }

    /// The severity this code always has.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::AllowWinsNotRecommended | Self::WeakIdentity => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One validation finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    /// The stable code.
    pub code: ErrorCode,
    /// How serious it is.
    pub severity: Severity,
    /// JSON Pointer (RFC 6901) to the offending value in the document.
    pub path: String,
    /// A human-readable explanation.
    pub message: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = match self.severity {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        write!(
            f,
            "{severity}[{}] {}: {}",
            self.code, self.path, self.message
        )
    }
}

impl std::error::Error for ValidationError {}

/// A policy document that passed validation. It can only be built by
/// [`PolicyDocument::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedPolicy {
    document: PolicyDocument,
    warnings: Vec<ValidationError>,
}

impl ValidatedPolicy {
    /// The validated document.
    #[must_use]
    pub const fn document(&self) -> &PolicyDocument {
        &self.document
    }

    /// Findings below `error` severity.
    #[must_use]
    pub fn warnings(&self) -> &[ValidationError] {
        &self.warnings
    }

    /// Gives the document back, for editing. It must be validated again
    /// before use.
    #[must_use]
    pub fn into_document(self) -> PolicyDocument {
        self.document
    }
}

impl PolicyDocument {
    /// Checks everything the JSON Schema cannot: limits measured in bytes,
    /// references between objects, unique IDs, the operator compatibility
    /// table, that every criterion compiles ([`crate::ops`]), and the
    /// safety rules from ADR 0004, ADR 0008, #31 and #32.
    ///
    /// Hash values are normalised first: a `0x` prefix is removed and the
    /// digits are lowercased, so the validated document holds the canonical
    /// form (#31).
    ///
    /// Every finding is reported, not just the first, in document order.
    ///
    /// # Errors
    ///
    /// Returns every finding if any has `error` severity.
    pub fn validate(mut self) -> Result<ValidatedPolicy, Vec<ValidationError>> {
        normalize_hashes(&mut self);
        let mut v = Validator::default();
        v.document(&self);
        if v.findings.iter().any(|f| f.severity == Severity::Error) {
            Err(v.findings)
        } else {
            Ok(ValidatedPolicy {
                document: self,
                warnings: v.findings,
            })
        }
    }
}

/// Escapes one JSON Pointer reference token (RFC 6901 section 3).
fn pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

struct Validator {
    findings: Vec<ValidationError>,
    /// Whether regular expressions are compiled. Off once the document
    /// holds more than the per-policy cap.
    compile_regexes: bool,
}

impl Default for Validator {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            compile_regexes: true,
        }
    }
}

/// Normalises every hash value in the document in place.
fn normalize_hashes(doc: &mut PolicyDocument) {
    for rule in doc.rule_sets.iter_mut().flat_map(|s| s.rules.iter_mut()) {
        let mut stack = vec![&mut rule.match_];
        while let Some(node) = stack.pop() {
            match node {
                Match::All(children) | Match::Any(children) => stack.extend(children.iter_mut()),
                Match::Not(child) => stack.push(child),
                Match::Criterion(c) => {
                    if let FieldClass::Hash { .. } = c.field.class() {
                        for value in &mut c.values {
                            if let Some(hex) = ops::normalize_hex(value) {
                                *value = hex;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl Validator {
    fn push(&mut self, code: ErrorCode, path: &str, message: impl Into<String>) {
        self.findings.push(ValidationError {
            code,
            severity: code.severity(),
            path: path.to_owned(),
            message: message.into(),
        });
    }

    fn document(&mut self, doc: &PolicyDocument) {
        if !doc.schema_version.is_readable_by(schema::CURRENT) {
            self.push(
                ErrorCode::UnsupportedSchemaVersion,
                "/schema_version",
                format!(
                    "schema version {} is not readable by a {} reader",
                    doc.schema_version,
                    schema::CURRENT
                ),
            );
        }

        let policy = &doc.policy;
        self.name("/policy/name", &policy.name);
        self.text("/policy/description", policy.description.as_deref());
        self.metadata("/policy/metadata", &policy.metadata);
        self.settings(doc);
        if policy.precedence_model == PrecedenceModel::AllowWins {
            self.push(
                ErrorCode::AllowWinsNotRecommended,
                "/policy/precedence_model",
                "`allow_wins` lets one broad allow defeat every deny; it is not recommended for Essential Eight",
            );
        }

        // Rule set IDs must be unique, and every reference must resolve.
        let mut set_ids = BTreeMap::new();
        for (i, set) in doc.rule_sets.iter().enumerate() {
            if let Some(first) = set_ids.insert(set.id, i) {
                self.push(
                    ErrorCode::DuplicateId,
                    &format!("/rule_sets/{i}/id"),
                    format!(
                        "rule set ID {} is already used by /rule_sets/{first}",
                        set.id
                    ),
                );
            }
        }
        let mut referenced = BTreeSet::new();
        for (i, id) in policy.rule_sets.iter().enumerate() {
            let path = format!("/policy/rule_sets/{i}");
            if !set_ids.contains_key(id) {
                self.push(
                    ErrorCode::UnknownRuleSet,
                    &path,
                    format!("rule set {id} is not in the document"),
                );
            }
            if !referenced.insert(*id) {
                self.push(
                    ErrorCode::DuplicateRuleSetRef,
                    &path,
                    format!("rule set {id} is listed more than once"),
                );
            }
        }

        for (path, count) in [
            ("/rule_sets", doc.rule_sets.len()),
            ("/policy/rule_sets", policy.rule_sets.len()),
        ] {
            if count > MAX_RULE_SETS_PER_POLICY {
                self.push(
                    ErrorCode::TooManyRuleSets,
                    path,
                    format!("{count} rule sets; at most {MAX_RULE_SETS_PER_POLICY} are allowed"),
                );
            }
        }

        let total_rules: usize = doc.rule_sets.iter().map(|s| s.rules.len()).sum();
        let total_regexes: usize = doc
            .rule_sets
            .iter()
            .flat_map(|s| &s.rules)
            .map(|r| regex_count(&r.match_))
            .sum();
        if total_regexes > MAX_REGEXES_PER_POLICY {
            self.compile_regexes = false;
            self.push(
                ErrorCode::TooManyRegexes,
                "/rule_sets",
                format!(
                    "{total_regexes} regular expressions; at most {MAX_REGEXES_PER_POLICY} are allowed"
                ),
            );
        }
        if total_rules > MAX_RULES_PER_POLICY {
            self.push(
                ErrorCode::TooManyRules,
                "/rule_sets",
                format!("{total_rules} rules; at most {MAX_RULES_PER_POLICY} are allowed"),
            );
        }

        let mut rule_ids = BTreeMap::new();
        for (i, set) in doc.rule_sets.iter().enumerate() {
            let base = format!("/rule_sets/{i}");
            self.name(&format!("{base}/name"), &set.name);
            self.text(&format!("{base}/description"), set.description.as_deref());
            if let Some(version) = &set.version {
                self.name(&format!("{base}/version"), version);
            }
            self.metadata(&format!("{base}/metadata"), &set.metadata);
            if set.mandatory && set.kind != RuleSetKind::Blocklist {
                self.push(
                    ErrorCode::MandatoryNotBlocklist,
                    &format!("{base}/mandatory"),
                    "only a blocklist can be mandatory",
                );
            }
            for (j, rule) in set.rules.iter().enumerate() {
                let path = format!("{base}/rules/{j}");
                if let Some(first) = rule_ids.insert(rule.id, path.clone()) {
                    self.push(
                        ErrorCode::DuplicateId,
                        &format!("{path}/id"),
                        format!("rule ID {} is already used by {first}", rule.id),
                    );
                }
                if set.mandatory && !matches!(rule.action, Action::Deny {}) {
                    self.push(
                        ErrorCode::MandatoryRuleNotDeny,
                        &format!("{path}/action"),
                        "every rule in a mandatory rule set must deny",
                    );
                }
                if set.mandatory && rule.enforcement_override == EnforcementOverride::NeverEnforce {
                    self.push(
                        ErrorCode::MandatoryRuleNotEnforced,
                        &format!("{path}/enforcement_override"),
                        "rules in a mandatory rule set block under every mode (ADR 0004) and cannot be `never_enforce`",
                    );
                }
                self.rule(&path, rule);
            }
        }
    }

    fn rule(&mut self, base: &str, rule: &Rule) {
        if let Some(display_id) = &rule.display_id {
            let digits = display_id.strip_prefix("R-").unwrap_or_default();
            if !(6..=12).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
                self.push(
                    ErrorCode::InvalidDisplayId,
                    &format!("{base}/display_id"),
                    "expected `R-` followed by 6 to 12 digits",
                );
            }
        }
        self.name(&format!("{base}/name"), &rule.name);
        self.text(&format!("{base}/description"), rule.description.as_deref());
        self.metadata(&format!("{base}/metadata"), &rule.metadata);

        let mut seen = BTreeSet::new();
        for (i, t) in rule.object_types.iter().enumerate() {
            if !seen.insert(*t) {
                self.push(
                    ErrorCode::DuplicateObjectType,
                    &format!("{base}/object_types/{i}"),
                    format!("object type {t} is listed more than once"),
                );
            }
        }

        let tree = format!("{base}/match");
        let depth = rule.match_.depth();
        if depth > MAX_TREE_DEPTH {
            self.push(
                ErrorCode::TreeTooDeep,
                &tree,
                format!("depth {depth}; at most {MAX_TREE_DEPTH} is allowed"),
            );
        }
        let mut criteria = 0usize;
        // Explicit stack, so a deep tree cannot overflow the call stack.
        let mut stack = vec![(&rule.match_, tree.clone())];
        let mut ordered = Vec::new();
        while let Some((node, path)) = stack.pop() {
            match node {
                Match::All(children) | Match::Any(children) => {
                    let key = if matches!(node, Match::All(_)) {
                        "all"
                    } else {
                        "any"
                    };
                    if children.is_empty() {
                        self.push(
                            ErrorCode::EmptyGroup,
                            &format!("{path}/{key}"),
                            format!("`{key}` needs at least one condition"),
                        );
                    }
                    for (i, child) in children.iter().enumerate().rev() {
                        stack.push((child, format!("{path}/{key}/{i}")));
                    }
                }
                Match::Not(child) => stack.push((child, format!("{path}/not"))),
                Match::Criterion(c) => {
                    criteria += 1;
                    ordered.push((c, format!("{path}/criterion")));
                }
            }
        }
        if criteria > MAX_CRITERIA_PER_RULE {
            self.push(
                ErrorCode::TooManyCriteria,
                &tree,
                format!("{criteria} criteria; at most {MAX_CRITERIA_PER_RULE} are allowed"),
            );
        }
        for (c, path) in ordered {
            self.criterion(&path, c);
        }

        // The recursive analysis is bounded by the depth limit, so it only
        // runs on trees that passed it.
        if depth <= MAX_TREE_DEPTH {
            let Guarantee { identity, witness } = guaranteed_identity(&rule.match_, "");
            let through = describe_witness(&witness);
            let negations_only = witness.iter().all(|w| w.negation);
            match (rule.action, identity) {
                (Action::Allow {}, Identity::None) => self.push(
                    ErrorCode::NoIdentityAnchor,
                    &tree,
                    format!("this allow rule can match through {through} without identifying the object: every way of matching needs a positive identity criterion outside `not`"),
                ),
                (_, Identity::None) if negations_only => self.push(
                    ErrorCode::NegationOnly,
                    &tree,
                    format!("this rule can match through {through}, on negations alone, which match almost every object; combine each negation with a positive identity criterion (a hash, signer, path or version-resource test) in an `all`"),
                ),
                (_, Identity::None) => self.push(
                    ErrorCode::NoIdentityAnchor,
                    &tree,
                    format!("this rule can match through {through} without identifying the object: user, device and session criteria narrow a rule, but every way of matching also needs a positive identity criterion"),
                ),
                (Action::Allow {}, Identity::WeakHashOnly) => self.push(
                    ErrorCode::WeakHashOnlyAllow,
                    &tree,
                    format!("this allow rule can match through {through} on SHA-1 or MD5 alone, which are compatibility hashes (ADR 0008); require a SHA-256 or another identity on every branch"),
                ),
                (Action::Allow {}, Identity::Weak) => self.push(
                    ErrorCode::WeakIdentity,
                    &tree,
                    format!("this allow rule can match through {through} on weak identities alone (file names, extensions or version-resource strings), which anyone can copy; add a hash, a publisher or a path"),
                ),
                _ => {}
            }
        }
    }

    fn criterion(&mut self, base: &str, c: &Criterion) {
        let class = c.field.class();
        if !c.operator.applies_to(class) {
            self.push(
                ErrorCode::OperatorFieldMismatch,
                &format!("{base}/operator"),
                format!(
                    "operator `{}` cannot be used on `{}`",
                    serde_name(&c.operator),
                    serde_name(&c.field)
                ),
            );
        }
        if c.case_sensitive.is_some() && !class.has_case() {
            self.push(
                ErrorCode::CaseSensitivityNotApplicable,
                &format!("{base}/case_sensitive"),
                format!("`{}` has no case to compare", serde_name(&c.field)),
            );
        }
        let (min, max) = c.operator.value_count();
        if c.values.len() < min || c.values.len() > max {
            let expected = if min == max {
                format!("exactly {min} is required")
            } else {
                format!("between {min} and {max} are allowed")
            };
            self.push(
                ErrorCode::InvalidValueCount,
                &format!("{base}/values"),
                format!(
                    "{} values; {expected} for `{}`",
                    c.values.len(),
                    serde_name(&c.operator)
                ),
            );
        }
        // Each value is checked against its field and operator: hash
        // lengths, versions, path forms, regular expressions and pattern
        // sizes. A value is compiled only once, and only if it is within the
        // size limits; past the per-policy regex cap, regular expressions
        // are not compiled at all, so hostile input cannot make validation
        // compile more than the limits allow.
        let mut all_ok = true;
        for (i, value) in c.values.iter().enumerate().take(MAX_VALUES_PER_CRITERION) {
            let path = format!("{base}/values/{i}");
            if let Some(problem) = value_problem(value) {
                self.push(ErrorCode::InvalidValue, &path, problem);
                all_ok = false;
            } else if c.operator.is_regex() && !self.compile_regexes {
                all_ok = false;
            } else if let Err(kind) = CompiledCriterion::check_value(c, value) {
                self.compile_error(&path, &kind);
                all_ok = false;
            }
        }
        // Checks across values, such as the order of a version range. Every
        // value already compiled, and a range has no patterns, so this
        // compiles nothing a second time.
        let well_formed =
            all_ok && c.operator.applies_to(class) && (min..=max).contains(&c.values.len());
        if well_formed && c.operator.is_version() {
            if let Err(errors) = CompiledCriterion::compile(c) {
                for e in errors {
                    let path = match e.value {
                        Some(i) => format!("{base}/values/{i}"),
                        None => format!("{base}/values"),
                    };
                    self.compile_error(&path, &e.kind);
                }
            }
        }
    }

    fn compile_error(&mut self, path: &str, kind: &CompileErrorKind) {
        let code = match kind {
            CompileErrorKind::OperatorFieldMismatch => ErrorCode::OperatorFieldMismatch,
            CompileErrorKind::ValueCount => ErrorCode::InvalidValueCount,
            CompileErrorKind::InvalidValue(_) => ErrorCode::InvalidValue,
            CompileErrorKind::RegexLookAround | CompileErrorKind::RegexBackreference => {
                ErrorCode::UnsupportedRegex
            }
            CompileErrorKind::RegexSyntax(_) => ErrorCode::InvalidRegex,
            CompileErrorKind::PatternTooLarge => ErrorCode::PatternTooLarge,
        };
        self.push(code, path, kind.to_string());
    }

    fn settings(&mut self, doc: &PolicyDocument) {
        let s = &doc.policy.settings;
        let base = "/policy/settings";
        let range = |v: &mut Self, field: &str, value: u64, min: u64, max: u64| {
            if value < min || value > max {
                v.push(
                    ErrorCode::SettingOutOfRange,
                    &format!("{base}/{field}"),
                    format!("{value} is outside {min}..={max}"),
                );
            }
        };
        range(
            self,
            "poll_interval_secs",
            s.poll_interval_secs.into(),
            ranges::POLL_INTERVAL_MIN.into(),
            ranges::POLL_INTERVAL_MAX.into(),
        );
        range(
            self,
            "decision_cache_ttl_secs",
            s.decision_cache_ttl_secs.into(),
            0,
            ranges::DECISION_CACHE_TTL_MAX.into(),
        );
        range(
            self,
            "max_ancestor_depth",
            s.max_ancestor_depth.into(),
            ranges::ANCESTOR_DEPTH_MIN.into(),
            ranges::ANCESTOR_DEPTH_MAX.into(),
        );
        if s.override_durations.len() > ranges::OVERRIDE_SLOTS_MAX {
            self.push(
                ErrorCode::SettingOutOfRange,
                &format!("{base}/override_durations"),
                format!(
                    "{} slots; at most {} are allowed",
                    s.override_durations.len(),
                    ranges::OVERRIDE_SLOTS_MAX
                ),
            );
        }
        for (i, minutes) in s.override_durations.iter().enumerate() {
            range(
                self,
                &format!("override_durations/{i}"),
                (*minutes).into(),
                0,
                ranges::OVERRIDE_MINUTES_MAX.into(),
            );
        }
        if s.advanced.len() > ranges::ADVANCED_KEYS_MAX {
            self.push(
                ErrorCode::SettingOutOfRange,
                &format!("{base}/advanced"),
                format!(
                    "{} keys; at most {} are allowed",
                    s.advanced.len(),
                    ranges::ADVANCED_KEYS_MAX
                ),
            );
        }
        for (key, value) in &s.advanced {
            let path = format!("{base}/advanced/{}", pointer_token(key));
            if !is_valid_advanced_key(key) {
                self.push(
                    ErrorCode::InvalidAdvancedKey,
                    &path,
                    format!(
                        "keys are a lowercase letter, then up to {} lowercase letters, digits, `_`, `.` or `-`",
                        ADVANCED_KEY_MAX_BYTES - 1
                    ),
                );
            } else if !s.allow_unknown_advanced && !KNOWN_ADVANCED_KEYS.contains(&key.as_str()) {
                self.push(
                    ErrorCode::UnknownAdvancedKey,
                    &path,
                    format!("`{key}` is not a known advanced setting"),
                );
            }
            if let crate::model::AdvancedValue::Text(text) = value {
                if text.len() > MAX_VALUE_BYTES || text.chars().any(char::is_control) {
                    self.push(
                        ErrorCode::InvalidValue,
                        &path,
                        format!(
                            "advanced text values are at most {MAX_VALUE_BYTES} bytes with no control characters"
                        ),
                    );
                }
            }
        }
    }

    fn name(&mut self, path: &str, name: &str) {
        let chars = name.chars().count();
        let problem = if name.trim().is_empty() {
            Some("must not be empty or only whitespace".to_owned())
        } else if chars > MAX_NAME_CHARS {
            Some(format!(
                "{chars} characters; at most {MAX_NAME_CHARS} are allowed"
            ))
        } else if name.trim() != name {
            Some("must not start or end with whitespace".to_owned())
        } else if name.chars().any(|c| c.is_control() || is_bidi_control(c)) {
            Some("must not contain control or bidirectional formatting characters".to_owned())
        } else {
            None
        };
        if let Some(problem) = problem {
            self.push(ErrorCode::InvalidName, path, problem);
        }
    }

    fn text(&mut self, path: &str, text: Option<&str>) {
        let Some(text) = text else { return };
        let chars = text.chars().count();
        if chars > MAX_TEXT_CHARS {
            self.push(
                ErrorCode::InvalidText,
                path,
                format!("{chars} characters; at most {MAX_TEXT_CHARS} are allowed"),
            );
        } else if has_control(text) {
            self.push(
                ErrorCode::InvalidText,
                path,
                "must not contain control characters other than tab and line breaks",
            );
        }
    }

    fn metadata(&mut self, base: &str, m: &Metadata) {
        self.text(&format!("{base}/justification"), m.justification.as_deref());
        self.text(&format!("{base}/comment"), m.comment.as_deref());
        if let Some(ticket) = &m.ticket_ref {
            self.name(&format!("{base}/ticket_ref"), ticket);
        }
        if m.tags.len() > MAX_TAGS {
            self.push(
                ErrorCode::InvalidTag,
                &format!("{base}/tags"),
                format!("{} tags; at most {MAX_TAGS} are allowed", m.tags.len()),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, tag) in m.tags.iter().enumerate() {
            let path = format!("{base}/tags/{i}");
            let chars = tag.chars().count();
            if tag.trim().is_empty()
                || tag.trim() != tag
                || chars > MAX_NAME_CHARS
                || tag.chars().any(|c| c.is_control() || is_bidi_control(c))
            {
                self.push(
                    ErrorCode::InvalidTag,
                    &path,
                    format!(
                        "tags are 1 to {MAX_NAME_CHARS} characters, trimmed, with no control or bidirectional formatting characters"
                    ),
                );
            } else if !seen.insert(tag.as_str()) {
                self.push(
                    ErrorCode::InvalidTag,
                    &path,
                    format!("tag `{tag}` is repeated"),
                );
            }
        }
    }
}

/// The weakest identity that every satisfying assignment of a tree is
/// guaranteed to have checked. Ordered from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identity {
    /// Some way of matching checks no positive identity at all.
    None,
    /// Some way of matching checks only SHA-1 or MD5.
    WeakHashOnly,
    /// Some way of matching checks only weak identities (#31).
    Weak,
    /// Every way of matching checks a medium or strong identity.
    Sound,
}

/// One node on a way of matching that has only the guaranteed identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Step {
    /// The JSON Pointer of the node, relative to the rule's `match`.
    pointer: String,
    /// The node is a negation: a `not`, or a criterion with a negative
    /// operator.
    negation: bool,
}

/// The weakest identity a tree guarantees, and a witness: the nodes that
/// one of its weakest ways of matching depends on.
struct Guarantee {
    identity: Identity,
    witness: Vec<Step>,
}

/// A conservative analysis: `all` guarantees the strongest of its children,
/// `any` only the weakest, and `not` guarantees nothing, because a negated
/// test never says what the object is. A context criterion (#33) says
/// nothing about the object either.
///
/// The witness of `all` joins its children's witnesses, since a way of
/// matching `all` goes through every child; the witness of `any` is its
/// weakest child's. With at most 32 criteria, a witness is short.
fn guaranteed_identity(node: &Match, pointer: &str) -> Guarantee {
    match node {
        Match::All(children) => {
            let parts: Vec<Guarantee> = children
                .iter()
                .enumerate()
                .map(|(i, c)| guaranteed_identity(c, &format!("{pointer}/all/{i}")))
                .collect();
            Guarantee {
                identity: parts
                    .iter()
                    .map(|g| g.identity)
                    .max()
                    .unwrap_or(Identity::None),
                witness: parts.into_iter().flat_map(|g| g.witness).collect(),
            }
        }
        Match::Any(children) => children
            .iter()
            .enumerate()
            .map(|(i, c)| guaranteed_identity(c, &format!("{pointer}/any/{i}")))
            // The first of the weakest, so the witness is stable.
            .reduce(|weakest, g| {
                if g.identity < weakest.identity {
                    g
                } else {
                    weakest
                }
            })
            .unwrap_or(Guarantee {
                identity: Identity::None,
                witness: Vec::new(),
            }),
        Match::Not(_) => Guarantee {
            identity: Identity::None,
            witness: vec![Step {
                pointer: format!("{pointer}/not"),
                negation: true,
            }],
        },
        Match::Criterion(c) => {
            let identity = match c.field.strength() {
                _ if !c.operator.is_positive() => Identity::None,
                None => Identity::None,
                Some(_) if c.field.is_weak_hash() => Identity::WeakHashOnly,
                Some(Strength::Weak) => Identity::Weak,
                Some(_) => Identity::Sound,
            };
            Guarantee {
                identity,
                witness: vec![Step {
                    pointer: format!("{pointer}/criterion"),
                    negation: !c.operator.is_positive(),
                }],
            }
        }
    }
}

/// Names the nodes of a witness for a message, such as
/// `` `/all/0/criterion` and `/all/1/not` ``. The root is `match` itself.
fn describe_witness(witness: &[Step]) -> String {
    let names: Vec<String> = witness
        .iter()
        .map(|s| format!("`match{}`", s.pointer))
        .collect();
    match names.as_slice() {
        [] => "`match`".to_owned(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The number of regular expression values in a tree.
fn regex_count(tree: &Match) -> usize {
    let mut count = 0usize;
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        if let Match::Criterion(c) = node {
            if c.operator.is_regex() {
                count = count.saturating_add(c.values.len());
            }
        }
        stack.extend(node.children());
    }
    count
}

/// Keys accepted in `settings.advanced`. None are defined yet; each will be
/// added here with its type when a feature needs one.
const KNOWN_ADVANCED_KEYS: &[&str] = &[];

/// Unicode bidirectional formatting characters, which can make a name read
/// differently from what it contains.
const fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Control characters other than tab, line feed and carriage return.
fn has_control(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

/// Why a criterion value is not acceptable for any field, if it is not.
/// Checks that depend on the field are in
/// [`CompiledCriterion::check_value`].
fn value_problem(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("values must not be empty".to_owned());
    }
    if value.len() > MAX_VALUE_BYTES {
        return Some(format!(
            "{} bytes; at most {MAX_VALUE_BYTES} are allowed",
            value.len()
        ));
    }
    if value.chars().any(char::is_control) {
        return Some("values must not contain control characters".to_owned());
    }
    None
}

/// The serde name of a unit enum variant, for messages.
fn serde_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".to_owned(),
    }
}
