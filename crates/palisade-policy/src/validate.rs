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
    PrecedenceModel, Rule, RuleSetKind,
};
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
    /// `case_sensitive` was set on a field that has no case (hashes, versions).
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
    /// An allow rule's tree contains no positive identity criterion.
    NoIdentityAnchor,
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
        }
    }

    /// The severity this code always has.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::AllowWinsNotRecommended => Severity::Warning,
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
    /// table, and the safety rules from ADR 0004 and ADR 0008.
    ///
    /// Every finding is reported, not just the first, in document order.
    ///
    /// # Errors
    ///
    /// Returns every finding if any has `error` severity.
    pub fn validate(self) -> Result<ValidatedPolicy, Vec<ValidationError>> {
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

#[derive(Default)]
struct Validator {
    findings: Vec<ValidationError>,
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
        if matches!(rule.action, Action::Allow {}) && depth <= MAX_TREE_DEPTH {
            match guaranteed_identity(&rule.match_) {
                Identity::None => self.push(
                    ErrorCode::NoIdentityAnchor,
                    &tree,
                    "an allow rule must identify the object on every way it can match: each `any` branch needs a positive identity criterion outside `not`",
                ),
                Identity::WeakHashOnly => self.push(
                    ErrorCode::WeakHashOnlyAllow,
                    &tree,
                    "this allow rule can match on SHA-1 or MD5 alone, which are compatibility hashes (ADR 0008); require a SHA-256 or another identity on every branch",
                ),
                Identity::Other => {}
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
        if c.case_sensitive.is_some()
            && matches!(class, FieldClass::Hash { .. } | FieldClass::Version)
        {
            self.push(
                ErrorCode::CaseSensitivityNotApplicable,
                &format!("{base}/case_sensitive"),
                format!("`{}` has no case to compare", serde_name(&c.field)),
            );
        }
        let max = if c.operator.is_single_valued() {
            1
        } else {
            MAX_VALUES_PER_CRITERION
        };
        if c.values.is_empty() || c.values.len() > max {
            self.push(
                ErrorCode::InvalidValueCount,
                &format!("{base}/values"),
                format!("{} values; between 1 and {max} are allowed", c.values.len()),
            );
        }
        for (i, value) in c.values.iter().enumerate() {
            let path = format!("{base}/values/{i}");
            if let Some(problem) = value_problem(class, value) {
                self.push(ErrorCode::InvalidValue, &path, problem);
            }
        }
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
    /// Every way of matching checks another identity criterion.
    Other,
}

/// A conservative analysis: `all` guarantees the strongest of its children,
/// `any` only the weakest, and `not` guarantees nothing, because a negated
/// test never says what the object is. The full identity-anchor rule,
/// including context criteria and strength ratings, is #33 and #31.
fn guaranteed_identity(node: &Match) -> Identity {
    match node {
        Match::All(children) => children
            .iter()
            .map(guaranteed_identity)
            .max()
            .unwrap_or(Identity::None),
        Match::Any(children) => children
            .iter()
            .map(guaranteed_identity)
            .min()
            .unwrap_or(Identity::None),
        Match::Not(_) => Identity::None,
        Match::Criterion(c) if !c.operator.is_positive() => Identity::None,
        Match::Criterion(c) if c.field.is_weak_hash() => Identity::WeakHashOnly,
        Match::Criterion(_) => Identity::Other,
    }
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

/// Why a criterion value is not acceptable for its field, if it is not.
fn value_problem(class: FieldClass, value: &str) -> Option<String> {
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
    match class {
        FieldClass::Hash { hex_len } => {
            let ok = value.len() == hex_len
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            (!ok).then(|| format!("expected {hex_len} lowercase hexadecimal digits"))
        }
        FieldClass::Version => {
            let parts: Vec<&str> = value.split('.').collect();
            let ok = (1..=4).contains(&parts.len())
                && parts.iter().all(|p| {
                    !p.is_empty()
                        && p.bytes().all(|b| b.is_ascii_digit())
                        && p.parse::<u16>().is_ok()
                });
            (!ok).then(|| {
                "expected a version of 1 to 4 dot-separated numbers, each at most 65535".to_owned()
            })
        }
        FieldClass::Path | FieldClass::Text => None,
    }
}

/// The serde name of a unit enum variant, for messages.
fn serde_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".to_owned(),
    }
}
