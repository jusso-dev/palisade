//! Semantic validation of a policy document (#30).
//!
//! [`PolicyDocument::validate`] collects every problem in one pass. Each
//! [`ValidationError`] has a stable [`ErrorCode`], a [`Severity`], the
//! JSON Pointer of the field (RFC 6901), and a message. A document with no
//! `error`-severity findings becomes a [`ValidatedPolicy`], which is the only
//! form later stages (compiler, evaluator) accept.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

mod actions;
mod mode;
mod precedence;
mod scope;
mod unknown;

pub use precedence::order_ranges;

#[cfg(test)]
pub(crate) use actions::scope_path_key;

use crate::model::limits::{
    MAX_CRITERIA_PER_RULE, MAX_NAME_CHARS, MAX_RULE_SETS_PER_POLICY, MAX_RULES_PER_POLICY,
    MAX_TAGS, MAX_TEXT_CHARS, MAX_TREE_DEPTH, MAX_VALUE_BYTES, MAX_VALUES_PER_CRITERION,
};
use crate::model::settings::{ADVANCED_KEY_MAX_BYTES, is_valid_advanced_key, ranges};
use crate::model::{
    Action, ActionKind, Criterion, EnforcementOverride, FieldClass, Match, Metadata,
    PolicyDocument, PrecedenceModel, Rule, RuleSetKind, Strength,
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
    /// The only identity of a rule that lets an object run, trusts it or
    /// excludes it is SHA-1 or MD5 (ADR 0008, #34).
    WeakHashOnlyAllow,
    /// The `allow_wins` model is not recommended for Essential Eight (ADR 0004).
    AllowWinsNotRecommended,
    /// A path through a rule's tree has no positive identity criterion: a
    /// path of negations or context alone in a rule that lets an object
    /// run, trusts it or excludes it (#34), or any rule's path
    /// that includes a context criterion (#33). The message names the nodes
    /// on one such path.
    NoIdentityAnchor,
    /// Every path through a deny or audit rule's tree that has no positive
    /// identity criterion is made of negations alone, which match almost
    /// every object (#32).
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
    /// The strongest guaranteed identity of a rule that lets an object run,
    /// trusts it or excludes it is weak, such as a file name or
    /// version-resource string (#31, #34).
    WeakIdentity,
    /// The action is not valid in a rule set of this kind (#34).
    ActionNotValidInRuleSet,
    /// The action, or one of its options, is not valid for an object type
    /// the rule applies to (#34).
    ActionNotValidForObjectType,
    /// An action option is malformed or inconsistent (#34).
    InvalidActionOption,
    /// `log: never` or `log: summary` on an action that needs an event per
    /// decision (#34).
    LogLevelNotAllowed,
    /// A notification text, notification setting or help URL is not valid (#34).
    InvalidNotification,
    /// An effect flag is outside its allowed range (#34).
    InvalidEffect,
    /// `effects` on an action that makes no decision (#34).
    EffectsNotApplicable,
    /// An `ignore` rule: a performance exclusion that needs the
    /// `admin.exclusions` permission at the server (#34).
    ExclusionNeedsPermission,
    /// Under `first_match`, a rule that allows or denies has no `order`
    /// (#35).
    OrderRequired,
    /// Under `first_match`, a rule of a custom rule set has an `order` in a
    /// reserved range (#35, [`order_ranges`]).
    OrderReserved,
    /// A rule's `order` is above 1000000 (#35).
    OrderOutOfRange,
    /// Under `priority`, a rule that allows or denies has no `priority`
    /// (#35).
    PriorityRequired,
    /// Under `priority`, two rules with different actions share a
    /// `priority`, so the fixed action order decides between them (#35).
    DuplicatePriority,
    /// A precedence option is set that the selected model does not use
    /// (#35).
    PrecedenceOptionUnused,
    /// A mode is set where it is not allowed: `disabled` for a policy, an
    /// object type or a rule set (#36).
    ModeNotAllowed,
    /// `mode_disconnected` is neither the policy's `mode` nor stricter, so
    /// losing the server would relax the device, or it would never apply
    /// (#36).
    ModeDisconnectedWeaker,
    /// `mode_override` on a rule set that is not a blocklist, or on a
    /// mandatory blocklist (#36, ADR 0004).
    ModeOverrideNotAllowed,
    /// `enforcement_override` other than `inherit` on a rule that does not
    /// deny: only a block can be enforced or relaxed (#36).
    EnforcementOverrideNotDeny,
    /// A match tree still holds a library reference (`ref`). References are
    /// replaced with their trees when the effective policy is built (#37).
    UnresolvedRef,
    /// A `category_path` is not `Category` or `Category/Subcategory` with
    /// valid parts (#37).
    InvalidCategory,
    /// `allow_child_suppress: true` on a mandatory rule set, whose rules
    /// can never be suppressed (#37, ADR 0004).
    SuppressNotAllowed,
    /// A scope is malformed: a value not valid for its kind, a list over
    /// its limit, an unknown location profile, or an option on rules it
    /// does not apply to (#38).
    InvalidScope,
    /// A schedule is malformed: a window, a date range or a window-close
    /// option (#38).
    InvalidSchedule,
    /// `user_pattern` in a position where a spoofed account name would
    /// make a rule that lets an object run apply, or keep a deny from
    /// applying (#38).
    UserPatternNotAllowed,
    /// A criterion option is set where it does not apply, such as
    /// `anchored` on an operator that takes no regular expression (#32), or
    /// `safety_critical` outside a mandatory blocklist (#32, #87).
    OptionNotApplicable,
    /// An unknown-handling level that cannot apply to the object type it is
    /// set for: `restrict` other than for executables, scripts and
    /// installers, or `prompt` for libraries and drivers (#39).
    UnknownLevelNotValidForType,
    /// A `restrict` level with no `restrict_profile` (#39).
    RestrictProfileRequired,
    /// The prompt settings are inconsistent: no options, a repeated option,
    /// or a `prompt` fallback (#39).
    InvalidPromptSettings,
    /// An unknown-handling level is `allow`: unknown objects run silently
    /// (#39).
    UnknownAllow,
    /// A policy tagged with an Essential Eight preset lets unknown objects
    /// in user profiles or temporary folders run silently (#39, ISM-1870).
    UnknownAllowNotPermitted,
    /// A policy tagged with a compliance preset is weaker than the preset
    /// for some object, or lacks what the preset requires (#39, #17).
    ComplianceWeakened,
    /// A deny would match one of Palisade's own pinned images (#39).
    DenyMatchesSelf,
    /// The `e8_ml3` preset needs a mandatory blocklist, and the policy
    /// references none (#39).
    MandatoryBlocklistRequired,
    /// A signer criterion matches signatures that the default would not
    /// trust: `allow_digest_mismatch`, or an `accept_status` beyond the
    /// default in a rule that lets an object run, trusts it or excludes it
    /// (#31).
    SignatureStatusRelaxed,
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
            Self::ActionNotValidInRuleSet => "action_not_valid_in_rule_set",
            Self::ActionNotValidForObjectType => "action_not_valid_for_object_type",
            Self::InvalidActionOption => "invalid_action_option",
            Self::LogLevelNotAllowed => "log_level_not_allowed",
            Self::InvalidNotification => "invalid_notification",
            Self::InvalidEffect => "invalid_effect",
            Self::EffectsNotApplicable => "effects_not_applicable",
            Self::ExclusionNeedsPermission => "exclusion_needs_permission",
            Self::OrderRequired => "order_required",
            Self::OrderReserved => "order_reserved",
            Self::OrderOutOfRange => "order_out_of_range",
            Self::PriorityRequired => "priority_required",
            Self::DuplicatePriority => "duplicate_priority",
            Self::PrecedenceOptionUnused => "precedence_option_unused",
            Self::ModeNotAllowed => "mode_not_allowed",
            Self::ModeDisconnectedWeaker => "mode_disconnected_weaker",
            Self::ModeOverrideNotAllowed => "mode_override_not_allowed",
            Self::EnforcementOverrideNotDeny => "enforcement_override_not_deny",
            Self::UnresolvedRef => "unresolved_ref",
            Self::InvalidCategory => "invalid_category",
            Self::SuppressNotAllowed => "suppress_not_allowed",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidSchedule => "invalid_schedule",
            Self::UserPatternNotAllowed => "user_pattern_not_allowed",
            Self::OptionNotApplicable => "option_not_applicable",
            Self::UnknownLevelNotValidForType => "unknown_level_not_valid_for_type",
            Self::RestrictProfileRequired => "restrict_profile_required",
            Self::InvalidPromptSettings => "invalid_prompt_settings",
            Self::UnknownAllow => "unknown_allow",
            Self::UnknownAllowNotPermitted => "unknown_allow_not_permitted",
            Self::ComplianceWeakened => "compliance_weakened",
            Self::DenyMatchesSelf => "deny_matches_self",
            Self::MandatoryBlocklistRequired => "mandatory_blocklist_required",
            Self::SignatureStatusRelaxed => "signature_status_relaxed",
        }
    }

    /// The severity this code always has.
    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::AllowWinsNotRecommended
            | Self::WeakIdentity
            | Self::ExclusionNeedsPermission
            | Self::DuplicatePriority
            | Self::PrecedenceOptionUnused
            | Self::UnknownAllow
            | Self::ComplianceWeakened
            | Self::SignatureStatusRelaxed => Severity::Warning,
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
    pub fn validate(self) -> Result<ValidatedPolicy, Vec<ValidationError>> {
        self.validate_with(Validator::default())
    }

    /// Validates a document assembled from documents that each passed
    /// [`validate`](Self::validate): the effective policy of a hierarchy
    /// (#37). Every rule is a copy of a validated rule, so its criterion
    /// values were already compiled and are not compiled again; everything
    /// else, including every check across rules and rule sets, the
    /// settings, modes and precedence, is checked as usual.
    pub(crate) fn validate_assembled(self) -> Result<ValidatedPolicy, Vec<ValidationError>> {
        self.validate_with(Validator {
            compile_values: false,
            ..Validator::default()
        })
    }

    fn validate_with(mut self, mut v: Validator) -> Result<ValidatedPolicy, Vec<ValidationError>> {
        normalize_hashes(&mut self);
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
    /// Whether criterion values are compiled at all. Off only for a
    /// document whose every criterion comes from documents that already
    /// passed validation ([`PolicyDocument::validate_assembled`]).
    compile_values: bool,
}

impl Default for Validator {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            compile_regexes: true,
            compile_values: true,
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
                Match::Ref(_) => {}
                Match::Criterion(c) => {
                    if let FieldClass::Hash { .. } | FieldClass::Digest = c.field.class() {
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
        self.modes(doc);
        self.unknown(doc);
        if policy.precedence_model == PrecedenceModel::AllowWins {
            self.push(
                ErrorCode::AllowWinsNotRecommended,
                "/policy/precedence_model",
                "`allow_wins` lets one broad allow defeat every deny; it is not recommended for Essential Eight",
            );
        }
        self.precedence(doc);
        let profiles = self.policy_scopes(doc);

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
            if let Some(category) = &set.category_path {
                if let Some(problem) = category_problem(category) {
                    self.push(
                        ErrorCode::InvalidCategory,
                        &format!("{base}/category_path"),
                        problem,
                    );
                }
            }
            if set.mandatory && set.allow_child_suppress == Some(true) {
                self.push(
                    ErrorCode::SuppressNotAllowed,
                    &format!("{base}/allow_child_suppress"),
                    "a mandatory rule set blocks under every policy below it (ADR 0004); its rules can never be suppressed",
                );
            }
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
                if set.mandatory && !matches!(rule.action, Action::Deny(_)) {
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
                self.rule(&path, rule, set.mandatory);
                self.action(&path, set, rule);
                if let Some(scope) = &rule.scope {
                    self.scope(
                        &format!("{path}/scope"),
                        scope,
                        scope::Covered::of(rule.action.kind()),
                        &profiles,
                    );
                }
            }
        }
    }

    /// Checks one rule. `mandatory` is whether its rule set is a mandatory
    /// blocklist, the only place `safety_critical` applies.
    fn rule(&mut self, base: &str, rule: &Rule, mandatory: bool) {
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
                Match::Ref(r) => self.push(
                    ErrorCode::UnresolvedRef,
                    &format!("{path}/ref"),
                    format!(
                        "library {} is referenced but not resolved; build the effective policy from the hierarchy (#37), which replaces each reference with its tree",
                        r.id
                    ),
                ),
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
            self.criterion(&path, c, mandatory);
            self.signer_options(&path, c, rule.action.kind());
        }

        // The recursive analysis is bounded by the depth limit, so it only
        // runs on trees that passed it.
        // Every action that lets an object run, trusts it or excludes it
        // needs an identity, as an allow does (#34).
        if depth <= MAX_TREE_DEPTH {
            // The analysis is structural: it does not decide whether the
            // criteria on a path can all hold at once, so the messages name
            // a path through the tree, not a way the rule is known to match.
            let Guarantee {
                identity,
                context,
                witness,
            } = guaranteed_identity(&rule.match_, "");
            let through = describe_witness(&witness);
            let kind = rule.action.kind();
            let rule_desc = if kind == ActionKind::Allow {
                "this allow rule".to_owned()
            } else {
                format!("this `{kind}` rule")
            };
            match (kind.needs_identity(), identity) {
                (true, Identity::None) => self.push(
                    ErrorCode::NoIdentityAnchor,
                    &tree,
                    format!("{rule_desc} has a path through {through} with no positive identity criterion outside `not`, so the analysis cannot show that it identifies the object; every path through the tree needs one"),
                ),
                (_, Identity::None) if !context => self.push(
                    ErrorCode::NegationOnly,
                    &tree,
                    format!("this rule has a path through {through} made of negations alone, which match almost every object; combine each negation with a positive identity criterion (a hash, signer, path or version-resource test) in an `all`"),
                ),
                (_, Identity::None) => self.push(
                    ErrorCode::NoIdentityAnchor,
                    &tree,
                    format!("this rule has a path through {through} with no positive identity criterion, so the analysis cannot show that it identifies the object: user, device and session criteria narrow a rule, but every path through the tree also needs a positive identity criterion"),
                ),
                (true, Identity::WeakHashOnly) => self.push(
                    ErrorCode::WeakHashOnlyAllow,
                    &tree,
                    format!("{rule_desc} has a path through {through} whose only identity is SHA-1 or MD5 (including SHA-1 thumbprints and TBS hashes), which are compatibility hashes (ADR 0008); require a SHA-256 or another identity on every path"),
                ),
                (true, Identity::Weak) => self.push(
                    ErrorCode::WeakIdentity,
                    &tree,
                    format!("{rule_desc} has a path through {through} whose only identities are weak (file names, extensions, version-resource strings, or a certificate authority, which vouches for every file it signs); add a hash, a publisher, a leaf certificate or a path"),
                ),
                _ => {}
            }
        }
    }

    fn criterion(&mut self, base: &str, c: &Criterion, mandatory: bool) {
        let class = c.field.class();
        if !c.operator.applies_to_field(c.field) {
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
        let case_ok = c.case_sensitive.is_none() || class.has_case();
        if !case_ok {
            self.push(
                ErrorCode::CaseSensitivityNotApplicable,
                &format!("{base}/case_sensitive"),
                format!("`{}` has no case to compare", serde_name(&c.field)),
            );
        }
        let problems = ops::option_problems(c);
        let options_ok = problems.is_empty() && ops::signer::option_problems(c).is_empty();
        for kind in &problems {
            if let CompileErrorKind::OptionNotApplicable(option, _) = kind {
                self.compile_error(&format!("{base}/{option}"), kind);
            }
        }
        // `safety_critical` makes an unknown fact count towards a deny, which
        // only fails closed in a mandatory blocklist (#32, #87). Anywhere
        // else it would do nothing, or make a rule fail open. It does not
        // change how the criterion compiles.
        if c.safety_critical && !mandatory {
            self.push(
                ErrorCode::OptionNotApplicable,
                &format!("{base}/safety_critical"),
                "`safety_critical` only applies in a mandatory blocklist",
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
            } else if !self.compile_values {
                // Compiled when the document it came from was validated.
            } else if let Err(kind) = CompiledCriterion::check_value(c, value) {
                self.compile_error(&path, &kind);
                all_ok = false;
            }
        }
        // Checks across values, such as the order of a version range. Every
        // value already compiled, and a range has no patterns, so this
        // compiles nothing a second time.
        // `case_sensitive` was reported above; compiling would report it
        // again.
        // A misplaced option was reported above and does not change the
        // values, so the bounds are still checked, without the options:
        // the author sees both findings in one pass.
        let well_formed = all_ok
            && case_ok
            && c.operator.applies_to_field(c.field)
            && (min..=max).contains(&c.values.len());
        // Ranges and windows are checked across their two values.
        if well_formed && self.compile_values && c.operator.value_count() == (2, 2) {
            let without_options;
            let c = if options_ok {
                c
            } else {
                without_options = Criterion {
                    anchored: None,
                    match_ads: None,
                    include_sub_ous: None,
                    signer: None,
                    ..c.clone()
                };
                &without_options
            };
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

    /// The `signer` options of a criterion (#31): each misplaced or invalid
    /// option is an error, and a status that a rule letting an object run
    /// accepts beyond the default, or a digest mismatch it allows, is a
    /// warning.
    fn signer_options(&mut self, base: &str, c: &Criterion, action: ActionKind) {
        for (option, kind) in ops::signer::option_problems(c) {
            self.compile_error(&format!("{base}/{option}"), &kind);
        }
        let Some(o) = c.signer.as_deref().filter(|_| c.field.is_signer()) else {
            return;
        };
        if o.allow_digest_mismatch {
            self.push(
                ErrorCode::SignatureStatusRelaxed,
                &format!("{base}/signer/allow_digest_mismatch"),
                "`allow_digest_mismatch` lets this criterion match a file that was changed after it was signed",
            );
        }
        let relaxed: Vec<String> = o
            .accept_status
            .iter()
            .flatten()
            .filter(|s| !s.is_trusted() && **s != crate::facts::SignerStatus::DigestMismatch)
            .map(|s| format!("`{}`", serde_name(s)))
            .collect();
        if action.needs_identity() && !relaxed.is_empty() {
            self.push(
                ErrorCode::SignatureStatusRelaxed,
                &format!("{base}/signer/accept_status"),
                format!(
                    "this rule trusts signatures whose status is {}, which do not show that the signer still vouches for the file",
                    relaxed.join(", ")
                ),
            );
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
            CompileErrorKind::CaseSensitivityNotApplicable => {
                ErrorCode::CaseSensitivityNotApplicable
            }
            CompileErrorKind::OptionNotApplicable(..) => ErrorCode::OptionNotApplicable,
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
            "group_cache_max_age_secs",
            s.group_cache_max_age_secs.into(),
            ranges::GROUP_CACHE_MAX_AGE_MIN.into(),
            ranges::GROUP_CACHE_MAX_AGE_MAX.into(),
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
        self.tags(&format!("{base}/tags"), &m.tags);
    }

    /// Checks a list of tags: at most 64, each 1 to 128 characters, trimmed,
    /// printable, and not repeated.
    fn tags(&mut self, base: &str, tags: &[String]) {
        if tags.len() > MAX_TAGS {
            self.push(
                ErrorCode::InvalidTag,
                base,
                format!("{} tags; at most {MAX_TAGS} are allowed", tags.len()),
            );
        }
        let mut seen = BTreeSet::new();
        for (i, tag) in tags.iter().enumerate() {
            let path = format!("{base}/{i}");
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

/// The weakest identity that every path through a tree checks. A path
/// takes every child of an `all` and one child of an `any`, and stops at a
/// `not`. Ordered from weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Identity {
    /// Some path checks no positive identity at all.
    None,
    /// Some path checks only SHA-1 or MD5.
    WeakHashOnly,
    /// Some path checks only weak identities (#31).
    Weak,
    /// Every path checks a medium or strong identity.
    Sound,
}

/// One node on a path that has only the guaranteed identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Step {
    /// The JSON Pointer of the node, relative to the rule's `match`.
    pointer: String,
}

/// The weakest identity a tree guarantees, and a witness: the nodes on one
/// of its weakest paths.
struct Guarantee {
    identity: Identity,
    /// Some path with no positive identity includes a positive context
    /// criterion, so it is not made of negations alone. This looks at every
    /// such path, so it never depends on the order of children.
    context: bool,
    witness: Vec<Step>,
}

impl Guarantee {
    /// Orders guarantees for an `any`: the weakest identity first and, among
    /// paths with no identity, one through a context criterion first, so
    /// the witness shows what the finding is about.
    fn weakness(&self) -> (Identity, bool) {
        (
            self.identity,
            self.identity == Identity::None && !self.context,
        )
    }
}

/// A conservative analysis: `all` guarantees the strongest of its children,
/// `any` only the weakest, and `not` guarantees nothing, because a negated
/// test never says what the object is. A context criterion (#33) says
/// nothing about the object either.
///
/// The witness of `all` joins its children's witnesses, since a path
/// through `all` goes through every child; the witness of `any` is its
/// weakest child's. With at most 32 criteria, a witness is short.
///
/// The paths are structural: a path whose criteria contradict each other,
/// such as `user.is_admin` both `is_true` and `is_false`, still counts.
fn guaranteed_identity(node: &Match, pointer: &str) -> Guarantee {
    match node {
        Match::All(children) => {
            let parts: Vec<Guarantee> = children
                .iter()
                .enumerate()
                .map(|(i, c)| guaranteed_identity(c, &format!("{pointer}/all/{i}")))
                .collect();
            // A path through `all` has no identity only if each child's part
            // has none, and it includes a context criterion if any part can.
            let unanchored = parts.iter().all(|g| g.identity == Identity::None);
            Guarantee {
                identity: parts
                    .iter()
                    .map(|g| g.identity)
                    .max()
                    .unwrap_or(Identity::None),
                context: unanchored && parts.iter().any(|g| g.context),
                witness: parts.into_iter().flat_map(|g| g.witness).collect(),
            }
        }
        Match::Any(children) => {
            let parts: Vec<Guarantee> = children
                .iter()
                .enumerate()
                .map(|(i, c)| guaranteed_identity(c, &format!("{pointer}/any/{i}")))
                .collect();
            // Every child's paths are paths of the `any`.
            let context = parts.iter().any(|g| g.context);
            parts
                .into_iter()
                // The first of the weakest, so the witness is stable.
                .reduce(|weakest, g| {
                    if g.weakness() < weakest.weakness() {
                        g
                    } else {
                        weakest
                    }
                })
                .map_or(
                    Guarantee {
                        identity: Identity::None,
                        context: false,
                        witness: Vec::new(),
                    },
                    |g| Guarantee { context, ..g },
                )
        }
        Match::Not(_) => Guarantee {
            identity: Identity::None,
            context: false,
            witness: vec![Step {
                pointer: format!("{pointer}/not"),
            }],
        },
        // Rejected as `unresolved_ref`; it guarantees nothing.
        Match::Ref(_) => Guarantee {
            identity: Identity::None,
            context: false,
            witness: vec![Step {
                pointer: format!("{pointer}/ref"),
            }],
        },
        Match::Criterion(c) => {
            let identity = match c.field.strength() {
                _ if !c.operator.is_positive() => Identity::None,
                None => Identity::None,
                Some(_) if c.field.is_weak_hash() => Identity::WeakHashOnly,
                Some(_) if c.field == crate::model::Field::SignerTbsHash => match sha1_values(c) {
                    Sha1Values::All => Identity::WeakHashOnly,
                    Sha1Values::Some => Identity::Weak,
                    Sha1Values::None => Identity::Sound,
                },
                Some(Strength::Weak) => Identity::Weak,
                Some(_) => Identity::Sound,
            };
            Guarantee {
                identity,
                // Only a context criterion is positive with no identity.
                context: identity == Identity::None && c.operator.is_positive(),
                witness: vec![Step {
                    pointer: format!("{pointer}/criterion"),
                }],
            }
        }
    }
}

/// How many values of a `signer.tbs_hash` criterion are 40-digit (SHA-1)
/// digests. The field takes SHA-1 to SHA-512 values, so its strength
/// depends on them (#31, ADR 0008): SHA-1 values alone are a weak hash, and
/// a list that mixes them in is only as strong as its weakest value.
enum Sha1Values {
    None,
    Some,
    All,
}

fn sha1_values(c: &Criterion) -> Sha1Values {
    let sha1 = |v: &String| ops::normalize_hex(v).is_some_and(|h| h.len() == 40);
    match c.values.iter().filter(|v| sha1(v)).count() {
        0 => Sha1Values::None,
        n if n == c.values.len() => Sha1Values::All,
        _ => Sha1Values::Some,
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

/// Most characters in one part of a `category_path`.
pub const MAX_CATEGORY_PART_CHARS: usize = 64;

/// Why a `category_path` is not acceptable, if it is not: one or two parts
/// separated by `/`, each 1 to 64 characters, trimmed, with no control or
/// bidirectional formatting characters.
pub(crate) fn category_problem(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() > 2 {
        return Some("at most two levels, `Category/Subcategory`".to_owned());
    }
    for part in parts {
        if part.trim().is_empty() {
            return Some("each part must be non-empty".to_owned());
        }
        if part.trim() != part {
            return Some("parts must not start or end with whitespace".to_owned());
        }
        if part.chars().count() > MAX_CATEGORY_PART_CHARS {
            return Some(format!(
                "each part is at most {MAX_CATEGORY_PART_CHARS} characters"
            ));
        }
        if part.chars().any(|c| c.is_control() || is_bidi_control(c)) {
            return Some(
                "must not contain control or bidirectional formatting characters".to_owned(),
            );
        }
    }
    None
}

/// Keys accepted in `settings.advanced`. None are defined yet; each will be
/// added here with its type when a feature needs one.
const KNOWN_ADVANCED_KEYS: &[&str] = &[];

/// Unicode bidirectional formatting characters, which can make a name read
/// differently from what it contains.
pub(crate) const fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// The findings of the policy metadata rules (#40) for `m` at `base`: the
/// same checks a policy, rule set or rule gets.
pub(crate) fn metadata_findings(base: &str, m: &Metadata) -> Vec<ValidationError> {
    let mut v = Validator::default();
    v.metadata(base, m);
    v.findings
}

/// Why a free-text field is not acceptable, if it is not: at most
/// `max_chars` characters, with no control characters other than tab and
/// line breaks, and no bidirectional formatting characters.
pub(crate) fn text_problem(text: &str, max_chars: usize) -> Option<String> {
    let chars = text.chars().count();
    if chars > max_chars {
        Some(format!(
            "{chars} characters; at most {max_chars} are allowed"
        ))
    } else if has_control(text) || text.chars().any(is_bidi_control) {
        Some(
            "must not contain control characters other than tab and line breaks, or bidirectional formatting characters"
                .to_owned(),
        )
    } else {
        None
    }
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
    if let Some(problem) = ops::value_too_long(value) {
        return Some(problem);
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
