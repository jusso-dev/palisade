//! The canonical policy object model (#30).
//!
//! A [`PolicyDocument`] is the unit that is stored, exchanged and versioned.
//! It holds one [`Policy`] and the [`RuleSet`]s that the policy references by
//! ID. Every type here maps one-to-one to the JSON Schema in
//! `schemas/policy/v1.json` ([`crate::schema`]).
//!
//! Deserialising gives a structurally valid document. It is not yet safe to
//! evaluate: [`PolicyDocument::validate`] checks limits, references and
//! field types, and returns the [`ValidatedPolicy`](crate::validate::ValidatedPolicy)
//! that later stages accept.
//!
//! All structs reject unknown fields (strict mode). Enums are `snake_case`
//! strings.

pub mod action;
pub mod effects;
pub mod mode;
pub mod precedence;
pub(crate) mod settings;
mod tree;
pub mod unknown;

#[cfg(test)]
pub(crate) mod arbitrary;

pub use action::{
    Action, ActionKind, ContainmentDirective, ContainmentProfileRef, DenyOptions, ElevationAuth,
    ElevationCondition, ElevationDirective, RequestTemplateRef, TokenProfileRef, TrustMode,
    TrustSourceDirective, UnknownAs,
};
pub use effects::{Effects, EventSeverity, LogLevel, Notify, ResolvedEffects, Upload};
pub use mode::ModeOptions;
pub use palisade_core::{Mode, ObjectType, PolicyId, RuleId, RuleSetId, SchemaVersion, ScriptKind};
pub use precedence::{AllowTiebreak, PrecedenceOptions, PriorityDirection, TierTiebreak};
pub use settings::{AdvancedValue, ControlLevel, PolicySettings, TimeZoneBasis};
pub use tree::{Criterion, Field, FieldClass, Match, Operator, Strength};
pub use unknown::{
    ApprovalScope, CompliancePreset, DriverBootPolicy, Level, LocationClass, OriginClass,
    PreexistingPolicy, PromptOption, PromptSettings, Reauth, ScopeLimit, UnknownPolicy,
};

use crate::scope::{LocationProfile, RuleSetScope, Scope};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Hard limits, enforced by [`PolicyDocument::validate`].
pub mod limits {
    /// Most rules in one document, over all rule sets.
    pub const MAX_RULES_PER_POLICY: usize = 100_000;
    /// Most rule sets in one document, and most references to them.
    pub const MAX_RULE_SETS_PER_POLICY: usize = 1_000;
    /// Most values in one criterion.
    pub const MAX_VALUES_PER_CRITERION: usize = 25;
    /// Longest criterion value, in UTF-8 bytes.
    pub const MAX_VALUE_BYTES: usize = 2048;
    /// Most criteria (leaves) in one rule's match tree.
    pub const MAX_CRITERIA_PER_RULE: usize = 32;
    /// Deepest match tree. A rule whose match is a single criterion has depth 1.
    pub const MAX_TREE_DEPTH: usize = 8;
    /// Longest name, in Unicode scalar values.
    pub const MAX_NAME_CHARS: usize = 128;
    /// Longest description or free-text field, in Unicode scalar values.
    pub const MAX_TEXT_CHARS: usize = 4096;
    /// Most tags on one object.
    pub const MAX_TAGS: usize = 64;
}

/// A versioned policy document: one policy and the rule sets it uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// The version of this schema the document was written for. A reader
    /// accepts the same major version and any minor version.
    pub schema_version: SchemaVersion,
    /// The policy.
    pub policy: Policy,
    /// The rule sets the policy references, in any order. The policy's
    /// `rule_sets` list gives the order that applies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub rule_sets: Vec<RuleSet>,
}

/// The decision part of a policy: which rule sets apply, and how.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Stable ID. Renaming the policy never changes it.
    pub id: PolicyId,
    /// Display name: 1 to 128 characters, trimmed, no control characters.
    /// Uniqueness within a tenant is checked by the server (#10).
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    /// Free-text description, at most 4096 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub description: Option<String>,
    /// Monotonic revision, raised by the server on every change (#10).
    pub revision: u64,
    /// How matching rules are combined (#35, ADR 0004).
    #[serde(default)]
    pub precedence_model: PrecedenceModel,
    /// Settings of the precedence models (#35). An option the selected
    /// model does not use is ignored, with a warning.
    #[serde(default, skip_serializing_if = "PrecedenceOptions::is_default")]
    pub precedence_options: PrecedenceOptions,
    /// The base enforcement mode (#36). `disabled` is not allowed: only a
    /// device can be disabled, with a reason and an expiry.
    pub mode: Mode,
    /// The modes per object type and while disconnected (#36).
    #[serde(default, skip_serializing_if = "ModeOptions::is_default")]
    pub mode_options: ModeOptions,
    /// Typed settings. Every field has a documented default.
    #[serde(default)]
    pub settings: PolicySettings,
    /// What happens when no rule decides (#39). The default blocks every
    /// unknown object.
    #[serde(default, skip_serializing_if = "UnknownPolicy::is_default")]
    pub unknown: UnknownPolicy,
    /// The rule sets that apply, in order, by ID.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub rule_sets: Vec<RuleSetId>,
    /// Who, where and when the whole policy applies (#38). Every rule must
    /// also be in this scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The scopes of rule set assignments (#38): each rule of the set must
    /// also be in every one of them. At most one entry per rule set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 1000))]
    pub rule_set_scopes: Vec<RuleSetScope>,
    /// Named network locations that scopes test with `location_profile`
    /// (#38).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    pub location_profiles: Vec<LocationProfile>,
    /// Governance metadata (#40).
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

/// How the matching rules of the ordinary rule sets are combined (#35).
///
/// The mandatory-deny tier and the implicit deny for unmatched files apply
/// under every model (ADR 0004). The semantics of each model are in
/// [`crate::precedence`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrecedenceModel {
    /// Any matching deny blocks; otherwise any matching allow allows. The default.
    #[default]
    DenyWins,
    /// Any matching allow allows. Not recommended for Essential Eight.
    AllowWins,
    /// The rule with the most specific identity wins.
    Specificity,
    /// Rules are ordered, and the first match decides.
    FirstMatch,
    /// The rule with the winning numeric priority decides.
    Priority,
}

/// A named, reusable, ordered collection of rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    /// Stable ID.
    pub id: RuleSetId,
    /// Display name, with the same rules as a policy name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    /// Free-text description, at most 4096 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub description: Option<String>,
    /// The content version of this rule set, for display (for example `3.0`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub version: Option<String>,
    /// What the rule set is for.
    pub kind: RuleSetKind,
    /// Only for `blocklist`: evaluated in the non-overridable mandatory-deny
    /// tier (#35, ADR 0004).
    #[serde(default)]
    pub mandatory: bool,
    /// The operating system the rules are written for.
    #[serde(default)]
    pub os: Os,
    /// Curated sets are read-only: edit a duplicate instead.
    #[serde(default)]
    pub read_only: bool,
    /// Hidden from default console views (staging).
    #[serde(default)]
    pub hidden: bool,
    /// Only for a blocklist that is not mandatory: the mode its rules
    /// decide in, replacing the mode for the object's type, for example to
    /// try a new blocklist in `audit` (#36). `disabled` is not allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_override: Option<Mode>,
    /// Whether a group below the one that assigns this rule set may disable
    /// one of its rules with `suppress_inherited` (#37). Unset means `true`
    /// for an allowlist or a baseline and `false` for every other kind. A
    /// mandatory rule set can never be suppressed (`suppress_not_allowed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_child_suppress: Option<bool>,
    /// The category, as `Category` or `Category/Subcategory`: each part 1 to
    /// 64 characters, trimmed, with no `/` or control characters. Assigning
    /// a category assigns every rule set library in it (#37).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = r"^[^/]+(/[^/]+)?$"))]
    pub category_path: Option<String>,
    /// The `first_match` band of the hierarchy level that assigned this rule
    /// set (#37): rules of a lower band come first, whatever their `order`.
    /// The hierarchy writes it into an effective policy and replaces any
    /// value an authored policy gives, so a local administrator cannot move
    /// a rule set ahead of global policy. 0, the default, outside a
    /// hierarchy.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub band: u8,
    /// The rules, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// Governance metadata (#40).
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

/// The purpose of a rule set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetKind {
    /// Rules that allow.
    Allowlist,
    /// Rules that deny.
    Blocklist,
    /// A baseline of what was present at a point in time.
    Baseline,
    /// Trusted sources (#9).
    Trust,
    /// Elevation rules (#12).
    Elevation,
    /// Containment rules (#14).
    Containment,
    /// Any mix of actions.
    Mixed,
}

/// The operating system a rule set targets. Other systems are reserved and
/// will be added in a minor version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    /// Windows.
    #[default]
    Windows,
}

/// One rule: a match tree and the action taken when it matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable ID, never reused.
    pub id: RuleId,
    /// Human short ID from the tenant's sequence, `R-` and 6 to 12 digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = r"^R-[0-9]{6,12}$"))]
    pub display_id: Option<String>,
    /// Display name, with the same rules as a policy name.
    #[schemars(length(min = 1, max = 128))]
    pub name: String,
    /// Free-text description, at most 4096 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub description: Option<String>,
    /// Disabled rules are kept, but never decide.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The object classes the rule applies to. Empty means every class.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub object_types: Vec<ObjectType>,
    /// When the rule matches (#33).
    #[serde(rename = "match")]
    pub match_: Match,
    /// What happens when it matches (#34).
    pub action: Action,
    /// Logging, upload, notification, severity and tags (#34). Unset
    /// fields take the action's defaults.
    #[serde(default, skip_serializing_if = "Effects::is_empty")]
    pub effects: Effects,
    /// Position for the `first_match` model (#35): 0 to 1000000, lowest
    /// first. Rules of custom (not read-only) rule sets use 100001 to
    /// 999989; the other ranges are reserved for system, curated and
    /// catch-all rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = 1_000_000))]
    pub order: Option<u32>,
    /// Priority for the `priority` model (#35).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Per-rule enforcement override (#36). Only for `deny` rules.
    #[serde(default)]
    pub enforcement_override: EnforcementOverride,
    /// Who, where and when the rule applies (#38). Unset means everyone,
    /// everywhere, always, within the policy's and the rule set's scopes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Governance metadata (#40).
    #[serde(default, skip_serializing_if = "Metadata::is_empty")]
    pub metadata: Metadata,
}

const fn default_true() -> bool {
    true
}

/// serde's `skip_serializing_if` passes a reference.
const fn is_zero(n: &u8) -> bool {
    *n == 0
}

/// How one rule relates to the policy mode (#36).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOverride {
    /// Follow the effective mode. The default.
    #[default]
    Inherit,
    /// Enforce this rule even in audit or learning mode.
    AlwaysEnforce,
    /// Never enforce this rule: it only reports what it would block.
    NeverEnforce,
}

/// Governance metadata (#40). More fields arrive with #40.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// Why the object exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub justification: Option<String>,
    /// A change or ticket reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub ticket_ref: Option<String>,
    /// Free-form labels, each 1 to 128 characters, at most 64.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64), inner(length(min = 1, max = 128)))]
    pub tags: Vec<String>,
    /// A free-text comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub comment: Option<String>,
}

impl Metadata {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// A document could not be read.
#[derive(Debug)]
pub enum LoadError {
    /// The input is not JSON, or does not match the model.
    Json(serde_json::Error),
    /// `schema_version` is missing or not a version string.
    MissingSchemaVersion,
    /// The document's major version is not one this reader implements.
    UnsupportedSchemaVersion(SchemaVersion),
}

impl core::fmt::Display for LoadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid policy document: {e}"),
            Self::MissingSchemaVersion => {
                f.write_str("invalid policy document: missing or invalid `schema_version`")
            }
            Self::UnsupportedSchemaVersion(v) => write!(
                f,
                "unsupported schema version {v}: this reader implements {}",
                crate::schema::CURRENT
            ),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl PolicyDocument {
    /// Reads a document from JSON in strict mode.
    ///
    /// The schema version is checked first, so a document from another major
    /// version gets a version error rather than a confusing field error.
    /// Unknown fields are rejected, including fields from a newer minor
    /// version (a lenient reader is future work in #30).
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] if the input is not a document this reader
    /// understands.
    pub fn from_json(input: &str) -> Result<Self, LoadError> {
        #[derive(Deserialize)]
        struct Header {
            schema_version: Option<serde_json::Value>,
        }
        let header: Header = serde_json::from_str(input).map_err(LoadError::Json)?;
        let version: SchemaVersion = header
            .schema_version
            .and_then(|v| v.as_str()?.parse().ok())
            .ok_or(LoadError::MissingSchemaVersion)?;
        if !version.is_readable_by(crate::schema::CURRENT) {
            return Err(LoadError::UnsupportedSchemaVersion(version));
        }
        serde_json::from_str(input).map_err(LoadError::Json)
    }

    /// Writes the document as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Only fails if serialisation itself fails, which the model's types do
    /// not do.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
