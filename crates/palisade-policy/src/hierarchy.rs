//! The group hierarchy, inheritance and the effective policy of a device
//! (#37).
//!
//! A [`HierarchyDocument`] is one snapshot of an installation's scopes:
//! the tree of nodes, the policies assigned to them, the reusable
//! [libraries](crate::library) and the automatic placement rules. It is an
//! immutable value. [`HierarchyDocument::validate`] checks it once and
//! returns a [`ValidatedHierarchy`], from which
//! [`ValidatedHierarchy::effective_policy`] computes the one effective
//! policy of a device. That is a pure function of the snapshot, the
//! libraries at their resolved versions, and the device's membership of
//! dynamic groups. The same inputs always give the same policy and the same
//! content hash, whatever order the snapshot lists anything in.
//!
//! The server stores the snapshot, computes and caches effective policies
//! (#10, #127, #128, #129), and ships them in the bundle (#43). The agent
//! only ever sees the flattened result.
//!
//! # Levels
//!
//! | Kind | Parent | Notes |
//! |---|---|---|
//! | `global` | none | Exactly one: installation-wide defaults ("global defaults"), visible only to installation administrators. |
//! | `tenant` | the global node | |
//! | `group` | a tenant or a group | Nested at most [`limits::MAX_GROUP_DEPTH`] deep below the tenant. |
//! | `device` | a group | A device has exactly one primary group: its parent. |
//! | `dynamic_group` | a tenant | Assignment only, not hierarchy: a device's membership is an input ([`Membership`]), computed from tags by #38 and #10. |
//! | `template` | the global node or a tenant | Not in the tree. A node may link to one (see [Templates](#templates)). |
//!
//! Each tenant has the built-in groups `unassigned` (exactly one: new and
//! unmapped devices; its mode is `audit` unless it sets one), and at most
//! one each of `unmanaged` (removed from management: the effective policy
//! is [`Management::Unmanaged`], and the agent goes to `disabled` with
//! tamper protection released) and `staging` (hidden: no device can be in
//! it, and placement cannot target it; it is for dry runs with
//! [`ValidatedHierarchy::effective_policy_as`]). Built-in groups sit
//! directly below their tenant and have no child groups. Every reference to
//! a node is checked, and a parent cycle is rejected with its path
//! (`node_cycle`).
//!
//! # Layers
//!
//! A device's effective policy is built from layers, from the outermost to
//! the nearest: the global node, its tenant, its groups from the tenant
//! down, its dynamic groups (the highest `rank` first, so the lowest rank is
//! nearest), and the device. A node that links to a template is preceded by
//! the template's layer at the same position. Within one node, policies are
//! applied by `slot_order`: the lowest slot wins a conflict.
//!
//! # Rules are additive
//!
//! A node contributes the rule sets of every policy assigned to it, the
//! rule set libraries it assigns (`rule_sets`), and every rule set library
//! in each of its `categories`, including ones added later. The effective
//! rule list is the union over all layers. Each rule keeps its provenance:
//! the nodes that contributed it and how ([`RuleProvenance`]). A rule set
//! that two layers contribute is included once. Two different rule sets
//! with one ID, including two versions of one library, are rejected
//! (`rule_set_conflict`, `library_version_conflict`), so a child cannot
//! pin an older version of an inherited blocklist.
//!
//! A child cannot delete an inherited rule. It can:
//!
//! - **suppress** it locally, with `suppress_inherited: [rule_id]`, if the
//!   rule set allows it: `allow_child_suppress`, which defaults to `true`
//!   for allowlists and baselines and to `false` for every other kind, so
//!   blocklists cannot be suppressed unless they say so. **A mandatory rule
//!   set can never be suppressed**, whatever it says (ADR 0004, #125). A
//!   suppressed rule stays in the effective policy, disabled, and its
//!   provenance says which node suppressed it. A suppression only applies
//!   to a rule that every contributing layer is above the suppressing node;
//!   if the node or a nearer layer also contributes the rule set, the rule
//!   stays active and is reported as reasserted; or
//! - **shadow** it with a rule of its own that wins under the precedence
//!   model. Mandatory denies are evaluated before every model, so nothing
//!   shadows them.
//!
//! # Settings are override-by-nearest
//!
//! Each top-level key of [`PolicySettings`](crate::model::PolicySettings)
//! is one setting. A layer sets a key through its node's `settings` map, or
//! through an assigned policy whose value for the key differs from the
//! default; to set a key back to its default below a node that changed it,
//! use the node's `settings`. A node's own `settings` beat the policies
//! assigned to it. The nearest layer that sets a key wins. A key in a
//! node's `locked_settings` keeps the value it has at that node (after the
//! node's own layers) for every layer below; a later attempt to change it is
//! ignored and reported (`blocked_by_lock`). Settings added to the model
//! later are inherited the same way, with no change here.
//!
//! The mode options are merged the same way, per key:
//! `mode_by_type.<type>`, `mode_disconnected` and `disconnected_after_secs`.
//! `locked_settings` may lock them too, as `mode_options.mode_disconnected`,
//! `mode_options.disconnected_after_secs` and `mode_options.mode_by_type`
//! (every type at once).
//! A `mode_disconnected` that is not at least as strict as the effective
//! mode is dropped, because unset means the effective mode itself.
//!
//! # Modes
//!
//! Each layer's mode is its node's `mode`, or else the mode of its
//! policies, merged by `mode_merge`: `closest` (the default) takes the
//! policy with the lowest slot, `strictest` the strictest (#36). The
//! built-in `unassigned` group is `audit` unless it sets a mode. Across
//! layers, `closest` takes the nearest layer's mode and `strictest` the
//! strictest of all. With no mode anywhere the device is in `audit`
//! (ADR 0012).
//!
//! A node with `lock_mode: true` fixes a **floor**: the mode in force at
//! that node. Nothing in the effective policy may then decide in a weaker
//! mode: a weaker effective mode, `mode_by_type` entry or rule set
//! `mode_override` is raised to the floor, a control level that would cap
//! below it is raised (an `enforce` floor needs `enforce`, an `audit` or
//! `learning` floor at least `audit`), and with an `enforce` floor
//! `never_enforce` rules become `inherit`. A lock applies to the whole
//! effective policy, including what the locking node assigns itself. Every
//! change is listed in [`ModeProvenance::adjustments`]. Raising is always
//! allowed below a lock.
//!
//! # Precedence models
//!
//! The model is chosen by the nearest of the global node and the tenant
//! that sets `precedence`; a group may set it only if its tenant's
//! `tenant_options.allow_group_precedence` is `true`
//! (`precedence_not_allowed`). With no node choosing, the model of the
//! highest-ranked policy (nearest layer, lowest slot) applies. Every policy
//! in the effective policy must use exactly that model and its options, or
//! the effective policy is rejected (`precedence_conflict`), so one
//! effective policy never mixes models.
//!
//! # First-match bands
//!
//! Under `first_match`, rules are ordered by level before their `order`:
//! every rule set carries the band of the first layer that contributed it
//! ([`RuleSet::band`](crate::model::RuleSet::band)). `level_order:
//! top_down` (the default) puts the global node first, then the tenant, the
//! groups from the tenant down, the dynamic groups and the device, so a
//! local administrator cannot pre-empt global policy; `bottom_up` reverses
//! that; `flat` puts every rule set in band 0, so only `order` counts.
//! Mandatory denies and exclusions are decided before the model in every
//! case, and the implicit deny after it.
//!
//! # Templates
//!
//! A node may be created from a template in two ways. A **one-time copy**
//! ([`ValidatedHierarchy::copy_from_template`]) copies the template's
//! assignments, rule sets, categories, settings, mode and suppressions into
//! a new node, with no link afterwards. A **linked** node sets `template`:
//! the template's layer is applied at the node's position, just before the
//! node's own, on every computation, so later changes to the template take
//! effect. A template cannot link to another template.
//!
//! # Explaining
//!
//! [`EffectivePolicy::rule`] and [`EffectivePolicy::setting`] return, for
//! a rule or a setting, every node that contributed it, how, and whether it
//! was suppressed, reasserted, overridden or blocked by a lock (for #41).
//!
//! # Placement
//!
//! Each tenant has an ordered list of placement rules (`placement`), see
//! [`placement`].

pub mod effective;
pub mod placement;
mod validate;

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::library::{Library, LibraryCode, LibraryRef, Realm};
use crate::model::{
    Mode, PolicyDocument, PrecedenceModel, PrecedenceOptions, RuleId, SchemaVersion,
};
use crate::validate::ErrorCode;
use palisade_core::Uuid7;

pub use effective::{
    Contribution, EffectivePolicy, Management, ModeAdjustment, ModeProvenance, PrecedenceSource,
    RuleProvenance, RuleStatus, SettingProvenance, SettingStep, StepOutcome, Via,
};
pub use placement::{
    PlacementConditions, PlacementFacts, PlacementOutcome, PlacementRule, PlacementTrigger,
};
pub use validate::ValidatedHierarchy;

/// Hard limits on a hierarchy snapshot.
pub mod limits {
    /// Most nodes in one snapshot.
    pub const MAX_NODES: usize = 200_000;
    /// Deepest nesting of groups below a tenant: a group directly below the
    /// tenant has depth 1.
    pub const MAX_GROUP_DEPTH: usize = 8;
    /// Most policies in one snapshot.
    pub const MAX_POLICIES: usize = 10_000;
    /// Most policy assignments on one node.
    pub const MAX_ASSIGNMENTS_PER_NODE: usize = 64;
    /// Most rule set libraries and categories on one node, each.
    pub const MAX_REFS_PER_NODE: usize = 256;
    /// Most suppressed rules on one node.
    pub const MAX_SUPPRESSIONS_PER_NODE: usize = 1_000;
    /// Most dynamic groups one device may be in.
    pub const MAX_DYNAMIC_GROUPS: usize = 64;
    /// Most placement rules in one tenant.
    pub const MAX_PLACEMENT_RULES: usize = 1_000;
}

/// The stable ID of a hierarchy node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(pub Uuid7);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One snapshot of the hierarchy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HierarchyDocument {
    /// The policy schema version the snapshot was written for.
    pub schema_version: SchemaVersion,
    /// Monotonic revision, raised by the server on every change. It is the
    /// effective policy's revision.
    pub revision: u64,
    /// The nodes, in any order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<Node>,
    /// The policies that nodes assign, in any order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyEntry>,
    /// Every library version, in any order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<Library>,
    /// Automatic placement rules, in any order; each tenant's are ranked
    /// by `order`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement: Vec<PlacementRule>,
}

impl HierarchyDocument {
    /// Reads a snapshot from JSON in strict mode, with the reader of
    /// [`crate::dsl`]: a key repeated at any depth (including inside a
    /// node's `settings` values) is an error, so JSON and YAML always read
    /// a snapshot the same way.
    ///
    /// # Errors
    ///
    /// The reader's error, or the model error, as text.
    pub fn from_json(input: &str) -> Result<Self, String> {
        Self::from_yaml(input)
    }

    /// Reads a snapshot from YAML, with the strict rules of
    /// [`crate::dsl`] (YAML 1.2, no anchors or tags, no duplicate keys at
    /// any depth). JSON is YAML here, read by the same strict reader.
    ///
    /// # Errors
    ///
    /// The reader's error, or the model error, as text.
    pub fn from_yaml(input: &str) -> Result<Self, String> {
        let value = crate::dsl::to_json_value(input, &crate::dsl::Limits::default())
            .map_err(|e| e.to_string())?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }
}

/// A policy and who it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntry {
    /// Global (usable anywhere) or one tenant's.
    pub realm: Realm,
    /// The policy and its rule sets. Its trees may hold `ref` nodes, which
    /// are resolved from its realm.
    pub document: PolicyDocument,
}

/// What a node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// The installation.
    Global,
    /// A tenant.
    Tenant,
    /// A group of devices, possibly nested.
    Group,
    /// One device.
    Device,
    /// A group for assignment only, by membership.
    DynamicGroup,
    /// A template that nodes may link to or be copied from.
    Template,
}

impl NodeKind {
    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Tenant => "tenant",
            Self::Group => "group",
            Self::Device => "device",
            Self::DynamicGroup => "dynamic_group",
            Self::Template => "template",
        }
    }
}

/// The built-in groups of a tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Builtin {
    /// New and unmapped devices. `audit` unless it sets a mode.
    Unassigned,
    /// Devices removed from management.
    Unmanaged,
    /// Hidden, for dry runs: no device can be in it.
    Staging,
}

impl Builtin {
    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unassigned => "unassigned",
            Self::Unmanaged => "unmanaged",
            Self::Staging => "staging",
        }
    }
}

/// One node of the hierarchy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Stable ID.
    pub id: NodeId,
    /// Display name, with the same rules as a policy name.
    pub name: String,
    /// What the node is.
    pub kind: NodeKind,
    /// The parent. Only the global node has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<NodeId>,
    /// For a built-in group, which one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin: Option<Builtin>,
    /// A linked template, applied just before this node on every
    /// computation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<NodeId>,
    /// The policies assigned here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<Assignment>,
    /// Rule set libraries assigned here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<LibraryRef>,
    /// Categories (`Category` or `Category/Subcategory`): every rule set
    /// library in one is assigned here, at its latest version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Inherited rules disabled here and below.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppress_inherited: Vec<RuleId>,
    /// Settings set here: keys of the policy `settings`, with their values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "crate::model::settings::unique_keys")]
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Settings that layers below cannot change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locked_settings: Vec<String>,
    /// The mode set here, beating the policies assigned here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// Layers below cannot lower the mode in force here.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub lock_mode: bool,
    /// The precedence model, on the global node, a tenant, or a group whose
    /// tenant allows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedence: Option<PrecedenceSetting>,
    /// Options of a tenant (or, as defaults, of the global node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_options: Option<TenantOptions>,
    /// For a dynamic group: its rank among the tenant's dynamic groups. A
    /// lower rank is nearer the device, so it wins a conflict. Unset is 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
    /// For a group: `false` opts it out of automatic placement, as a source
    /// (a device in it is never moved) and as a target. Unset is `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_auto_assignment: Option<bool>,
}

/// A policy assigned to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    /// The policy.
    pub policy: crate::model::PolicyId,
    /// The slot: unique on the node, and the lower slot wins a conflict.
    pub slot_order: u32,
}

/// A precedence model chosen by a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrecedenceSetting {
    /// The model.
    pub model: PrecedenceModel,
    /// Its options.
    #[serde(default, skip_serializing_if = "PrecedenceOptions::is_default")]
    pub options: PrecedenceOptions,
}

/// How `first_match` orders the levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LevelOrder {
    /// Global first, the device last. The default.
    #[default]
    TopDown,
    /// The device first, global last.
    BottomUp,
    /// No bands: only `order` counts.
    Flat,
}

/// How the modes of several policies combine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeMerge {
    /// The nearest layer, and on one node the lowest slot. The default.
    #[default]
    Closest,
    /// The strictest of all.
    Strictest,
}

/// A tenant's options. Each unset option takes the global node's, then the
/// default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantOptions {
    /// `top_down` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level_order: Option<LevelOrder>,
    /// `closest` by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_merge: Option<ModeMerge>,
    /// Whether groups may choose their own precedence model. `false` by
    /// default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_group_precedence: Option<bool>,
    /// Whether a change of signed-in user re-runs placement. `false` by
    /// default; first contact and reconnects always do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place_on_user_change: Option<bool>,
}

/// A device's membership of dynamic groups: an input, computed from tags
/// and other facts by #38 and #10.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    /// The dynamic groups, in any order.
    pub dynamic_groups: Vec<NodeId>,
}

/// The stable code of a hierarchy finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HierarchyCode {
    /// A library finding.
    Library(LibraryCode),
    /// A finding of a policy, or of the effective policy, from
    /// [`PolicyDocument::validate`].
    Policy(ErrorCode),
    /// The schema version's major is not this reader's.
    UnsupportedSchemaVersion,
    /// A name is not valid.
    InvalidName,
    /// Two nodes, policies or placement rules share an ID.
    DuplicateId,
    /// A reference names a node that does not exist, or of the wrong kind.
    UnknownNode,
    /// Parents, or template links, form a cycle.
    NodeCycle,
    /// A node's parent is not allowed for its kind, or a node has no path
    /// to the global node.
    InvalidParent,
    /// Groups nest too deeply.
    GroupTooDeep,
    /// A built-in group is missing, repeated or misplaced.
    InvalidBuiltin,
    /// An assignment names a policy that does not exist.
    UnknownPolicy,
    /// A policy or library is used where it is not visible.
    NotVisible,
    /// A policy is assigned twice to a node, or two assignments share a
    /// slot.
    DuplicateAssignment,
    /// A field is set on a kind of node that cannot have it.
    FieldNotAllowed,
    /// A setting key is unknown, or its value is not valid.
    InvalidSetting,
    /// A suppressed rule is not inherited by the node.
    SuppressUnknownRule,
    /// A suppressed rule's rule set does not allow suppression.
    SuppressNotAllowed,
    /// A group sets a precedence model its tenant does not allow.
    PrecedenceNotAllowed,
    /// Policies in one effective policy use different precedence models.
    PrecedenceConflict,
    /// Two different rule sets share an ID.
    RuleSetConflict,
    /// Two versions of one rule set library would apply to one device.
    LibraryVersionConflict,
    /// A template link is not valid.
    InvalidTemplate,
    /// A category is not valid.
    InvalidCategory,
    /// A placement rule is not valid.
    InvalidPlacement,
    /// Too many of something.
    TooMany,
    /// A device's membership names a node that is not one of its tenant's
    /// dynamic groups.
    InvalidMembership,
    /// The library is still referenced.
    InUse,
}

impl HierarchyCode {
    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Library(c) => c.as_str(),
            Self::Policy(c) => c.as_str(),
            Self::UnsupportedSchemaVersion => "unsupported_schema_version",
            Self::InvalidName => "invalid_name",
            Self::DuplicateId => "duplicate_id",
            Self::UnknownNode => "unknown_node",
            Self::NodeCycle => "node_cycle",
            Self::InvalidParent => "invalid_parent",
            Self::GroupTooDeep => "group_too_deep",
            Self::InvalidBuiltin => "invalid_builtin",
            Self::UnknownPolicy => "unknown_policy",
            Self::NotVisible => "not_visible",
            Self::DuplicateAssignment => "duplicate_assignment",
            Self::FieldNotAllowed => "field_not_allowed",
            Self::InvalidSetting => "invalid_setting",
            Self::SuppressUnknownRule => "suppress_unknown_rule",
            Self::SuppressNotAllowed => "suppress_not_allowed",
            Self::PrecedenceNotAllowed => "precedence_not_allowed",
            Self::PrecedenceConflict => "precedence_conflict",
            Self::RuleSetConflict => "rule_set_conflict",
            Self::LibraryVersionConflict => "library_version_conflict",
            Self::InvalidTemplate => "invalid_template",
            Self::InvalidCategory => "invalid_category",
            Self::InvalidPlacement => "invalid_placement",
            Self::TooMany => "too_many",
            Self::InvalidMembership => "invalid_membership",
            Self::InUse => "in_use",
        }
    }
}

impl fmt::Display for HierarchyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One hierarchy finding: a code, the JSON Pointer of the offending value
/// in the snapshot (or, for the effective policy, under `/effective`), and a
/// message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HierarchyError {
    /// The stable code.
    pub code: HierarchyCode,
    /// Where.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for HierarchyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error[{}] {}: {}", self.code, self.path, self.message)
    }
}

impl std::error::Error for HierarchyError {}

pub(crate) fn herr(
    code: HierarchyCode,
    path: impl Into<String>,
    message: impl Into<String>,
) -> HierarchyError {
    HierarchyError {
        code,
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
pub(crate) mod tests;
