//! Computing the effective policy of a device (#37). The semantics are in
//! the [module documentation](super).

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::limits::MAX_DYNAMIC_GROUPS;
use super::validate::{NodeInfo, ValidatedHierarchy, pointer_escape};
use super::{
    Builtin, HierarchyCode, HierarchyError, LevelOrder, Membership, ModeMerge, NodeId, NodeKind,
    herr,
};
use crate::library::{LibraryContent, LibraryId, Version};
use crate::mode::strictness;
use crate::model::{
    Action, ControlLevel, EnforcementOverride, Metadata, Mode, ModeOptions, ObjectType, Policy,
    PolicyDocument, PolicyId, PolicySettings, PrecedenceModel, PrecedenceOptions, RuleId, RuleSet,
    RuleSetId, RuleSetKind,
};
use crate::schema;
use crate::validate::{Severity, ValidatedPolicy};

/// Whether the device is managed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Management {
    /// It has an effective policy.
    Managed,
    /// Its primary group is the built-in `unmanaged` group: it has no
    /// policy, and the agent goes to `disabled` with tamper protection
    /// released (#69, #220).
    Unmanaged,
}

/// How a node contributed something.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// A policy assigned to the node.
    Policy {
        /// The policy.
        policy: PolicyId,
        /// Its slot on the node.
        slot_order: u32,
    },
    /// A rule set library the node assigns.
    Library {
        /// The library.
        library: LibraryId,
        /// The version used.
        version: u32,
    },
    /// A rule set library in a category the node assigns.
    Category {
        /// The category.
        category: String,
        /// The library.
        library: LibraryId,
        /// The version used: the latest.
        version: u32,
    },
    /// The node's own `settings`.
    Node,
}

/// One node's part in a rule set or a setting.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Contribution {
    /// The node whose layer contributed: a template's ID for a template
    /// layer.
    pub node: NodeId,
    /// For a template layer, the node that links to the template.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_for: Option<NodeId>,
    /// How.
    pub via: Via,
}

/// Whether an effective rule can decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum RuleStatus {
    /// It is enabled.
    Active,
    /// Its rule set has it disabled.
    Disabled,
    /// A node suppressed it (`suppress_inherited`): it is in the effective
    /// policy, disabled.
    Suppressed {
        /// The node.
        by: NodeId,
    },
    /// A node suppressed it, but that node or a nearer layer also
    /// contributes its rule set, so it stays active.
    Reasserted {
        /// The node whose suppression did not apply.
        suppressed_by: NodeId,
    },
}

/// Where one effective rule came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleProvenance {
    /// The rule.
    pub rule_id: RuleId,
    /// Its rule set.
    pub rule_set_id: RuleSetId,
    /// Every contribution of its rule set, from the outermost layer to the
    /// nearest. The first is where it is `inherited_from`.
    pub contributions: Vec<Contribution>,
    /// Whether it can decide.
    #[serde(flatten)]
    pub status: RuleStatus,
}

impl RuleProvenance {
    /// The outermost node that contributed the rule.
    #[must_use]
    pub fn inherited_from(&self) -> Option<NodeId> {
        self.contributions.first().map(|c| c.node)
    }
}

/// What became of one value a layer offered for a setting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum StepOutcome {
    /// It is the effective value.
    Applied,
    /// A nearer layer, the node's own settings or a lower slot set
    /// another.
    Overridden,
    /// A node above locked the setting.
    BlockedByLock {
        /// The node that locked it.
        locked_at: NodeId,
    },
}

/// One value a layer offered for a setting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingStep {
    /// Who offered it.
    #[serde(flatten)]
    pub from: Contribution,
    /// The value.
    pub value: serde_json::Value,
    /// What became of it.
    #[serde(flatten)]
    pub outcome: StepOutcome,
}

/// Where one effective setting came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingProvenance {
    /// The effective value.
    pub value: serde_json::Value,
    /// The node whose value applies, or `None` for the default.
    pub source: Option<NodeId>,
    /// The node that locked it, if any.
    pub locked_at: Option<NodeId>,
    /// Whether the merge changed the value after the layers offered it: a
    /// `lock_mode` floor raised a control level or a type mode, or a
    /// `mode_disconnected` weaker than the effective mode was dropped. The
    /// change is in [`ModeProvenance::adjustments`].
    pub raised_by_floor: bool,
    /// Every value offered, from the outermost layer to the nearest.
    pub steps: Vec<SettingStep>,
}

/// A change a mode floor made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModeAdjustment {
    /// The JSON Pointer of the value in the effective policy.
    pub path: String,
    /// The value before.
    pub from: serde_json::Value,
    /// The value after, or `null` if it was removed.
    pub to: serde_json::Value,
}

/// Where the effective mode came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModeProvenance {
    /// The effective base mode.
    pub mode: Mode,
    /// The node whose mode it is before any floor, or `None` for the
    /// default `audit`.
    pub source: Option<NodeId>,
    /// How modes were merged.
    pub merge: ModeMerge,
    /// The strictest `lock_mode` floor, and the node that set it.
    pub floor: Option<(Mode, NodeId)>,
    /// What the floor changed.
    pub adjustments: Vec<ModeAdjustment>,
}

/// Who chose the precedence model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecedenceSource {
    /// A node's `precedence`.
    Node(NodeId),
    /// The highest-ranked policy.
    Policy(PolicyId),
    /// Nothing chose: `deny_wins`.
    Default,
}

/// The effective policy of one device (or, for a dry run, of a device in
/// one node), with its provenance and a content hash.
#[derive(Clone, Debug)]
pub struct EffectivePolicy {
    node: NodeId,
    management: Management,
    policy: Option<ValidatedPolicy>,
    rules: BTreeMap<RuleId, RuleProvenance>,
    rule_sets: BTreeMap<RuleSetId, Vec<Contribution>>,
    settings: BTreeMap<String, SettingProvenance>,
    mode: Option<ModeProvenance>,
    precedence: Option<PrecedenceSource>,
    libraries: BTreeSet<Version>,
    content_hash: String,
}

impl EffectivePolicy {
    /// The node it was computed for.
    #[must_use]
    pub const fn node(&self) -> NodeId {
        self.node
    }

    /// Whether the device is managed.
    #[must_use]
    pub const fn management(&self) -> Management {
        self.management
    }

    /// The flattened, validated policy, ready for the evaluator. Its ID is
    /// the node's ID and its revision the snapshot's. `None` for an
    /// unmanaged device.
    #[must_use]
    pub const fn policy(&self) -> Option<&ValidatedPolicy> {
        self.policy.as_ref()
    }

    /// Where a rule came from, and whether it can decide.
    #[must_use]
    pub fn rule(&self, id: RuleId) -> Option<&RuleProvenance> {
        self.rules.get(&id)
    }

    /// Every rule, by ID.
    #[must_use]
    pub const fn rules(&self) -> &BTreeMap<RuleId, RuleProvenance> {
        &self.rules
    }

    /// Who contributed a rule set.
    #[must_use]
    pub fn rule_set(&self, id: RuleSetId) -> Option<&[Contribution]> {
        self.rule_sets.get(&id).map(Vec::as_slice)
    }

    /// Where a setting came from: a key of the policy `settings`, or
    /// `mode_options.mode_disconnected`, `mode_options.disconnected_after_secs`
    /// or `mode_options.mode_by_type.<type>`.
    #[must_use]
    pub fn setting(&self, key: &str) -> Option<&SettingProvenance> {
        self.settings.get(key)
    }

    /// Every setting.
    #[must_use]
    pub const fn settings(&self) -> &BTreeMap<String, SettingProvenance> {
        &self.settings
    }

    /// Where the mode came from. `None` for an unmanaged device.
    #[must_use]
    pub const fn mode(&self) -> Option<&ModeProvenance> {
        self.mode.as_ref()
    }

    /// Who chose the precedence model. `None` for an unmanaged device.
    #[must_use]
    pub const fn precedence(&self) -> Option<PrecedenceSource> {
        self.precedence
    }

    /// Every library version used: rule sets, and the fragments and sets
    /// that trees referred to. A bundle records these (#43).
    #[must_use]
    pub const fn libraries(&self) -> &BTreeSet<Version> {
        &self.libraries
    }

    /// The SHA-256 of [`canonical_json`](Self::canonical_json), in
    /// lowercase hex.
    #[must_use]
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }

    /// The hashed form: the effective policy as JSON with sorted keys and
    /// its revision set to 0, the resolved library versions and the
    /// management state. The revision is left out so that a snapshot change
    /// that does not change this device keeps the hash.
    #[must_use]
    pub fn canonical_json(&self) -> String {
        canonical(
            self.management,
            self.policy.as_ref().map(ValidatedPolicy::document),
            &self.libraries,
        )
    }
}

fn canonical(
    management: Management,
    doc: Option<&PolicyDocument>,
    libraries: &BTreeSet<Version>,
) -> String {
    let document = doc.map(|d| {
        let mut d = d.clone();
        d.policy.revision = 0;
        schema::sort_keys(serde_json::to_value(&d).unwrap_or_default())
    });
    let libraries: Vec<(String, u32)> = libraries
        .iter()
        .map(|(id, v)| (id.to_string(), *v))
        .collect();
    let value = schema::sort_keys(serde_json::json!({
        "document": document,
        "libraries": libraries,
        "management": management,
    }));
    value.to_string()
}

fn sha256_hex(text: &str) -> String {
    use core::fmt::Write as _;
    let digest = Sha256::digest(text.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// One layer: a node's configuration applied at one position.
#[derive(Clone, Copy)]
struct Layer<'h> {
    info: &'h NodeInfo,
    template_for: Option<NodeId>,
    band: u8,
}

impl Layer<'_> {
    fn contribution(&self, via: Via) -> Contribution {
        Contribution {
            node: self.info.node.id,
            template_for: self.template_for,
            via,
        }
    }
}

/// The band of each level, top down.
const BAND_GLOBAL: u8 = 0;
const BAND_TENANT: u8 = 1;
const BAND_DYNAMIC: u8 = 10;
const BAND_DEVICE: u8 = 11;

impl ValidatedHierarchy {
    /// The effective policy of `device`, given its dynamic groups.
    ///
    /// # Errors
    ///
    /// `unknown_node` if `device` is not a device, `invalid_membership` if
    /// a dynamic group is not one of its tenant's, and every finding of
    /// the computation (see [`effective_policy_as`](Self::effective_policy_as)).
    pub fn effective_policy(
        &self,
        device: NodeId,
        membership: &Membership,
    ) -> Result<EffectivePolicy, Vec<HierarchyError>> {
        match self.nodes.get(&device) {
            Some(info) if info.node.kind == NodeKind::Device => {
                self.effective_policy_as(device, membership)
            }
            _ => Err(vec![herr(
                HierarchyCode::UnknownNode,
                "",
                format!("node {device} is not a device"),
            )]),
        }
    }

    /// The effective policy a device would have at `node`: a device, or
    /// for a dry run a group (including `staging`), a tenant or the global
    /// node.
    ///
    /// # Errors
    ///
    /// Every finding: an unknown node or bad membership; a suppression of a
    /// rule that is not inherited or not suppressible; a precedence
    /// conflict; two different rule sets with one ID; and every error of
    /// validating the effective policy, under `/effective`.
    pub fn effective_policy_as(
        &self,
        node: NodeId,
        membership: &Membership,
    ) -> Result<EffectivePolicy, Vec<HierarchyError>> {
        let target = self.nodes.get(&node).ok_or_else(|| {
            vec![herr(
                HierarchyCode::UnknownNode,
                "",
                format!("node {node} does not exist"),
            )]
        })?;
        if matches!(
            target.node.kind,
            NodeKind::DynamicGroup | NodeKind::Template
        ) {
            return Err(vec![herr(
                HierarchyCode::UnknownNode,
                target.path(),
                format!(
                    "`{}` is a `{}`, which has no effective policy of its own",
                    target.node.name,
                    target.node.kind.as_str()
                ),
            )]);
        }
        let dynamic = self.dynamic_groups(target, membership)?;
        let unmanaged = target.node.builtin == Some(Builtin::Unmanaged)
            || (target.node.kind == NodeKind::Device
                && target
                    .node
                    .parent
                    .and_then(|p| self.nodes.get(&p))
                    .is_some_and(|p| p.node.builtin == Some(Builtin::Unmanaged)));
        if unmanaged {
            let libraries = BTreeSet::new();
            let text = canonical(Management::Unmanaged, None, &libraries);
            return Ok(EffectivePolicy {
                node,
                management: Management::Unmanaged,
                policy: None,
                rules: BTreeMap::new(),
                rule_sets: BTreeMap::new(),
                settings: BTreeMap::new(),
                mode: None,
                precedence: None,
                libraries,
                content_hash: sha256_hex(&text),
            });
        }
        let (level_order, merge) = self.options(target.tenant);
        let layers = self.layers(target, &dynamic, level_order);
        Builder::new(self, &layers, merge).build(node, true)
    }

    /// Checks the effective policy a device would have at `node`, as
    /// [`effective_policy_as`](Self::effective_policy_as) does, without
    /// hashing it. Validation runs this for every configured structural
    /// node.
    pub(crate) fn check_effective_at(&self, node: NodeId) -> Result<(), Vec<HierarchyError>> {
        let Some(target) = self.nodes.get(&node) else {
            return Ok(());
        };
        let (level_order, merge) = self.options(target.tenant);
        let layers = self.layers(target, &[], level_order);
        Builder::new(self, &layers, merge)
            .build(node, false)
            .map(|_| ())
    }

    /// The dynamic groups of a device at `target`, checked, sorted from the
    /// outermost (highest rank) to the nearest (lowest rank).
    fn dynamic_groups(
        &self,
        target: &NodeInfo,
        membership: &Membership,
    ) -> Result<Vec<&NodeInfo>, Vec<HierarchyError>> {
        let ids: BTreeSet<NodeId> = membership.dynamic_groups.iter().copied().collect();
        if ids.len() > MAX_DYNAMIC_GROUPS {
            return Err(vec![herr(
                HierarchyCode::TooMany,
                "/membership",
                format!(
                    "{} dynamic groups; at most {MAX_DYNAMIC_GROUPS} are allowed",
                    ids.len()
                ),
            )]);
        }
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for id in ids {
            match self.nodes.get(&id) {
                Some(g)
                    if g.node.kind == NodeKind::DynamicGroup
                        && target.tenant.is_some()
                        && g.tenant == target.tenant =>
                {
                    out.push(g);
                }
                _ => errors.push(herr(
                    HierarchyCode::InvalidMembership,
                    "/membership",
                    format!("node {id} is not a dynamic group of the device's tenant"),
                )),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        // The highest rank first, so the lowest rank is nearest; equal ranks
        // by ID, so the order never depends on the input.
        out.sort_by(|a, b| {
            (b.node.rank.unwrap_or(0), b.node.id).cmp(&(a.node.rank.unwrap_or(0), a.node.id))
        });
        Ok(out)
    }

    /// The layers of a device at `target`, from the outermost to the
    /// nearest, with each linked template just before its node.
    fn layers<'h>(
        &'h self,
        target: &'h NodeInfo,
        dynamic: &[&'h NodeInfo],
        order: LevelOrder,
    ) -> Vec<Layer<'h>> {
        let mut chain: Vec<&NodeInfo> = Vec::new();
        let mut at = Some(target);
        while let Some(info) = at {
            chain.push(info);
            at = info.node.parent.and_then(|p| self.nodes.get(&p));
        }
        chain.reverse();
        let device = (target.node.kind == NodeKind::Device)
            .then(|| chain.pop())
            .flatten();
        let mut nodes: Vec<(&NodeInfo, u8)> = Vec::new();
        let mut depth = 0u8;
        for info in chain {
            let band = match info.node.kind {
                NodeKind::Global => BAND_GLOBAL,
                NodeKind::Tenant => BAND_TENANT,
                _ => {
                    depth = depth.saturating_add(1);
                    BAND_TENANT.saturating_add(depth)
                }
            };
            nodes.push((info, band));
        }
        nodes.extend(dynamic.iter().map(|g| (*g, BAND_DYNAMIC)));
        if let Some(d) = device {
            nodes.push((d, BAND_DEVICE));
        }
        let mut layers = Vec::new();
        for (info, band) in nodes {
            let band = match order {
                LevelOrder::TopDown => band,
                LevelOrder::BottomUp => BAND_DEVICE.saturating_sub(band),
                LevelOrder::Flat => 0,
            };
            if let Some(t) = info.node.template.and_then(|t| self.nodes.get(&t)) {
                layers.push(Layer {
                    info: t,
                    template_for: Some(info.node.id),
                    band,
                });
            }
            layers.push(Layer {
                info,
                template_for: None,
                band,
            });
        }
        layers
    }
}

/// A rule set in the making.
struct SetEntry {
    set: RuleSet,
    /// The scopes it is assigned with (#38): the contributing policy's
    /// `scope`, then that policy's `rule_set_scopes` for the set. Empty for
    /// a rule set library a node assigns.
    scopes: Vec<crate::scope::Scope>,
    /// `(layer position, contribution)`, in layer order.
    contributions: Vec<(usize, Contribution)>,
    band: u8,
}

struct Builder<'a, 'h> {
    h: &'h ValidatedHierarchy,
    layers: &'a [Layer<'h>],
    merge: ModeMerge,
    errors: Vec<HierarchyError>,
    sets: BTreeMap<RuleSetId, SetEntry>,
    /// Library ID -> the version used and where, for version conflicts.
    library_versions: BTreeMap<LibraryId, (u32, String)>,
    libraries: BTreeSet<Version>,
}

impl<'a, 'h> Builder<'a, 'h> {
    fn new(h: &'h ValidatedHierarchy, layers: &'a [Layer<'h>], merge: ModeMerge) -> Self {
        Self {
            h,
            layers,
            merge,
            errors: Vec::new(),
            sets: BTreeMap::new(),
            library_versions: BTreeMap::new(),
            libraries: BTreeSet::new(),
        }
    }

    /// The policies of a layer, by slot.
    fn policies(&self, layer: &Layer<'h>) -> Vec<(u32, &'h PolicyDocument)> {
        let mut out: Vec<(u32, &PolicyDocument)> = layer
            .info
            .node
            .assignments
            .iter()
            .filter_map(|a| {
                self.h
                    .policies
                    .get(&a.policy)
                    .map(|p| (a.slot_order, &p.document))
            })
            .collect();
        out.sort_by_key(|(slot, _)| *slot);
        out
    }

    /// Builds the effective policy. With `hash` false (a validation check)
    /// the content hash is left empty.
    fn build(mut self, node: NodeId, hash: bool) -> Result<EffectivePolicy, Vec<HierarchyError>> {
        self.collect_rule_sets();
        let rules = self.suppressions();
        let precedence = self.precedence();
        let (mut settings, mut settings_prov) = self.settings();
        let (mut mode_options, mode_prov) = self.mode_options();
        let mut mode = self.mode();
        let location_profiles = self.location_profiles();
        self.scope_set_versions();
        if !self.errors.is_empty() {
            return Err(self.errors);
        }
        let Some((model, options, source)) = precedence else {
            return Err(self.errors);
        };
        // The floor.
        let mut adjustments = Vec::new();
        let mut sets: BTreeMap<RuleSetId, RuleSet> = BTreeMap::new();
        for (id, entry) in &self.sets {
            let mut set = entry.set.clone();
            set.band = entry.band;
            for rule in &mut set.rules {
                if let Some(p) = rules.get(&rule.id) {
                    if matches!(p.status, RuleStatus::Suppressed { .. }) {
                        rule.enabled = false;
                    }
                }
            }
            sets.insert(*id, set);
        }
        if let Some((floor, _)) = mode.floor {
            apply_floor(
                floor,
                &mut mode,
                &mut mode_options,
                &mut settings,
                &mut sets,
                &mut adjustments,
                &mut settings_prov,
            );
        }
        // Unset `mode_disconnected` means the effective mode itself, so a
        // merged one that is not at least as strict is dropped.
        if let Some(offline) = mode_options.mode_disconnected {
            if offline != mode.mode && strictness(offline) <= strictness(mode.mode) {
                adjustments.push(ModeAdjustment {
                    path: "/policy/mode_options/mode_disconnected".to_owned(),
                    from: serde_json::to_value(offline).unwrap_or_default(),
                    to: serde_json::Value::Null,
                });
                mode_options.mode_disconnected = None;
            }
        }
        mode.adjustments = adjustments;
        // The provenance of the mode options shows their final values.
        let mut mode_prov = mode_prov;
        for (key, p) in &mut mode_prov {
            let now = if let Some(t) = key.strip_prefix("mode_options.mode_by_type.") {
                t.parse::<ObjectType>()
                    .ok()
                    .and_then(|t| mode_options.mode_by_type.get(&t))
                    .map(|m| serde_json::to_value(m).unwrap_or_default())
            } else if key == "mode_options.mode_disconnected" {
                mode_options
                    .mode_disconnected
                    .map(|m| serde_json::to_value(m).unwrap_or_default())
            } else {
                mode_options.disconnected_after_secs.map(Into::into)
            }
            .unwrap_or(serde_json::Value::Null);
            if now != p.value {
                p.raised_by_floor = true;
                p.value = now;
            }
        }
        settings_prov.extend(mode_prov);

        let target = self.h.nodes.get(&node);
        let name = target.map_or_else(|| node.to_string(), |t| t.node.name.clone());
        // Each contributing policy's scopes now sit on its rule sets, so the
        // effective policy has no scope of its own (#38). Location profiles
        // are the union of the contributing policies'; two with one name
        // and different tests cannot both hold.
        let rule_set_scopes = self
            .sets
            .iter()
            .filter(|(_, e)| !e.scopes.is_empty())
            .map(|(id, e)| crate::scope::RuleSetScope {
                rule_set: *id,
                scopes: e.scopes.clone(),
            })
            .collect();
        let doc = PolicyDocument {
            schema_version: schema::CURRENT,
            policy: Policy {
                id: PolicyId(node.0),
                name,
                description: None,
                revision: self.h.revision,
                precedence_model: model,
                precedence_options: options,
                mode: mode.mode,
                mode_options,
                settings,
                unknown: self.unknown(),
                rule_sets: sets.keys().copied().collect(),
                scope: None,
                rule_set_scopes,
                location_profiles,
                metadata: Metadata::default(),
            },
            rule_sets: sets.into_values().collect(),
        };
        // Every rule is a copy of one in a validated policy or rule set
        // library, so its criteria are not compiled again.
        let validated = doc.validate_assembled().map_err(|findings| {
            findings
                .into_iter()
                .filter(|f| f.severity == Severity::Error)
                .map(|f| HierarchyError {
                    code: HierarchyCode::Policy(f.code),
                    path: format!("/effective{}", f.path),
                    message: f.message,
                })
                .collect::<Vec<_>>()
        })?;
        let content_hash = if hash {
            sha256_hex(&canonical(
                Management::Managed,
                Some(validated.document()),
                &self.libraries,
            ))
        } else {
            String::new()
        };
        let rule_sets = self
            .sets
            .iter()
            .map(|(id, e)| {
                (
                    *id,
                    e.contributions.iter().map(|(_, c)| c.clone()).collect(),
                )
            })
            .collect();
        Ok(EffectivePolicy {
            node,
            management: Management::Managed,
            policy: Some(validated),
            rules,
            rule_sets,
            settings: settings_prov,
            mode: Some(mode),
            precedence: Some(source),
            libraries: self.libraries,
            content_hash,
        })
    }

    /// One version of each library set the scopes use (#38), as of each
    /// rule set library and policy: two pins of one set would leave a
    /// device-set membership fact, which names the set only, ambiguous.
    fn scope_set_versions(&mut self) {
        let mut seen: BTreeMap<LibraryId, (crate::library::Pin, String)> = BTreeMap::new();
        let mut found = Vec::new();
        // The policies' scopes also limit their unknown settings (#39).
        for layer in self.layers {
            for (_, doc) in self.policies(layer) {
                let u = &doc.policy.unknown;
                let scopes = doc
                    .policy
                    .scope
                    .iter()
                    .chain(&u.scopes)
                    .chain(u.scope_groups.iter().flat_map(|g| &g.all_of));
                for scope in scopes {
                    for (_, r, _) in crate::scope::set_refs(scope) {
                        found.push((
                            r,
                            format!("/effective/policy/unknown/scope_groups ({})", doc.policy.id),
                        ));
                    }
                }
            }
        }
        for (id, e) in &self.sets {
            let scopes = e
                .scopes
                .iter()
                .chain(e.set.rules.iter().filter_map(|r| r.scope.as_ref()));
            for scope in scopes {
                for (_, r, _) in crate::scope::set_refs(scope) {
                    found.push((r, format!("/effective/rule_sets/{id}")));
                }
            }
        }
        for (r, at) in found {
            match seen.get(&r.id) {
                Some((pin, first)) if *pin != r.pin => self.errors.push(herr(
                    HierarchyCode::LibraryVersionConflict,
                    at,
                    format!(
                        "library set {} is used at version {} and at version {pin} ({first}); one device uses one version of each set",
                        r.id, r.pin
                    ),
                )),
                Some(_) => {}
                None => {
                    seen.insert(r.id, (r.pin, at));
                }
            }
        }
    }

    /// The location profiles of every contributing policy (#38), by name.
    /// Two with one name and different tests are a `conflicting_scope`.
    fn location_profiles(&mut self) -> Vec<crate::scope::LocationProfile> {
        let mut out: BTreeMap<String, (crate::scope::LocationProfile, String)> = BTreeMap::new();
        let layers = self.layers;
        for layer in layers {
            let base = layer.info.path();
            for (_, doc) in self.policies(layer) {
                for (i, p) in doc.policy.location_profiles.iter().enumerate() {
                    let key = crate::scope::text::group_name(&p.name);
                    let at = self.h.policies.get(&doc.policy.id).map_or_else(
                        || base.clone(),
                        |info| {
                            format!(
                                "/policies/{}/document/policy/location_profiles/{i}",
                                info.index
                            )
                        },
                    );
                    match out.get(&key) {
                        Some((q, first)) if q.all != p.all => {
                            let message = format!(
                                "location profile `{}` is defined differently by two policies ({first}); give one of them another name",
                                p.name
                            );
                            self.errors
                                .push(herr(HierarchyCode::ConflictingScope, at, message));
                        }
                        Some(_) => {}
                        None => {
                            out.insert(key, (p.clone(), at));
                        }
                    }
                }
            }
        }
        out.into_values().map(|(p, _)| p).collect()
    }

    /// Adds one rule set from layer `pos`.
    fn add_set(
        &mut self,
        pos: usize,
        set: &RuleSet,
        library: Option<Version>,
        scopes: Vec<crate::scope::Scope>,
        contribution: Contribution,
        at: &str,
    ) {
        let band = self.layers[pos].band;
        if let Some((id, version)) = library {
            match self.library_versions.get(&id) {
                Some((v, first)) if *v != version => {
                    self.errors.push(herr(
                        HierarchyCode::LibraryVersionConflict,
                        at,
                        format!(
                            "rule set library {id} would apply at version {version} and at version {v} ({first}); one device uses one version of each rule set"
                        ),
                    ));
                    return;
                }
                _ => {
                    self.library_versions.insert(id, (version, at.to_owned()));
                }
            }
        }
        match self.sets.get_mut(&set.id) {
            Some(entry) => {
                let mut a = entry.set.clone();
                let mut b = set.clone();
                a.band = 0;
                b.band = 0;
                if a == b && entry.scopes != scopes {
                    self.errors.push(herr(
                        HierarchyCode::ConflictingScope,
                        at,
                        format!(
                            "rule set {} (`{}`) is also contributed with a different scope; give it one scope, or contribute it once",
                            set.id, set.name
                        ),
                    ));
                    return;
                }
                if a != b {
                    self.errors.push(herr(
                        HierarchyCode::RuleSetConflict,
                        at,
                        format!(
                            "rule set {} (`{}`) is also contributed with different content; a rule set ID names one rule set",
                            set.id, set.name
                        ),
                    ));
                    return;
                }
                entry.band = entry.band.min(band);
                entry.contributions.push((pos, contribution));
            }
            None => {
                self.sets.insert(
                    set.id,
                    SetEntry {
                        set: set.clone(),
                        scopes,
                        contributions: vec![(pos, contribution)],
                        band,
                    },
                );
            }
        }
    }

    fn collect_rule_sets(&mut self) {
        let layers = self.layers;
        for (pos, layer) in layers.iter().enumerate() {
            let info = layer.info;
            let base = info.path();
            for (slot, doc) in self.policies(layer) {
                let by_id: BTreeMap<RuleSetId, &RuleSet> =
                    doc.rule_sets.iter().map(|s| (s.id, s)).collect();
                if let Some(p) = self.h.policies.get(&doc.policy.id) {
                    self.libraries.extend(p.used.iter().copied());
                }
                for id in &doc.policy.rule_sets {
                    if let Some(set) = by_id.get(id) {
                        let via = Via::Policy {
                            policy: doc.policy.id,
                            slot_order: slot,
                        };
                        // The policy's scope covers its rule sets, so it
                        // moves onto each of them (#38).
                        let scopes: Vec<crate::scope::Scope> = doc
                            .policy
                            .scope
                            .iter()
                            .cloned()
                            .chain(
                                doc.policy
                                    .rule_set_scopes
                                    .iter()
                                    .filter(|a| a.rule_set == *id)
                                    .flat_map(|a| a.scopes.iter().cloned()),
                            )
                            .collect();
                        self.add_set(
                            pos,
                            set,
                            None,
                            scopes,
                            layer.contribution(via),
                            &format!("{base}/assignments"),
                        );
                    }
                }
            }
            for (i, r) in info.node.rule_sets.iter().enumerate() {
                let Ok(lib) = self.h.catalogue.resolve(r, info.visibility()) else {
                    continue;
                };
                let version = (lib.id, lib.version);
                let Some(entry) = self.h.rule_sets.get(&version) else {
                    continue;
                };
                self.libraries.insert(version);
                self.libraries.extend(entry.used.iter().copied());
                let via = Via::Library {
                    library: lib.id,
                    version: lib.version,
                };
                let set = entry.rule_set.clone();
                self.add_set(
                    pos,
                    &set,
                    Some(version),
                    Vec::new(),
                    layer.contribution(via),
                    &format!("{base}/rule_sets/{i}"),
                );
            }
            for (i, category) in info.node.categories.iter().enumerate() {
                for lib in self.h.catalogue.in_category(category, info.visibility()) {
                    let version = (lib.id, lib.version);
                    let Some(entry) = self.h.rule_sets.get(&version) else {
                        continue;
                    };
                    if !matches!(lib.content, LibraryContent::RuleSet { .. }) {
                        continue;
                    }
                    self.libraries.insert(version);
                    self.libraries.extend(entry.used.iter().copied());
                    let via = Via::Category {
                        category: category.clone(),
                        library: lib.id,
                        version: lib.version,
                    };
                    let set = entry.rule_set.clone();
                    self.add_set(
                        pos,
                        &set,
                        Some(version),
                        Vec::new(),
                        layer.contribution(via),
                        &format!("{base}/categories/{i}"),
                    );
                }
            }
        }
    }

    /// Every rule's provenance, after the suppressions.
    fn suppressions(&mut self) -> BTreeMap<RuleId, RuleProvenance> {
        let mut out = BTreeMap::new();
        for (set_id, entry) in &self.sets {
            for rule in &entry.set.rules {
                out.entry(rule.id).or_insert_with(|| RuleProvenance {
                    rule_id: rule.id,
                    rule_set_id: *set_id,
                    contributions: entry.contributions.iter().map(|(_, c)| c.clone()).collect(),
                    status: if rule.enabled {
                        RuleStatus::Active
                    } else {
                        RuleStatus::Disabled
                    },
                });
            }
        }
        // The nearest suppression of each rule decides.
        let mut nearest: BTreeMap<RuleId, (usize, NodeId)> = BTreeMap::new();
        for (pos, layer) in self.layers.iter().enumerate() {
            let info = layer.info;
            for (i, id) in info.node.suppress_inherited.iter().enumerate() {
                let path = format!("{}/suppress_inherited/{i}", info.path());
                let Some(p) = out.get(id) else {
                    self.errors.push(herr(
                        HierarchyCode::SuppressUnknownRule,
                        path,
                        format!(
                            "rule {id} is not in the effective policy of a device below `{}`",
                            info.node.name
                        ),
                    ));
                    continue;
                };
                let Some(entry) = self.sets.get(&p.rule_set_id) else {
                    continue;
                };
                if !entry.contributions.iter().any(|(at, _)| *at < pos) {
                    self.errors.push(herr(
                        HierarchyCode::SuppressUnknownRule,
                        path,
                        format!(
                            "rule {id} is not inherited by `{}`: its rule set `{}` is contributed only here or below; remove it instead",
                            info.node.name, entry.set.name
                        ),
                    ));
                    continue;
                }
                if !suppressible(&entry.set) {
                    let why = if entry.set.mandatory {
                        "it is in a mandatory rule set, which blocks under every policy below it (ADR 0004)".to_owned()
                    } else {
                        format!(
                            "its rule set `{}` does not allow it (`allow_child_suppress`, which is false by default for a `{}`)",
                            entry.set.name,
                            kind_name(entry.set.kind)
                        )
                    };
                    self.errors.push(herr(
                        HierarchyCode::SuppressNotAllowed,
                        path,
                        format!("rule {id} cannot be suppressed: {why}; shadow it with a rule that wins under the precedence model instead"),
                    ));
                    continue;
                }
                nearest.insert(*id, (pos, info.node.id));
            }
        }
        for (id, (pos, by)) in nearest {
            let Some(p) = out.get_mut(&id) else { continue };
            let Some(entry) = self.sets.get(&p.rule_set_id) else {
                continue;
            };
            // A rule its rule set disables stays disabled: a suppression
            // can neither enable it nor make it look active.
            if p.status == RuleStatus::Disabled {
                continue;
            }
            let inherited_only = entry.contributions.iter().all(|(at, _)| *at < pos);
            p.status = if inherited_only {
                RuleStatus::Suppressed { by }
            } else {
                RuleStatus::Reasserted { suppressed_by: by }
            };
        }
        out
    }

    /// The model, its options and who chose them. `None` after an error.
    fn precedence(&mut self) -> Option<(PrecedenceModel, PrecedenceOptions, PrecedenceSource)> {
        let chosen = self
            .layers
            .iter()
            .rev()
            .find_map(|l| l.info.node.precedence.map(|p| (p, l.info.node.id)));
        let mut ranked: Vec<(usize, u32, &PolicyDocument, &NodeInfo)> = Vec::new();
        for (pos, layer) in self.layers.iter().enumerate() {
            for (slot, doc) in self.policies(layer) {
                ranked.push((pos, slot, doc, layer.info));
            }
        }
        let (model, options, source) = match chosen {
            Some((p, node)) => (p.model, p.options, PrecedenceSource::Node(node)),
            None => match ranked
                .iter()
                .min_by_key(|(pos, slot, doc, _)| (core::cmp::Reverse(*pos), *slot, doc.policy.id))
            {
                Some((_, _, doc, _)) => (
                    doc.policy.precedence_model,
                    doc.policy.precedence_options,
                    PrecedenceSource::Policy(doc.policy.id),
                ),
                None => (
                    PrecedenceModel::DenyWins,
                    PrecedenceOptions::default(),
                    PrecedenceSource::Default,
                ),
            },
        };
        let mut ok = true;
        let mut seen = BTreeSet::new();
        for (_, _, doc, info) in &ranked {
            let differs =
                doc.policy.precedence_model != model || doc.policy.precedence_options != options;
            if differs && seen.insert(doc.policy.id) {
                ok = false;
                let what = if doc.policy.precedence_model == model {
                    format!("other `{}` options", name_of(&model))
                } else {
                    format!("`{}`", name_of(&doc.policy.precedence_model))
                };
                self.errors.push(herr(
                    HierarchyCode::PrecedenceConflict,
                    format!("{}/assignments", info.path()),
                    format!(
                        "policy `{}` uses {what}, but the effective policy uses `{}` ({}); one effective policy uses one model with one set of options",
                        doc.policy.name,
                        name_of(&model),
                        match source {
                            PrecedenceSource::Node(n) => format!("chosen by node {n}"),
                            PrecedenceSource::Policy(p) => format!("the model of the highest-ranked policy, {p}"),
                            PrecedenceSource::Default => "the default".to_owned(),
                        }
                    ),
                ));
            }
        }
        ok.then_some((model, options, source))
    }

    /// The unknown-application policy (#39): the strictest combination of
    /// every assigned policy's ([`UnknownPolicy::stricter`](crate::model::UnknownPolicy::stricter)),
    /// so no layer can make unknown objects run more freely than another
    /// layer allows. Policies are folded from the outermost layer in, and
    /// within a layer from the highest `slot_order` down, so where a value
    /// cannot be compared the nearest layer's lowest slot gives it, as for
    /// every other merge here. With no policy, the default (block).
    ///
    /// A policy's `scope` and its `unknown.scopes` limit where its unknown
    /// settings apply (#38): `scope` and any of `scopes`. The effective
    /// policy has no scope of its own, so that limit moves into
    /// `unknown.scope_groups`, one all-of group (`scope`, one entry of
    /// `scopes`) per entry ([`UnknownPolicy::scope_groups_of`](crate::model::UnknownPolicy::scope_groups_of)).
    /// The merged settings apply to a subject in at least one contributing
    /// policy's limit (everyone if one has none), exactly where that
    /// policy's own evaluation would apply its settings, and the built-in
    /// implicit deny decides for any other. Where several limits overlap,
    /// the merged settings are at least as strict as each policy's.
    fn unknown(&self) -> crate::model::UnknownPolicy {
        let mut acc: Option<crate::model::UnknownPolicy> = None;
        for layer in self.layers {
            for (_, d) in self.policies(layer).into_iter().rev() {
                let mut u = d.policy.unknown.clone();
                u.scope_groups = u
                    .scope_groups_of(d.policy.scope.as_ref(), stage_six_scope)
                    .unwrap_or_default();
                u.scopes = Vec::new();
                acc = Some(match acc {
                    None => u,
                    Some(outer) => u.stricter(&outer),
                });
            }
        }
        acc.unwrap_or_default()
    }

    /// The merged settings and their provenance.
    fn settings(&mut self) -> (PolicySettings, BTreeMap<String, SettingProvenance>) {
        let default = super::validate::default_settings();
        let keys = super::validate::setting_keys();
        let mut current: BTreeMap<String, Option<serde_json::Value>> = keys
            .iter()
            .map(|k| (k.clone(), default.get(k).cloned()))
            .collect();
        let mut prov: BTreeMap<String, SettingProvenance> = keys
            .iter()
            .map(|k| {
                (
                    k.clone(),
                    SettingProvenance {
                        value: default.get(k).cloned().unwrap_or(serde_json::Value::Null),
                        source: None,
                        locked_at: None,
                        raised_by_floor: false,
                        steps: Vec::new(),
                    },
                )
            })
            .collect();
        let mut locks: BTreeMap<String, NodeId> = BTreeMap::new();
        for layer in self.layers {
            let policies: Vec<(u32, serde_json::Value, PolicyId)> = self
                .policies(layer)
                .into_iter()
                .map(|(slot, d)| {
                    (
                        slot,
                        serde_json::to_value(&d.policy.settings).unwrap_or_default(),
                        d.policy.id,
                    )
                })
                .collect();
            for key in keys {
                let mut offers: Vec<(Contribution, serde_json::Value)> = Vec::new();
                if let Some(v) = layer.info.node.settings.get(key) {
                    offers.push((layer.contribution(Via::Node), v.clone()));
                }
                for (slot, value, policy) in &policies {
                    // A field left at its default is not written, so a
                    // missing key is the default too.
                    let v = value.get(key).or_else(|| default.get(key));
                    if v != default.get(key) {
                        offers.push((
                            layer.contribution(Via::Policy {
                                policy: *policy,
                                slot_order: *slot,
                            }),
                            v.cloned().unwrap_or(serde_json::Value::Null),
                        ));
                    }
                }
                let Some(p) = prov.get_mut(key) else { continue };
                for (i, (from, value)) in offers.into_iter().enumerate() {
                    // A lock above blocks every offer of the layer; without
                    // one, the first offer applies and the rest lose to it.
                    let outcome = if let Some(&locked_at) = locks.get(key) {
                        StepOutcome::BlockedByLock { locked_at }
                    } else if i > 0 {
                        StepOutcome::Overridden
                    } else {
                        current.insert(key.clone(), Some(value.clone()));
                        StepOutcome::Applied
                    };
                    p.steps.push(SettingStep {
                        from,
                        value,
                        outcome,
                    });
                }
            }
            for key in &layer.info.node.locked_settings {
                locks.entry(key.clone()).or_insert(layer.info.node.id);
            }
        }
        for (key, p) in &mut prov {
            let last = p
                .steps
                .iter()
                .rposition(|s| s.outcome == StepOutcome::Applied);
            for (i, step) in p.steps.iter_mut().enumerate() {
                if step.outcome == StepOutcome::Applied && Some(i) != last {
                    step.outcome = StepOutcome::Overridden;
                }
            }
            p.source = last.map(|i| p.steps[i].from.node);
            p.locked_at = locks.get(key).copied();
            p.value = current
                .get(key)
                .cloned()
                .flatten()
                .unwrap_or(serde_json::Value::Null);
        }
        let map: serde_json::Map<String, serde_json::Value> = current
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v)))
            .collect();
        let settings =
            match serde_json::from_value::<PolicySettings>(serde_json::Value::Object(map)) {
                Ok(s) => s,
                Err(e) => {
                    self.errors.push(herr(
                        HierarchyCode::InvalidSetting,
                        "/effective/policy/settings",
                        format!("the merged settings are not valid: {e}"),
                    ));
                    PolicySettings::default()
                }
            };
        (settings, prov)
    }

    /// The merged mode options, nearest layer and lowest slot first.
    ///
    /// A key in a node's `locked_settings` (`mode_options.mode_disconnected`,
    /// `mode_options.disconnected_after_secs` or `mode_options.mode_by_type`,
    /// which locks every type) keeps the value it has after that node's
    /// layer; later offers are `blocked_by_lock`.
    fn mode_options(&self) -> (ModeOptions, BTreeMap<String, SettingProvenance>) {
        let mut out = ModeOptions::default();
        let mut prov: BTreeMap<String, SettingProvenance> = BTreeMap::new();
        let mut locks: BTreeMap<String, NodeId> = BTreeMap::new();
        let lock_of = |locks: &BTreeMap<String, NodeId>, key: &str| {
            locks.get(key).copied().or_else(|| {
                key.starts_with("mode_options.mode_by_type.")
                    .then(|| locks.get("mode_options.mode_by_type").copied())
                    .flatten()
            })
        };
        let mut offer = |locks: &BTreeMap<String, NodeId>,
                         key: String,
                         from: Contribution,
                         value: serde_json::Value| {
            let locked_at = lock_of(locks, &key);
            let p = prov.entry(key).or_insert_with(|| SettingProvenance {
                value: serde_json::Value::Null,
                source: None,
                locked_at: None,
                raised_by_floor: false,
                steps: Vec::new(),
            });
            p.locked_at = p.locked_at.or(locked_at);
            p.steps.push(SettingStep {
                from,
                value,
                outcome: match locked_at {
                    Some(locked_at) => StepOutcome::BlockedByLock { locked_at },
                    None => StepOutcome::Overridden,
                },
            });
        };
        for layer in self.layers {
            for (slot, doc) in self.policies(layer) {
                let from = layer.contribution(Via::Policy {
                    policy: doc.policy.id,
                    slot_order: slot,
                });
                let o = &doc.policy.mode_options;
                for (t, m) in &o.mode_by_type {
                    offer(
                        &locks,
                        format!("mode_options.mode_by_type.{t}"),
                        from.clone(),
                        serde_json::to_value(m).unwrap_or_default(),
                    );
                }
                if let Some(m) = o.mode_disconnected {
                    offer(
                        &locks,
                        "mode_options.mode_disconnected".to_owned(),
                        from.clone(),
                        serde_json::to_value(m).unwrap_or_default(),
                    );
                }
                if let Some(s) = o.disconnected_after_secs {
                    offer(
                        &locks,
                        "mode_options.disconnected_after_secs".to_owned(),
                        from.clone(),
                        s.into(),
                    );
                }
            }
            for key in &layer.info.node.locked_settings {
                if key.starts_with("mode_options.") {
                    locks.entry(key.clone()).or_insert(layer.info.node.id);
                }
            }
        }
        // A locked key is reported even if no layer offered it (it is then
        // locked at unset); a lock on `mode_by_type` covers every type
        // offered anywhere.
        for key in locks.keys() {
            if key != "mode_options.mode_by_type" {
                prov.entry(key.clone())
                    .or_insert_with(|| SettingProvenance {
                        value: serde_json::Value::Null,
                        source: None,
                        locked_at: None,
                        raised_by_floor: false,
                        steps: Vec::new(),
                    });
            }
        }
        // Within a layer the lowest slot wins, across layers the nearest:
        // the winner is the first offer of the last layer that offered and
        // was not blocked by a lock.
        for (key, p) in &mut prov {
            p.locked_at = lock_of(&locks, key);
            let open = |s: &SettingStep| !matches!(s.outcome, StepOutcome::BlockedByLock { .. });
            let Some(last_node) = p
                .steps
                .iter()
                .rev()
                .find(|s| open(s))
                .map(|s| (s.from.node, s.from.template_for))
            else {
                continue;
            };
            let Some(win) = p
                .steps
                .iter()
                .position(|s| open(s) && (s.from.node, s.from.template_for) == last_node)
            else {
                continue;
            };
            p.steps[win].outcome = StepOutcome::Applied;
            p.source = Some(p.steps[win].from.node);
            p.value = p.steps[win].value.clone();
            let value = p.value.clone();
            if let Some(t) = key.strip_prefix("mode_options.mode_by_type.") {
                if let (Ok(t), Ok(m)) = (
                    t.parse::<ObjectType>(),
                    serde_json::from_value::<Mode>(value),
                ) {
                    out.mode_by_type.insert(t, m);
                }
            } else if key == "mode_options.mode_disconnected" {
                out.mode_disconnected = serde_json::from_value(value).ok();
            } else {
                out.disconnected_after_secs = serde_json::from_value(value).ok();
            }
        }
        (out, prov)
    }

    /// Each layer's mode, merged, and the strictest floor.
    fn mode(&self) -> ModeProvenance {
        let mut current: Option<(Mode, NodeId)> = None;
        let mut floor: Option<(Mode, NodeId)> = None;
        for layer in self.layers {
            let info = layer.info;
            let own = info.node.mode.or_else(|| {
                let modes: Vec<Mode> = self
                    .policies(layer)
                    .into_iter()
                    .map(|(_, d)| d.policy.mode)
                    .collect();
                match self.merge {
                    ModeMerge::Closest => modes.first().copied(),
                    // The first of the strictest, by slot.
                    ModeMerge::Strictest => modes
                        .iter()
                        .copied()
                        .reduce(|a, b| if strictness(b) > strictness(a) { b } else { a }),
                }
                .or_else(|| (info.node.builtin == Some(Builtin::Unassigned)).then_some(Mode::Audit))
            });
            if let Some(m) = own {
                current = match (self.merge, current) {
                    (ModeMerge::Strictest, Some((c, n))) if strictness(c) >= strictness(m) => {
                        Some((c, n))
                    }
                    _ => Some((m, info.node.id)),
                };
            }
            if info.node.lock_mode {
                let at = current.map_or(Mode::Audit, |(m, _)| m);
                if floor.is_none_or(|(f, _)| strictness(at) > strictness(f)) {
                    floor = Some((at, info.node.id));
                }
            }
        }
        ModeProvenance {
            mode: current.map_or(Mode::Audit, |(m, _)| m),
            source: current.map(|(_, n)| n),
            merge: self.merge,
            floor,
            adjustments: Vec::new(),
        }
    }
}

/// A policy's `scope` as it limits stage 6 (#39): without the options that
/// only act on a deciding rule (an instance limit, what happens when a
/// window closes), which stage 6 has no use for.
fn stage_six_scope(mut s: crate::scope::Scope) -> crate::scope::Scope {
    s.max_instances_per_session = 0;
    if let Some(schedule) = &mut s.schedule {
        schedule.on_window_close = crate::scope::OnWindowClose::None;
        schedule.grace_secs = None;
    }
    s
}

/// Raises everything below `floor` to it. See the module documentation.
fn apply_floor(
    floor: Mode,
    mode: &mut ModeProvenance,
    options: &mut ModeOptions,
    settings: &mut PolicySettings,
    sets: &mut BTreeMap<RuleSetId, RuleSet>,
    adjustments: &mut Vec<ModeAdjustment>,
    settings_prov: &mut BTreeMap<String, SettingProvenance>,
) {
    let json = |v: &dyn erased::Ser| v.to_json();
    let f = strictness(floor);
    if strictness(mode.mode) < f {
        adjustments.push(ModeAdjustment {
            path: "/policy/mode".to_owned(),
            from: json(&mode.mode),
            to: json(&floor),
        });
        mode.mode = floor;
    }
    for (t, m) in &mut options.mode_by_type {
        if strictness(*m) < f {
            adjustments.push(ModeAdjustment {
                path: format!(
                    "/policy/mode_options/mode_by_type/{}",
                    pointer_escape(&t.to_string())
                ),
                from: json(m),
                to: json(&floor),
            });
            *m = floor;
        }
    }
    // Control levels cap the mode: `audit` at audit, `off` at monitor.
    let needed = if f >= strictness(Mode::Enforce) {
        Some(ControlLevel::Enforce)
    } else if f >= strictness(Mode::Audit) {
        Some(ControlLevel::Audit)
    } else {
        None
    };
    if let Some(needed) = needed {
        let rank = |c: ControlLevel| match c {
            ControlLevel::Off => 0,
            ControlLevel::Audit => 1,
            ControlLevel::Enforce => 2,
        };
        let mut raise = |key: &str, path: String, level: &mut ControlLevel| {
            if rank(*level) < rank(needed) {
                adjustments.push(ModeAdjustment {
                    path,
                    from: json(level),
                    to: json(&needed),
                });
                *level = needed;
                if let Some(p) = settings_prov.get_mut(key) {
                    p.raised_by_floor = true;
                }
            }
        };
        raise(
            "script_control",
            "/policy/settings/script_control".to_owned(),
            &mut settings.script_control,
        );
        raise(
            "dll_control",
            "/policy/settings/dll_control".to_owned(),
            &mut settings.dll_control,
        );
        raise(
            "driver_control",
            "/policy/settings/driver_control".to_owned(),
            &mut settings.driver_control,
        );
        for (kind, level) in &mut settings.script_control_by_kind {
            raise(
                "script_control_by_kind",
                format!("/policy/settings/script_control_by_kind/{}", kind.as_str()),
                level,
            );
        }
        for key in [
            "script_control",
            "dll_control",
            "driver_control",
            "script_control_by_kind",
        ] {
            if let (Some(p), Ok(Some(v))) = (
                settings_prov.get_mut(key),
                serde_json::to_value(&*settings).map(|s| s.get(key).cloned()),
            ) {
                p.value = v;
            }
        }
    }
    for (i, set) in sets.values_mut().enumerate() {
        if let Some(m) = set.mode_override {
            if strictness(m) < f {
                adjustments.push(ModeAdjustment {
                    path: format!("/rule_sets/{i}/mode_override"),
                    from: json(&m),
                    to: json(&floor),
                });
                set.mode_override = Some(floor);
            }
        }
        if floor == Mode::Enforce {
            for (j, rule) in set.rules.iter_mut().enumerate() {
                if rule.enforcement_override == EnforcementOverride::NeverEnforce
                    && matches!(rule.action, Action::Deny(_))
                {
                    adjustments.push(ModeAdjustment {
                        path: format!("/rule_sets/{i}/rules/{j}/enforcement_override"),
                        from: json(&rule.enforcement_override),
                        to: json(&EnforcementOverride::Inherit),
                    });
                    rule.enforcement_override = EnforcementOverride::Inherit;
                }
            }
        }
    }
}

/// Serialising a value for an adjustment record, without generics in the
/// closure.
mod erased {
    pub(super) trait Ser {
        fn to_json(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Ser for T {
        fn to_json(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap_or_default()
        }
    }
}

/// Whether a rule set's rules may be suppressed below where it is
/// assigned: never for a mandatory rule set; otherwise
/// `allow_child_suppress`, which defaults to `true` for allowlists and
/// baselines and `false` for every other kind.
#[must_use]
pub fn suppressible(set: &RuleSet) -> bool {
    if set.mandatory {
        return false;
    }
    set.allow_child_suppress.unwrap_or(matches!(
        set.kind,
        RuleSetKind::Allowlist | RuleSetKind::Baseline
    ))
}

fn kind_name(kind: RuleSetKind) -> String {
    name_of(&kind)
}

fn name_of<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".to_owned(),
    }
}
