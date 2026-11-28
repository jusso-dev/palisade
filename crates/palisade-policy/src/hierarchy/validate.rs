//! Validation of a hierarchy snapshot (#37).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use super::limits::{
    MAX_ASSIGNMENTS_PER_NODE, MAX_GROUP_DEPTH, MAX_NODES, MAX_POLICIES, MAX_REFS_PER_NODE,
    MAX_SUPPRESSIONS_PER_NODE, MAX_UNKNOWN_SCOPE_VALUES,
};
use super::placement::{self, PlacementRule};
use super::{
    Builtin, HierarchyCode, HierarchyDocument, HierarchyError, LevelOrder, ModeMerge, Node, NodeId,
    NodeKind, herr,
};
use crate::library::{
    Catalogue, Library, LibraryCode, LibraryContent, LibraryError, LibraryId, LibraryRef, Realm,
    Version, Visibility, name_problem, refs_in,
};
use crate::model::{Mode, PolicyDocument, PolicyId, PolicySettings, RuleSet};
use crate::schema;
use crate::validate::ErrorCode;

/// A node, with what validation worked out about it.
#[derive(Clone, Debug)]
pub(crate) struct NodeInfo {
    pub(crate) node: Node,
    pub(crate) index: usize,
    /// The tenant it is in, or `None` for the global node and global
    /// templates.
    pub(crate) tenant: Option<NodeId>,
}

impl NodeInfo {
    pub(crate) const fn visibility(&self) -> Visibility {
        match self.tenant {
            Some(t) => Visibility::Tenant(t),
            None => Visibility::Global,
        }
    }

    pub(crate) fn path(&self) -> String {
        format!("/nodes/{}", self.index)
    }
}

/// A policy, with its references replaced and validated.
#[derive(Clone, Debug)]
pub(crate) struct PolicyInfo {
    pub(crate) index: usize,
    pub(crate) realm: Realm,
    /// The document, with every `ref` replaced, as validation normalised it.
    pub(crate) document: PolicyDocument,
    /// The library versions its trees use.
    pub(crate) used: BTreeSet<Version>,
    /// The libraries its trees refer to directly.
    pub(crate) refs: BTreeSet<LibraryId>,
}

/// A rule set library version, with its references replaced and validated.
#[derive(Clone, Debug)]
pub(crate) struct RuleSetInfo {
    pub(crate) rule_set: RuleSet,
    pub(crate) used: BTreeSet<Version>,
}

/// A hierarchy snapshot that passed validation. It can only be built by
/// [`HierarchyDocument::validate`].
#[derive(Clone, Debug)]
pub struct ValidatedHierarchy {
    pub(crate) revision: u64,
    pub(crate) nodes: BTreeMap<NodeId, NodeInfo>,
    /// The global node.
    pub(crate) global: Option<NodeId>,
    /// Each tenant's `unassigned` group.
    pub(crate) unassigned: BTreeMap<NodeId, NodeId>,
    pub(crate) policies: BTreeMap<PolicyId, PolicyInfo>,
    pub(crate) catalogue: Catalogue,
    pub(crate) rule_sets: BTreeMap<Version, RuleSetInfo>,
    pub(crate) library_index: BTreeMap<Version, usize>,
    /// Each tenant's placement rules, in evaluation order.
    pub(crate) placement: BTreeMap<NodeId, Vec<PlacementRule>>,
}

/// The top-level keys of the policy settings, from its schema.
pub(crate) fn setting_keys() -> &'static BTreeSet<String> {
    static KEYS: OnceLock<BTreeSet<String>> = OnceLock::new();
    KEYS.get_or_init(|| {
        let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
        let schema = generator.into_root_schema_for::<PolicySettings>();
        schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default()
    })
}

/// The keys besides `settings` that `locked_settings` may name.
pub(crate) const MODE_OPTION_LOCKS: [&str; 3] = [
    "mode_options.mode_disconnected",
    "mode_options.disconnected_after_secs",
    "mode_options.mode_by_type",
];

/// The default value of every setting, including those the model leaves
/// out when they are empty (`[]` or `{}`), so provenance never reports
/// `null` for a setting that has a value.
pub(crate) fn default_settings() -> &'static serde_json::Value {
    static DEFAULT: OnceLock<serde_json::Value> = OnceLock::new();
    DEFAULT.get_or_init(|| {
        let mut value = serde_json::to_value(PolicySettings::default()).unwrap_or_default();
        let generator = schemars::generate::SchemaSettings::draft2020_12().into_generator();
        let schema = generator.into_root_schema_for::<PolicySettings>();
        if let (Some(map), Some(props)) = (
            value.as_object_mut(),
            schema
                .get("properties")
                .and_then(serde_json::Value::as_object),
        ) {
            for (key, prop) in props {
                if map.contains_key(key) {
                    continue;
                }
                let empty = match prop.get("type").and_then(serde_json::Value::as_str) {
                    Some("array") => serde_json::json!([]),
                    Some("object") => serde_json::json!({}),
                    _ => continue,
                };
                map.insert(key.clone(), empty);
            }
        }
        value
    })
}

/// Why one setting's value is not valid, if it is not: it must read as
/// that key of [`PolicySettings`].
pub(crate) fn setting_problem(key: &str, value: &serde_json::Value) -> Option<String> {
    if !setting_keys().contains(key) {
        return Some(format!("`{key}` is not a policy setting"));
    }
    let mut map = serde_json::Map::new();
    map.insert(key.to_owned(), value.clone());
    serde_json::from_value::<PolicySettings>(serde_json::Value::Object(map))
        .err()
        .map(|e| format!("not a valid value for `{key}`: {e}"))
}

fn lib_errors(
    prefix: &str,
    errors: Vec<LibraryError>,
) -> impl Iterator<Item = HierarchyError> + '_ {
    errors.into_iter().map(move |e| HierarchyError {
        code: HierarchyCode::Library(e.code),
        path: format!("{prefix}{}", e.path),
        message: e.message,
    })
}

impl HierarchyDocument {
    /// Checks the snapshot: the shape of the tree, every reference between
    /// nodes, policies and libraries, every library and policy (with its
    /// references replaced), the placement rules, and the effective policy
    /// of every global, tenant and group node. Devices are checked when
    /// their effective policy is computed, because it depends on their
    /// dynamic groups.
    ///
    /// # Errors
    ///
    /// Every finding, in a stable order.
    pub fn validate(self) -> Result<ValidatedHierarchy, Vec<HierarchyError>> {
        let mut errors = Vec::new();
        if !self.schema_version.is_readable_by(schema::CURRENT) {
            errors.push(herr(
                HierarchyCode::UnsupportedSchemaVersion,
                "/schema_version",
                format!(
                    "schema version {} is not readable by a {} reader",
                    self.schema_version,
                    schema::CURRENT
                ),
            ));
        }
        for (key, len, max) in [
            ("/nodes", self.nodes.len(), MAX_NODES),
            ("/policies", self.policies.len(), MAX_POLICIES),
        ] {
            if len > max {
                errors.push(herr(
                    HierarchyCode::TooMany,
                    key,
                    format!("{len} entries; at most {max} are allowed"),
                ));
                return Err(errors);
            }
        }

        let library_index = library_positions(&self.libraries);
        let catalogue = match Catalogue::new(self.libraries.clone()) {
            Ok(c) => Some(c),
            Err(e) => {
                errors.extend(lib_errors("", e));
                None
            }
        };

        let nodes = check_nodes(&self.nodes, &mut errors);
        let tenants: BTreeSet<NodeId> = nodes
            .values()
            .filter(|n| n.node.kind == NodeKind::Tenant)
            .map(|n| n.node.id)
            .collect();
        for (i, lib) in self.libraries.iter().enumerate() {
            if let Realm::Tenant(t) = lib.realm
                && !tenants.contains(&t)
            {
                errors.push(herr(
                    HierarchyCode::UnknownNode,
                    format!("/libraries/{i}/realm"),
                    format!("tenant {t} does not exist"),
                ));
            }
        }

        let (policies, rule_sets) = match &catalogue {
            Some(c) => (
                check_policies(&self.policies, &tenants, c, &mut errors),
                check_rule_set_libraries(&self.libraries, c, &mut errors),
            ),
            None => (BTreeMap::new(), BTreeMap::new()),
        };
        if let Some(c) = &catalogue {
            for info in nodes.values() {
                check_node_refs(info, &policies, c, &mut errors);
            }
        }
        let placement = placement::check(&self.placement, &nodes, &mut errors);

        errors.extend(unknown_scope_bounds(&nodes, &policies));
        if !errors.is_empty() {
            return Err(errors);
        }
        let global = nodes
            .values()
            .find(|n| n.node.kind == NodeKind::Global)
            .map(|n| n.node.id);
        let unassigned = nodes
            .values()
            .filter(|n| n.node.builtin == Some(Builtin::Unassigned))
            .filter_map(|n| n.tenant.map(|t| (t, n.node.id)))
            .collect();
        let validated = ValidatedHierarchy {
            revision: self.revision,
            global,
            unassigned,
            nodes,
            policies,
            catalogue: catalogue.unwrap_or_default(),
            rule_sets,
            library_index,
            placement,
        };
        // The effective policy of every configured structural node: catches
        // suppressions of rules that are not inherited, precedence
        // conflicts and effective documents that do not validate before any
        // device is computed. A group that configures nothing has the
        // findings of its parent, so it is skipped. Each check costs what
        // computing one device's policy costs, with no regular expression
        // compiled again and no hash, so validation is bounded by the work
        // the server does anyway to compute its devices' policies (#10).
        let mut seen = BTreeSet::new();
        for info in validated.nodes.values() {
            let structural = matches!(
                info.node.kind,
                NodeKind::Global | NodeKind::Tenant | NodeKind::Group
            ) && info.node.builtin != Some(Builtin::Unmanaged);
            if !structural || !configures(info) {
                continue;
            }
            if let Err(found) = validated.check_effective_at(info.node.id) {
                for mut e in found {
                    if e.path.starts_with("/effective") {
                        e.message = format!(
                            "in the effective policy of `{}`: {}",
                            info.node.name, e.message
                        );
                        e.path = format!("{}{}", info.path(), e.path);
                    }
                    if seen.insert((e.code, e.path.clone(), e.message.clone())) {
                        errors.push(e);
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(validated)
        } else {
            Err(errors)
        }
    }
}

/// The unknown-application limits (`unknown.scope_limits`) of any device's
/// effective policy must stay within [`MAX_UNKNOWN_SCOPE_VALUES`] (#39).
/// For each structural node and device, this sums an upper bound: the
/// scope values of every policy on its own layers (the node, its
/// ancestors, and the templates they link to), plus those of every
/// dynamic group of its tenant and their templates, since which dynamic
/// groups a device is in is only known when its policy is computed. A
/// node over the cap is reported once, at the nearest node that makes the
/// total exceed it, with the largest contributors.
///
/// Each node's chain total is memoised from its parent's, so the check is
/// linear in the nodes whatever the depth (validation also has to stay
/// fast on the over-deep chains it rejects). The largest contributors are
/// only gathered for the few nodes it reports.
fn unknown_scope_bounds(
    nodes: &BTreeMap<NodeId, NodeInfo>,
    policies: &BTreeMap<PolicyId, PolicyInfo>,
) -> Vec<HierarchyError> {
    // Scope values one policy contributes: its `scope` (one) and its
    // `unknown.scopes`. A policy with no limit contributes none.
    let size = |p: &PolicyInfo| {
        let d = &p.document.policy;
        usize::from(d.scope.is_some()) + d.unknown.scopes.len()
    };
    // What one node's own assignments, and its linked template's, add.
    let own = |info: &NodeInfo| -> Vec<(usize, String)> {
        let mut out = Vec::new();
        let mut add = |n: &NodeInfo, via: &str| {
            for a in &n.node.assignments {
                if let Some(p) = policies.get(&a.policy) {
                    let s = size(p);
                    if s > 0 {
                        out.push((
                            s,
                            format!(
                                "policy `{}` on `{}`{via} ({s})",
                                p.document.policy.name, n.node.name
                            ),
                        ));
                    }
                }
            }
        };
        add(info, "");
        if let Some(t) = info.node.template.and_then(|t| nodes.get(&t)) {
            add(t, &format!(" (template of `{}`)", info.node.name));
        }
        out
    };
    let own_total = |info: &NodeInfo| own(info).iter().map(|(s, _)| s).sum::<usize>();
    // Every dynamic group of each tenant could apply to its devices.
    let mut dynamic: BTreeMap<NodeId, Vec<(usize, String)>> = BTreeMap::new();
    for info in nodes.values() {
        if info.node.kind == NodeKind::DynamicGroup
            && let Some(t) = info.tenant
        {
            dynamic.entry(t).or_default().extend(
                own(info)
                    .into_iter()
                    .map(|(s, d)| (s, format!("dynamic group: {d}"))),
            );
        }
    }
    let dynamic_total = |info: &NodeInfo| {
        info.tenant
            .and_then(|t| dynamic.get(&t))
            .map_or(0, |d| d.iter().map(|(s, _)| s).sum::<usize>())
    };
    // Chain totals, memoised: a node's is its own plus its parent's. A
    // cycle or a missing parent (reported elsewhere) stops the walk.
    let mut chain: BTreeMap<NodeId, usize> = BTreeMap::new();
    for id in nodes.keys() {
        let mut path = Vec::new();
        let mut at = Some(*id);
        let mut base = 0;
        while let Some(n) = at {
            if let Some(t) = chain.get(&n) {
                base = *t;
                break;
            }
            if path.contains(&n) || path.len() > nodes.len() {
                break;
            }
            path.push(n);
            at = nodes.get(&n).and_then(|i| i.node.parent);
        }
        for n in path.into_iter().rev() {
            base += nodes.get(&n).map_or(0, own_total);
            chain.insert(n, base);
        }
    }
    let bound =
        |info: &NodeInfo| chain.get(&info.node.id).copied().unwrap_or(0) + dynamic_total(info);
    let mut errors = Vec::new();
    for info in nodes.values() {
        if !matches!(
            info.node.kind,
            NodeKind::Global | NodeKind::Tenant | NodeKind::Group | NodeKind::Device
        ) {
            continue;
        }
        let total = bound(info);
        if total <= MAX_UNKNOWN_SCOPE_VALUES {
            continue;
        }
        // Report at the nearest node only: one whose parent is within the
        // cap.
        if info
            .node
            .parent
            .and_then(|p| nodes.get(&p))
            .is_some_and(|p| bound(p) > MAX_UNKNOWN_SCOPE_VALUES)
        {
            continue;
        }
        let mut parts: Vec<(usize, String)> = Vec::new();
        let mut at = Some(info);
        let mut steps = 0;
        while let Some(n) = at {
            parts.extend(own(n));
            steps += 1;
            if steps > MAX_GROUP_DEPTH + 3 {
                break;
            }
            at = n.node.parent.and_then(|p| nodes.get(&p));
        }
        if let Some(t) = info.tenant {
            parts.extend(dynamic.get(&t).cloned().unwrap_or_default());
        }
        parts.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let largest: Vec<&str> = parts.iter().take(5).map(|(_, d)| d.as_str()).collect();
        errors.push(herr(
            HierarchyCode::TooMany,
            format!("{}/assignments", info.path()),
            format!(
                "a device at `{}` could receive up to {total} unknown-application scope values (each policy's `scope` and `unknown.scopes`, over its layers and every dynamic group of its tenant); at most {MAX_UNKNOWN_SCOPE_VALUES} are allowed. This is an upper bound, because a device's dynamic groups are only known when its policy is computed. Largest: {}. Slim or consolidate these policies, especially dynamic-group ones",
                info.node.name,
                largest.join("; ")
            ),
        ));
    }
    errors
}

/// Whether a structural node changes anything for the devices below it
/// beyond what its parent gives them. The global node, tenants and built-in
/// groups always count.
fn configures(info: &NodeInfo) -> bool {
    let n = &info.node;
    n.kind != NodeKind::Group
        || n.builtin.is_some()
        || n.template.is_some()
        || !n.assignments.is_empty()
        || !n.rule_sets.is_empty()
        || !n.categories.is_empty()
        || !n.suppress_inherited.is_empty()
        || !n.settings.is_empty()
        || !n.locked_settings.is_empty()
        || n.mode.is_some()
        || n.lock_mode
        || n.precedence.is_some()
}

fn library_positions(libraries: &[Library]) -> BTreeMap<Version, usize> {
    let mut out = BTreeMap::new();
    for (i, lib) in libraries.iter().enumerate() {
        out.entry((lib.id, lib.version)).or_insert(i);
    }
    out
}

/// The shape of the tree. Returns the nodes that are well placed.
fn check_nodes(input: &[Node], errors: &mut Vec<HierarchyError>) -> BTreeMap<NodeId, NodeInfo> {
    let mut by_id: BTreeMap<NodeId, usize> = BTreeMap::new();
    for (i, n) in input.iter().enumerate() {
        let base = format!("/nodes/{i}");
        if let Some(problem) = name_problem(&n.name) {
            errors.push(herr(
                HierarchyCode::InvalidName,
                format!("{base}/name"),
                problem,
            ));
        }
        if let Some(first) = by_id.insert(n.id, i) {
            by_id.insert(n.id, first);
            errors.push(herr(
                HierarchyCode::DuplicateId,
                format!("{base}/id"),
                format!("node ID {} is already used by /nodes/{first}", n.id),
            ));
        }
    }
    let kind_of = |id: &NodeId| by_id.get(id).map(|&i| &input[i]);

    // Exactly one global node, with no parent.
    let globals: Vec<usize> = (0..input.len())
        .filter(|&i| input[i].kind == NodeKind::Global)
        .collect();
    if globals.len() != 1 {
        errors.push(herr(
            HierarchyCode::InvalidParent,
            "/nodes",
            format!(
                "a snapshot has exactly one `global` node; found {}",
                globals.len()
            ),
        ));
    }

    for (i, n) in input.iter().enumerate() {
        let base = format!("/nodes/{i}");
        match (n.kind, n.parent) {
            (NodeKind::Global, None) => {}
            (NodeKind::Global, Some(_)) => errors.push(herr(
                HierarchyCode::InvalidParent,
                format!("{base}/parent"),
                "the global node has no parent",
            )),
            (kind, None) => errors.push(herr(
                HierarchyCode::InvalidParent,
                format!("{base}/parent"),
                format!("a `{}` node needs a parent", kind.as_str()),
            )),
            (kind, Some(p)) => match kind_of(&p) {
                None => errors.push(herr(
                    HierarchyCode::UnknownNode,
                    format!("{base}/parent"),
                    format!("node {p} does not exist"),
                )),
                Some(parent) => {
                    let ok = match kind {
                        NodeKind::Tenant => parent.kind == NodeKind::Global,
                        NodeKind::Group => {
                            matches!(parent.kind, NodeKind::Tenant | NodeKind::Group)
                                && parent.builtin.is_none()
                        }
                        NodeKind::Device => {
                            parent.kind == NodeKind::Group
                                && parent.builtin != Some(Builtin::Staging)
                        }
                        NodeKind::DynamicGroup => parent.kind == NodeKind::Tenant,
                        NodeKind::Template => {
                            matches!(parent.kind, NodeKind::Global | NodeKind::Tenant)
                        }
                        NodeKind::Global => true,
                    };
                    if !ok {
                        let why = match kind {
                            NodeKind::Tenant => "a tenant's parent is the global node",
                            NodeKind::Group => {
                                "a group's parent is a tenant or a group that is not built in"
                            }
                            NodeKind::Device => {
                                "a device's parent is its primary group, which cannot be `staging`"
                            }
                            NodeKind::DynamicGroup => "a dynamic group's parent is its tenant",
                            _ => "a template's parent is the global node or a tenant",
                        };
                        errors.push(herr(
                            HierarchyCode::InvalidParent,
                            format!("{base}/parent"),
                            format!("`{}` is a `{}`; {why}", parent.name, parent.kind.as_str()),
                        ));
                    }
                }
            },
        }
        check_fields(&base, n, errors);
    }

    // Parent cycles, each named once, from its smallest node ID.
    let mut cyclic: BTreeSet<NodeId> = BTreeSet::new();
    let mut done: BTreeSet<NodeId> = BTreeSet::new();
    let mut reported: BTreeSet<Vec<NodeId>> = BTreeSet::new();
    for n in input {
        let mut walk: Vec<NodeId> = Vec::new();
        // Position of each node on this walk, so a repeat is found in
        // O(log n), and every node is walked once overall.
        let mut on_walk: BTreeMap<NodeId, usize> = BTreeMap::new();
        let mut at = Some(n.id);
        while let Some(id) = at {
            if done.contains(&id) {
                break;
            }
            if let Some(&start) = on_walk.get(&id) {
                let mut cycle = walk[start..].to_vec();
                let min = cycle
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, v)| **v)
                    .map_or(0, |(i, _)| i);
                cycle.rotate_left(min);
                cyclic.extend(cycle.iter().copied());
                if reported.insert(cycle.clone()) {
                    let mut names: Vec<String> = cycle
                        .iter()
                        .filter_map(&kind_of)
                        .map(|c| format!("`{}`", c.name))
                        .collect();
                    if let Some(first) = names.first().cloned() {
                        names.push(first);
                    }
                    let i = by_id.get(&cycle[0]).copied().unwrap_or(0);
                    errors.push(herr(
                        HierarchyCode::NodeCycle,
                        format!("/nodes/{i}/parent"),
                        format!("parents form a cycle: {}", names.join(" -> ")),
                    ));
                }
                break;
            }
            on_walk.insert(id, walk.len());
            walk.push(id);
            at = kind_of(&id).and_then(|n| n.parent);
        }
        done.extend(walk);
    }

    // Tenants, depths and built-in groups, for nodes not on a cycle.
    let mut placed: BTreeMap<NodeId, (Option<NodeId>, usize)> = BTreeMap::new();
    let mut out = BTreeMap::new();
    let mut builtins: BTreeMap<(NodeId, Builtin), Vec<usize>> = BTreeMap::new();
    for (i, n) in input.iter().enumerate() {
        if cyclic.contains(&n.id) || by_id.get(&n.id) != Some(&i) {
            continue;
        }
        let (tenant, group_depth) = place_of(n.id, &kind_of, &cyclic, &mut placed);
        let depth = if n.kind == NodeKind::Group {
            group_depth
        } else {
            0
        };
        if n.kind == NodeKind::Group && depth > MAX_GROUP_DEPTH {
            errors.push(herr(
                HierarchyCode::GroupTooDeep,
                format!("/nodes/{i}/parent"),
                format!(
                    "group `{}` is nested {depth} deep below its tenant; at most {MAX_GROUP_DEPTH} is allowed",
                    n.name
                ),
            ));
        }
        if let Some(b) = n.builtin {
            match (n.kind, n.parent.and_then(|p| kind_of(&p)).map(|p| p.kind)) {
                (NodeKind::Group, Some(NodeKind::Tenant)) => {
                    if let Some(t) = tenant {
                        builtins.entry((t, b)).or_default().push(i);
                    }
                }
                _ => errors.push(herr(
                    HierarchyCode::InvalidBuiltin,
                    format!("/nodes/{i}/builtin"),
                    "a built-in group is a group directly below its tenant",
                )),
            }
        }
        out.insert(
            n.id,
            NodeInfo {
                node: n.clone(),
                index: i,
                tenant,
            },
        );
    }
    for info in out.values().filter(|n| n.node.kind == NodeKind::Tenant) {
        let t = info.node.id;
        for b in [Builtin::Unassigned, Builtin::Unmanaged, Builtin::Staging] {
            let found = builtins.get(&(t, b)).map_or(&[][..], Vec::as_slice);
            let required = b == Builtin::Unassigned;
            if found.len() > 1 || (required && found.is_empty()) {
                errors.push(herr(
                    HierarchyCode::InvalidBuiltin,
                    info.path(),
                    format!(
                        "tenant `{}` has {} `{}` groups; it needs {}",
                        info.node.name,
                        found.len(),
                        b.as_str(),
                        if required {
                            "exactly one"
                        } else {
                            "at most one"
                        }
                    ),
                ));
            }
        }
    }
    // A template link: to a template visible from the node, never from a
    // template.
    for info in out.values() {
        let Some(t) = info.node.template else {
            continue;
        };
        let base = format!("{}/template", info.path());
        let problem = match out.get(&t) {
            None => Some(format!("node {t} does not exist")),
            Some(target) if target.node.kind != NodeKind::Template => {
                Some(format!("`{}` is not a template", target.node.name))
            }
            Some(_) if info.node.kind == NodeKind::Template => {
                Some("a template cannot link to another template".to_owned())
            }
            Some(_) if info.node.kind == NodeKind::Global => {
                Some("the global node cannot link to a template".to_owned())
            }
            Some(target) if target.tenant.is_some() && target.tenant != info.tenant => Some(
                format!("template `{}` belongs to another tenant", target.node.name),
            ),
            Some(_) => None,
        };
        if let Some(problem) = problem {
            errors.push(herr(HierarchyCode::InvalidTemplate, base, problem));
        }
    }
    // Precedence on a group needs its tenant's permission.
    let global_options = out
        .values()
        .find(|n| n.node.kind == NodeKind::Global)
        .and_then(|n| n.node.tenant_options);
    for info in out.values() {
        if info.node.kind != NodeKind::Group || info.node.precedence.is_none() {
            continue;
        }
        let tenant_options = info
            .tenant
            .and_then(|t| out.get(&t))
            .and_then(|t| t.node.tenant_options);
        let allowed = tenant_options
            .and_then(|o| o.allow_group_precedence)
            .or_else(|| global_options.and_then(|o| o.allow_group_precedence))
            .unwrap_or(false);
        if !allowed {
            errors.push(herr(
                HierarchyCode::PrecedenceNotAllowed,
                format!("{}/precedence", info.path()),
                format!(
                    "group `{}` sets a precedence model, but its tenant does not allow groups to (`tenant_options.allow_group_precedence`)",
                    info.node.name
                ),
            ));
        }
    }
    out
}

/// The tenant a node is in and, for a group, how deep it is below that
/// tenant (a group directly below it is 1), memoised in `placed` so the
/// whole tree costs O(n log n). The walk stops at the first node already
/// placed, at a missing or cyclic parent, or at the tenant.
fn place_of<'n>(
    id: NodeId,
    kind_of: &impl Fn(&NodeId) -> Option<&'n Node>,
    cyclic: &BTreeSet<NodeId>,
    placed: &mut BTreeMap<NodeId, (Option<NodeId>, usize)>,
) -> (Option<NodeId>, usize) {
    // Walk up to a node whose answer is known.
    let mut chain: Vec<&Node> = Vec::new();
    let mut at = Some(id);
    let mut known = (None, 0usize);
    while let Some(i) = at {
        if let Some(&p) = placed.get(&i) {
            known = p;
            break;
        }
        let Some(node) = kind_of(&i) else { break };
        if cyclic.contains(&i) {
            break;
        }
        chain.push(node);
        if node.kind == NodeKind::Tenant {
            break;
        }
        at = node.parent;
    }
    // Fill in from the top down.
    for node in chain.into_iter().rev() {
        known = match node.kind {
            NodeKind::Tenant => (Some(node.id), 0),
            NodeKind::Group => (known.0, known.1.saturating_add(1)),
            // Devices, dynamic groups and templates do not add depth.
            _ => (known.0, known.1),
        };
        placed.insert(node.id, known);
    }
    known
}

/// Fields that only some kinds of node may have, and per-node limits.
fn check_fields(base: &str, n: &Node, errors: &mut Vec<HierarchyError>) {
    if n.mode == Some(Mode::Disabled) {
        errors.push(herr(
            HierarchyCode::Policy(ErrorCode::ModeNotAllowed),
            format!("{base}/mode"),
            "a node cannot be `disabled`: a device is disabled only through the mode state machine, with a reason and an expiry (#36), and a device removed from management belongs in the `unmanaged` group",
        ));
    }
    let mut not_allowed = |field: &str, why: &str| {
        errors.push(herr(
            HierarchyCode::FieldNotAllowed,
            format!("{base}/{field}"),
            why.to_owned(),
        ));
    };
    let kind = n.kind;
    if n.rank.is_some() && kind != NodeKind::DynamicGroup {
        not_allowed("rank", "only a dynamic group has a rank");
    }
    if n.precedence.is_some()
        && !matches!(kind, NodeKind::Global | NodeKind::Tenant | NodeKind::Group)
    {
        not_allowed(
            "precedence",
            "the precedence model is chosen by the global node, a tenant or, if the tenant allows it, a group",
        );
    }
    if n.tenant_options.is_some() && !matches!(kind, NodeKind::Global | NodeKind::Tenant) {
        not_allowed(
            "tenant_options",
            "only the global node and tenants have tenant options",
        );
    }
    if n.builtin.is_some() && kind != NodeKind::Group {
        not_allowed("builtin", "only a group can be built in");
    }
    if n.allow_auto_assignment.is_some() && kind != NodeKind::Group {
        not_allowed(
            "allow_auto_assignment",
            "only a group takes part in placement",
        );
    }
    if n.builtin == Some(Builtin::Unmanaged) {
        let configured = !n.assignments.is_empty()
            || !n.rule_sets.is_empty()
            || !n.categories.is_empty()
            || !n.suppress_inherited.is_empty()
            || !n.settings.is_empty()
            || !n.locked_settings.is_empty()
            || n.mode.is_some()
            || n.lock_mode
            || n.template.is_some()
            || n.precedence.is_some();
        if configured {
            not_allowed(
                "builtin",
                "the `unmanaged` group is removed from management: it has no policies, settings or modes",
            );
        }
    }
    for (key, len, max) in [
        ("assignments", n.assignments.len(), MAX_ASSIGNMENTS_PER_NODE),
        ("rule_sets", n.rule_sets.len(), MAX_REFS_PER_NODE),
        ("categories", n.categories.len(), MAX_REFS_PER_NODE),
        (
            "suppress_inherited",
            n.suppress_inherited.len(),
            MAX_SUPPRESSIONS_PER_NODE,
        ),
    ] {
        if len > max {
            errors.push(herr(
                HierarchyCode::TooMany,
                format!("{base}/{key}"),
                format!("{len} entries; at most {max} are allowed"),
            ));
        }
    }
    for (key, value) in &n.settings {
        if let Some(problem) = setting_problem(key, value) {
            errors.push(herr(
                HierarchyCode::InvalidSetting,
                format!("{base}/settings/{}", pointer_escape(key)),
                problem,
            ));
        }
    }
    let mut locked = BTreeSet::new();
    for (i, key) in n.locked_settings.iter().enumerate() {
        let path = format!("{base}/locked_settings/{i}");
        if !setting_keys().contains(key) && !MODE_OPTION_LOCKS.contains(&key.as_str()) {
            errors.push(herr(
                HierarchyCode::InvalidSetting,
                path,
                format!(
                    "`{key}` is not a policy setting or one of {}",
                    MODE_OPTION_LOCKS.join(", ")
                ),
            ));
        } else if !locked.insert(key) {
            errors.push(herr(
                HierarchyCode::InvalidSetting,
                path,
                format!("`{key}` is listed more than once"),
            ));
        }
    }
    let mut suppressed = BTreeSet::new();
    for (i, id) in n.suppress_inherited.iter().enumerate() {
        if !suppressed.insert(id) {
            errors.push(herr(
                HierarchyCode::SuppressUnknownRule,
                format!("{base}/suppress_inherited/{i}"),
                format!("rule {id} is listed more than once"),
            ));
        }
    }
    let mut categories = BTreeSet::new();
    for (i, c) in n.categories.iter().enumerate() {
        let path = format!("{base}/categories/{i}");
        if let Some(problem) = crate::validate::category_problem(c) {
            errors.push(herr(HierarchyCode::InvalidCategory, path, problem));
        } else if !categories.insert(c) {
            errors.push(herr(
                HierarchyCode::InvalidCategory,
                path,
                format!("category `{c}` is listed more than once"),
            ));
        }
    }
}

/// JSON Pointer escaping (RFC 6901) of one key.
pub(crate) fn pointer_escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Assignments, rule set libraries and the visibility of what a node uses.
fn check_node_refs(
    info: &NodeInfo,
    policies: &BTreeMap<PolicyId, PolicyInfo>,
    catalogue: &Catalogue,
    errors: &mut Vec<HierarchyError>,
) {
    let base = info.path();
    let n = &info.node;
    let mut seen_policy = BTreeMap::new();
    let mut seen_slot = BTreeMap::new();
    for (i, a) in n.assignments.iter().enumerate() {
        let path = format!("{base}/assignments/{i}");
        match policies.get(&a.policy) {
            None => errors.push(herr(
                HierarchyCode::UnknownPolicy,
                format!("{path}/policy"),
                format!("policy {} does not exist", a.policy),
            )),
            Some(p) => {
                if !visible(p.realm, info) {
                    errors.push(herr(
                        HierarchyCode::NotVisible,
                        format!("{path}/policy"),
                        format!(
                            "policy `{}` belongs to another tenant",
                            p.document.policy.name
                        ),
                    ));
                }
            }
        }
        if let Some(first) = seen_policy.insert(a.policy, i) {
            errors.push(herr(
                HierarchyCode::DuplicateAssignment,
                format!("{path}/policy"),
                format!(
                    "policy {} is already assigned by {base}/assignments/{first}",
                    a.policy
                ),
            ));
        }
        if let Some(first) = seen_slot.insert(a.slot_order, i) {
            errors.push(herr(
                HierarchyCode::DuplicateAssignment,
                format!("{path}/slot_order"),
                format!(
                    "slot {} is already used by {base}/assignments/{first}; each slot on a node is unique",
                    a.slot_order
                ),
            ));
        }
    }
    let mut seen_lib = BTreeMap::new();
    for (i, r) in n.rule_sets.iter().enumerate() {
        let path = format!("{base}/rule_sets/{i}");
        if let Some(first) = seen_lib.insert(r.id, i) {
            errors.push(herr(
                HierarchyCode::DuplicateAssignment,
                path.clone(),
                format!(
                    "library {} is already assigned by {base}/rule_sets/{first}",
                    r.id
                ),
            ));
        }
        match catalogue.resolve(r, info.visibility()) {
            Err(e) => errors.extend(lib_errors(&path, vec![e])),
            Ok(lib) if !matches!(lib.content, LibraryContent::RuleSet { .. }) => {
                errors.push(herr(
                    HierarchyCode::Library(LibraryCode::RefKindNotAllowed),
                    path,
                    format!(
                        "library `{}` is a `{}`; a node assigns rule set libraries only",
                        lib.name,
                        lib.content.kind()
                    ),
                ));
            }
            Ok(_) => {}
        }
    }
}

/// Whether something in `realm` may be used at the node.
pub(crate) fn visible(realm: Realm, info: &NodeInfo) -> bool {
    match realm {
        Realm::Global => true,
        Realm::Tenant(t) => info.tenant == Some(t),
    }
}

/// Every policy, with its references replaced, validated on its own.
fn check_policies(
    input: &[super::PolicyEntry],
    tenants: &BTreeSet<NodeId>,
    catalogue: &Catalogue,
    errors: &mut Vec<HierarchyError>,
) -> BTreeMap<PolicyId, PolicyInfo> {
    let mut out = BTreeMap::new();
    for (i, entry) in input.iter().enumerate() {
        let base = format!("/policies/{i}");
        let id = entry.document.policy.id;
        if let Some(first) = out.get(&id).map(|p: &PolicyInfo| p.index) {
            errors.push(herr(
                HierarchyCode::DuplicateId,
                format!("{base}/document/policy/id"),
                format!("policy ID {id} is already used by /policies/{first}"),
            ));
            continue;
        }
        if let Realm::Tenant(t) = entry.realm
            && !tenants.contains(&t)
        {
            errors.push(herr(
                HierarchyCode::UnknownNode,
                format!("{base}/realm"),
                format!("tenant {t} does not exist"),
            ));
        }
        let from = match entry.realm {
            Realm::Global => Visibility::Global,
            Realm::Tenant(t) => Visibility::Tenant(t),
        };
        let mut document = entry.document.clone();
        let mut used = BTreeSet::new();
        let mut refs = BTreeSet::new();
        let mut ok = true;
        for (j, set) in document.rule_sets.iter_mut().enumerate() {
            for (k, rule) in set.rules.iter_mut().enumerate() {
                for (_, r) in refs_in(&rule.match_) {
                    refs.insert(r.id);
                }
                match catalogue.expand(&rule.match_, from, &mut used) {
                    Ok(tree) => rule.match_ = tree,
                    Err(e) => {
                        ok = false;
                        errors.extend(lib_errors(
                            &format!("{base}/document/rule_sets/{j}/rules/{k}/match"),
                            vec![e],
                        ));
                    }
                }
            }
        }
        // The library sets the policy's scopes use (#38): each must exist,
        // be visible and be of the right kind, and is pinned to the version
        // used, so the effective policy and its hash follow it.
        if !scope_refs(
            &mut document,
            &format!("{base}/document"),
            catalogue,
            from,
            &mut used,
            &mut refs,
            errors,
        ) {
            continue;
        }
        if !ok {
            continue;
        }
        match document.validate() {
            Ok(v) => {
                out.insert(
                    id,
                    PolicyInfo {
                        index: i,
                        realm: entry.realm,
                        document: v.into_document(),
                        used,
                        refs,
                    },
                );
            }
            Err(findings) => {
                for f in findings
                    .into_iter()
                    .filter(|f| f.severity == crate::validate::Severity::Error)
                {
                    errors.push(herr(
                        HierarchyCode::Policy(f.code),
                        format!("{base}/document{}", f.path),
                        f.message,
                    ));
                }
            }
        }
    }
    out
}

/// Every rule set library version, with its references replaced, checked
/// as a policy of one rule set would be.
fn check_rule_set_libraries(
    libraries: &[Library],
    catalogue: &Catalogue,
    errors: &mut Vec<HierarchyError>,
) -> BTreeMap<Version, RuleSetInfo> {
    let mut out = BTreeMap::new();
    for (i, lib) in libraries.iter().enumerate() {
        let LibraryContent::RuleSet { rule_set } = &lib.content else {
            continue;
        };
        if out.contains_key(&(lib.id, lib.version)) {
            continue;
        }
        let base = format!("/libraries/{i}/content/rule_set");
        let from = match lib.realm {
            Realm::Global => Visibility::Global,
            Realm::Tenant(t) => Visibility::Tenant(t),
        };
        let mut set = rule_set.clone();
        let mut used = BTreeSet::new();
        let mut ok = true;
        for (k, rule) in set.rules.iter_mut().enumerate() {
            match catalogue.expand(&rule.match_, from, &mut used) {
                Ok(tree) => rule.match_ = tree,
                Err(e) => {
                    ok = false;
                    errors.extend(lib_errors(&format!("{base}/rules/{k}/match"), vec![e]));
                }
            }
        }
        if !ok {
            continue;
        }
        let mut wrapped = wrap(set);
        let mut refs = BTreeSet::new();
        if !scope_refs(
            &mut wrapped,
            "",
            catalogue,
            from,
            &mut used,
            &mut refs,
            &mut Vec::new(),
        ) {
            for (path, problem) in scope_ref_problems(&wrapped, catalogue, from) {
                let rest = path
                    .strip_prefix("/rule_sets/0")
                    .unwrap_or(&path)
                    .to_owned();
                errors.push(herr(
                    HierarchyCode::Library(problem.code),
                    format!("{base}{rest}"),
                    problem.message,
                ));
            }
            continue;
        }
        let Some(mut set) = wrapped.rule_sets.pop() else {
            continue;
        };
        set.band = 0;
        match wrap(set).validate() {
            Ok(v) => {
                let mut doc = v.into_document();
                if let Some(set) = doc.rule_sets.pop() {
                    out.insert(
                        (lib.id, lib.version),
                        RuleSetInfo {
                            rule_set: set,
                            used,
                        },
                    );
                }
            }
            Err(findings) => {
                for f in findings
                    .into_iter()
                    .filter(|f| f.severity == crate::validate::Severity::Error)
                {
                    // Every error is reported. Findings about the rule set
                    // map to its path in the library; document-level ones
                    // (`/rule_sets`, such as too many rules or regular
                    // expressions) to the rule set itself. Nothing is
                    // dropped, so an invalid library never validates and then
                    // goes missing from an effective policy.
                    let rest = f.path.strip_prefix("/rule_sets/0").unwrap_or_default();
                    errors.push(herr(
                        HierarchyCode::Library(LibraryCode::InvalidRuleSet),
                        format!("{base}{rest}"),
                        format!("{}: {}", f.code, f.message),
                    ));
                }
            }
        }
    }
    out
}

/// The library set references of `doc` (its scopes and its location
/// profiles' tests), resolved from `from`: each must name a library of the
/// kind its position needs. A `latest` reference is pinned to the version it resolves to. Every
/// version used goes into `used` and every library into `refs`. Returns
/// whether all resolved; problems go to `errors` under `base`.
fn scope_refs(
    doc: &mut PolicyDocument,
    base: &str,
    catalogue: &Catalogue,
    from: Visibility,
    used: &mut BTreeSet<Version>,
    refs: &mut BTreeSet<LibraryId>,
    errors: &mut Vec<HierarchyError>,
) -> bool {
    let problems = scope_ref_problems(doc, catalogue, from);
    let ok = problems.is_empty();
    for (path, e) in problems {
        errors.push(HierarchyError {
            code: HierarchyCode::Library(e.code),
            path: format!("{base}{path}"),
            message: e.message,
        });
    }
    if !ok {
        return false;
    }
    let pin = |r: &mut LibraryRef, used: &mut BTreeSet<Version>, refs: &mut BTreeSet<LibraryId>| {
        if let Ok(lib) = catalogue.resolve(r, from) {
            used.insert((lib.id, lib.version));
            refs.insert(lib.id);
            r.pin = crate::library::Pin::Version(lib.version);
        }
    };
    crate::scope::for_each_document_set_ref(doc, |r| pin(r, used, refs));
    true
}

/// The library set references of `doc` (its scopes and its location
/// profiles' tests) that do not resolve to a library of the right kind,
/// with their JSON Pointers.
fn scope_ref_problems(
    doc: &PolicyDocument,
    catalogue: &Catalogue,
    from: Visibility,
) -> Vec<(String, LibraryError)> {
    let mut out = Vec::new();
    for (path, r, kind) in crate::scope::document_set_refs(doc) {
        match catalogue.resolve(&r, from) {
            Err(e) => out.push((path, e)),
            Ok(lib) if lib.content.kind() != kind => out.push((
                path,
                LibraryError {
                    code: LibraryCode::RefKindNotAllowed,
                    path: String::new(),
                    message: format!(
                        "library `{}` is a `{}`; this position needs a `{}`",
                        lib.name,
                        lib.content.kind(),
                        kind.as_str()
                    ),
                },
            )),
            Ok(_) => {}
        }
    }
    out
}

/// A policy holding only `set`, to validate the set on its own.
fn wrap(set: RuleSet) -> PolicyDocument {
    PolicyDocument {
        schema_version: schema::CURRENT,
        policy: crate::model::Policy {
            id: PolicyId(set.id.0),
            name: "Library".to_owned(),
            description: None,
            revision: 0,
            precedence_model: crate::model::PrecedenceModel::DenyWins,
            precedence_options: crate::model::PrecedenceOptions::default(),
            mode: crate::model::Mode::Enforce,
            mode_options: crate::model::ModeOptions::default(),
            settings: PolicySettings::default(),
            unknown: crate::model::UnknownPolicy::default(),
            governance: crate::model::GovernanceSettings::default(),
            rule_sets: vec![set.id],
            scope: None,
            rule_set_scopes: Vec::new(),
            location_profiles: Vec::new(),
            metadata: crate::model::Metadata::default(),
        },
        rule_sets: vec![set],
    }
}

impl ValidatedHierarchy {
    /// The node, if it exists.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(&id).map(|n| &n.node)
    }

    /// The revision of the snapshot.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The libraries.
    #[must_use]
    pub const fn catalogue(&self) -> &Catalogue {
        &self.catalogue
    }

    /// The `level_order` and `mode_merge` that apply in `tenant`: the
    /// tenant's own, then the global node's, then the defaults.
    pub(crate) fn options(&self, tenant: Option<NodeId>) -> (LevelOrder, ModeMerge) {
        let global = self
            .global
            .and_then(|g| self.nodes.get(&g))
            .and_then(|n| n.node.tenant_options);
        let own = tenant
            .and_then(|t| self.nodes.get(&t))
            .and_then(|t| t.node.tenant_options);
        let level = own
            .and_then(|o| o.level_order)
            .or_else(|| global.and_then(|o| o.level_order));
        let merge = own
            .and_then(|o| o.mode_merge)
            .or_else(|| global.and_then(|o| o.mode_merge));
        (level.unwrap_or_default(), merge.unwrap_or_default())
    }

    /// Whether a change of signed-in user re-runs placement in `tenant`.
    pub(crate) fn place_on_user_change(&self, tenant: NodeId) -> bool {
        let get = |id: Option<NodeId>| {
            id.and_then(|i| self.nodes.get(&i))
                .and_then(|n| n.node.tenant_options)
                .and_then(|o| o.place_on_user_change)
        };
        get(Some(tenant))
            .or_else(|| get(self.global))
            .unwrap_or(false)
    }

    /// Checks that library `id` can be deleted: nothing references it.
    ///
    /// # Errors
    ///
    /// `in_use`, listing every referrer: nodes that assign it or one of its
    /// categories, policies whose trees use it, and other libraries.
    pub fn check_delete(&self, id: LibraryId) -> Result<(), HierarchyError> {
        let mut users: BTreeSet<String> = BTreeSet::new();
        for info in self.nodes.values() {
            if info.node.rule_sets.iter().any(|r: &LibraryRef| r.id == id) {
                users.insert(format!("node `{}` ({})", info.node.name, info.path()));
            }
            for c in &info.node.categories {
                if self
                    .catalogue
                    .in_category(c, info.visibility())
                    .iter()
                    .any(|l| l.id == id)
                {
                    users.insert(format!(
                        "node `{}` through category `{c}` ({})",
                        info.node.name,
                        info.path()
                    ));
                }
            }
        }
        for p in self.policies.values() {
            if p.refs.contains(&id) {
                users.insert(format!(
                    "policy `{}` (/policies/{})",
                    p.document.policy.name, p.index
                ));
            }
        }
        for ((lib_id, version), lib) in self.catalogue.versions() {
            if lib_id == id {
                continue;
            }
            let in_scope = match &lib.content {
                LibraryContent::RuleSet { rule_set } => crate::scope::rule_set_scopes(rule_set)
                    .iter()
                    .any(|(_, s)| crate::scope::set_refs(s).iter().any(|(_, r, _)| r.id == id)),
                _ => false,
            };
            if in_scope
                || lib
                    .content
                    .trees()
                    .iter()
                    .any(|(_, t)| refs_in(t).iter().any(|(_, r)| r.id == id))
            {
                let at = self
                    .library_index
                    .get(&(lib_id, version))
                    .copied()
                    .unwrap_or(0);
                users.insert(format!(
                    "library `{}` v{version} (/libraries/{at})",
                    lib.name
                ));
            }
        }
        if users.is_empty() {
            Ok(())
        } else {
            let at = self
                .catalogue
                .versions()
                .find(|((l, _), _)| *l == id)
                .and_then(|(v, _)| self.library_index.get(&v))
                .map_or_else(|| "/libraries".to_owned(), |i| format!("/libraries/{i}"));
            Err(herr(
                HierarchyCode::InUse,
                at,
                format!(
                    "library {id} is still used by {}",
                    users.into_iter().collect::<Vec<_>>().join(", ")
                ),
            ))
        }
    }

    /// A new node copied once from `template`, with no link to it:
    /// assignments, rule set libraries, categories, suppressions,
    /// settings, locks and mode. Add it to the next snapshot, which is
    /// validated as usual.
    ///
    /// # Errors
    ///
    /// `invalid_template` if `template` is not a template.
    pub fn copy_from_template(
        &self,
        template: NodeId,
        id: NodeId,
        name: String,
        kind: NodeKind,
        parent: NodeId,
    ) -> Result<Node, HierarchyError> {
        let t = self
            .nodes
            .get(&template)
            .filter(|t| t.node.kind == NodeKind::Template)
            .ok_or_else(|| {
                herr(
                    HierarchyCode::InvalidTemplate,
                    "",
                    format!("node {template} is not a template"),
                )
            })?;
        let t = &t.node;
        Ok(Node {
            id,
            name,
            kind,
            parent: Some(parent),
            builtin: None,
            template: None,
            assignments: t.assignments.clone(),
            rule_sets: t.rule_sets.clone(),
            categories: t.categories.clone(),
            suppress_inherited: t.suppress_inherited.clone(),
            settings: t.settings.clone(),
            locked_settings: t.locked_settings.clone(),
            mode: t.mode,
            lock_mode: t.lock_mode,
            precedence: None,
            tenant_options: None,
            rank: None,
            allow_auto_assignment: None,
        })
    }
}
