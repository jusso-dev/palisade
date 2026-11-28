//! Group provenance for traces and the effective view (#41, #37).
//!
//! A device's policy is built from the group hierarchy
//! ([`crate::hierarchy::EffectivePolicy`]): each rule set comes from one or
//! more nodes (the global node, a tenant, groups, dynamic groups,
//! templates or the device), through a policy assigned to the node, a rule
//! set library or a category, and a node below may have suppressed one of
//! its rules. [`GroupProvenance`] carries that record, with the names of
//! the nodes, into a [`Tracer`](super::Tracer) and
//! [`effective_view`](super::effective::effective_view), so a trace says
//! which groups a deciding rule came from and the view says it for every
//! rule.
//!
//! The group steps go before the policy, rule set and rule steps, outermost
//! node first: [`InheritanceStep::node`] is the node's kind (`global`,
//! `tenant`, `group`, `dynamic_group`, `template` or `device`), `via` says
//! how the node contributed, and `outcome` is `contributed`, or for the
//! node that suppressed the rule `suppressed` or `suppression_overridden`.
//!
//! Names follow the trace's privacy settings: every name passes the
//! [`Redactor`](super::Redactor) and is cut to
//! [`MAX_VALUE_CHARS`](super::privacy::MAX_VALUE_CHARS) characters, as
//! policy, rule set and rule names do, and the ID is always written. A
//! node is named only by its configured name; group membership of the user
//! or device is never part of it.

use std::collections::BTreeMap;

use crate::hierarchy::{
    Contribution, EffectivePolicy, NodeId, RuleStatus, ValidatedHierarchy, Via,
};
use crate::model::{RuleId, RuleSetId};

use super::InheritanceStep;
use super::privacy::Privacy;

/// Where every rule of a device's effective policy came from, by node,
/// with the names of the nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GroupProvenance {
    rule_sets: BTreeMap<RuleSetId, Vec<Contribution>>,
    rules: BTreeMap<RuleId, RuleStatus>,
    nodes: BTreeMap<NodeId, (&'static str, String)>,
}

impl GroupProvenance {
    /// The provenance of `effective`, naming its nodes from `hierarchy`. A
    /// node the hierarchy does not hold is named by its ID.
    #[must_use]
    pub fn new(effective: &EffectivePolicy, hierarchy: &ValidatedHierarchy) -> Self {
        let mut out = Self {
            rule_sets: BTreeMap::new(),
            rules: effective
                .rules()
                .iter()
                .map(|(id, p)| (*id, p.status))
                .collect(),
            nodes: BTreeMap::new(),
        };
        for p in effective.rules().values() {
            out.rule_sets
                .entry(p.rule_set_id)
                .or_insert_with(|| p.contributions.clone());
        }
        let mut name = |id: NodeId| {
            out.nodes.entry(id).or_insert_with(|| {
                hierarchy.node(id).map_or_else(
                    || ("node", id.to_string()),
                    |n| (n.kind.as_str(), n.name.clone()),
                )
            });
        };
        let ids: Vec<NodeId> = out
            .rule_sets
            .values()
            .flatten()
            .flat_map(|c| core::iter::once(c.node).chain(c.template_for))
            .chain(out.rules.values().filter_map(|s| match s {
                RuleStatus::Suppressed { by } => Some(*by),
                RuleStatus::Reasserted { suppressed_by } => Some(*suppressed_by),
                RuleStatus::Active | RuleStatus::Disabled => None,
            }))
            .collect();
        for id in ids {
            name(id);
        }
        out
    }

    /// The group steps of one rule, outermost first, then the step of the
    /// node that suppressed it, if any. Empty for a rule set or rule this
    /// provenance does not hold.
    #[must_use]
    pub fn steps(&self, set: RuleSetId, rule: RuleId, privacy: &Privacy) -> Vec<InheritanceStep> {
        let mut out: Vec<InheritanceStep> = self
            .rule_sets
            .get(&set)
            .into_iter()
            .flatten()
            .map(|c| self.step(c.node, Some(via(c)), "contributed", c.template_for, privacy))
            .collect();
        match self.rules.get(&rule) {
            Some(RuleStatus::Suppressed { by }) => {
                out.push(self.step(*by, None, "suppressed", None, privacy));
            }
            Some(RuleStatus::Reasserted { suppressed_by }) => {
                out.push(self.step(
                    *suppressed_by,
                    None,
                    "suppression_overridden",
                    None,
                    privacy,
                ));
            }
            _ => {}
        }
        out
    }

    /// Whether a hierarchy node suppressed `rule` (`suppress_inherited`),
    /// so that it is disabled in the effective policy.
    #[must_use]
    pub fn suppressed(&self, rule: RuleId) -> bool {
        matches!(self.rules.get(&rule), Some(RuleStatus::Suppressed { .. }))
    }

    fn step(
        &self,
        id: NodeId,
        via: Option<String>,
        outcome: &'static str,
        template_for: Option<NodeId>,
        privacy: &Privacy,
    ) -> InheritanceStep {
        let (kind, name) = self
            .nodes
            .get(&id)
            .map_or(("node", id.to_string()), |(k, n)| (*k, n.clone()));
        InheritanceStep {
            node: kind,
            id: id.to_string(),
            name: privacy.text(&name).0,
            via,
            outcome: Some(outcome),
            template_for: template_for.map(|t| t.to_string()),
        }
    }
}

/// How a node contributed a rule set, as the trace writes it.
fn via(c: &Contribution) -> String {
    match &c.via {
        Via::Policy { policy, slot_order } => format!("policy {policy} (slot {slot_order})"),
        Via::Library { library, version } => format!("library {library} v{version}"),
        Via::Category {
            category,
            library,
            version,
        } => format!("category {category}: library {library} v{version}"),
        Via::Node => "node settings".to_owned(),
    }
}

#[cfg(test)]
mod tests;
