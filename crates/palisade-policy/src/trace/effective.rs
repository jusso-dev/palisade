//! The effective-policy view of one device (#41): what it enforces.
//!
//! [`effective_view`] flattens the policy for a device in a given state:
//! every rule with where it comes from and whether it takes part, the
//! settings with their sources, the effective mode per object type, the
//! active override session and lockdown, and the protection status (#36).
//! Each rule's provenance is its policy and rule set.
//! [`effective_view_with_groups`] puts first the hierarchy nodes it came
//! from, when the policy is a device's effective policy from the group
//! hierarchy (#37, [`crate::hierarchy::EffectivePolicy`]): which global,
//! tenant, group, dynamic-group, template or device layer contributed its
//! rule set, how, and which node suppressed it, if one did
//! ([`super::groups`]). The view is for administrators, so it writes names
//! unredacted ([`Privacy::DEFAULT`]); pass a [`Privacy`] to
//! [`effective_view_with_groups`] to redact
//! them as a trace would.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::decision::RuleRef;
use crate::lifecycle::Activity;
use crate::mode::{self, DeviceState, ProtectionStatus, SessionKind};
use crate::model::{ActionKind, Mode, ObjectType, PolicyId};
use crate::validate::ValidatedPolicy;

use super::groups::GroupProvenance;
use super::{InheritanceStep, Privacy, RuleStage};

/// One rule as the device sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveRule {
    /// The rule.
    pub rule: RuleRef,
    /// Its name.
    pub name: String,
    /// Its action.
    pub action: ActionKind,
    /// Its stage, or `null` for `defer`.
    pub stage: Option<RuleStage>,
    /// Whether it takes part in evaluation: it is enabled, inside its
    /// activity window at the view's clock, and the device is not
    /// disabled, as [`Evaluator::evaluate_in`] decides.
    ///
    /// [`Evaluator::evaluate_in`]: crate::evaluate::Evaluator::evaluate_in
    pub active: bool,
    /// Why not, if it does not: `disabled` (the rule is disabled),
    /// `suppressed` (a hierarchy node disabled it with `suppress_inherited`,
    /// shown with group provenance, [`effective_view_with_groups`]),
    /// `not_yet_active` or `expired` (outside its activity window at the
    /// view's clock, #40), or `device_disabled` (the device mode is
    /// `disabled`, so no rule runs). An expired rule with `on_expire:
    /// convert_to_audit` is listed as `expired`: it only annotates.
    pub inactive_reason: Option<&'static str>,
    /// Its rule set's `mode_override`.
    pub rule_set_mode: Option<Mode>,
    /// Where it comes from, outermost first.
    pub provenance: Vec<InheritanceStep>,
}

/// One setting and its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveSetting {
    /// The setting's key, as a document writes it.
    pub key: String,
    /// Its value.
    pub value: serde_json::Value,
    /// Where it comes from: `policy` if the document sets it, `default`
    /// otherwise.
    pub source: &'static str,
}

/// The mode of one object type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TypeMode {
    /// The type.
    pub object_type: ObjectType,
    /// Its mode before any rule (#36 steps 1 to 5, without a session).
    pub mode: Mode,
}

/// What a device enforces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveView {
    /// The policy.
    pub policy_id: PolicyId,
    /// Its revision.
    pub policy_revision: u64,
    /// The device mode (#36).
    pub device_mode: Mode,
    /// The protection status.
    pub protection: ProtectionStatus,
    /// Emergency lockdown is set.
    pub lockdown: bool,
    /// The active override session: `audit`, `full_bypass` or `null`.
    pub override_session: Option<&'static str>,
    /// The device is disconnected.
    pub disconnected: bool,
    /// The mode of every object type.
    pub modes: Vec<TypeMode>,
    /// The settings, by key.
    pub settings: Vec<EffectiveSetting>,
    /// Every rule of the referenced rule sets, in policy order.
    pub rules: Vec<EffectiveRule>,
}

/// The effective view of a device in `state` under `policy`, with rule
/// activity judged at `clock` as the evaluator judges it
/// ([`crate::lifecycle::activity_at`]; `None` is an evaluator without a
/// clock).
#[must_use]
pub fn effective_view(
    policy: &ValidatedPolicy,
    state: &DeviceState,
    clock: Option<&crate::lifecycle::RuleClock>,
) -> EffectiveView {
    view(policy, state, clock, None, &Privacy::DEFAULT)
}

/// The same as [`effective_view`], with each rule's provenance starting at
/// the hierarchy nodes it came from (`groups`, built from the effective
/// policy `policy` is), and every name written as `privacy` says.
#[must_use]
pub fn effective_view_with_groups(
    policy: &ValidatedPolicy,
    state: &DeviceState,
    clock: Option<&crate::lifecycle::RuleClock>,
    groups: &GroupProvenance,
    privacy: &Privacy,
) -> EffectiveView {
    view(policy, state, clock, Some(groups), privacy)
}

fn view(
    policy: &ValidatedPolicy,
    state: &DeviceState,
    clock: Option<&crate::lifecycle::RuleClock>,
    groups: Option<&GroupProvenance>,
    privacy: &Privacy,
) -> EffectiveView {
    let doc = policy.document();
    let p = &doc.policy;
    let sets: BTreeMap<_, _> = doc.rule_sets.iter().map(|s| (s.id, s)).collect();
    // The evaluator runs no rule on a disabled device. The resolved mode is
    // used, because lockdown overrides a disabled device mode.
    let device_mode = mode::device_mode(p, state);
    let device_disabled = device_mode == Mode::Disabled;
    let mut rules = Vec::new();
    for id in &p.rule_sets {
        let Some(set) = sets.get(id).copied() else {
            continue;
        };
        for rule in &set.rules {
            let activity = crate::lifecycle::activity_at(rule, clock);
            let window = match activity {
                Activity::Active | Activity::Disabled => None,
                Activity::NotYetActive => Some("not_yet_active"),
                Activity::Expired => Some("expired"),
            };
            rules.push(EffectiveRule {
                rule: RuleRef::new(p, set, rule),
                name: privacy.text(&rule.name).0,
                action: rule.action.kind(),
                stage: RuleStage::of(set, rule),
                active: activity.is_active() && !device_disabled,
                inactive_reason: if !rule.enabled {
                    // A node's `suppress_inherited` disables the rule in
                    // the effective policy (#37); say so when it is known.
                    Some(if groups.is_some_and(|g| g.suppressed(rule.id)) {
                        "suppressed"
                    } else {
                        "disabled"
                    })
                } else if window.is_some() {
                    window
                } else if device_disabled {
                    Some("device_disabled")
                } else {
                    None
                },
                rule_set_mode: set.mode_override,
                provenance: groups
                    .map(|g| g.steps(set.id, rule.id, privacy))
                    .unwrap_or_default()
                    .into_iter()
                    .chain([
                        InheritanceStep::document("policy", p.id.to_string(), &p.name, privacy),
                        InheritanceStep::document(
                            "rule_set",
                            set.id.to_string(),
                            &set.name,
                            privacy,
                        ),
                    ])
                    .collect(),
            });
        }
    }
    let modes = ObjectType::ALL
        .into_iter()
        .map(|t| TypeMode {
            object_type: t,
            mode: mode::object_mode(p, state, t),
        })
        .collect();
    EffectiveView {
        policy_id: p.id,
        policy_revision: p.revision,
        device_mode,
        protection: ProtectionStatus::of(p, state),
        lockdown: state.lockdown,
        override_session: state.session.map(|s| match s {
            SessionKind::Audit => "audit",
            SessionKind::FullBypass => "full_bypass",
        }),
        disconnected: state.connectivity == mode::Connectivity::Disconnected,
        modes,
        settings: settings(p),
        rules,
    }
}

/// The settings, each marked `policy` if it differs from the default.
fn settings(p: &crate::model::Policy) -> Vec<EffectiveSetting> {
    let actual = serde_json::to_value(&p.settings).unwrap_or_default();
    let default = serde_json::to_value(crate::model::PolicySettings::default()).unwrap_or_default();
    let mut out = Vec::new();
    if let serde_json::Value::Object(map) = &actual {
        for (k, v) in map {
            out.push(EffectiveSetting {
                key: k.clone(),
                value: v.clone(),
                source: if default.get(k) == Some(v) {
                    "default"
                } else {
                    "policy"
                },
            });
        }
    }
    // Keys the default writes but the policy's settings leave out (empty
    // maps) are still settings.
    if let serde_json::Value::Object(map) = &default {
        for (k, v) in map {
            if actual.get(k).is_none() {
                out.push(EffectiveSetting {
                    key: k.clone(),
                    value: v.clone(),
                    source: "default",
                });
            }
        }
    }
    out.push(EffectiveSetting {
        key: "mode".to_owned(),
        value: serde_json::to_value(p.mode).unwrap_or_default(),
        source: "policy",
    });
    out.push(EffectiveSetting {
        key: "precedence_model".to_owned(),
        value: serde_json::to_value(p.precedence_model).unwrap_or_default(),
        source: if p.precedence_model == crate::model::PrecedenceModel::default() {
            "default"
        } else {
            "policy"
        },
    });
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}
