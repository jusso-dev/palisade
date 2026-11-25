//! The mode resolution steps of one decision (#36), for the trace.
//!
//! [`crate::mode::resolve`] gives the effective mode. These steps restate
//! its order, one step per rule it applies, so a reader can see which
//! setting set the mode. The last step is the result of `resolve` itself,
//! and the tests check that the steps lead to it.

use serde::Serialize;

use crate::decision::{Decision, Outcome, ReasonCode};
use crate::mode::{self, Connectivity, DeviceState, SessionKind};
use crate::model::{
    Action, ControlLevel, EnforcementOverride, Mode, ObjectType, Policy, Rule, RuleSet,
};

/// What one resolution step looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeStepKind {
    /// Emergency lockdown forces `enforce`.
    Lockdown,
    /// The device's base mode.
    DeviceMode,
    /// A mandatory deny always enforces.
    MandatoryDeny,
    /// `mode_disconnected` while the device is disconnected.
    Disconnected,
    /// `mode_by_type` for the object's type.
    ObjectType,
    /// The class's control level caps the mode.
    ControlLevel,
    /// The deciding rule set's `mode_override`.
    RuleSetOverride,
    /// The deciding rule's `enforcement_override`.
    RuleOverride,
    /// An active override session.
    Session,
    /// The effective mode.
    Effective,
    /// What the mode did to the outcome.
    Applied,
}

/// One step of mode resolution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModeStep {
    /// The step.
    pub kind: ModeStepKind,
    /// Whether it changed the mode (or, for `lockdown`, `mandatory_deny`
    /// and `effective`, fixed it).
    pub applied: bool,
    /// The mode after the step.
    pub mode: Mode,
    /// What the step read, such as `script.powershell: audit`.
    pub detail: String,
}

fn step(kind: ModeStepKind, applied: bool, mode: Mode, detail: impl Into<String>) -> ModeStep {
    ModeStep {
        kind,
        applied,
        mode,
        detail: detail.into(),
    }
}

fn name(m: Mode) -> &'static str {
    match m {
        Mode::Disabled => "disabled",
        Mode::Monitor => "monitor",
        Mode::Audit => "audit",
        Mode::Learning => "learning",
        Mode::Enforce => "enforce",
    }
}

/// The steps for a disabled device, which decides nothing.
pub(crate) fn disabled_steps(state: &DeviceState) -> Vec<ModeStep> {
    vec![
        step(
            ModeStepKind::DeviceMode,
            true,
            Mode::Disabled,
            format!("device mode {}", name(state.mode)),
        ),
        step(
            ModeStepKind::Effective,
            true,
            Mode::Disabled,
            "the engine is not consulted",
        ),
    ]
}

/// The steps that led to `decision`'s mode, for an object of type `t`
/// decided by `rule` (or the implicit deny). Each step's mode is the mode
/// after it, computed with the functions of [`crate::mode`]; the
/// `effective` step is [`mode::resolve`] itself, and the tests check that
/// the step before it agrees.
pub(crate) fn steps(
    policy: &Policy,
    t: ObjectType,
    rule: Option<(&RuleSet, &Rule)>,
    state: &DeviceState,
    decision: &Decision,
) -> Vec<ModeStep> {
    let mut out = Vec::new();
    let effective = mode::resolve(policy, t, rule, state);
    if state.lockdown {
        out.push(step(
            ModeStepKind::Lockdown,
            true,
            Mode::Enforce,
            "emergency lockdown",
        ));
    } else if rule.is_some_and(|(set, _)| set.mandatory) {
        out.push(step(
            ModeStepKind::DeviceMode,
            false,
            state.mode,
            format!("device mode {}", name(state.mode)),
        ));
        out.push(step(
            ModeStepKind::MandatoryDeny,
            true,
            Mode::Enforce,
            "a mandatory deny enforces in every mode",
        ));
    } else {
        out.push(step(
            ModeStepKind::DeviceMode,
            false,
            state.mode,
            format!("device mode {}", name(state.mode)),
        ));
        let device = mode::device_mode(policy, state);
        if state.connectivity == Connectivity::Disconnected {
            out.push(step(
                ModeStepKind::Disconnected,
                device != state.mode,
                device,
                match policy.mode_options.mode_disconnected {
                    Some(m) => format!("disconnected; mode_disconnected {}", name(m)),
                    None => "disconnected; no mode_disconnected".to_owned(),
                },
            ));
        }
        let object = mode::object_mode(policy, state, t);
        let by_type = policy.mode_options.mode_by_type.get(&t).copied();
        let level = mode::control_level(policy, t);
        if by_type.is_some() || level != ControlLevel::Enforce {
            let mut detail = Vec::new();
            if let Some(m) = by_type {
                detail.push(format!("mode_by_type {t}: {}", name(m)));
            }
            match level {
                ControlLevel::Enforce => {}
                ControlLevel::Audit => detail.push("control level audit".to_owned()),
                ControlLevel::Off => detail.push("control level off".to_owned()),
            }
            out.push(step(
                if by_type.is_some() {
                    ModeStepKind::ObjectType
                } else {
                    ModeStepKind::ControlLevel
                },
                object != device,
                object,
                detail.join("; "),
            ));
        }
        let mut current = object;
        let mut always = false;
        if let Some((set, r)) = rule {
            if let Some(o) = set.mode_override {
                // `disabled` below a device is read as `monitor`.
                let m = if o == Mode::Disabled {
                    Mode::Monitor
                } else {
                    o
                };
                out.push(step(
                    ModeStepKind::RuleSetOverride,
                    m != current,
                    m,
                    format!("rule set mode_override {}", name(o)),
                ));
                current = m;
            }
            if matches!(r.action, Action::Deny(_)) {
                match r.enforcement_override {
                    EnforcementOverride::Inherit => {}
                    EnforcementOverride::AlwaysEnforce => {
                        always = true;
                        out.push(step(
                            ModeStepKind::RuleOverride,
                            current != Mode::Enforce,
                            Mode::Enforce,
                            "enforcement_override always_enforce",
                        ));
                        current = Mode::Enforce;
                    }
                    EnforcementOverride::NeverEnforce => {
                        let m = mode::capped(current, Mode::Audit);
                        out.push(step(
                            ModeStepKind::RuleOverride,
                            m != current,
                            m,
                            "enforcement_override never_enforce",
                        ));
                        current = m;
                    }
                }
            }
        }
        if let Some(s) = state.session {
            let full = s == SessionKind::FullBypass;
            let kind = if full { "full_bypass" } else { "audit" };
            if always && !full {
                out.push(step(
                    ModeStepKind::Session,
                    false,
                    current,
                    format!("override session {kind}; always_enforce is not relaxed"),
                ));
            } else {
                let m = mode::capped(current, Mode::Audit);
                out.push(step(
                    ModeStepKind::Session,
                    m != current,
                    m,
                    format!("override session {kind}"),
                ));
            }
        }
    }
    out.push(step(
        ModeStepKind::Effective,
        true,
        effective.mode,
        if effective.by_session {
            "lowered by the override session"
        } else {
            ""
        },
    ));
    out.push(step(
        ModeStepKind::Applied,
        decision.outcome() != decision.would_have_been(),
        decision.mode(),
        applied_detail(decision),
    ));
    out
}

fn applied_detail(d: &Decision) -> &'static str {
    match (d.would_have_been(), d.outcome(), d.reason_code()) {
        (Outcome::Blocked, Outcome::AllowedAudit, _) => {
            "would have blocked; runs because the mode does not enforce"
        }
        (Outcome::Blocked, Outcome::AllowedOverride, _) => {
            "would have blocked; runs because of the override session"
        }
        (Outcome::Blocked, Outcome::Blocked, ReasonCode::MandatoryDeny) => {
            "blocked; a mandatory deny is never relaxed"
        }
        (Outcome::Blocked, Outcome::Blocked, ReasonCode::ImplicitDenyUnknown) => {
            "blocked; no rule allows it, and the mode enforces"
        }
        (Outcome::Blocked, Outcome::Blocked, _) => "blocked; the deciding rule enforces",
        _ => "the outcome is the enforce-mode outcome",
    }
}
