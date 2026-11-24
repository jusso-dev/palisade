//! Enforcement modes: which mode applies to one decision, and what it does
//! to the decision (#36).
//!
//! The evaluator ([`crate::evaluate`]) first computes the enforce-mode
//! decision. [`resolve`] then finds the effective mode for that decision,
//! and [`Evaluator::evaluate_in`](crate::evaluate::Evaluator::evaluate_in)
//! applies it. Everything here is a pure function of the policy and a
//! [`DeviceState`] that the agent supplies; nothing reads a clock. The
//! state machine that changes a device's mode over time is in
//! [`machine`].
//!
//! # The modes
//!
//! | Mode | Effect on a decision |
//! |---|---|
//! | `disabled` | The engine is not consulted: there is no decision ([`Evaluator::evaluate_in`](crate::evaluate::Evaluator::evaluate_in) returns `None`). Mandatory denies do not apply, and the device is reported `disabled`. Only a whole device can be disabled. |
//! | `monitor` | Evaluated fully. What enforce mode would block runs (`allowed_audit`), and `would_have_been` is `blocked`. |
//! | `audit` | As `monitor`. The two differ only in which events the agent sends (#16). |
//! | `learning` | As `audit`. An object that only the implicit deny would block is also a learning candidate ([`Decision::learning_candidate`](crate::decision::Decision::learning_candidate)). |
//! | `enforce` | Decisions take effect. |
//!
//! Two kinds of block are never relaxed by a mode, a session or any
//! override, only by `disabled`:
//!
//! - **A mandatory deny** (ADR 0004, #125: the blocklist always wins). It
//!   blocks in `monitor`, `audit` and `learning`, during every override
//!   session including `full_bypass`, and whatever a rule set's
//!   `mode_override` says (validation rejects one on a mandatory rule set).
//! - **An `always_enforce` rule**, except during a `full_bypass` session.
//!
//! # Resolution
//!
//! For an object of type `t` decided by `rule` (or by the implicit deny),
//! in this order:
//!
//! 1. **Lockdown.** If [`DeviceState::lockdown`] is set, `enforce`, and
//!    stop. Sessions, a disabled device mode, type modes, control levels,
//!    rule set overrides and `never_enforce` are all ignored.
//! 2. **Device mode.** The device's base mode, [`DeviceState::mode`]
//!    (the policy's `mode`, or what the [`machine`] moved it to).
//!    `disabled` stops here: no decision.
//! 3. **Mandatory deny.** If `rule` is in a mandatory rule set, `enforce`,
//!    and stop.
//! 4. **Disconnected.** While the device is disconnected, a
//!    `mode_disconnected` stricter than the device mode replaces it.
//! 5. **Object type.** `mode_by_type[t]` if set (raised to a stricter
//!    `mode_disconnected` while disconnected), otherwise the device mode.
//!    Then the class's control level in the settings (`script_control`,
//!    `script_control_by_kind`, `dll_control`, `driver_control`) caps it:
//!    `audit` caps it at `audit`, and `off` caps it at `monitor`. `off`
//!    means the agent does not intercept the class (#4, #92); if such an
//!    object is evaluated anyway, only a mandatory deny, a blocklist with
//!    `mode_override: enforce` or an `always_enforce` deny blocks it.
//! 6. **Rule set.** The `mode_override` of `rule`'s rule set, if set,
//!    replaces the mode. Only non-mandatory blocklists may have one.
//! 7. **Rule.** For a deny, `always_enforce` makes it `enforce` and
//!    `never_enforce` caps it at `audit`. Other actions cannot set it.
//! 8. **Override session** (#9). An active session caps the mode at
//!    `audit`, unless the rule is `always_enforce` and the session is not
//!    `full_bypass`.
//!
//! A cap lowers a mode to the cap's strictness and never raises it.
//! Strictness ranks `enforce` above `learning` and `audit` (equal), above
//! `monitor`, above `disabled` ([`strictness`]).
//!
//! Lockdown never changes [`DeviceState::mode`], so clearing it restores
//! every prior mode.

pub mod machine;

use crate::model::{
    Action, ControlLevel, EnforcementOverride, Mode, ObjectType, Policy, Rule, RuleSet, ScriptKind,
};

/// Whether the device has checked in recently (#36).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Connectivity {
    /// It has checked in within `disconnected_after_secs`.
    #[default]
    Connected,
    /// It has not.
    Disconnected,
}

impl Connectivity {
    /// The connectivity of a device whose last successful check-in was
    /// `secs_since_check_in` seconds ago, for a policy that counts a device
    /// as disconnected after `disconnected_after` seconds
    /// ([`ModeOptions::disconnected_after`](crate::model::ModeOptions::disconnected_after)).
    /// The agent measures the time on its monotonic clock.
    #[must_use]
    pub const fn since_check_in(secs_since_check_in: u64, disconnected_after: u64) -> Self {
        if secs_since_check_in >= disconnected_after {
            Self::Disconnected
        } else {
            Self::Connected
        }
    }
}

/// The kind of an active override session (#9). Opening and timing a
/// session is #9 and #120; the engine only reads that one is active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionKind {
    /// Relaxes everything except mandatory denies and `always_enforce`
    /// rules.
    Audit,
    /// Also relaxes `always_enforce` rules. Never a mandatory deny.
    FullBypass,
}

/// What the agent knows about the device, besides the policy. The agent
/// keeps it (#69); the engine only reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceState {
    /// The device's base mode: the policy's `mode`, or the mode the
    /// [`machine`] moved the device to.
    pub mode: Mode,
    /// Whether the device has checked in recently.
    pub connectivity: Connectivity,
    /// The active override session, if any.
    pub session: Option<SessionKind>,
    /// Whether emergency lockdown is set. It comes in the policy bundle
    /// with top precedence (#43); an offline device applies it at its next
    /// check-in.
    pub lockdown: bool,
}

impl DeviceState {
    /// A connected device in the policy's mode, with no session and no
    /// lockdown.
    #[must_use]
    pub const fn of(policy: &Policy) -> Self {
        Self {
            mode: policy.mode,
            connectivity: Connectivity::Connected,
            session: None,
            lockdown: false,
        }
    }
}

/// The mode that applies to one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EffectiveMode {
    /// The mode.
    pub mode: Mode,
    /// Whether the override session lowered it from `enforce`, so that a
    /// block it relaxes is reported as `allowed_override`.
    pub by_session: bool,
}

/// How strict a mode is: `disabled` 0, `monitor` 1, `audit` and `learning`
/// 2, `enforce` 3. Only `enforce` blocks.
#[must_use]
pub const fn strictness(mode: Mode) -> u8 {
    match mode {
        Mode::Disabled => 0,
        Mode::Monitor => 1,
        Mode::Audit | Mode::Learning => 2,
        Mode::Enforce => 3,
    }
}

/// `mode`, lowered to the strictness of `cap` if it is stricter.
#[must_use]
pub const fn capped(mode: Mode, cap: Mode) -> Mode {
    if strictness(mode) > strictness(cap) {
        cap
    } else {
        mode
    }
}

/// The device mode: `enforce` in lockdown, otherwise
/// [`DeviceState::mode`], raised while disconnected to `mode_disconnected`
/// if that is stricter. A disabled device stays disabled while
/// disconnected: it returns to its prior mode when its time box ends
/// ([`machine`]).
#[must_use]
pub fn device_mode(policy: &Policy, state: &DeviceState) -> Mode {
    if state.lockdown {
        return Mode::Enforce;
    }
    if state.mode == Mode::Disabled {
        return Mode::Disabled;
    }
    raise_offline(policy, state, state.mode)
}

/// `mode`, raised to `mode_disconnected` while disconnected if that is
/// stricter.
fn raise_offline(policy: &Policy, state: &DeviceState, mode: Mode) -> Mode {
    match (state.connectivity, policy.mode_options.mode_disconnected) {
        (Connectivity::Disconnected, Some(offline)) if strictness(offline) > strictness(mode) => {
            offline
        }
        _ => mode,
    }
}

/// Only a whole device is ever disabled. Validation rejects `disabled`
/// below the device; if it is there anyway, it is read as `monitor`, which
/// still evaluates and reports.
const fn enabled(mode: Mode) -> Mode {
    match mode {
        Mode::Disabled => Mode::Monitor,
        other => other,
    }
}

/// The control level of an object type in the policy settings. Types with
/// no setting of their own are `enforce`.
#[must_use]
pub fn control_level(policy: &Policy, object_type: ObjectType) -> ControlLevel {
    let s = &policy.settings;
    match object_type {
        ObjectType::Script(kind) => script_level(s, kind),
        ObjectType::Library => s.dll_control,
        ObjectType::Driver => s.driver_control,
        _ => ControlLevel::Enforce,
    }
}

fn script_level(s: &crate::model::PolicySettings, kind: ScriptKind) -> ControlLevel {
    s.script_control_by_kind
        .get(&kind)
        .copied()
        .unwrap_or(s.script_control)
}

/// The mode for objects of one type, before any rule: steps 1 to 5 of the
/// module documentation, without the session. `disabled` only when the
/// device is disabled.
#[must_use]
pub fn object_mode(policy: &Policy, state: &DeviceState, object_type: ObjectType) -> Mode {
    let device = device_mode(policy, state);
    if device == Mode::Disabled || state.lockdown {
        return device;
    }
    let mode = policy
        .mode_options
        .mode_by_type
        .get(&object_type)
        .map_or(device, |&m| raise_offline(policy, state, enabled(m)));
    match control_level(policy, object_type) {
        ControlLevel::Enforce => mode,
        ControlLevel::Audit => capped(mode, Mode::Audit),
        ControlLevel::Off => capped(mode, Mode::Monitor),
    }
}

/// The effective mode for a decision about an object of `object_type`,
/// decided by `rule` in `set`, or by the implicit deny when `rule` is
/// `None`. See the module documentation for the steps.
#[must_use]
pub fn resolve(
    policy: &Policy,
    object_type: ObjectType,
    rule: Option<(&RuleSet, &Rule)>,
    state: &DeviceState,
) -> EffectiveMode {
    let fixed = |mode| EffectiveMode {
        mode,
        by_session: false,
    };
    if state.lockdown {
        return fixed(Mode::Enforce);
    }
    if state.mode == Mode::Disabled {
        return fixed(Mode::Disabled);
    }
    if rule.is_some_and(|(set, _)| set.mandatory) {
        return fixed(Mode::Enforce);
    }
    let mut mode = object_mode(policy, state, object_type);
    // Only a deny blocks, so only a deny's override means anything;
    // validation rejects it on any other action.
    let enforcement = rule
        .filter(|(_, r)| matches!(r.action, Action::Deny(_)))
        .map_or(EnforcementOverride::Inherit, |(_, r)| {
            r.enforcement_override
        });
    if let Some(over) = rule.and_then(|(set, _)| set.mode_override) {
        mode = enabled(over);
    }
    mode = match enforcement {
        EnforcementOverride::Inherit => mode,
        EnforcementOverride::AlwaysEnforce => Mode::Enforce,
        EnforcementOverride::NeverEnforce => capped(mode, Mode::Audit),
    };
    let Some(session) = state.session else {
        return fixed(mode);
    };
    if enforcement == EnforcementOverride::AlwaysEnforce && session != SessionKind::FullBypass {
        return fixed(mode);
    }
    EffectiveMode {
        mode: capped(mode, Mode::Audit),
        by_session: mode == Mode::Enforce,
    }
}

/// The object types that Essential Eight application control requires to
/// be enforced (ISM-1657, ISM-1658): executables, libraries, drivers,
/// every script kind, installers, compiled HTML, HTML applications and
/// control panel applets.
#[must_use]
pub fn essential_eight_types() -> Vec<ObjectType> {
    ObjectType::ALL
        .into_iter()
        .filter(|t| {
            matches!(
                t,
                ObjectType::Executable
                    | ObjectType::Library
                    | ObjectType::Driver
                    | ObjectType::Script(_)
                    | ObjectType::Installer
                    | ObjectType::CompiledHtml
                    | ObjectType::HtmlApplication
                    | ObjectType::ControlPanelApplet
            )
        })
        .collect()
}

/// A device's protection status, for device lists, health and evidence
/// (#10, #17). The snake_case name is part of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStatus {
    /// Every Essential Eight type is enforced.
    ProtectedEnforce,
    /// The device mode is `enforce`, but at least one Essential Eight type
    /// is not. It does not count as effective (#17).
    ProtectedPartial,
    /// The device is in `audit`.
    Audit,
    /// The device is in `learning`.
    Learning,
    /// The device is in `monitor`.
    Monitor,
    /// The device is disabled: unprotected.
    Disabled,
    /// An override session is active.
    OverrideActive,
    /// Emergency lockdown is set.
    Lockdown,
}

impl ProtectionStatus {
    /// The status of a device. The first that applies: `lockdown`,
    /// `disabled`, `override_active`, then `protected_enforce` if every
    /// Essential Eight type is in `enforce`, then `protected_partial` if
    /// the device mode is `enforce`, and otherwise the device mode.
    ///
    /// `stale_policy` needs the bundle's expiry and is #61.
    #[must_use]
    pub fn of(policy: &Policy, state: &DeviceState) -> Self {
        let device = device_mode(policy, state);
        if state.lockdown {
            return Self::Lockdown;
        }
        if device == Mode::Disabled {
            return Self::Disabled;
        }
        if state.session.is_some() {
            return Self::OverrideActive;
        }
        let all_enforced = essential_eight_types()
            .into_iter()
            .all(|t| object_mode(policy, state, t) == Mode::Enforce);
        match device {
            _ if all_enforced => Self::ProtectedEnforce,
            Mode::Enforce => Self::ProtectedPartial,
            Mode::Learning => Self::Learning,
            Mode::Audit => Self::Audit,
            Mode::Monitor => Self::Monitor,
            Mode::Disabled => Self::Disabled,
        }
    }
}

#[cfg(test)]
mod tests;
