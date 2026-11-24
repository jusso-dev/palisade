//! The mode state machine: which mode changes are legal, and when a
//! time-boxed mode ends (#36).
//!
//! A [`ModeMachine`] holds a device's base mode ([`DeviceState::mode`](super::DeviceState::mode))
//! and, when the device was moved to a weaker mode for a limited time, the
//! [`TimeBox`] that moves it back. It is pure: every call takes the time
//! from the caller ([`Now`], usually from a [`Clock`]), and the agent
//! stores the machine between calls (#69).
//!
//! # Legal transitions
//!
//! | From | To |
//! |---|---|
//! | `disabled` | any |
//! | `monitor` | `audit`, `learning`, `enforce`, `disabled` |
//! | `audit` | `learning`, `enforce`, `monitor`, `disabled` |
//! | `learning` | `audit`, `enforce`, `disabled` |
//! | `enforce` | `audit`, `learning`, `monitor`, `disabled`, each time-boxed |
//!
//! A mode never transitions to itself. Every other change is rejected
//! ([`TransitionError::Illegal`]), and a rejected request changes nothing.
//!
//! # Time boxes
//!
//! Leaving `enforce` for a weaker mode, and entering `disabled` from any
//! mode, needs a `reason`, a ticket reference when the tenant requires
//! one, and an `expires_at` at most 30 days ahead. Only `enforce` to
//! `audit` may instead be `permanent`, and only for an actor with the
//! elevated permission ([`Governance::may_weaken_permanently`]).
//!
//! When a time box ends, the machine moves back to the mode it left (its
//! rollback target, [`TimeBox::prior`]), with no server involved, so an
//! offline device reverts too. A later change to a mode at least as strict
//! as the target ends the box early. Any other change keeps it: the
//! device still reverts to the target at the same time, and the change
//! cannot set an expiry of its own. A change inside a box to a mode weaker
//! than the target still needs a reason (and a ticket where required).
//!
//! A time box is a target for clock rollback: setting the clock back would
//! keep a weaker mode alive. So the end is checked against two clocks, and
//! the first to pass ends the box (ADR 0012):
//!
//! - the wall clock reaches `expires_at`; or
//! - the monotonic clock has advanced by the box's budget (`expires_at`
//!   minus the wall time when the box started), whatever the wall clock
//!   says.
//!
//! Setting the wall clock back therefore cannot extend a box, and setting
//! it forward only ends one early, which is the strict direction. A
//! monotonic reading below the box's start (the agent restarted, and its
//! monotonic clock with it) also ends the box. Carrying the remaining
//! budget across a restart in protected storage, as ADR 0012 does for
//! override sessions, is the agent's part (#69, #220).
//!
//! Every change, requested or by expiry, gives a [`ModeChanged`] record
//! for the `mode_changed` event (#16).

use crate::model::Mode;

use super::strictness;

/// The longest time box, in seconds (30 days).
pub const MAX_TIME_BOX_SECS: i64 = 30 * 86_400;

/// One reading of the agent's two clocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Now {
    /// Wall-clock time, in seconds since 1970-01-01T00:00:00Z. On the
    /// agent this is anchored time where it has it (ADR 0012).
    pub wall_secs: i64,
    /// Monotonic time, in seconds since an arbitrary origin. It only goes
    /// forwards while the agent runs.
    pub monotonic_secs: u64,
}

/// A source of [`Now`]. The agent supplies one (#69, #220); tests use a
/// simulated clock.
pub trait Clock {
    /// The current reading.
    fn now(&self) -> Now;
}

/// Whether `from` may change to `to`, ignoring the time-box requirements.
#[must_use]
pub const fn is_legal(from: Mode, to: Mode) -> bool {
    use Mode::{Audit, Disabled, Enforce, Learning, Monitor};
    match (from, to) {
        (Disabled, Disabled)
        | (Monitor, Monitor)
        | (Audit, Audit)
        | (Learning, Learning)
        | (Enforce, Enforce)
        | (Learning, Monitor) => false,
        (Disabled | Monitor | Audit | Learning | Enforce, _) => true,
    }
}

/// Whether a change from `from` to `to` needs a time box: leaving
/// `enforce` for a weaker mode, or entering `disabled`.
#[must_use]
pub const fn needs_time_box(from: Mode, to: Mode) -> bool {
    (matches!(from, Mode::Enforce) && !matches!(to, Mode::Enforce)) || matches!(to, Mode::Disabled)
}

/// What the tenant requires of a change that needs a time box.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Governance {
    /// A ticket reference is required.
    pub require_ticket: bool,
    /// The actor holds the elevated permission that allows a permanent
    /// move from `enforce` to `audit` (#131).
    pub may_weaken_permanently: bool,
}

/// A requested mode change.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    /// The new mode.
    pub to: Mode,
    /// Who asked.
    pub actor: String,
    /// Why.
    pub reason: Option<String>,
    /// A change or ticket reference.
    pub ticket: Option<String>,
    /// When the new mode ends, in wall-clock seconds.
    pub expires_at: Option<i64>,
    /// The new mode does not end.
    pub permanent: bool,
}

impl Request {
    /// A request to move to `to`, by `actor`, with no reason, ticket or
    /// expiry.
    #[must_use]
    pub fn new(to: Mode, actor: impl Into<String>) -> Self {
        Self {
            to,
            actor: actor.into(),
            reason: None,
            ticket: None,
            expires_at: None,
            permanent: false,
        }
    }
}

/// Why a request was rejected. The machine is unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransitionError {
    /// The request names no actor.
    ActorRequired,
    /// The device is already in the mode.
    SameMode,
    /// The change is not in the table of legal transitions.
    Illegal {
        /// The current mode.
        from: Mode,
        /// The requested mode.
        to: Mode,
    },
    /// The change needs a reason that is not empty.
    ReasonRequired,
    /// The tenant requires a ticket reference for the change.
    TicketRequired,
    /// The change needs `expires_at` (or `permanent`, where allowed).
    ExpiryRequired,
    /// `expires_at` is not after the current wall-clock time.
    ExpiryInPast,
    /// `expires_at` is more than 30 days ahead.
    ExpiryTooFar,
    /// `permanent` is only allowed from `enforce` to `audit`, for an actor
    /// with the elevated permission, and never with `expires_at`.
    PermanentNotAllowed,
    /// `expires_at` or `permanent` was given for a change that starts no
    /// time box: one that does not need one, or one made while a time box
    /// is already running. Time boxes on other changes are #69.
    TimeBoxNotAllowed,
}

impl core::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ActorRequired => f.write_str("the change needs an actor"),
            Self::SameMode => f.write_str("the device is already in this mode"),
            Self::Illegal { from, to } => write!(f, "{from:?} cannot change to {to:?}"),
            Self::ReasonRequired => f.write_str("this change needs a reason"),
            Self::TicketRequired => f.write_str("this change needs a ticket reference"),
            Self::ExpiryRequired => f.write_str("this change needs an expiry"),
            Self::ExpiryInPast => f.write_str("the expiry is not in the future"),
            Self::ExpiryTooFar => f.write_str("the expiry is more than 30 days ahead"),
            Self::PermanentNotAllowed => f.write_str("this change cannot be permanent"),
            Self::TimeBoxNotAllowed => f.write_str("this change cannot set an expiry"),
        }
    }
}

impl std::error::Error for TransitionError {}

/// A weaker mode that ends by itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TimeBox {
    /// The mode to return to: the rollback target.
    pub prior: Mode,
    /// When it ends, in wall-clock seconds.
    pub expires_at: i64,
    /// How long it lasts on the monotonic clock, in seconds.
    pub budget_secs: u64,
    /// The monotonic time it started at.
    pub started_monotonic: u64,
}

impl TimeBox {
    /// Whether the box has ended at `now`: the wall clock has reached
    /// `expires_at`, or the monotonic clock has run for the budget or gone
    /// backwards.
    #[must_use]
    pub const fn has_ended(&self, now: Now) -> bool {
        now.wall_secs >= self.expires_at
            || now.monotonic_secs < self.started_monotonic
            || now.monotonic_secs - self.started_monotonic >= self.budget_secs
    }
}

/// Why the mode changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cause {
    /// A request.
    Requested,
    /// A time box ended.
    Expired,
}

/// One mode change, for the `mode_changed` event (#16). The scope
/// (device or group) is added by the caller (#37, #38).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ModeChanged {
    /// The mode before.
    pub old: Mode,
    /// The mode after.
    pub new: Mode,
    /// Why it changed.
    pub cause: Cause,
    /// Who asked; `None` on expiry.
    pub actor: Option<String>,
    /// The request's reason.
    pub reason: Option<String>,
    /// The request's ticket reference.
    pub ticket: Option<String>,
    /// When the new mode ends, if it is time-boxed.
    pub expires_at: Option<i64>,
    /// The device left `learning`, so the learning-ended summary is due
    /// (#5, #69).
    pub learning_ended: bool,
}

/// A device's base mode and its time box.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ModeMachine {
    mode: Mode,
    time_box: Option<TimeBox>,
}

impl ModeMachine {
    /// A machine in `mode`, with no time box.
    #[must_use]
    pub const fn new(mode: Mode) -> Self {
        Self {
            mode,
            time_box: None,
        }
    }

    /// The mode as last stored. It may be a time-boxed mode that has ended;
    /// [`current`](Self::current) accounts for that.
    #[must_use]
    pub const fn stored(&self) -> Mode {
        self.mode
    }

    /// The running time box, if any.
    #[must_use]
    pub const fn time_box(&self) -> Option<&TimeBox> {
        self.time_box.as_ref()
    }

    /// The mode at `now`: the rollback target if the time box has ended.
    #[must_use]
    pub const fn current(&self, now: Now) -> Mode {
        match self.time_box {
            Some(b) if b.has_ended(now) => b.prior,
            _ => self.mode,
        }
    }

    /// Ends the time box if it has ended at `now`, and reports the change.
    pub fn tick(&mut self, now: Now) -> Option<ModeChanged> {
        let b = self.time_box.filter(|b| b.has_ended(now))?;
        let old = self.mode;
        self.mode = b.prior;
        self.time_box = None;
        Some(ModeChanged {
            old,
            new: b.prior,
            cause: Cause::Expired,
            actor: None,
            reason: None,
            ticket: None,
            expires_at: None,
            learning_ended: old == Mode::Learning && b.prior != Mode::Learning,
        })
    }

    /// Applies a request at `now`. A time box that has ended is closed
    /// first, and the request is checked against the mode that results.
    /// Returns every change, in order: the expiry, if any, then the
    /// requested change.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError`] if the request is not allowed. The
    /// machine is then unchanged, even if a time box has ended; call
    /// [`tick`](Self::tick) for that.
    pub fn transition(
        &mut self,
        request: &Request,
        governance: &Governance,
        now: Now,
    ) -> Result<Vec<ModeChanged>, TransitionError> {
        let mut next = *self;
        let mut changes: Vec<ModeChanged> = next.tick(now).into_iter().collect();
        let change = next.apply(request, governance, now)?;
        changes.push(change);
        *self = next;
        Ok(changes)
    }

    fn apply(
        &mut self,
        r: &Request,
        governance: &Governance,
        now: Now,
    ) -> Result<ModeChanged, TransitionError> {
        let from = self.mode;
        if r.actor.trim().is_empty() {
            return Err(TransitionError::ActorRequired);
        }
        if from == r.to {
            return Err(TransitionError::SameMode);
        }
        if !is_legal(from, r.to) {
            return Err(TransitionError::Illegal { from, to: r.to });
        }
        // A change that needs a time box starts one, unless one is already
        // running: then the device keeps its rollback target and end.
        let boxed = needs_time_box(from, r.to) && self.time_box.is_none();
        let wants_box = r.expires_at.is_some() || r.permanent;
        if !boxed && wants_box {
            return Err(TransitionError::TimeBoxNotAllowed);
        }
        // Weakening needs a reason, also inside a running box.
        let weakening = needs_time_box(from, r.to)
            || self
                .time_box
                .is_some_and(|b| strictness(r.to) < strictness(b.prior));
        if weakening {
            if r.reason.as_deref().is_none_or(|s| s.trim().is_empty()) {
                return Err(TransitionError::ReasonRequired);
            }
            if governance.require_ticket && r.ticket.as_deref().is_none_or(|s| s.trim().is_empty())
            {
                return Err(TransitionError::TicketRequired);
            }
        }
        let time_box = match (boxed, r.expires_at, r.permanent) {
            (false, _, _) => None,
            (true, Some(_), true) => return Err(TransitionError::PermanentNotAllowed),
            (true, None, true) => {
                if from == Mode::Enforce && r.to == Mode::Audit && governance.may_weaken_permanently
                {
                    None
                } else {
                    return Err(TransitionError::PermanentNotAllowed);
                }
            }
            (true, None, false) => return Err(TransitionError::ExpiryRequired),
            (true, Some(at), false) => {
                let ahead = at.saturating_sub(now.wall_secs);
                if ahead <= 0 {
                    return Err(TransitionError::ExpiryInPast);
                }
                if ahead > MAX_TIME_BOX_SECS {
                    return Err(TransitionError::ExpiryTooFar);
                }
                Some(TimeBox {
                    prior: from,
                    expires_at: at,
                    budget_secs: ahead.unsigned_abs(),
                    started_monotonic: now.monotonic_secs,
                })
            }
        };
        // A change to a mode at least as strict as the rollback target
        // ends the running box; any other change keeps it.
        if let Some(b) = self.time_box {
            if strictness(r.to) >= strictness(b.prior) {
                self.time_box = None;
            }
        } else {
            self.time_box = time_box;
        }
        self.mode = r.to;
        Ok(ModeChanged {
            old: from,
            new: r.to,
            cause: Cause::Requested,
            actor: Some(r.actor.clone()),
            reason: r.reason.clone(),
            ticket: r.ticket.clone(),
            expires_at: self.time_box.map(|b| b.expires_at),
            learning_ended: from == Mode::Learning,
        })
    }
}

#[cfg(test)]
mod tests;
