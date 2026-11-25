//! Event fidelity per mode (#36): which decisions a mode reports, and how.
//!
//! The engine classifies; the agent emits the events, and their wire
//! format is #16. [`fidelity`] maps one result of
//! [`Evaluator::evaluate_in`](crate::evaluate::Evaluator::evaluate_in) to a
//! [`Report`], from the decision's effective mode, its outcome and its
//! effective `log` flag:
//!
//! | Decision | `enforce` | `monitor` | `audit`, `learning` |
//! |---|---|---|---|
//! | none (device `disabled`) | – | – | – |
//! | `ignored` | none | none | none |
//! | `blocked` | the rule's `log` | the rule's `log` | the rule's `log` |
//! | would-block (`allowed_audit`) | – | event | event |
//! | `allowed_override` | event | event | event |
//! | `allowed` | the rule's `log` | summary | event |
//!
//! - A disabled device makes no decisions and reports none; the agent only
//!   sends its periodic heartbeat, which says the device is disabled (#4).
//! - `monitor` is the low-volume mode: a full event for each would-block,
//!   and allowed objects only in the periodic summaries (or not at all
//!   where the rule says `log: never`).
//! - `audit` and `learning` are full fidelity: every decision is an event,
//!   whatever its rule's `log` says. Only `ignore` stays silent.
//! - A `learning` decision that is a learning candidate
//!   ([`Decision::learning_candidate`]) is an event with the object's full
//!   facts, for the recommendation pipeline (#5).
//! - A block keeps its rule's `log`, which validation only allows to be
//!   `always` or `sampled` on a deny, so every block is loggable. The
//!   implicit deny logs `always`.
//! - The use of an override session is always an event (#9).
//!
//! A relaxed or overridden block keeps the deciding rule's effects, so the
//! event's severity, tags and upload timing are the rule's.

use serde::Serialize;

use crate::decision::{Decision, Outcome};
use crate::model::{LogLevel, Mode};

/// How a decision is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Report {
    /// Not at all.
    None,
    /// Counted in the periodic summary per device, user, object and rule.
    Summary,
    /// A sample of such decisions produces events.
    Sampled,
    /// A full event for this decision.
    Event,
}

/// What the agent reports for one decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct EventFidelity {
    /// How the decision is reported.
    pub report: Report,
    /// The event carries the object's full facts, as a learning candidate
    /// (#5). Only with [`Report::Event`].
    pub learning_candidate: bool,
}

impl EventFidelity {
    const fn just(report: Report) -> Self {
        Self {
            report,
            learning_candidate: false,
        }
    }
}

const fn of_log(log: LogLevel) -> Report {
    match log {
        LogLevel::Always => Report::Event,
        LogLevel::Sampled => Report::Sampled,
        LogLevel::Summary => Report::Summary,
        LogLevel::Never => Report::None,
    }
}

/// How the result of `evaluate_in` is reported: `None` (a disabled device)
/// reports nothing. See the module documentation.
#[must_use]
pub fn fidelity(decision: Option<&Decision>) -> EventFidelity {
    let Some(d) = decision else {
        return EventFidelity::just(Report::None);
    };
    let log = of_log(d.effects().log);
    let report = match d.outcome() {
        Outcome::Ignored => Report::None,
        Outcome::Blocked => log,
        Outcome::AllowedAudit | Outcome::AllowedOverride => Report::Event,
        Outcome::Allowed => match d.mode() {
            Mode::Enforce => log,
            Mode::Monitor => match log {
                Report::None => Report::None,
                Report::Summary | Report::Sampled | Report::Event => Report::Summary,
            },
            Mode::Audit | Mode::Learning => Report::Event,
            // `evaluate_in` never decides in `disabled`; if a decision
            // claims it anyway, report it rather than drop it.
            Mode::Disabled => Report::Event,
        },
    };
    EventFidelity {
        report,
        learning_candidate: report == Report::Event && d.learning_candidate(),
    }
}
