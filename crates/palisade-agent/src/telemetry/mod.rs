//! Process creation and image-load monitoring (#59).
//!
//! The parts that read untrusted bytes or hold state are portable, have
//! no `unsafe` code, and are tested (and fuzzed) on every OS:
//!
//! - [`kernel`] decodes the kernel process provider's ETW records.
//! - [`tree`] is the process tree, keyed by process ID **and** creation
//!   time, so a reused process ID never corrupts ancestry.
//! - [`cmdline`] captures, redacts and truncates command lines.
//! - [`monitor`] is the state machine that turns records into events.
//! - [`output`] is what it emits: a [`TelemetrySink`](output::TelemetrySink),
//!   which the event pipeline's intake (#63) implements.
//!
//! On Windows, `windows` is the subsystem that runs the ETW session
//! through `ffi::etw` (the agent's allowlisted unsafe module, ADR 0011)
//! and feeds the monitor.

#![forbid(unsafe_code)]

pub mod cmdline;
pub mod kernel;
pub mod monitor;
pub mod output;
pub mod tree;
#[cfg(windows)]
pub mod windows;

use std::sync::Arc;

use output::Counters;

use crate::subsystem::{Health, Subsystem};

/// The subsystem's name.
pub const NAME: &str = "process-monitor";

/// The ETW session's name. There is one per machine; a stale one left by a
/// crash is stopped and started again.
pub const SESSION_NAME: &str = "Palisade-Agent-Trace";

/// The subsystems that read the OS, for the console and service runs. On
/// Windows, the process monitor, whose events go into the event pipeline
/// (#63) through `intake`; events its queue cannot take are counted in the
/// monitor's health and by the pipeline.
#[must_use]
pub fn os_subsystems(intake: crate::pipeline::intake::Intake) -> Vec<Arc<dyn Subsystem>> {
    #[cfg(windows)]
    {
        vec![Arc::new(windows::EtwProcessMonitor::new(
            Arc::new(intake),
            monitor::MonitorSettings::default(),
        ))]
    }
    #[cfg(not(windows))]
    {
        drop(intake);
        Vec::new()
    }
}

/// The monitor's health from its counters: degraded while the OS reports
/// lost events, records are dropped or not decoded, or `status` reports a
/// problem. Losses are always visible, never silent.
#[must_use]
pub fn health_of(counters: &Counters, status: Option<String>) -> Health {
    let mut reasons = Vec::new();
    if let Some(status) = status {
        reasons.push(status);
    }
    for (what, value) in [
        ("events lost by the OS", Counters::get(&counters.os_lost)),
        (
            "records dropped from the queue",
            Counters::get(&counters.queue_dropped),
        ),
        (
            "records not decoded",
            Counters::get(&counters.decode_errors),
        ),
        (
            "events dropped by the sink",
            Counters::get(&counters.dropped),
        ),
    ] {
        if value > 0 {
            reasons.push(format!("{value} {what}"));
        }
    }
    if reasons.is_empty() {
        Health::Healthy
    } else {
        Health::Degraded(reasons.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_oses_have_no_os_subsystems() {
        let (intake, _outlet) = crate::pipeline::intake::channel(1, 1);
        assert_eq!(os_subsystems(intake).len(), usize::from(cfg!(windows)));
    }

    #[test]
    fn health_reports_every_loss() {
        let c = Counters::default();
        assert_eq!(health_of(&c, None), Health::Healthy);
        Counters::bump(&c.os_lost);
        Counters::bump(&c.dropped);
        let Health::Degraded(why) = health_of(&c, Some("query failed".into())) else {
            panic!()
        };
        assert_eq!(
            why,
            "query failed; 1 events lost by the OS; 1 events dropped by the sink"
        );
    }
}
