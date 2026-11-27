//! Enforcement readiness (#41, #36): how many would-block events each
//! device had over a period, and whether a move to `enforce` is safe.
//!
//! A would-block is an event that enforce mode would block but the
//! device's mode let run (`allowed_audit`), recomputed by the simulator
//! from the recorded facts, so it reflects the policy as it is now, not as
//! it was when the event was recorded. An event blocked anyway is not a
//! would-block: enforcing changes nothing for it.
//!
//! [`readiness`] reports, over the events in `[until − days, until)`:
//!
//! - every device, with its would-block count, ready when the count is at
//!   most `max_would_block`;
//! - the objects with the most would-blocks, with a draft allow rule for
//!   each (the trace's suggestion; the recommendation flow is #5);
//! - the gate of #36: "N would-block events across M devices in the last D
//!   days", and whether a `readiness_ack` is required before the
//!   transition, which is when N exceeds the configured threshold.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::decision::Outcome;
use crate::evaluate::BuildError;
use crate::validate::ValidatedPolicy;

use super::simulate::{FactsSnapshot, SimError, Simulator, object_key};
use super::{RuleDraft, TraceLevel, TraceOptions};

/// The most top objects listed.
pub const MAX_TOP_OBJECTS: usize = 25;

/// The most devices listed.
pub const MAX_DEVICES: usize = 10_000;

/// What a readiness check counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadinessOptions {
    /// The end of the window, in wall-clock seconds (exclusive).
    pub until: i64,
    /// The window's length, in days.
    pub days: u32,
    /// A device is ready with at most this many would-blocks.
    pub max_would_block: u64,
    /// The gate requires a `readiness_ack` when the total would-block count
    /// is above this. `None`: never required.
    pub ack_threshold: Option<u64>,
    /// How many objects to list.
    pub top_objects: usize,
}

/// One device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceReadiness {
    /// The device.
    pub device_id: String,
    /// Events in the window.
    pub events: u64,
    /// Would-blocks in the window.
    pub would_block: u64,
    /// `would_block <= max_would_block`.
    pub ready: bool,
}

/// One object with would-blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TopObject {
    /// The object: `sha256:…` or `path:…`.
    pub object: String,
    /// Its would-blocks.
    pub would_block: u64,
    /// On how many devices.
    pub devices: u64,
    /// The rule enforce mode would block it by, or `null` for the implicit
    /// deny.
    pub blocked_by: Option<String>,
    /// A draft rule that would allow it, for the recommendation flow (#5).
    pub recommended_rule: Option<RuleDraft>,
}

/// The gate before a move to `enforce` (#36).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadinessGate {
    /// Would-blocks in the window.
    pub would_block_events: u64,
    /// Devices with at least one.
    pub devices_affected: u64,
    /// The window, in days.
    pub days: u32,
    /// A `readiness_ack` is required before the transition.
    pub ack_required: bool,
    /// "N would-block events across M devices in the last D days".
    pub message: String,
}

/// The report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadinessReport {
    /// The window, in wall-clock seconds: `[from, until)`.
    pub window: (i64, i64),
    /// Events in the window.
    pub events: u64,
    /// Events left out: outside the window or without a timestamp.
    pub events_outside_window: u64,
    /// Devices, by device ID.
    pub devices: Vec<DeviceReadiness>,
    /// Devices past [`MAX_DEVICES`].
    pub devices_omitted: u64,
    /// Ready devices.
    pub ready_devices: u64,
    /// The objects with the most would-blocks.
    pub top_objects: Vec<TopObject>,
    /// The gate.
    pub gate: ReadinessGate,
}

/// Checks how ready the devices in `snapshots` are for `enforce` under
/// `policy`.
///
/// # Errors
///
/// [`SimError`] if a snapshot cannot be used or the policy cannot be
/// compiled.
pub fn readiness(
    policy: &ValidatedPolicy,
    snapshots: &[FactsSnapshot],
    options: &ReadinessOptions,
) -> Result<ReadinessReport, SimError> {
    // Every snapshot is checked, inside the window or not, so the result
    // never depends on the window hiding a bad input.
    super::simulate::check_snapshots(snapshots).map_err(SimError::Snapshot)?;
    let sim = Simulator::new(policy).map_err(build)?;
    let from = options
        .until
        .saturating_sub(i64::from(options.days).saturating_mul(86_400));
    let in_window: Vec<&FactsSnapshot> = snapshots
        .iter()
        .filter(|s| s.timestamp.is_some_and(|t| t >= from && t < options.until))
        .collect();
    let owned: Vec<FactsSnapshot> = in_window.iter().map(|s| (*s).clone()).collect();
    let decisions = sim.decide_all(&owned).map_err(SimError::Snapshot)?;

    let mut devices: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut objects: BTreeMap<String, ObjectTally> = BTreeMap::new();
    let mut total = 0u64;
    for (i, (s, d)) in owned.iter().zip(&decisions).enumerate() {
        let device = s
            .device_id
            .clone()
            .unwrap_or_else(|| "(unknown)".to_owned());
        let e = devices.entry(device.clone()).or_default();
        e.0 += 1;
        let would = d
            .as_ref()
            .is_some_and(|d| d.outcome() == Outcome::AllowedAudit && d.would_have_been().stops());
        if would {
            e.1 += 1;
            total += 1;
            let key = object_key(s).unwrap_or_else(|| "(unknown)".to_owned());
            let o = objects
                .entry(key)
                .or_insert_with(|| (0, BTreeSet::new(), None, i));
            o.0 += 1;
            o.1.insert(device);
            if o.2.is_none() {
                o.2 = d
                    .as_ref()
                    .and_then(|d| d.matched_rule())
                    .map(|r| r.rule_id.to_string());
            }
        }
    }
    let affected = devices.values().filter(|(_, w)| *w > 0).count() as u64;
    let ready_devices = devices
        .values()
        .filter(|(_, w)| *w <= options.max_would_block)
        .count() as u64;
    let devices_omitted = devices.len().saturating_sub(MAX_DEVICES) as u64;
    let device_list = devices
        .into_iter()
        .take(MAX_DEVICES)
        .map(|(device_id, (events, would_block))| DeviceReadiness {
            device_id,
            events,
            would_block,
            ready: would_block <= options.max_would_block,
        })
        .collect();

    let mut top: Vec<(String, ObjectTally)> = objects.into_iter().collect();
    top.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
    top.truncate(options.top_objects.min(MAX_TOP_OBJECTS));
    let mut top_objects = Vec::with_capacity(top.len());
    for (object, (would_block, devs, blocked_by, first)) in top {
        let recommended_rule = sim
            .trace(&owned[first], &TraceOptions::at(TraceLevel::Full))
            .ok()
            .and_then(|t| t.allow_suggestion);
        top_objects.push(TopObject {
            object,
            would_block,
            devices: devs.len() as u64,
            blocked_by,
            recommended_rule,
        });
    }
    let ack_required = options.ack_threshold.is_some_and(|t| total > t);
    Ok(ReadinessReport {
        window: (from, options.until),
        events: owned.len() as u64,
        events_outside_window: (snapshots.len() - owned.len()) as u64,
        devices: device_list,
        devices_omitted,
        ready_devices,
        top_objects,
        gate: ReadinessGate {
            would_block_events: total,
            devices_affected: affected,
            days: options.days,
            ack_required,
            message: format!(
                "{total} would-block {} across {affected} {} in the last {} {}",
                if total == 1 { "event" } else { "events" },
                if affected == 1 { "device" } else { "devices" },
                options.days,
                if options.days == 1 { "day" } else { "days" },
            ),
        },
    })
}

/// Per object: would-blocks, devices, the rule that would block it, and
/// the index of its first event.
type ObjectTally = (u64, BTreeSet<String>, Option<String>, usize);

fn build(e: BuildError) -> SimError {
    SimError::Candidate(super::simulate::CandidateError::Build(e))
}
