//! Where producers hand events to the pipeline (#63, #197).
//!
//! [`Intake`] is a cheap, cloneable handle with two bounded queues: one
//! for priority events (security, blocked, audited) and one for the rest,
//! so a flood of process or allowed events never fills the queue a tamper
//! or block event needs. Offering never blocks the producer. An event that
//! does not fit is counted per class and reported by the pipeline as a
//! `queue_full` loss: never silent.
//!
//! The producers' sink traits are implemented on [`Intake`]:
//!
//! - the process monitor (#59): [`TelemetrySink`]. A process start becomes
//!   a `process.created` event. Stops, image loads and parent-spoof
//!   signals have no canonical event type yet (their identity and audit
//!   evaluation is #59's remaining work), so they are counted as
//!   `unmapped`, not as losses;
//! - event-log ingest (#58): [`EventSink`] and [`EnvelopeSource`];
//! - the policy cache (#61, #326): [`PolicyEventSink`].
//!
//! Inventory (#60) keeps its own store and is not an event stream here.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use palisade_proto::events::{Event, EventType, Labels, Outcome, PolicyRef, Sid, Timestamp, User};
use palisade_proto::mapping::Envelope;
use palisade_proto::policy_bundle::select::{Finding, Load};

use super::aggregate::classify;
use super::core::{Identity, new_event};
use super::segment::Class;
use crate::eventlog::ingest::{EnvelopeSource, EventSink};
use crate::policy_cache::{Detail, PolicyEvent, PolicyEventSink, Tamper};
use crate::telemetry::output::{TelemetryEvent, TelemetrySink, start_fields};

/// The default size of the priority queue.
pub const PRIORITY_CAPACITY: usize = 10_000;
/// The default size of the bulk queue: #59's identity queue size.
pub const BULK_CAPACITY: usize = 50_000;

#[derive(Debug)]
struct Shared {
    priority: SyncSender<Event>,
    bulk: SyncSender<Event>,
    refused: [AtomicU64; 7],
    unmapped: AtomicU64,
}

/// The producers' handle on the pipeline.
#[derive(Clone, Debug)]
pub struct Intake(Arc<Shared>);

/// The pipeline's end of the queues.
#[derive(Debug)]
pub struct Outlet {
    priority: Receiver<Event>,
    bulk: Receiver<Event>,
    shared: Arc<Shared>,
}

/// A pair of queues holding at most `priority` and `bulk` events.
#[must_use]
pub fn channel(priority: usize, bulk: usize) -> (Intake, Outlet) {
    let (ptx, prx) = sync_channel(priority);
    let (btx, brx) = sync_channel(bulk);
    let shared = Arc::new(Shared {
        priority: ptx,
        bulk: btx,
        refused: Default::default(),
        unmapped: AtomicU64::new(0),
    });
    (
        Intake(Arc::clone(&shared)),
        Outlet {
            priority: prx,
            bulk: brx,
            shared,
        },
    )
}

impl Intake {
    /// Offers a canonical event. Returns `false`, and counts it, if its
    /// queue is full or the pipeline has stopped.
    pub fn offer(&self, event: Event) -> bool {
        let class = classify(&event);
        let queue = if class.is_priority() {
            &self.0.priority
        } else {
            &self.0.bulk
        };
        match queue.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                if let Some(c) = self.0.refused.get(usize::from(class.code())) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
                false
            }
        }
    }

    /// Process-monitor events with no canonical type yet.
    #[must_use]
    pub fn unmapped(&self) -> u64 {
        self.0.unmapped.load(Ordering::Relaxed)
    }
}

impl Outlet {
    /// The next event, priority first, waiting at most `timeout` when both
    /// queues are empty. `None` on timeout, or when every producer is gone.
    pub fn recv(&self, timeout: std::time::Duration) -> Option<Event> {
        if let Ok(e) = self.priority.try_recv() {
            return Some(e);
        }
        if let Ok(e) = self.bulk.try_recv() {
            return Some(e);
        }
        // Wait on the bulk queue (the busy one), then look at priority
        // again; a priority event waits at most one timeout.
        match self.bulk.recv_timeout(timeout) {
            Ok(e) => Some(e),
            Err(_) => self.priority.try_recv().ok(),
        }
    }

    /// Events refused since the last call, per class.
    pub fn take_refused(&self) -> Vec<(Class, u64)> {
        Class::ALL
            .into_iter()
            .filter_map(|c| {
                let n = self
                    .shared
                    .refused
                    .get(usize::from(c.code()))?
                    .swap(0, Ordering::Relaxed);
                (n > 0).then_some((c, n))
            })
            .collect()
    }
}

fn timestamp(micros: i64) -> Timestamp {
    Timestamp::from_unix_micros(micros).unwrap_or(Timestamp::MIN)
}

impl TelemetrySink for Intake {
    fn offer(&self, event: TelemetryEvent) -> bool {
        match event {
            TelemetryEvent::ProcessStart { process, ancestry } => {
                let Some(mut e) = new_event(
                    EventType::ProcessCreated,
                    Outcome::Info,
                    "create",
                    "A process was created.",
                    timestamp(process.key.created.0),
                ) else {
                    return false;
                };
                e.process = Some(start_fields(&process, ancestry.first().copied()));
                e.user = process
                    .token
                    .user_sid
                    .as_deref()
                    .and_then(|s| s.parse::<Sid>().ok())
                    .map(|sid| User {
                        sid: Some(sid),
                        session_id: process.session_id,
                        elevated: process.token.elevated,
                        ..User::default()
                    });
                Self::offer(self, e)
            }
            TelemetryEvent::ProcessStop { .. }
            | TelemetryEvent::ImageLoad(_)
            | TelemetryEvent::ParentSpoof { .. } => {
                self.0.unmapped.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }
}

impl EventSink for Intake {
    fn offer(&mut self, event: Event) -> bool {
        Self::offer(self, event)
    }
}

/// Envelopes for event-log ingest: placeholders the pipeline replaces.
/// Mapping needs an envelope to build a valid event; the pipeline owns the
/// real one (ID, sequence number, chain, tenant and host).
impl EnvelopeSource for Intake {
    fn next(&mut self) -> Envelope {
        let identity = Identity::unenrolled();
        Envelope {
            event_id: super::fixed_uuid(0),
            tenant_id: identity.tenant,
            host: identity.host,
            seq: 0,
            prev_hash: None,
            clock_synced: true,
            ts_agent_monotonic: None,
            clock_skew_ms: None,
            labels: Labels::default(),
        }
    }
}

/// A clock for policy events: they carry no time of their own.
pub trait WallClock: Send + Sync + std::fmt::Debug {
    /// Now, in microseconds since the epoch.
    fn now_micros(&self) -> i64;
}

/// The policy cache's sink: converts each [`PolicyEvent`] to a canonical
/// event and offers it.
#[derive(Debug)]
pub struct PolicySink {
    intake: Intake,
    clock: Box<dyn WallClock>,
}

impl PolicySink {
    /// A sink offering to `intake`, timed by `clock`.
    #[must_use]
    pub fn new(intake: Intake, clock: Box<dyn WallClock>) -> Self {
        Self { intake, clock }
    }
}

fn policy_ref(load: &Load) -> PolicyRef {
    match load {
        Load::Active { bundle, .. } | Load::Previous(bundle) => PolicyRef {
            version: Some(bundle.version),
            hash: Some(bundle.sha256),
            ..PolicyRef::default()
        },
        Load::Emergency | Load::FirstInstall => PolicyRef::default(),
    }
}

/// The canonical form of a policy event.
#[must_use]
pub fn policy_event(event: &PolicyEvent, ts: Timestamp) -> Option<Event> {
    let ty = event.event_type();
    let description = match &event.detail {
        Detail::Finding(Finding::Rejected { .. }) => "A cached policy bundle was not loaded.",
        Detail::Finding(Finding::LoadedUnsigned) => {
            "A policy bundle with an invalid signature was loaded, as the signature mode allows."
        }
        Detail::Finding(Finding::LkgLoaded) => {
            "The last known good policy was loaded because the current one failed."
        }
        Detail::Finding(Finding::EmergencyLoaded) | Detail::Emergency { enforced: true } => {
            "The built-in emergency policy was loaded and is enforced."
        }
        Detail::Emergency { enforced: false } => {
            "The built-in emergency policy was loaded but is not enforced (native only)."
        }
        Detail::Finding(Finding::RollbackSuspected(_)) => {
            "The policy anti-rollback record is missing, damaged or inconsistent."
        }
        Detail::Applied(_) => "A policy bundle was applied.",
        Detail::Rejected(_) => "A downloaded policy bundle was refused.",
        Detail::Stale(_) => "The running policy is stale; it is still enforced.",
        Detail::Tamper(Tamper::Memory) => {
            "The policy in memory changed or no longer verifies; it was reloaded."
        }
        Detail::Tamper(Tamper::File(_)) => {
            "A policy cache file changed or went missing; it was rewritten."
        }
    };
    let action = match &event.detail {
        Detail::Applied(_) => "apply",
        Detail::Rejected(_) | Detail::Finding(Finding::Rejected { .. }) => "reject",
        Detail::Tamper(_) => "verify",
        _ => "load",
    };
    let mut e = new_event(ty, Outcome::Info, action, description, ts)?;
    let mut policy = policy_ref(&event.load);
    if let Detail::Applied(meta) = &event.detail {
        policy.version = Some(meta.version);
        policy.hash = Some(meta.sha256);
    }
    e.policy = Some(policy);
    if e.event_type
        .required()
        .contains(&palisade_proto::events::FieldSet::Agent)
    {
        e.agent = Some(Default::default());
    }
    Some(e)
}

impl PolicyEventSink for PolicySink {
    fn emit(&self, event: PolicyEvent) -> bool {
        tracing::warn!(
            event = event.event_type().as_str(),
            critical = event.critical(),
            detail = ?event.detail,
            "policy event"
        );
        let Some(e) = policy_event(&event, timestamp(self.clock.now_micros())) else {
            return false;
        };
        self.intake.offer(e)
    }
}

#[cfg(test)]
mod tests;
