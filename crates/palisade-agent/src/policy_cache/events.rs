//! The policy-integrity events (#326, event types from #303), and the sink
//! they go to until the event pipeline (#63) exists.
//!
//! The cache never waits on a sink: [`PolicyEventSink::emit`] must not
//! block, and a sink that is full drops the event and counts it. The
//! pipeline (#63) will implement the trait and forward to the server;
//! [`BoundedSink`] keeps the events in memory, bounded, until then.

use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use palisade_proto::{
    events::EventType,
    policy_bundle::{
        BundleMeta, Rejection,
        select::{CacheFile, Finding, Load},
        stale::Staleness,
    },
};

/// One policy-integrity event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEvent {
    /// What happened.
    pub detail: Detail,
    /// What runs once it happened.
    pub load: Load,
}

/// What a [`PolicyEvent`] reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detail {
    /// A startup finding (#304). [`Finding::EmergencyLoaded`] is reported as
    /// [`Detail::Emergency`] instead.
    Finding(Finding),
    /// The emergency policy was loaded. `enforced` is `false` under the
    /// `native_only` strategy, where nothing in Palisade's layer enforces
    /// it (ADR 0018).
    Emergency {
        /// Whether a Palisade enforcer applies it.
        enforced: bool,
    },
    /// A bundle was activated (`policy.applied`).
    Applied(BundleMeta),
    /// A downloaded bundle was refused.
    Rejected(Rejection),
    /// The running policy became stale (`policy.stale`).
    Stale(Staleness),
    /// Periodic re-verification found the running policy or its cache file
    /// changed (`agent.tamper`).
    Tamper(Tamper),
}

/// What re-verification found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tamper {
    /// The policy in memory no longer matches its verified bytes, or no
    /// longer verifies against the trust set. It was reloaded from the
    /// cache.
    Memory,
    /// The cache file the running policy came from changed, went missing
    /// or cannot be read. It was rewritten from the verified copy in
    /// memory, which keeps running.
    File(CacheFile),
}

impl PolicyEvent {
    /// The event type (#303).
    pub const fn event_type(&self) -> EventType {
        match &self.detail {
            Detail::Finding(f) => f.event_type(),
            Detail::Emergency { .. } => EventType::PolicyEmergencyLoaded,
            Detail::Applied(_) => EventType::PolicyApplied,
            Detail::Rejected(r) => r.event_type(),
            Detail::Stale(_) => EventType::PolicyStale,
            Detail::Tamper(_) => EventType::AgentTamper,
        }
    }

    /// Whether it is critical: anything that suggests tampering, or that
    /// the device no longer runs the policy it was given.
    pub const fn critical(&self) -> bool {
        matches!(
            self.detail,
            Detail::Finding(Finding::LkgLoaded | Finding::RollbackSuspected(_))
                | Detail::Emergency { .. }
                | Detail::Tamper(_)
        )
    }
}

/// Where policy events go. Must not block.
pub trait PolicyEventSink: Send + Sync + fmt::Debug {
    /// Takes one event. Returns `false` if it was dropped.
    fn emit(&self, event: PolicyEvent) -> bool;
}

/// A bounded in-memory queue of events, for until #63. When full, it drops
/// the new event and counts it, so the first events (the ones closest to
/// what went wrong) are kept.
#[derive(Debug)]
pub struct BoundedSink {
    queue: Mutex<VecDeque<PolicyEvent>>,
    capacity: usize,
    dropped: AtomicU64,
}

impl BoundedSink {
    /// The default capacity.
    pub const DEFAULT_CAPACITY: usize = 256;

    /// A queue holding at most `capacity` events (at least 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<PolicyEvent>> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes every queued event, oldest first.
    pub fn drain(&self) -> Vec<PolicyEvent> {
        self.queue().drain(..).collect()
    }

    /// How many events were dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Default for BoundedSink {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl PolicyEventSink for BoundedSink {
    fn emit(&self, event: PolicyEvent) -> bool {
        tracing::event!(
            tracing::Level::WARN,
            event = event.event_type().as_str(),
            critical = event.critical(),
            detail = ?event.detail,
            "policy event"
        );
        let mut queue = self.queue();
        if queue.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        queue.push_back(event);
        true
    }
}

#[cfg(test)]
mod tests {
    use palisade_proto::policy_bundle::select::Suspicion;

    use super::*;

    fn event(detail: Detail) -> PolicyEvent {
        PolicyEvent {
            detail,
            load: Load::Emergency,
        }
    }

    #[test]
    fn each_detail_names_its_event_type_and_severity() {
        let cases = [
            (
                Detail::Finding(Finding::LkgLoaded),
                EventType::PolicyLkgLoaded,
                true,
            ),
            (
                Detail::Finding(Finding::RollbackSuspected(Suspicion {
                    copies_disagree: true,
                    ..Suspicion::default()
                })),
                EventType::TamperPolicyRollbackSuspected,
                true,
            ),
            (
                Detail::Finding(Finding::LoadedUnsigned),
                EventType::PolicySignatureInvalid,
                false,
            ),
            (
                Detail::Emergency { enforced: false },
                EventType::PolicyEmergencyLoaded,
                true,
            ),
            (
                Detail::Rejected(Rejection::Rollback),
                EventType::PolicyRollbackRejected,
                false,
            ),
            (Detail::Tamper(Tamper::Memory), EventType::AgentTamper, true),
            (
                Detail::Tamper(Tamper::File(CacheFile::Active)),
                EventType::AgentTamper,
                true,
            ),
        ];
        for (detail, ty, critical) in cases {
            let e = event(detail);
            assert_eq!(e.event_type(), ty, "{e:?}");
            assert_eq!(e.critical(), critical, "{e:?}");
        }
    }

    #[test]
    fn a_full_sink_drops_new_events_and_counts_them() {
        let sink = BoundedSink::new(0);
        assert!(sink.emit(event(Detail::Tamper(Tamper::Memory))));
        assert!(!sink.emit(event(Detail::Emergency { enforced: true })));
        assert_eq!(sink.dropped(), 1);
        assert_eq!(sink.drain(), [event(Detail::Tamper(Tamper::Memory))]);
        assert!(sink.drain().is_empty());
        assert!(sink.emit(event(Detail::Emergency { enforced: true })));
        assert_eq!(
            BoundedSink::default().capacity,
            BoundedSink::DEFAULT_CAPACITY
        );
    }
}
