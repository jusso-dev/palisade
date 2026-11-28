//! The pipeline itself: one event in, spooled events out (#63, #197).
//!
//! [`Pipeline::submit`] takes a canonical event from a producer and:
//!
//! 1. stamps the envelope the agent owns ([`Identity`]: tenant, host,
//!    event ID, monotonic time, clock state);
//! 2. classifies it ([`classify`]) and asks the [`Throttle`];
//! 3. passes it through the [`Aggregator`] (summary, first-seen or
//!    de-duplication), which may hold it in an aggregate;
//! 4. numbers and chains what is kept ([`Chainer`]) and appends it to the
//!    [`Spool`]. Priority events are synced at once; the rest at the next
//!    [`Pipeline::tick`] (every 250 ms in the subsystem), so a crash loses
//!    at most that batch (#63).
//!
//! Every loss (a full producer queue, the throttle, the spool's caps or a
//! failed write) is counted per class and reason and reported by
//! [`Pipeline::tick`] as an `agent.dropped` event with `agent.losses`,
//! which is itself security class and so never evicted while there is room.
//! Throttle changes are reported as `agent.throttled`. A loss is never
//! silent (ADR 0018).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use palisade_proto::events::{
    AgentInfo, BoundedVec, Description, Event, EventType, Host, Loss, LossClass, LossReason,
    Outcome, TenantId, Timestamp, Token, Uuid7,
};

use super::aggregate::{AggregateSettings, Aggregator, Disposition, classify};
use super::chain::Chainer;
use super::segment::{Class, StoredRecord};
use super::spool::{DropReason, Dropped, Recovery, Spool, SpoolStats};
use super::throttle::{Admit, Throttle, ThrottleSettings, Transition};

/// What the agent stamps on every event it produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The tenant, from enrolment.
    pub tenant: TenantId,
    /// The device, from enrolment.
    pub host: Host,
}

impl Identity {
    /// The identity before enrolment (#62): the nil-like tenant and host
    /// IDs `…7000-8000-000000000000`. Events are spooled under it and
    /// re-stamped by nothing: the server attributes them by the device
    /// certificate of the connection that uploads them.
    #[must_use]
    pub fn unenrolled() -> Self {
        let id = super::fixed_uuid(0);
        Self {
            tenant: TenantId(id),
            host: Host {
                id: palisade_proto::events::HostId(id),
                name: None,
                fqdn: None,
                domain: None,
                os: None,
                os_build: None,
                arch: None,
                agent_version: palisade_proto::events::Name::new(env!("CARGO_PKG_VERSION")).ok(),
                ips: BoundedVec::default(),
                groups: BoundedVec::default(),
            },
        }
    }
}

/// Event IDs: UUIDv7 from the time, a per-boot random prefix and a
/// counter, so IDs are unique without a random number per event.
#[derive(Clone, Debug)]
pub struct EventIds {
    salt: [u8; 4],
    counter: u32,
}

impl EventIds {
    /// IDs salted with `salt` (random per agent start).
    #[must_use]
    pub const fn new(salt: [u8; 4]) -> Self {
        Self { salt, counter: 0 }
    }

    /// The next ID, for an event at `ts`.
    pub fn next(&mut self, ts: Timestamp) -> Uuid7 {
        self.counter = self.counter.wrapping_add(1);
        let millis = u64::try_from(ts.unix_micros().div_euclid(1000)).unwrap_or(0);
        let mut b = [0u8; 16];
        let m = millis.to_be_bytes();
        b[..6].copy_from_slice(&m[2..]);
        let c = self.counter.to_be_bytes();
        b[6] = 0x70 | (c[0] & 0x0f);
        b[7] = c[1];
        b[8] = 0x80 | (c[2] & 0x3f);
        b[9] = c[3];
        b[10..14].copy_from_slice(&self.salt);
        b[14] = c[0] >> 4;
        b[15] = c[2] >> 6;
        // Version 7 and the RFC 9562 variant are set above, so this always
        // succeeds; the fallback only keeps the code panic-free.
        Uuid7::from_bytes(b).unwrap_or(super::fixed_uuid(0))
    }
}

/// The clock state stamped on events.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClockState {
    /// Whether the wall clock is believed synchronised. `false` after a
    /// detected jump until the next server check-in corrects it.
    pub synced: bool,
    /// The last measured offset to the server, in milliseconds.
    pub skew_ms: Option<i64>,
}

/// Pipeline settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipelineSettings {
    /// Summaries and de-duplication.
    pub aggregate: AggregateSettings,
    /// The per-agent quota.
    pub throttle: ThrottleSettings,
}

/// Counters for health and metrics (#63).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Events submitted, per class.
    pub submitted: BTreeMap<Class, u64>,
    /// Events spooled.
    pub spooled: u64,
    /// Events lost, in every class and for every reason, since start.
    pub lost: u64,
    /// Events not reported because allowed mode is `off`.
    pub suppressed: u64,
    /// Whether the throttle is above its high watermark.
    pub throttling: bool,
    /// Spool errors since start.
    pub spool_errors: u64,
    /// The last spool error.
    pub last_error: Option<String>,
}

fn loss_class(class: Class) -> LossClass {
    match class {
        Class::Diagnostic => LossClass::Diagnostic,
        Class::Summary => LossClass::Summary,
        Class::Allowed => LossClass::Allowed,
        Class::Info => LossClass::Info,
        Class::Audit => LossClass::Audit,
        Class::Blocked => LossClass::Blocked,
        Class::Security => LossClass::Security,
    }
}

const fn loss_reason(reason: DropReason) -> LossReason {
    match reason {
        DropReason::SpoolFull => LossReason::SpoolFull,
        DropReason::Expired => LossReason::Expired,
        DropReason::Corrupt => LossReason::Corrupt,
    }
}

/// Losses waiting to be reported, merged by class and reason.
#[derive(Clone, Debug, Default)]
struct Losses(BTreeMap<(Class, LossReasonKey), Pending>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum LossReasonKey {
    QueueFull,
    Throttled,
    SpoolFull,
    Expired,
    Corrupt,
}

impl LossReasonKey {
    const fn of(reason: LossReason) -> Self {
        match reason {
            LossReason::QueueFull => Self::QueueFull,
            LossReason::Throttled => Self::Throttled,
            LossReason::SpoolFull => Self::SpoolFull,
            LossReason::Expired => Self::Expired,
            LossReason::Corrupt => Self::Corrupt,
        }
    }

    const fn reason(self) -> LossReason {
        match self {
            Self::QueueFull => LossReason::QueueFull,
            Self::Throttled => LossReason::Throttled,
            Self::SpoolFull => LossReason::SpoolFull,
            Self::Expired => LossReason::Expired,
            Self::Corrupt => LossReason::Corrupt,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Pending {
    count: u64,
    seqs: Option<(u64, u64)>,
}

impl Losses {
    fn add(&mut self, class: Class, reason: LossReason, count: u64, seqs: Option<(u64, u64)>) {
        if count == 0 {
            return;
        }
        let p = self
            .0
            .entry((class, LossReasonKey::of(reason)))
            .or_default();
        p.count = p.count.saturating_add(count);
        if let Some((from, to)) = seqs {
            p.seqs = Some(p.seqs.map_or((from, to), |(f, t)| (f.min(from), t.max(to))));
        }
    }

    fn total(&self) -> u64 {
        self.0.values().map(|p| p.count).sum()
    }

    /// Up to 16 entries for `agent.losses`, merging the rest into the last.
    fn take(&mut self) -> Vec<Loss> {
        let mut out: Vec<Loss> = Vec::new();
        for ((class, reason), p) in std::mem::take(&mut self.0) {
            let Some(count) = NonZeroU64::new(p.count) else {
                continue;
            };
            out.push(Loss {
                class: loss_class(class),
                reason: reason.reason(),
                count,
                from_seq: p.seqs.map(|s| s.0),
                to_seq: p.seqs.map(|s| s.1),
            });
        }
        // 7 classes × 5 reasons can exceed 16: keep the highest classes
        // apart, and report the lowest ones' counts in what is kept.
        while out.len() > 16 {
            if let Some(extra) = out.first().cloned() {
                out.remove(0);
                if let Some(first) = out.first_mut() {
                    first.count = first.count.saturating_add(extra.count.get());
                    first.from_seq = None;
                    first.to_seq = None;
                }
            }
        }
        out
    }
}

/// A new event of `ty` with no field sets: the envelope is completed by
/// the pipeline. `None` if `action` or `description` is not valid.
#[must_use]
pub fn new_event(
    ty: EventType,
    outcome: Outcome,
    action: &str,
    description: &str,
    ts: Timestamp,
) -> Option<Event> {
    let identity = Identity::unenrolled();
    Some(Event {
        schema_version: palisade_proto::events::CURRENT,
        event_id: super::fixed_uuid(0),
        event_type: ty,
        category: ty.category(),
        action: action.parse::<Token>().ok()?,
        outcome,
        severity: ty.default_severity(),
        mode: None,
        description: Description::new(description).ok()?,
        ts,
        ts_agent_monotonic: None,
        clock_synced: true,
        clock_skew_ms: None,
        tenant_id: identity.tenant,
        host: identity.host,
        user: None,
        policy: None,
        seq: 0,
        prev_hash: None,
        labels: palisade_proto::events::Labels::default(),
        source: None,
        process: None,
        file: None,
        script: None,
        native: None,
        agent: None,
        network: None,
        device: None,
        registry: None,
        elevation: None,
        approval: None,
        admin: None,
        identity: None,
        audit_policy: None,
        restriction: None,
        probe: None,
        fim: None,
        aggregate: None,
    })
}

/// The pipeline.
pub struct Pipeline {
    identity: Identity,
    ids: EventIds,
    clock: ClockState,
    aggregator: Aggregator,
    throttle: Throttle,
    chainer: Chainer,
    spool: Box<dyn Spool>,
    losses: Losses,
    stats: PipelineStats,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("head", &self.chainer.head().map(|h| h.0))
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Pipeline {
    /// A pipeline over `spool`, which was opened with `recovery`. Damage
    /// the spool found is reported as a loss (and a tamper finding when
    /// the state was damaged) at the first tick.
    #[must_use]
    pub fn new(
        identity: Identity,
        settings: PipelineSettings,
        spool: Box<dyn Spool>,
        recovery: &Recovery,
        salt: [u8; 4],
    ) -> Self {
        let mut pipeline = Self {
            identity,
            ids: EventIds::new(salt),
            clock: ClockState {
                synced: true,
                skew_ms: None,
            },
            aggregator: Aggregator::new(settings.aggregate),
            throttle: Throttle::new(settings.throttle),
            chainer: Chainer::resume(spool.head()),
            spool,
            losses: Losses::default(),
            stats: PipelineStats::default(),
        };
        for d in &recovery.damaged {
            // The records cut off are unknown in number: at least one.
            pipeline.losses.add(
                d.segment.class,
                LossReason::Corrupt,
                1,
                d.last_kept
                    .map(|s| (s.saturating_add(1), s.saturating_add(1))),
            );
        }
        pipeline
    }

    /// Changes the settings (a new policy). Open aggregates are flushed
    /// into the spool first.
    pub fn reconfigure(&mut self, settings: PipelineSettings, now: Timestamp, monotonic: u64) {
        for e in self.aggregator.reconfigure(settings.aggregate) {
            let e = self.envelope(e, monotonic);
            self.keep(e, now);
        }
        self.throttle = Throttle::new(settings.throttle);
    }

    /// Sets the clock state stamped on later events.
    pub fn set_clock(&mut self, clock: ClockState) {
        self.clock = clock;
    }

    /// Sets the identity stamped on later events (enrolment, #62).
    pub fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }

    /// Records losses that happened before the pipeline: a producer whose
    /// queue was full.
    pub fn record_queue_loss(&mut self, class: Class, count: u64) {
        self.losses.add(class, LossReason::QueueFull, count, None);
        self.stats.lost = self.stats.lost.saturating_add(count);
    }

    /// Stamps what the agent owns on `event`.
    fn envelope(&mut self, mut event: Event, monotonic: u64) -> Event {
        event.event_id = self.ids.next(event.ts);
        event.tenant_id = self.identity.tenant;
        // Keep what the producer knew about the host only where the
        // agent's own identity has nothing.
        let host = self.identity.host.clone();
        event.host = Host {
            name: host.name.or(event.host.name),
            fqdn: host.fqdn.or(event.host.fqdn),
            domain: host.domain.or(event.host.domain),
            os: host.os.or(event.host.os),
            os_build: host.os_build.or(event.host.os_build),
            arch: host.arch.or(event.host.arch),
            agent_version: host.agent_version.or(event.host.agent_version),
            ..host
        };
        event.ts_agent_monotonic = Some(monotonic);
        event.clock_synced = self.clock.synced;
        event.clock_skew_ms = self.clock.skew_ms;
        event.schema_version = event.schema_version.max(event.min_version());
        event
    }

    /// Takes one event from a producer, at monotonic time `monotonic`
    /// (microseconds since the agent started).
    pub fn submit(&mut self, event: Event, monotonic: u64) {
        let event = self.envelope(event, monotonic);
        let class = classify(&event);
        *self.stats.submitted.entry(class).or_default() += 1;
        let ts = event.ts;
        if self.throttle.admit(class, ts.unix_micros()) == Admit::Drop {
            self.losses.add(class, LossReason::Throttled, 1, None);
            self.stats.lost = self.stats.lost.saturating_add(1);
            return;
        }
        match self.aggregator.offer(event, self.throttle.is_throttling()) {
            Disposition::Forward(event) => self.keep(*event, ts),
            Disposition::Folded => {}
            Disposition::Suppressed => {
                self.stats.suppressed = self.stats.suppressed.saturating_add(1);
            }
        }
    }

    /// Numbers, chains and spools one event.
    fn keep(&mut self, event: Event, now: Timestamp) {
        let class = classify(&event);
        let mut chainer = self.chainer;
        let stamped = match chainer.stamp(event) {
            Ok(s) => s,
            Err(e) => {
                self.spool_error(class, &e.to_string());
                return;
            }
        };
        let record = StoredRecord {
            seq: stamped.event.seq,
            class,
            time: now.unix_micros(),
            chain: stamped.chain,
            payload: stamped.canonical,
        };
        match self.spool.append(record) {
            Ok(appended) => {
                // The number is issued even when the record was refused.
                self.chainer = chainer;
                for d in &appended.dropped {
                    self.spool_dropped(d);
                }
                if appended.stored {
                    self.stats.spooled = self.stats.spooled.saturating_add(1);
                    if class.is_priority()
                        && let Err(e) = self.spool.sync()
                    {
                        self.spool_error(class, &e.to_string());
                    }
                }
            }
            Err(e) => {
                // Not stored and not issued: the next event takes the
                // number, so the chain has no gap.
                self.spool_error(class, &e.to_string());
            }
        }
    }

    fn spool_dropped(&mut self, d: &Dropped) {
        self.losses.add(
            d.class,
            loss_reason(d.reason),
            d.count,
            Some((d.from_seq, d.to_seq)),
        );
        self.stats.lost = self.stats.lost.saturating_add(d.count);
    }

    fn spool_error(&mut self, class: Class, error: &str) {
        self.losses.add(class, LossReason::Corrupt, 1, None);
        self.stats.lost = self.stats.lost.saturating_add(1);
        self.stats.spool_errors = self.stats.spool_errors.saturating_add(1);
        if self.stats.last_error.as_deref() != Some(error) {
            tracing::error!(
                error,
                ?class,
                "the event spool failed; the event is lost and reported"
            );
        }
        self.stats.last_error = Some(error.to_owned());
    }

    /// An agent event the pipeline raises itself.
    fn agent_event(
        &self,
        ty: EventType,
        now: Timestamp,
        description: &str,
        agent: AgentInfo,
    ) -> Option<Event> {
        let mut event = new_event(ty, Outcome::Info, "report", description, now)?;
        event.clock_synced = self.clock.synced;
        event.tenant_id = self.identity.tenant;
        event.host = self.identity.host.clone();
        event.agent = Some(agent);
        Some(event)
    }

    /// Periodic work at wall time `now` and monotonic time `monotonic`:
    /// emits due aggregates, reports throttle changes and losses, expires
    /// old events and syncs the spool.
    pub fn tick(&mut self, now: Timestamp, monotonic: u64) {
        for e in self.aggregator.tick(now.unix_micros()) {
            let e = self.envelope(e, monotonic);
            self.keep(e, now);
        }
        match self.spool.expire(now.unix_micros()) {
            Ok(dropped) => {
                for d in &dropped {
                    self.spool_dropped(d);
                }
            }
            Err(e) => self.spool_error(Class::Diagnostic, &e.to_string()),
        }
        // Throttle drops are counted per event in `submit`.
        let _ = self.throttle.take_dropped();
        for t in self.throttle.take_transitions() {
            let (text, throttled) = match t {
                Transition::Throttling => (
                    "The event rate crossed the high watermark; allowed events are summarised.",
                    Some(self.throttle.count_last_hour()),
                ),
                Transition::Normal => ("The event rate is back below the low watermark.", Some(0)),
                Transition::Exceeded => (
                    "The event quota was exceeded by events that are never dropped; they are kept.",
                    Some(self.throttle.count_last_hour()),
                ),
            };
            let agent = AgentInfo {
                throttled_count: throttled,
                ..AgentInfo::default()
            };
            if let Some(e) = self.agent_event(EventType::AgentThrottled, now, text, agent) {
                let e = self.envelope(e, monotonic);
                self.keep(e, now);
            }
        }
        self.stats.throttling = self.throttle.is_throttling();
        self.report_losses(now, monotonic);
        if let Err(e) = self.spool.sync() {
            self.spool_error(Class::Diagnostic, &e.to_string());
        }
    }

    fn report_losses(&mut self, now: Timestamp, monotonic: u64) {
        // A loss report that is itself lost is folded into the next one,
        // so the loop ends: at most two attempts per tick.
        for _ in 0..2 {
            let total = self.losses.total();
            if total == 0 {
                return;
            }
            let losses = self.losses.take();
            let agent = AgentInfo {
                dropped_count: Some(total),
                losses: BoundedVec::new(losses).unwrap_or_default(),
                ..AgentInfo::default()
            };
            let text = format!("The agent lost {total} events; see agent.losses.");
            if let Some(e) = self.agent_event(EventType::AgentDropped, now, &text, agent) {
                let e = self.envelope(e, monotonic);
                self.keep(e, now);
            }
        }
    }

    /// Emits every open aggregate and syncs, as on shutdown.
    pub fn flush(&mut self, now: Timestamp, monotonic: u64) {
        for e in self.aggregator.flush_all() {
            let e = self.envelope(e, monotonic);
            self.keep(e, now);
        }
        self.tick(now, monotonic);
    }

    /// The spool, for delivery.
    pub fn spool_mut(&mut self) -> &mut dyn Spool {
        self.spool.as_mut()
    }

    /// The counters.
    #[must_use]
    pub fn stats(&self) -> &PipelineStats {
        &self.stats
    }

    /// The spool's counters.
    #[must_use]
    pub fn spool_stats(&self) -> SpoolStats {
        self.spool.stats()
    }

    /// The aggregator's counters.
    #[must_use]
    pub fn aggregate_stats(&self) -> super::aggregate::AggregateStats {
        self.aggregator.stats()
    }
}

#[cfg(test)]
mod tests;
