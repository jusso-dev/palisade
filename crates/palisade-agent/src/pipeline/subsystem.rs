//! The `event-pipeline` subsystem (#63, #197).
//!
//! It opens the spool (on Windows `%ProgramData%\Palisade\spool`, which
//! the installer restricts to SYSTEM; in memory elsewhere, and when that
//! directory cannot be opened, which its health reports), then runs the
//! [`Pipeline`] on a dedicated thread (ADR 0009: no blocking file I/O on
//! the async workers). The thread drains the [`Intake`] queues, ticks the
//! pipeline every [`TICK`] (so a batch is synced at least every 250 ms,
//! #63), and pumps delivery through the [`Uploader`] every
//! [`UPLOAD_INTERVAL`]. On stop it flushes open aggregates and syncs.
//!
//! Producers get an [`Intake`] from [`EventPipeline::intake`] when the
//! host builds them, so they can be constructed before the pipeline runs;
//! events offered before it starts wait in the bounded queues.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use palisade_core::platform::Clock;
use palisade_proto::events::Timestamp;

use super::core::{ClockState, Identity, Pipeline, PipelineSettings, PipelineStats};
use super::intake::{self, Intake, Outlet, WallClock};
use super::spool::{SegmentSpool, Spool, SpoolLimits, SpoolStats, StateStatus};
use super::storage::{FileStorage, MemoryStorage};
use super::upload::{Delivery, DeliverySettings, OfflineUploader, Uploader};
use crate::clock::ClockJump;
use crate::subsystem::{
    BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError,
};

/// How often the pipeline ticks: the longest a non-priority batch waits
/// for its sync.
pub const TICK: Duration = Duration::from_millis(250);
/// How often delivery is attempted.
pub const UPLOAD_INTERVAL: Duration = Duration::from_secs(5);

/// The spool directory on Windows: `%ProgramData%\Palisade\spool`.
/// `None` elsewhere.
///
/// # Errors
///
/// `ProgramData` is unset, empty or relative on Windows.
pub fn spool_dir() -> Result<Option<PathBuf>, crate::config::ConfigError> {
    Ok(crate::config::default_path()?.and_then(|p| p.parent().map(|d| d.join("spool"))))
}

/// A [`WallClock`] over a platform [`Clock`].
#[derive(Debug)]
pub struct ClockAdapter<C>(pub C);

impl<C: Clock + Send + Sync + std::fmt::Debug> WallClock for ClockAdapter<C> {
    fn now_micros(&self) -> i64 {
        self.0.now_utc().0
    }
}

/// What the subsystem shares with its health report.
#[derive(Debug, Default)]
struct Status {
    pipeline: PipelineStats,
    spool: SpoolStats,
    storage: Option<String>,
    state_damaged: bool,
    offline: bool,
}

/// The `event-pipeline` subsystem.
pub struct EventPipeline<C> {
    clock: C,
    settings: PipelineSettings,
    limits: SpoolLimits,
    delivery: DeliverySettings,
    dir: Option<PathBuf>,
    uploader: Arc<dyn Uploader>,
    intake: Intake,
    outlet: Arc<Mutex<Outlet>>,
    status: Arc<Mutex<Status>>,
    clock_jumps: Option<tokio::sync::watch::Receiver<Option<ClockJump>>>,
}

impl<C> std::fmt::Debug for EventPipeline<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventPipeline")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl<C: Clock + Clone + Send + Sync + std::fmt::Debug + 'static> EventPipeline<C> {
    /// The subsystem's name.
    pub const NAME: &'static str = "event-pipeline";

    /// A pipeline spooling to `dir` (in memory when `None`), uploading
    /// through `uploader`.
    #[must_use]
    pub fn new(clock: C, dir: Option<PathBuf>, uploader: Arc<dyn Uploader>) -> Self {
        let (intake, outlet) = intake::channel(intake::PRIORITY_CAPACITY, intake::BULK_CAPACITY);
        Self {
            clock,
            settings: PipelineSettings::default(),
            limits: SpoolLimits::default(),
            delivery: DeliverySettings::default(),
            dir,
            uploader,
            intake,
            outlet: Arc::new(Mutex::new(outlet)),
            status: Arc::new(Mutex::new(Status::default())),
            clock_jumps: None,
        }
    }

    /// The pipeline the agent runs: the platform spool directory, and no
    /// server connection until #62.
    #[must_use]
    pub fn for_platform(clock: C) -> Self {
        let dir = match spool_dir() {
            Ok(dir) => dir,
            Err(e) => {
                tracing::error!(error = %e, "no spool directory; events are kept in memory");
                None
            }
        };
        Self::new(clock, dir, Arc::new(OfflineUploader))
    }

    /// Uses `limits` for the spool.
    #[must_use]
    pub fn with_limits(mut self, limits: SpoolLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Uses `settings` for summaries, de-duplication and the throttle.
    #[must_use]
    pub fn with_settings(mut self, settings: PipelineSettings) -> Self {
        self.settings = settings;
        self
    }

    /// Uses `delivery` for batching and replay.
    #[must_use]
    pub fn with_delivery(mut self, delivery: DeliverySettings) -> Self {
        self.delivery = delivery;
        self
    }

    /// Follows the clock monitor's jumps: events are stamped
    /// `clock_synced: false` after one (ISM-0988).
    #[must_use]
    pub fn with_clock_jumps(
        mut self,
        jumps: tokio::sync::watch::Receiver<Option<ClockJump>>,
    ) -> Self {
        self.clock_jumps = Some(jumps);
        self
    }

    /// The producers' handle.
    #[must_use]
    pub fn intake(&self) -> Intake {
        self.intake.clone()
    }

    /// A policy-event sink offering to this pipeline.
    #[must_use]
    pub fn policy_sink(&self) -> intake::PolicySink {
        intake::PolicySink::new(self.intake(), Box::new(ClockAdapter(self.clock.clone())))
    }

    /// The pipeline's counters.
    #[must_use]
    pub fn stats(&self) -> (PipelineStats, SpoolStats) {
        let s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        (s.pipeline.clone(), s.spool.clone())
    }

    fn open_spool(&self) -> (Box<dyn Spool>, super::spool::Recovery, Option<String>) {
        if let Some(dir) = &self.dir {
            match FileStorage::open(dir)
                .map_err(super::spool::SpoolError::from)
                .and_then(|s| SegmentSpool::open(s, self.limits))
            {
                Ok((spool, recovery)) => return (Box::new(spool), recovery, None),
                Err(e) => {
                    tracing::error!(error = %e, dir = %dir.display(), "cannot open the event spool; events are kept in memory");
                    let why = format!("event spool unavailable ({e}); events are kept in memory");
                    return self.memory_spool(Some(why));
                }
            }
        }
        self.memory_spool(None)
    }

    fn memory_spool(
        &self,
        why: Option<String>,
    ) -> (Box<dyn Spool>, super::spool::Recovery, Option<String>) {
        match SegmentSpool::open(MemoryStorage::default(), self.limits) {
            Ok((spool, recovery)) => (Box::new(spool), recovery, why),
            // Memory storage does not fail to open.
            Err(e) => {
                let recovery = super::spool::Recovery {
                    state: StateStatus::Absent,
                    damaged: Vec::new(),
                    head: None,
                    pending: 0,
                };
                (Box::new(NullSpool), recovery, Some(e.to_string()))
            }
        }
    }
}

/// A spool that stores nothing and reports every record as lost; only if
/// even the memory spool cannot be opened.
#[derive(Debug)]
struct NullSpool;

impl Spool for NullSpool {
    fn append(
        &mut self,
        record: super::segment::StoredRecord,
    ) -> Result<super::spool::Appended, super::spool::SpoolError> {
        Ok(super::spool::Appended {
            stored: false,
            dropped: vec![super::spool::Dropped {
                class: record.class,
                reason: super::spool::DropReason::Corrupt,
                count: 1,
                from_seq: record.seq,
                to_seq: record.seq,
            }],
        })
    }
    fn sync(&mut self) -> Result<(), super::spool::SpoolError> {
        Ok(())
    }
    fn pending(
        &mut self,
        _class: super::segment::Class,
        _after: Option<u64>,
        _max_records: usize,
        _max_bytes: usize,
    ) -> Result<Vec<super::segment::StoredRecord>, super::spool::SpoolError> {
        Ok(Vec::new())
    }
    fn ack(
        &mut self,
        _class: super::segment::Class,
        _seq: u64,
    ) -> Result<(), super::spool::SpoolError> {
        Ok(())
    }
    fn expire(
        &mut self,
        _now: i64,
    ) -> Result<Vec<super::spool::Dropped>, super::spool::SpoolError> {
        Ok(Vec::new())
    }
    fn head(&self) -> Option<(u64, [u8; 32])> {
        None
    }
    fn stats(&self) -> SpoolStats {
        SpoolStats::default()
    }
}

fn now_ts<C: Clock>(clock: &C) -> Timestamp {
    Timestamp::from_unix_micros(clock.now_utc().0).unwrap_or(Timestamp::MIN)
}

/// The worker thread's state.
struct Worker<C> {
    clock: C,
    pipeline: Pipeline,
    outlet: Arc<Mutex<Outlet>>,
    delivery: Delivery,
    uploader: Arc<dyn Uploader>,
    status: Arc<Mutex<Status>>,
    stop: Arc<AtomicBool>,
    jumps: Option<tokio::sync::watch::Receiver<Option<ClockJump>>>,
}

impl<C: Clock> Worker<C> {
    fn run(mut self) {
        let mut last_tick = self.clock.monotonic().0;
        let mut last_upload = 0u64;
        let tick = u64::try_from(TICK.as_micros()).unwrap_or(u64::MAX);
        let upload = u64::try_from(UPLOAD_INTERVAL.as_micros()).unwrap_or(u64::MAX);
        loop {
            let stopping = self.stop.load(Ordering::Acquire);
            let wait = if stopping { Duration::ZERO } else { TICK };
            let next = self
                .outlet
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .recv(wait);
            if let Some(event) = next {
                self.pipeline.submit(event, self.clock.monotonic().0);
            } else if stopping {
                break;
            }
            let mono = self.clock.monotonic().0;
            if mono.saturating_sub(last_tick) >= tick {
                last_tick = mono;
                self.tick(mono);
            }
            if mono.saturating_sub(last_upload) >= upload {
                last_upload = mono;
                self.upload(mono);
            }
        }
        let mono = self.clock.monotonic().0;
        let refused = self
            .outlet
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_refused();
        for (class, n) in refused {
            self.pipeline.record_queue_loss(class, n);
        }
        self.pipeline.flush(now_ts(&self.clock), mono);
        self.upload(mono);
        self.publish(None);
    }

    fn tick(&mut self, mono: u64) {
        let refused = self
            .outlet
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_refused();
        for (class, n) in refused {
            self.pipeline.record_queue_loss(class, n);
        }
        if let Some(jumps) = &mut self.jumps
            && jumps.has_changed().unwrap_or(false)
            && let Some(jump) = *jumps.borrow_and_update()
        {
            // Until a check-in measures the offset again (#62).
            self.pipeline.set_clock(ClockState {
                synced: false,
                skew_ms: Some(jump.skew_micros / 1000),
            });
        }
        self.pipeline.tick(now_ts(&self.clock), mono);
        self.publish(None);
    }

    fn upload(&mut self, mono: u64) {
        let pumped = self
            .delivery
            .pump(self.pipeline.spool_mut(), self.uploader.as_ref(), mono);
        self.publish(Some(pumped.offline));
    }

    fn publish(&self, offline: Option<bool>) {
        let mut s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        s.pipeline = self.pipeline.stats().clone();
        s.spool = self.pipeline.spool_stats();
        if let Some(offline) = offline {
            s.offline = offline;
        }
    }
}

impl<C: Clock + Clone + Send + Sync + std::fmt::Debug + 'static> Subsystem for EventPipeline<C> {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    /// Losing the event pipeline loses the audit trail, so the agent is
    /// degraded without it; enforcement does not depend on it (ADR 0009).
    fn criticality(&self) -> Criticality {
        Criticality::NonCritical
    }

    fn dependencies(&self) -> &[&'static str] {
        &[crate::host::ConfigSubsystem::NAME]
    }

    fn health(&self) -> Health {
        let s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
        let mut reasons = Vec::new();
        if let Some(why) = &s.storage {
            reasons.push(why.clone());
        }
        if s.state_damaged {
            reasons.push("the spool state was damaged; acknowledged events are sent again".into());
        }
        if s.pipeline.lost > 0 {
            reasons.push(format!(
                "{} events lost (reported in agent.dropped)",
                s.pipeline.lost
            ));
        }
        if s.pipeline.throttling {
            reasons.push("event rate above the high watermark; allowed events summarised".into());
        }
        if let Some(e) = &s.pipeline.last_error {
            reasons.push(format!("spool error: {e}"));
        }
        if reasons.is_empty() {
            Health::Healthy
        } else {
            Health::Degraded(reasons.join("; "))
        }
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            // The queues outlive a failed run, so a restart carries on
            // with what the producers offered meanwhile.
            let outlet = Arc::clone(&self.outlet);
            let this = Arc::clone(&self);
            let opened = tokio::task::spawn_blocking(move || this.open_spool())
                .await
                .map_err(|e| SubsystemError::new(format!("opening the spool: {e}")))?;
            let (spool, recovery, storage) = opened;
            if !recovery.damaged.is_empty() {
                tracing::warn!(damaged = ?recovery.damaged, "the event spool had damaged segments; they were cut and the loss is reported");
            }
            if recovery.state == StateStatus::Damaged {
                tracing::error!("the event spool state was damaged; pending events are sent again");
            }
            {
                let mut s = self.status.lock().unwrap_or_else(PoisonError::into_inner);
                s.storage = storage;
                s.state_damaged = recovery.state == StateStatus::Damaged;
            }
            let salt = salt(&self.clock);
            let pipeline = Pipeline::new(
                Identity::unenrolled(),
                self.settings,
                spool,
                &recovery,
                salt,
            );
            let stop = Arc::new(AtomicBool::new(false));
            let worker = Worker {
                clock: self.clock.clone(),
                pipeline,
                outlet,
                delivery: Delivery::new(self.delivery),
                uploader: Arc::clone(&self.uploader),
                status: Arc::clone(&self.status),
                stop: Arc::clone(&stop),
                jumps: self.clock_jumps.clone(),
            };
            let handle = std::thread::Builder::new()
                .name("palisade-events".into())
                .spawn(move || worker.run())
                .map_err(|e| SubsystemError::new(format!("event pipeline thread: {e}")))?;
            ctx.set_ready();
            let mut check = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = ctx.stopped() => break,
                    _ = check.tick() => {
                        if handle.is_finished() {
                            return Err(SubsystemError::new("the event pipeline thread ended unexpectedly"));
                        }
                    }
                }
            }
            stop.store(true, Ordering::Release);
            let joined = tokio::task::spawn_blocking(move || handle.join()).await;
            match joined {
                Ok(Ok(())) => Ok(()),
                _ => Err(SubsystemError::new(
                    "the event pipeline thread failed while stopping",
                )),
            }
        })
    }
}

/// A per-start salt for event IDs, from the clocks. Event IDs need to be
/// unique, not secret.
fn salt<C: Clock>(clock: &C) -> [u8; 4] {
    let mixed = clock.monotonic().0.rotate_left(17) ^ clock.now_utc().0.cast_unsigned();
    let h = super::chain::chain_value(&mixed.to_le_bytes());
    [h[0], h[1], h[2], h[3]]
}
