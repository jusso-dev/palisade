//! The `inventory` subsystem: runs the [`Engine`] over every volume the
//! [`VolumeProvider`] gives, on a blocking thread, until a stop.
//!
//! For each volume it finishes (or resumes) the initial scan, then polls
//! the change journal every [`POLL_INTERVAL`]. A volume without a journal
//! is rescanned every [`RESCAN_INTERVAL`]. Its health says `Baseline:
//! scanning` until every volume's first scan is complete, which the server
//! shows as `WaitingForBaseline` (E05).
//!
//! The resource budgets are #65. Until then the [`PacedThrottle`] waits
//! between batches at low priority, and every throttle stops at once when
//! a stop is requested; the checkpoint lets the scan resume.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use palisade_core::platform::{Clock, MonotonicTime, UtcTime};

use super::engine::{Engine, Identifier, PollOutcome, Throttle, VolumeSource};
use super::entry::Discovery;
use super::scope::{InventoryScope, ScanPriority};
use super::store::{InventoryStore, MemoryStore};
use crate::platform::SystemClock;
use crate::subsystem::{
    BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError,
};

/// How often the change journals are read.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How often a volume without a journal is rescanned.
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// A volume and the identifier that reads its files.
pub struct Volume {
    /// The volume.
    pub source: Box<dyn VolumeSource + Send>,
    /// Identifies its files.
    pub identifier: Box<dyn Identifier + Send>,
}

/// Lists the volumes in scope. Called on the blocking thread.
pub trait VolumeProvider: Send + Sync + 'static {
    /// The volumes to inventory now.
    fn volumes(&self, scope: &InventoryScope) -> Vec<Volume>;
}

/// No volumes: the provider on platforms without a file-system backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoVolumes;

impl VolumeProvider for NoVolumes {
    fn volumes(&self, _scope: &InventoryScope) -> Vec<Volume> {
        Vec::new()
    }
}

/// A throttle that stops when asked, and at low priority waits between
/// batches. The #65 budgets replace the pacing.
#[derive(Debug)]
pub struct PacedThrottle {
    stop: Arc<AtomicBool>,
    pause: Duration,
}

impl PacedThrottle {
    /// A throttle for `priority` that stops once `stop` is set.
    #[must_use]
    pub fn new(stop: Arc<AtomicBool>, priority: ScanPriority) -> Self {
        let pause = match priority {
            ScanPriority::Low => Duration::from_millis(20),
            ScanPriority::Normal => Duration::from_millis(2),
            ScanPriority::High => Duration::ZERO,
        };
        Self { stop, pause }
    }
}

impl Throttle for PacedThrottle {
    fn admit(&mut self, _files: usize) -> bool {
        if self.stop.load(Ordering::Relaxed) {
            return false;
        }
        if !self.pause.is_zero() {
            std::thread::sleep(self.pause);
        }
        !self.stop.load(Ordering::Relaxed)
    }
}

/// The inventory subsystem.
pub struct InventorySubsystem {
    scope: InventoryScope,
    provider: Arc<dyn VolumeProvider>,
    store: Arc<Mutex<MemoryStore>>,
    health: Arc<Mutex<Health>>,
}

impl std::fmt::Debug for InventorySubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InventorySubsystem")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl InventorySubsystem {
    /// The subsystem's name.
    pub const NAME: &'static str = "inventory";

    /// An inventory of the volumes `provider` gives, within `scope`.
    pub fn new(scope: InventoryScope, provider: Arc<dyn VolumeProvider>) -> Self {
        Self {
            scope,
            provider,
            store: Arc::new(Mutex::new(MemoryStore::default())),
            health: Arc::new(Mutex::new(Health::Degraded("Baseline: not started".into()))),
        }
    }

    /// The subsystem for this platform: the Windows volumes on Windows,
    /// none elsewhere.
    #[must_use]
    pub fn for_platform() -> Self {
        #[cfg(windows)]
        let provider: Arc<dyn VolumeProvider> = Arc::new(super::windows::FixedVolumes);
        #[cfg(not(windows))]
        let provider: Arc<dyn VolumeProvider> = Arc::new(NoVolumes);
        Self::new(InventoryScope::default(), provider)
    }

    /// The number of entries, for diagnostics.
    pub fn len(&self) -> usize {
        self.store
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
            .unwrap_or(0)
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Sets the flag when dropped.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn set(health: &Mutex<Health>, value: Health) {
    *health.lock().unwrap_or_else(PoisonError::into_inner) = value;
}

/// The state of the work across ticks.
struct Worker {
    scope: InventoryScope,
    volumes: Vec<Volume>,
    engines: Vec<Engine>,
    baseline_done: Vec<bool>,
    last_rescan: Vec<Option<MonotonicTime>>,
}

impl Worker {
    fn new(scope: &InventoryScope, volumes: Vec<Volume>) -> Self {
        let n = volumes.len();
        Self {
            scope: scope.clone(),
            engines: (0..n).map(|_| Engine::new(scope)).collect(),
            volumes,
            baseline_done: vec![false; n],
            last_rescan: vec![None; n],
        }
    }

    /// One pass over every volume: poll its journal, scan it if needed,
    /// purge old deletions. Returns the health to report.
    fn tick(
        &mut self,
        store: &mut dyn InventoryStore,
        clock: &dyn Clock,
        throttle: &mut dyn Throttle,
    ) -> Health {
        let now = || (clock.now_utc(), clock.monotonic());
        let rescan_micros = u64::try_from(RESCAN_INTERVAL.as_micros()).unwrap_or(u64::MAX);
        for i in 0..self.volumes.len() {
            let (Some(v), Some(engine)) = (self.volumes.get_mut(i), self.engines.get_mut(i)) else {
                continue;
            };
            let serial = v.source.serial();
            let outcome = engine.poll(
                v.source.as_mut(),
                store,
                v.identifier.as_mut(),
                throttle,
                &now,
            );
            let done = self.baseline_done.get(i).copied().unwrap_or(false);
            let rescan_due = self
                .last_rescan
                .get(i)
                .copied()
                .flatten()
                .is_none_or(|t| clock.monotonic().0.saturating_sub(t.0) >= rescan_micros);
            let scan = match outcome {
                Ok(PollOutcome::NeedsScan) => Some(Discovery::InitialScan),
                Ok(PollOutcome::NoJournal) if !done => Some(Discovery::InitialScan),
                Ok(PollOutcome::NoJournal) if rescan_due => Some(Discovery::Rescan),
                Ok(PollOutcome::Reconciled(r)) => {
                    tracing::warn!(
                        volume = serial,
                        added = r.added,
                        deleted = r.deleted,
                        "inventory reconciled after the change journal cursor was lost"
                    );
                    mark(
                        &mut self.baseline_done,
                        &mut self.last_rescan,
                        i,
                        r.complete,
                        clock,
                    );
                    None
                }
                Ok(_) => {
                    mark(
                        &mut self.baseline_done,
                        &mut self.last_rescan,
                        i,
                        true,
                        clock,
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(volume = serial, error = %e, "inventory poll failed");
                    None
                }
            };
            if let Some(discovery) = scan {
                match engine.scan(
                    v.source.as_mut(),
                    store,
                    v.identifier.as_mut(),
                    throttle,
                    &now,
                    discovery,
                ) {
                    Ok(r) => {
                        tracing::info!(
                            volume = serial,
                            listed = r.listed,
                            added = r.added,
                            complete = r.complete,
                            "inventory scan"
                        );
                        if r.complete {
                            mark(
                                &mut self.baseline_done,
                                &mut self.last_rescan,
                                i,
                                true,
                                clock,
                            );
                        }
                    }
                    Err(e) => tracing::warn!(volume = serial, error = %e, "inventory scan failed"),
                }
            }
        }
        let retention = i64::from(self.scope.deleted_retention_days).saturating_mul(86_400_000_000);
        if let Err(e) = store.purge_deleted(UtcTime(clock.now_utc().0.saturating_sub(retention))) {
            tracing::warn!(error = %e, "inventory purge failed");
        }
        if self.baseline_done.iter().all(|d| *d) {
            Health::Healthy
        } else {
            let done = self.baseline_done.iter().filter(|d| **d).count();
            Health::Degraded(format!(
                "Baseline: scanning ({done} of {} volumes done)",
                self.baseline_done.len()
            ))
        }
    }
}

/// Records that volume `i`'s scan completed (or not), and when.
fn mark(
    baseline_done: &mut [bool],
    last_rescan: &mut [Option<MonotonicTime>],
    i: usize,
    complete: bool,
    clock: &dyn Clock,
) {
    if let Some(d) = baseline_done.get_mut(i) {
        *d |= complete;
    }
    if complete && let Some(t) = last_rescan.get_mut(i) {
        t.get_or_insert(clock.monotonic());
    }
}

/// One tick of the work, on a blocking thread: the worker is created on
/// the first, so listing the volumes stays off the async workers too.
fn tick_once(this: &InventorySubsystem, worker: &Mutex<Option<Worker>>, stop: &Arc<AtomicBool>) {
    let mut slot = worker.lock().unwrap_or_else(PoisonError::into_inner);
    let w =
        slot.get_or_insert_with(|| Worker::new(&this.scope, this.provider.volumes(&this.scope)));
    let mut throttle = PacedThrottle::new(Arc::clone(stop), this.scope.scan_priority);
    let h = {
        let mut s = this.store.lock().unwrap_or_else(PoisonError::into_inner);
        w.tick(&mut *s, &SystemClock, &mut throttle)
    };
    set(&this.health, h);
}

impl Subsystem for InventorySubsystem {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::NonCritical
    }

    fn dependencies(&self) -> &[&'static str] {
        &["config"]
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let stop = Arc::new(AtomicBool::new(false));
            // Set on every way out of this future, including an abort at
            // the stop deadline, so a tick in progress stops at its next
            // batch; what it has not done resumes from the checkpoint.
            let _guard = StopOnDrop(Arc::clone(&stop));
            let worker = Arc::new(Mutex::new(None));
            ctx.set_ready();
            // Each tick is a short blocking task, never one that lives for
            // the whole run, so the runtime can shut down without waiting
            // on it.
            loop {
                let tick = {
                    let this = Arc::clone(&self);
                    let worker = Arc::clone(&worker);
                    let stop = Arc::clone(&stop);
                    tokio::task::spawn_blocking(move || tick_once(&this, &worker, &stop))
                };
                tokio::select! {
                    _ = ctx.stopped() => return Ok(()),
                    done = tick => if let Err(e) = done {
                        return Err(SubsystemError::new(format!("inventory tick: {e}")));
                    },
                }
                tokio::select! {
                    _ = ctx.stopped() => return Ok(()),
                    () = tokio::time::sleep(POLL_INTERVAL) => {}
                }
            }
        })
    }

    fn health(&self) -> Health {
        self.health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_throttle_stops_when_asked() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut t = PacedThrottle::new(Arc::clone(&stop), ScanPriority::High);
        assert!(t.admit(10));
        let mut low = PacedThrottle::new(Arc::clone(&stop), ScanPriority::Low);
        assert!(low.admit(10));
        assert!(PacedThrottle::new(Arc::clone(&stop), ScanPriority::Normal).admit(1));
        stop.store(true, Ordering::Relaxed);
        assert!(!t.admit(10));
        assert!(!low.admit(10));
    }

    #[test]
    fn ticks_report_the_baseline_and_finish_it() {
        use crate::inventory::engine::Unthrottled;
        use palisade_core::test_util::MockClock;

        let scope = InventoryScope::default();
        let clock = MockClock::new(UtcTime(1_000_000_000), MonotonicTime(0));
        let mut store = MemoryStore::default();
        // No volumes: the baseline is trivially complete.
        let mut w = Worker::new(&scope, Vec::new());
        assert_eq!(
            w.tick(&mut store, &clock, &mut Unthrottled),
            Health::Healthy
        );
        // One volume: scanning until its first poll after the scan.
        let mut w = Worker::new(&scope, vec![test_volume()]);
        let h = w.tick(&mut store, &clock, &mut Unthrottled);
        assert_eq!(h, Health::Healthy, "the scan completed in the tick");
        assert_eq!(store.len().unwrap(), 1);
        // A throttle that refuses leaves the scan for the next tick.
        let mut store = MemoryStore::default();
        let mut w = Worker::new(&scope, vec![test_volume()]);
        let mut stop = PacedThrottle::new(Arc::new(AtomicBool::new(true)), ScanPriority::High);
        assert!(matches!(
            w.tick(&mut store, &clock, &mut stop),
            Health::Degraded(m) if m.contains("0 of 1")
        ));
        assert!(store.checkpoint(1).unwrap().is_some());
    }

    /// A volume with one file and no journal, identified as a PE.
    fn test_volume() -> Volume {
        use crate::inventory::engine::{Identified, Listed, SourceError};
        use crate::inventory::entry::{EntryKey, IdentitySummary};
        use crate::inventory::store::JournalCursor;
        use crate::inventory::track::Change;
        use palisade_fileid::fsctx::ntfs::JournalData;

        struct One;
        impl VolumeSource for One {
            fn serial(&self) -> u64 {
                1
            }
            fn journal(&mut self) -> Result<Option<JournalData>, SourceError> {
                Ok(None)
            }
            fn list(
                &mut self,
                start: u64,
                _: i64,
            ) -> Result<Option<(u64, Vec<Listed>)>, SourceError> {
                Ok((start == 0).then(|| {
                    (
                        1,
                        vec![Listed {
                            file_id: [1; 16],
                            path: Some(r"C:.exe".into()),
                            directory: false,
                        }],
                    )
                }))
            }
            fn changes(&mut self, _: JournalCursor) -> Result<(i64, Vec<Change>), SourceError> {
                Err(SourceError::Other("no journal".into()))
            }
            fn resolve(&mut self, _: [u8; 16]) -> Option<String> {
                None
            }
        }
        struct Pe;
        impl Identifier for Pe {
            fn identify(&mut self, _: EntryKey) -> Identified {
                Identified::Known {
                    summary: Box::new(IdentitySummary {
                        executable_content: Some(true),
                        ..IdentitySummary::default()
                    }),
                    user_writable: Some(false),
                }
            }
        }
        Volume {
            source: Box::new(One),
            identifier: Box::new(Pe),
        }
    }

    #[test]
    fn the_subsystem_describes_itself() {
        let sub = InventorySubsystem::new(InventoryScope::default(), Arc::new(NoVolumes));
        assert!(matches!(sub.health(), Health::Degraded(_)));
        assert!(sub.is_empty());
        assert_eq!(sub.name(), "inventory");
        assert_eq!(sub.criticality(), Criticality::NonCritical);
        assert_eq!(sub.dependencies(), ["config"]);
        assert!(NoVolumes.volumes(&InventoryScope::default()).is_empty());
        assert!(format!("{sub:?}").contains("InventorySubsystem"));
    }

    #[test]
    fn the_worker_is_told_to_stop_however_the_run_ends() {
        let stop = Arc::new(AtomicBool::new(false));
        drop(StopOnDrop(Arc::clone(&stop)));
        assert!(stop.load(Ordering::Relaxed));
    }
}
