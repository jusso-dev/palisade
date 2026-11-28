//! The process monitor subsystem on Windows (#59).
//!
//! Three parts:
//!
//! 1. The **ETW consumer** thread runs `ProcessTrace` on the
//!    `Palisade-Agent-Trace` session. Its callback only copies the record
//!    and offers it to a bounded queue; a full queue drops the record and
//!    counts it. It never blocks the OS's delivery.
//! 2. The **monitor** thread takes records from the queue and runs the
//!    portable [`ProcessMonitor`], reading command lines and tokens through
//!    the platform backends.
//! 3. The async **subsystem** starts both, reports the session's loss
//!    counters in its health, evicts expired processes, and on stop ends
//!    the session, which ends both threads.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use palisade_core::path::VolumeMap;
use palisade_core::platform::{Clock, IdentityProvider, ProcessInfo, ProcessKey};

use super::kernel::{KERNEL_PROCESS, KEYWORD_IMAGE, KEYWORD_PROCESS, RawEvent};
use super::monitor::{Enricher, Enrichment, MonitorSettings, ProcessMonitor, SnapshotProcess};
use super::output::{Counters, TelemetrySink};
use super::tree::{DEFAULT_CAPACITY, DEFAULT_RETENTION, ProcessTree, TokenFacts};
use super::{SESSION_NAME, health_of};
use crate::ffi::{etw, snapshot};
use crate::platform::SystemClock;
use crate::platform::windows::{WindowsIdentity, WindowsProcesses};
use crate::subsystem::{
    BoxFuture, Criticality, Health, Subsystem, SubsystemContext, SubsystemError,
};

/// 64 KiB buffers, at least 16 and at most 256 of them (#59).
const BUFFERS: etw::Buffers = etw::Buffers {
    size_kb: 64,
    min: 16,
    max: 256,
};

/// The raw record queue between the consumer and the monitor.
const QUEUE_CAPACITY: usize = 50_000;

/// How often loss counters are read and expired processes evicted.
const TICK: Duration = Duration::from_secs(5);

/// Reads command lines and tokens through the OS.
struct OsEnricher {
    processes: WindowsProcesses,
    identity: WindowsIdentity,
}

fn token_facts(identity: &WindowsIdentity, key: ProcessKey) -> Option<TokenFacts> {
    let t = identity.token(key).ok()?;
    Some(TokenFacts {
        user_sid: Some(t.user_sid),
        groups: Some(t.groups),
        session_kind: Some(t.session_kind),
        integrity: Some(t.integrity),
        elevation: Some(t.elevation),
        elevated: Some(t.elevated),
    })
}

impl Enricher for OsEnricher {
    fn enrich(&self, key: ProcessKey) -> Enrichment {
        Enrichment {
            command_line: self.processes.get(key).ok().and_then(|r| r.command_line),
            token: token_facts(&self.identity, key),
        }
    }
}

fn volume_map() -> VolumeMap {
    let mut map = VolumeMap::new();
    for letter in 'A'..='Z' {
        if let Some(device) = snapshot::drive_device(letter) {
            map.insert(&device, letter);
        }
    }
    map
}

fn startup_snapshot(enricher: &OsEnricher) -> Vec<SnapshotProcess> {
    let Ok(ids) = snapshot::process_ids() else {
        tracing::warn!("cannot list processes; the process tree starts empty");
        return Vec::new();
    };
    ids.into_iter()
        .filter(|&pid| pid > 4)
        .filter_map(|pid| {
            let record = enricher.processes.by_pid(pid).ok()?;
            let token = token_facts(&enricher.identity, record.key);
            Some(SnapshotProcess { record, token })
        })
        .collect()
}

/// The process monitor subsystem.
pub struct EtwProcessMonitor {
    sink: Arc<dyn TelemetrySink>,
    settings: MonitorSettings,
    counters: Arc<Counters>,
    status: Mutex<Option<String>>,
}

impl std::fmt::Debug for EtwProcessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EtwProcessMonitor").finish_non_exhaustive()
    }
}

impl EtwProcessMonitor {
    /// A monitor that sends its events to `sink`.
    pub fn new(sink: Arc<dyn TelemetrySink>, settings: MonitorSettings) -> Self {
        Self {
            sink,
            settings,
            counters: Arc::new(Counters::default()),
            status: Mutex::new(None),
        }
    }

    fn set_status(&self, status: Option<String>) {
        *self.status.lock().unwrap_or_else(PoisonError::into_inner) = status;
    }
}

fn consumer(tx: SyncSender<RawEvent>, counters: Arc<Counters>) -> std::io::Result<()> {
    etw::consume(SESSION_NAME, &mut |raw| match tx.try_send(raw) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            Counters::bump(&counters.queue_dropped);
        }
    })
}

fn worker(
    rx: Receiver<RawEvent>,
    mut monitor: ProcessMonitor<Arc<dyn TelemetrySink>>,
    enricher: OsEnricher,
) {
    let clock = SystemClock;
    loop {
        match rx.recv_timeout(TICK) {
            Ok(raw) => monitor.handle(&raw, &enricher),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        monitor.tick(clock.now_utc());
    }
}

impl Subsystem for EtwProcessMonitor {
    fn name(&self) -> &'static str {
        super::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::NonCritical
    }

    fn dependencies(&self) -> &[&'static str] {
        &[crate::host::ConfigSubsystem::NAME]
    }

    fn health(&self) -> Health {
        let status = self
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        health_of(&self.counters, status)
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let session = etw::Session::start(SESSION_NAME, BUFFERS)
                .map_err(|e| SubsystemError::new(format!("trace session: {e}")))?;
            session
                .enable(KERNEL_PROCESS, KEYWORD_PROCESS | KEYWORD_IMAGE)
                .map_err(|e| SubsystemError::new(format!("kernel process provider: {e}")))?;
            let stopper = session.stopper();

            let this = Arc::clone(&self);
            let (tx, rx) = sync_channel(QUEUE_CAPACITY);
            let counters = Arc::clone(&self.counters);
            let consumer = std::thread::Builder::new()
                .name("palisade-etw".into())
                .spawn(move || consumer(tx, counters))
                .map_err(|e| SubsystemError::new(format!("ETW consumer thread: {e}")))?;

            let enricher = OsEnricher {
                processes: WindowsProcesses,
                identity: WindowsIdentity::new(),
            };
            let mut monitor = ProcessMonitor::new(
                ProcessTree::new(DEFAULT_CAPACITY, DEFAULT_RETENTION),
                this.settings.clone(),
                volume_map(),
                Arc::clone(&this.sink),
                Arc::clone(&this.counters),
            );
            // The session is already running, so a process that starts
            // during the snapshot is seen by one or the other (or both,
            // and merged).
            monitor.snapshot(startup_snapshot(&enricher));
            let worker = std::thread::Builder::new()
                .name("palisade-procmon".into())
                .spawn(move || worker(rx, monitor, enricher))
                .map_err(|e| SubsystemError::new(format!("process monitor thread: {e}")))?;
            ctx.set_ready();

            let mut tick = tokio::time::interval(TICK);
            loop {
                tokio::select! {
                    _ = ctx.stopped() => break,
                    _ = tick.tick() => {
                        match session.stats() {
                            Ok(s) => {
                                let lost = u64::from(s.events_lost)
                                    + u64::from(s.realtime_buffers_lost)
                                    + u64::from(s.log_buffers_lost);
                                this.counters.os_lost.store(lost, std::sync::atomic::Ordering::Relaxed);
                                this.set_status(None);
                            }
                            Err(e) => this.set_status(Some(format!("session query failed: {e}"))),
                        }
                        if consumer.is_finished() || worker.is_finished() {
                            return Err(SubsystemError::new("the trace session ended unexpectedly"));
                        }
                    }
                }
            }
            stopper.stop();
            drop(session);
            let _ = tokio::task::spawn_blocking(move || {
                let _ = consumer.join();
                let _ = worker.join();
            })
            .await;
            Ok(())
        })
    }
}
