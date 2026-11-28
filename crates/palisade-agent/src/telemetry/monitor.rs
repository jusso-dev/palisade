//! The process monitor's state machine (#59).
//!
//! [`ProcessMonitor`] takes decoded kernel process records in order, keeps
//! the [`ProcessTree`], and emits [`TelemetryEvent`]s. It reads the OS only
//! through an [`Enricher`] (command line and token of a new process) and
//! the startup snapshot, so it runs and is tested on every OS. The Windows
//! subsystem (`telemetry::windows`) feeds it from the ETW session.
//!
//! What it does with each record:
//!
//! - **Process start**: finds the parent ([`ProcessTree::find_parent`]:
//!   never a process that reused the parent's ID), records the creator when
//!   it is not the parent, reads the command line and token through the
//!   enricher, records the process and emits `ProcessStart`. A creator that
//!   is not the recorded parent also emits an advisory `ParentSpoof`.
//! - **Process stop**: marks the process exited (it is kept for late
//!   correlation) and, if enabled, emits `ProcessStop`.
//! - **Image load**: a kernel-mode image is a driver and is always
//!   emitted. A user-mode library is emitted according to [`DllEvents`].
//!   The process's own main image is covered by `ProcessStart`.
//!
//! Every event the sink refuses is counted in [`Counters::dropped`].

#![forbid(unsafe_code)]

use std::sync::Arc;

use palisade_core::path::{PathKind, VolumeMap, normalize_with};
use palisade_core::platform::{ProcessKey, ProcessRecord, UtcTime};

use super::cmdline::CmdlinePolicy;
use super::kernel::{self, ImageEvent, KernelEvent, ProcessStart, ProcessStop, RawEvent};
use super::output::{
    Counters, ImageKind, ImageLoad, PostStartAction, TelemetryEvent, TelemetrySink,
};
use super::tree::{CommandLine, ProcInfo, ProcessTree, TokenFacts};

/// Which library loads are emitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DllEvents {
    /// None.
    None,
    /// Only libraries not known to be trusted. Until the identity pipeline
    /// (#59, E03) judges libraries, none is known to be trusted, so every
    /// library is emitted: a load is never hidden on a guess (ADR 0018).
    #[default]
    UntrustedOnly,
    /// All.
    All,
}

/// The monitor's settings.
#[derive(Clone, Debug)]
pub struct MonitorSettings {
    /// Command-line capture and redaction.
    pub cmdline: CmdlinePolicy,
    /// Which library loads are emitted.
    pub dll_events: DllEvents,
    /// Whether process stops are emitted.
    pub process_stop_events: bool,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            cmdline: CmdlinePolicy::default(),
            dll_events: DllEvents::default(),
            process_stop_events: true,
        }
    }
}

/// What the OS says about a new process beyond its start record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Enrichment {
    /// The raw command line, if it could be read.
    pub command_line: Option<String>,
    /// The token, if it could be read.
    pub token: Option<TokenFacts>,
}

/// Reads what a start record does not carry.
pub trait Enricher {
    /// The command line and token of the running process `key`. A process
    /// that has already exited, or refuses the query, gives `None`s.
    fn enrich(&self, key: ProcessKey) -> Enrichment;
}

/// An enricher that knows nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoEnrichment;

impl Enricher for NoEnrichment {
    fn enrich(&self, _key: ProcessKey) -> Enrichment {
        Enrichment::default()
    }
}

/// A process found by the startup snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotProcess {
    /// What the OS reported.
    pub record: ProcessRecord,
    /// Its token, if it could be read.
    pub token: Option<TokenFacts>,
}

/// The process monitor.
pub struct ProcessMonitor<S: TelemetrySink> {
    tree: ProcessTree,
    settings: MonitorSettings,
    volumes: VolumeMap,
    sink: S,
    counters: Arc<Counters>,
    post_start: Option<Arc<dyn PostStartAction>>,
}

impl<S: TelemetrySink> std::fmt::Debug for ProcessMonitor<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessMonitor")
            .field("processes", &self.tree.len())
            .finish_non_exhaustive()
    }
}

impl<S: TelemetrySink> ProcessMonitor<S> {
    /// A monitor with an empty tree.
    pub fn new(
        tree: ProcessTree,
        settings: MonitorSettings,
        volumes: VolumeMap,
        sink: S,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            tree,
            settings,
            volumes,
            sink,
            counters,
            post_start: None,
        }
    }

    /// Sets the post-start action (off by default).
    pub fn set_post_start(&mut self, action: Arc<dyn PostStartAction>) {
        self.post_start = Some(action);
    }

    /// The tree.
    #[must_use]
    pub const fn tree(&self) -> &ProcessTree {
        &self.tree
    }

    fn emit(&self, event: TelemetryEvent) {
        if self.sink.offer(event) {
            Counters::bump(&self.counters.emitted);
        } else {
            Counters::bump(&self.counters.dropped);
        }
    }

    /// The path with its device resolved to a drive, if it resolves.
    fn normalise(&self, path: &str) -> Option<String> {
        let n = normalize_with(path, &self.volumes);
        (n.kind() != PathKind::Device && n.kind() != PathKind::Relative)
            .then(|| n.as_str().to_owned())
    }

    /// Records the processes found running at startup, parents first where
    /// the creation times allow, so each finds its parent. Nothing is
    /// emitted for them: they were not seen starting.
    pub fn snapshot(&mut self, mut processes: Vec<SnapshotProcess>) {
        processes.sort_by_key(|p| (p.record.key.created, p.record.key.pid));
        for p in processes {
            let r = p.record;
            let parent_pid = r.parent_pid.unwrap_or(0);
            let mut info = ProcInfo::new(r.key, parent_pid, r.image_path.clone());
            info.parent = self.tree.find_parent(parent_pid, None, r.key.created);
            info.image_path_normalised = self.normalise(&r.image_path);
            info.command_line = self.settings.cmdline.apply(r.command_line.as_deref());
            if let Some(token) = p.token {
                info.token = token;
            }
            self.tree.insert(info);
        }
    }

    /// Handles one raw record. A record that does not decode is counted
    /// and skipped.
    pub fn handle(&mut self, raw: &RawEvent, enricher: &dyn Enricher) {
        match kernel::decode(raw) {
            Ok(event) => self.handle_decoded(event, enricher),
            Err(e) => {
                Counters::bump(&self.counters.decode_errors);
                tracing::debug!(error = %e, "kernel process record skipped");
            }
        }
    }

    /// Handles one decoded record.
    pub fn handle_decoded(&mut self, event: KernelEvent, enricher: &dyn Enricher) {
        match event {
            KernelEvent::ProcessStart(start) => self.on_start(start, enricher),
            KernelEvent::ProcessStop(stop) => self.on_stop(&stop),
            KernelEvent::ImageLoad(image) => self.on_image(image),
            KernelEvent::ImageUnload(_) => {}
        }
    }

    fn on_start(&mut self, s: ProcessStart, enricher: &dyn Enricher) {
        let key = ProcessKey {
            pid: s.pid,
            created: s.created,
        };
        let parent = self
            .tree
            .find_parent(s.parent_pid, s.parent_sequence, s.created);
        // The creator: the process that logged the event, when it is not
        // the recorded parent. The idle and system processes create
        // processes with no user-mode creator.
        let creator =
            if s.creator_pid != s.parent_pid && s.creator_pid != s.pid && s.creator_pid > 4 {
                self.tree.alive_at(s.creator_pid, s.created).map(|p| p.key)
            } else {
                None
            };
        let enrichment = enricher.enrich(key);
        let mut info = ProcInfo::new(key, s.parent_pid, s.image_name.clone());
        info.sequence = s.sequence;
        info.parent = parent;
        info.creator = creator;
        info.image_path_normalised = self.normalise(&s.image_name);
        info.command_line = self
            .settings
            .cmdline
            .apply(enrichment.command_line.as_deref());
        info.session_id = Some(s.session_id);
        let mut token = enrichment.token.unwrap_or_default();
        // The start record's own token fields are taken when the token
        // could not be read: they describe the same token.
        token.integrity = token.integrity.or(s.integrity);
        token.elevation = token.elevation.or(s.elevation);
        token.elevated = token.elevated.or(s.elevated);
        info.token = token;
        info.package_full_name = s.package_full_name;
        info.image_checksum = s.image_checksum;
        info.time_date_stamp = s.time_date_stamp;
        info.observed_start = true;
        self.tree.insert(info);
        let Some(recorded) = self.tree.get(key) else {
            // The tree is full of running processes; the start is still
            // reported, without ancestry.
            self.emit(TelemetryEvent::ProcessStart {
                process: Box::new(ProcInfo::new(key, s.parent_pid, s.image_name)),
                ancestry: Vec::new(),
            });
            return;
        };
        if let Some(action) = &self.post_start {
            action.on_start(recorded);
        }
        let process = Box::new(recorded.clone());
        let ancestry = self.tree.ancestry(key);
        self.emit(TelemetryEvent::ProcessStart { process, ancestry });
        if let Some(creator) = creator {
            self.emit(TelemetryEvent::ParentSpoof {
                child: key,
                parent_pid: s.parent_pid,
                creator,
            });
        }
    }

    fn on_stop(&mut self, s: &ProcessStop) {
        let key = ProcessKey {
            pid: s.pid,
            created: s.created,
        };
        let Some(info) = self.tree.exit(key, s.exited, s.exit_code) else {
            return;
        };
        if self.settings.process_stop_events {
            let process = Box::new(info.clone());
            self.emit(TelemetryEvent::ProcessStop { process });
        }
    }

    fn on_image(&mut self, image: ImageEvent) {
        let process = (!image.is_kernel())
            .then(|| self.tree.alive_at(image.pid, image.timestamp))
            .flatten();
        let kind = if image.is_kernel() {
            ImageKind::Driver
        } else if process.is_some_and(|p| p.image_path.eq_ignore_ascii_case(&image.image_name)) {
            ImageKind::Executable
        } else {
            ImageKind::Library
        };
        let emit = match kind {
            ImageKind::Driver => true,
            ImageKind::Executable => false,
            ImageKind::Library => self.settings.dll_events != DllEvents::None,
        };
        if !emit {
            return;
        }
        let event = ImageLoad {
            process: process.map(|p| p.key),
            kind,
            image_path_normalised: self.normalise(&image.image_name),
            image_path: image.image_name,
            base: image.base,
            size: image.size,
            checksum: image.checksum,
            time_date_stamp: image.time_date_stamp,
            time: image.timestamp,
        };
        self.emit(TelemetryEvent::ImageLoad(event));
    }

    /// Evicts exited processes whose retention has passed.
    pub fn tick(&mut self, now: UtcTime) -> usize {
        self.tree.evict_expired(now)
    }

    /// The command line policy (for tests and diagnostics).
    #[must_use]
    pub const fn settings(&self) -> &MonitorSettings {
        &self.settings
    }
}

/// The text of a captured command line, for diagnostics.
#[must_use]
pub fn cmdline_text(c: &CommandLine) -> &str {
    c.text().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use palisade_core::platform::{Elevation, IntegrityLevel};

    use super::super::kernel::encode;
    use super::super::tree::DEFAULT_RETENTION;
    use super::*;

    #[derive(Default)]
    struct Collect(Mutex<Vec<TelemetryEvent>>, bool);

    impl TelemetrySink for Collect {
        fn offer(&self, event: TelemetryEvent) -> bool {
            if self.1 {
                return false;
            }
            self.0.lock().unwrap().push(event);
            true
        }
    }

    impl TelemetrySink for &Collect {
        fn offer(&self, event: TelemetryEvent) -> bool {
            (*self).offer(event)
        }
    }

    struct Fixed(Enrichment);
    impl Enricher for Fixed {
        fn enrich(&self, _key: ProcessKey) -> Enrichment {
            self.0.clone()
        }
    }

    fn volumes() -> VolumeMap {
        let mut v = VolumeMap::new();
        v.insert("\\Device\\HarddiskVolume3", 'c');
        v
    }

    fn monitor(sink: &Collect, settings: MonitorSettings) -> ProcessMonitor<&Collect> {
        ProcessMonitor::new(
            ProcessTree::new(100, DEFAULT_RETENTION),
            settings,
            volumes(),
            sink,
            Arc::new(Counters::default()),
        )
    }

    fn start(pid: u32, created: i64, parent: u32, creator: u32) -> ProcessStart {
        ProcessStart {
            pid,
            sequence: None,
            created: UtcTime(created),
            parent_pid: parent,
            parent_sequence: None,
            session_id: 1,
            flags: None,
            elevation: Some(Elevation::Limited),
            elevated: Some(false),
            integrity: Some(IntegrityLevel::Medium),
            image_name: format!("\\Device\\HarddiskVolume3\\p{pid}.exe"),
            image_checksum: None,
            time_date_stamp: None,
            package_full_name: None,
            package_app_id: None,
            security_mitigations: None,
            creator_pid: creator,
        }
    }

    fn snap(pid: u32, created: i64, parent: Option<u32>) -> SnapshotProcess {
        SnapshotProcess {
            record: ProcessRecord {
                key: ProcessKey {
                    pid,
                    created: UtcTime(created),
                },
                parent_pid: parent,
                image_path: format!("C:\\s{pid}.exe"),
                command_line: Some(format!("s{pid}.exe password=x")),
            },
            token: Some(TokenFacts {
                user_sid: Some("S-1-5-18".into()),
                ..TokenFacts::default()
            }),
        }
    }

    fn key(pid: u32, created: i64) -> ProcessKey {
        ProcessKey {
            pid,
            created: UtcTime(created),
        }
    }

    #[test]
    fn a_spawn_chain_gets_parent_grandparent_and_command_line() {
        let sink = Collect::default();
        let mut m = monitor(&sink, MonitorSettings::default());
        // Snapshot children before parents: sorting fixes the order.
        m.snapshot(vec![snap(20, 2, Some(10)), snap(10, 1, None)]);
        assert!(m.tree().get(key(10, 1)).is_some());
        assert_eq!(
            m.tree().get(key(20, 1 + 1)).unwrap().parent,
            Some(key(10, 1))
        );
        assert!(!m.tree().get(key(20, 2)).unwrap().observed_start);
        assert_eq!(
            cmdline_text(&m.tree().get(key(20, 2)).unwrap().command_line),
            "s20.exe [redacted]"
        );
        let e = Fixed(Enrichment {
            command_line: Some("cmd /c echo hi".into()),
            token: None,
        });
        let raw = encode::process_start(&start(30, 3, 20, 20), 4, 0);
        m.handle(&raw, &e);
        let events = sink.0.lock().unwrap().clone();
        let [TelemetryEvent::ProcessStart { process, ancestry }] = events.as_slice() else {
            panic!("{events:?}")
        };
        assert_eq!(*ancestry, [key(20, 2), key(10, 1)]);
        assert_eq!(process.command_line.text(), Some("cmd /c echo hi"));
        assert_eq!(
            process.image_path_normalised.as_deref(),
            Some("C:\\p30.exe")
        );
        assert_eq!(process.token.integrity, Some(IntegrityLevel::Medium));
        assert_eq!(process.creator, None);
        assert!(process.observed_start);
        assert_eq!(Counters::get(&m.counters.emitted), 1);
    }

    #[test]
    fn pid_reuse_does_not_corrupt_ancestry() {
        let sink = Collect::default();
        let mut m = monitor(&sink, MonitorSettings::default());
        let e = NoEnrichment;
        m.handle_decoded(KernelEvent::ProcessStart(start(100, 1, 0, 0)), &e);
        m.handle_decoded(
            KernelEvent::ProcessStop(ProcessStop {
                pid: 100,
                sequence: None,
                created: UtcTime(1),
                exited: UtcTime(2),
                exit_code: 0,
                image_name: "p100.exe".into(),
            }),
            &e,
        );
        // ID 100 is reused by an unrelated process.
        m.handle_decoded(KernelEvent::ProcessStart(start(100, 5, 0, 0)), &e);
        // A late start record for a child of the first process.
        m.handle_decoded(KernelEvent::ProcessStart(start(200, 1, 100, 100)), &e);
        assert_eq!(m.tree().get(key(200, 1)).unwrap().parent, Some(key(100, 1)));
        // A child created after the reuse gets the new process.
        m.handle_decoded(KernelEvent::ProcessStart(start(201, 6, 100, 100)), &e);
        assert_eq!(m.tree().get(key(201, 6)).unwrap().parent, Some(key(100, 5)));
        // A child created in the gap has no parent.
        m.handle_decoded(KernelEvent::ProcessStart(start(202, 3, 100, 100)), &e);
        assert_eq!(m.tree().get(key(202, 3)).unwrap().parent, None);
        let stops = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(e, TelemetryEvent::ProcessStop { .. }))
            .count();
        assert_eq!(stops, 1);
    }

    #[test]
    fn a_creator_that_is_not_the_parent_is_reported() {
        let sink = Collect::default();
        let mut m = monitor(&sink, MonitorSettings::default());
        let e = NoEnrichment;
        m.handle_decoded(KernelEvent::ProcessStart(start(10, 1, 0, 0)), &e);
        m.handle_decoded(KernelEvent::ProcessStart(start(11, 1, 0, 0)), &e);
        m.handle_decoded(KernelEvent::ProcessStart(start(12, 2, 10, 11)), &e);
        let events = sink.0.lock().unwrap().clone();
        assert!(events.contains(&TelemetryEvent::ParentSpoof {
            child: key(12, 2),
            parent_pid: 10,
            creator: key(11, 1),
        }));
        assert_eq!(m.tree().get(key(12, 2)).unwrap().creator, Some(key(11, 1)));
        // The system process as creator is not a spoof; nor is an unknown
        // creator.
        m.handle_decoded(KernelEvent::ProcessStart(start(13, 3, 10, 4)), &e);
        m.handle_decoded(KernelEvent::ProcessStart(start(14, 3, 10, 999)), &e);
        assert_eq!(m.tree().get(key(13, 3)).unwrap().creator, None);
        assert_eq!(m.tree().get(key(14, 3)).unwrap().creator, None);
    }

    #[test]
    fn image_loads_follow_the_dll_setting() {
        let image = |pid: u32, name: &str| ImageEvent {
            pid,
            base: 1,
            size: 2,
            checksum: 3,
            time_date_stamp: 4,
            default_base: 5,
            image_name: name.into(),
            timestamp: UtcTime(10),
        };
        for (setting, libraries) in [
            (DllEvents::None, 0),
            (DllEvents::UntrustedOnly, 1),
            (DllEvents::All, 1),
        ] {
            let sink = Collect::default();
            let settings = MonitorSettings {
                dll_events: setting,
                ..MonitorSettings::default()
            };
            let mut m = monitor(&sink, settings);
            let e = NoEnrichment;
            m.handle_decoded(KernelEvent::ProcessStart(start(10, 1, 0, 0)), &e);
            sink.0.lock().unwrap().clear();
            m.handle_decoded(
                KernelEvent::ImageLoad(image(10, "\\Device\\HarddiskVolume3\\p10.exe")),
                &e,
            );
            m.handle_decoded(
                KernelEvent::ImageLoad(image(10, "\\Device\\HarddiskVolume3\\x.dll")),
                &e,
            );
            m.handle_decoded(
                KernelEvent::ImageLoad(image(4, "\\SystemRoot\\drv.sys")),
                &e,
            );
            m.handle_decoded(KernelEvent::ImageUnload(image(10, "x.dll")), &e);
            let events = sink.0.lock().unwrap().clone();
            let kinds: Vec<_> = events
                .iter()
                .map(|e| match e {
                    TelemetryEvent::ImageLoad(i) => i.kind,
                    other => panic!("{other:?}"),
                })
                .collect();
            assert_eq!(
                kinds.iter().filter(|k| **k == ImageKind::Library).count(),
                libraries,
                "{setting:?}"
            );
            assert!(kinds.contains(&ImageKind::Driver));
            assert!(!kinds.contains(&ImageKind::Executable));
            for event in &events {
                let TelemetryEvent::ImageLoad(i) = event else {
                    unreachable!()
                };
                if i.kind == ImageKind::Library {
                    assert_eq!(i.process, Some(key(10, 1)));
                    assert_eq!(i.image_path_normalised.as_deref(), Some("C:\\x.dll"));
                } else {
                    assert_eq!(i.process, None);
                    assert_eq!(i.image_path_normalised, None);
                }
            }
        }
    }

    #[test]
    fn drops_bad_records_and_full_trees_are_counted() {
        let sink = Collect(Mutex::default(), true);
        let counters = Arc::new(Counters::default());
        let mut m = ProcessMonitor::new(
            ProcessTree::new(1, DEFAULT_RETENTION),
            MonitorSettings {
                process_stop_events: false,
                ..MonitorSettings::default()
            },
            VolumeMap::new(),
            &sink,
            Arc::clone(&counters),
        );
        let e = NoEnrichment;
        let mut bad = encode::process_start(&start(1, 1, 0, 0), 0, 0);
        bad.data.truncate(3);
        m.handle(&bad, &e);
        assert_eq!(Counters::get(&counters.decode_errors), 1);
        m.handle_decoded(KernelEvent::ProcessStart(start(1, 1, 0, 0)), &e);
        // Full: the second start is reported without being recorded.
        m.handle_decoded(KernelEvent::ProcessStart(start(2, 2, 1, 1)), &e);
        assert!(m.tree().get(key(2, 2)).is_none());
        assert_eq!(Counters::get(&counters.dropped), 2);
        // A stop with stop events off emits nothing; an unknown stop is
        // ignored.
        let stop = |pid, created| {
            KernelEvent::ProcessStop(ProcessStop {
                pid,
                sequence: None,
                created: UtcTime(created),
                exited: UtcTime(9),
                exit_code: 1,
                image_name: "a".into(),
            })
        };
        m.handle_decoded(stop(1, 1), &e);
        m.handle_decoded(stop(7, 7), &e);
        assert_eq!(Counters::get(&counters.dropped), 2);
        assert_eq!(m.tick(UtcTime(i64::MAX)), 1);
        assert!(format!("{m:?}").contains("ProcessMonitor"));
        assert!(m.settings().process_stop_events.eq(&false));
    }

    #[test]
    fn the_post_start_action_sees_every_recorded_start() {
        struct Count(AtomicUsize);
        impl PostStartAction for Count {
            fn on_start(&self, _process: &ProcInfo) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let sink = Collect::default();
        let mut m = monitor(&sink, MonitorSettings::default());
        let action = Arc::new(Count(AtomicUsize::new(0)));
        m.set_post_start(action.clone());
        m.handle_decoded(KernelEvent::ProcessStart(start(1, 1, 0, 0)), &NoEnrichment);
        assert_eq!(action.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn enriched_tokens_win_over_the_start_record() {
        let sink = Collect::default();
        let mut m = monitor(&sink, MonitorSettings::default());
        let e = Fixed(Enrichment {
            command_line: None,
            token: Some(TokenFacts {
                integrity: Some(IntegrityLevel::High),
                ..TokenFacts::default()
            }),
        });
        m.handle_decoded(KernelEvent::ProcessStart(start(1, 1, 0, 0)), &e);
        let p = m.tree().get(key(1, 1)).unwrap();
        assert_eq!(p.token.integrity, Some(IntegrityLevel::High));
        assert_eq!(p.token.elevation, Some(Elevation::Limited));
        assert_eq!(p.command_line, CommandLine::Unavailable);
        assert_eq!(cmdline_text(&p.command_line), "");
        let _ = Duration::ZERO;
    }
}
