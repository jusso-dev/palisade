//! What the process monitor emits, and where it goes (#59).
//!
//! The event pipeline (#63, #197) owns the canonical envelope (sequence
//! numbers, the hash chain, the tenant and host), so the monitor emits
//! [`TelemetryEvent`]s into a [`TelemetrySink`] and the pipeline turns them
//! into canonical events. [`process_fields`] builds the canonical
//! `process` field set from the tree, so that translation is shared.
//!
//! The host connects the monitor to the pipeline's intake
//! (`crate::pipeline::intake::Intake`), a bounded queue that never blocks
//! the producer. A full queue refuses the event, which the monitor counts
//! ([`Counters::dropped`]) and the pipeline reports; a drop is never
//! silent. [`ChannelSink`] and [`DiscardSink`] remain for tests and fuzzing.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use palisade_core::platform::{Elevation, IntegrityLevel, ProcessKey, UtcTime};
use palisade_proto::events::{
    self, LongText, Name, ParentProcess, Process, ProcessSummary, TokenElevationType,
};

use super::tree::{ProcInfo, ProcessTree, key_text};

/// The kind of an image load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    /// A kernel-mode image (a driver).
    Driver,
    /// A user-mode image other than the process's main image.
    Library,
    /// The process's main image.
    Executable,
}

/// An image load the monitor reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageLoad {
    /// The process the image was mapped into; `None` for drivers and for
    /// processes not in the tree.
    pub process: Option<ProcessKey>,
    /// The kind.
    pub kind: ImageKind,
    /// The path as the OS reported it.
    pub image_path: String,
    /// The path with the device resolved to a drive, where possible.
    pub image_path_normalised: Option<String>,
    /// The base address.
    pub base: u64,
    /// The mapped size.
    pub size: u64,
    /// The image header checksum, for a quick identity pre-match.
    pub checksum: u32,
    /// The image header time stamp, for a quick identity pre-match.
    pub time_date_stamp: u32,
    /// When it was loaded.
    pub time: UtcTime,
}

/// An event from the process monitor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TelemetryEvent {
    /// A process started, with its record and ancestry.
    ProcessStart {
        /// The process.
        process: Box<ProcInfo>,
        /// Its ancestors, parent first.
        ancestry: Vec<ProcessKey>,
    },
    /// A process stopped.
    ProcessStop {
        /// The process.
        process: Box<ProcInfo>,
    },
    /// An image was loaded.
    ImageLoad(ImageLoad),
    /// A process was created by a process other than its recorded parent:
    /// re-parenting, or parent process ID spoofing. Advisory only.
    ParentSpoof {
        /// The new process.
        child: ProcessKey,
        /// The parent ID the OS recorded.
        parent_pid: u32,
        /// The process that created it.
        creator: ProcessKey,
    },
}

/// Counters shared by the monitor and its health report.
#[derive(Debug, Default)]
pub struct Counters {
    /// Events the sink could not accept.
    pub dropped: AtomicU64,
    /// Raw records the consumer could not queue for decoding.
    pub queue_dropped: AtomicU64,
    /// Raw records that did not decode.
    pub decode_errors: AtomicU64,
    /// Events the OS reports as lost from the session.
    pub os_lost: AtomicU64,
    /// Events emitted.
    pub emitted: AtomicU64,
}

impl Counters {
    /// Adds one to `counter`.
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The value of `counter`.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Where the monitor sends its events. Implementations must not block.
pub trait TelemetrySink: Send + Sync {
    /// Offers an event. Returns `false` if it was not accepted; the caller
    /// counts the drop.
    fn offer(&self, event: TelemetryEvent) -> bool;
}

/// A bounded channel, for tests.
#[derive(Debug, Clone)]
pub struct ChannelSink {
    tx: SyncSender<TelemetryEvent>,
}

/// The default capacity of [`ChannelSink::bounded`]: #59's identity queue
/// size.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 50_000;

impl ChannelSink {
    /// A channel holding at most `capacity` events, and its receiver.
    #[must_use]
    pub fn bounded(capacity: usize) -> (Self, Receiver<TelemetryEvent>) {
        let (tx, rx) = sync_channel(capacity);
        (Self { tx }, rx)
    }
}

impl TelemetrySink for ChannelSink {
    fn offer(&self, event: TelemetryEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }
}

/// A sink that accepts nothing: every event counts as dropped. For fuzzing
/// and tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiscardSink;

impl TelemetrySink for DiscardSink {
    fn offer(&self, _event: TelemetryEvent) -> bool {
        false
    }
}

impl<T: TelemetrySink + ?Sized> TelemetrySink for Arc<T> {
    fn offer(&self, event: TelemetryEvent) -> bool {
        (**self).offer(event)
    }
}

/// An optional action on a newly started process, such as terminating one
/// that policy denies (E06, E08, E14). Off by default. It acts after the
/// process has started, so it is never presented as prevention.
pub trait PostStartAction: Send + Sync {
    /// Called for each process start the monitor records.
    fn on_start(&self, process: &ProcInfo);
}

fn integrity(level: IntegrityLevel) -> events::IntegrityLevel {
    match level {
        IntegrityLevel::Untrusted => events::IntegrityLevel::Untrusted,
        IntegrityLevel::Low => events::IntegrityLevel::Low,
        IntegrityLevel::Medium => events::IntegrityLevel::Medium,
        IntegrityLevel::MediumPlus => events::IntegrityLevel::MediumPlus,
        IntegrityLevel::High => events::IntegrityLevel::High,
        IntegrityLevel::System => events::IntegrityLevel::System,
        IntegrityLevel::Protected => events::IntegrityLevel::Protected,
    }
}

fn elevation(e: Elevation) -> TokenElevationType {
    match e {
        Elevation::Default => TokenElevationType::Default,
        Elevation::Full => TokenElevationType::Full,
        Elevation::Limited => TokenElevationType::Limited,
    }
}

fn long(text: &str) -> Option<LongText> {
    LongText::new(text).ok()
}

/// The canonical fields of one process, without its parent. A value that
/// does not fit the schema is left out, never cut silently.
fn parent_fields(p: &ProcInfo) -> ParentProcess {
    ParentProcess {
        pid: Some(p.key.pid),
        process_key: Name::new(p.process_key()).ok(),
        image_path: long(&p.image_path),
        image_path_normalised: p.image_path_normalised.as_deref().and_then(long),
        cmdline: p.command_line.text().and_then(long),
        integrity_level: p.token.integrity.map(integrity),
        token_elevation_type: p.token.elevation.map(elevation),
        owner_sid: p.token.user_sid.as_deref().and_then(|s| s.parse().ok()),
        ..ParentProcess::default()
    }
}

/// The canonical `process` field set of a process start, from the record
/// the monitor emitted: the process, and its parent's key and ID when
/// known. The pipeline (#63) uses it for `process.created`; the monitor's
/// tree, with the full parent record, is [`process_fields`].
#[must_use]
pub fn start_fields(p: &ProcInfo, parent: Option<ProcessKey>) -> Process {
    let own = parent_fields(p);
    Process {
        pid: own.pid,
        process_key: own.process_key,
        image_path: own.image_path,
        image_path_normalised: own.image_path_normalised,
        cmdline: own.cmdline,
        integrity_level: own.integrity_level,
        token_elevation_type: own.token_elevation_type,
        owner_sid: own.owner_sid,
        parent: parent.map(|k| {
            Box::new(ParentProcess {
                pid: Some(k.pid),
                process_key: Name::new(key_text(k)).ok(),
                ..ParentProcess::default()
            })
        }),
        ..Process::default()
    }
}

/// The canonical `process` field set for process `key`: the process, its
/// parent and a summary of its grandparent, where the tree knows them.
#[must_use]
pub fn process_fields(tree: &ProcessTree, key: ProcessKey) -> Option<Process> {
    let p = tree.get(key)?;
    let own = parent_fields(p);
    let parent = p.parent.and_then(|k| tree.get(k));
    let grandparent = parent.and_then(|q| q.parent).and_then(|k| tree.get(k));
    Some(Process {
        pid: own.pid,
        process_key: own.process_key,
        image_path: own.image_path,
        image_path_normalised: own.image_path_normalised,
        cmdline: own.cmdline,
        integrity_level: own.integrity_level,
        token_elevation_type: own.token_elevation_type,
        owner_sid: own.owner_sid,
        parent: parent.map(|q| Box::new(parent_fields(q))),
        grandparent: grandparent.map(|g| ProcessSummary {
            pid: Some(g.key.pid),
            process_key: Name::new(key_text(g.key)).ok(),
            image_path: long(&g.image_path),
        }),
        ..Process::default()
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::tree::CommandLine;
    use super::*;

    fn key(pid: u32) -> ProcessKey {
        ProcessKey {
            pid,
            created: UtcTime(i64::from(pid)),
        }
    }

    #[test]
    fn process_fields_include_parent_and_grandparent() {
        let mut t = ProcessTree::new(10, Duration::from_secs(1));
        let mut g = ProcInfo::new(key(1), 0, "C:\\g.exe".into());
        g.token.integrity = Some(IntegrityLevel::System);
        t.insert(g);
        let mut p = ProcInfo::new(key(2), 1, "C:\\p.exe".into());
        p.parent = Some(key(1));
        p.token.elevation = Some(Elevation::Full);
        p.token.user_sid = Some("S-1-5-18".into());
        t.insert(p);
        let mut c = ProcInfo::new(key(3), 2, "\\Device\\HarddiskVolume3\\c.exe".into());
        c.parent = Some(key(2));
        c.image_path_normalised = Some("C:\\c.exe".into());
        c.command_line = CommandLine::Captured {
            text: "c.exe /x".into(),
            truncated: false,
        };
        for (level, want) in [
            (IntegrityLevel::Untrusted, events::IntegrityLevel::Untrusted),
            (IntegrityLevel::Low, events::IntegrityLevel::Low),
            (IntegrityLevel::Medium, events::IntegrityLevel::Medium),
            (
                IntegrityLevel::MediumPlus,
                events::IntegrityLevel::MediumPlus,
            ),
            (IntegrityLevel::High, events::IntegrityLevel::High),
            (IntegrityLevel::Protected, events::IntegrityLevel::Protected),
        ] {
            assert_eq!(integrity(level), want);
        }
        c.token.elevation = Some(Elevation::Limited);
        t.insert(c);
        let f = process_fields(&t, key(3)).unwrap();
        assert_eq!(f.pid, Some(3));
        assert_eq!(f.process_key.unwrap().as_str(), "3-3");
        assert_eq!(f.cmdline.unwrap().as_str(), "c.exe /x");
        assert_eq!(f.image_path_normalised.unwrap().as_str(), "C:\\c.exe");
        assert_eq!(f.token_elevation_type, Some(TokenElevationType::Limited));
        let parent = f.parent.unwrap();
        assert_eq!(parent.pid, Some(2));
        assert_eq!(parent.token_elevation_type, Some(TokenElevationType::Full));
        assert_eq!(parent.owner_sid.unwrap().as_str(), "S-1-5-18");
        assert_eq!(f.grandparent.unwrap().pid, Some(1));
        let g = process_fields(&t, key(1)).unwrap();
        assert_eq!(g.integrity_level, Some(events::IntegrityLevel::System));
        assert!(g.parent.is_none());
        assert!(process_fields(&t, key(9)).is_none());
        // A default-elevation token maps too.
        assert_eq!(elevation(Elevation::Default), TokenElevationType::Default);
    }

    #[test]
    fn channel_sink_is_bounded_and_never_blocks() {
        let (sink, rx) = ChannelSink::bounded(1);
        let ev = || TelemetryEvent::ParentSpoof {
            child: key(1),
            parent_pid: 2,
            creator: key(3),
        };
        assert!(sink.offer(ev()));
        assert!(!sink.offer(ev()));
        assert_eq!(rx.try_recv().unwrap(), ev());
        drop(rx);
        assert!(!sink.offer(ev()));
        assert!(!DiscardSink.offer(ev()));
        let shared: Arc<dyn TelemetrySink> = Arc::new(DiscardSink);
        assert!(!shared.offer(ev()));
    }

    #[test]
    fn counters_count() {
        let c = Counters::default();
        Counters::bump(&c.dropped);
        assert_eq!(Counters::get(&c.dropped), 1);
    }
}
