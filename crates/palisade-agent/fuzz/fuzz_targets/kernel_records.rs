//! Fuzzes the kernel process provider's record decoder and the process
//! monitor that consumes it (#59). The input is a sequence of records, as
//! the ETW session delivers them from the OS: each is a 6-byte header (the
//! event ID as `u16` LE, the version, the pointer size and the user data
//! length as `u16` LE) followed by the user data. No input may panic, and
//! the process tree must stay within its bounds.
#![no_main]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use palisade_agent::telemetry::kernel::{KERNEL_PROCESS, RawEvent, decode};
use palisade_agent::telemetry::monitor::{MonitorSettings, NoEnrichment, ProcessMonitor};
use palisade_agent::telemetry::output::{Counters, DiscardSink};
use palisade_agent::telemetry::tree::ProcessTree;
use palisade_core::path::VolumeMap;
use palisade_core::platform::UtcTime;

/// A small tree, so eviction and rejection are reached.
const CAPACITY: usize = 64;

/// The settings, built once: compiling the redaction patterns per input
/// would dominate the run time.
fn settings() -> &'static MonitorSettings {
    static SETTINGS: OnceLock<MonitorSettings> = OnceLock::new();
    SETTINGS.get_or_init(MonitorSettings::default)
}

fuzz_target!(|data: &[u8]| {
    let mut monitor = ProcessMonitor::new(
        ProcessTree::new(CAPACITY, Duration::from_micros(1000)),
        settings().clone(),
        VolumeMap::new(),
        DiscardSink,
        Arc::new(Counters::default()),
    );
    let mut rest = data;
    while let [id0, id1, version, pointer_size, len0, len1, tail @ ..] = rest {
        let len = usize::from(u16::from_le_bytes([*len0, *len1])).min(tail.len());
        let (body, next) = tail.split_at(len);
        rest = next;
        let raw = RawEvent {
            provider: KERNEL_PROCESS,
            id: u16::from_le_bytes([*id0, *id1]),
            version: *version,
            pointer_size: *pointer_size,
            header_pid: u32::from(*id0),
            header_tid: 0,
            timestamp: u64::from(*len0) << 20,
            data: body.to_vec(),
        };
        // Decoding is deterministic.
        assert_eq!(decode(&raw), decode(&raw));
        monitor.handle(&raw, &NoEnrichment);
        assert!(monitor.tree().len() <= CAPACITY);
        monitor.tick(UtcTime(i64::from(*len1) << 10));
    }
});
