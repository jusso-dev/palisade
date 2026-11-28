//! The process monitor end to end on encoded kernel records (#59): a spawn
//! storm, a forced process ID reuse harness, and the fuzz seeds.

// Test code: helpers outside `#[test]` functions may unwrap or expect, since
// a failure there should fail the test loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

use palisade_agent::telemetry::kernel::{ImageEvent, ProcessStart, ProcessStop, RawEvent, encode};
use palisade_agent::telemetry::monitor::{
    Enricher, Enrichment, MonitorSettings, NoEnrichment, ProcessMonitor,
};
use palisade_agent::telemetry::output::{ChannelSink, Counters, TelemetryEvent};
use palisade_agent::telemetry::tree::{DEFAULT_CAPACITY, DEFAULT_RETENTION, ProcessTree};
use palisade_core::path::VolumeMap;
use palisade_core::platform::{Elevation, IntegrityLevel, ProcessKey, UtcTime};

const T0: i64 = 1_795_000_000_000_000;

fn start(pid: u32, created: i64, parent: u32, sequence: u64, parent_sequence: u64) -> ProcessStart {
    ProcessStart {
        pid,
        sequence: Some(sequence),
        created: UtcTime(created),
        parent_pid: parent,
        parent_sequence: Some(parent_sequence),
        session_id: 1,
        flags: Some(0),
        elevation: Some(Elevation::Limited),
        elevated: Some(false),
        integrity: Some(IntegrityLevel::Medium),
        image_name: "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe".into(),
        image_checksum: Some(1),
        time_date_stamp: Some(2),
        package_full_name: None,
        package_app_id: None,
        security_mitigations: Some(0),
        creator_pid: parent,
    }
}

fn stop(pid: u32, created: i64, exited: i64, sequence: u64) -> ProcessStop {
    ProcessStop {
        pid,
        sequence: Some(sequence),
        created: UtcTime(created),
        exited: UtcTime(exited),
        exit_code: 0,
        image_name: "cmd.exe".into(),
    }
}

struct CmdLine;
impl Enricher for CmdLine {
    fn enrich(&self, key: ProcessKey) -> Enrichment {
        Enrichment {
            command_line: Some(format!("cmd /c echo {}", key.pid)),
            token: None,
        }
    }
}

fn monitor() -> (
    ProcessMonitor<ChannelSink>,
    Receiver<TelemetryEvent>,
    Arc<Counters>,
) {
    let (sink, rx) = ChannelSink::bounded(100_000);
    let counters = Arc::new(Counters::default());
    let mut volumes = VolumeMap::new();
    volumes.insert("\\Device\\HarddiskVolume3", 'c');
    let m = ProcessMonitor::new(
        ProcessTree::new(DEFAULT_CAPACITY, DEFAULT_RETENTION),
        MonitorSettings::default(),
        volumes,
        sink,
        Arc::clone(&counters),
    );
    (m, rx, counters)
}

/// A 1,000-process `cmd /c` storm: a shell spawns each child, which spawns
/// a grandchild, and both exit. Every grandchild has the right parent and
/// grandparent and a command line, and nothing is lost.
#[test]
fn a_spawn_storm_is_fully_observed() {
    let (mut m, rx, counters) = monitor();
    let shell = start(500, T0, 4, 1, 0);
    m.handle(&encode::process_start(&shell, 4, 0), &CmdLine);
    let mut seq = 10;
    let mut t = T0;
    for i in 0..500_u32 {
        let child_pid = 1000 + (i % 50) * 4; // IDs are reused across rounds.
        let grandchild_pid = 5000 + (i % 50) * 4;
        t += 10;
        let child_seq = seq;
        m.handle(
            &encode::process_start(&start(child_pid, t, 500, child_seq, 1), 4, 0),
            &CmdLine,
        );
        t += 10;
        m.handle(
            &encode::process_start(
                &start(grandchild_pid, t, child_pid, child_seq + 1, child_seq),
                4,
                0,
            ),
            &CmdLine,
        );
        t += 10;
        m.handle(
            &encode::process_stop(&stop(grandchild_pid, t - 10, t, child_seq + 1), 2, 0),
            &NoEnrichment,
        );
        m.handle(
            &encode::process_stop(&stop(child_pid, t - 20, t, child_seq), 2, 0),
            &NoEnrichment,
        );
        seq += 2;
    }
    let events: Vec<_> = rx.try_iter().collect();
    let starts: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            TelemetryEvent::ProcessStart { process, ancestry } => Some((process, ancestry)),
            _ => None,
        })
        .collect();
    assert_eq!(starts.len(), 1001);
    for (process, ancestry) in &starts[1..] {
        assert!(
            process
                .command_line
                .text()
                .unwrap()
                .starts_with("cmd /c echo")
        );
        assert_eq!(
            process.image_path_normalised.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        if process.key.pid >= 5000 {
            assert_eq!(ancestry.len(), 2, "{process:?}");
            let parent = ancestry[0];
            assert_eq!(parent.created.0, process.key.created.0 - 10);
            assert_eq!(ancestry[1].pid, 500);
        } else {
            assert_eq!(ancestry.len(), 1);
        }
    }
    let stops = events
        .iter()
        .filter(|e| matches!(e, TelemetryEvent::ProcessStop { .. }))
        .count();
    assert_eq!(stops, 1000);
    assert_eq!(Counters::get(&counters.dropped), 0);
    assert_eq!(Counters::get(&counters.decode_errors), 0);
}

/// Forced process ID reuse: every process reuses one ID right after the
/// previous holder exits, and the ancestry of each is still exact.
#[test]
fn forced_pid_reuse_does_not_corrupt_ancestry() {
    let (mut m, rx, _) = monitor();
    let mut t = T0;
    // Generation g: process 100 (reused every time) spawns process 200
    // (also reused). Without creation times, 200 of generation g would be
    // linked to 100 of generation g + 1.
    for g in 0..200_u64 {
        t += 100;
        let parent = start(100, t, 4, 1000 + 2 * g, 0);
        m.handle(&encode::process_start(&parent, 4, 0), &NoEnrichment);
        let child = start(200, t + 1, 100, 1001 + 2 * g, 1000 + 2 * g);
        m.handle(&encode::process_start(&child, 4, 0), &NoEnrichment);
        m.handle(
            &encode::process_stop(&stop(100, t, t + 2, 1000 + 2 * g), 2, 0),
            &NoEnrichment,
        );
        m.handle(
            &encode::process_stop(&stop(200, t + 1, t + 3, 1001 + 2 * g), 2, 0),
            &NoEnrichment,
        );
    }
    // Late start records, older than the processes now using the IDs,
    // without sequence numbers: they are matched by creation time.
    let late = ProcessStart {
        sequence: None,
        parent_sequence: None,
        ..start(300, T0 + 101, 100, 0, 0)
    };
    m.handle(&encode::process_start(&late, 2, 0), &NoEnrichment);
    for e in rx.try_iter() {
        if let TelemetryEvent::ProcessStart { process, ancestry } = e {
            if process.key.pid == 200 {
                assert_eq!(ancestry.len(), 1);
                assert_eq!(ancestry[0].pid, 100);
                assert_eq!(ancestry[0].created.0, process.key.created.0 - 1);
            }
            if process.key.pid == 300 {
                assert_eq!(
                    ancestry,
                    [ProcessKey {
                        pid: 100,
                        created: UtcTime(T0 + 100)
                    }]
                );
            }
        }
    }
}

/// Seeds for the `kernel_records` fuzz target, in its input format.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR=target/seeds \
///     cargo test -p palisade-agent --test telemetry -- --ignored write_kernel_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_kernel_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    let frame = |out: &mut Vec<u8>, raw: &RawEvent| {
        out.extend_from_slice(&raw.id.to_le_bytes());
        out.push(raw.version);
        out.push(raw.pointer_size);
        out.extend_from_slice(&u16::try_from(raw.data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&raw.data);
    };
    let image = ImageEvent {
        pid: 4,
        base: 0x1000,
        size: 0x2000,
        checksum: 1,
        time_date_stamp: 2,
        default_base: 0x1000,
        image_name: "\\SystemRoot\\System32\\drivers\\x.sys".into(),
        timestamp: UtcTime(T0),
    };
    let mut all = Vec::new();
    for v in 0..=4 {
        let mut one = Vec::new();
        frame(
            &mut one,
            &encode::process_start(&start(10, T0, 4, 1, 0), v, 0),
        );
        std::fs::write(dir.join(format!("seed-start-v{v}")), &one).unwrap();
        all.extend_from_slice(&one);
    }
    for v in 0..=2 {
        let mut one = Vec::new();
        frame(
            &mut one,
            &encode::process_stop(&stop(10, T0, T0 + 1, 1), v, 0),
        );
        std::fs::write(dir.join(format!("seed-stop-v{v}")), &one).unwrap();
        all.extend_from_slice(&one);
    }
    for ptr in [4, 8] {
        let mut one = Vec::new();
        frame(&mut one, &encode::image_load(&image, ptr));
        std::fs::write(dir.join(format!("seed-image-{ptr}")), &one).unwrap();
        all.extend_from_slice(&one);
    }
    std::fs::write(dir.join("seed-sequence"), &all).unwrap();
}
