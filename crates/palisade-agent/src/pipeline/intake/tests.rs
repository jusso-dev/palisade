use std::time::Duration;

use palisade_core::platform::{ProcessKey, UtcTime};
use palisade_proto::policy_bundle::{BundleMeta, Rejection, select::CacheFile, stale::Staleness};

use super::*;
use crate::pipeline::testing::{event, exec};
use crate::telemetry::tree::{CommandLine, ProcInfo};

#[derive(Debug)]
struct Fixed;

impl WallClock for Fixed {
    fn now_micros(&self) -> i64 {
        1_700_000_000_000_000
    }
}

fn key(pid: u32) -> ProcessKey {
    ProcessKey {
        pid,
        created: UtcTime(1_700_000_000_000_000 + i64::from(pid)),
    }
}

#[test]
fn priority_events_have_their_own_queue() {
    let (intake, outlet) = channel(1, 1);
    assert!(intake.offer(exec(Outcome::Allowed, 0, "C:\\a.exe")));
    assert!(
        !intake.offer(exec(Outcome::Allowed, 1, "C:\\a.exe")),
        "bulk full"
    );
    assert!(
        intake.offer(exec(Outcome::Blocked, 2, "C:\\x.exe")),
        "priority has room"
    );
    assert!(!intake.offer(event(EventType::AgentTamper, Outcome::Info, 3)));
    assert_eq!(
        outlet.take_refused(),
        [(Class::Allowed, 1), (Class::Security, 1)]
    );
    assert!(outlet.take_refused().is_empty());
    // Priority first.
    let first = outlet.recv(Duration::ZERO).unwrap();
    assert_eq!(first.outcome, Outcome::Blocked);
    assert_eq!(
        outlet.recv(Duration::ZERO).unwrap().outcome,
        Outcome::Allowed
    );
    assert!(outlet.recv(Duration::from_millis(1)).is_none());
    // A priority event that arrives while waiting is not lost.
    assert!(intake.offer(exec(Outcome::Blocked, 4, "C:\\x.exe")));
    assert!(outlet.recv(Duration::from_millis(1)).is_some());
    drop(outlet);
    assert!(
        !intake.offer(exec(Outcome::Blocked, 5, "C:\\x.exe")),
        "stopped"
    );
}

#[test]
fn process_starts_become_process_created_and_the_rest_is_counted() {
    let (intake, outlet) = channel(4, 4);
    let mut p = ProcInfo::new(key(10), 4, "C:\\Windows\\cmd.exe".into());
    p.command_line = CommandLine::Captured {
        text: "cmd /c dir".into(),
        truncated: false,
    };
    p.token.user_sid = Some("S-1-5-21-1-2-3-1001".into());
    p.session_id = Some(1);
    p.token.elevated = Some(false);
    assert!(TelemetrySink::offer(
        &intake,
        TelemetryEvent::ProcessStart {
            process: Box::new(p),
            ancestry: vec![key(4)],
        }
    ));
    let e = outlet.recv(Duration::ZERO).unwrap();
    assert_eq!(e.event_type, EventType::ProcessCreated);
    assert_eq!(e.validate(), Ok(()));
    let process = e.process.as_ref().unwrap();
    assert_eq!(process.pid, Some(10));
    assert_eq!(process.cmdline.as_ref().unwrap().as_str(), "cmd /c dir");
    assert_eq!(process.parent.as_ref().unwrap().pid, Some(4));
    let user = e.user.as_ref().unwrap();
    assert_eq!(user.session_id, Some(1));
    assert_eq!(user.elevated, Some(false));
    // A start without a parent or user.
    assert!(TelemetrySink::offer(
        &intake,
        TelemetryEvent::ProcessStart {
            process: Box::new(ProcInfo::new(key(11), 0, "C:\\a.exe".into())),
            ancestry: Vec::new(),
        }
    ));
    let e = outlet.recv(Duration::ZERO).unwrap();
    assert!(e.user.is_none() && e.process.as_ref().unwrap().parent.is_none());
    // No canonical type yet: counted, not lost.
    assert!(TelemetrySink::offer(
        &intake,
        TelemetryEvent::ProcessStop {
            process: Box::new(ProcInfo::new(key(10), 4, "x".into())),
        }
    ));
    assert!(TelemetrySink::offer(
        &intake,
        TelemetryEvent::ParentSpoof {
            child: key(1),
            parent_pid: 2,
            creator: key(3),
        }
    ));
    assert_eq!(intake.unmapped(), 2);
    assert!(outlet.recv(Duration::ZERO).is_none());
}

#[test]
fn event_log_events_go_in_unchanged_and_envelopes_are_placeholders() {
    let (mut intake, outlet) = channel(4, 4);
    let e = exec(Outcome::Audited, 0, "C:\\x.exe");
    assert!(EventSink::offer(&mut intake, e.clone()));
    assert_eq!(outlet.recv(Duration::ZERO).unwrap(), e);
    let env = EnvelopeSource::next(&mut intake);
    assert_eq!(env.seq, 0);
    assert_eq!(env.tenant_id, Identity::unenrolled().tenant);
}

#[test]
fn policy_events_become_canonical_events() {
    let meta = BundleMeta {
        target: palisade_proto::policy_bundle::Target {
            tenant: palisade_proto::events::TenantId(crate::pipeline::testing::uuid(1)),
            scope: palisade_proto::policy_bundle::Scope::Group(crate::pipeline::testing::uuid(2)),
        },
        version: 7,
        sha256: palisade_proto::events::Sha256Hex::from_bytes([1; 32]),
    };
    let ts = Timestamp::from_unix_micros(Fixed.now_micros()).unwrap();
    let cases = [
        Detail::Applied(meta),
        Detail::Rejected(Rejection::Rollback),
        Detail::Stale(Staleness {
            not_refreshed: true,
            expired: false,
        }),
        Detail::Tamper(Tamper::Memory),
        Detail::Tamper(Tamper::File(CacheFile::Active)),
        Detail::Emergency { enforced: true },
        Detail::Emergency { enforced: false },
        Detail::Finding(Finding::LkgLoaded),
        Detail::Finding(Finding::LoadedUnsigned),
        Detail::Finding(Finding::EmergencyLoaded),
        Detail::Finding(Finding::RollbackSuspected(Default::default())),
        Detail::Finding(Finding::Rejected {
            file: CacheFile::Previous,
            reason: Rejection::SignatureInvalid,
        }),
    ];
    for detail in cases {
        for load in [
            Load::Active {
                bundle: meta,
                signed: true,
            },
            Load::Emergency,
        ] {
            let pe = PolicyEvent {
                detail: detail.clone(),
                load,
            };
            let e = policy_event(&pe, ts).unwrap();
            assert_eq!(e.event_type, pe.event_type());
            assert_eq!(e.validate(), Ok(()), "{detail:?}");
        }
    }
    let applied = policy_event(
        &PolicyEvent {
            detail: Detail::Applied(meta),
            load: Load::FirstInstall,
        },
        ts,
    )
    .unwrap();
    assert_eq!(applied.policy.as_ref().unwrap().version, Some(7));
    // Tamper is security class: it goes in the priority queue.
    let (intake, outlet) = channel(1, 1);
    let sink = PolicySink::new(intake, Box::new(Fixed));
    assert!(sink.emit(PolicyEvent {
        detail: Detail::Tamper(Tamper::Memory),
        load: Load::Emergency,
    }));
    let e = outlet.recv(Duration::ZERO).unwrap();
    assert_eq!(e.event_type, EventType::AgentTamper);
    assert_eq!(classify(&e), Class::Security);
}
