use super::*;
use crate::pipeline::aggregate::AllowedMode;
use crate::pipeline::chain;
use crate::pipeline::spool::{SegmentSpool, SpoolLimits};
use crate::pipeline::storage::MemoryStorage;
use crate::pipeline::testing::{at, event, exec};

fn pipeline_with(
    storage: &MemoryStorage,
    settings: PipelineSettings,
    limits: SpoolLimits,
) -> Pipeline {
    let (spool, recovery) = SegmentSpool::open(storage.clone(), limits).unwrap();
    Pipeline::new(
        Identity::unenrolled(),
        settings,
        Box::new(spool),
        &recovery,
        [1, 2, 3, 4],
    )
}

fn pipeline(storage: &MemoryStorage) -> Pipeline {
    pipeline_with(storage, PipelineSettings::default(), SpoolLimits::default())
}

/// Every spooled event, in sequence order.
fn spooled(p: &mut Pipeline) -> Vec<Event> {
    let mut all = Vec::new();
    for class in Class::ALL {
        all.extend(
            p.spool_mut()
                .pending(class, None, usize::MAX, usize::MAX)
                .unwrap(),
        );
    }
    all.sort_by_key(|r| r.seq);
    all.iter()
        .map(|r| Event::from_json(std::str::from_utf8(&r.payload).unwrap()).unwrap())
        .collect()
}

#[test]
fn events_are_stamped_chained_and_spooled_by_class() {
    let storage = MemoryStorage::default();
    let mut p = pipeline(&storage);
    p.submit(exec(Outcome::Blocked, 0, "C:\\x.exe"), 10);
    p.submit(event(EventType::AgentTamper, Outcome::Info, 1), 11);
    p.submit(event(EventType::ProcessCreated, Outcome::Info, 2), 12);
    // An allowed event is folded into a summary: nothing yet.
    p.submit(exec(Outcome::Allowed, 3, "C:\\a.exe"), 13);
    p.tick(at(4), 14);
    let events = spooled(&mut p);
    assert_eq!(
        events.iter().map(|e| e.event_type).collect::<Vec<_>>(),
        [
            EventType::ExecDecision,
            EventType::AgentTamper,
            EventType::ProcessCreated
        ]
    );
    assert!(chain::verify(None, &events));
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.validate(), Ok(()), "{e:?}");
        assert_eq!(e.ts_agent_monotonic, Some(10 + u64::try_from(i).unwrap()));
        assert_eq!(e.tenant_id, Identity::unenrolled().tenant);
        assert!(e.clock_synced);
    }
    // Event IDs are unique.
    let ids: std::collections::BTreeSet<_> = events.iter().map(|e| e.event_id).collect();
    assert_eq!(ids.len(), events.len());
    let stats = p.stats();
    assert_eq!(stats.spooled, 3);
    assert_eq!(stats.submitted.get(&Class::Allowed), Some(&1));
    assert_eq!(p.aggregate_stats().folded, 1);
    // The summary arrives when its window closes.
    p.tick(at(3 + 3600), 15);
    let events = spooled(&mut p);
    let summary = events.last().unwrap();
    assert_eq!(
        summary.aggregate.as_ref().unwrap().kind,
        palisade_proto::events::AggregateKind::Summary
    );
    assert_eq!(summary.schema_version, palisade_proto::events::V1_4);
    assert!(chain::verify(None, &events));
    assert!(format!("{p:?}").contains("Pipeline"));
}

#[test]
fn the_chain_continues_after_a_restart() {
    let storage = MemoryStorage::default();
    let mut p = pipeline(&storage);
    p.submit(exec(Outcome::Blocked, 0, "C:\\x.exe"), 1);
    p.tick(at(1), 2);
    let head = p.spool_mut().head();
    drop(p);
    let mut p = pipeline(&storage);
    p.submit(exec(Outcome::Blocked, 2, "C:\\y.exe"), 3);
    p.tick(at(3), 4);
    let events = spooled(&mut p);
    assert_eq!(events.len(), 2);
    assert!(chain::verify(None, &events));
    assert_eq!(events[1].seq, head.unwrap().0 + 1);
}

#[test]
fn spool_losses_are_reported_as_agent_dropped() {
    let storage = MemoryStorage::default();
    // Room for very little: allowed events in full evict each other.
    let limits = SpoolLimits {
        segment_bytes: 1,
        max_bytes: 6000,
        soft_percent: 50,
        ..SpoolLimits::default()
    };
    let settings = PipelineSettings {
        aggregate: crate::pipeline::aggregate::AggregateSettings {
            allowed: AllowedMode::Complete,
            ..Default::default()
        },
        ..PipelineSettings::default()
    };
    let mut p = pipeline_with(&storage, settings, limits);
    for i in 0..20 {
        p.submit(exec(Outcome::Allowed, i, &format!("C:\\{i}.exe")), 1);
    }
    assert!(p.stats().lost > 0);
    p.tick(at(30), 2);
    let events = spooled(&mut p);
    let dropped: Vec<&Event> = events
        .iter()
        .filter(|e| e.event_type == EventType::AgentDropped)
        .collect();
    assert_eq!(dropped.len(), 1);
    let agent = dropped[0].agent.as_ref().unwrap();
    assert_eq!(agent.dropped_count, Some(p.stats().lost));
    let loss = &agent.losses.as_slice()[0];
    assert_eq!(loss.class, LossClass::Allowed);
    assert_eq!(loss.reason, LossReason::SpoolFull);
    assert!(loss.from_seq.is_some() && loss.to_seq >= loss.from_seq);
    assert_eq!(dropped[0].validate(), Ok(()));
    // Reported once.
    p.tick(at(31), 3);
    assert_eq!(
        spooled(&mut p)
            .iter()
            .filter(|e| e.event_type == EventType::AgentDropped)
            .count(),
        1
    );
}

#[test]
fn queue_losses_and_write_failures_are_reported() {
    let storage = MemoryStorage::default();
    let mut p = pipeline(&storage);
    p.record_queue_loss(Class::Info, 5);
    p.record_queue_loss(Class::Info, 0);
    storage.fail_writes(true);
    p.submit(exec(Outcome::Blocked, 0, "C:\\x.exe"), 1);
    assert_eq!(p.stats().spool_errors, 1);
    assert!(p.stats().last_error.is_some());
    storage.fail_writes(false);
    p.tick(at(1), 2);
    let events = spooled(&mut p);
    let dropped = events
        .iter()
        .find(|e| e.event_type == EventType::AgentDropped)
        .unwrap();
    let losses = dropped.agent.as_ref().unwrap().losses.as_slice();
    let kinds: Vec<_> = losses
        .iter()
        .map(|l| (l.class, l.reason, l.count.get()))
        .collect();
    assert!(kinds.contains(&(LossClass::Info, LossReason::QueueFull, 5)));
    assert!(kinds.contains(&(LossClass::Blocked, LossReason::Corrupt, 1)));
    // The failed write did not use up a sequence number.
    assert!(chain::verify(None, &events));
}

#[test]
fn a_throttle_storm_never_suppresses_a_block() {
    let storage = MemoryStorage::default();
    let settings = PipelineSettings {
        aggregate: crate::pipeline::aggregate::AggregateSettings {
            allowed: AllowedMode::Complete,
            ..Default::default()
        },
        throttle: ThrottleSettings {
            per_hour: 50,
            ..ThrottleSettings::default()
        },
    };
    let mut p = pipeline_with(&storage, settings, SpoolLimits::default());
    // A fork bomb of distinct allowed binaries.
    for i in 0..500 {
        p.submit(exec(Outcome::Allowed, 0, &format!("C:\\bomb{i}.exe")), 1);
    }
    p.submit(exec(Outcome::Blocked, 0, "C:\\evil.exe"), 2);
    p.tick(at(1), 3);
    let events = spooled(&mut p);
    assert!(events.iter().any(|e| e.outcome == Outcome::Blocked
        && e.file.as_ref().unwrap().path.as_ref().unwrap().as_str() == "C:\\evil.exe"));
    let types: Vec<EventType> = events.iter().map(|e| e.event_type).collect();
    assert!(types.contains(&EventType::AgentThrottled));
    assert!(types.contains(&EventType::AgentDropped));
    assert!(p.stats().throttling);
    // Once throttling, allowed events are summarised rather than sent.
    let allowed_full = events
        .iter()
        .filter(|e| e.outcome == Outcome::Allowed && e.aggregate.is_none())
        .count();
    assert!(allowed_full < 50, "{allowed_full}");
    // Counts stay exact: every allowed occurrence is in a full event, a
    // summary or the loss report.
    p.flush(at(2), 4);
    let events = spooled(&mut p);
    let allowed: u64 = events
        .iter()
        .filter(|e| e.outcome == Outcome::Allowed)
        .map(|e| e.aggregate.as_ref().map_or(1, |a| a.count.get()))
        .sum();
    let lost: u64 = events
        .iter()
        .filter_map(|e| e.agent.as_ref())
        .flat_map(|a| a.losses.as_slice())
        .filter(|l| l.class == LossClass::Allowed)
        .map(|l| l.count.get())
        .sum();
    assert_eq!(allowed + lost, 500);
    assert!(chain::verify(None, &events));
}

#[test]
fn clock_identity_and_settings_changes_apply() {
    let storage = MemoryStorage::default();
    let mut p = pipeline(&storage);
    p.set_clock(ClockState {
        synced: false,
        skew_ms: Some(-400_000),
    });
    let mut identity = Identity::unenrolled();
    identity.tenant = TenantId(crate::pipeline::testing::uuid(7));
    identity.host.name = palisade_proto::events::Name::new("pc1").ok();
    p.set_identity(identity.clone());
    p.submit(exec(Outcome::Allowed, 0, "C:\\a.exe"), 1);
    // A new policy flushes the open summary into the spool.
    p.reconfigure(PipelineSettings::default(), at(1), 2);
    let events = spooled(&mut p);
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(
        e.ts_agent_monotonic,
        Some(2),
        "re-enveloped with its own ID"
    );
    assert!(!e.clock_synced);
    assert_eq!(e.clock_skew_ms, Some(-400_000));
    assert_eq!(e.tenant_id, identity.tenant);
    assert_eq!(e.host.name.as_ref().unwrap().as_str(), "pc1");
}

#[test]
fn damaged_spool_segments_are_reported_at_the_first_tick() {
    let storage = MemoryStorage::default();
    let mut p = pipeline(&storage);
    p.submit(exec(Outcome::Blocked, 0, "C:\\x.exe"), 1);
    p.tick(at(1), 2);
    drop(p);
    let id = storage.list_ids()[0];
    storage.corrupt(id, |b| b.extend_from_slice(&[9, 9, 9]));
    let mut p = pipeline(&storage);
    p.tick(at(2), 3);
    let events = spooled(&mut p);
    let dropped = events
        .iter()
        .find(|e| e.event_type == EventType::AgentDropped)
        .unwrap();
    let loss = &dropped.agent.as_ref().unwrap().losses.as_slice()[0];
    assert_eq!(
        (loss.class, loss.reason),
        (LossClass::Blocked, LossReason::Corrupt)
    );
}

#[test]
fn many_kinds_of_loss_fit_in_one_report() {
    let mut losses = Losses::default();
    for class in Class::ALL {
        for reason in [
            LossReason::QueueFull,
            LossReason::Throttled,
            LossReason::SpoolFull,
            LossReason::Expired,
        ] {
            losses.add(class, reason, 1, Some((1, 2)));
        }
    }
    assert_eq!(losses.total(), 28);
    let taken = losses.take();
    assert_eq!(taken.len(), 16);
    assert_eq!(taken.iter().map(|l| l.count.get()).sum::<u64>(), 28);
    // The highest classes are kept apart.
    assert_eq!(taken.last().unwrap().class, LossClass::Security);
    assert_eq!(losses.total(), 0);
}

#[test]
fn event_ids_are_valid_and_distinct() {
    let mut ids = EventIds::new([9, 9, 9, 9]);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..10_000 {
        assert!(seen.insert(ids.next(at(0))));
    }
    // The time prefix orders IDs across milliseconds.
    let a = ids.next(at(0));
    let b = ids.next(at(1));
    assert!(a.as_bytes()[..6] < b.as_bytes()[..6]);
    assert!(new_event(EventType::AgentStarted, Outcome::Info, "Bad", "x", at(0)).is_none());
}
