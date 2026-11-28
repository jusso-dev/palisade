use proptest::prelude::*;

use super::*;
use crate::pipeline::testing::{at, event, exec};

const MIN: i64 = 60;

fn count(events: &[Event]) -> u64 {
    events
        .iter()
        .map(|e| e.aggregate.as_ref().map_or(1, |a| a.count.get()))
        .sum()
}

fn forwarded(d: Disposition) -> Event {
    match d {
        Disposition::Forward(e) => *e,
        other => panic!("expected a forward, got {other:?}"),
    }
}

#[test]
fn events_are_classified_by_type_and_outcome() {
    for (ty, outcome, class) in [
        (EventType::ExecDecision, Outcome::Allowed, Class::Allowed),
        (EventType::ExecDecision, Outcome::Blocked, Class::Blocked),
        (EventType::ExecDecision, Outcome::Audited, Class::Audit),
        (EventType::ScriptDecision, Outcome::Allowed, Class::Allowed),
        (EventType::ExecOriginCheck, Outcome::Info, Class::Diagnostic),
        (EventType::ProcessCreated, Outcome::Info, Class::Info),
        (EventType::PolicyApplied, Outcome::Info, Class::Info),
        (EventType::AgentTamper, Outcome::Info, Class::Security),
        (EventType::AgentDropped, Outcome::Info, Class::Security),
        (
            EventType::TamperPolicyRollbackSuspected,
            Outcome::Info,
            Class::Security,
        ),
        (EventType::AdminAction, Outcome::Info, Class::Security),
        // A tamper event is security class whatever its outcome.
        (EventType::AgentTamper, Outcome::Blocked, Class::Security),
    ] {
        assert_eq!(classify(&event(ty, outcome, 0)), class, "{ty} {outcome:?}");
    }
    let mut summary = exec(Outcome::Allowed, 0, "C:\\a.exe");
    summary.aggregate = Some(Aggregate {
        kind: AggregateKind::Summary,
        count: NonZeroU64::new(2).unwrap(),
        first_seen: at(0),
        last_seen: at(0),
        window_secs: None,
        partial: false,
        cmdline_samples: BoundedVec::default(),
    });
    assert_eq!(classify(&summary), Class::Summary);
}

#[test]
fn allowed_events_are_summarised_per_tuple_and_window() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    for i in 0..5 {
        assert_eq!(
            agg.offer(exec(Outcome::Allowed, i, "C:\\a.exe"), false),
            Disposition::Folded
        );
    }
    assert_eq!(
        agg.offer(exec(Outcome::Allowed, 7, "C:\\b.exe"), false),
        Disposition::Folded
    );
    assert_eq!(agg.open_tuples(), 2);
    // Nothing is due before the first partial (5 minutes).
    assert!(agg.tick(at(60).unix_micros()).is_empty());
    // A partial summary per tuple at 5 minutes, with the counts so far.
    let partial = agg.tick(at(5 * MIN + 7).unix_micros());
    assert_eq!(partial.len(), 2);
    let a = partial
        .iter()
        .find(|e| e.file.as_ref().unwrap().path.as_ref().unwrap().as_str() == "C:\\a.exe")
        .unwrap();
    let agg_a = a.aggregate.as_ref().unwrap();
    assert_eq!(agg_a.kind, AggregateKind::Summary);
    assert_eq!(agg_a.count.get(), 5);
    assert!(agg_a.partial);
    assert_eq!(agg_a.window_secs, Some(3600));
    assert_eq!((agg_a.first_seen, agg_a.last_seen), (at(0), at(4)));
    assert_eq!(a.validate(), Ok(()));
    // More in the same window; the closing summary carries only those.
    agg.offer(exec(Outcome::Allowed, 10 * MIN, "C:\\a.exe"), false);
    assert!(agg.tick(at(6 * MIN).unix_micros()).is_empty());
    assert!(
        agg.tick(at(10 * MIN + 6).unix_micros()).is_empty(),
        "nothing new for b"
    );
    // a's window closes at 60 minutes with its one new occurrence; b's,
    // 7 seconds later, with nothing new.
    let closed = agg.tick(at(60 * MIN).unix_micros());
    assert_eq!(count(&closed), 1);
    assert!(!closed[0].aggregate.as_ref().unwrap().partial);
    assert!(agg.tick(at(60 * MIN + 7).unix_micros()).is_empty());
    assert_eq!(agg.open_tuples(), 0);
    let stats = agg.stats();
    assert_eq!((stats.seen, stats.folded, stats.forwarded), (7, 7, 0));
    assert_eq!(stats.aggregates, 3);
}

#[test]
fn closing_events_with_nothing_new_emit_nothing() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    agg.offer(exec(Outcome::Allowed, 0, "C:\\a.exe"), false);
    let first = agg.tick(at(5 * MIN).unix_micros());
    assert_eq!(count(&first), 1);
    // Nothing since: the window closes silently.
    assert!(agg.tick(at(60 * MIN).unix_micros()).is_empty());
}

#[test]
fn summaries_keep_up_to_three_distinct_command_lines() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    for (i, cmd) in ["a /1", "a /2", "a /1", "a /3", "a /4"]
        .into_iter()
        .enumerate()
    {
        let mut e = exec(Outcome::Allowed, i64::try_from(i).unwrap(), "C:\\a.exe");
        e.process = Some(palisade_proto::events::Process {
            cmdline: Some(LongText::new(cmd).unwrap()),
            ..Default::default()
        });
        agg.offer(e, false);
    }
    let out = agg.flush_all();
    let samples: Vec<&str> = out[0]
        .aggregate
        .as_ref()
        .unwrap()
        .cmdline_samples
        .as_slice()
        .iter()
        .map(|t| t.as_str())
        .collect();
    assert_eq!(samples, ["a /1", "a /2", "a /3"]);
    assert_eq!(out[0].aggregate.as_ref().unwrap().count.get(), 5);
}

#[test]
fn modes_change_what_is_sent() {
    // Complete: everything in full.
    let mut agg = Aggregator::new(AggregateSettings {
        allowed: AllowedMode::Complete,
        ..AggregateSettings::default()
    });
    for i in 0..3 {
        forwarded(agg.offer(exec(Outcome::Allowed, i, "C:\\a.exe"), false));
    }
    assert!(agg.flush_all().is_empty());
    // A throttle above its watermark forces summaries even in complete.
    assert_eq!(
        agg.offer(exec(Outcome::Allowed, 4, "C:\\a.exe"), true),
        Disposition::Folded
    );

    // First seen: the first in full, the rest counted.
    let mut agg = Aggregator::new(AggregateSettings {
        allowed: AllowedMode::FirstSeen,
        ..AggregateSettings::default()
    });
    let first = forwarded(agg.offer(exec(Outcome::Allowed, 0, "C:\\a.exe"), false));
    assert!(first.aggregate.is_none());
    for i in 1..4 {
        assert_eq!(
            agg.offer(exec(Outcome::Allowed, i, "C:\\a.exe"), false),
            Disposition::Folded
        );
    }
    let out = agg.flush_all();
    assert_eq!(out[0].aggregate.as_ref().unwrap().count.get(), 3);

    // Off: counted, not reported, even when throttling.
    let mut agg = Aggregator::new(AggregateSettings {
        allowed: AllowedMode::Off,
        ..AggregateSettings::default()
    });
    assert_eq!(
        agg.offer(exec(Outcome::Allowed, 0, "C:\\a.exe"), true),
        Disposition::Suppressed
    );
    assert_eq!(agg.stats().suppressed, 1);
    // Off never hides a block.
    forwarded(agg.offer(exec(Outcome::Blocked, 0, "C:\\a.exe"), false));
}

#[test]
fn blocked_events_are_deduplicated_with_exact_repeat_counts() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    let first = forwarded(agg.offer(exec(Outcome::Blocked, 0, "C:\\x.exe"), false));
    assert_eq!(first.outcome, Outcome::Blocked);
    for i in 1..=4 {
        assert_eq!(
            agg.offer(exec(Outcome::Blocked, i, "C:\\x.exe"), false),
            Disposition::Folded
        );
    }
    // Another file is a new tuple.
    forwarded(agg.offer(exec(Outcome::Blocked, 5, "C:\\y.exe"), false));
    // No partials for repeat counts.
    assert!(agg.tick(at(5 * MIN).unix_micros()).is_empty());
    let out = agg.tick(at(10 * MIN).unix_micros());
    assert_eq!(out.len(), 1);
    let repeat = out[0].aggregate.as_ref().unwrap();
    assert_eq!(repeat.kind, AggregateKind::Repeat);
    assert_eq!(repeat.count.get(), 4);
    assert_eq!(repeat.window_secs, None);
    assert_eq!(out[0].outcome, Outcome::Blocked);
    assert_eq!(out[0].validate(), Ok(()));
    // After the window, the next one is sent in full again.
    forwarded(agg.offer(exec(Outcome::Blocked, 11 * MIN, "C:\\x.exe"), false));
}

#[test]
fn a_late_occurrence_closes_the_old_window_first() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    forwarded(agg.offer(exec(Outcome::Blocked, 0, "C:\\x.exe"), false));
    agg.offer(exec(Outcome::Blocked, 1, "C:\\x.exe"), false);
    // No tick in between: the next occurrence is past the window.
    forwarded(agg.offer(exec(Outcome::Blocked, 20 * MIN, "C:\\x.exe"), false));
    let out = agg.tick(at(20 * MIN).unix_micros());
    assert_eq!(count(&out), 1);
    assert_eq!(out[0].aggregate.as_ref().unwrap().last_seen, at(1));
}

#[test]
fn security_and_information_events_are_never_folded() {
    let mut agg = Aggregator::new(AggregateSettings::default());
    for i in 0..3 {
        forwarded(agg.offer(event(EventType::AgentTamper, Outcome::Info, i), false));
        forwarded(agg.offer(event(EventType::ProcessCreated, Outcome::Info, i), false));
    }
    // An event that already carries an aggregate passes through.
    let mut pre = exec(Outcome::Blocked, 0, "C:\\x.exe");
    pre.aggregate = Some(Aggregate {
        kind: AggregateKind::Repeat,
        count: NonZeroU64::new(9).unwrap(),
        first_seen: at(0),
        last_seen: at(0),
        window_secs: None,
        partial: false,
        cmdline_samples: BoundedVec::default(),
    });
    forwarded(agg.offer(pre, false));
    // A zero window turns de-duplication off.
    let mut agg = Aggregator::new(AggregateSettings {
        dedup_window: Duration::ZERO,
        ..AggregateSettings::default()
    });
    for i in 0..2 {
        forwarded(agg.offer(exec(Outcome::Blocked, i, "C:\\x.exe"), false));
    }
}

#[test]
fn a_full_table_sends_new_tuples_in_full() {
    let mut agg = Aggregator::new(AggregateSettings {
        max_keys: 1,
        ..AggregateSettings::default()
    });
    assert_eq!(
        agg.offer(exec(Outcome::Allowed, 0, "C:\\a.exe"), false),
        Disposition::Folded
    );
    forwarded(agg.offer(exec(Outcome::Allowed, 0, "C:\\b.exe"), false));
    assert_eq!(agg.stats().table_full, 1);
}

#[test]
fn the_window_is_clamped_and_reconfiguring_flushes() {
    let s = AggregateSettings {
        summary_window: Duration::from_secs(1),
        ..AggregateSettings::default()
    };
    assert_eq!(s.window(), AggregateSettings::MIN_WINDOW);
    let s = AggregateSettings {
        summary_window: Duration::from_secs(7 * 86_400),
        ..AggregateSettings::default()
    };
    assert_eq!(s.window(), AggregateSettings::MAX_WINDOW);
    let mut agg = Aggregator::new(AggregateSettings::default());
    agg.offer(exec(Outcome::Allowed, 0, "C:\\a.exe"), false);
    let out = agg.reconfigure(AggregateSettings {
        allowed: AllowedMode::Complete,
        ..AggregateSettings::default()
    });
    assert_eq!(count(&out), 1);
    forwarded(agg.offer(exec(Outcome::Allowed, 1, "C:\\a.exe"), false));
}

#[test]
fn unrelated_agent_events_are_not_merged() {
    let mut a = exec(Outcome::Blocked, 0, "C:\\a.exe");
    a.file = None;
    a.event_type = EventType::NetworkHostDecision;
    a.category = a.event_type.category();
    let mut b = a.clone();
    b.description = palisade_proto::events::Description::new("Another.").unwrap();
    assert_ne!(key_of(&a, false), key_of(&b, false));
    // The per-occurrence fields do not matter.
    let mut c = a.clone();
    c.ts = at(99);
    c.seq = 4;
    c.event_id = crate::pipeline::testing::uuid(9);
    assert_eq!(key_of(&a, false), key_of(&c, false));
}

proptest! {
    /// Every occurrence is in exactly one full event or one aggregate,
    /// whatever the mix, order and timing (#63's count conservation).
    #[test]
    fn counts_are_conserved(
        ops in proptest::collection::vec((0u8..6, 0u8..3, 0i64..7200, any::<bool>()), 1..200),
        mode in 0u8..4,
    ) {
        let mut agg = Aggregator::new(AggregateSettings {
            allowed: [AllowedMode::Complete, AllowedMode::FirstSeen, AllowedMode::Summary, AllowedMode::Off][usize::from(mode)],
            max_keys: 4,
            ..AggregateSettings::default()
        });
        let mut out = Vec::new();
        let mut suppressed = 0u64;
        let mut ops = ops;
        ops.sort_by_key(|o| o.2);
        for (kind, file, secs, tick) in ops {
            let outcome = [Outcome::Allowed, Outcome::Blocked, Outcome::Audited][usize::from(kind % 3)];
            let e = if kind >= 3 {
                event(EventType::AgentTamper, Outcome::Info, secs)
            } else {
                exec(outcome, secs, &format!("C:\\{file}.exe"))
            };
            match agg.offer(e, false) {
                Disposition::Forward(e) => out.push(*e),
                Disposition::Folded => {}
                Disposition::Suppressed => suppressed += 1,
            }
            if tick {
                out.extend(agg.tick(at(secs).unix_micros()));
            }
        }
        out.extend(agg.flush_all());
        let stats = agg.stats();
        prop_assert_eq!(count(&out) + suppressed, stats.seen);
        for e in &out {
            prop_assert_eq!(e.validate(), Ok(()));
        }
    }
}
