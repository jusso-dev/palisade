use super::*;
use crate::pipeline::storage::MemoryStorage;

const T0: i64 = 1_700_000_000_000_000;
const DAY: i64 = 86_400_000_000;

fn rec(seq: u64, class: Class, size: usize) -> StoredRecord {
    StoredRecord {
        seq,
        class,
        time: T0 + i64::try_from(seq).unwrap(),
        chain: [u8::try_from(seq % 251).unwrap(); 32],
        payload: vec![b'x'; size],
    }
}

/// The encoded size of a record with a `size`-byte payload.
fn len(size: usize) -> u64 {
    u64::try_from(rec(0, Class::Info, size).encoded_len()).unwrap()
}

fn open(storage: &MemoryStorage, limits: SpoolLimits) -> (SegmentSpool<MemoryStorage>, Recovery) {
    SegmentSpool::open(storage.clone(), limits).unwrap()
}

fn seqs(records: &[StoredRecord]) -> Vec<u64> {
    records.iter().map(|r| r.seq).collect()
}

fn all(spool: &mut SegmentSpool<MemoryStorage>, class: Class) -> Vec<u64> {
    seqs(&spool.pending(class, None, usize::MAX, usize::MAX).unwrap())
}

#[test]
fn appends_are_read_back_per_class_in_order_and_survive_a_restart() {
    let storage = MemoryStorage::default();
    let limits = SpoolLimits {
        segment_bytes: MAGIC_LEN + 2 * len(10),
        ..SpoolLimits::default()
    };
    let (mut spool, recovery) = open(&storage, limits);
    assert_eq!(recovery.state, StateStatus::Absent);
    assert_eq!((recovery.head, recovery.pending), (None, 0));
    for seq in 0..7 {
        let class = if seq % 3 == 0 {
            Class::Blocked
        } else {
            Class::Allowed
        };
        let a = spool.append(rec(seq, class, 10)).unwrap();
        assert!(a.stored && a.dropped.is_empty());
    }
    assert_eq!(spool.stats().unsynced, 7);
    spool.sync().unwrap();
    assert_eq!(spool.stats().unsynced, 0);
    assert_eq!(all(&mut spool, Class::Blocked), [0, 3, 6]);
    assert_eq!(all(&mut spool, Class::Allowed), [1, 2, 4, 5]);
    // Two records per segment: allowed has two segments.
    assert_eq!(storage.list_ids().len(), 4);
    // Paging: after a sequence number, by count and by size.
    let page = spool
        .pending(Class::Allowed, Some(2), 1, usize::MAX)
        .unwrap();
    assert_eq!(seqs(&page), [4]);
    let page = spool.pending(Class::Allowed, None, 10, 15).unwrap();
    assert_eq!(seqs(&page), [1]);
    let page = spool.pending(Class::Allowed, None, 10, 5).unwrap();
    assert_eq!(seqs(&page), [1], "at least one record");
    assert_eq!(spool.head().map(|h| h.0), Some(6));
    let stats = spool.stats();
    assert_eq!(stats.total_pending(), 7);
    assert_eq!(stats.oldest_pending, Some(T0));
    assert_eq!(stats.bytes, u64::try_from(storage.stored_bytes()).unwrap());

    drop(spool);
    let (mut spool, recovery) = open(&storage, limits);
    assert!(recovery.damaged.is_empty());
    assert_eq!(recovery.head, Some((6, [6; 32])));
    assert_eq!(recovery.pending, 7);
    assert_eq!(all(&mut spool, Class::Blocked), [0, 3, 6]);
    // Numbers keep increasing after a restart.
    assert!(matches!(
        spool.append(rec(6, Class::Info, 1)),
        Err(SpoolError::OutOfOrder { seq: 6, head: 6 })
    ));
    assert!(spool.append(rec(7, Class::Info, 1)).unwrap().stored);
}

#[test]
fn acknowledged_segments_are_deleted_and_stay_acknowledged() {
    let storage = MemoryStorage::default();
    let limits = SpoolLimits {
        segment_bytes: MAGIC_LEN + 2 * len(1),
        ..SpoolLimits::default()
    };
    let (mut spool, _) = open(&storage, limits);
    for seq in 0..5 {
        spool.append(rec(seq, Class::Info, 1)).unwrap();
    }
    spool.ack(Class::Info, 2).unwrap();
    assert_eq!(all(&mut spool, Class::Info), [3, 4]);
    // The first segment (0, 1) is gone; the second (2, 3) stays for 3.
    assert_eq!(storage.list_ids().len(), 2);
    // An older acknowledgement changes nothing.
    spool.ack(Class::Info, 1).unwrap();
    assert_eq!(spool.stats().total_pending(), 2);
    drop(spool);
    let (mut spool, recovery) = open(&storage, limits);
    assert_eq!(recovery.state, StateStatus::Intact);
    assert_eq!(recovery.pending, 2);
    assert_eq!(all(&mut spool, Class::Info), [3, 4]);
    spool.ack(Class::Info, 4).unwrap();
    assert!(storage.list_ids().is_empty());
    assert_eq!(spool.stats(), SpoolStats::default());
    // The head survives with every segment gone.
    drop(spool);
    let (spool, recovery) = open(&storage, limits);
    assert_eq!(recovery.head, Some((4, [4; 32])));
    assert_eq!(spool.head(), recovery.head);
}

#[test]
fn a_crash_loses_at_most_the_unsynced_tail() {
    // Every possible cut of the unsynced bytes.
    let size = len(5);
    for cut in 0..=3 * usize::try_from(size).unwrap() {
        let storage = MemoryStorage::default();
        let (mut spool, _) = open(&storage, SpoolLimits::default());
        spool.append(rec(0, Class::Blocked, 5)).unwrap();
        spool.append(rec(1, Class::Blocked, 5)).unwrap();
        spool.sync().unwrap();
        for seq in 2..5 {
            spool.append(rec(seq, Class::Blocked, 5)).unwrap();
        }
        drop(spool);
        storage.crash(|_| cut);
        let (mut spool, recovery) = open(&storage, SpoolLimits::default());
        let whole = cut / usize::try_from(size).unwrap();
        let kept = all(&mut spool, Class::Blocked);
        assert_eq!(kept.len(), 2 + whole, "cut {cut}");
        assert_eq!(recovery.head.map(|h| h.0), kept.last().copied());
        let torn = cut % usize::try_from(size).unwrap() != 0;
        assert_eq!(recovery.damaged.len(), usize::from(torn), "cut {cut}");
        if let Some(d) = recovery.damaged.first() {
            assert_eq!(d.tail, Tail::Torn);
            assert_eq!(d.last_kept, kept.last().copied());
        }
        // The tail was cut, so new records follow the valid ones.
        let next = kept.last().unwrap() + 1;
        spool.append(rec(next, Class::Blocked, 5)).unwrap();
        spool.sync().unwrap();
        drop(spool);
        let (mut spool, recovery) = open(&storage, SpoolLimits::default());
        assert!(recovery.damaged.is_empty(), "cut {cut}");
        assert_eq!(all(&mut spool, Class::Blocked).last(), Some(&next));
    }
}

#[test]
fn damaged_and_misplaced_segments_are_reported_and_cut() {
    let storage = MemoryStorage::default();
    let (mut spool, _) = open(&storage, SpoolLimits::default());
    for seq in 0..3 {
        spool.append(rec(seq, Class::Audit, 4)).unwrap();
    }
    spool.append(rec(3, Class::Info, 4)).unwrap();
    spool.sync().unwrap();
    drop(spool);
    let audit = SegmentId {
        class: Class::Audit,
        first_seq: 0,
    };
    // A flipped byte in the second record.
    let at = MAGIC.len() + usize::try_from(len(4)).unwrap() + 12;
    storage.corrupt(audit, |b| b[at] ^= 1);
    // A segment whose name does not match its first record.
    let info = SegmentId {
        class: Class::Info,
        first_seq: 3,
    };
    let bytes = storage.clone().read(info).unwrap();
    storage.clone().remove(info).unwrap();
    let renamed = SegmentId {
        class: Class::Info,
        first_seq: 9,
    };
    storage.clone().create(renamed, &bytes).unwrap();
    // An empty segment left by a crash just after it was created.
    let empty = SegmentId {
        class: Class::Summary,
        first_seq: 1,
    };
    storage.clone().create(empty, &MAGIC).unwrap();
    // A segment with a wrong magic.
    let junk = SegmentId {
        class: Class::Diagnostic,
        first_seq: 1,
    };
    storage.clone().create(junk, b"junk").unwrap();

    let (mut spool, recovery) = open(&storage, SpoolLimits::default());
    let mut damaged = recovery.damaged.clone();
    damaged.sort_by_key(|d| d.segment);
    assert_eq!(damaged.len(), 3, "{damaged:?}");
    assert_eq!(damaged[0].segment, junk);
    assert_eq!(damaged[0].tail, Tail::BadMagic);
    assert_eq!(damaged[1].segment, renamed);
    assert_eq!(damaged[1].tail, Tail::Corrupt);
    assert_eq!(damaged[2].segment, audit);
    assert_eq!(damaged[2].tail, Tail::Corrupt);
    assert_eq!(damaged[2].last_kept, Some(0));
    assert_eq!(all(&mut spool, Class::Audit), [0]);
    assert!(all(&mut spool, Class::Info).is_empty());
    // The empty segment was removed quietly.
    assert!(!storage.list_ids().contains(&empty));
    // The state file still names the real head.
    assert_eq!(recovery.head.map(|h| h.0), Some(3));
}

#[test]
fn a_damaged_state_is_reported_and_everything_is_sent_again() {
    let storage = MemoryStorage::default();
    let (mut spool, _) = open(&storage, SpoolLimits::default());
    for seq in 0..3 {
        spool.append(rec(seq, Class::Info, 1)).unwrap();
    }
    spool.ack(Class::Info, 1).unwrap();
    drop(spool);
    let mut bytes = storage.clone().read_state().unwrap().unwrap();
    bytes[20] ^= 1;
    storage.set_state(Some(bytes));
    let (mut spool, recovery) = open(&storage, SpoolLimits::default());
    assert_eq!(recovery.state, StateStatus::Damaged);
    assert_eq!(all(&mut spool, Class::Info), [0, 1, 2]);
    assert_eq!(recovery.head.map(|h| h.0), Some(2));
    // Wrong lengths, magic and flags are damage too.
    let good = State {
        head: Some((5, [1; 32])),
        acks: [Some(1), None, None, None, None, None, Some(9)],
    };
    assert_eq!(State::decode(&good.encode()), Some(good));
    assert_eq!(
        State::decode(&State::default().encode()),
        Some(State::default())
    );
    let mut short = good.encode();
    short.pop();
    assert_eq!(State::decode(&short), None);
    let mut magic = good.encode();
    magic[0] = b'X';
    assert_eq!(State::decode(&magic), None);
    // A flag byte of 2, with the CRC fixed up.
    let mut flag = good.encode();
    flag[STATE_MAGIC.len()] = 2;
    let body = flag.len() - 4;
    let crc = crc32c(&flag[..body]).to_le_bytes();
    flag[body..].copy_from_slice(&crc);
    assert_eq!(State::decode(&flag), None);
}

#[test]
fn caps_give_up_the_lowest_class_first_and_report_it() {
    let storage = MemoryStorage::default();
    // Room for 10 records in all, 8 of them unprotected; one record per
    // segment.
    let per = MAGIC_LEN + len(10);
    let limits = SpoolLimits {
        segment_bytes: per,
        max_bytes: 10 * per,
        soft_percent: 80,
        ..SpoolLimits::default()
    };
    let (mut spool, _) = open(&storage, limits);
    let classes = [
        Class::Allowed,
        Class::Diagnostic,
        Class::Summary,
        Class::Allowed,
        Class::Info,
        Class::Audit,
        Class::Allowed,
        Class::Diagnostic,
    ];
    for (seq, class) in (0u64..).zip(classes) {
        assert!(spool.append(rec(seq, class, 10)).unwrap().stored);
    }
    // Full for unprotected classes: an allowed event displaces the oldest
    // diagnostic.
    let a = spool.append(rec(8, Class::Allowed, 10)).unwrap();
    assert!(a.stored);
    assert_eq!(
        a.dropped,
        [Dropped {
            class: Class::Diagnostic,
            reason: DropReason::SpoolFull,
            count: 1,
            from_seq: 1,
            to_seq: 1
        }]
    );
    // A diagnostic can displace only diagnostics.
    let a = spool.append(rec(9, Class::Diagnostic, 10)).unwrap();
    assert!(a.stored);
    assert_eq!(a.dropped[0].from_seq, 7);
    let a = spool.append(rec(10, Class::Diagnostic, 10)).unwrap();
    assert_eq!(a.dropped[0].from_seq, 9);
    // A summary displaces the newest diagnostic, then may not displace
    // anything above it.
    let a = spool.append(rec(11, Class::Summary, 10)).unwrap();
    assert!(a.stored);
    assert_eq!(a.dropped[0].class, Class::Diagnostic);
    let a = spool.append(rec(12, Class::Diagnostic, 10)).unwrap();
    assert!(!a.stored, "nothing lower to give up");
    assert_eq!(
        a.dropped,
        [Dropped {
            class: Class::Diagnostic,
            reason: DropReason::SpoolFull,
            count: 1,
            from_seq: 12,
            to_seq: 12
        }]
    );
    // A refused record's number is still issued.
    assert_eq!(spool.head().map(|h| h.0), Some(12));
    // Blocked events go above the soft cap without giving anything up.
    for seq in 13..15 {
        let a = spool.append(rec(seq, Class::Blocked, 10)).unwrap();
        assert!(a.stored && a.dropped.is_empty(), "{seq}");
    }
    // Physically full: a blocked event gives up the lowest classes first:
    // summaries (2, 11), then allowed (0, 3, 6, 8), info, audit.
    let mut lost = Vec::new();
    for seq in 15..25 {
        let a = spool.append(rec(seq, Class::Security, 10)).unwrap();
        assert!(a.stored, "{seq}");
        lost.extend(a.dropped.iter().map(|d| (d.class, d.from_seq)));
    }
    assert_eq!(
        lost,
        [
            (Class::Summary, 2),
            (Class::Summary, 11),
            (Class::Allowed, 0),
            (Class::Allowed, 3),
            (Class::Allowed, 6),
            (Class::Allowed, 8),
            (Class::Info, 4),
            (Class::Audit, 5),
            (Class::Blocked, 13),
            (Class::Blocked, 14),
        ]
    );
    assert!(spool.stats().bytes <= limits.max_bytes);
    // A record larger than the whole spool is refused, and reported.
    let a = spool.append(rec(25, Class::Security, 1000)).unwrap();
    assert!(!a.stored);
    assert_eq!(a.dropped.len(), 1);
}

#[test]
fn acknowledged_records_in_an_evicted_segment_are_not_reported_lost() {
    let storage = MemoryStorage::default();
    let per = MAGIC_LEN + 3 * len(1);
    let limits = SpoolLimits {
        segment_bytes: per,
        max_bytes: 2 * per,
        soft_percent: 100,
        ..SpoolLimits::default()
    };
    let (mut spool, _) = open(&storage, limits);
    for seq in 0..3 {
        spool.append(rec(seq, Class::Allowed, 1)).unwrap();
    }
    spool.ack(Class::Allowed, 0).unwrap();
    for seq in 3..6 {
        spool.append(rec(seq, Class::Allowed, 1)).unwrap();
    }
    let a = spool.append(rec(6, Class::Allowed, 1)).unwrap();
    assert!(a.stored);
    assert_eq!(
        a.dropped,
        [Dropped {
            class: Class::Allowed,
            reason: DropReason::SpoolFull,
            count: 2,
            from_seq: 1,
            to_seq: 2
        }]
    );
    // A wholly acknowledged segment is not a loss at all.
    spool.ack(Class::Allowed, 5).unwrap();
    assert_eq!(all(&mut spool, Class::Allowed), [6]);
}

#[test]
fn old_unprotected_events_expire_and_protected_ones_do_not() {
    let storage = MemoryStorage::default();
    let limits = SpoolLimits {
        segment_bytes: MAGIC_LEN + len(1),
        max_age: Duration::from_secs(86_400),
        ..SpoolLimits::default()
    };
    let (mut spool, _) = open(&storage, limits);
    spool.append(rec(0, Class::Allowed, 1)).unwrap();
    spool.append(rec(1, Class::Blocked, 1)).unwrap();
    let mut late = rec(2, Class::Allowed, 1);
    late.time = T0 + 2 * DAY;
    spool.append(late).unwrap();
    assert!(spool.expire(T0 + DAY).unwrap().is_empty());
    let dropped = spool.expire(T0 + DAY + 10).unwrap();
    assert_eq!(
        dropped,
        [Dropped {
            class: Class::Allowed,
            reason: DropReason::Expired,
            count: 1,
            from_seq: 0,
            to_seq: 0
        }]
    );
    assert_eq!(all(&mut spool, Class::Blocked), [1]);
    assert_eq!(all(&mut spool, Class::Allowed), [2]);
    assert!(spool.expire(T0 + 100 * DAY).unwrap().len() == 1);
    assert_eq!(all(&mut spool, Class::Blocked), [1]);
}

#[test]
fn a_failed_write_is_an_error_and_the_next_record_starts_a_new_segment() {
    let storage = MemoryStorage::default();
    let (mut spool, _) = open(&storage, SpoolLimits::default());
    spool.append(rec(0, Class::Info, 1)).unwrap();
    storage.fail_writes(true);
    let e = spool.append(rec(1, Class::Info, 1)).unwrap_err();
    assert!(matches!(e, SpoolError::Io(_)));
    assert!(e.to_string().contains("spool storage"));
    assert!(std::error::Error::source(&e).is_some());
    assert!(spool.ack(Class::Info, 0).is_err());
    storage.fail_writes(false);
    assert!(spool.append(rec(2, Class::Info, 1)).unwrap().stored);
    assert_eq!(storage.list_ids().len(), 2);
    assert_eq!(all(&mut spool, Class::Info), [0, 2]);
    // Too large for a record at all.
    let huge = rec(3, Class::Info, segment::MAX_PAYLOAD + 1);
    let e = spool.append(huge).unwrap_err();
    assert!(matches!(e, SpoolError::TooLarge));
    assert!(e.to_string().contains("too large"));
    assert!(std::error::Error::source(&e).is_none());
    let e = SpoolError::OutOfOrder { seq: 1, head: 2 };
    assert!(e.to_string().contains("not above"));
    assert!(format!("{spool:?}").contains("SegmentSpool"));
}

#[test]
fn limits_have_the_documented_defaults() {
    let limits = SpoolLimits::default();
    assert_eq!(limits.segment_bytes, 4 << 20);
    assert_eq!(limits.max_bytes, 512 << 20);
    assert_eq!(limits.soft_bytes(), (512 << 20) * 95 / 100);
    let all_of_it = SpoolLimits {
        max_bytes: u64::MAX,
        soft_percent: 200,
        ..limits
    };
    assert_eq!(all_of_it.soft_bytes(), u64::MAX);
    assert_eq!(limits.max_age, Duration::from_secs(30 * 86_400));
}
