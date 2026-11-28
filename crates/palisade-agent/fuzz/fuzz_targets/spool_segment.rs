//! Fuzzes the event spool's segment reader and recovery (#63, #197). The
//! input is the bytes of one segment file, as a crash or an attacker with
//! write access to the spool directory could leave it. No input may panic;
//! the reader must return only records that pass every check, and recovery
//! must cut the file to the valid prefix it reports.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_agent::pipeline::segment::{Class, Tail, decode};
use palisade_agent::pipeline::spool::{SegmentSpool, Spool, SpoolLimits};
use palisade_agent::pipeline::storage::{MemoryStorage, SegmentId, Storage};

fuzz_target!(|data: &[u8]| {
    // The first byte picks the class the file claims to hold.
    let Some((&pick, bytes)) = data.split_first() else {
        return;
    };
    let class = Class::ALL[usize::from(pick) % Class::ALL.len()];
    let decoded = decode(bytes, class);
    assert!(decoded.valid_len <= bytes.len());
    // A clean segment is valid to its end; anything left over is a torn
    // or damaged tail. (A file cut inside its magic is torn and has no
    // valid prefix at all.)
    if decoded.tail == Tail::Clean {
        assert_eq!(decoded.valid_len, bytes.len());
    } else {
        assert!(decoded.valid_len < bytes.len() || decoded.valid_len == 0);
    }
    let mut last = None;
    for record in &decoded.records {
        assert_eq!(record.class, class);
        assert!(last.is_none_or(|l| record.seq > l));
        last = Some(record.seq);
    }

    // Recovery over the same file keeps exactly those records.
    let mut storage = MemoryStorage::default();
    let id = SegmentId {
        class,
        first_seq: decoded.records.first().map_or(0, |r| r.seq),
    };
    if storage.create(id, bytes).is_err() {
        return;
    }
    let Ok((mut spool, recovery)) = SegmentSpool::open(storage.clone(), SpoolLimits::default())
    else {
        return;
    };
    let kept = spool
        .pending(class, None, usize::MAX, usize::MAX)
        .unwrap_or_default();
    assert_eq!(kept, decoded.records);
    assert_eq!(recovery.head.map(|h| h.0), last);
});
