use super::*;
use crate::pipeline::spool::{SegmentSpool, SpoolLimits};
use crate::pipeline::storage::MemoryStorage;

const SEC: u64 = 1_000_000;

fn spool_with(classes: &[(Class, u64)]) -> SegmentSpool<MemoryStorage> {
    let (mut spool, _) =
        SegmentSpool::open(MemoryStorage::default(), SpoolLimits::default()).unwrap();
    let mut seq = 0;
    for &(class, n) in classes {
        for _ in 0..n {
            spool
                .append(StoredRecord {
                    seq,
                    class,
                    time: 0,
                    chain: [0; 32],
                    payload: format!("{{\"seq\":{seq}}}").into_bytes(),
                })
                .unwrap();
            seq += 1;
        }
    }
    spool
}

fn pending(spool: &mut dyn Spool) -> u64 {
    spool.stats().total_pending()
}

#[test]
fn priority_classes_go_first_in_batches_and_are_acknowledged() {
    // A backlog of allowed events, then one block.
    let mut spool = spool_with(&[(Class::Allowed, 25), (Class::Blocked, 1), (Class::Info, 3)]);
    let uploader = RecordingUploader::default();
    let mut d = Delivery::new(DeliverySettings {
        batch_events: 10,
        ..DeliverySettings::default()
    });
    let out = d.pump(&mut spool, &uploader, 0);
    assert!(!out.offline);
    let batches = uploader.batches();
    assert_eq!(batches[0].class, Class::Blocked, "the block goes first");
    assert_eq!(batches[1].class, Class::Info);
    assert_eq!(
        batches[2..]
            .iter()
            .map(|b| b.events.len())
            .collect::<Vec<_>>(),
        [10, 10, 5]
    );
    assert!(
        batches
            .iter()
            .all(|b| b.events.windows(2).all(|w| w[0].seq < w[1].seq))
    );
    assert_eq!(out.acked.get(&Class::Allowed), Some(&25));
    assert_eq!(out.batches, 5);
    assert_eq!(pending(&mut spool), 0);
    assert!(batches[0].bytes() > 0);
}

#[test]
fn a_partial_acknowledgement_resends_the_rest() {
    let mut spool = spool_with(&[(Class::Blocked, 5)]);
    let uploader = RecordingUploader::default();
    uploader.script([Scripted::First(2), Scripted::First(0)]);
    let mut d = Delivery::new(DeliverySettings::default());
    let out = d.pump(&mut spool, &uploader, 0);
    // 2 acknowledged, then a batch of the other 3 with nothing stored.
    assert_eq!(out.acked.get(&Class::Blocked), Some(&2));
    assert!(out.offline);
    assert_eq!(pending(&mut spool), 3);
    let out = d.pump(&mut spool, &uploader, SEC);
    assert_eq!(out.acked.get(&Class::Blocked), Some(&3));
    let batches = uploader.batches();
    assert_eq!(batches.len(), 3);
    assert_eq!(batches[1].events[0].seq, 2);
    assert_eq!(batches[2].events[0].seq, 2, "sent again");
}

#[test]
fn offline_and_failures_keep_everything() {
    let mut spool = spool_with(&[(Class::Security, 2)]);
    let uploader = RecordingUploader::default();
    uploader.set_offline(true);
    let mut d = Delivery::new(DeliverySettings::default());
    assert!(d.pump(&mut spool, &uploader, 0).offline);
    assert_eq!(pending(&mut spool), 2);
    uploader.set_offline(false);
    uploader.script([Scripted::Fail]);
    assert!(d.pump(&mut spool, &uploader, 0).offline);
    assert_eq!(pending(&mut spool), 2);
    assert!(!d.pump(&mut spool, &uploader, 0).offline);
    assert_eq!(pending(&mut spool), 0);
    // The placeholder uploader is always offline.
    let mut spool = spool_with(&[(Class::Info, 1)]);
    assert!(d.pump(&mut spool, &OfflineUploader, 0).offline);
    assert!(UploadError::Offline.to_string().contains("no connection"));
    assert!(
        UploadError::Transport("x".into())
            .to_string()
            .contains("failed")
    );
}

#[test]
fn a_server_throttle_holds_delivery() {
    let mut spool = spool_with(&[(Class::Info, 2)]);
    let uploader = RecordingUploader::default();
    uploader.script([Scripted::Throttle(Duration::from_secs(30))]);
    let mut d = Delivery::new(DeliverySettings::default());
    let out = d.pump(&mut spool, &uploader, 0);
    assert_eq!(out.throttled, Some(Duration::from_secs(30)));
    // Held: nothing is sent.
    let out = d.pump(&mut spool, &uploader, 10 * SEC);
    assert_eq!(out.throttled, Some(Duration::from_secs(20)));
    assert_eq!(uploader.batches().len(), 1);
    let out = d.pump(&mut spool, &uploader, 30 * SEC);
    assert_eq!(out.acked.get(&Class::Info), Some(&2));
}

#[test]
fn replay_is_rate_limited_but_priority_events_are_not() {
    let mut spool = spool_with(&[(Class::Allowed, 30), (Class::Blocked, 30)]);
    let uploader = RecordingUploader::default();
    let mut d = Delivery::new(DeliverySettings {
        replay_per_sec: 10,
        ..DeliverySettings::default()
    });
    let out = d.pump(&mut spool, &uploader, 0);
    assert_eq!(out.acked.get(&Class::Blocked), Some(&30));
    assert_eq!(out.acked.get(&Class::Allowed), Some(&10));
    // Half a second later: 5 more.
    let out = d.pump(&mut spool, &uploader, SEC / 2);
    assert_eq!(out.acked.get(&Class::Allowed), Some(&5));
    // The bucket holds at most one second's worth.
    let out = d.pump(&mut spool, &uploader, 100 * SEC);
    assert_eq!(out.acked.get(&Class::Allowed), Some(&10));
    // 0 removes the limit.
    let mut d = Delivery::new(DeliverySettings {
        replay_per_sec: 0,
        ..DeliverySettings::default()
    });
    let out = d.pump(&mut spool, &uploader, 0);
    assert_eq!(out.acked.get(&Class::Allowed), Some(&5));
}

#[test]
fn a_large_backlog_never_delays_a_new_block() {
    // #63: a block is delivered while a large allowed backlog replays.
    let mut spool = spool_with(&[(Class::Allowed, 5000)]);
    let uploader = RecordingUploader::default();
    let mut d = Delivery::new(DeliverySettings::default());
    d.pump(&mut spool, &uploader, 0);
    assert!(
        pending(&mut spool) > 0,
        "the replay limit holds the backlog"
    );
    spool
        .append(StoredRecord {
            seq: 5000,
            class: Class::Blocked,
            time: 0,
            chain: [0; 32],
            payload: b"{}".to_vec(),
        })
        .unwrap();
    let before = uploader.batches().len();
    let out = d.pump(&mut spool, &uploader, SEC / 1000);
    assert_eq!(out.acked.get(&Class::Blocked), Some(&1));
    assert_eq!(uploader.batches()[before].class, Class::Blocked);
}

#[test]
fn defaults_match_the_issue() {
    let d = DeliverySettings::default();
    assert_eq!(
        (d.batch_events, d.batch_bytes, d.replay_per_sec),
        (1000, 1 << 20, 2000)
    );
    let b = Batch {
        class: Class::Info,
        events: Vec::new(),
    };
    assert_eq!(b.last_seq(), None);
}
