//! The event pipeline's spool (#63, #197), through its public interface.

use std::path::Path;

use palisade_agent::pipeline::segment::{Class, MAGIC, StoredRecord, encode};
use palisade_agent::pipeline::spool::{SegmentSpool, Spool, SpoolLimits};
use palisade_agent::pipeline::storage::FileStorage;

fn rec(seq: u64, class: Class, payload: &[u8]) -> StoredRecord {
    StoredRecord {
        seq,
        class,
        time: 1_700_000_000_000_000,
        chain: [7; 32],
        payload: payload.to_vec(),
    }
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "palisade-agent-pipeline-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_file_spool_survives_a_restart_and_a_torn_tail() {
    let dir = TempDir::new("restart");
    let limits = SpoolLimits::default();
    let (mut spool, _) = SegmentSpool::open(FileStorage::open(&dir.0).unwrap(), limits).unwrap();
    for seq in 0..3 {
        assert!(
            spool
                .append(rec(seq, Class::Blocked, b"event"))
                .unwrap()
                .stored
        );
    }
    spool.sync().unwrap();
    spool.ack(Class::Blocked, 0).unwrap();
    drop(spool);
    // A write cut short by a crash.
    let segment = dir.0.join("blocked-00000000000000000000.seg");
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes.extend_from_slice(&[1, 2, 3]);
    std::fs::write(&segment, &bytes).unwrap();

    let (mut spool, recovery) =
        SegmentSpool::open(FileStorage::open(&dir.0).unwrap(), limits).unwrap();
    assert_eq!(recovery.damaged.len(), 1);
    assert_eq!(recovery.damaged[0].bytes, 3);
    assert_eq!(recovery.head.map(|h| h.0), Some(2));
    let pending = spool.pending(Class::Blocked, None, 10, usize::MAX).unwrap();
    assert_eq!(pending.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(std::fs::read(&segment).unwrap().len(), bytes.len() - 3);
}

/// Seeds for the `spool_segment` fuzz target: a class byte, then a
/// segment file.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR=target/seeds \
///     cargo test -p palisade-agent --test pipeline -- --ignored write_spool_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_spool_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for class in Class::ALL {
        let mut seed = vec![class.code()];
        seed.extend_from_slice(&MAGIC);
        for seq in [3, 4, 9] {
            encode(&rec(seq, class, b"{\"seq\":1}"), &mut seed).unwrap();
        }
        std::fs::write(dir.join(format!("seed-{}", class.as_str())), &seed).unwrap();
        // A torn tail.
        seed.truncate(seed.len() - 5);
        std::fs::write(dir.join(format!("seed-{}-torn", class.as_str())), &seed).unwrap();
    }
    let mut empty = vec![0];
    empty.extend_from_slice(&MAGIC);
    std::fs::write(dir.join("seed-empty"), &empty).unwrap();
}

mod subsystem {
    use std::sync::Arc;
    use std::time::Duration;

    use palisade_agent::pipeline::segment::Class;
    use palisade_agent::pipeline::spool::{SegmentSpool, Spool, SpoolLimits};
    use palisade_agent::pipeline::storage::FileStorage;
    use palisade_agent::pipeline::subsystem::EventPipeline;
    use palisade_agent::pipeline::upload::{RecordingUploader, Uploader};
    use palisade_agent::platform::SystemClock;
    use palisade_agent::policy_cache::{Detail, PolicyEvent, PolicyEventSink, Tamper};
    use palisade_agent::subsystem::{Health, Subsystem};
    use palisade_agent::supervisor::{RestartPolicy, StopOutcome, Supervisor};
    use palisade_proto::events::{Event, EventType};
    use palisade_proto::policy_bundle::select::Load;

    use super::TempDir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn events_flow_from_producers_to_the_spool_and_the_uploader() {
        let dir = TempDir::new("subsystem");
        let uploader = Arc::new(RecordingUploader::default());
        uploader.set_offline(true);
        let pipeline = Arc::new(EventPipeline::new(
            SystemClock,
            Some(dir.0.clone()),
            Arc::clone(&uploader) as Arc<dyn Uploader>,
        ));
        assert_eq!(pipeline.name(), "event-pipeline");
        let sink = pipeline.policy_sink();
        // Offered before the pipeline runs: it waits in the queue.
        assert!(sink.emit(PolicyEvent {
            detail: Detail::Tamper(Tamper::Memory),
            load: Load::Emergency,
        }));
        let subsystems: Vec<Arc<dyn Subsystem>> = vec![
            Arc::new(palisade_agent::host::ConfigSubsystem::new(
                palisade_agent::config::LoadedConfig {
                    config: palisade_agent::config::AgentConfig::default(),
                    source: None,
                },
            )),
            Arc::clone(&pipeline) as Arc<dyn Subsystem>,
        ];
        let handle = Supervisor::new(subsystems, RestartPolicy::default())
            .unwrap()
            .start();
        // Wait for the tamper event to be spooled.
        let mut spooled = false;
        for _ in 0..200 {
            if pipeline.stats().0.spooled >= 1 {
                spooled = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(spooled, "{:?}", pipeline.stats());
        assert_eq!(pipeline.health(), Health::Healthy);
        let report = handle.shutdown(Duration::from_secs(10)).await;
        assert!(
            report
                .outcomes
                .iter()
                .all(|(_, o)| *o == StopOutcome::Clean),
            "{report:?}"
        );
        // The spool on disk holds the event, numbered from 0.
        let (mut spool, recovery) =
            SegmentSpool::open(FileStorage::open(&dir.0).unwrap(), SpoolLimits::default()).unwrap();
        assert!(recovery.damaged.is_empty());
        let records = spool
            .pending(Class::Security, None, 10, usize::MAX)
            .unwrap();
        let event = Event::from_json(std::str::from_utf8(&records[0].payload).unwrap()).unwrap();
        assert_eq!(event.event_type, EventType::AgentTamper);
        assert_eq!((event.seq, event.prev_hash), (0, None));
        assert_eq!(event.validate(), Ok(()));
    }
}
