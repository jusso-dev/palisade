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
