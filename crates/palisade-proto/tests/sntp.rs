//! Seeds for the `sntp_reply` fuzz target, and a check of the public API
//! from outside the crate.

#![allow(clippy::unwrap_used, missing_docs)]

use std::path::Path;

use palisade_proto::sntp::{self, NtpTimestamp, PACKET_LEN, Reply};

/// 2026-11-24T00:00:00Z, in microseconds since 1970.
const NOW: i64 = 1_795_478_400_000_000;

/// A fuzz input: the request's transmit timestamp, then a reply.
fn seed(sent: NtpTimestamp, first: u8, stratum: u8, rx: i64, tx: i64) -> Vec<u8> {
    let mut reply = [0u8; PACKET_LEN];
    reply[0] = first;
    reply[1] = stratum;
    reply[24..32].copy_from_slice(&sent.0.to_be_bytes());
    reply[32..40].copy_from_slice(&NtpTimestamp::from_unix_micros(rx).0.to_be_bytes());
    reply[40..48].copy_from_slice(&NtpTimestamp::from_unix_micros(tx).0.to_be_bytes());
    [sent.0.to_be_bytes().as_slice(), &reply].concat()
}

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let sent = NtpTimestamp::from_unix_micros(NOW);
    vec![
        (
            "valid-v4",
            seed(sent, (4 << 3) | 4, 2, NOW + 1_000, NOW + 2_000),
        ),
        ("valid-v3", seed(sent, (3 << 3) | 4, 1, NOW, NOW)),
        ("kiss", seed(sent, (4 << 3) | 4, 0, NOW, NOW)),
        (
            "unsynchronised",
            seed(sent, (3 << 6) | (4 << 3) | 4, 2, NOW, NOW),
        ),
        ("client-mode", seed(sent, (4 << 3) | 3, 2, NOW, NOW)),
        (
            "backwards",
            seed(sent, (4 << 3) | 4, 2, NOW, NOW - 1_000_000),
        ),
        (
            "era-wrap",
            seed(
                NtpTimestamp::from_unix_micros(2_085_978_496_000_000),
                (4 << 3) | 4,
                2,
                2_085_978_495_999_000,
                2_085_978_496_001_000,
            ),
        ),
    ]
}

#[test]
fn seeds_parse_as_documented() {
    let results: Vec<bool> = seeds()
        .iter()
        .map(|(_, input)| {
            let (sent, packet) = input.split_at(8);
            let sent = NtpTimestamp(u64::from_be_bytes(sent.try_into().unwrap()));
            Reply::parse(packet, sent).is_ok()
        })
        .collect();
    assert_eq!(results, [true, true, false, false, false, false, true]);
    let request = sntp::request(NtpTimestamp::from_unix_micros(NOW));
    assert_eq!(request.len(), PACKET_LEN);
    assert_eq!(sntp::PORT, 123);
}

/// Writes the seeds for `sntp_reply`:
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/sntp_reply" \
///     cargo test -p palisade-proto --test sntp -- --ignored write_sntp_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_sntp_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for (name, bytes) in seeds() {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    }
}
