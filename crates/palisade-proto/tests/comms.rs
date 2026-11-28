//! Seed inputs for the `comms_messages` fuzz target
//! (`fuzz/fuzz_targets/comms_messages.rs`). The first byte of each seed
//! picks the parser: 0 proxy reply, 1 enrolment request, 2 check-in,
//! 3 check-in reply, 4 enrolment reply.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::str::FromStr;

use palisade_proto::comms::{
    Base64, CheckIn, CheckInResponse, DeviceFacts, EnrolPayload, EnrolRequest, HealthSummary,
    KeyProtection,
};
use palisade_proto::events::{BoundedVec, Name, Text, Timestamp};
use palisade_proto::pki::leaf_key::LeafKey;

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let (key, _) = LeafKey::generate().unwrap();
    let payload = EnrolPayload {
        code: Text::new("ABCDEFGHJKMN").unwrap(),
        public_key: Base64::new(key.public_key().spki_der().to_vec()).unwrap(),
        key_protection: KeyProtection::Software,
        nonce: Base64::new(vec![1; 32]).unwrap(),
        created_at: Timestamp::from_str("2026-11-29T00:00:00.000000Z").unwrap(),
        facts: DeviceFacts {
            hostname: Text::new("ws-01").unwrap(),
            fqdn: None,
            os: Name::new("Windows 11").unwrap(),
            os_build: None,
            arch: None,
            smbios_uuid: None,
            serial: None,
            macs: BoundedVec::default(),
            domain: None,
            agent_version: Text::new("0.1.0").unwrap(),
        },
    };
    let enrol = serde_json::to_vec(&EnrolRequest::sign(&payload, &key).unwrap()).unwrap();
    let check_in = serde_json::to_vec(&CheckIn {
        agent_version: Text::new("0.1.0").unwrap(),
        os_build: None,
        uptime_s: 1,
        policy_version: Some(1),
        bundle_hash: None,
        trust_version: 1,
        health: HealthSummary::Healthy,
        ips: BoundedVec::default(),
    })
    .unwrap();
    let reply = serde_json::to_vec(&CheckInResponse {
        server_time: Timestamp::from_str("2026-11-29T00:00:00.000000Z").unwrap(),
        policy_version: Some(2),
        bundle_hash: None,
        trust_version: 1,
        next_checkin_s: 60,
    })
    .unwrap();
    let tag = |t: u8, body: &[u8]| {
        let mut v = vec![t];
        v.extend_from_slice(body);
        v
    };
    vec![
        (
            "proxy-ok",
            tag(0, b"HTTP/1.1 200 Connection established\r\nVia: p\r\n\r\n"),
        ),
        (
            "proxy-407",
            tag(0, b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic\r\n\r\n"),
        ),
        ("enrol", tag(1, &enrol)),
        ("checkin", tag(2, &check_in)),
        ("checkin-reply", tag(3, &reply)),
        ("enrol-reply-empty", tag(4, b"{}")),
    ]
}

#[test]
fn seeds_parse() {
    for (name, bytes) in seeds() {
        assert!(bytes.len() > 1, "{name}");
    }
}

/// Writes seed inputs for the `comms_messages` fuzz target into the
/// directory in `PALISADE_FUZZ_SEED_DIR`.
///
/// ```text
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/comms_messages" \
///     cargo test -p palisade-proto --test comms -- --ignored write_comms_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_comms_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();
    for (name, bytes) in seeds() {
        std::fs::write(dir.join(format!("seed-{name}")), bytes).unwrap();
    }
}
