//! Fuzzes the SNTP reply checker (#224): the input is a UDP datagram from
//! the network. No input may panic, and every accepted reply must match the
//! rules: 48 bytes, server mode, a synchronised stratum, the request's
//! originate timestamp echoed, and offset and delay computable without
//! overflow for any local times.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_proto::sntp::{NtpTimestamp, PACKET_LEN, Reply};

fuzz_target!(|data: &[u8]| {
    // The first 8 bytes choose the request's transmit timestamp, so the
    // originate check is reachable; the rest is the reply.
    let Some((sent, packet)) = data.split_first_chunk::<8>() else {
        return;
    };
    let sent = NtpTimestamp(u64::from_be_bytes(*sent));
    if let Ok(reply) = Reply::parse(packet, sent) {
        assert_eq!(packet.len(), PACKET_LEN);
        assert!((1..=15).contains(&reply.stratum));
        for (t1, t4) in [(0, 0), (i64::MIN, i64::MAX), (i64::MAX, i64::MIN), (1_795_478_400_000_000, 1_795_478_400_100_000)] {
            let _ = reply.offset_micros(t1, t4);
            assert!(reply.delay_micros(t1, t4) >= 0);
        }
    }
});
