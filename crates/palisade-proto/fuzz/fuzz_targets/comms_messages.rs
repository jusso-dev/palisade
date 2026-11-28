//! Fuzzes the agent-server message parsers (#223, #62): the server parses
//! enrolment and check-in requests from the network, and the agent parses
//! check-in and enrolment replies, HTTP response heads and its proxy's
//! `CONNECT` reply. No input
//! may panic, an accepted proxy reply's head must lie inside the input, and
//! an enrolment request only opens when its proof of possession verifies.
#![no_main]

use libfuzzer_sys::fuzz_target;
use palisade_proto::comms::{self, CheckIn, CheckInResponse, EnrolRequest, EnrolResponse, proxy};

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    match which % 6 {
        0 => {
            if let Ok(reply) = proxy::parse_reply(rest) {
                assert!(reply.head_len <= rest.len());
                assert!((100..=599).contains(&reply.status));
            }
        }
        1 => {
            if let Ok(request) = serde_json::from_slice::<EnrolRequest>(rest) {
                if let Ok((payload, key)) = request.open() {
                    assert_eq!(payload.public_key.as_bytes(), key.spki_der());
                }
            }
        }
        2 => {
            let _ = serde_json::from_slice::<CheckIn>(rest);
        }
        3 => {
            if let Ok(reply) = serde_json::from_slice::<CheckInResponse>(rest) {
                let interval = reply.interval_s();
                assert!((comms::MIN_CHECKIN_INTERVAL_S..=comms::MAX_CHECKIN_INTERVAL_S).contains(&interval));
            }
        }
        4 => {
            if let Ok(head) = comms::http::parse_head(rest) {
                assert!(head.head_len <= rest.len());
                assert!((100..=599).contains(&head.status));
            }
        }
        _ => {
            if let Ok(reply) = serde_json::from_slice::<EnrolResponse>(rest) {
                assert!(reply.chain.len() <= comms::MAX_CHAIN);
            }
        }
    }
});
