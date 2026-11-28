//! Tests for the agent-server messages.

#![allow(clippy::indexing_slicing)]

use std::str::FromStr;

use proptest::prelude::*;

use super::code::{self, CodeError, Pepper};
use super::proxy::{self, ProxyError};
use super::*;
use crate::pki::leaf_key::LeafKey;

fn facts() -> DeviceFacts {
    DeviceFacts {
        hostname: Text::new("ws-01").unwrap(),
        fqdn: Some(DnsName::from_str("ws-01.corp.example").unwrap()),
        os: Name::new("Windows 11 Pro").unwrap(),
        os_build: Some(Text::new("26100").unwrap()),
        arch: Some(Text::new("x86_64").unwrap()),
        smbios_uuid: None,
        serial: None,
        macs: BoundedVec::new(vec![Text::new("aa:bb:cc:dd:ee:ff").unwrap()]).unwrap(),
        domain: None,
        agent_version: Text::new("0.1.0").unwrap(),
    }
}

fn payload(key: &LeafKey) -> EnrolPayload {
    EnrolPayload {
        code: Text::new("ABCDEFGHJKMN").unwrap(),
        public_key: Base64::new(key.public_key().spki_der().to_vec()).unwrap(),
        key_protection: KeyProtection::Software,
        nonce: Base64::new(vec![7; 32]).unwrap(),
        created_at: Timestamp::from_unix_micros(1_795_478_400_000_000).unwrap(),
        facts: facts(),
    }
}

#[test]
fn an_enrolment_request_opens_with_its_own_key() {
    let (key, _) = LeafKey::generate().unwrap();
    let request = EnrolRequest::sign(&payload(&key), &key).unwrap();
    let json = serde_json::to_string(&request).unwrap();
    let back: EnrolRequest = serde_json::from_str(&json).unwrap();
    let (opened, public) = back.open().unwrap();
    assert_eq!(opened, payload(&key));
    assert_eq!(&public, key.public_key());
}

#[test]
fn an_enrolment_request_with_a_changed_payload_or_key_is_refused() {
    let (key, _) = LeafKey::generate().unwrap();
    let (other, _) = LeafKey::generate().unwrap();
    let request = EnrolRequest::sign(&payload(&key), &key).unwrap();

    // Signed by another key than the one it names.
    let forged = EnrolRequest::sign(&payload(&key), &other).unwrap();
    assert_eq!(forged.open().unwrap_err(), WireError::BadProof);

    // The payload changed after signing.
    let mut changed = payload(&key);
    changed.code = Text::new("ZZZZZZZZZZZZ").unwrap();
    let tampered = EnrolRequest {
        payload: Base64::new(serde_json::to_vec(&changed).unwrap()).unwrap(),
        signature: request.signature.clone(),
    };
    assert_eq!(tampered.open().unwrap_err(), WireError::BadProof);

    // Not a payload at all.
    let junk = EnrolRequest {
        payload: Base64::new(b"{}".to_vec()).unwrap(),
        signature: request.signature.clone(),
    };
    assert_eq!(junk.open().unwrap_err(), WireError::Malformed);

    // An Ed25519 key, validly encoded: malformed, not a bad proof.
    let mut signer = crate::pki::SoftwareSigner::new();
    let kid = signer
        .generate(
            crate::pki::KeyPurpose::PolicySigning,
            crate::pki::SignatureAlgorithm::Ed25519,
        )
        .unwrap();
    let mut ed = payload(&key);
    ed.public_key = Base64::new(
        crate::pki::Signer::public_key(&signer, &kid)
            .unwrap()
            .spki_der()
            .to_vec(),
    )
    .unwrap();
    let ed_request = EnrolRequest {
        payload: Base64::new(serde_json::to_vec(&ed).unwrap()).unwrap(),
        signature: request.signature.clone(),
    };
    assert_eq!(ed_request.open().unwrap_err(), WireError::Malformed);

    // A payload whose key is not P-384.
    let mut bad_key = payload(&key);
    bad_key.public_key = Base64::new(vec![0x30, 0x00]).unwrap();
    let bad = EnrolRequest {
        payload: Base64::new(serde_json::to_vec(&bad_key).unwrap()).unwrap(),
        signature: request.signature,
    };
    assert_eq!(bad.open().unwrap_err(), WireError::Malformed);
}

#[test]
fn messages_refuse_unknown_fields_and_oversized_values() {
    let extra = r#"{"payload":"","signature":"","admin":true}"#;
    assert!(serde_json::from_str::<EnrolRequest>(extra).is_err());
    let long_sig = format!(r#"{{"payload":"","signature":"{}"}}"#, "A".repeat(200));
    assert!(serde_json::from_str::<EnrolRequest>(&long_sig).is_err());
    let not_b64 = r#"{"payload":"!!!!","signature":""}"#;
    assert!(serde_json::from_str::<EnrolRequest>(not_b64).is_err());
    assert!(Base64::<2>::new(vec![1, 2, 3]).is_err());
    assert_eq!(
        format!("{:?}", Base64::<4>::new(vec![1]).unwrap()),
        "Base64(1 bytes)"
    );
}

#[test]
fn check_in_round_trips_and_the_interval_is_clamped() {
    let check_in = CheckIn {
        agent_version: Text::new("0.1.0").unwrap(),
        os_build: None,
        uptime_s: 42,
        policy_version: Some(3),
        bundle_hash: None,
        trust_version: 1,
        health: HealthSummary::Healthy,
        ips: BoundedVec::new(vec![IpAddress::from_str("192.0.2.1").unwrap()]).unwrap(),
    };
    let json = serde_json::to_string(&check_in).unwrap();
    assert_eq!(serde_json::from_str::<CheckIn>(&json).unwrap(), check_in);

    let mut reply = CheckInResponse {
        server_time: Timestamp::from_unix_micros(0).unwrap(),
        policy_version: None,
        bundle_hash: None,
        trust_version: 1,
        next_checkin_s: 0,
    };
    assert_eq!(reply.interval_s(), MIN_CHECKIN_INTERVAL_S);
    reply.next_checkin_s = u32::MAX;
    assert_eq!(reply.interval_s(), MAX_CHECKIN_INTERVAL_S);
    reply.next_checkin_s = 60;
    assert_eq!(reply.interval_s(), 60);
    assert_eq!(
        serde_json::to_string(&ErrorCode::CodeRejected).unwrap(),
        r#""code_rejected""#
    );
}

#[test]
fn wire_errors_have_messages() {
    for e in [
        WireError::TooLarge,
        WireError::Encode,
        WireError::Malformed,
        WireError::BadProof,
        WireError::Sign(crate::pki::SignerError::NotX509),
    ] {
        assert!(!e.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Registration codes
// ---------------------------------------------------------------------------

#[test]
fn codes_normalise_case_spaces_and_hyphens() {
    let a = code::normalise("abcd-efgh-jkmn").unwrap();
    let b = code::normalise("ABCD EFGH JKMN").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.expose(), "ABCDEFGHJKMN");
    assert_eq!(format!("{a:?}"), "Code([REDACTED])");
    assert_eq!(code::normalise("ABCDEFGHJKM"), Err(CodeError::Length));
    assert_eq!(code::normalise(&"A".repeat(25)), Err(CodeError::Length));
    // Confusable characters are not in the alphabet.
    for bad in [
        "ABCDEFGHJKM0",
        "ABCDEFGHJKMO",
        "ABCDEFGHJKM1",
        "ABCDEFGHJKMI",
        "ABCDEFGHJKMU",
        "ABCDEFGHJKMÄ",
    ] {
        assert_eq!(code::normalise(bad), Err(CodeError::Character), "{bad}");
    }
    for e in [CodeError::Length, CodeError::Character, CodeError::Random] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn generated_codes_have_the_length_asked_for() {
    assert_eq!(code::generate(11), Err(CodeError::Length));
    assert_eq!(code::generate(25), Err(CodeError::Length));
    for len in [code::MIN_LEN, code::DEFAULT_LEN, code::MAX_LEN] {
        let c = code::generate(len).unwrap();
        assert_eq!(c.expose().len(), len);
        assert_eq!(code::normalise(c.expose()).unwrap(), c);
    }
    // Two draws differ (a collision has odds of about 2^-98).
    assert_ne!(code::generate(20).unwrap(), code::generate(20).unwrap());
}

#[test]
fn the_stored_hash_depends_on_the_pepper() {
    let c = code::normalise("ABCDEFGHJKMN").unwrap();
    let p1 = Pepper::new(&[1; 32]);
    let p2 = Pepper::new(&[2; 32]);
    assert_eq!(
        p1.hash(&c),
        p1.hash(&code::normalise("abcd-efgh-jkmn").unwrap())
    );
    assert_ne!(p1.hash(&c), p2.hash(&c));
    assert_eq!(format!("{p1:?}"), "Pepper([REDACTED])");
}

proptest! {
    #[test]
    fn every_generated_code_uses_only_the_alphabet(len in code::MIN_LEN..=code::MAX_LEN) {
        let c = code::generate(len).unwrap();
        prop_assert_eq!(c.expose().len(), len);
        prop_assert!(c.expose().bytes().all(|b| code::ALPHABET.contains(&b)));
    }

    #[test]
    fn normalise_never_panics_and_accepts_only_the_alphabet(text in "\\PC{0,40}") {
        if let Ok(c) = code::normalise(&text) {
            prop_assert!((code::MIN_LEN..=code::MAX_LEN).contains(&c.expose().len()));
            prop_assert!(c.expose().bytes().all(|b| code::ALPHABET.contains(&b)));
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy CONNECT
// ---------------------------------------------------------------------------

#[test]
fn connect_requests_name_the_target_and_optional_credentials() {
    let r = proxy::connect_request("palisade.example", 443, None).unwrap();
    assert_eq!(
        r,
        b"CONNECT palisade.example:443 HTTP/1.1\r\nHost: palisade.example:443\r\n\r\n"
    );
    let r = proxy::connect_request("2001:db8::1", 8444, Some("Basic dXNlcjpwdw==")).unwrap();
    assert_eq!(
        String::from_utf8(r).unwrap(),
        "CONNECT [2001:db8::1]:8444 HTTP/1.1\r\nHost: [2001:db8::1]:8444\r\nProxy-Authorization: Basic dXNlcjpwdw==\r\n\r\n"
    );
    for bad in ["", "a b", "a\r\nX: y", "user@host", "host/path"] {
        assert_eq!(
            proxy::connect_request(bad, 443, None),
            Err(ProxyError::BadTarget),
            "{bad:?}"
        );
    }
    assert_eq!(
        proxy::connect_request("h", 1, Some("Basic x\r\nInjected: 1")),
        Err(ProxyError::BadTarget)
    );
    assert_eq!(
        proxy::connect_request("h", 1, Some("")),
        Err(ProxyError::BadTarget)
    );
}

#[test]
fn proxy_replies_parse_strictly() {
    let ok = b"HTTP/1.1 200 Connection established\r\nVia: proxy\r\n\r\n\x16\x03";
    let reply = proxy::parse_reply(ok).unwrap();
    assert!(reply.is_open());
    assert_eq!(reply.status, 200);
    assert_eq!(&ok[reply.head_len..], b"\x16\x03");

    let bare = proxy::parse_reply(b"HTTP/1.0 200\r\n\r\n").unwrap();
    assert!(bare.is_open());

    let denied = proxy::parse_reply(
        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
    )
    .unwrap();
    assert!(!denied.is_open());
    assert_eq!(denied.status, 407);

    assert_eq!(
        proxy::parse_reply(b"HTTP/1.1 200 OK\r\n"),
        Err(ProxyError::Incomplete)
    );
    assert_eq!(proxy::parse_reply(b""), Err(ProxyError::Incomplete));
    for bad in [
        &b"HTTP/2 200\r\n\r\n"[..],
        b"HTTP/1.1 20x OK\r\n\r\n",
        b"HTTP/1.1 099 Low\r\n\r\n",
        b"HTTP/1.1 600 High\r\n\r\n",
        b"HTTP/1.1 200OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nBad name: x\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n: empty\r\n\r\n",
        b"HTTP/1.1 200 OK\nX: y\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n",
        b"HTTP/1.1 200 O\x00K\r\n\r\n",
    ] {
        assert_eq!(
            proxy::parse_reply(bad),
            Err(ProxyError::Malformed),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    let mut big = b"HTTP/1.1 200 OK\r\n".to_vec();
    big.resize(proxy::MAX_HEAD + 1, b'a');
    assert_eq!(proxy::parse_reply(&big), Err(ProxyError::TooLarge));
    let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
    for _ in 0..=proxy::MAX_HEADERS {
        many.extend_from_slice(b"X: y\r\n");
    }
    many.extend_from_slice(b"\r\n");
    assert_eq!(proxy::parse_reply(&many), Err(ProxyError::TooLarge));
    for e in [
        ProxyError::Incomplete,
        ProxyError::TooLarge,
        ProxyError::Malformed,
        ProxyError::BadTarget,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn response_heads_report_framing_and_retry_after() {
    use super::http::{HeadError, parse_head};
    let h =
        parse_head(b"HTTP/1.1 429 Too Many\r\nRetry-After: 30\r\nContent-Length:  12 \r\n\r\nbody")
            .unwrap();
    assert_eq!(h.status, 429);
    assert_eq!(h.retry_after, Some(30));
    assert_eq!(h.content_length, Some(12));
    assert!(!h.transfer_encoding);
    let h = parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nRetry-After: Wed, 21 Oct 2026 07:28:00 GMT\r\n\r\n").unwrap();
    assert!(h.transfer_encoding);
    assert_eq!(h.retry_after, None);
    assert_eq!(h.content_length, None);
    for bad in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1 2\r\n\r\n",
    ] {
        assert_eq!(
            parse_head(bad),
            Err(HeadError::Malformed),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    for e in [
        HeadError::Incomplete,
        HeadError::TooLarge,
        HeadError::Malformed,
    ] {
        assert!(!e.to_string().is_empty());
    }
}

proptest! {
    #[test]
    fn proxy_parsing_never_panics_and_heads_fit(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(reply) = proxy::parse_reply(&input) {
            prop_assert!(reply.head_len <= input.len());
            prop_assert!((100..=599).contains(&reply.status));
            prop_assert_eq!(&input[reply.head_len - 4..reply.head_len], b"\r\n\r\n");
        }
    }
}
