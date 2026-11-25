//! OCSP responses as revocation data (#50).
//!
//! The fixtures in `fixtures/ocsp` were made by `generate.sh` there with
//! throwaway test CAs. Every response has a `thisUpdate` of the time the
//! script ran and a `nextUpdate` ten years later (one minute later for
//! `good-expired.der`); the tests read those times from the responses.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    CertRevocation, CertSummary, Coverage, DigestAlgorithm, OcspCertStatus, OcspError,
    OcspResponse, ResponderId, RevocationFailure, RevocationMode, RevocationReason, RevocationSet,
    RevocationSource, SignatureReport, TrustConfig, ValidityContext, ValidityPolicy,
    VerificationError, VerifyOptions, evaluate_trust, evaluate_validity, verify_pe,
};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ocsp");

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

fn cert(name: &str) -> CertSummary {
    CertSummary::from_der(&bytes(&format!("{name}.der"))).unwrap()
}

fn response(name: &str) -> OcspResponse {
    OcspResponse::from_der(&bytes(&format!("{name}.der"))).unwrap()
}

/// A time at which every ten-year response is current.
fn now_of(r: &OcspResponse) -> i64 {
    r.responses[0].this_update + 86_400
}

fn state(r: OcspResponse, cert_name: &str) -> CertRevocation {
    let now = now_of(&r);
    let mut set = RevocationSet::new();
    set.add_ocsp(r);
    let (c, root) = (cert(cert_name), cert("root"));
    set.state_of(&[&c, &root], 0, now)
}

#[test]
fn responses_parse() {
    let r = response("good-by-root");
    assert_eq!(r.responses.len(), 1);
    let single = &r.responses[0];
    assert_eq!(single.status, OcspCertStatus::Good);
    assert_eq!(single.serial, "1001");
    assert_eq!(single.hash_alg, DigestAlgorithm::Sha1);
    assert!(single.next_update.is_some());
    assert!(matches!(r.responder, ResponderId::ByName(_)));
    assert!(r.certificates.len() <= 1);
    assert_eq!(
        response("good-by-root-sha256").responses[0].hash_alg,
        DigestAlgorithm::Sha256
    );
    assert!(matches!(
        response("good-by-key").responder,
        ResponderId::ByKey(_)
    ));
    let revoked = response("revoked-delegated");
    assert_eq!(
        revoked.responses[0].status,
        OcspCertStatus::Revoked {
            at: 1_622_505_600, // 2021-06-01
            reason: RevocationReason::KeyCompromise
        }
    );
    assert_eq!(
        response("unknown-by-root").responses[0].status,
        OcspCertStatus::Unknown
    );
    // A response serialises.
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["responses"][0]["status"], "good");
}

#[test]
fn a_current_good_answer_covers_the_certificate() {
    for name in [
        "good-by-root",
        "good-by-root-sha256",
        "good-by-key",
        "good-delegated",
    ] {
        assert_eq!(
            state(response(name), "leaf"),
            CertRevocation::Good,
            "{name}"
        );
    }
}

#[test]
fn only_an_authorised_responder_counts() {
    // Signed by a certificate the root issued but without the OCSP Signing
    // EKU: not an authorised responder, so the answer is not used.
    let rogue = response("good-rogue");
    let (leaf, root) = (cert("leaf"), cert("root"));
    assert!(!rogue.verified_by(&root));
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(rogue.clone());
    // `leaf` names an OCSP URL, so OnlineRequired needs an answer: with only
    // the unusable one, its status is unknown.
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now_of(&rogue)),
        CertRevocation::Unknown
    );
    // The root's own and its delegate's answers are about the leaf.
    let delegated = response("good-delegated");
    assert!(delegated.verified_by(&root));
    assert_eq!(delegated.answers_for(&leaf, &root).len(), 1);
    assert!(rogue.answers_for(&leaf, &root).is_empty());
    // The responder signed its own response, but it issued nothing the
    // response is about, so it answers nothing as an issuer.
    let responder = cert("responder");
    assert!(delegated.verified_by(&responder));
    assert!(delegated.answers_for(&leaf, &responder).is_empty());
    // Another root's key verifies nothing.
    let tsa_root = CertSummary::from_der(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/timestamp/tsa-root.der"
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(!response("good-by-root").verified_by(&tsa_root));
    assert!(!delegated.verified_by(&tsa_root));
}

#[test]
fn a_revoked_answer_revokes_with_its_date_and_reason() {
    let r = response("revoked-delegated");
    match state(r, "other") {
        CertRevocation::Revoked { entries, coverage } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].revoked_at, Some(1_622_505_600));
            assert_eq!(entries[0].reason, RevocationReason::KeyCompromise);
            assert_eq!(entries[0].source, RevocationSource::Ocsp(0));
            // The answer was not `good`, so nothing vouches for coverage;
            // with mode Off nothing more is needed either.
            assert_eq!(coverage, Coverage::Good);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_response_for_another_certificate_says_nothing() {
    // The good response names 1001; `other` is 1002.
    assert_eq!(
        state(response("good-by-root"), "other"),
        CertRevocation::Good
    );
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    let r = response("good-by-root");
    let now = now_of(&r);
    set.add_ocsp(r);
    let (other, root) = (cert("other"), cert("root"));
    assert_eq!(
        set.state_of(&[&other, &root], 0, now),
        CertRevocation::Unknown
    );
    // Neither does an `unknown` answer.
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(response("unknown-by-root"));
    let leaf = cert("leaf");
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now),
        CertRevocation::Unknown
    );
}

#[test]
fn a_stale_good_answer_vouches_for_nothing() {
    let r = response("good-expired");
    let single = &r.responses[0];
    let after = single.next_update.unwrap() + 1;
    assert!(single.is_current(single.this_update));
    assert!(!single.is_current(after));
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(r);
    let (leaf, root) = (cert("leaf"), cert("root"));
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, after),
        CertRevocation::Unknown
    );
}

fn entry(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(u32::try_from(data.len()).unwrap() + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

fn signed() -> SignatureReport {
    let image = PeBuilder {
        certificate: Some(entry(&bytes("leaf.p7"))),
        ..PeBuilder::default()
    }
    .build();
    verify_pe(&image, &VerifyOptions::default()).unwrap()
}

#[test]
fn evaluate_validity_uses_ocsp_answers() {
    let report = signed();
    assert!(report.signatures[0].status.is_valid(), "{report:#?}");
    let mut trust_cfg = TrustConfig::new();
    trust_cfg
        .add_anchor("ocsp root", &bytes("root.der"))
        .unwrap();
    let trust = evaluate_trust(&report, &trust_cfg, None);
    assert!(trust.signers[0].trusted);
    let policy = ValidityPolicy::default();
    let tsa = TrustConfig::new();
    let run = |set: &RevocationSet, now: i64| {
        let ctx = ValidityContext {
            now,
            clock_floor: None,
            policy: &policy,
            revocation: set,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx).signatures[0].clone()
    };
    let good = response("good-delegated");
    let now = now_of(&good);
    // OnlineRequired and fail closed: the leaf's answer is required.
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.failure = RevocationFailure::FailClosed;
    assert_eq!(
        run(&set, now).error,
        VerificationError::RevocationUnavailable
    );
    set.add_ocsp(good);
    let v = run(&set, now);
    assert!(v.is_ok(), "{v:#?}");
    // A revoked answer for this leaf (made by splicing nothing: the
    // revoked fixture is for another serial) does not apply to it.
    set.add_ocsp(response("revoked-delegated"));
    assert!(run(&set, now).is_ok());
}

#[test]
fn malformed_responses_are_rejected() {
    let good = bytes("good-by-root.der");
    // Truncated.
    assert!(OcspResponse::from_der(&good[..good.len() - 1]).is_err());
    // Too large.
    assert_eq!(
        OcspResponse::from_der(&vec![
            0_u8;
            palisade_fileid::authenticode::MAX_OCSP_SIZE + 1
        ])
        .unwrap_err(),
        OcspError::TooLarge(palisade_fileid::authenticode::MAX_OCSP_SIZE + 1)
    );
    // An unsuccessful status: 30 03 0a 01 01 (malformedRequest).
    assert_eq!(
        OcspResponse::from_der(&[0x30, 0x03, 0x0a, 0x01, 0x01]).unwrap_err(),
        OcspError::Unsuccessful(1)
    );
    // Successful but with no response bytes.
    assert!(OcspResponse::from_der(&[0x30, 0x03, 0x0a, 0x01, 0x00]).is_err());
    // A tampered signature never verifies.
    let mut tampered = good.clone();
    let last = tampered.len() - 300;
    tampered[last] ^= 0x01;
    if let Ok(r) = OcspResponse::from_der(&tampered) {
        assert!(!r.verified_by(&cert("root")));
    }
    for garbage in [&[][..], &[0x30], &[0x30, 0x80], &[0x04, 0x00]] {
        assert!(OcspResponse::from_der(garbage).is_err());
    }
}

/// Writes seed inputs for the `timestamp_crl` fuzz target (selector 3:
/// OCSP).
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/timestamp_crl" \
///     cargo test -p palisade-fileid --test ocsp -- --ignored write_ocsp_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_ocsp_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in [
        "good-by-root",
        "good-delegated",
        "revoked-delegated",
        "unknown-by-root",
    ] {
        let mut seed = vec![3_u8];
        seed.extend(bytes(&format!("{name}.der")));
        std::fs::write(dir.join(format!("ocsp-{name}")), seed).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mutated_responses_never_panic_or_vouch_falsely(
        which in 0_usize..4,
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let name = ["good-by-root", "good-delegated", "revoked-delegated", "good-by-key"][which];
        let original = bytes(&format!("{name}.der"));
        let mut data = original.clone();
        for (i, b) in flips {
            let at = i.index(data.len());
            data[at] = b;
        }
        if let Ok(r) = OcspResponse::from_der(&data) {
            let root = cert("root");
            if data != original && r.verified_by(&root) {
                // A mutation that still verifies must leave what was signed
                // (and so the answer) as it was.
                let before = OcspResponse::from_der(&original).unwrap();
                prop_assert_eq!(&r.responses, &before.responses);
            }
        }
    }
}

#[test]
fn an_unreachable_responder_fails_open_or_closed_as_policy_says() {
    // The fetcher (#4, #126) reports the leaf's OCSP URL as unreachable (a
    // timeout or an error): the leaf's status is unknown, whatever mode.
    let report = signed();
    let mut trust_cfg = TrustConfig::new();
    trust_cfg
        .add_anchor("ocsp root", &bytes("root.der"))
        .unwrap();
    let trust = evaluate_trust(&report, &trust_cfg, None);
    let leaf = cert("leaf");
    assert_eq!(leaf.ocsp_urls, ["http://ocsp.test/"]);
    let policy = ValidityPolicy::default();
    let tsa = TrustConfig::new();
    // When the good answer is current (the leaf is valid until 2040).
    let now = now_of(&response("good-delegated"));
    let run = |set: &RevocationSet| {
        let ctx = ValidityContext {
            now,
            clock_floor: None,
            policy: &policy,
            revocation: set,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx).signatures[0].clone()
    };
    for mode in [RevocationMode::Online, RevocationMode::OnlineRequired] {
        let mut set = RevocationSet::new();
        set.mode = mode;
        set.unavailable_urls = vec!["http://ocsp.test/".into()];
        // Fail open (the default): a warning, and the signature passes.
        let v = run(&set);
        assert!(v.is_ok(), "{v:#?}");
        assert!(!v.warnings.is_empty());
        // Fail closed: code 1006.
        set.failure = RevocationFailure::FailClosed;
        assert_eq!(run(&set).error, VerificationError::RevocationUnavailable);
        // A good answer fetched later covers it again.
        set.unavailable_urls.clear();
        set.add_ocsp(response("good-delegated"));
        assert!(run(&set).is_ok());
    }
}
