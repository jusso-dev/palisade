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
    assert_eq!(
        delegated
            .answers_for(&leaf, &root, now_of(&delegated))
            .len(),
        1
    );
    assert!(rogue.answers_for(&leaf, &root, now_of(&rogue)).is_empty());
    // The responder signed its own response, but it issued nothing the
    // response is about, so it answers nothing as an issuer.
    let responder = cert("responder");
    assert!(delegated.verified_by(&responder));
    assert!(
        delegated
            .answers_for(&leaf, &responder, now_of(&delegated))
            .is_empty()
    );
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
            // A current `revoked` answer from an authorised responder is
            // itself coverage.
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
    // Successful but with no response bytes: a DER error, not "unsuccessful".
    assert!(matches!(
        OcspResponse::from_der(&[0x30, 0x03, 0x0a, 0x01, 0x00]).unwrap_err(),
        OcspError::Asn1(_)
    ));
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

#[test]
fn an_expired_or_revoked_responder_vouches_for_nothing() {
    let (leaf, root) = (cert("leaf"), cert("root"));
    // Valid only in 2021, but the response was produced in this run's time.
    let old = response("good-old-responder");
    assert!(old.produced_at > cert("old-responder").not_after);
    assert!(!old.verified_by(&root));
    assert!(old.answers_for(&leaf, &root, now_of(&old)).is_empty());
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(old.clone());
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now_of(&old)),
        CertRevocation::Unknown
    );
    // A responder an offline entry revokes vouches for nothing either.
    let good = response("good-delegated");
    let responder = cert("responder");
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(good.clone());
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now_of(&good)),
        CertRevocation::Good
    );
    set.add_certificate(palisade_fileid::authenticode::RevokedCertificate {
        cert: palisade_fileid::authenticode::CertificateMatch::Sha256Thumbprint(
            responder.sha256_thumbprint.to_ascii_uppercase(),
        ),
        revoked_at: None,
        reason: RevocationReason::KeyCompromise,
        source: RevocationSource::Policy,
    });
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now_of(&good)),
        CertRevocation::Unknown
    );
    // A delegated `good` answer stops vouching once the responder expires.
    let after = responder.not_after + 1;
    assert!(good.answers_for(&leaf, &root, after).is_empty());
    assert_eq!(good.answers_for(&leaf, &root, now_of(&good)).len(), 1);
    // The root's own answers have no such limit.
    let by_root = response("good-by-root");
    assert_eq!(by_root.answers_for(&leaf, &root, after).len(), 1);
}

#[test]
fn a_response_never_names_another_issuers_certificate() {
    // A certificate with the leaf's serial under another issuer: the
    // response's CertID hashes the OCSP root, not that issuer.
    let leaf = cert("leaf");
    let root = cert("root");
    let foreign_issuer = CertSummary::from_der(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/timestamp/root.der"
        ))
        .unwrap(),
    )
    .unwrap();
    let r = response("good-by-root");
    assert!(r.responses[0].names(&leaf, &root));
    // The right issuer certificate, but the checked certificate names
    // another issuer.
    let mut stranger = leaf.clone();
    stranger.issuer = foreign_issuer.subject.clone();
    assert!(!r.responses[0].names(&stranger, &root));
    assert!(r.answers_for(&stranger, &root, now_of(&r)).is_empty());
    // A key identifier that disagrees.
    let mut rekeyed = leaf.clone();
    rekeyed.authority_key_id = Some("00".repeat(20));
    assert!(!r.responses[0].names(&rekeyed, &root));
    // And the foreign issuer itself is not the response's.
    assert!(!r.responses[0].names(&leaf, &foreign_issuer));
}

#[test]
fn a_current_revoked_answer_is_coverage() {
    // Under OnlineRequired, a current `revoked` answer is an answer: the
    // certificate is covered even when policy excuses the entry (revoked
    // after a trusted signing time, for a reason that is not a compromise).
    let r = response("revoked-delegated");
    let now = now_of(&r);
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(r);
    let (other, root) = (cert("other"), cert("root"));
    match set.state_of(&[&other, &root], 0, now) {
        CertRevocation::Revoked { coverage, .. } => assert_eq!(coverage, Coverage::Good),
        s => panic!("{s:?}"),
    }
}

// --- Synthetic responses, for each parser rule. ----------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

const SHA1_OID: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const NONCE: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];

fn gtime() -> Vec<u8> {
    tlv(0x18, b"20240101000000Z")
}

fn ext(id: &[u8], critical: bool) -> Vec<u8> {
    let mut body = tlv(0x06, id);
    if critical {
        body.extend(tlv(0x01, &[0xff]));
    }
    body.extend(tlv(0x04, &tlv(0x04, &[1, 2, 3])));
    tlv(0x30, &body)
}

/// A SingleResponse with these parts.
struct Single {
    hash_oid: Vec<u8>,
    hash_len: usize,
    status: Vec<u8>,
    extensions: Option<Vec<Vec<u8>>>,
}

impl Default for Single {
    fn default() -> Self {
        Self {
            hash_oid: SHA1_OID.to_vec(),
            hash_len: 20,
            status: tlv(0x80, &[]),
            extensions: None,
        }
    }
}

impl Single {
    fn der(&self) -> Vec<u8> {
        let alg = tlv(
            0x30,
            &[tlv(0x06, &self.hash_oid), vec![0x05, 0x00]].concat(),
        );
        let cert_id = tlv(
            0x30,
            &[
                alg,
                tlv(0x04, &vec![0xaa; self.hash_len]),
                tlv(0x04, &vec![0xbb; self.hash_len]),
                tlv(0x02, &[0x10, 0x01]),
            ]
            .concat(),
        );
        let mut body = [cert_id, self.status.clone(), gtime()].concat();
        body.extend(tlv(0xa0, &gtime()));
        if let Some(exts) = &self.extensions {
            body.extend(tlv(0xa1, &tlv(0x30, &exts.concat())));
        }
        tlv(0x30, &body)
    }
}

/// A whole OCSPResponse (never validly signed) with these parts.
fn synthetic(
    version: Option<u8>,
    singles: &[Vec<u8>],
    exts: Option<&[Vec<u8>]>,
    certs: usize,
) -> Vec<u8> {
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, b"x")].concat(),
            ),
        ),
    );
    let mut tbs = Vec::new();
    if let Some(v) = version {
        tbs.extend(tlv(0xa0, &tlv(0x02, &[v])));
    }
    tbs.extend(tlv(0xa1, &name));
    tbs.extend(gtime());
    tbs.extend(tlv(0x30, &singles.concat()));
    if let Some(exts) = exts {
        tbs.extend(tlv(0xa1, &tlv(0x30, &exts.concat())));
    }
    let alg = tlv(0x30, &[tlv(0x06, SHA256_RSA), vec![0x05, 0x00]].concat());
    let mut basic = [tlv(0x30, &tbs), alg, tlv(0x03, &[0x00, 0x01])].concat();
    if certs > 0 {
        let c = bytes("root.der");
        let all: Vec<u8> = std::iter::repeat_n(c, certs).flatten().collect();
        basic.extend(tlv(0xa0, &tlv(0x30, &all)));
    }
    let basic = tlv(0x30, &basic);
    let response_bytes = tlv(
        0x30,
        &[
            tlv(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
            ),
            tlv(0x04, &basic),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[tlv(0x0a, &[0x00]), tlv(0xa0, &response_bytes)].concat(),
    )
}

fn parse(der: &[u8]) -> Result<OcspResponse, OcspError> {
    OcspResponse::from_der(der)
}

#[test]
fn every_parser_rule_has_a_test() {
    let one = [Single::default().der()];
    // The baseline parses.
    let r = parse(&synthetic(None, &one, None, 0)).unwrap();
    assert_eq!(r.responses.len(), 1);
    assert_eq!(r.responses[0].serial, "1001");
    // A non-critical nonce is ignored...
    assert!(parse(&synthetic(None, &one, Some(&[ext(NONCE, false)]), 0)).is_ok());
    // ...a critical one is rejected, as is any other critical extension.
    assert!(matches!(
        parse(&synthetic(None, &one, Some(&[ext(NONCE, true)]), 0)).unwrap_err(),
        OcspError::UnhandledCriticalExtension(_)
    ));
    assert!(matches!(
        parse(&synthetic(None, &one, Some(&[ext(&[0x2a, 0x03], true)]), 0)).unwrap_err(),
        OcspError::UnhandledCriticalExtension(_)
    ));
    // Duplicate and empty extension lists.
    assert!(matches!(
        parse(&synthetic(
            None,
            &one,
            Some(&[ext(NONCE, false), ext(NONCE, false)]),
            0
        ))
        .unwrap_err(),
        OcspError::DuplicateExtension(_)
    ));
    assert!(matches!(
        parse(&synthetic(None, &one, Some(&[]), 0)).unwrap_err(),
        OcspError::Asn1(_)
    ));
    // Single-response extensions follow the same rules.
    let critical_single = Single {
        extensions: Some(vec![ext(&[0x2a, 0x03], true)]),
        ..Single::default()
    };
    assert!(matches!(
        parse(&synthetic(None, &[critical_single.der()], None, 0)).unwrap_err(),
        OcspError::UnhandledCriticalExtension(_)
    ));
    // An encoded v1 is not DER; any other version is unknown.
    assert!(matches!(
        parse(&synthetic(Some(0), &one, None, 0)).unwrap_err(),
        OcspError::Asn1(_)
    ));
    assert_eq!(
        parse(&synthetic(Some(1), &one, None, 0)).unwrap_err(),
        OcspError::UnsupportedVersion(2)
    );
    // An undefined revocation reason.
    let reason = |r: u8| Single {
        status: tlv(0xa1, &[gtime(), tlv(0xa0, &tlv(0x0a, &[r]))].concat()),
        ..Single::default()
    };
    let r = parse(&synthetic(None, &[reason(1).der()], None, 0)).unwrap();
    assert_eq!(
        r.responses[0].status,
        OcspCertStatus::Revoked {
            at: 1_704_067_200,
            reason: RevocationReason::KeyCompromise
        }
    );
    assert_eq!(
        parse(&synthetic(None, &[reason(7).der()], None, 0)).unwrap_err(),
        OcspError::BadReason(7)
    );
    // CertID hash algorithm and length.
    let md5 = Single {
        hash_oid: vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05],
        hash_len: 16,
        ..Single::default()
    };
    assert!(matches!(
        parse(&synthetic(None, &[md5.der()], None, 0)).unwrap_err(),
        OcspError::UnsupportedCertIdHash(_)
    ));
    let short = Single {
        hash_len: 19,
        ..Single::default()
    };
    assert_eq!(
        parse(&synthetic(None, &[short.der()], None, 0)).unwrap_err(),
        OcspError::CertIdHashLength
    );
    // A status that is not one of the three choices.
    let bad_status = Single {
        status: tlv(0x83, &[]),
        ..Single::default()
    };
    assert!(parse(&synthetic(None, &[bad_status.der()], None, 0)).is_err());
    // The response and certificate caps.
    use palisade_fileid::authenticode::{MAX_OCSP_CERTIFICATES, MAX_OCSP_RESPONSES_PER_RESPONSE};
    let many: Vec<Vec<u8>> = (0..=MAX_OCSP_RESPONSES_PER_RESPONSE)
        .map(|_| Single::default().der())
        .collect();
    assert_eq!(
        parse(&synthetic(None, &many, None, 0)).unwrap_err(),
        OcspError::TooMany
    );
    assert!(parse(&synthetic(None, &many[1..], None, 0)).is_ok());
    assert_eq!(
        parse(&synthetic(None, &one, None, MAX_OCSP_CERTIFICATES + 1)).unwrap_err(),
        OcspError::TooMany
    );
    assert!(parse(&synthetic(None, &one, None, MAX_OCSP_CERTIFICATES)).is_ok());
    // Every error has a message.
    assert!(!OcspError::TooMany.to_string().is_empty());
}

#[test]
fn the_set_holds_a_bounded_number_of_responses() {
    use palisade_fileid::authenticode::MAX_OCSP_RESPONSES;
    let r = response("good-by-root");
    let mut set = RevocationSet::new();
    for i in 0..MAX_OCSP_RESPONSES {
        assert_eq!(set.add_ocsp(r.clone()), Some(i));
    }
    assert_eq!(set.add_ocsp(r), None);
    assert_eq!(set.ocsp_responses().len(), MAX_OCSP_RESPONSES);
}

#[test]
fn a_response_without_next_update_never_vouches() {
    let r = response("good-by-root");
    let mut single = r.responses[0].clone();
    assert!(single.is_current(single.this_update));
    single.next_update = None;
    assert!(!single.is_current(single.this_update));
}

#[test]
fn ocsp_checks_share_the_crl_budget_and_fail_closed() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    // More signer-relevant responses than the budget can check: each one
    // names the leaf and is signed by a delegate (two checks), so past the
    // budget the leaf's state is NotChecked, which fails closed.
    let r = response("good-delegated");
    let now = now_of(&r);
    let mut set = RevocationSet::new();
    for _ in 0..=MAX_CRL_CHECKS {
        set.add_ocsp(r.clone());
    }
    let (leaf, root) = (cert("leaf"), cert("root"));
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now),
        CertRevocation::NotChecked
    );
    // Within the budget the same answers cover it.
    let mut set = RevocationSet::new();
    for _ in 0..MAX_CRL_CHECKS / 2 {
        set.add_ocsp(r.clone());
    }
    assert_eq!(set.state_of(&[&leaf, &root], 0, now), CertRevocation::Good);
}

#[test]
fn a_responder_revoked_by_its_issuer_vouches_for_nothing() {
    use palisade_fileid::authenticode::Crl;
    let (leaf, root) = (cert("leaf"), cert("root"));
    let good = response("good-delegated");
    let now = now_of(&good);
    let crl = Crl::from_der(&bytes("crl-responder-revoked.der")).unwrap();
    // The CRL runs 2024 to 2034. At a time it is stale it covers nothing,
    // but it still revokes the responder: then nothing covers the leaf.
    let stale = crl.next_update.unwrap() + 1;
    assert!(stale > now && stale < cert("responder").not_after);
    let mut current = good.clone();
    current.responses[0].next_update = Some(stale + 1);
    let state = |crl: Option<Crl>, extra: Option<OcspResponse>, at: i64| {
        let mut set = RevocationSet::new();
        set.mode = RevocationMode::OnlineRequired;
        set.add_ocsp(current.clone());
        if let Some(c) = crl {
            set.add_crl(c);
        }
        if let Some(r) = extra {
            set.add_ocsp(r);
        }
        set.state_of(&[&leaf, &root], 0, at)
    };
    // Without the CRL, the responder's answer covers the leaf.
    assert_eq!(state(None, None, stale), CertRevocation::Good);
    // With it, the revoked responder vouches for nothing.
    assert_eq!(
        state(Some(crl.clone()), None, stale),
        CertRevocation::Unknown
    );
    // Another CA's CRL (it lists serial 1001 under another root) revokes
    // nothing here: a CRL counts only from the responder's issuer.
    let forged = Crl::from_der(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/timestamp/crl-forged.der"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(state(Some(forged), None, stale), CertRevocation::Good);
    // By the issuer's own OCSP answer about the responder.
    assert_eq!(
        state(None, Some(response("revoked-responder-by-root")), now),
        CertRevocation::Unknown
    );
}

#[test]
fn a_responder_vouches_only_inside_its_validity() {
    let (leaf, root) = (cert("leaf"), cert("root"));
    let responder = cert("responder");
    let mut good = response("good-delegated");
    // Make the answer current across the responder's whole life and
    // beyond, so only the responder's validity decides.
    good.responses[0].this_update = responder.not_before - 1_000_000;
    good.responses[0].next_update = Some(responder.not_after + 1_000_000);
    let run = |r: &OcspResponse, now: i64| {
        let mut set = RevocationSet::new();
        set.mode = RevocationMode::OnlineRequired;
        set.add_ocsp(r.clone());
        set.state_of(&[&leaf, &root], 0, now)
    };
    let inside = now_of(&response("good-delegated"));
    assert_eq!(run(&good, inside), CertRevocation::Good);
    // Before the responder is valid, and after it expires: no coverage.
    assert_eq!(
        run(&good, responder.not_before - 1),
        CertRevocation::Unknown
    );
    assert_eq!(run(&good, responder.not_after + 1), CertRevocation::Unknown);
    // A delegated `revoked` answer still revokes after the responder
    // expires, but is not coverage then.
    let mut revoked = response("revoked-delegated");
    revoked.responses[0].next_update = Some(responder.not_after + 1_000_000);
    let other = cert("other");
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(revoked);
    match set.state_of(&[&other, &root], 0, responder.not_after + 1) {
        CertRevocation::Revoked { coverage, .. } => assert_eq!(coverage, Coverage::Unknown),
        s => panic!("{s:?}"),
    }
}

#[test]
fn responder_revocation_checks_are_budgeted_and_fail_closed() {
    use palisade_fileid::authenticode::{Crl, MAX_CRL_CHECKS};
    let (leaf, root) = (cert("leaf"), cert("root"));
    let good = response("good-delegated");
    let now = now_of(&good);
    let revoking = Crl::from_der(&bytes("crl-responder-revoked.der")).unwrap();
    // A CRL that names the responder's serial but that the root did not
    // sign: the root's name, another key (the timestamp fixtures' forged CRL
    // is for another serial, so make one by flipping the signature).
    let mut der = bytes("crl-responder-revoked.der");
    let last = der.len() - 1;
    der[last] ^= 1;
    let forged = Crl::from_der(&der).unwrap();
    // Many forged copies, then the real one: checking each costs one CRL
    // check. Past the budget the responder's state is unknown, so its
    // answer is not used and the leaf is NotChecked: fail closed.
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(good.clone());
    for _ in 0..MAX_CRL_CHECKS {
        set.add_crl(forged.clone());
    }
    set.add_crl(revoking.clone());
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now),
        CertRevocation::NotChecked
    );
    // Within the budget, the real CRL is reached and revokes the responder.
    // (CRL checks are cached per issuer key, so the responder's check of
    // the root's CRLs reuses those made for the leaf itself.)
    let stale = revoking.next_update.unwrap() + 1;
    let mut current = good.clone();
    current.responses[0].next_update = Some(stale + 1);
    let mut set2 = RevocationSet::new();
    set2.mode = RevocationMode::OnlineRequired;
    set2.add_ocsp(current);
    for _ in 0..4 {
        set2.add_crl(forged.clone());
    }
    set2.add_crl(revoking);
    assert_eq!(
        set2.state_of(&[&leaf, &root], 0, stale),
        CertRevocation::Unknown
    );
    // Forged CRLs alone revoke nothing: the responder's answer still counts.
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(good.clone());
    for _ in 0..4 {
        set.add_crl(forged.clone());
    }
    assert_eq!(set.state_of(&[&leaf, &root], 0, now), CertRevocation::Good);
}

#[test]
fn an_issuer_ocsp_answer_about_the_responder_is_budgeted() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    let (leaf, root) = (cert("leaf"), cert("root"));
    let good = response("good-delegated");
    let now = now_of(&good);
    // The root's own answer revoking the responder, but with its signature
    // broken: checking it costs one check and revokes nothing.
    let mut broken = bytes("revoked-responder-by-root.der");
    // The signature's last byte sits just before the `[0]` certificates.
    let root_der = bytes("root.der");
    let certs_at = broken
        .windows(root_der.len())
        .position(|w| w == root_der.as_slice())
        .unwrap()
        - 8;
    broken[certs_at - 1] ^= 1;
    let broken = OcspResponse::from_der(&broken).unwrap();
    assert!(!broken.verified_by(&root));
    let run = |copies: usize| {
        let mut set = RevocationSet::new();
        set.mode = RevocationMode::OnlineRequired;
        set.add_ocsp(good.clone());
        for _ in 0..copies {
            set.add_ocsp(broken.clone());
        }
        set.state_of(&[&leaf, &root], 0, now)
    };
    // A few broken answers: checked, rejected, the responder still counts.
    assert_eq!(run(4), CertRevocation::Good);
    // More than the budget leaves: the responder's revocation state is not
    // known, so its answer is not used, and the leaf fails closed.
    assert_eq!(run(MAX_CRL_CHECKS), CertRevocation::NotChecked);
}

#[test]
fn responses_not_claiming_the_issuer_cost_nothing_to_rule_out() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    let (leaf, root) = (cert("leaf"), cert("root"));
    let good = response("good-delegated");
    let now = now_of(&good);
    // The root's answer revoking the responder, relabelled as if another
    // responder (by name) had signed it: it cannot be the issuer's own, so
    // ruling it out needs no signature check.
    let mut other = response("revoked-responder-by-root");
    other.responder = ResponderId::ByName(leaf.subject.der.clone());
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    set.add_ocsp(good.clone());
    for _ in 0..(2 * MAX_CRL_CHECKS) {
        set.add_ocsp(other.clone());
    }
    // Were each charged a check, the budget would run out: NotChecked.
    assert_eq!(set.state_of(&[&leaf, &root], 0, now), CertRevocation::Good);
    // The genuine issuer-signed answer still revokes the responder, and the
    // check made for it is shared with the response's own signer check.
    set.add_ocsp(response("revoked-responder-by-root"));
    assert_eq!(
        set.state_of(&[&leaf, &root], 0, now),
        CertRevocation::Unknown
    );
}
