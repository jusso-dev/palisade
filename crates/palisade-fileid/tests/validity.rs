//! Timestamps, expiry, revocation and the verification-error taxonomy
//! (#50).
//!
//! The fixtures in `fixtures/timestamp` were made by `generate.sh` there,
//! with throwaway test CAs and fixed dates (listed in the script). Every
//! signature claims 2021-01-01; the `leaf` signer expired on 2022-01-01.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

mod common;

use common::*;
use palisade_fileid::authenticode::{
    CertRevocation, CertificateMatch, CertificateOptions, CertificatePin, Coverage, Crl, CrlError,
    ErrorIgnoreFlags, ExpiryPolicy, IgnoreFlag, RelaxedCheck, RevocationFailure, RevocationMode,
    RevocationReason, RevocationSet, RevocationSource, RevokedCertificate, SignatureReport,
    TimeValidity, TimestampKind, TimestampStatus, TrustConfig, UntrustedReason, ValidityContext,
    ValidityPolicy, ValidityReport, ValidityWarning, VerificationError, VerifyOptions,
    evaluate_trust, evaluate_validity, parse_timestamp_time, verify_pe, verify_timestamps,
};
use palisade_fileid::hash::{Digest, HashAlgorithm};
use proptest::prelude::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/timestamp");

const Y2020_06: i64 = 1_590_969_600; // 2020-06-01
const Y2021: i64 = 1_609_459_200; // 2021-01-01
const Y2021_06: i64 = 1_622_505_600; // 2021-06-01
const Y2023: i64 = 1_672_531_200; // 2023-01-01
const Y2026: i64 = 1_767_225_600; // 2026-01-01
const Y2041: i64 = 2_240_524_800; // 2041-01-01, after the TSA expires

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

fn entry(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(data.len() as u32 + 8).to_le_bytes());
    out.extend_from_slice(&0x0200_u16.to_le_bytes());
    out.extend_from_slice(&2_u16.to_le_bytes());
    out.extend_from_slice(data);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out
}

fn report_of(blob: &[u8]) -> SignatureReport {
    let image = PeBuilder {
        certificate: Some(entry(blob)),
        ..PeBuilder::default()
    }
    .build();
    verify_pe(&image, &VerifyOptions::default()).unwrap()
}

fn code_trust() -> TrustConfig {
    let mut t = TrustConfig::new();
    t.add_anchor("code root", &bytes("root.der")).unwrap();
    t
}

fn tsa_trust() -> TrustConfig {
    let mut t = TrustConfig::new();
    t.add_anchor("tsa root", &bytes("tsa-root.der")).unwrap();
    t
}

struct Case {
    policy: ValidityPolicy,
    revocation: RevocationSet,
    tsa: TrustConfig,
    now: i64,
    floor: Option<i64>,
    digests: Vec<Digest>,
}

impl Case {
    fn new(now: i64) -> Self {
        Self {
            policy: ValidityPolicy::default(),
            revocation: RevocationSet::new(),
            tsa: tsa_trust(),
            now,
            floor: None,
            digests: Vec::new(),
        }
    }

    fn run(&self, fixture: &str) -> ValidityReport {
        let report = report_of(&bytes(fixture));
        assert!(report.signatures[0].status.is_valid(), "{report:#?}");
        let trust = evaluate_trust(&report, &code_trust(), None);
        assert!(trust.signers[0].trusted, "{trust:#?}");
        let ctx = ValidityContext {
            now: self.now,
            clock_floor: self.floor,
            policy: &self.policy,
            revocation: &self.revocation,
            tsa_trust: &self.tsa,
            file_digests: &self.digests,
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx)
    }

    fn error(&self, fixture: &str) -> VerificationError {
        self.run(fixture).signatures[0].error
    }
}

fn crl(name: &str) -> Crl {
    Crl::from_der(&bytes(name)).unwrap()
}

// --- Timestamps ----------------------------------------------------------

#[test]
fn rfc3161_token_is_parsed_and_verified() {
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    let sig = &report.signatures[0];
    assert_eq!(sig.timestamp_tokens.len(), 1);
    let ts = &verify_timestamps(sig, &tsa_trust())[0];
    assert_eq!(ts.kind, TimestampKind::Rfc3161);
    assert_eq!(ts.status, TimestampStatus::Valid, "{ts:#?}");
    assert!(ts.valid);
    assert_eq!(ts.time, Some(Y2021));
    assert_eq!(
        ts.digest_alg,
        Some(palisade_fileid::authenticode::DigestAlgorithm::Sha256)
    );
    assert!(ts.policy.is_some() && ts.serial_number.is_some());
    let tsa = ts.tsa_cert.as_ref().unwrap();
    assert_eq!(tsa.subject.common_name(), Some("Palisade Test TSA"));
    assert!(ts.tsa_chain.as_ref().unwrap().full_chain.anchored);
    // The accuracy osslsigncode writes is widened into the window.
    assert!(ts.earliest().unwrap() <= Y2021 && ts.latest().unwrap() >= Y2021);
}

#[test]
fn legacy_countersignature_is_parsed_and_verified() {
    let report = report_of(&bytes("leaf-legacy.p7"));
    let sig = &report.signatures[0];
    assert!(sig.status.is_valid());
    assert_eq!(
        sig.timestamp_tokens[0].kind,
        TimestampKind::CounterSignature
    );
    let ts = &verify_timestamps(sig, &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::Valid, "{ts:#?}");
    assert_eq!(ts.time, Some(Y2021));
    assert_eq!(ts.accuracy_secs, 0);
    assert_eq!(
        ts.tsa_cert.as_ref().unwrap().subject.common_name(),
        Some("Palisade Test TSA")
    );
}

#[test]
fn a_timestamp_needs_a_trusted_tsa() {
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    // The code signing root does not vouch for the TSA.
    let ts = &verify_timestamps(&report.signatures[0], &code_trust())[0];
    assert_eq!(ts.status, TimestampStatus::UntrustedTsa);
    assert!(!ts.valid);
    let ts = &verify_timestamps(&report.signatures[0], &TrustConfig::new())[0];
    assert_eq!(ts.status, TimestampStatus::UntrustedTsa);
}

#[test]
fn a_tsa_chain_must_permit_time_stamping() {
    let report = report_of(&bytes("current-rfc3161-cs-ca.p7"));
    let ts = &verify_timestamps(&report.signatures[0], &tsa_trust())[0];
    assert_eq!(
        ts.status,
        TimestampStatus::MissingTimeStampingEku,
        "{ts:#?}"
    );
}

#[test]
fn a_timestamp_copied_from_another_signature_does_not_cover_this_one() {
    // `current-rfc3161`'s token, spliced onto the `leaf` signature: valid
    // in itself, but its imprint is of another signature value.
    let mut report = report_of(&bytes("leaf-rfc3161.p7"));
    let other = report_of(&bytes("current-rfc3161.p7"));
    report.signatures[0].timestamp_tokens = other.signatures[0].timestamp_tokens.clone();
    let ts = &verify_timestamps(&report.signatures[0], &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::ImprintMismatch);

    let mut legacy = report_of(&bytes("leaf-legacy.p7"));
    legacy.signatures[0].signature_value[0] ^= 1;
    let ts = &verify_timestamps(&legacy.signatures[0], &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::ImprintMismatch);
}

/// The offset of the first occurrence of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).position(|w| w == needle).unwrap()
}

#[test]
fn a_tampered_token_fails_its_own_checks() {
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    let sig = &report.signatures[0];
    let token = &sig.timestamp_tokens[0].der;
    // The genTime digits inside TSTInfo: changing one breaks the token's
    // messageDigest attribute.
    let at = find(token, b"20210101000000");
    let mut changed = sig.clone();
    changed.timestamp_tokens[0].der[at + 3] = b'2';
    let ts = &verify_timestamps(&changed, &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::ContentDigestMismatch);
    // The last byte of the token is the end of its signature value.
    let mut changed = sig.clone();
    let last = changed.timestamp_tokens[0].der.len() - 1;
    changed.timestamp_tokens[0].der[last] ^= 1;
    let ts = &verify_timestamps(&changed, &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::SignatureInvalid);
    // Truncated: malformed, never valid.
    let mut changed = sig.clone();
    changed.timestamp_tokens[0].der.truncate(40);
    let ts = &verify_timestamps(&changed, &tsa_trust())[0];
    assert!(matches!(ts.status, TimestampStatus::Malformed(_)), "{ts:?}");
}

#[test]
fn a_timestamp_outside_the_tsa_validity_is_not_used() {
    // 2018-06-01: before the TSA certificate's validity (from 2019).
    let report = report_of(&bytes("leaf-rfc3161-2018.p7"));
    let ts = &verify_timestamps(&report.signatures[0], &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::TsaNotValidAtTime);
    // A timestamp inside it stands, judged long after the TSA expired.
    let v = Case::new(Y2041).run("leaf-rfc3161.p7");
    assert_eq!(v.signatures[0].trusted_timestamp, Some(0));
}

#[test]
fn the_earliest_valid_timestamp_wins() {
    let mut report = report_of(&bytes("leaf-rfc3161.p7"));
    let later = report_of(&bytes("leaf-rfc3161-2023.p7"));
    // Both tokens cover the same signature value (RSA PKCS #1 v1.5 is
    // deterministic), so the later one is valid here too.
    let mut tokens = later.signatures[0].timestamp_tokens.clone();
    tokens.extend(report.signatures[0].timestamp_tokens.clone());
    report.signatures[0].timestamp_tokens = tokens;
    let trust = evaluate_trust(&report, &code_trust(), None);
    let case = Case::new(Y2026);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    let sig = &v.signatures[0];
    assert!(sig.timestamps.iter().all(|t| t.valid), "{sig:#?}");
    assert_eq!(sig.trusted_timestamp, Some(1));
    assert_eq!(sig.signing_time, Some(Y2021));
    assert_eq!(sig.error, VerificationError::Ok);
}

// --- Expiry --------------------------------------------------------------

#[test]
fn an_expired_signer_with_a_valid_timestamp_is_valid_timestamped() {
    let v = Case::new(Y2026).run("leaf-rfc3161.p7");
    let sig = &v.signatures[0];
    assert_eq!(sig.validity, Some(TimeValidity::ValidTimestamped));
    assert_eq!(sig.error, VerificationError::Ok, "{sig:#?}");
    assert_eq!(v.primary, Some(0));
    assert_eq!(v.error, VerificationError::Ok);
}

#[test]
fn the_same_signature_without_the_timestamp_is_expired() {
    let v = Case::new(Y2026).run("leaf-untimestamped.p7");
    let sig = &v.signatures[0];
    assert_eq!(sig.validity, Some(TimeValidity::Expired));
    assert_eq!(sig.error, VerificationError::Expired);
    assert_eq!(sig.error.code(), 5);
    assert_eq!(v.primary, None);
    // While the signer was still valid, it was fine.
    let v = Case::new(Y2021).run("leaf-untimestamped.p7");
    assert_eq!(v.signatures[0].validity, Some(TimeValidity::Valid));
    assert!(v.signatures[0].is_ok());
}

#[test]
fn a_timestamp_after_the_signer_expired_does_not_help() {
    let v = Case::new(Y2026).run("leaf-rfc3161-2023.p7");
    let sig = &v.signatures[0];
    assert_eq!(sig.signing_time, Some(Y2023));
    assert_eq!(sig.validity, Some(TimeValidity::SignedOutsideValidity));
    assert_eq!(sig.error, VerificationError::Expired);
}

#[test]
fn an_untrusted_timestamp_on_an_expired_signer_is_signing_time_untrusted() {
    let mut case = Case::new(Y2026);
    case.tsa = TrustConfig::new();
    let sig = &case.run("leaf-rfc3161.p7").signatures[0];
    assert_eq!(sig.trusted_timestamp, None);
    assert_eq!(sig.validity, Some(TimeValidity::Expired));
    assert_eq!(sig.error, VerificationError::SigningTimeUntrusted);
    assert_eq!(sig.error.code(), 9);
    // On a current signer an untrusted timestamp changes nothing.
    assert!(case.run("current-rfc3161.p7").signatures[0].is_ok());
}

#[test]
fn lifetime_signing_expires_whatever_the_timestamp() {
    let v = Case::new(Y2026).run("lifetime-rfc3161.p7");
    let sig = &v.signatures[0];
    assert!(sig.lifetime_signing);
    assert_eq!(sig.trusted_timestamp, Some(0));
    assert_eq!(sig.validity, Some(TimeValidity::Expired));
    assert_eq!(sig.error, VerificationError::Expired);
    // Before expiry it is fine.
    assert!(Case::new(Y2021).run("lifetime-rfc3161.p7").signatures[0].is_ok());
}

#[test]
fn expiry_policies() {
    let mut case = Case::new(Y2026);
    case.policy.expiry_policy = ExpiryPolicy::Strict;
    assert_eq!(case.error("leaf-rfc3161.p7"), VerificationError::Expired);
    assert!(case.run("current-rfc3161.p7").signatures[0].is_ok());

    case.policy.expiry_policy = ExpiryPolicy::Ignore;
    let v = case.run("leaf-untimestamped.p7");
    assert!(v.signatures[0].is_ok());
    assert_eq!(v.signatures[0].validity, Some(TimeValidity::Expired));
    assert!(
        v.signatures[0]
            .warnings
            .contains(&ValidityWarning::ExpiryIgnored)
    );
    assert_eq!(case.error("lifetime-rfc3161.p7"), VerificationError::Ok);
}

#[test]
fn rolling_the_clock_back_does_not_revive_an_expired_signer() {
    let mut case = Case::new(Y2021);
    case.floor = Some(Y2026);
    let v = case.run("leaf-untimestamped.p7");
    assert!(v.clock_suspect);
    assert_eq!(v.effective_now, Y2026);
    assert_eq!(v.signatures[0].error, VerificationError::Expired);
}

#[test]
fn not_yet_valid_is_not_a_failure_when_the_clock_is_suspect() {
    // 2019: before the signer's validity. The floor says the clock is wrong,
    // but the floor itself is also before 2020.
    let mut case = Case::new(1_546_300_800); // 2019-01-01
    let v = case.run("current-rfc3161.p7");
    // A trusted 2021 timestamp: valid as of signing whatever now is.
    assert!(v.signatures[0].is_ok());
    let v = case.run("leaf-untimestamped.p7");
    assert_eq!(v.signatures[0].validity, Some(TimeValidity::NotYetValid));
    assert_eq!(v.signatures[0].error, VerificationError::Expired);
    case.floor = Some(1_561_939_200); // 2019-07-01, still before 2020
    let v = case.run("leaf-untimestamped.p7");
    assert!(v.clock_suspect);
    assert!(v.signatures[0].is_ok(), "{:#?}", v.signatures[0]);
    assert!(
        v.signatures[0]
            .warnings
            .contains(&ValidityWarning::NotYetValidClockSuspect)
    );
}

#[test]
fn sha1_timestamps_after_the_cutoff_are_not_trusted() {
    let mut case = Case::new(Y2026);
    assert!(case.run("leaf-rfc3161-sha1.p7").signatures[0].is_ok());
    case.policy.sha1_timestamp_cutoff = Some(Y2020_06);
    let v = case.run("leaf-rfc3161-sha1.p7");
    let sig = &v.signatures[0];
    assert_eq!(sig.timestamps[0].status, TimestampStatus::Sha1PastCutoff);
    assert_eq!(sig.trusted_timestamp, None);
    assert_eq!(sig.error, VerificationError::Sha1TimestampPastCutoff);
    assert_eq!(sig.error.code(), 20);
    // A cutoff after the time leaves it trusted.
    case.policy.sha1_timestamp_cutoff = Some(Y2021_06);
    assert!(case.run("leaf-rfc3161-sha1.p7").signatures[0].is_ok());
    // SHA-256 timestamps are not affected.
    case.policy.sha1_timestamp_cutoff = Some(Y2020_06);
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
}

#[test]
fn sign_time_after_and_requires_countersignature() {
    let mut case = Case::new(Y2021);
    case.policy.sign_time_after = Some(Y2020_06);
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
    // No timestamp: the constraint fails.
    assert_eq!(
        case.error("leaf-untimestamped.p7"),
        VerificationError::SigningTimeUntrusted
    );
    case.policy.sign_time_after = Some(Y2021_06);
    assert_eq!(
        case.error("leaf-rfc3161.p7"),
        VerificationError::SigningTimeUntrusted
    );

    let mut case = Case::new(Y2021);
    case.policy.requires_countersignature = true;
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
    assert!(case.run("leaf-legacy.p7").signatures[0].is_ok());
    let sig = &case.run("leaf-untimestamped.p7").signatures[0];
    assert_eq!(sig.error, VerificationError::CountersignatureRequired);
    assert_eq!(sig.error.code(), 1005);
    case.tsa = TrustConfig::new();
    assert_eq!(
        case.error("leaf-rfc3161.p7"),
        VerificationError::CountersignatureRequired
    );
}

#[test]
fn minimum_key_sizes() {
    let mut case = Case::new(Y2021);
    case.policy.min_rsa_bits = Some(2048);
    assert!(case.run("current-rfc3161.p7").signatures[0].is_ok());
    case.policy.min_rsa_bits = Some(3072);
    assert_eq!(
        case.error("current-rfc3161.p7"),
        VerificationError::KeyTooSmall
    );
}

// --- Revocation ----------------------------------------------------------

fn by_thumbprint(name: &str, at: Option<i64>, reason: RevocationReason) -> RevokedCertificate {
    let cert = palisade_fileid::authenticode::CertSummary::from_der(&bytes(name)).unwrap();
    RevokedCertificate {
        cert: CertificateMatch::Sha256Thumbprint(cert.sha256_thumbprint),
        revoked_at: at,
        reason,
        source: RevocationSource::Policy,
    }
}

#[test]
fn offline_revocation_by_thumbprint_and_by_tbs_hash() {
    let mut case = Case::new(Y2021);
    case.revocation.add_certificate(by_thumbprint(
        "current.der",
        None,
        RevocationReason::Unspecified,
    ));
    let sig = &case.run("current-rfc3161.p7").signatures[0];
    assert_eq!(sig.error, VerificationError::Revoked);
    assert_eq!(sig.error.code(), 4);
    assert!(sig.revocation[0].effective);

    let cert = palisade_fileid::authenticode::CertSummary::from_der(&bytes("current.der")).unwrap();
    for tbs in [cert.tbs_hash.clone().unwrap(), cert.tbs_hash_sha256.clone()] {
        let mut case = Case::new(Y2021);
        case.revocation.add_certificate(RevokedCertificate {
            cert: CertificateMatch::TbsHash(tbs),
            revoked_at: None,
            reason: RevocationReason::Unspecified,
            source: RevocationSource::OsDisallowedList,
        });
        assert_eq!(case.error("current-rfc3161.p7"), VerificationError::Revoked);
    }
    let mut case = Case::new(Y2021);
    case.revocation.add_certificate(RevokedCertificate {
        cert: CertificateMatch::IssuerSerial {
            issuer: cert.issuer.der.clone(),
            serial: cert.serial.clone(),
        },
        revoked_at: None,
        reason: RevocationReason::Unspecified,
        source: RevocationSource::Policy,
    });
    assert_eq!(case.error("current-rfc3161.p7"), VerificationError::Revoked);
    // The root, revoked: the whole chain is checked.
    let mut case = Case::new(Y2021);
    case.revocation.add_certificate(by_thumbprint(
        "root.der",
        None,
        RevocationReason::CaCompromise,
    ));
    assert_eq!(case.error("current-rfc3161.p7"), VerificationError::Revoked);
}

#[test]
fn revocation_after_the_signing_time_honours_the_timestamp() {
    let mut case = Case::new(Y2026);
    case.revocation.add_certificate(by_thumbprint(
        "leaf.der",
        Some(Y2021_06),
        RevocationReason::Superseded,
    ));
    let sig = &case.run("leaf-rfc3161.p7").signatures[0];
    assert!(sig.is_ok(), "{sig:#?}");
    assert!(
        sig.warnings
            .contains(&ValidityWarning::RevokedAfterSigning { position: 0 })
    );
    // Without a timestamp, it revokes.
    assert_eq!(
        Case {
            now: Y2021,
            ..case_with(&case)
        }
        .error("leaf-untimestamped.p7"),
        VerificationError::Revoked
    );
    // With the timing rule off, it revokes.
    case.policy.revocation_honours_timestamp = false;
    assert_eq!(case.error("leaf-rfc3161.p7"), VerificationError::Revoked);
}

fn case_with(other: &Case) -> Case {
    Case {
        policy: other.policy.clone(),
        revocation: other.revocation.clone(),
        tsa: tsa_trust(),
        now: other.now,
        floor: other.floor,
        digests: other.digests.clone(),
    }
}

#[test]
fn each_revocation_reason_after_signing() {
    for code in [0, 1, 2, 3, 4, 5, 6, 8, 9, 10] {
        let reason = RevocationReason::from_code(code).unwrap();
        for strict in [true, false] {
            let mut case = Case::new(Y2026);
            case.policy.strict_key_compromise = strict;
            case.revocation
                .add_certificate(by_thumbprint("leaf.der", Some(Y2021_06), reason));
            let expect = if strict && reason.is_compromise() {
                VerificationError::Revoked
            } else {
                VerificationError::Ok
            };
            assert_eq!(
                case.error("leaf-rfc3161.p7"),
                expect,
                "{reason:?} strict={strict}"
            );
        }
    }
}

#[test]
fn revocation_before_the_signing_time_always_revokes() {
    let mut case = Case::new(Y2026);
    case.revocation.add_certificate(by_thumbprint(
        "leaf.der",
        Some(Y2020_06),
        RevocationReason::Superseded,
    ));
    assert_eq!(case.error("leaf-rfc3161.p7"), VerificationError::Revoked);
}

#[test]
fn revoked_file_hashes_are_code_19() {
    let mut case = Case::new(Y2021);
    let digest = Digest::new(HashAlgorithm::Sha256, &[7; 32]).unwrap();
    case.revocation.add_file_hash(digest.clone());
    assert!(case.run("current-rfc3161.p7").signatures[0].is_ok());
    case.digests = vec![digest];
    let v = case.run("current-rfc3161.p7");
    assert!(v.file_revoked);
    assert_eq!(v.signatures[0].error, VerificationError::RevokedByHash);
    assert_eq!(v.signatures[0].error.code(), 19);
    assert_eq!(v.error, VerificationError::RevokedByHash);
}

#[test]
fn crls_are_parsed() {
    let c = crl("crl-leaf-compromise-after.der");
    assert_eq!(c.version, 2);
    assert_eq!(c.issuer.common_name(), Some("Palisade Timestamp Test Root"));
    assert_eq!(c.this_update, 1_704_067_200);
    assert_eq!(c.next_update, Some(2_019_686_400));
    assert_eq!(c.entries().len(), 1);
    assert_eq!(c.entries()[0].serial, "1001");
    assert_eq!(c.entries()[0].revocation_date, Y2021_06);
    assert_eq!(c.entries()[0].reason, RevocationReason::KeyCompromise);
    assert!(c.authority_key_id.is_some());
    assert_eq!(c.crl_number.as_deref(), Some("01"));
    assert!(crl("crl-empty.der").entries().is_empty());
}

#[test]
fn crl_entries_follow_the_same_rules() {
    // (CRL, whether it names the leaf as revoked, the verdict.)
    let cases = [
        ("crl-leaf-superseded-after.der", true, VerificationError::Ok),
        (
            "crl-leaf-compromise-after.der",
            true,
            VerificationError::Revoked,
        ),
        ("crl-leaf-before.der", true, VerificationError::Revoked),
        ("crl-empty.der", false, VerificationError::Ok),
        // Signed with another key under the root's name: never used.
        ("crl-forged.der", false, VerificationError::Ok),
    ];
    for (name, names_leaf, expect) in cases {
        let mut case = Case::new(Y2026);
        case.revocation.add_crl(crl(name)).unwrap();
        let v = case.run("leaf-rfc3161.p7");
        let sig = &v.signatures[0];
        assert_eq!(sig.error, expect, "{name}: {sig:#?}");
        let from_crl = sig.revocation.iter().any(|r| {
            r.state
                .parts()
                .0
                .iter()
                .any(|e| e.source == RevocationSource::Crl(0))
        });
        assert_eq!(from_crl, names_leaf, "{name}");
    }
    // Without the timestamp, a CRL entry dated after the claimed signing
    // time still revokes: the claim is not trusted.
    let mut case = Case::new(Y2021);
    case.revocation
        .add_crl(crl("crl-leaf-superseded-after.der"))
        .unwrap();
    assert_eq!(
        case.error("leaf-untimestamped.p7"),
        VerificationError::Revoked
    );
}

#[test]
fn a_forged_crl_cannot_revoke_and_cannot_vouch() {
    // The forged CRL does not cover the leaf, so with `OnlineRequired` the
    // leaf's state is still unknown.
    let mut case = Case::new(Y2026);
    case.revocation.mode = RevocationMode::OnlineRequired;
    case.revocation.failure = RevocationFailure::FailClosed;
    case.revocation.add_crl(crl("crl-forged.der")).unwrap();
    // The fixtures name no distribution point, so nothing needs an answer.
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
}

#[test]
fn tsa_revocation_drops_the_timestamp() {
    let mut case = Case::new(Y2026);
    case.revocation.add_crl(crl("crl-tsa-before.der")).unwrap();
    let v = case.run("leaf-rfc3161.p7");
    let sig = &v.signatures[0];
    assert_eq!(sig.timestamps[0].status, TimestampStatus::TsaRevoked);
    assert_eq!(sig.trusted_timestamp, None);
    // So the expired signer has no trusted time.
    assert_eq!(sig.error, VerificationError::SigningTimeUntrusted);
}

#[test]
fn unknown_revocation_fails_open_or_closed() {
    // The timestamp fixtures name no distribution point, so an unavailable
    // URL that no certificate names changes nothing.
    let mut case = Case::new(Y2021);
    case.revocation.mode = RevocationMode::Online;
    case.revocation.failure = RevocationFailure::FailClosed;
    case.revocation.unavailable_urls = vec!["http://crl.example.test/ca.crl".into()];
    assert!(case.run("current-rfc3161.p7").signatures[0].is_ok());
}

#[test]
fn revocation_unknown_with_a_distribution_point() {
    // A chain fixture that names a CRL distribution point and OCSP URL:
    // `leaf.der` from the chain fixtures is issued by `inter`, which `root`
    // issued.
    let chain_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain");
    let read = |n: &str| std::fs::read(format!("{chain_dir}/{n}.der")).unwrap();
    let leaf = palisade_fileid::authenticode::CertSummary::from_der(&read("leaf")).unwrap();
    assert!(!leaf.crl_distribution_points.is_empty());
    let mut config = TrustConfig::new();
    config.add_anchor("root", &read("root")).unwrap();
    let chain =
        palisade_fileid::authenticode::build_chain(&[read("leaf"), read("inter")], 0, &config)
            .unwrap();
    let certs: Vec<_> = chain.full_chain_certs().collect();
    let mut set = RevocationSet::new();
    assert_eq!(set.state_of(&certs, 0, Y2026), CertRevocation::Good);
    set.unavailable_urls = leaf.crl_distribution_points.clone();
    assert_eq!(set.state_of(&certs, 0, Y2026), CertRevocation::Unknown);
    let mut set = RevocationSet::new();
    set.mode = RevocationMode::OnlineRequired;
    assert_eq!(set.state_of(&certs, 0, Y2026), CertRevocation::Unknown);
    // The intermediate names none, so it needs no answer.
    assert_eq!(set.state_of(&certs, 1, Y2026), CertRevocation::Good);
}

// --- Per-certificate relaxations ------------------------------------------

#[test]
fn ignore_flags_relax_only_pinned_chains_and_are_recorded() {
    let leaf = palisade_fileid::authenticode::CertSummary::from_der(&bytes("leaf.der")).unwrap();
    let mut case = Case::new(Y2026);
    case.policy.certificate_options.push(CertificateOptions {
        label: "legacy vendor".into(),
        pin: CertificatePin::Sha256Thumbprint(leaf.sha256_thumbprint.clone()),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::IGNORE_EXPIRY),
    });
    let sig = &case.run("leaf-untimestamped.p7").signatures[0];
    assert!(sig.is_ok());
    assert_eq!(sig.relaxed.len(), 1);
    assert_eq!(sig.relaxed[0].flag, IgnoreFlag::IgnoreExpiry);
    assert_eq!(sig.relaxed[0].suppressed, VerificationError::Expired);
    // Another certificate's pin relaxes nothing here.
    let lifetime =
        palisade_fileid::authenticode::CertSummary::from_der(&bytes("lifetime.der")).unwrap();
    case.policy.certificate_options[0].pin = CertificatePin::TbsHash(lifetime.tbs_hash_sha256);
    assert_eq!(
        case.error("leaf-untimestamped.p7"),
        VerificationError::Expired
    );
    // A flag that does not apply relaxes nothing.
    case.policy.certificate_options[0] = CertificateOptions {
        label: "x".into(),
        pin: CertificatePin::Sha256Thumbprint(leaf.sha256_thumbprint),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::IGNORE_REVOCATION_UNKNOWN),
    };
    assert_eq!(
        case.error("leaf-untimestamped.p7"),
        VerificationError::Expired
    );
}

#[test]
fn allow_untrusted_root_needs_the_pin_on_the_chain() {
    let report = report_of(&bytes("current-rfc3161.p7"));
    let trust = evaluate_trust(&report, &TrustConfig::new(), None);
    assert!(!trust.signers[0].trusted);
    let root = palisade_fileid::authenticode::CertSummary::from_der(&bytes("root.der")).unwrap();
    let mut policy = ValidityPolicy::default();
    let revocation = RevocationSet::new();
    let tsa = tsa_trust();
    let ctx = |policy: &ValidityPolicy| {
        let ctx = ValidityContext {
            now: Y2021,
            clock_floor: None,
            policy,
            revocation: &revocation,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx)
    };
    // The root is embedded and self-signed, so the chain is complete but
    // anchored to nothing.
    assert_eq!(
        ctx(&policy).signatures[0].error,
        VerificationError::UntrustedRoot
    );
    assert_eq!(VerificationError::UntrustedRoot.code(), 7);
    policy.certificate_options.push(CertificateOptions {
        label: "lab root".into(),
        pin: CertificatePin::Sha256Thumbprint(root.sha256_thumbprint),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::ALLOW_UNTRUSTED_ROOT),
    });
    let v = ctx(&policy);
    assert!(v.signatures[0].is_ok(), "{:#?}", v.signatures[0]);
    assert_eq!(
        v.signatures[0].relaxed[0].flag,
        IgnoreFlag::AllowUntrustedRoot
    );
    assert_eq!(v.primary, Some(0));
}

// --- The taxonomy ----------------------------------------------------------

#[test]
fn every_signature_status_maps_to_a_code() {
    use palisade_fileid::authenticode::{BadSignature, SignatureStatus, status_error};
    assert_eq!(status_error(&SignatureStatus::Valid), None);
    assert_eq!(
        status_error(&SignatureStatus::DigestMismatch),
        Some(VerificationError::InvalidHash)
    );
    assert_eq!(
        status_error(&SignatureStatus::BadSignature(
            BadSignature::SignatureInvalid
        )),
        Some(VerificationError::Generic)
    );
    assert_eq!(
        status_error(&SignatureStatus::BadSignature(
            BadSignature::MessageDigestMismatch
        )),
        Some(VerificationError::DigestMismatch)
    );
    assert_eq!(
        status_error(&SignatureStatus::WeakAlgorithm(
            palisade_fileid::authenticode::DigestAlgorithm::Md5
        )),
        Some(VerificationError::WeakHashAlgorithm)
    );
}

#[test]
fn ecc_signers_are_code_23_for_os_rules_only() {
    // An ECC signature verifies here; the OS reports ECC as 23. Make sure
    // the code exists with that number for the #58 decoder.
    assert_eq!(VerificationError::UnsupportedKeyAlgorithm.code(), 23);
    assert_eq!(
        VerificationError::from_code(23),
        Some(VerificationError::UnsupportedKeyAlgorithm)
    );
}

#[test]
fn unsigned_and_invalid_files() {
    let image = PeBuilder::default().build();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    let trust = evaluate_trust(&report, &code_trust(), None);
    let case = Case::new(Y2021);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.error, VerificationError::NotSigned);
    assert_eq!(v.error.code(), 3);
    // A signature over another file.
    let mut blob = bytes("current-rfc3161.p7");
    let report = {
        let image = PeBuilder {
            certificate: Some(entry(&blob)),
            sections: vec![SectionSpec {
                name: *b".other\0\0",
                data: vec![1; 16],
                virtual_size: None,
                characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
            }],
            ..PeBuilder::default()
        }
        .build();
        verify_pe(&image, &VerifyOptions::default()).unwrap()
    };
    let trust = evaluate_trust(&report, &code_trust(), None);
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.signatures[0].error, VerificationError::InvalidHash);
    assert_eq!(v.error, VerificationError::InvalidHash);
    // Garbage in the table.
    blob.truncate(30);
    let report = report_of(&blob);
    let trust = evaluate_trust(&report, &code_trust(), None);
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.error, VerificationError::MalformedSignature);
}

#[test]
fn untrusted_signers_never_become_primary() {
    let report = report_of(&bytes("current-rfc3161.p7"));
    let trust = evaluate_trust(&report, &TrustConfig::new(), None);
    let case = Case::new(Y2021);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.primary, None);
    assert!(v.identity.is_none());
}

#[test]
fn reports_serialise() {
    let v = Case::new(Y2026).run("leaf-rfc3161.p7");
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["error"], "ok");
    assert_eq!(json["signatures"][0]["validity"], "valid_timestamped");
    assert_eq!(json["signatures"][0]["timestamps"][0]["status"], "valid");
    let v = Case::new(Y2026).run("leaf-untimestamped.p7");
    assert_eq!(serde_json::to_value(&v).unwrap()["error"], "expired");
}

// --- Untrusted input --------------------------------------------------------

#[test]
fn crl_negative_cases() {
    let good = bytes("crl-empty.der");
    // Truncated.
    for len in [0, 1, 10, good.len() - 1] {
        assert!(Crl::from_der(&good[..len]).is_err());
    }
    // Trailing data.
    let mut long = good.clone();
    long.push(0);
    assert!(Crl::from_der(&long).is_err());
    // Change the outer signature algorithm OID's last byte: the two
    // algorithm fields no longer agree.
    let alg = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let last = good.windows(alg.len()).rposition(|w| w == alg).unwrap();
    let mut changed = good.clone();
    changed[last + alg.len() - 1] = 0x0c;
    assert_eq!(
        Crl::from_der(&changed).unwrap_err(),
        CrlError::SignatureAlgorithmMismatch
    );
}

#[test]
fn timestamp_time_parser_handles_garbage() {
    assert_eq!(parse_timestamp_time(TimestampKind::Rfc3161, &[]), None);
    assert_eq!(
        parse_timestamp_time(TimestampKind::CounterSignature, &[0x30, 0x00]),
        None
    );
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    assert_eq!(
        parse_timestamp_time(
            TimestampKind::Rfc3161,
            &report.signatures[0].timestamp_tokens[0].der
        ),
        Some(Y2021)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn mutated_tokens_never_panic_or_validate_wrongly(
        index in 0_usize..6000,
        value in any::<u8>(),
    ) {
        let report = report_of(&bytes("leaf-rfc3161.p7"));
        let mut sig = report.signatures[0].clone();
        let der = &mut sig.timestamp_tokens[0].der;
        let at = index % der.len();
        let unchanged = der[at] == value;
        der[at] = value;
        let ts = &verify_timestamps(&sig, &tsa_trust())[0];
        // A byte of a certificate's own signature, or an unread
        // unauthenticated part, may change without effect; a valid result
        // must still carry the genuine time.
        if ts.valid && !unchanged {
            prop_assert_eq!(ts.time, Some(Y2021));
        }
        prop_assert_eq!(ts.valid, ts.status == TimestampStatus::Valid);
    }

    #[test]
    fn mutated_crls_never_panic(index in 0_usize..600, value in any::<u8>()) {
        let mut der = bytes("crl-leaf-compromise-after.der");
        let at = index % der.len();
        der[at] = value;
        let _ = Crl::from_der(&der);
    }

    #[test]
    fn mutated_legacy_countersignatures_never_panic(index in 0_usize..6000, value in any::<u8>()) {
        let report = report_of(&bytes("leaf-legacy.p7"));
        let mut sig = report.signatures[0].clone();
        let der = &mut sig.timestamp_tokens[0].der;
        let at = index % der.len();
        der[at] = value;
        let ts = &verify_timestamps(&sig, &tsa_trust())[0];
        prop_assert_eq!(ts.valid, ts.status == TimestampStatus::Valid);
    }
}

#[test]
fn timestamps_and_crls_beyond_the_limits() {
    use palisade_fileid::authenticode::{MAX_CRLS, MAX_FILE_TIMESTAMPS};
    let mut set = RevocationSet::new();
    let c = crl("crl-empty.der");
    for _ in 0..MAX_CRLS {
        assert!(set.add_crl(c.clone()).is_some());
    }
    assert!(set.add_crl(c).is_none());
    // A file whose signatures carry more timestamps than the file budget:
    // the rest are not checked, never valid.
    let mut report = report_of(&bytes("leaf-rfc3161.p7"));
    let token = report.signatures[0].timestamp_tokens[0].clone();
    report.signatures[0].timestamp_tokens = vec![token; MAX_FILE_TIMESTAMPS + 3];
    let trust = evaluate_trust(&report, &code_trust(), None);
    let case = Case::new(Y2021);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    let ts = &v.signatures[0].timestamps;
    assert_eq!(ts.len(), MAX_FILE_TIMESTAMPS + 3);
    assert!(ts[..MAX_FILE_TIMESTAMPS].iter().all(|t| t.valid));
    assert!(
        ts[MAX_FILE_TIMESTAMPS..]
            .iter()
            .all(|t| t.status == TimestampStatus::NotChecked && !t.valid)
    );
}

/// Writes fuzz seeds for `timestamp_crl`: each fixture token and CRL with
/// its selector byte.
///
/// ```sh
/// PALISADE_FUZZ_SEED_DIR="$PWD/fuzz/corpus/timestamp_crl" \
///     cargo test -p palisade-fileid --test validity -- --ignored write_timestamp_fuzz_seeds
/// ```
#[test]
#[ignore = "writes files; run on demand to seed the fuzz corpus"]
fn write_timestamp_fuzz_seeds() {
    let dir = std::env::var_os("PALISADE_FUZZ_SEED_DIR").expect("set PALISADE_FUZZ_SEED_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let dir = std::path::PathBuf::from(dir);
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    for (selector, name) in [
        (0_u8, "leaf-rfc3161.p7"),
        (0, "leaf-rfc3161-sha1.p7"),
        (1, "leaf-legacy.p7"),
    ] {
        let report = report_of(&bytes(name));
        let mut seed = vec![selector];
        seed.extend_from_slice(&report.signatures[0].timestamp_tokens[0].der);
        seeds.push((format!("ts-{name}"), seed));
    }
    for name in [
        "crl-leaf-superseded-after.der",
        "crl-leaf-compromise-after.der",
        "crl-empty.der",
        "crl-forged.der",
    ] {
        let mut seed = vec![2_u8];
        seed.extend_from_slice(&bytes(name));
        seeds.push((name.to_owned(), seed));
    }
    for (name, seed) in seeds {
        std::fs::write(dir.join(name), seed).unwrap();
    }
}

#[test]
fn only_a_current_crl_shows_a_certificate_is_good() {
    // The CRLs run from 2024 to 2034.
    let empty = crl("crl-empty.der");
    assert!(empty.is_current(Y2026));
    assert!(!empty.is_current(Y2023));
    assert!(!empty.is_current(2_051_222_400)); // 2035
    let leaf = palisade_fileid::authenticode::CertSummary::from_der(&bytes("leaf.der")).unwrap();
    let root = palisade_fileid::authenticode::CertSummary::from_der(&bytes("root.der")).unwrap();
    let chain = [&leaf, &root];
    // An entry in a stale CRL still revokes.
    let mut set = RevocationSet::new();
    set.add_crl(crl("crl-leaf-before.der")).unwrap();
    for now in [Y2023, Y2026, 2_051_222_400] {
        assert!(matches!(
            set.state_of(&chain, 0, now),
            CertRevocation::Revoked { .. }
        ));
    }
    // A stale CRL that lists nothing is not an answer: with an unavailable
    // URL on record for the certificate, the state stays unknown. (The
    // fixture names no URL, so mark one on a copy of it.)
    let mut named = leaf.clone();
    named.crl_distribution_points = vec!["http://crl.example.test/root.crl".into()];
    let chain = [&named, &root];
    let mut set = RevocationSet::new();
    set.unavailable_urls = named.crl_distribution_points.clone();
    set.add_crl(empty).unwrap();
    assert_eq!(set.state_of(&chain, 0, Y2026), CertRevocation::Good);
    assert_eq!(set.state_of(&chain, 0, Y2023), CertRevocation::Unknown);
}

#[test]
fn a_signature_without_a_trust_verdict_never_passes() {
    let report = report_of(&bytes("current-rfc3161.p7"));
    let mut trust = evaluate_trust(&report, &code_trust(), None);
    // A trust report from another file: no entry for this signature.
    trust.signers.clear();
    let case = Case::new(Y2021);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert!(!v.signatures[0].is_ok());
    assert_eq!(v.primary, None);
}

#[test]
fn every_entry_for_a_serial_is_judged() {
    // The leaf is listed twice: certificateHold on 2021-06-01, then
    // keyCompromise on 2021-09-01. Both are after the 2021-01-01 timestamp;
    // the hold alone would be honoured, but the compromise must not hide
    // behind it.
    let c = crl("crl-leaf-twice.der");
    let entries: Vec<_> = c.entries_for("1001").collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].reason, RevocationReason::CertificateHold);
    assert_eq!(entries[1].reason, RevocationReason::KeyCompromise);
    assert_eq!(c.entries_for("1001".to_uppercase().as_str()).count(), 2);
    assert_eq!(c.entries_for("1002").count(), 0);
    let mut case = Case::new(Y2026);
    case.revocation.add_crl(c).unwrap();
    assert_eq!(case.error("leaf-rfc3161.p7"), VerificationError::Revoked);
    case.policy.strict_key_compromise = false;
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());

    // The same with offline entries: an earlier mild one and a later
    // compromise.
    let mut case = Case::new(Y2026);
    case.revocation.add_certificate(by_thumbprint(
        "leaf.der",
        Some(Y2021_06),
        RevocationReason::Superseded,
    ));
    case.revocation.add_certificate(by_thumbprint(
        "leaf.der",
        Some(Y2021_06),
        RevocationReason::KeyCompromise,
    ));
    assert_eq!(case.error("leaf-rfc3161.p7"), VerificationError::Revoked);
}

#[test]
fn hex_matches_ignore_case() {
    let cert = palisade_fileid::authenticode::CertSummary::from_der(&bytes("current.der")).unwrap();
    let mut case = Case::new(Y2021);
    case.revocation.add_certificate(RevokedCertificate {
        cert: CertificateMatch::Sha256Thumbprint(cert.sha256_thumbprint.to_uppercase()),
        revoked_at: None,
        reason: RevocationReason::Unspecified,
        source: RevocationSource::OsDisallowedList,
    });
    assert_eq!(case.error("current-rfc3161.p7"), VerificationError::Revoked);
    let mut case = Case::new(Y2021);
    case.revocation.add_certificate(RevokedCertificate {
        cert: CertificateMatch::TbsHash(cert.tbs_hash_sha256.to_uppercase()),
        revoked_at: None,
        reason: RevocationReason::Unspecified,
        source: RevocationSource::Policy,
    });
    assert_eq!(case.error("current-rfc3161.p7"), VerificationError::Revoked);
    assert!(CertificatePin::TbsHash(cert.tbs_hash_sha256.to_uppercase()).matches(&cert));
}

#[test]
fn invalidity_date_counts_when_earlier() {
    let e = palisade_fileid::authenticode::CrlEntry {
        serial: "1001".into(),
        revocation_date: Y2021_06,
        reason: RevocationReason::KeyCompromise,
        invalidity_date: Some(Y2020_06),
    };
    assert_eq!(e.effective_date(), Y2020_06);
    let later = palisade_fileid::authenticode::CrlEntry {
        invalidity_date: Some(Y2023),
        ..e
    };
    assert_eq!(later.effective_date(), Y2021_06);
}

#[test]
fn an_expired_intermediate_is_judged_like_an_expired_leaf() {
    // From the chain fixtures: `inter-expired` was valid 2001 to 2002, and
    // `leaf-expired-ca` under it from 2026 on. The chain is anchored, but
    // without a trusted time the intermediate's expiry fails it. The
    // signature itself comes from another fixture; only its chain is
    // swapped, which is all `evaluate_validity` reads.
    let chain_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain");
    let read = |n: &str| std::fs::read(format!("{chain_dir}/{n}.der")).unwrap();
    let mut config = TrustConfig::new();
    config.add_anchor("root", &read("root")).unwrap();
    let chain = palisade_fileid::authenticode::build_chain(
        &[read("leaf-expired-ca"), read("inter-expired")],
        0,
        &config,
    )
    .unwrap();
    assert!(chain.full_chain.anchored);
    let report = report_of(&bytes("leaf-untimestamped.p7"));
    let mut trust = evaluate_trust(&report, &code_trust(), None);
    trust.signers[0].chain = Some(chain);
    let case = Case::new(Y2026);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.signatures[0].validity, Some(TimeValidity::Expired));
    assert_eq!(v.signatures[0].error, VerificationError::Expired);
}

#[test]
fn the_standard_timestamp_token_attribute_is_collected() {
    let report = report_of(&bytes("leaf-rfc3161-aa.p7"));
    let sig = &report.signatures[0];
    assert!(sig.status.is_valid());
    assert_eq!(sig.timestamp_tokens[0].kind, TimestampKind::Rfc3161);
    assert!(verify_timestamps(sig, &tsa_trust())[0].valid);
    assert!(Case::new(Y2026).run("leaf-rfc3161-aa.p7").signatures[0].is_ok());
}

#[test]
fn the_ess_signing_certificate_binds_the_tsa_certificate() {
    // `tsa-reissued` has the TSA's key, issuer and serial, so it matches
    // the token's signer identifier and the token's signature verifies with
    // it; only the ESS signingCertificate hash tells it apart.
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    let mut sig = report.signatures[0].clone();
    let original = bytes("tsa.der");
    let reissued = bytes("tsa-reissued.der");
    assert_eq!(original.len(), reissued.len());
    let token = &mut sig.timestamp_tokens[0].der;
    let at = find(token, &original);
    token[at..at + original.len()].copy_from_slice(&reissued);
    let ts = &verify_timestamps(&sig, &tsa_trust())[0];
    assert_eq!(ts.status, TimestampStatus::SigningCertificateMismatch);
}

#[test]
fn allow_untrusted_root_never_excuses_an_incomplete_chain() {
    // The embedded root removed: the chain stops at the leaf, which is not
    // self-signed. Pinning the leaf with every flag must not make it pass.
    let report = report_of(&bytes("current-rfc3161.p7"));
    let mut sig = report.signatures[0].clone();
    let root = bytes("root.der");
    sig.certs_in_blob.retain(|c| *c != root);
    let leaf_der = bytes("current.der");
    sig.signer.as_mut().unwrap().signer_cert = sig
        .certs_in_blob
        .iter()
        .position(|c| *c == leaf_der)
        .unwrap();
    let mut report = report.clone();
    report.signatures[0] = sig;
    let trust = evaluate_trust(&report, &TrustConfig::new(), None);
    let leaf = palisade_fileid::authenticode::CertSummary::from_der(&bytes("current.der")).unwrap();
    let mut policy = ValidityPolicy::default();
    policy.certificate_options.push(CertificateOptions {
        label: "pinned leaf".into(),
        pin: CertificatePin::Sha256Thumbprint(leaf.sha256_thumbprint),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::ALL),
    });
    let revocation = RevocationSet::new();
    let tsa = tsa_trust();
    let ctx = ValidityContext {
        now: Y2021,
        clock_floor: None,
        policy: &policy,
        revocation: &revocation,
        tsa_trust: &tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.signatures[0].error, VerificationError::ChainIncomplete);
    assert!(v.signatures[0].relaxed.is_empty());
    assert_eq!(v.primary, None);
}

#[test]
fn a_pinned_leaf_anchor_still_has_its_own_validity_checked() {
    // A self-signed signer configured as its own anchor (chain fixtures,
    // valid for ten years from generation): judged after it expires, with
    // no timestamp, it is expired.
    let chain_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain");
    let read = |n: &str| std::fs::read(format!("{chain_dir}/{n}.der")).unwrap();
    let pinned = read("leaf-self-signed");
    let cert = palisade_fileid::authenticode::CertSummary::from_der(&pinned).unwrap();
    let mut config = TrustConfig::new();
    config.add_anchor("pinned", &pinned).unwrap();
    let chain = palisade_fileid::authenticode::build_chain(&[pinned], 0, &config).unwrap();
    assert!(chain.full_chain.anchored);
    assert_eq!(chain.full_chain.certs.len(), 1);
    let report = report_of(&bytes("leaf-untimestamped.p7"));
    let mut trust = evaluate_trust(&report, &code_trust(), None);
    trust.signers[0].chain = Some(chain);
    let run = |now: i64, expiry: ExpiryPolicy| {
        let policy = ValidityPolicy {
            expiry_policy: expiry,
            ..ValidityPolicy::default()
        };
        let revocation = RevocationSet::new();
        let tsa = tsa_trust();
        let ctx = ValidityContext {
            now,
            clock_floor: None,
            policy: &policy,
            revocation: &revocation,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx).signatures[0].clone()
    };
    let inside = run(cert.not_before + 1, ExpiryPolicy::TimestampAware);
    assert_eq!(inside.validity, Some(TimeValidity::Valid));
    for policy in [ExpiryPolicy::TimestampAware, ExpiryPolicy::Strict] {
        let after = run(cert.not_after + 1, policy);
        assert_eq!(after.validity, Some(TimeValidity::Expired), "{policy:?}");
        assert_eq!(after.error, VerificationError::Expired);
    }
}

#[test]
fn crl_signature_checks_are_bounded() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    // More CRLs from the leaf's issuer than the per-file budget: the leaf's
    // state cannot be fully known, so it fails closed.
    let mut case = Case::new(Y2026);
    for _ in 0..MAX_CRL_CHECKS {
        case.revocation.add_crl(crl("crl-empty.der")).unwrap();
    }
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
    case.revocation.add_crl(crl("crl-empty.der")).unwrap();
    let sig = &case.run("leaf-rfc3161.p7").signatures[0];
    assert_eq!(sig.error, VerificationError::RevocationUnavailable);
    assert!(
        sig.revocation
            .iter()
            .any(|r| r.state.parts().1 == Coverage::NotChecked)
    );
}

#[test]
fn crls_for_untrusted_chains_are_not_checked() {
    // An unanchored chain has already failed; its CRLs cost nothing.
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    let trust = evaluate_trust(&report, &TrustConfig::new(), None);
    let mut case = Case::new(Y2026);
    case.revocation.add_crl(crl("crl-leaf-before.der")).unwrap();
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(v.signatures[0].error, VerificationError::UntrustedRoot);
    assert!(v.signatures[0].revocation.is_empty());
}

#[test]
fn ignore_invalid_usage_relaxes_eku_failures_only_for_the_pin() {
    use palisade_fileid::authenticode::UntrustedReason;
    let report = report_of(&bytes("current-rfc3161.p7"));
    let mut trust = evaluate_trust(&report, &code_trust(), None);
    trust.signers[0].untrusted = vec![UntrustedReason::CodeSigningNotPermitted];
    trust.signers[0].trusted = false;
    let leaf = palisade_fileid::authenticode::CertSummary::from_der(&bytes("current.der")).unwrap();
    let mut policy = ValidityPolicy::default();
    let revocation = RevocationSet::new();
    let tsa = tsa_trust();
    let eval = |policy: &ValidityPolicy| {
        let ctx = ValidityContext {
            now: Y2021,
            clock_floor: None,
            policy,
            revocation: &revocation,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        evaluate_validity(&report, &trust, &ctx).signatures[0].clone()
    };
    assert_eq!(eval(&policy).error, VerificationError::MissingRequiredEku);
    policy.certificate_options.push(CertificateOptions {
        label: "x".into(),
        pin: CertificatePin::Sha256Thumbprint(leaf.sha256_thumbprint),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::IGNORE_INVALID_USAGE),
    });
    let sig = eval(&policy);
    assert!(sig.is_ok());
    assert_eq!(sig.relaxed[0].flag, IgnoreFlag::IgnoreInvalidUsage);
    assert_eq!(
        sig.relaxed[0].suppressed,
        VerificationError::MissingRequiredEku
    );
}

#[test]
fn a_hash_revoked_file_with_a_broken_table_is_code_19() {
    let mut blob = bytes("current-rfc3161.p7");
    blob.truncate(30);
    let image = PeBuilder {
        certificate: Some(vec![1, 0, 0, 0]),
        ..PeBuilder::default()
    }
    .build();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    assert!(report.signatures.is_empty());
    let trust = evaluate_trust(&report, &code_trust(), None);
    let mut case = Case::new(Y2021);
    let digest = Digest::new(HashAlgorithm::Sha256, &[9; 32]).unwrap();
    case.revocation.add_file_hash(digest.clone());
    case.digests = vec![digest];
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &case.digests,
        version: None,
    };
    assert_eq!(
        evaluate_validity(&report, &trust, &ctx).error,
        VerificationError::RevokedByHash
    );
}

#[test]
fn an_excused_entry_never_hides_missing_coverage() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    // An offline `superseded` entry after the signing time is excused by
    // the timestamp; that must not stand in for CRLs that were not
    // checked.
    let mut case = Case::new(Y2026);
    case.revocation.add_certificate(by_thumbprint(
        "leaf.der",
        Some(Y2021_06),
        RevocationReason::Superseded,
    ));
    assert!(case.run("leaf-rfc3161.p7").signatures[0].is_ok());
    for _ in 0..=MAX_CRL_CHECKS {
        case.revocation.add_crl(crl("crl-empty.der")).unwrap();
    }
    let sig = &case.run("leaf-rfc3161.p7").signatures[0];
    assert_eq!(sig.error, VerificationError::RevocationUnavailable);

    // Nor for an answer that is missing under `FailClosed`. Give the leaf a
    // distribution point the caller could not fetch, by swapping the chain.
    let report = report_of(&bytes("leaf-rfc3161.p7"));
    let mut trust = evaluate_trust(&report, &code_trust(), None);
    let chain = trust.signers[0].chain.as_mut().unwrap();
    let leaf = chain.leaf;
    let url = "http://crl.example.test/root.crl".to_owned();
    chain.certificates[leaf].cert.crl_distribution_points = vec![url.clone()];
    for failure in [RevocationFailure::FailOpen, RevocationFailure::FailClosed] {
        let mut revocation = RevocationSet::new();
        revocation.failure = failure;
        revocation.unavailable_urls = vec![url.clone()];
        revocation.add_certificate(by_thumbprint(
            "leaf.der",
            Some(Y2021_06),
            RevocationReason::Superseded,
        ));
        let policy = ValidityPolicy::default();
        let tsa = tsa_trust();
        let ctx = ValidityContext {
            now: Y2026,
            clock_floor: None,
            policy: &policy,
            revocation: &revocation,
            tsa_trust: &tsa,
            file_digests: &[],
            version: None,
        };
        let sig = evaluate_validity(&report, &trust, &ctx).signatures[0].clone();
        match failure {
            RevocationFailure::FailClosed => {
                assert_eq!(sig.error, VerificationError::RevocationUnavailable);
            }
            RevocationFailure::FailOpen => {
                assert!(sig.is_ok());
                assert!(
                    sig.warnings
                        .contains(&ValidityWarning::RevocationUnknown { position: 0 })
                );
            }
        }
    }
}

#[test]
fn an_excused_tsa_entry_never_hides_missing_coverage() {
    use palisade_fileid::authenticode::MAX_CRL_CHECKS;
    // The TSA certificate has an offline entry dated after the timestamp,
    // which alone is excused. With more TSA-root CRLs than can be checked
    // (each one listing nothing for the TSA would be fine, but they cannot
    // all be verified), the timestamp is not used.
    let mut case = Case::new(Y2026);
    case.revocation.add_certificate(by_thumbprint(
        "tsa.der",
        Some(Y2023),
        RevocationReason::Superseded,
    ));
    let sig = &case.run("current-rfc3161.p7").signatures[0];
    assert!(sig.timestamps[0].valid, "{sig:#?}");
    // Current CRLs from the TSA root that list nothing: one more than the
    // per-file CRL budget can check.
    for _ in 0..=MAX_CRL_CHECKS {
        case.revocation.add_crl(crl("crl-tsa-empty.der")).unwrap();
    }
    let sig = &case.run("current-rfc3161.p7").signatures[0];
    assert_eq!(
        sig.timestamps[0].status,
        TimestampStatus::TsaRevocationUnknown,
        "{sig:#?}"
    );
    assert_eq!(sig.trusted_timestamp, None);
}

#[test]
fn constraints_are_not_reported_on_signatures_that_already_failed() {
    let mut case = Case::new(Y2021);
    case.policy.requires_countersignature = true;
    case.policy.sign_time_after = Some(Y2020_06);
    let blob = bytes("current-rfc3161.p7");
    let image = PeBuilder {
        certificate: Some(entry(&blob)),
        sections: vec![SectionSpec {
            name: *b".other\0\0",
            data: vec![1; 16],
            virtual_size: None,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        }],
        ..PeBuilder::default()
    }
    .build();
    let report = verify_pe(&image, &VerifyOptions::default()).unwrap();
    let trust = evaluate_trust(&report, &code_trust(), None);
    let ctx = ValidityContext {
        now: case.now,
        clock_floor: None,
        policy: &case.policy,
        revocation: &case.revocation,
        tsa_trust: &case.tsa,
        file_digests: &[],
        version: None,
    };
    let v = evaluate_validity(&report, &trust, &ctx);
    assert_eq!(
        v.signatures[0].failures,
        vec![VerificationError::InvalidHash]
    );
}

// --- Chain-building relaxations (#49) ------------------------------------

const CHAIN_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chain");

fn chain_der(name: &str) -> Vec<u8> {
    std::fs::read(format!("{CHAIN_FIXTURES}/{name}.der")).unwrap()
}

/// A full verdict for a synthetic signature whose embedded chain is
/// `names` (leaf first), anchored at the chain fixtures' root under
/// `trust`. The trust entry is built from the chain, so these tests judge
/// chain shape alone.
fn judge_chain(
    names: &[&str],
    trust: &TrustConfig,
    policy: &ValidityPolicy,
    now: i64,
) -> palisade_fileid::authenticode::SignatureValidity {
    let certs: Vec<Vec<u8>> = names.iter().map(|n| chain_der(n)).collect();
    let chain = palisade_fileid::authenticode::build_chain(&certs, 0, trust).unwrap();
    // Any valid signature carries the verdict; its own chain is replaced.
    let report = report_of(&bytes("leaf-untimestamped.p7"));
    let mut t = evaluate_trust(&report, &code_trust(), None);
    // The verdict as `evaluate_trust` would give it for this chain.
    let signer = &mut t.signers[0];
    signer.untrusted.clear();
    if !chain.full_chain.anchored {
        signer.untrusted.push(UntrustedReason::NoTrustAnchor);
    }
    if !chain.permits_code_signing() {
        signer
            .untrusted
            .push(UntrustedReason::CodeSigningNotPermitted);
    }
    signer.trusted = signer.untrusted.is_empty();
    signer.chain = Some(chain);
    let revocation = RevocationSet::new();
    let tsa = tsa_trust();
    let ctx = ValidityContext {
        now,
        clock_floor: None,
        policy,
        revocation: &revocation,
        tsa_trust: &tsa,
        file_digests: &[],
        version: None,
    };
    evaluate_validity(&report, &t, &ctx).signatures[0].clone()
}

fn chain_root_trust() -> TrustConfig {
    let mut t = TrustConfig::new();
    t.add_anchor("chain root", &chain_der("root")).unwrap();
    t
}

/// 2030, inside every chain fixture's validity except `inter-expired`.
const Y2030: i64 = 1_893_456_000;

#[test]
fn ignore_basic_constraints_needs_an_option_naming_the_issuer() {
    let names = ["leaf-under-not-ca", "inter-not-ca", "root"];
    let inter =
        palisade_fileid::authenticode::CertSummary::from_der(&chain_der("inter-not-ca")).unwrap();
    let option = CertificateOptions {
        label: "legacy CA".into(),
        pin: CertificatePin::Sha256Thumbprint(inter.sha256_thumbprint.clone()),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::IGNORE_BASIC_CONSTRAINTS),
    };
    // Without the option, chain building refuses the non-CA: untrusted.
    let strict = judge_chain(
        &names,
        &chain_root_trust(),
        &ValidityPolicy::default(),
        Y2030,
    );
    assert_eq!(strict.error, VerificationError::ChainIncomplete);
    // With it, `relax_trust` passes it to chain building, the chain
    // anchors, and the relaxation is recorded.
    let mut policy = ValidityPolicy::default();
    policy.certificate_options.push(option.clone());
    let mut trust = chain_root_trust();
    policy.relax_trust(&mut trust);
    let v = judge_chain(&names, &trust, &policy, Y2030);
    assert!(v.is_ok(), "{v:#?}");
    assert_eq!(
        v.relaxed,
        [RelaxedCheck {
            flag: IgnoreFlag::IgnoreBasicConstraints,
            option: 0,
            suppressed: VerificationError::BasicConstraintsViolated,
        }]
    );
    // A trust configuration relaxed by someone else, with no option that
    // allows it, fails with code 1008.
    let v = judge_chain(&names, &trust, &ValidityPolicy::default(), Y2030);
    assert_eq!(v.error, VerificationError::BasicConstraintsViolated);
    assert_eq!(VerificationError::BasicConstraintsViolated.code(), 1008);
    // An option naming another certificate does not allow it either.
    let mut other = ValidityPolicy::default();
    other.certificate_options.push(CertificateOptions {
        pin: CertificatePin::Sha256Thumbprint(
            palisade_fileid::authenticode::CertSummary::from_der(&chain_der("root"))
                .unwrap()
                .sha256_thumbprint,
        ),
        ..option
    });
    let v = judge_chain(&names, &trust, &other, Y2030);
    assert_eq!(v.error, VerificationError::BasicConstraintsViolated);
}

#[test]
fn time_nesting_is_required_only_when_policy_says() {
    // `inter-expired` was valid in 2001 only, so the leaf it issued is not
    // time nested. Expiry is ignored here to isolate nesting.
    let names = ["leaf-expired-ca", "inter-expired", "root"];
    let mut policy = ValidityPolicy {
        expiry_policy: ExpiryPolicy::Ignore,
        ..ValidityPolicy::default()
    };
    let v = judge_chain(&names, &chain_root_trust(), &policy, Y2030);
    assert!(v.is_ok(), "{v:#?}");
    policy.require_time_nesting = true;
    let v = judge_chain(&names, &chain_root_trust(), &policy, Y2030);
    assert_eq!(v.error, VerificationError::TimeNotNested);
    assert_eq!(VerificationError::TimeNotNested.code(), 1007);
    // A nested chain passes.
    let v = judge_chain(
        &["leaf", "inter", "root"],
        &chain_root_trust(),
        &policy,
        Y2030,
    );
    assert!(v.is_ok(), "{v:#?}");
    // The flag on a certificate of the chain excuses it, and is recorded.
    let inter =
        palisade_fileid::authenticode::CertSummary::from_der(&chain_der("inter-expired")).unwrap();
    policy.certificate_options.push(CertificateOptions {
        label: "old CA".into(),
        pin: CertificatePin::TbsHash(inter.tbs_hash_sha256),
        flags: ErrorIgnoreFlags(ErrorIgnoreFlags::IGNORE_TIME_NESTING),
    });
    let v = judge_chain(&names, &chain_root_trust(), &policy, Y2030);
    assert!(v.is_ok(), "{v:#?}");
    assert_eq!(v.relaxed[0].flag, IgnoreFlag::IgnoreTimeNesting);
    assert_eq!(v.relaxed[0].suppressed, VerificationError::TimeNotNested);
}

#[test]
fn every_flag_has_a_bit() {
    let flags = [
        (IgnoreFlag::IgnoreExpiry, ErrorIgnoreFlags::IGNORE_EXPIRY),
        (
            IgnoreFlag::IgnoreRevocationUnknown,
            ErrorIgnoreFlags::IGNORE_REVOCATION_UNKNOWN,
        ),
        (
            IgnoreFlag::IgnoreInvalidUsage,
            ErrorIgnoreFlags::IGNORE_INVALID_USAGE,
        ),
        (
            IgnoreFlag::AllowUntrustedRoot,
            ErrorIgnoreFlags::ALLOW_UNTRUSTED_ROOT,
        ),
        (
            IgnoreFlag::IgnoreTimeNesting,
            ErrorIgnoreFlags::IGNORE_TIME_NESTING,
        ),
        (
            IgnoreFlag::IgnoreBasicConstraints,
            ErrorIgnoreFlags::IGNORE_BASIC_CONSTRAINTS,
        ),
    ];
    let mut all = 0_u8;
    for (flag, bit) in flags {
        assert_eq!(bit.count_ones(), 1, "{flag:?}");
        assert_eq!(all & bit, 0, "{flag:?} shares a bit");
        all |= bit;
        assert!(ErrorIgnoreFlags(ErrorIgnoreFlags::ALL).contains(bit));
        // The trace names each flag in snake_case.
        assert!(
            serde_json::to_value(flag)
                .unwrap()
                .as_str()
                .unwrap()
                .contains('_')
        );
    }
    assert_eq!(all, ErrorIgnoreFlags::ALL);
}
