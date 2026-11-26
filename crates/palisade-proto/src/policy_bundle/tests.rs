// Tests may index: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::str::FromStr;

use proptest::prelude::*;

use super::record::{Record, RecordCopies, RecordError, RecordKey};
use super::select::{self, Activation, CacheFile, Finding, Load, PendingOutcome, Startup};
use super::stale::{self, StaleAfter};
use super::*;
use crate::events::{EventType, Timestamp};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn uuid(n: u8) -> Uuid7 {
    let mut b = [n; 16];
    b[6] = 0x70 | (n & 0x0f);
    b[8] = 0x80 | (n & 0x3f);
    Uuid7::from_bytes(b).unwrap()
}

fn target() -> Target {
    Target {
        tenant: TenantId(uuid(1)),
        scope: Scope::Group(uuid(2)),
    }
}

fn other_target() -> Target {
    Target {
        tenant: TenantId(uuid(1)),
        scope: Scope::Device(HostId(uuid(3))),
    }
}

fn meta(version: u64) -> BundleMeta {
    BundleMeta {
        target: target(),
        version,
        sha256: content_hash(&version.to_be_bytes()),
    }
}

/// A bundle that passes every check.
fn good(version: u64) -> Examined {
    Examined::Parsed {
        meta: meta(version),
        signature_valid: true,
        agent_supported: true,
        schema_supported: true,
    }
}

fn unsigned(version: u64) -> Examined {
    match good(version) {
        Examined::Parsed {
            meta,
            agent_supported,
            schema_supported,
            ..
        } => Examined::Parsed {
            meta,
            signature_valid: false,
            agent_supported,
            schema_supported,
        },
        Examined::Unreadable => unreachable!(),
    }
}

fn with(version: u64, f: impl FnOnce(&mut BundleMeta, &mut [bool; 3])) -> Examined {
    let mut m = meta(version);
    let mut flags = [true; 3];
    f(&mut m, &mut flags);
    Examined::Parsed {
        meta: m,
        signature_valid: flags[0],
        agent_supported: flags[1],
        schema_supported: flags[2],
    }
}

fn key() -> RecordKey {
    RecordKey::from_bytes(&[7u8; 32])
}

fn copies(records: &[Option<Record>]) -> RecordCopies {
    let sealed: Vec<Option<Vec<u8>>> = records.iter().map(|r| r.map(|r| r.seal(&key()))).collect();
    let refs: Vec<Option<&[u8]>> = sealed.iter().map(Option::as_deref).collect();
    RecordCopies::read(&refs, &key(), target())
}

fn rec(floor: u64, fallback: Option<u64>) -> Record {
    Record::new(target(), floor, fallback).unwrap()
}

fn both(floor: u64, fallback: Option<u64>) -> RecordCopies {
    copies(&[Some(rec(floor, fallback)), Some(rec(floor, fallback))])
}

fn start(
    record: &RecordCopies,
    active: Option<Examined>,
    previous: Option<Examined>,
) -> select::Selection {
    select::startup(&Startup {
        target: target(),
        record,
        active,
        previous,
        mode: EffectiveMode::ENFORCE,
    })
}

fn events(s: &select::Selection) -> Vec<EventType> {
    s.findings.iter().map(|f| f.event_type()).collect()
}

fn activation(outcome: PendingOutcome) -> Activation {
    match outcome {
        PendingOutcome::Activate(a) => *a,
        PendingOutcome::AlreadyCurrent => panic!("not an activation"),
    }
}

// ---------------------------------------------------------------------------
// MAC and record
// ---------------------------------------------------------------------------

#[test]
fn hmac_sha256_matches_rfc_4231() {
    // RFC 4231 test case 2 (its key is 4 bytes, so it goes straight to
    // ring), then the 32-byte-key wrapper against ring.
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"Jefe");
    let tag = ring::hmac::sign(&key, b"what do ya want for nothing?");
    assert_eq!(
        tag.as_ref(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
    // The wrapper over a 32-byte key agrees with ring and verifies its tags.
    let k = [0x0bu8; 32];
    let mac = crate::pki::crypto::MacKey::new(&k);
    let direct = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &k), b"x");
    assert_eq!(mac.tag(b"x").as_slice(), direct.as_ref());
    assert!(mac.verify(b"x", &mac.tag(b"x")));
    assert!(!mac.verify(b"y", &mac.tag(b"x")));
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_sealed_record_has_a_fixed_layout() {
    let r = rec(9, Some(8));
    let sealed = r.seal(&key());
    assert_eq!(sealed.len(), record::SEALED_LEN_WITH_FALLBACK);
    assert_eq!(sealed[0], record::FORMAT_VERSION);
    assert_eq!(&sealed[1..17], target().tenant.0.as_bytes());
    assert_eq!(sealed[17], 1);
    assert_eq!(&sealed[34..42], &9u64.to_be_bytes());
    assert_eq!(sealed[42], 1);
    assert_eq!(&sealed[43..51], &8u64.to_be_bytes());
    assert_eq!(rec(9, None).seal(&key()).len(), record::SEALED_LEN);
    assert_eq!(Record::unseal(&sealed, &key(), target()), Ok(r));
    // Deterministic, so copies can be compared byte for byte.
    assert_eq!(sealed, r.seal(&key()));
    assert_eq!(format!("{:?}", key()), "RecordKey(..)");
}

#[test]
fn records_keep_the_fallback_below_the_floor() {
    assert_eq!(
        Record::new(target(), 5, Some(5)),
        Err(RecordError::InvalidFallback)
    );
    assert_eq!(
        Record::new(target(), 5, Some(0)),
        Err(RecordError::InvalidFallback)
    );
    assert_eq!(
        Record::new(target(), 0, Some(0)),
        Err(RecordError::InvalidFallback)
    );
    assert!(Record::new(target(), 5, Some(4)).is_ok());
}

#[test]
fn a_record_copy_is_refused_unless_it_verifies_for_this_target() {
    let sealed = rec(9, Some(8)).seal(&key());
    let other_key = RecordKey::from_bytes(&[8u8; 32]);
    assert_eq!(
        Record::unseal(&sealed, &other_key, target()),
        Err(RecordError::BadTag)
    );
    assert_eq!(
        Record::unseal(&sealed, &key(), other_target()),
        Err(RecordError::WrongTarget)
    );
    for len in 0..sealed.len() {
        assert!(Record::unseal(&sealed[..len], &key(), target()).is_err());
    }
    let mut long = sealed.clone();
    long.push(0);
    assert!(Record::unseal(&long, &key(), target()).is_err());
    // A copy with a valid tag over a bad layout is still refused.
    let body = [&[2u8][..], &[0u8; 42]].concat();
    let forged = [
        body.clone(),
        crate::pki::crypto::MacKey::new(&[7u8; 32])
            .tag(&body)
            .to_vec(),
    ]
    .concat();
    assert!(Record::unseal(&forged, &key(), target()).is_err());
}

proptest! {
    #[test]
    fn a_tampered_record_copy_is_never_trusted(
        floor in 1u64..,
        fallback in proptest::option::of(any::<u64>()),
        bit in 0usize..(record::SEALED_LEN_WITH_FALLBACK * 8),
    ) {
        let fallback = fallback.map(|f| f % floor).filter(|f| *f > 0);
        let r = Record::new(target(), floor, fallback).unwrap();
        let mut sealed = r.seal(&key());
        let bit = bit % (sealed.len() * 8);
        sealed[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(Record::unseal(&sealed, &key(), target()).is_err());
    }

    #[test]
    fn unsealing_random_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..80)) {
        let _ = Record::unseal(&bytes, &key(), target());
    }
}

#[test]
fn copies_combine_to_the_highest_floor_and_an_agreed_fallback() {
    let c = copies(&[Some(rec(5, Some(4))), Some(rec(7, Some(6)))]);
    assert_eq!(c.floor(), 7);
    assert_eq!(c.fallback(), None);
    assert!(c.disagree());
    let c = both(5, Some(4));
    assert_eq!((c.floor(), c.fallback()), (5, Some(4)));
    assert!(!c.disagree());
    let c = copies(&[None, None]);
    assert_eq!(c.record(), Record::empty(target()));
}

#[test]
fn only_the_disagreements_of_an_interrupted_activation_are_benign() {
    // Step 3 interrupted (same floor, the cleared copy has no fallback).
    let step3 = copies(&[Some(rec(5, Some(4))), Some(rec(5, None))]);
    assert!(step3.interrupted_activation(Some(5)));
    // Step 5 interrupted (new floor and fallback in one copy only).
    let step5 = copies(&[Some(rec(6, Some(5))), Some(rec(5, None))]);
    assert!(step5.interrupted_activation(Some(6)));
    // ...but not if the loaded `active` is not at the highest floor.
    assert!(!step5.interrupted_activation(Some(5)));
    assert!(!step5.interrupted_activation(None));
    for bad in [
        // The lower copy still has a fallback: not what step 3 leaves.
        copies(&[Some(rec(6, None)), Some(rec(5, Some(4)))]),
        // The newer fallback is not the older floor: an old copy restored.
        copies(&[Some(rec(9, Some(8))), Some(rec(5, None))]),
        // A copy missing or corrupt.
        copies(&[Some(rec(6, Some(5))), None]),
        // Three values.
        copies(&[
            Some(rec(6, Some(5))),
            Some(rec(5, None)),
            Some(rec(4, None)),
        ]),
    ] {
        assert!(!bad.interrupted_activation(Some(bad.floor())), "{bad:?}");
    }
}

// ---------------------------------------------------------------------------
// The #225 check order and the signature mode
// ---------------------------------------------------------------------------

#[test]
fn each_rejection_raises_exactly_one_event() {
    use EventType as E;
    for (r, e) in [
        (Rejection::Unreadable, E::PolicySignatureInvalid),
        (Rejection::SignatureInvalid, E::PolicySignatureInvalid),
        (Rejection::TargetMismatch, E::PolicyTargetMismatch),
        (Rejection::Rollback, E::PolicyRollbackRejected),
        (Rejection::VersionReused, E::PolicyRollbackRejected),
        (Rejection::AgentTooOld, E::PolicySchemaUnsupported),
        (Rejection::SchemaUnsupported, E::PolicySchemaUnsupported),
    ] {
        assert_eq!(r.event_type(), e, "{r}");
    }
}

#[test]
fn checks_run_in_the_issue_order() {
    let t = target();
    let m = EffectiveMode::ENFORCE;
    // Every check fails: the first in #225's order wins.
    let all_bad = with(1, |meta, f| {
        meta.target = other_target();
        *f = [false; 3];
    });
    assert_eq!(check(all_bad, t, m), Err(Rejection::SignatureInvalid));
    let from_target = with(0, |meta, f| {
        meta.target = other_target();
        f[1] = false;
        f[2] = false;
    });
    assert_eq!(check(from_target, t, m), Err(Rejection::TargetMismatch));
    let version_zero = with(0, |_, f| {
        f[1] = false;
    });
    assert_eq!(check(version_zero, t, m), Err(Rejection::Rollback));
    let old_agent = with(1, |_, f| *f = [true, false, false]);
    assert_eq!(check(old_agent, t, m), Err(Rejection::AgentTooOld));
    let schema = with(1, |_, f| f[2] = false);
    assert_eq!(check(schema, t, m), Err(Rejection::SchemaUnsupported));
    assert_eq!(
        check(Examined::Unreadable, t, m),
        Err(Rejection::Unreadable)
    );
    assert_eq!(check(good(1), t, m), Ok(Passed::Verified(meta(1))));
}

#[test]
fn relaxed_signature_modes_need_a_dev_build_or_a_group_opt_in() {
    use SignatureMode::{Audit, Enforce, Warn};
    let closed = ModeGate::default();
    let dev = ModeGate {
        dev_build: true,
        group_opt_in: false,
    };
    let group = ModeGate {
        dev_build: false,
        group_opt_in: true,
    };
    for requested in [Audit, Warn, Enforce] {
        assert_eq!(EffectiveMode::resolve(requested, closed).mode(), Enforce);
        assert_eq!(EffectiveMode::resolve(requested, dev).mode(), requested);
        assert_eq!(EffectiveMode::resolve(requested, group).mode(), requested);
    }
    assert_eq!(SignatureMode::default(), Enforce);
    assert_eq!(EffectiveMode::default(), EffectiveMode::ENFORCE);
    let audit = EffectiveMode::resolve(Audit, dev);
    let warn = EffectiveMode::resolve(Warn, dev);
    assert!(audit.tolerates_invalid_signature() && audit.console_banner());
    assert!(!audit.tray_notification());
    assert!(warn.tolerates_invalid_signature() && warn.tray_notification());
    assert!(!EffectiveMode::ENFORCE.tolerates_invalid_signature());
    assert!(!EffectiveMode::ENFORCE.console_banner());
    // Audit tolerates only the signature: every other check still applies.
    let t = target();
    assert_eq!(check(unsigned(3), t, audit), Ok(Passed::Unsigned(meta(3))));
    assert_eq!(
        check(Examined::Unreadable, t, audit),
        Err(Rejection::Unreadable)
    );
    let wrong = with(3, |m, f| {
        m.target = other_target();
        f[0] = false;
    });
    assert_eq!(check(wrong, t, audit), Err(Rejection::TargetMismatch));
}

// ---------------------------------------------------------------------------
// ADR 0012's failure table, row by row
// ---------------------------------------------------------------------------

/// "New bundle (`pending`) fails verification or activation": keep
/// `active`, report the rejection.
#[test]
fn adr_0012_pending_fails_keeps_active() {
    let r = rec(5, Some(4));
    let active = Some(meta(5));
    let m = EffectiveMode::ENFORCE;
    let cases = [
        (Examined::Unreadable, Rejection::Unreadable),
        (unsigned(6), Rejection::SignatureInvalid),
        (
            with(6, |m, _| m.target = other_target()),
            Rejection::TargetMismatch,
        ),
        (good(4), Rejection::Rollback),
        (good(1), Rejection::Rollback),
        (
            with(5, |m, _| m.sha256 = content_hash(b"other")),
            Rejection::VersionReused,
        ),
        (with(6, |_, f| f[1] = false), Rejection::AgentTooOld),
        (with(6, |_, f| f[2] = false), Rejection::SchemaUnsupported),
    ];
    for (examined, reason) in cases {
        assert_eq!(
            select::pending(examined, target(), r, active, m),
            Err(reason),
            "{examined:?}"
        );
    }
    // The same version with the same content is the idempotent no-op.
    assert_eq!(
        select::pending(good(5), target(), r, active, m),
        Ok(PendingOutcome::AlreadyCurrent)
    );
    // A higher version follows ADR 0007's activation order.
    let a = activation(select::pending(good(6), target(), r, active, m).unwrap());
    assert!(a.signed && a.copy_active_to_previous);
    assert_eq!(a.record_before_rename, rec(5, None));
    assert_eq!(a.record_after_rename, rec(6, Some(5)));
}

/// "Active bundle (N) corrupt or fails verification at load": load `previous`
/// if it verifies and is the recorded fallback, raise `policy.lkg_loaded`.
#[test]
fn adr_0012_active_fails_loads_the_recorded_previous() {
    let c = both(5, Some(4));
    for bad_active in [
        Examined::Unreadable,
        unsigned(5),
        with(5, |m, _| m.target = other_target()),
        with(5, |_, f| f[2] = false),
        good(3),
    ] {
        let s = start(&c, Some(bad_active), Some(good(4)));
        assert_eq!(s.load, Load::Previous(meta(4)), "{bad_active:?}");
        assert_eq!(events(&s).last(), Some(&EventType::PolicyLkgLoaded));
        assert_eq!(events(&s).len(), 2, "{bad_active:?}: rejection, then lkg");
        assert!(s.rapid_check_in);
        // The floor stays at N, so only N or above is accepted later.
        assert_eq!(s.record.floor(), 5);
        assert_eq!(s.loadable_active(), None);
    }
    // `active` missing altogether.
    let s = start(&c, None, Some(good(4)));
    assert_eq!(s.load, Load::Previous(meta(4)));
    assert_eq!(events(&s), [EventType::PolicyLkgLoaded]);
}

/// The one-step exception never reaches further back than the recorded
/// fallback (ADR 0007's fix, proposed in #234).
#[test]
fn adr_0012_previous_must_be_the_recorded_fallback() {
    for (record, previous) in [
        // `active` 10 was corrupt when 11 arrived: no fallback recorded.
        (both(11, None), good(9)),
        // `previous` is older than the fallback.
        (both(5, Some(4)), good(3)),
        // Copies disagree on the fallback, so none is trusted.
        (
            copies(&[Some(rec(5, Some(4))), Some(rec(5, Some(3)))]),
            good(4),
        ),
    ] {
        let s = start(&record, Some(Examined::Unreadable), Some(previous));
        assert_eq!(s.load, Load::Emergency, "{record:?}");
        assert!(s.findings.contains(&Finding::Rejected {
            file: CacheFile::Previous,
            reason: Rejection::Rollback,
        }));
    }
    // `previous` is never loaded unsigned, even in audit mode.
    let audit = EffectiveMode::resolve(
        SignatureMode::Audit,
        ModeGate {
            dev_build: true,
            group_opt_in: false,
        },
    );
    let c = both(5, Some(4));
    let s = select::startup(&Startup {
        target: target(),
        record: &c,
        active: Some(Examined::Unreadable),
        previous: Some(unsigned(4)),
        mode: audit,
    });
    assert_eq!(s.load, Load::Emergency);
}

/// "Active and previous bundles both fail, after a policy was ever
/// accepted": the emergency policy, a critical event, never first-install.
#[test]
fn adr_0012_both_fail_loads_the_emergency_policy() {
    let c = both(5, Some(4));
    let s = start(&c, Some(Examined::Unreadable), Some(Examined::Unreadable));
    assert_eq!(s.load, Load::Emergency);
    assert_eq!(
        events(&s),
        [
            EventType::PolicySignatureInvalid,
            EventType::PolicySignatureInvalid,
            EventType::PolicyEmergencyLoaded,
        ]
    );
    assert!(s.rapid_check_in);
    // Both files gone, record intact: still emergency.
    assert_eq!(start(&c, None, None).load, Load::Emergency);
    // Record gone, a file left: still a policy was accepted.
    let none = copies(&[None, None]);
    let s = start(&none, Some(Examined::Unreadable), None);
    assert_eq!(s.load, Load::Emergency);
    // A corrupt record copy alone is evidence of an earlier policy.
    let corrupt = RecordCopies::read(&[Some(&[0u8; 3][..]), None], &key(), target());
    let s = start(&corrupt, None, None);
    assert_eq!(s.load, Load::Emergency);
    assert!(events(&s).contains(&EventType::TamperPolicyRollbackSuspected));
}

/// The floor rejecting every bundle on disk is treated as both failing,
/// with the tamper event, and the floor is never lowered (ADR 0007).
#[test]
fn adr_0012_floor_rejecting_every_bundle_is_suspected_rollback() {
    let c = both(9, Some(8));
    let s = start(&c, Some(good(6)), Some(good(5)));
    assert_eq!(s.load, Load::Emergency);
    assert_eq!(s.record.floor(), 9);
    assert!(s.findings.iter().any(|f| matches!(
        f,
        Finding::RollbackSuspected(sus) if sus.floor_rejected_all
    )));
    assert_eq!(
        events(&s),
        [
            EventType::PolicyRollbackRejected,
            EventType::PolicyRollbackRejected,
            EventType::PolicyEmergencyLoaded,
            EventType::TamperPolicyRollbackSuspected,
        ]
    );
}

/// "No policy yet (first install, before the first bundle)": the built-in
/// audit defaults, and nothing is suspected.
#[test]
fn adr_0012_first_install_runs_the_audit_defaults() {
    let none = copies(&[None, None]);
    let s = start(&none, None, None);
    assert_eq!(s.load, Load::FirstInstall);
    assert!(s.findings.is_empty());
    assert!(!s.rewrite_record && !s.rapid_check_in);
    // An interrupted first download (a leftover `pending`) is deleted by
    // the caller before startup, so it cannot leave first-install either
    // way; the first verified bundle then activates.
    let a = activation(
        select::pending(good(1), target(), s.record, None, EffectiveMode::ENFORCE).unwrap(),
    );
    assert!(!a.copy_active_to_previous);
    assert_eq!(a.record_after_rename, rec(1, None));
}

/// "Policy stale or past `expires_at`": keep enforcing and report
/// `policy.stale`. Staleness has no input to `startup`, so it cannot change
/// what loads; this checks the report itself.
#[test]
fn adr_0012_stale_policy_keeps_enforcing_and_reports() {
    let day = 86_400_000_000i64;
    let t0 = Timestamp::from_str("2026-11-01T00:00:00.000000Z").unwrap();
    let at = |d: i64| Timestamp::from_unix_micros(t0.unix_micros() + d).unwrap();
    let w = StaleAfter::DEFAULT;
    assert!(!stale::check(at(7 * day), t0, w, None).is_stale());
    assert!(stale::check(at(7 * day + 1), t0, w, None).not_refreshed);
    // The 30-day offline acceptance case.
    let s = stale::check(at(30 * day), t0, w, Some(at(10 * day)));
    assert!(s.not_refreshed && s.expired);
    assert_eq!(s.event_type(), Some(EventType::PolicyStale));
    assert!(!stale::check(at(day), t0, w, Some(at(day))).expired);
    assert!(stale::check(at(day + 1), t0, w, Some(at(day))).expired);
    assert_eq!(stale::check(t0, t0, w, None).event_type(), None);
    assert_eq!(
        StaleAfter::new(std::time::Duration::from_secs(60)).as_micros(),
        60_000_000
    );
    // A clock set far back is not "fresh forever" by overflow.
    assert!(!stale::check(Timestamp::MIN, Timestamp::MAX, w, None).is_stale());
    assert!(stale::check(Timestamp::MAX, Timestamp::MIN, w, None).is_stale());
    // And the selection with a stale bundle is the normal one.
    let c = both(5, None);
    assert_eq!(
        start(&c, Some(good(5)), None).load,
        Load::Active {
            bundle: meta(5),
            signed: true
        }
    );
}

/// "Unknown or newer bundle schema": reject, keep the last known good,
/// report `policy.schema_unsupported`.
#[test]
fn adr_0012_unsupported_schema_keeps_the_last_known_good() {
    let schema = with(6, |_, f| f[2] = false);
    let r = rec(5, Some(4));
    let err = select::pending(schema, target(), r, Some(meta(5)), EffectiveMode::ENFORCE);
    assert_eq!(err, Err(Rejection::SchemaUnsupported));
    assert_eq!(
        Rejection::SchemaUnsupported.event_type(),
        EventType::PolicySchemaUnsupported
    );
    // At startup (an agent downgrade): `active` is refused, N-1 loads.
    let s = start(
        &both(5, Some(4)),
        Some(with(5, |_, f| f[2] = false)),
        Some(good(4)),
    );
    assert_eq!(s.load, Load::Previous(meta(4)));
    assert_eq!(events(&s)[0], EventType::PolicySchemaUnsupported);
}

// ---------------------------------------------------------------------------
// Record handling at startup
// ---------------------------------------------------------------------------

#[test]
fn a_mismatch_between_copies_raises_the_tamper_event() {
    for c in [
        copies(&[Some(rec(5, None)), None]),
        // Not what an interrupted activation leaves: the lower copy still
        // has a fallback. ((5, none) beside (3, none) would be: step 5
        // interrupted after activating 5 from `previous` or emergency.)
        copies(&[Some(rec(5, None)), Some(rec(3, Some(2)))]),
        RecordCopies::read(
            &[Some(&rec(5, None).seal(&key())[..]), Some(&[1u8; 51][..])],
            &key(),
            target(),
        ),
    ] {
        let s = start(&c, Some(good(5)), None);
        assert!(matches!(s.load, Load::Active { .. }));
        assert_eq!(
            events(&s),
            [EventType::TamperPolicyRollbackSuspected],
            "{c:?}"
        );
        assert!(s.rewrite_record && s.rapid_check_in);
        assert_eq!(s.record.floor(), 5);
    }
}

#[test]
fn an_interrupted_activation_is_completed_without_a_tamper_event() {
    // Crash between the rename and step 5: `active` is 6, the floor 5.
    let s = start(&both(5, None), Some(good(6)), Some(good(5)));
    assert_eq!(
        s.load,
        Load::Active {
            bundle: meta(6),
            signed: true
        }
    );
    assert!(s.findings.is_empty());
    assert_eq!(s.record, rec(6, None));
    assert!(s.rewrite_record);
    // Crash during step 5: one copy updated.
    let c = copies(&[Some(rec(6, Some(5))), Some(rec(5, None))]);
    let s = start(&c, Some(good(6)), Some(good(5)));
    assert!(s.findings.is_empty());
    assert_eq!(s.record, rec(6, None));
    // Crash during step 3: `active` is still 5.
    let c = copies(&[Some(rec(5, Some(4))), Some(rec(5, None))]);
    let s = start(&c, Some(good(5)), Some(good(4)));
    assert!(s.findings.is_empty());
    assert_eq!(s.record, rec(5, None));
    // Nothing to do when everything agrees.
    let s = start(&both(5, Some(4)), Some(good(5)), Some(good(4)));
    assert!(s.findings.is_empty() && !s.rewrite_record && !s.rapid_check_in);
    assert_eq!(s.loadable_active(), Some(meta(5)));
}

#[test]
fn an_unsigned_bundle_never_moves_the_record() {
    let audit = EffectiveMode::resolve(
        SignatureMode::Warn,
        ModeGate {
            dev_build: false,
            group_opt_in: true,
        },
    );
    let r = rec(5, Some(4));
    let a = activation(select::pending(unsigned(9), target(), r, Some(meta(5)), audit).unwrap());
    assert!(!a.signed);
    assert_eq!(a.record_after_rename, rec(5, None));
    // At startup it loads under the relaxed mode, reported, but the floor
    // is not raised and it is not a base for `previous`.
    let c = both(5, None);
    let s = select::startup(&Startup {
        target: target(),
        record: &c,
        active: Some(unsigned(9)),
        previous: Some(good(5)),
        mode: audit,
    });
    assert_eq!(
        s.load,
        Load::Active {
            bundle: meta(9),
            signed: false
        }
    );
    assert_eq!(events(&s), [EventType::PolicySignatureInvalid]);
    assert_eq!(s.record, rec(5, None));
    assert_eq!(s.loadable_active(), None);
}

#[test]
fn a_refetched_copy_of_the_failed_version_is_accepted() {
    // Running `previous` (4) because `active` (5) failed: 5 is accepted
    // again, and the fallback is not carried over (step 2 copies nothing).
    let s = start(&both(5, Some(4)), Some(Examined::Unreadable), Some(good(4)));
    let a = activation(
        select::pending(
            good(5),
            target(),
            s.record,
            s.loadable_active(),
            EffectiveMode::ENFORCE,
        )
        .unwrap(),
    );
    assert!(!a.copy_active_to_previous);
    assert_eq!(a.record_after_rename, rec(5, None));
    // But nothing below the floor.
    assert_eq!(
        select::pending(good(4), target(), s.record, None, EffectiveMode::ENFORCE),
        Err(Rejection::Rollback)
    );
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    /// A lower version is never accepted, whatever else is true.
    #[test]
    fn a_lower_version_is_never_accepted(
        floor in 0u64..20,
        active in proptest::option::of(1u64..20),
        version in 0u64..20,
        signed in any::<bool>(),
        relaxed in any::<bool>(),
    ) {
        let mode = if relaxed {
            EffectiveMode::resolve(SignatureMode::Audit, ModeGate { dev_build: true, group_opt_in: false })
        } else {
            EffectiveMode::ENFORCE
        };
        let examined = if signed { good(version) } else { unsigned(version) };
        let r = Record::new(target(), floor, None).unwrap();
        let result = select::pending(examined, target(), r, active.map(meta), mode);
        let lower = version < floor || active.is_some_and(|a| version < a) || version == 0;
        if lower {
            prop_assert!(result.is_err());
            // Rollback is the reason whenever the earlier checks pass.
            if signed || relaxed {
                prop_assert_eq!(&result, &Err(Rejection::Rollback));
            }
        }
        if let Ok(PendingOutcome::Activate(a)) = result {
            prop_assert!(a.bundle.version >= floor);
            prop_assert!(a.record_after_rename.floor() >= floor);
            prop_assert!(a.record_before_rename.floor() == floor);
            prop_assert!(a.record_before_rename.fallback().is_none());
        }
    }
}

/// One step of the agent model.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// A bundle arrives. `crash` stops the activation after that many of
    /// ADR 0007's writes (0 to 5; 5 means it completed), then restarts.
    Deliver {
        version: u64,
        signed: bool,
        crash: u8,
    },
    Restart,
    CorruptActive,
    CorruptPrevious,
    DeleteActive,
    DeletePrevious,
    /// Replace `active` with an older, validly signed bundle.
    ReplaceActiveWithOld(u64),
    DeleteCopy(usize),
    CorruptCopy(usize),
    /// Put back an earlier sealed copy into one store.
    RestoreCopy(usize, usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (1u64..12, prop::bool::weighted(0.85), 0u8..=5)
            .prop_map(|(version, signed, crash)| Op::Deliver { version, signed, crash }),
        2 => Just(Op::Restart),
        1 => Just(Op::CorruptActive),
        1 => Just(Op::CorruptPrevious),
        1 => Just(Op::DeleteActive),
        1 => Just(Op::DeletePrevious),
        1 => (1u64..12).prop_map(Op::ReplaceActiveWithOld),
        1 => (0usize..2).prop_map(Op::DeleteCopy),
        1 => (0usize..2).prop_map(Op::CorruptCopy),
        1 => (0usize..2, any::<usize>()).prop_map(|(i, n)| Op::RestoreCopy(i, n)),
    ]
}

/// The disk the agent owns: two cache files and two record copies.
#[derive(Clone, Debug, Default)]
struct Disk {
    active: Option<Examined>,
    previous: Option<Examined>,
    copies: [Option<Vec<u8>>; 2],
    /// Every sealed copy ever written, for `RestoreCopy`.
    history: Vec<Vec<u8>>,
}

impl Disk {
    fn write_record(&mut self, r: Record, upto: usize) {
        let sealed = r.seal(&key());
        for c in self.copies.iter_mut().take(upto) {
            *c = Some(sealed.clone());
        }
        self.history.push(sealed);
    }

    fn startup(&mut self, mode: EffectiveMode) -> select::Selection {
        let refs: Vec<Option<&[u8]>> = self.copies.iter().map(Option::as_deref).collect();
        let copies = RecordCopies::read(&refs, &key(), target());
        let s = select::startup(&Startup {
            target: target(),
            record: &copies,
            active: self.active,
            previous: self.previous,
            mode,
        });
        check_selection(&copies, self, &s);
        if s.rewrite_record {
            self.write_record(s.record, 2);
        }
        s
    }
}

/// The invariants every startup decision keeps.
fn check_selection(copies: &RecordCopies, disk: &Disk, s: &select::Selection) {
    let floor = copies.floor();
    // The floor is never lowered.
    assert!(s.record.floor() >= floor, "floor lowered: {s:?}");
    // First-install (the only non-enforcing outcome) only when the disk
    // shows no sign of any policy.
    let any_sign =
        floor > 0 || disk.active.is_some() || disk.previous.is_some() || copies.any_corrupt();
    assert_eq!(s.load == Load::FirstInstall, !any_sign, "{s:?} {disk:?}");
    match s.load {
        // `active` never runs below the floor.
        Load::Active { bundle, .. } => assert!(bundle.version >= floor),
        // `previous` only at or above the floor, or exactly the agreed
        // fallback; and always verified.
        Load::Previous(b) => {
            assert!(b.version >= floor || Some(b.version) == copies.fallback());
            assert!(matches!(
                disk.previous,
                Some(Examined::Parsed {
                    signature_valid: true,
                    ..
                })
            ));
        }
        Load::Emergency | Load::FirstInstall => {}
    }
    // Every finding maps to an event of this module's set.
    for f in &s.findings {
        let e = f.event_type();
        assert!(e.as_str().starts_with("policy.") || e.as_str().starts_with("tamper.policy."));
    }
}

fn run(ops: &[Op], mode: EffectiveMode) {
    let mut disk = Disk::default();
    let mut sel = disk.startup(mode);
    let mut tampered = false;
    let mut highest_signed = 0u64;
    for &op in ops {
        match op {
            Op::Deliver {
                version,
                signed,
                crash,
            } => {
                let examined = if signed {
                    good(version)
                } else {
                    unsigned(version)
                };
                let outcome =
                    select::pending(examined, target(), sel.record, sel.loadable_active(), mode);
                match outcome {
                    Ok(PendingOutcome::Activate(a)) => {
                        let steps = [
                            |d: &mut Disk, a: &Activation| {
                                if a.copy_active_to_previous {
                                    d.previous = d.active;
                                }
                            },
                            |d: &mut Disk, a: &Activation| {
                                d.write_record(a.record_before_rename, 1)
                            },
                            |d: &mut Disk, a: &Activation| {
                                d.write_record(a.record_before_rename, 2)
                            },
                            |d: &mut Disk, a: &Activation| {
                                d.active = Some(if a.signed {
                                    good(a.bundle.version)
                                } else {
                                    unsigned(a.bundle.version)
                                });
                            },
                            |d: &mut Disk, a: &Activation| d.write_record(a.record_after_rename, 1),
                            |d: &mut Disk, a: &Activation| d.write_record(a.record_after_rename, 2),
                        ];
                        let done = usize::from(crash) + 1;
                        for step in steps.iter().take(done) {
                            step(&mut disk, &a);
                        }
                        if a.signed && done == steps.len() {
                            highest_signed = highest_signed.max(a.bundle.version);
                        }
                        // Activation keeps the record in memory too.
                        sel = disk.startup(mode);
                        if !tampered {
                            assert!(
                                !sel.findings
                                    .iter()
                                    .any(|f| matches!(f, Finding::RollbackSuspected(_))),
                                "a crash alone raised the tamper event: {sel:?}"
                            );
                            assert!(sel.load != Load::Emergency, "{sel:?}");
                        }
                    }
                    Ok(PendingOutcome::AlreadyCurrent) | Err(_) => {}
                }
            }
            Op::Restart => sel = disk.startup(mode),
            tamper => {
                tampered = true;
                match tamper {
                    Op::CorruptActive => disk.active = disk.active.map(|_| Examined::Unreadable),
                    Op::CorruptPrevious => {
                        disk.previous = disk.previous.map(|_| Examined::Unreadable);
                    }
                    Op::DeleteActive => disk.active = None,
                    Op::DeletePrevious => disk.previous = None,
                    Op::ReplaceActiveWithOld(v) => disk.active = Some(good(v)),
                    Op::DeleteCopy(i) => disk.copies[i] = None,
                    Op::CorruptCopy(i) => {
                        if let Some(c) = disk.copies[i].as_mut() {
                            c[40] ^= 1;
                        }
                    }
                    Op::RestoreCopy(i, n) => {
                        if !disk.history.is_empty() {
                            disk.copies[i] = Some(disk.history[n % disk.history.len()].clone());
                        }
                    }
                    _ => unreachable!(),
                }
                sel = disk.startup(mode);
            }
        }
        // Without tampering, a signed bundle once fully activated is never
        // undercut: what runs is that version or later.
        if !tampered {
            if let Load::Active { bundle, .. } = sel.load {
                assert!(bundle.version >= highest_signed, "{sel:?}");
            } else if highest_signed > 0 {
                panic!("lost the active policy without tampering: {sel:?}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Random activations, crashes at every step and tampering: the
    /// invariants in `check_selection` hold after every startup, a crash
    /// alone never raises the tamper event or loads the emergency policy,
    /// and without tampering the device never runs below its highest
    /// signed version.
    #[test]
    fn no_sequence_of_crashes_or_tampering_breaks_the_invariants(
        ops in proptest::collection::vec(op(), 0..40),
        relaxed in any::<bool>(),
    ) {
        let mode = if relaxed {
            EffectiveMode::resolve(SignatureMode::Audit, ModeGate { dev_build: true, group_opt_in: false })
        } else {
            EffectiveMode::ENFORCE
        };
        run(&ops, mode);
    }
}
