// Tests may index and unwrap: a panic is a test failure.
#![allow(clippy::indexing_slicing)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use palisade_core::Uuid7;
use palisade_policy::{
    bundle::{Body, Header, PolicyBundle, SourceRevisions, TargetScope, diff},
    context::EvaluationContext,
    decision::{Outcome as Verdict2, TraceId},
    demand::FactSet,
    engine::{EngineConfig, Outcome, Request, SystemClock},
    evaluate::Subject,
    facts::{ObjectFacts, PathVariables},
    mode::DeviceState,
    model::{Mode, ObjectType, PolicyDocument},
    test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash},
};
use palisade_proto::{
    events::{EventType, HostId, TenantId, Timestamp},
    pki::{
        KeyPurpose, KeyStatus, Kid, SignatureAlgorithm, Signer as _, SoftwareSigner, TrustSet,
        TrustedKey, Validity,
    },
    policy_bundle::{
        EffectiveMode, ModeGate, Rejection, Scope, SignatureMode, Target, content_hash,
        envelope::Envelope,
        record::{Record, RecordCopies, RecordKey},
        select::{CacheFile, Finding, Load},
        stale::StaleAfter,
    },
};

use super::*;
use crate::subsystem::Health;
use arc_swap::ArcSwap;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A directory removed on drop.
pub(super) struct TempDir(PathBuf);

impl TempDir {
    pub(super) fn new(tag: &str) -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "palisade-policy-cache-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn uuid(n: u8) -> Uuid7 {
    let mut b = [n; 16];
    b[6] = 0x70 | (n & 0x0f);
    b[8] = 0x80 | (n & 0x3f);
    Uuid7::from_bytes(b).unwrap()
}

/// This device: tenant 1, device 2.
fn target() -> Target {
    Target {
        tenant: TenantId(uuid(1)),
        scope: Scope::Device(HostId(uuid(2))),
    }
}

const T0: i64 = 1_764_201_600_000_000;
const DAY: i64 = 86_400 * 1_000_000;

fn ts(micros: i64) -> Timestamp {
    Timestamp::from_unix_micros(micros).unwrap()
}

/// A policy that blocks hash `b` and allows hash `a`, with `extra` more
/// allow rules so that versions differ in content.
fn doc(extra: u32) -> PolicyDocument {
    let mut allow = RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a')));
    for n in 0..extra {
        allow = allow.rule(RuleBuilder::allow(100 + n, hash('c')));
    }
    PolicyBuilder::new()
        .rule_set(allow)
        .rule_set(RuleSetBuilder::mandatory_blocklist(2).rule(RuleBuilder::deny(2, hash('b'))))
        .build()
}

fn bundle_for(scope: TargetScope, version: u64, doc: PolicyDocument) -> PolicyBundle {
    let header = Header::new(
        palisade_policy::bundle::Target {
            tenant: uuid(1),
            scope,
        },
        version,
        T0 + i64::try_from(version).unwrap(),
    );
    PolicyBundle::new(
        header,
        Body::new(doc, Vec::new(), SourceRevisions::default()).unwrap(),
    )
}

fn bundle(version: u64) -> PolicyBundle {
    bundle_for(
        TargetScope::Device(uuid(2)),
        version,
        doc(u32::try_from(version).unwrap()),
    )
}

/// The policy-signing keys: `listed` is in the device's trust set,
/// `unlisted` is not.
struct Keys {
    signer: SoftwareSigner,
    listed: Kid,
    unlisted: Kid,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let mut signer = SoftwareSigner::new();
        let mut generate = || {
            signer
                .generate(KeyPurpose::PolicySigning, SignatureAlgorithm::Ed25519)
                .unwrap()
        };
        let (listed, unlisted) = (generate(), generate());
        Keys {
            signer,
            listed,
            unlisted,
        }
    })
}

/// A year either side of `T0`.
fn validity() -> Validity {
    Validity::new(ts(T0 - 365 * DAY), ts(T0 + 365 * DAY)).unwrap()
}

/// A trust set listing `kid` as a policy key valid during `validity`.
fn trust_listing(kid: Kid, validity: Validity) -> TrustSet {
    let k = keys();
    let mut set = TrustSet::new(1, ts(T0), &[SignatureAlgorithm::Ed25519]).unwrap();
    set.add_policy_key(
        TrustedKey::new(
            k.signer.public_key(&kid).unwrap(),
            KeyPurpose::PolicySigning,
            SignatureAlgorithm::Ed25519,
            KeyStatus::Active,
            validity,
        )
        .unwrap(),
    )
    .unwrap();
    set
}

/// The device's trust set: the listed key, for a year either side of `T0`.
fn trust() -> SharedTrust {
    Arc::new(ArcSwap::from_pointee(trust_listing(
        keys().listed,
        validity(),
    )))
}

/// A bundle envelope signed by `kid`.
fn sign_with(bundle: &[u8], kid: Kid) -> Vec<u8> {
    Envelope::sign_bundle(bundle, &keys().signer, &[kid])
        .unwrap()
        .encode()
}

/// A bundle envelope signed by the trusted key.
fn sign(bundle: &[u8]) -> Vec<u8> {
    sign_with(bundle, keys().listed)
}

fn signed(version: u64) -> Vec<u8> {
    sign(&bundle(version).to_bytes().unwrap())
}

const KEY: [u8; 32] = [9; 32];

/// The cache over `dir`, with `records` as the record store.
fn cache_with(dir: &Path, records: Box<dyn RecordStore>, mode: EffectiveMode) -> PolicyCache {
    PolicyCache::new(setup(dir, records, mode))
}

fn setup(dir: &Path, records: Box<dyn RecordStore>, mode: EffectiveMode) -> CacheSetup {
    CacheSetup {
        target: target(),
        store: PolicyStore::open(dir.join("policy")).unwrap(),
        records,
        key: RecordKey::from_bytes(&KEY),
        verifier: Box::new(SignedEnvelopes::new(trust())),
        baseline: None,
        mode,
        stale_after: StaleAfter::DEFAULT,
        engine: EngineConfig::default(),
    }
}

fn files(dir: &Path) -> Box<dyn RecordStore> {
    Box::new(FileRecordStore::open(dir.join("record")).unwrap())
}

fn cache(dir: &Path) -> PolicyCache {
    cache_with(dir, files(dir), EffectiveMode::ENFORCE)
}

fn started(dir: &Path) -> (PolicyCache, StartupReport) {
    let c = cache(dir);
    let report = c.load_startup(ts(T0));
    (c, report)
}

fn store(dir: &Path) -> PolicyStore {
    PolicyStore::open(dir.join("policy")).unwrap()
}

fn record_of(dir: &Path) -> RecordCopies {
    let raw = FileRecordStore::open(dir.join("record")).unwrap().read();
    let copies: Vec<Option<&[u8]>> = raw.iter().map(Option::as_deref).collect();
    RecordCopies::read(&copies, &RecordKey::from_bytes(&KEY), target())
}

fn version(cache: &PolicyCache) -> u64 {
    cache.current().policy_version()
}

/// Decides an object with hash `digit`, with every fact computed.
fn decide(active: &Active, digit: char) -> (Verdict2, Verdict) {
    let mut facts = ObjectFacts::new();
    let sha: String = std::iter::repeat_n(digit, 64).collect();
    assert!(facts.set(palisade_policy::model::Field::HashSha256, &sha));
    let vars = PathVariables::new();
    let ctx = EvaluationContext::new();
    let snapshot = active.policy();
    let state = DeviceState::of(&snapshot.policy().document().policy);
    let request = Request {
        subject: Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &vars,
            context: &ctx,
        },
        computed: FactSet::ALL,
        state: &state,
        trace_id: TraceId([1; 16]),
        file: None,
        session: None,
        expires_before: None,
    };
    let verdict = active.evaluate(&request, &SystemClock::new());
    let Outcome::Decided(Some(d)) = &verdict.outcome else {
        panic!("not decided: {:?}", verdict.outcome);
    };
    (d.outcome(), verdict)
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

#[test]
fn before_startup_the_emergency_policy_decides() {
    let dir = TempDir::new("before");
    let c = cache(dir.path());
    assert_eq!(c.current().load(), Load::Emergency);
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);
    // And no bundle is accepted against an unknown floor.
    assert!(matches!(
        c.activate(&signed(1), ts(T0)),
        Err(ActivateError::Io(_))
    ));
}

#[test]
fn an_unenrolled_device_runs_the_first_install_policy_and_refuses_bundles() {
    let c = PolicyCache::unenrolled(EngineConfig::default());
    let report = c.load_startup(ts(T0));
    assert_eq!(report.load, Load::FirstInstall);
    assert!(report.findings.is_empty());
    let (outcome, verdict) = decide(&c.current(), 'z');
    assert_eq!(outcome, Verdict2::AllowedAudit);
    assert_eq!(verdict.policy_version(), 0);
    assert_eq!(verdict.bundle_sha256(), None);
    assert!(matches!(
        c.activate(&signed(1), ts(T0)),
        Err(ActivateError::NotEnrolled)
    ));
    assert_eq!(c.status(ts(T0)).staleness, None);
}

#[test]
fn first_install_runs_in_audit_mode_until_the_first_bundle() {
    let dir = TempDir::new("first");
    let (c, report) = started(dir.path());
    assert_eq!(report.load, Load::FirstInstall);
    assert!(!report.rapid_check_in);
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::AllowedAudit);
    assert_eq!(
        health_of(&c.status(ts(T0))),
        Health::Degraded("PolicyMissing: no policy received yet".into())
    );

    let file = signed(1);
    assert_eq!(
        c.activate(&file, ts(T0)).unwrap(),
        Activated::Activated(c.current().bundle().unwrap())
    );
    assert_eq!(version(&c), 1);
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);
    assert_eq!(decide(&c.current(), 'a').0, Verdict2::Allowed);
    assert_eq!(
        store(dir.path()).read(CacheFile::Active).unwrap().unwrap(),
        file
    );
    assert!(
        store(dir.path())
            .read(CacheFile::Previous)
            .unwrap()
            .is_none()
    );
    assert!(
        store(dir.path())
            .read(CacheFile::Pending)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        record_of(dir.path()).record(),
        Record::new(target(), 1, None).unwrap()
    );
    assert_eq!(health_of(&c.status(ts(T0))), Health::Healthy);
}

#[test]
fn activation_keeps_the_last_known_good_and_raises_the_floor() {
    let dir = TempDir::new("lkg");
    let (c, _) = started(dir.path());
    let (one, two) = (signed(1), signed(2));
    c.activate(&one, ts(T0)).unwrap();
    c.activate(&two, ts(T0)).unwrap();
    assert_eq!(version(&c), 2);
    assert_eq!(
        store(dir.path())
            .read(CacheFile::Previous)
            .unwrap()
            .unwrap(),
        one
    );
    assert_eq!(
        store(dir.path()).read(CacheFile::Active).unwrap().unwrap(),
        two
    );
    assert_eq!(
        record_of(dir.path()).record(),
        Record::new(target(), 2, Some(1)).unwrap()
    );

    // A restart runs the same bundle, with nothing to report.
    let (again, report) = started(dir.path());
    assert_eq!(version(&again), 2);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        again.current().bundle_sha256(),
        Some(content_hash(&bundle(2).to_bytes().unwrap()))
    );
}

#[test]
fn a_corrupt_active_falls_back_to_previous_then_to_the_emergency_policy() {
    let dir = TempDir::new("corrupt");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();
    let s = store(dir.path());
    let mut active = s.read(CacheFile::Active).unwrap().unwrap();
    // A flipped byte in the signature: the header still reads.
    let last = active.len() - 1;
    active[last] ^= 1;
    s.write(CacheFile::Active, &active).unwrap();

    let (c, report) = started(dir.path());
    assert_eq!(version(&c), 1);
    assert!(matches!(report.load, Load::Previous(m) if m.version == 1));
    assert!(report.findings.contains(&Finding::LkgLoaded));
    assert!(report.findings.contains(&Finding::Rejected {
        file: CacheFile::Active,
        reason: Rejection::SignatureInvalid
    }));
    assert!(report.rapid_check_in);
    assert_eq!(health_of(&c.status(ts(T0))), Health::Healthy);

    // Both corrupt: the emergency policy, in enforce mode. Nothing is
    // allowed that the bundles would have blocked, and more is blocked.
    s.write(CacheFile::Previous, b"garbage").unwrap();
    let (c, report) = started(dir.path());
    assert_eq!(report.load, Load::Emergency);
    assert!(report.findings.contains(&Finding::EmergencyLoaded));
    assert_eq!(
        c.current().policy().policy().document().policy.mode,
        Mode::Enforce
    );
    assert_eq!(decide(&c.current(), 'a').0, Verdict2::Blocked);
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);
    assert!(
        matches!(health_of(&c.status(ts(T0))), Health::Degraded(r) if r.starts_with("PolicyEmergency"))
    );

    // Deleting both files does not reopen the first-install path: the
    // record shows a policy was accepted.
    s.remove(CacheFile::Active).unwrap();
    s.remove(CacheFile::Previous).unwrap();
    assert_eq!(started(dir.path()).1.load, Load::Emergency);

    // A fresh copy of the version that failed is accepted again.
    c.activate(&signed(2), ts(T0)).unwrap();
    assert_eq!(version(&c), 2);
}

#[test]
fn a_bundle_that_does_not_compile_is_refused_like_an_unsupported_schema() {
    let dir = TempDir::new("schema");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();

    // A signed bundle whose header reads but whose body does not.
    let mut bytes = bundle(3).to_bytes().unwrap();
    bytes.truncate(bytes.len() - 1);
    let broken = sign(&bytes);
    assert!(matches!(
        c.activate(&broken, ts(T0)),
        Err(ActivateError::Rejected(Rejection::SchemaUnsupported))
    ));
    assert_eq!(
        c.status(ts(T0)).last_rejection,
        Some(Rejection::SchemaUnsupported)
    );
    assert_eq!(version(&c), 2);
    assert!(
        store(dir.path())
            .read(CacheFile::Pending)
            .unwrap()
            .is_none()
    );

    // The same on disk at startup: `previous` loads instead.
    store(dir.path()).write(CacheFile::Active, &broken).unwrap();
    let (c, report) = started(dir.path());
    assert_eq!(version(&c), 1);
    assert!(report.findings.contains(&Finding::Rejected {
        file: CacheFile::Active,
        reason: Rejection::SchemaUnsupported
    }));
}

#[test]
fn a_bundle_whose_policy_is_invalid_is_refused_like_an_unsupported_schema() {
    let dir = TempDir::new("invalid");
    let (c, _) = started(dir.path());
    // A body the decoder reads but validation refuses: a rule set the
    // policy names that it does not hold.
    let mut d = doc(1);
    d.policy
        .rule_sets
        .push(palisade_policy::test_util::rule_set_id(99));
    let b = bundle_for(TargetScope::Device(uuid(2)), 1, d);
    assert!(matches!(
        c.activate(&sign(&b.to_bytes().unwrap()), ts(T0)),
        Err(ActivateError::Rejected(Rejection::SchemaUnsupported))
    ));
    assert_eq!(c.current().load(), Load::FirstInstall);
}

#[test]
fn signatures_are_checked_against_the_trust_set_at_trusted_time() {
    let dir = TempDir::new("trust");
    let trust = trust();
    let c = PolicyCache::new(CacheSetup {
        verifier: Box::new(SignedEnvelopes::new(Arc::clone(&trust))),
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    // Outside the key's validity window (and the skew tolerance).
    let late = ts(T0 + 366 * DAY);
    assert!(matches!(
        c.activate(&signed(1), late),
        Err(ActivateError::Rejected(Rejection::SignatureInvalid))
    ));
    c.activate(&signed(1), ts(T0)).unwrap();

    // The trust set rotates to the other key: bundles signed by the old one
    // are refused, and a restart no longer loads the cached one.
    trust.store(Arc::new(trust_listing(keys().unlisted, validity())));
    assert!(matches!(
        c.activate(&signed(2), ts(T0)),
        Err(ActivateError::Rejected(Rejection::SignatureInvalid))
    ));
    let again = PolicyCache::new(CacheSetup {
        verifier: Box::new(SignedEnvelopes::new(Arc::clone(&trust))),
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    assert_eq!(again.load_startup(ts(T0)).load, Load::Emergency);
    // A bundle signed by the new key is accepted.
    again
        .activate(
            &sign_with(&bundle(2).to_bytes().unwrap(), keys().unlisted),
            ts(T0),
        )
        .unwrap();
    assert_eq!(version(&again), 2);
}

#[test]
fn the_system_baseline_is_added_to_every_bundle_loaded() {
    let dir = TempDir::new("baseline");
    let facts = SystemBaseline {
        publishers: vec!["Operating System Publisher".into()],
        writable_dirs: Vec::new(),
    };
    let c = PolicyCache::new(CacheSetup {
        baseline: Some(facts.clone()),
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    c.activate(&signed(1), ts(T0)).unwrap();
    let has_baseline = |c: &PolicyCache| {
        c.current()
            .policy()
            .policy()
            .document()
            .rule_sets
            .iter()
            .any(palisade_policy::unknown::baseline::is_system_baseline)
    };
    assert!(has_baseline(&c));
    assert!(c.current().profiles().is_some());
    // And at startup.
    let again = PolicyCache::new(CacheSetup {
        baseline: Some(facts),
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    again.load_startup(ts(T0));
    assert!(has_baseline(&again));
    // Without facts, nothing is added; built-in policies have no profiles.
    assert!(!has_baseline(&started(dir.path()).0));
    assert!(cache(dir.path()).current().profiles().is_none());
}

#[test]
fn a_leftover_pending_file_is_deleted_at_startup() {
    let dir = TempDir::new("pending");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    store(dir.path())
        .write(CacheFile::Pending, &signed(2))
        .unwrap();
    let (c, report) = started(dir.path());
    assert_eq!(version(&c), 1);
    assert!(report.io_errors.is_empty());
    assert!(
        store(dir.path())
            .read(CacheFile::Pending)
            .unwrap()
            .is_none()
    );
}

#[test]
fn an_unreadable_cache_file_counts_as_unreadable_not_missing() {
    let dir = TempDir::new("unreadable");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    let s = store(dir.path());
    s.remove(CacheFile::Active).unwrap();
    fs::create_dir(s.path(CacheFile::Active)).unwrap();
    let (_, report) = started(dir.path());
    assert_eq!(report.load, Load::Emergency);
    assert_eq!(report.io_errors.len(), 1, "{:?}", report.io_errors);
    assert!(report.findings.contains(&Finding::Rejected {
        file: CacheFile::Active,
        reason: Rejection::Unreadable
    }));
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

#[test]
fn rejected_bundles_leave_the_policy_and_the_files_alone() {
    let dir = TempDir::new("reject");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();
    let before = |s: &PolicyStore| {
        (
            s.read(CacheFile::Active).unwrap(),
            s.read(CacheFile::Previous).unwrap(),
        )
    };
    let s = store(dir.path());
    let files_before = before(&s);
    let record_before = record_of(dir.path()).record();

    // One flipped byte anywhere fails the signature.
    let good = signed(3);
    for i in [0, good.len() / 2, good.len() - 1] {
        let mut tampered = good.clone();
        tampered[i] ^= 0x01;
        let err = c.activate(&tampered, ts(T0)).unwrap_err();
        assert!(
            matches!(
                err,
                ActivateError::Rejected(Rejection::SignatureInvalid | Rejection::Unreadable)
            ),
            "{err}"
        );
    }
    let other = sign(
        &bundle_for(TargetScope::Device(uuid(3)), 3, doc(3))
            .to_bytes()
            .unwrap(),
    );
    let cases = [
        (signed(1), Rejection::Rollback),
        (
            sign(
                &bundle_for(TargetScope::Device(uuid(2)), 2, doc(9))
                    .to_bytes()
                    .unwrap(),
            ),
            Rejection::VersionReused,
        ),
        (other, Rejection::TargetMismatch),
        (b"short".to_vec(), Rejection::Unreadable),
    ];
    for (file, reason) in cases {
        match c.activate(&file, ts(T0)) {
            Err(ActivateError::Rejected(r)) => assert_eq!(r, reason),
            other => panic!("{other:?}"),
        }
        assert_eq!(c.status(ts(T0)).last_rejection, Some(reason));
    }
    assert_eq!(version(&c), 2);
    assert_eq!(before(&s), files_before);
    assert_eq!(record_of(dir.path()).record(), record_before);
    assert!(s.read(CacheFile::Pending).unwrap().is_none());

    // The running bundle again is a no-op.
    assert_eq!(
        c.activate(&signed(2), ts(T0)).unwrap(),
        Activated::AlreadyCurrent
    );
}

#[test]
fn the_signature_mode_decides_whether_an_unsigned_bundle_loads() {
    let dir = TempDir::new("mode");
    // Signed by a key the trust set does not list: in enforce mode it
    // never loads.
    let bare = |mode| cache_with(dir.path(), files(dir.path()), mode);
    let raw = sign_with(&bundle(1).to_bytes().unwrap(), keys().unlisted);
    let c = bare(EffectiveMode::ENFORCE);
    c.load_startup(ts(T0));
    assert!(matches!(
        c.activate(&raw, ts(T0)),
        Err(ActivateError::Rejected(Rejection::SignatureInvalid))
    ));

    // Audit mode, which needs a dev build or an explicit opt-in, loads it
    // but never raises the floor or keeps it as a fallback.
    let audit = EffectiveMode::resolve(
        SignatureMode::Audit,
        ModeGate {
            dev_build: true,
            group_opt_in: false,
        },
    );
    let c = bare(audit);
    c.load_startup(ts(T0));
    c.activate(&raw, ts(T0)).unwrap();
    assert_eq!(
        c.current().load(),
        Load::Active {
            bundle: c.current().bundle().unwrap(),
            signed: false
        }
    );
    assert_eq!(record_of(dir.path()).floor(), 0);
    let report = bare(audit).load_startup(ts(T0));
    assert!(report.findings.contains(&Finding::LoadedUnsigned));
    // Without the gate, the request for audit mode is ignored.
    let ungated = EffectiveMode::resolve(SignatureMode::Audit, ModeGate::default());
    assert_eq!(ungated, EffectiveMode::ENFORCE);
}

/// A record store that fails its `n`th write (from 1) and every later
/// one, as a crash at that point would leave the disk.
#[derive(Debug)]
struct FailingRecords {
    inner: FileRecordStore,
    writes: AtomicUsize,
    fail_from: usize,
}

impl RecordStore for FailingRecords {
    fn read(&self) -> Vec<Option<Vec<u8>>> {
        self.inner.read()
    }

    fn write(&self, sealed: &[u8]) -> io::Result<()> {
        let n = self.writes.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.fail_from {
            Err(io::Error::other("injected"))
        } else {
            self.inner.write(sealed)
        }
    }
}

fn failing(dir: &Path, fail_from: usize) -> PolicyCache {
    cache_with(
        dir,
        Box::new(FailingRecords {
            inner: FileRecordStore::open(dir.join("record")).unwrap(),
            writes: AtomicUsize::new(0),
            fail_from,
        }),
        EffectiveMode::ENFORCE,
    )
}

#[test]
fn a_failure_before_the_rename_keeps_the_old_policy_on_disk_and_in_memory() {
    let dir = TempDir::new("step3");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();

    // Step 3 (the first record write) fails.
    let c = failing(dir.path(), 1);
    c.load_startup(ts(T0));
    assert!(matches!(
        c.activate(&signed(3), ts(T0)),
        Err(ActivateError::Io(_))
    ));
    assert_eq!(version(&c), 2);
    assert!(
        store(dir.path())
            .read(CacheFile::Pending)
            .unwrap()
            .is_none()
    );
    // `previous` was refreshed from the verified bytes of the running
    // bundle, which is harmless: it is the bundle `active` holds.
    let (c, report) = started(dir.path());
    assert_eq!(version(&c), 2);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn a_failure_after_the_rename_activates_and_the_next_start_completes_it() {
    let dir = TempDir::new("step5");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();

    // Step 5 (the second record write) fails: the power went after the
    // rename.
    let c = failing(dir.path(), 2);
    c.load_startup(ts(T0));
    assert!(matches!(
        c.activate(&signed(3), ts(T0)),
        Ok(Activated::Activated(_))
    ));
    assert_eq!(version(&c), 3);
    assert_eq!(
        record_of(dir.path()).record(),
        Record::new(target(), 2, None).unwrap()
    );

    // The next start runs 3, raises the floor and raises no tamper event.
    let (c, report) = started(dir.path());
    assert_eq!(version(&c), 3);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        record_of(dir.path()).record(),
        Record::new(target(), 3, None).unwrap()
    );
}

#[test]
fn copies_that_disagree_in_another_way_are_reported_as_tampering() {
    let dir = TempDir::new("tamper");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    // One copy replaced by a validly sealed older record.
    let older = Record::new(target(), 0, None)
        .unwrap()
        .seal(&RecordKey::from_bytes(&KEY));
    fs::write(dir.path().join("record").join("record.2"), older).unwrap();
    fs::remove_file(dir.path().join("record").join("record.1")).unwrap();
    let (_, report) = started(dir.path());
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.event_type() == EventType::TamperPolicyRollbackSuspected),
        "{:?}",
        report.findings
    );
}

#[test]
fn the_record_is_never_lowered_to_make_an_old_bundle_load() {
    let dir = TempDir::new("floor");
    let (c, _) = started(dir.path());
    for v in 1..=3 {
        c.activate(&signed(v), ts(T0)).unwrap();
    }
    // Both files replaced with older, validly signed bundles.
    let s = store(dir.path());
    s.write(CacheFile::Active, &signed(1)).unwrap();
    s.write(CacheFile::Previous, &signed(1)).unwrap();
    let (_, report) = started(dir.path());
    assert_eq!(report.load, Load::Emergency);
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::RollbackSuspected(s) if s.floor_rejected_all))
    );
    assert_eq!(record_of(dir.path()).floor(), 3);
}

// ---------------------------------------------------------------------------
// Deltas
// ---------------------------------------------------------------------------

#[test]
fn a_delta_rebuilds_the_full_bundle_from_the_running_one() {
    let dir = TempDir::new("delta");
    let (c, _) = started(dir.path());
    // Nothing to apply a delta to on a built-in policy.
    let delta = diff(&bundle(1), &bundle(2)).unwrap();
    let result = bundle(2).to_bytes().unwrap();
    let k = keys();
    let wrapped = |kid| {
        Envelope::sign_delta(&delta, &result, &k.signer, &[kid])
            .unwrap()
            .encode()
    };
    assert!(c.rebuild_from_delta(&wrapped(k.listed)).is_err());

    c.activate(&signed(1), ts(T0)).unwrap();
    // A full bundle envelope is not a delta.
    assert!(c.rebuild_from_delta(&signed(2)).is_err());
    let rebuilt = c.rebuild_from_delta(&wrapped(k.listed)).unwrap();
    // The rebuilt envelope is the full bundle with the delta's signatures,
    // so it is what a full download would have been.
    assert_eq!(rebuilt, signed(2));

    // A delta signed by an untrusted key rebuilds, but never activates.
    let forged = c.rebuild_from_delta(&wrapped(k.unlisted)).unwrap();
    assert!(matches!(
        c.activate(&forged, ts(T0)),
        Err(ActivateError::Rejected(Rejection::SignatureInvalid))
    ));
    assert_eq!(version(&c), 1);

    c.activate(&rebuilt, ts(T0)).unwrap();
    assert_eq!(version(&c), 2);
    // A delta against another base asks for a full bundle.
    assert!(c.rebuild_from_delta(&wrapped(k.listed)).is_err());
}

// ---------------------------------------------------------------------------
// Offline
// ---------------------------------------------------------------------------

#[test]
fn a_week_offline_keeps_enforcing_and_reports_stale() {
    let dir = TempDir::new("offline");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    let at = |days: i64| ts(T0 + days * DAY);

    for day in 0..=7 {
        let status = c.status(at(day));
        assert!(!status.staleness.unwrap().is_stale(), "day {day}");
        assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);
    }
    let status = c.status(ts(T0 + 7 * DAY + 1));
    assert!(status.staleness.unwrap().not_refreshed);
    assert_eq!(health_of(&status), Health::Degraded("PolicyStale".into()));
    // Still enforcing, on the same policy.
    assert_eq!(status.load, c.current().load());
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);

    // Back online: a check-in with nothing new restarts the window.
    c.mark_current(at(8));
    assert!(!c.status(at(8)).staleness.unwrap().is_stale());
    // And a new bundle does too.
    c.activate(&signed(2), at(20)).unwrap();
    assert!(!c.status(at(20)).staleness.unwrap().is_stale());
    // `AlreadyCurrent` counts as a check-in.
    assert_eq!(
        c.activate(&signed(2), at(30)).unwrap(),
        Activated::AlreadyCurrent
    );
    assert!(!c.status(at(30)).staleness.unwrap().is_stale());
}

#[test]
fn startup_measures_staleness_from_when_the_bundle_was_generated() {
    let dir = TempDir::new("stale-start");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0 + 30 * DAY)).unwrap();
    let (c, _) = started(dir.path());
    // `generated_at` is T0 + 1 µs, so the restart may report sooner than
    // the received time would, never later.
    assert!(c.status(ts(T0 + 7 * DAY + 2)).staleness.unwrap().is_stale());
}

#[test]
fn a_bundle_past_expires_at_is_stale_but_keeps_enforcing() {
    let dir = TempDir::new("expiry");
    let (c, _) = started(dir.path());
    let mut b = bundle(1);
    b.header.expires_at = Some(T0 + DAY);
    c.activate(&sign(&b.to_bytes().unwrap()), ts(T0)).unwrap();
    assert!(!c.status(ts(T0 + DAY)).staleness.unwrap().is_stale());
    let status = c.status(ts(T0 + DAY + 1));
    assert!(status.staleness.unwrap().expired);
    assert_eq!(decide(&c.current(), 'z').0, Verdict2::Blocked);
    assert_eq!(c.current().header().unwrap().expires_at, Some(T0 + DAY));
}

#[test]
fn timestamps_outside_the_representable_years_are_clamped() {
    assert_eq!(clamp_timestamp(i64::MIN), Timestamp::MIN);
    assert_eq!(clamp_timestamp(i64::MAX), Timestamp::MAX);
    assert_eq!(clamp_timestamp(T0), ts(T0));
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

#[test]
fn decisions_during_a_swap_finish_on_one_whole_policy() {
    let dir = TempDir::new("swap");
    let (c, _) = started(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    let c = Arc::new(c);
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let (c, done) = (Arc::clone(&c), Arc::clone(&done));
            std::thread::spawn(move || {
                let mut seen = 0_u64;
                let mut last = 0;
                while !done.load(Ordering::Relaxed) {
                    let active = c.current();
                    let (outcome, verdict) = decide(&active, 'b');
                    // Every policy blocks `b`; the stamp names the policy
                    // that decided, and versions never go backwards.
                    assert_eq!(outcome, Verdict2::Blocked);
                    assert_eq!(verdict.policy_version(), active.policy_version());
                    assert!(verdict.policy_version() >= last);
                    last = verdict.policy_version();
                    seen += 1;
                }
                seen
            })
        })
        .collect();
    for v in 2..=12 {
        c.activate(&signed(v), ts(T0)).unwrap();
    }
    done.store(true, Ordering::Relaxed);
    for r in readers {
        assert!(r.join().unwrap() > 0);
    }
    assert_eq!(version(&c), 12);
}

#[test]
fn the_cache_and_the_subsystem_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<PolicyCache>();
    check::<PolicyCacheSubsystem>();
    check::<Active>();
}

// ---------------------------------------------------------------------------
// Subsystem
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_subsystem_loads_then_reports_health() {
    use palisade_core::{
        platform::{MonotonicTime, UtcTime},
        test_util::MockClock,
    };

    use crate::{
        subsystem::Subsystem,
        supervisor::{RestartPolicy, Supervisor},
    };

    #[derive(Debug)]
    struct SharedClock(std::sync::Mutex<MockClock>);
    impl palisade_core::platform::Clock for SharedClock {
        fn now_utc(&self) -> UtcTime {
            self.0.lock().unwrap().now_utc()
        }
        fn monotonic(&self) -> MonotonicTime {
            self.0.lock().unwrap().monotonic()
        }
    }

    let dir = TempDir::new("subsystem");
    {
        let (c, _) = started(dir.path());
        c.activate(&signed(1), ts(T0)).unwrap();
    }
    let clock = Arc::new(SharedClock(std::sync::Mutex::new(MockClock::new(
        UtcTime(T0),
        MonotonicTime(0),
    ))));
    let sub = Arc::new(PolicyCacheSubsystem::new(
        Arc::new(cache(dir.path())),
        Arc::clone(&clock) as Arc<dyn palisade_core::platform::Clock + Send + Sync>,
    ));
    assert_eq!(sub.name(), "policy_cache");
    assert_eq!(sub.dependencies(), ["config"]);
    assert_eq!(sub.criticality(), crate::subsystem::Criticality::Critical);
    assert!(matches!(sub.health(), Health::Unhealthy(_)));

    let config = Arc::new(crate::host::ConfigSubsystem::new(
        crate::config::LoadedConfig {
            config: crate::config::AgentConfig::default(),
            source: None,
        },
    ));
    let supervisor = Supervisor::new(
        vec![config, Arc::clone(&sub) as Arc<dyn Subsystem>],
        RestartPolicy::default(),
    )
    .unwrap();
    let events = supervisor.host_events();
    let handle = supervisor.start();
    let mut rx = handle.subscribe();
    rx.wait_for(|s| *s != crate::lifecycle::AgentState::Starting)
        .await
        .unwrap();
    assert_eq!(sub.health(), Health::Healthy);
    assert_eq!(sub.cache().current().policy_version(), 1);

    // Eight days later, a time change makes it look again.
    clock.0.lock().unwrap().set_utc(UtcTime(T0 + 8 * DAY));
    events.publish(crate::control::HostEvent::TimeChange);
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sub.health(), Health::Degraded("PolicyStale".into()));

    // Back in date: the hourly check sees it.
    sub.cache().mark_current(ts(T0 + 8 * DAY));
    tokio::time::sleep(subsystem::STATUS_INTERVAL).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sub.health(), Health::Healthy);
    handle.shutdown(std::time::Duration::from_secs(1)).await;
}
