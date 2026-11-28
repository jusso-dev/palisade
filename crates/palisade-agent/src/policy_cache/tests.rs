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

use palisade_core::{Uuid7, path::VolumeMap};
use palisade_policy::{
    bundle::{Body, Header, PolicyBundle, SourceRevisions, TargetScope, diff},
    context::EvaluationContext,
    decision::{Outcome as Verdict2, TraceId},
    demand::FactSet,
    engine::{EngineConfig, Outcome, Request},
    evaluate::Subject,
    facts::{
        ObjectFacts, PathFact, PathVariable, PathVariables, SignatureSource, SignerFact,
        SignerStatus,
    },
    mode::DeviceState,
    model::{Mode, ObjectType, PolicyDocument},
    test_util::{PolicyBuilder, RuleBuilder, RuleSetBuilder, hash},
    unknown::SystemBaseline,
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
        facts: AgentFacts::default(),
        events: Arc::new(BoundedSink::default()),
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

/// A monotonic clock that never advances, so the engine's evaluation
/// budget never runs out in a test.
struct FrozenClock;

impl palisade_policy::engine::Clock for FrozenClock {
    fn monotonic_micros(&self) -> u64 {
        0
    }
}

/// Decides an object with hash `digit`, with every fact computed.
fn decide(active: &Active, digit: char) -> (Verdict2, Verdict) {
    let mut facts = ObjectFacts::new();
    let sha: String = std::iter::repeat_n(digit, 64).collect();
    assert!(facts.set(palisade_policy::model::Field::HashSha256, &sha));
    decide_facts(active, &facts)
}

/// Decides an object with `facts`, everything else computed.
fn decide_facts(active: &Active, facts: &ObjectFacts) -> (Verdict2, Verdict) {
    let vars = PathVariables::new()
        .with(PathVariable::Windir, &["C:\\Windows"])
        .with(PathVariable::System32, &["C:\\Windows\\System32"])
        .with(PathVariable::ProgramFiles, &["C:\\Program Files"]);
    let ctx = EvaluationContext::new();
    let snapshot = active.policy();
    let state = DeviceState::of(&snapshot.policy().document().policy);
    let request = Request {
        subject: Subject {
            object_type: ObjectType::Executable,
            facts,
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
    // A clock that never advances: these tests check which policy decides,
    // not the evaluation budget, and a slow or busy CI runner (several
    // threads at once) must not turn a decision into `TimedOut`.
    let verdict = active.evaluate(&request, &FrozenClock);
    let Outcome::Decided(Some(d)) = &verdict.outcome else {
        panic!("not decided: {:?}", verdict.outcome);
    };
    (d.outcome(), verdict)
}

/// An executable with hash `digit`, signed by `publisher`, at `path`, not
/// writable by users.
fn signed_file(digit: char, publisher: &str, path: &str) -> ObjectFacts {
    let sha: String = std::iter::repeat_n(digit, 64).collect();
    let mut signer = SignerFact::new(SignerStatus::CatalogSigned, SignatureSource::Catalog);
    signer.publisher = Some(publisher.into());
    ObjectFacts::new()
        .with(palisade_policy::model::Field::HashSha256, sha)
        .with_signers(vec![signer])
        .with_path(
            PathFact::new(path, &VolumeMap::new())
                .with_user_writable(false)
                .with_volume(palisade_policy::unknown::VolumeKind::Fixed),
        )
}

const OS: &str = "Operating System Publisher";

fn emergency_facts(enforcement: Enforcement) -> AgentFacts {
    AgentFacts {
        baseline: Some(SystemBaseline {
            publishers: vec![OS.into()],
            writable_dirs: Vec::new(),
        }),
        self_pins: vec![SelfPin {
            sha256: "e".repeat(64),
            publisher: "Palisade".into(),
        }],
        enforcement,
    }
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
    let c = PolicyCache::unenrolled(EngineConfig::default(), Arc::new(BoundedSink::default()));
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
        facts: AgentFacts {
            baseline: Some(facts.clone()),
            ..AgentFacts::default()
        },
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
        facts: AgentFacts {
            baseline: Some(facts),
            ..AgentFacts::default()
        },
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

// ---------------------------------------------------------------------------
// Emergency policy and events (#326)
// ---------------------------------------------------------------------------

/// A cache whose two files are corrupt, so it starts on the emergency
/// policy, built from `facts`.
fn emergency(dir: &Path, facts: AgentFacts) -> (PolicyCache, Arc<BoundedSink>, StartupReport) {
    {
        let (c, _) = started(dir);
        c.activate(&signed(1), ts(T0)).unwrap();
        c.activate(&signed(2), ts(T0)).unwrap();
    }
    let s = store(dir);
    s.write(CacheFile::Active, b"garbage").unwrap();
    s.write(CacheFile::Previous, b"garbage").unwrap();
    let sink = Arc::new(BoundedSink::default());
    let c = PolicyCache::new(CacheSetup {
        facts,
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir, files(dir), EffectiveMode::ENFORCE)
    });
    let report = c.load_startup(ts(T0));
    (c, sink, report)
}

#[test]
fn the_emergency_policy_allows_the_os_and_palisade_and_blocks_the_rest() {
    let dir = TempDir::new("emergency");
    let (c, sink, report) = emergency(dir.path(), emergency_facts(Enforcement::Palisade));
    assert_eq!(report.load, Load::Emergency);
    let active = c.current();
    let os = signed_file('d', OS, "C:\\Windows\\System32\\a.exe");
    assert_eq!(decide_facts(&active, &os).0, Verdict2::Allowed);
    // An OS-signed binary outside the OS locations, or in a user-writable
    // folder inside them, is not allowed.
    for path in ["D:\\Tools\\a.exe", "C:\\Windows\\Temp\\a.exe"] {
        let f = signed_file('d', OS, path);
        assert_eq!(decide_facts(&active, &f).0, Verdict2::Blocked, "{path}");
    }
    // Palisade's own image, by hash and publisher.
    let me = signed_file('e', "Palisade", "C:\\Program Files\\Palisade\\agent.exe");
    assert_eq!(decide_facts(&active, &me).0, Verdict2::Allowed);
    // The same hash signed by someone else, or another file signed by
    // Palisade, is blocked.
    let copy = signed_file('e', "Someone Else", "D:\\agent.exe");
    assert_eq!(decide_facts(&active, &copy).0, Verdict2::Blocked);
    let other = signed_file('f', "Palisade", "D:\\other.exe");
    assert_eq!(decide_facts(&active, &other).0, Verdict2::Blocked);
    // Everything else, including what the bundles allowed.
    assert_eq!(decide(&active, 'a').0, Verdict2::Blocked);
    assert_eq!(decide(&active, 'z').0, Verdict2::Blocked);

    // A critical event says it is enforced.
    let events = sink.drain();
    let emergency: Vec<_> = events
        .iter()
        .filter(|e| e.event_type() == EventType::PolicyEmergencyLoaded)
        .collect();
    assert_eq!(emergency.len(), 1, "{events:?}");
    assert_eq!(emergency[0].detail, Detail::Emergency { enforced: true });
    assert!(emergency[0].critical());
    assert!(
        matches!(health_of(&c.status(ts(T0))), Health::Degraded(r) if r.starts_with("PolicyEmergency:"))
    );
}

#[test]
fn under_native_only_the_emergency_policy_is_audited_and_reported_unenforced() {
    let dir = TempDir::new("native-only");
    let (c, sink, _) = emergency(dir.path(), emergency_facts(Enforcement::NativeOnly));
    assert_eq!(
        decide(&c.current(), 'z').0,
        Verdict2::AllowedAudit,
        "nothing in Palisade's layer enforces it"
    );
    assert!(sink.drain().contains(&PolicyEvent {
        detail: Detail::Emergency { enforced: false },
        load: Load::Emergency
    }));
    assert!(
        matches!(health_of(&c.status(ts(T0))), Health::Degraded(r) if r.starts_with("PolicyEmergencyUnenforced"))
    );
}

#[test]
fn activation_and_rejection_raise_events() {
    let dir = TempDir::new("events");
    let sink = Arc::new(BoundedSink::default());
    let c = PolicyCache::new(CacheSetup {
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    c.activate(&signed(2), ts(T0)).unwrap();
    let _ = c.activate(&signed(1), ts(T0));
    let _ = c.activate(&signed(2), ts(T0));
    let events = sink.drain();
    assert_eq!(
        events
            .iter()
            .map(PolicyEvent::event_type)
            .collect::<Vec<_>>(),
        [EventType::PolicyApplied, EventType::PolicyRollbackRejected],
        "AlreadyCurrent raises nothing"
    );
    assert_eq!(
        events[0].detail,
        Detail::Applied(c.current().bundle().unwrap())
    );
    // A corrupt active at startup: the fallback is reported.
    let s = store(dir.path());
    c.activate(&signed(3), ts(T0)).unwrap();
    s.write(CacheFile::Active, b"garbage").unwrap();
    let c = PolicyCache::new(CacheSetup {
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    sink.drain();
    c.load_startup(ts(T0));
    let types: Vec<_> = sink.drain().iter().map(PolicyEvent::event_type).collect();
    assert!(types.contains(&EventType::PolicyLkgLoaded), "{types:?}");
}

// ---------------------------------------------------------------------------
// Re-verification (#326)
// ---------------------------------------------------------------------------

fn with_sink(dir: &Path) -> (PolicyCache, Arc<BoundedSink>) {
    let sink = Arc::new(BoundedSink::default());
    let c = PolicyCache::new(CacheSetup {
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir, files(dir), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    (c, sink)
}

#[test]
fn reverification_with_nothing_changed_finds_it_intact() {
    let dir = TempDir::new("reverify-ok");
    let (c, sink) = with_sink(dir.path());
    assert_eq!(c.reverify(ts(T0)), Reverified::Builtin);
    c.activate(&signed(1), ts(T0)).unwrap();
    sink.drain();
    assert_eq!(c.reverify(ts(T0)), Reverified::Intact);
    assert!(sink.drain().is_empty());
    let unenrolled = PolicyCache::unenrolled(EngineConfig::default(), sink.clone());
    assert_eq!(unenrolled.reverify(ts(T0)), Reverified::Builtin);
}

#[test]
fn a_cache_file_changed_on_disk_is_restored_from_the_verified_copy() {
    let dir = TempDir::new("reverify-file");
    let (c, sink) = with_sink(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    sink.drain();
    let s = store(dir.path());
    for change in [Some(b"garbage".to_vec()), Some(signed(9)), None] {
        match &change {
            Some(bytes) => s.write(CacheFile::Active, bytes).unwrap(),
            None => s.remove(CacheFile::Active).unwrap(),
        }
        assert_eq!(
            c.reverify(ts(T0)),
            Reverified::FileRestored(CacheFile::Active)
        );
        assert_eq!(s.read(CacheFile::Active).unwrap().unwrap(), signed(1));
        assert_eq!(version(&c), 1);
        let events = sink.drain();
        assert_eq!(
            events,
            [PolicyEvent {
                detail: Detail::Tamper(Tamper::File(CacheFile::Active)),
                load: c.current().load()
            }]
        );
    }

    // Running `previous` after `active` failed: `previous` is the file
    // checked and restored.
    c.activate(&signed(2), ts(T0)).unwrap();
    let mut active = s.read(CacheFile::Active).unwrap().unwrap();
    let last = active.len() - 1;
    active[last] ^= 1;
    s.write(CacheFile::Active, &active).unwrap();
    let (c, sink) = with_sink(dir.path());
    assert!(matches!(c.current().load(), Load::Previous(_)));
    sink.drain();
    s.write(CacheFile::Previous, b"garbage").unwrap();
    assert_eq!(
        c.reverify(ts(T0)),
        Reverified::FileRestored(CacheFile::Previous)
    );
    assert_eq!(s.read(CacheFile::Previous).unwrap().unwrap(), signed(1));
    assert_eq!(c.reverify(ts(T0)), Reverified::Intact);
}

#[test]
fn a_file_that_cannot_be_restored_keeps_the_verified_policy_running() {
    let dir = TempDir::new("reverify-stuck");
    let (c, _) = with_sink(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    let s = store(dir.path());
    // A directory where the file was: neither readable nor replaceable.
    s.remove(CacheFile::Active).unwrap();
    fs::create_dir(s.path(CacheFile::Active)).unwrap();
    fs::write(s.path(CacheFile::Active).join("x"), b"x").unwrap();
    assert_eq!(
        c.reverify(ts(T0)),
        Reverified::FileNotRestored(CacheFile::Active)
    );
    assert_eq!(version(&c), 1);
}

#[test]
fn a_bundle_that_no_longer_verifies_is_reloaded_and_fails_closed() {
    let dir = TempDir::new("reverify-trust");
    let trust = trust();
    let sink = Arc::new(BoundedSink::default());
    let c = PolicyCache::new(CacheSetup {
        verifier: Box::new(SignedEnvelopes::new(Arc::clone(&trust))),
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();
    sink.drain();
    // The signing key leaves the trust set: neither bundle verifies, so
    // the cache reloads onto the emergency policy, never onto nothing.
    trust.store(Arc::new(trust_listing(keys().unlisted, validity())));
    let Reverified::Reloaded(report) = c.reverify(ts(T0)) else {
        panic!("not reloaded");
    };
    assert_eq!(report.load, Load::Emergency);
    assert_eq!(c.current().load(), Load::Emergency);
    let types: Vec<_> = sink.drain().iter().map(PolicyEvent::event_type).collect();
    assert!(
        types.contains(&EventType::PolicyEmergencyLoaded),
        "{types:?}"
    );
    assert!(!types.contains(&EventType::AgentTamper), "{types:?}");

    // Past the key's validity window, likewise.
    let dir = TempDir::new("reverify-late");
    let (c, _) = with_sink(dir.path());
    c.activate(&signed(1), ts(T0)).unwrap();
    assert!(matches!(
        c.reverify(ts(T0 + 400 * DAY)),
        Reverified::Reloaded(r) if r.load == Load::Emergency
    ));
}

/// Verifies with [`SignedEnvelopes`], but once `skew` is set reports the
/// bundle one byte off: what the cache sees if the bytes it holds no longer
/// match what was verified.
#[derive(Debug)]
struct Shifting {
    inner: SignedEnvelopes,
    skew: Arc<AtomicBool>,
}

impl EnvelopeVerifier for Shifting {
    fn examine(&self, file: &[u8], now: Timestamp, mode: EffectiveMode) -> Examination {
        let mut e = self.inner.examine(file, now, mode);
        if self.skew.load(Ordering::Relaxed) {
            e.bundle = e.bundle.start + 1..e.bundle.end;
        }
        e
    }
}

#[test]
fn a_policy_in_memory_that_no_longer_matches_is_reloaded_as_tamper() {
    let dir = TempDir::new("reverify-memory");
    let skew = Arc::new(AtomicBool::new(false));
    let sink = Arc::new(BoundedSink::default());
    let c = PolicyCache::new(CacheSetup {
        verifier: Box::new(Shifting {
            inner: SignedEnvelopes::new(trust()),
            skew: Arc::clone(&skew),
        }),
        events: Arc::clone(&sink) as Arc<dyn PolicyEventSink>,
        ..setup(dir.path(), files(dir.path()), EffectiveMode::ENFORCE)
    });
    c.load_startup(ts(T0));
    c.activate(&signed(1), ts(T0)).unwrap();
    sink.drain();
    skew.store(true, Ordering::Relaxed);
    assert!(matches!(c.reverify(ts(T0)), Reverified::Reloaded(_)));
    let events = sink.drain();
    assert_eq!(events[0].event_type(), EventType::AgentTamper);
    assert_eq!(events[0].detail, Detail::Tamper(Tamper::Memory));
    // The reload could not read the bundle at the wrong place either, so
    // it fails closed onto the emergency policy.
    assert_eq!(c.current().load(), Load::Emergency);
}

#[tokio::test(start_paused = true)]
async fn the_subsystem_reverifies_on_its_interval() {
    use crate::{
        subsystem::Subsystem,
        supervisor::{RestartPolicy, Supervisor},
    };

    let dir = TempDir::new("subsystem-reverify");
    {
        let (c, _) = started(dir.path());
        c.activate(&signed(1), ts(T0)).unwrap();
    }
    #[derive(Debug)]
    struct At;
    impl palisade_core::platform::Clock for At {
        fn now_utc(&self) -> palisade_core::platform::UtcTime {
            palisade_core::platform::UtcTime(T0)
        }
        fn monotonic(&self) -> palisade_core::platform::MonotonicTime {
            palisade_core::platform::MonotonicTime(0)
        }
    }
    let sub = Arc::new(
        PolicyCacheSubsystem::new(Arc::new(cache(dir.path())), Arc::new(At))
            .with_reverify_interval(std::time::Duration::ZERO),
    );
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
    let handle = supervisor.start();
    let mut rx = handle.subscribe();
    rx.wait_for(|s| *s != crate::lifecycle::AgentState::Starting)
        .await
        .unwrap();
    // The file changes; within one interval (clamped to a second) it is
    // put back.
    store(dir.path())
        .write(CacheFile::Active, b"garbage")
        .unwrap();
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if store(dir.path()).read(CacheFile::Active).unwrap().unwrap() == signed(1) {
            break;
        }
    }
    assert_eq!(
        store(dir.path()).read(CacheFile::Active).unwrap().unwrap(),
        signed(1)
    );
    assert_eq!(sub.health(), Health::Healthy);
    assert_eq!(subsystem::REVERIFY_INTERVAL.as_secs(), 15 * 60);
    handle.shutdown(std::time::Duration::from_secs(1)).await;
}

// ---------------------------------------------------------------------------
// At rest (#326)
// ---------------------------------------------------------------------------

/// A protector shared between caches, as DPAPI is between restarts.
#[derive(Debug, Clone)]
struct SharedProtector(Arc<MemoryProtector>);

impl Protector for SharedProtector {
    fn protect(&self, d: &[u8], p: &[u8]) -> io::Result<Vec<u8>> {
        self.0.protect(d, p)
    }
    fn unprotect(&self, d: &[u8], p: &[u8]) -> io::Result<Vec<u8>> {
        self.0.unprotect(d, p)
    }
}

fn sealed_cache(dir: &Path, protector: &SharedProtector) -> PolicyCache {
    let sealer = Arc::new(Sealer::open(dir.join("policy"), Box::new(protector.clone())).unwrap());
    let records = ProtectedRecordStore::new(
        vec![
            Box::new(FileSlot::new(dir.join("record/1")).unwrap()),
            Box::new(FileSlot::new(dir.join("record/2")).unwrap()),
        ],
        Box::new(protector.clone()),
    );
    PolicyCache::new(CacheSetup {
        store: PolicyStore::open(dir.join("policy"))
            .unwrap()
            .sealed(sealer),
        ..setup(dir, Box::new(records), EffectiveMode::ENFORCE)
    })
}

#[test]
fn a_sealed_cache_activates_restarts_and_falls_back_like_a_plain_one() {
    let dir = TempDir::new("at-rest");
    let protector = SharedProtector(Arc::new(MemoryProtector::new().unwrap()));
    let c = sealed_cache(dir.path(), &protector);
    assert_eq!(c.load_startup(ts(T0)).load, Load::FirstInstall);
    c.activate(&signed(1), ts(T0)).unwrap();
    c.activate(&signed(2), ts(T0)).unwrap();
    // Nothing on disk is the plaintext envelope.
    let raw = fs::read(dir.path().join("policy/active")).unwrap();
    assert!(palisade_proto::policy_bundle::at_rest::looks_sealed(&raw));
    assert_ne!(raw, signed(2));
    assert_eq!(c.reverify(ts(T0)), Reverified::Intact);

    // A restart opens and verifies it.
    let again = sealed_cache(dir.path(), &protector);
    let report = again.load_startup(ts(T0));
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(version(&again), 2);

    // A damaged sealed `active` is unreadable: `previous` loads.
    let mut bad = raw.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    fs::write(dir.path().join("policy/active"), &bad).unwrap();
    let again = sealed_cache(dir.path(), &protector);
    let report = again.load_startup(ts(T0));
    assert!(report.findings.contains(&Finding::Rejected {
        file: CacheFile::Active,
        reason: Rejection::Unreadable
    }));
    assert_eq!(version(&again), 1);

    // A protector that cannot open the keyring or the record copies (the
    // disk moved to another machine): nothing is trusted, and the record
    // copies read as corrupt, so it reports rollback suspicion and runs the
    // emergency policy, never first-install.
    let other = SharedProtector(Arc::new(MemoryProtector::new().unwrap()));
    let moved = sealed_cache(dir.path(), &other);
    let report = moved.load_startup(ts(T0));
    assert_eq!(report.load, Load::Emergency, "{report:?}");
    assert!(
        report
            .findings
            .iter()
            .any(|f| matches!(f, Finding::RollbackSuspected(_))),
        "{:?}",
        report.findings
    );
}

/// The facts bridge's request decides through the cache's evaluator: a
/// hash allow on a file identified by `palisade_fileid` lets it run, and
/// the same file with its hashes not computed yet asks for them.
#[test]
fn bridged_facts_decide_through_the_active_policy() {
    use palisade_fileid::identity::{IdentityContext, Tier, Tiers, identify_bytes};
    let bytes = b"MZ not really a program";
    let id = identify_bytes(
        bytes,
        Some("a.exe"),
        Tiers::ALL,
        &IdentityContext::untrusted(0),
    );
    let bridged = crate::facts::from_identity(&id, &VolumeMap::new());
    let sha = bridged
        .facts
        .get(palisade_policy::model::Field::HashSha256)
        .unwrap()
        .to_owned();
    let policy = palisade_policy::test_util::PolicyBuilder::new()
        .rule_set(
            palisade_policy::test_util::RuleSetBuilder::allowlist(1).rule(
                palisade_policy::test_util::RuleBuilder::allow(
                    1,
                    palisade_policy::test_util::criterion(
                        palisade_policy::model::Field::HashSha256,
                        palisade_policy::model::Operator::Equals,
                        &[&sha],
                    ),
                ),
            ),
        )
        .validate();
    let engine = palisade_policy::engine::Engine::new(policy, EngineConfig::default()).unwrap();
    let snapshot = engine.snapshot();
    let state = DeviceState::of(&snapshot.policy().document().policy);
    let (vars, ctx) = (PathVariables::new(), EvaluationContext::new());
    let ask = |b: &crate::facts::Bridged| {
        engine.evaluate(
            &b.request(
                ObjectType::Executable,
                &vars,
                &ctx,
                &state,
                TraceId([2; 16]),
            ),
            &FrozenClock,
        )
    };
    let Outcome::Decided(Some(d)) = ask(&bridged) else {
        panic!("not decided");
    };
    assert_eq!(d.outcome(), Verdict2::Allowed);
    let stat = identify_bytes(
        bytes,
        Some("a.exe"),
        Tier::Stat.into(),
        &IdentityContext::untrusted(0),
    );
    let early = crate::facts::from_identity(&stat, &VolumeMap::new());
    assert!(matches!(ask(&early), Outcome::NeedFacts(_)));
}
