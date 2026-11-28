//! The local policy cache (#61): which policy the agent enforces, how a new
//! bundle is activated, and how the agent behaves offline.
//!
//! The decisions are made by [`palisade_proto::policy_bundle`] (#304): what
//! loads at startup ([`select::startup`]), whether a downloaded bundle is
//! accepted ([`select::pending`]), the anti-rollback record and staleness.
//! This module reads and writes the files in the order ADR 0007 requires,
//! and swaps the evaluator.
//!
//! - **Startup** ([`PolicyCache::load_startup`]): delete any leftover
//!   `pending`, read `active`, `previous` and the record copies, let
//!   [`select::startup`] choose, and decode only the bundle it chose. A
//!   bundle that then fails to decode, validate or compile counts as an
//!   unsupported schema, and the choice is made again. If nothing loads,
//!   the built-in emergency policy runs (enforce mode), or the first-install
//!   policy (audit mode) if no policy was ever accepted ([`builtin`]).
//! - **Activation** ([`PolicyCache::activate`]): verify and compile the new
//!   bundle in memory, write `pending` and read it back, copy the verified
//!   `active` bytes to `previous`, clear the record's fallback, rename
//!   `pending` over `active` with write-through, raise the floor, then swap
//!   the evaluator. Any failure before the rename leaves the current policy
//!   in force, in memory and on disk.
//! - **Evaluation** ([`PolicyCache::current`]): the running policy is one
//!   [`Active`] behind an `ArcSwap`. A decision holds the `Arc` it started
//!   with, so it finishes on that policy, and its [`Verdict`] names the
//!   version and bundle hash that decided it.
//! - **Offline** ([`PolicyCache::status`]): staleness is only reported.
//!   Nothing relaxes enforcement automatically (ADR 0018): there is no
//!   `on_expiry = audit_only`, and the stricter `mode_disconnected` of the
//!   policy model (#36) applies through the device state the caller passes.
//!
//! What a cache file holds is the business of an [`EnvelopeVerifier`]: the
//! signed envelope of #325 plugs in there. Until then, [`BareBundles`]
//! reports every bundle as unsigned, so in the default `enforce` signature
//! mode nothing loads.

#![forbid(unsafe_code)]

pub mod builtin;
pub mod store;
mod subsystem;
pub mod verify;

#[cfg(test)]
mod tests;

use std::{
    fmt, io,
    sync::{Arc, Mutex, MutexGuard},
};

use arc_swap::ArcSwap;
use palisade_policy::{
    bundle::{BundleDelta, BundleLimits, DeltaError, Header, PolicyBundle, apply},
    engine::{self, Engine, EngineConfig, Outcome, Request},
};
use palisade_proto::{
    events::{Sha256Hex, Timestamp},
    policy_bundle::{
        BundleMeta, EffectiveMode, Examined, Rejection, Target,
        record::{Record, RecordCopies, RecordKey},
        select::{self, CacheFile, Finding, Load, PendingOutcome, Startup},
        stale::{self, StaleAfter, Staleness},
    },
};

pub use builtin::Builtin;
pub use store::{FileRecordStore, PolicyStore, RecordStore};
pub use subsystem::{PolicyCacheSubsystem, STATUS_INTERVAL, health_of};
pub use verify::{BareBundles, EnvelopeVerifier, Examination};

/// What an enrolled device's cache needs.
#[derive(Debug)]
pub struct CacheSetup {
    /// This device's tenant and target, from enrolment.
    pub target: Target,
    /// The cache files.
    pub store: PolicyStore,
    /// The anti-rollback record copies.
    pub records: Box<dyn RecordStore>,
    /// The device's record key (#220).
    pub key: RecordKey,
    /// Reads the envelope of a cache file (#325).
    pub verifier: Box<dyn EnvelopeVerifier>,
    /// The signature mode in force, after its gate.
    pub mode: EffectiveMode,
    /// `policy.stale_after`.
    pub stale_after: StaleAfter,
    /// The engine's settings.
    pub engine: EngineConfig,
}

/// The policy that decides, with what is known about it.
#[derive(Debug)]
pub struct Active {
    engine: Engine,
    load: Load,
    header: Option<Header>,
    /// The whole cache file it was read from, exactly as verified, and
    /// where the bundle is in it. `None` for a built-in policy.
    file: Option<(Arc<[u8]>, std::ops::Range<usize>)>,
}

impl Active {
    fn builtin(which: Builtin, config: EngineConfig) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "fixed policies with no rules; `builtins_validate_and_build` tests them"
        )]
        let engine = Engine::new(which.policy(), config).expect("the built-in policies build");
        Self {
            engine,
            load: match which {
                Builtin::FirstInstall => Load::FirstInstall,
                Builtin::Emergency => Load::Emergency,
            },
            header: None,
            file: None,
        }
    }

    /// The engine.
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// What is running: which file, or which built-in policy.
    pub const fn load(&self) -> Load {
        self.load
    }

    /// The bundle's `policy_version`, or 0 for a built-in policy.
    pub const fn policy_version(&self) -> u64 {
        match self.bundle() {
            Some(meta) => meta.version,
            None => 0,
        }
    }

    /// SHA-256 of the canonical bundle bytes, for events. `None` for a
    /// built-in policy.
    pub const fn bundle_sha256(&self) -> Option<Sha256Hex> {
        match self.bundle() {
            Some(meta) => Some(meta.sha256),
            None => None,
        }
    }

    const fn bundle(&self) -> Option<BundleMeta> {
        match self.load {
            Load::Active { bundle, .. } | Load::Previous(bundle) => Some(bundle),
            Load::Emergency | Load::FirstInstall => None,
        }
    }

    /// The bundle header. `None` for a built-in policy.
    pub const fn header(&self) -> Option<&Header> {
        self.header.as_ref()
    }

    /// The validated policy.
    pub fn policy(&self) -> Arc<engine::Snapshot> {
        self.engine.snapshot()
    }

    /// Decides one object with this policy, and stamps the result.
    pub fn evaluate(&self, request: &Request<'_>, clock: &dyn engine::Clock) -> Verdict {
        Verdict {
            outcome: self.engine.evaluate(request, clock),
            load: self.load,
        }
    }

    fn bundle_bytes(&self) -> Option<&[u8]> {
        self.file
            .as_ref()
            .and_then(|(file, range)| file.get(range.clone()))
    }
}

/// A decision and the policy that made it. Every event about the decision
/// carries [`Verdict::policy_version`] and [`Verdict::bundle_sha256`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The engine's result.
    pub outcome: Outcome,
    /// The policy that decided.
    pub load: Load,
}

impl Verdict {
    /// The bundle's `policy_version`, or 0 for a built-in policy.
    pub const fn policy_version(&self) -> u64 {
        match self.load {
            Load::Active { bundle, .. } | Load::Previous(bundle) => bundle.version,
            Load::Emergency | Load::FirstInstall => 0,
        }
    }

    /// The bundle's SHA-256, or `None` for a built-in policy.
    pub const fn bundle_sha256(&self) -> Option<Sha256Hex> {
        match self.load {
            Load::Active { bundle, .. } | Load::Previous(bundle) => Some(bundle.sha256),
            Load::Emergency | Load::FirstInstall => None,
        }
    }
}

/// What startup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupReport {
    /// What runs.
    pub load: Load,
    /// What to report, in order (#303 event types through
    /// [`Finding::event_type`]).
    pub findings: Vec<Finding>,
    /// Whether to check in at once for a fresh bundle.
    pub rapid_check_in: bool,
    /// I/O errors met on the way. Each is also reflected in `load`: a file
    /// that could not be read counts as unreadable.
    pub io_errors: Vec<String>,
}

/// What [`PolicyCache::activate`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activated {
    /// The bundle is now `active` and decides.
    Activated(BundleMeta),
    /// It is the bundle already running: nothing changed (`policy.applied`).
    AlreadyCurrent,
}

/// Why [`PolicyCache::activate`] did not activate a bundle. The current
/// policy stays in force in every case.
#[derive(Debug)]
pub enum ActivateError {
    /// The device is not enrolled, so no bundle can be for it.
    NotEnrolled,
    /// The bundle was refused (`PolicyRejected`).
    Rejected(Rejection),
    /// The cache could not be written.
    Io(io::Error),
}

impl fmt::Display for ActivateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnrolled => f.write_str("the device is not enrolled"),
            Self::Rejected(r) => write!(f, "the bundle was rejected: {r}"),
            Self::Io(e) => write!(f, "the policy cache could not be written: {e}"),
        }
    }
}

impl std::error::Error for ActivateError {}

/// The policy status for health and check-in (#62).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    /// What runs.
    pub load: Load,
    /// Staleness, for a bundle. `None` for a built-in policy.
    pub staleness: Option<Staleness>,
    /// The last bundle refused since startup, if any.
    pub last_rejection: Option<Rejection>,
}

/// State changed only under the activation lock.
#[derive(Debug)]
struct Locked {
    /// The record in force. `None` until startup ran.
    record: Option<Record>,
    /// [`select::Selection::loadable_active`], kept up to date.
    loadable_active: Option<BundleMeta>,
    /// When a bundle was last received or confirmed current. Startup uses
    /// the running bundle's `generated_at`, which is no later than when it
    /// was received, so staleness is never reported late.
    last_received: Option<Timestamp>,
    last_rejection: Option<Rejection>,
}

/// The policy cache. `Send + Sync`; share it in an `Arc`.
#[derive(Debug)]
pub struct PolicyCache {
    active: ArcSwap<Active>,
    locked: Mutex<Locked>,
    setup: Option<CacheSetup>,
    engine: EngineConfig,
    stale_after: StaleAfter,
}

impl PolicyCache {
    /// A cache for an enrolled device. Until [`Self::load_startup`] runs,
    /// the emergency policy decides, so nothing is decided more loosely
    /// than the cache allows.
    pub fn new(setup: CacheSetup) -> Self {
        let engine = setup.engine;
        let stale_after = setup.stale_after;
        Self::with(Some(setup), engine, stale_after)
    }

    /// A cache for a device that is not enrolled: it runs the first-install
    /// policy and refuses every bundle. Enrolment (#62) replaces it with
    /// [`Self::new`].
    pub fn unenrolled(engine: EngineConfig) -> Self {
        Self::with(None, engine, StaleAfter::DEFAULT)
    }

    fn with(setup: Option<CacheSetup>, engine: EngineConfig, stale_after: StaleAfter) -> Self {
        Self {
            active: ArcSwap::from_pointee(Active::builtin(Builtin::Emergency, engine)),
            locked: Mutex::new(Locked {
                record: None,
                loadable_active: None,
                last_received: None,
                last_rejection: None,
            }),
            setup,
            engine,
            stale_after,
        }
    }

    /// The policy deciding now. Hold the returned `Arc` for the whole of one
    /// decision, so the decision and its stamp come from the same policy.
    pub fn current(&self) -> Arc<Active> {
        self.active.load_full()
    }

    fn lock(&self) -> MutexGuard<'_, Locked> {
        // A panic while the lock was held left nothing half-written in
        // memory: every field is replaced whole, after the disk work.
        self.locked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Chooses and loads the policy to run (see the module docs). Blocking
    /// I/O: call it from a blocking thread.
    pub fn load_startup(&self) -> StartupReport {
        let mut locked = self.lock();
        let Some(setup) = &self.setup else {
            self.active.store(Arc::new(Active::builtin(
                Builtin::FirstInstall,
                self.engine,
            )));
            return StartupReport {
                load: Load::FirstInstall,
                findings: Vec::new(),
                rapid_check_in: false,
                io_errors: Vec::new(),
            };
        };
        let mut io_errors = Vec::new();
        if let Err(e) = setup.store.remove(CacheFile::Pending) {
            io_errors.push(format!("deleting pending: {e}"));
        }

        let copies = setup.records.read();
        let copies: Vec<Option<&[u8]>> = copies.iter().map(Option::as_deref).collect();
        let record = RecordCopies::read(&copies, &setup.key, setup.target);

        let mut read = |file| match setup.store.read(file) {
            Ok(bytes) => bytes.map(Arc::<[u8]>::from).map(Ok),
            Err(e) => {
                io_errors.push(format!("reading {file:?}: {e}"));
                // It exists but cannot be read: unreadable, not missing.
                Some(Err(()))
            }
        };
        let mut active = Candidate::examine(read(CacheFile::Active), &*setup.verifier);
        let mut previous = Candidate::examine(read(CacheFile::Previous), &*setup.verifier);

        // Decode only what `select` chose. A bundle that does not decode,
        // validate or compile is refused as unsupported, and the choice is
        // made again; each round refuses one more file, so this ends.
        let (selection, chosen) = loop {
            let selection = select::startup(&Startup {
                target: setup.target,
                record: &record,
                active: active.as_ref().map(|c| c.examination.examined),
                previous: previous.as_ref().map(|c| c.examination.examined),
                mode: setup.mode,
            });
            let candidate = match selection.load {
                Load::Active { .. } => &mut active,
                Load::Previous(_) => &mut previous,
                Load::Emergency | Load::FirstInstall => break (selection, None),
            };
            let Some(c) = candidate.as_mut() else {
                break (selection, None);
            };
            match c.compile(self.engine) {
                Ok(compiled) => break (selection, Some((compiled, c.clone_file()))),
                Err(()) => c.refuse_schema(),
            }
        };

        if selection.rewrite_record
            && let Err(e) = setup.records.write(&selection.record.seal(&setup.key))
        {
            io_errors.push(format!("rewriting the anti-rollback record: {e}"));
        }

        let next = match chosen {
            Some(((engine, header), file)) => Active {
                engine,
                load: selection.load,
                header: Some(header),
                file,
            },
            None => Active::builtin(
                if selection.load == Load::FirstInstall {
                    Builtin::FirstInstall
                } else {
                    Builtin::Emergency
                },
                self.engine,
            ),
        };
        *locked = Locked {
            record: Some(selection.record),
            loadable_active: selection.loadable_active(),
            last_received: next.header.map(|h| clamp_timestamp(h.generated_at)),
            last_rejection: None,
        };
        self.active.store(Arc::new(next));
        StartupReport {
            load: selection.load,
            findings: selection.findings,
            rapid_check_in: selection.rapid_check_in,
            io_errors,
        }
    }

    /// Activates a downloaded cache file (ADR 0007 steps 1 to 5). `now` is
    /// trusted time (#220), recorded as when a bundle was last received.
    /// Blocking I/O: call it from a blocking thread.
    ///
    /// # Errors
    ///
    /// [`ActivateError`]; the current policy then stays in force.
    pub fn activate(&self, file: &[u8], now: Timestamp) -> Result<Activated, ActivateError> {
        let Some(setup) = &self.setup else {
            return Err(ActivateError::NotEnrolled);
        };
        let mut locked = self.lock();
        let Some(record) = locked.record else {
            // Startup has not run, so the record is unknown: refuse rather
            // than activate against a floor of 0.
            return Err(ActivateError::Io(io::Error::other(
                "the policy cache has not started",
            )));
        };
        let result = self.activate_locked(setup, record, &mut locked, file, now);
        if let Err(ActivateError::Rejected(r)) = &result {
            locked.last_rejection = Some(*r);
        }
        result
    }

    fn activate_locked(
        &self,
        setup: &CacheSetup,
        record: Record,
        locked: &mut Locked,
        file: &[u8],
        now: Timestamp,
    ) -> Result<Activated, ActivateError> {
        let candidate = Candidate::from_bytes(Arc::from(file), &*setup.verifier);
        // Step 1: every check, then the version against the floor and the
        // running `active`.
        let plan = match select::pending(
            candidate.examination.examined,
            setup.target,
            record,
            locked.loadable_active,
            setup.mode,
        )
        .map_err(ActivateError::Rejected)?
        {
            PendingOutcome::AlreadyCurrent => {
                locked.last_received = Some(now);
                return Ok(Activated::AlreadyCurrent);
            }
            PendingOutcome::Activate(plan) => plan,
        };
        // Compiled before anything is written, so a bundle that does not
        // build never reaches the disk.
        let (engine, header) = candidate
            .compile(self.engine)
            .map_err(|()| ActivateError::Rejected(Rejection::SchemaUnsupported))?;

        let io = ActivateError::Io;
        // Step 1: write `pending`, and check that what is on disk is what
        // was verified.
        setup.store.write(CacheFile::Pending, file).map_err(io)?;
        let written = setup.store.read(CacheFile::Pending);
        if !matches!(&written, Ok(Some(w)) if w.as_slice() == file) {
            let _ = setup.store.remove(CacheFile::Pending);
            return Err(io(io::Error::other(
                "pending does not read back as written",
            )));
        }
        let undo = |e| {
            let _ = setup.store.remove(CacheFile::Pending);
            io(e)
        };
        // Step 2: the verified bytes of the running `active`, not whatever
        // is on disk now.
        if plan.copy_active_to_previous {
            let current = self.current();
            let Some((bytes, _)) = current.file.as_ref() else {
                return Err(undo(io::Error::other("the active bundle is not in memory")));
            };
            setup
                .store
                .write(CacheFile::Previous, bytes)
                .map_err(undo)?;
        }
        // Step 3.
        setup
            .records
            .write(&plan.record_before_rename.seal(&setup.key))
            .map_err(undo)?;
        // Step 4.
        setup.store.promote_pending().map_err(undo)?;
        // Step 5. The new bundle is `active` now whatever happens here; a
        // record left behind is completed at the next startup.
        if let Err(e) = setup
            .records
            .write(&plan.record_after_rename.seal(&setup.key))
        {
            tracing::warn!(error = %e, "the anti-rollback record was not raised; the next start completes it");
        }

        let load = Load::Active {
            bundle: plan.bundle,
            signed: plan.signed,
        };
        let file = candidate.clone_file();
        self.active.store(Arc::new(Active {
            engine,
            load,
            header: Some(header),
            file,
        }));
        locked.record = Some(plan.record_after_rename);
        locked.loadable_active = plan.signed.then_some(plan.bundle);
        locked.last_received = Some(now);
        Ok(Activated::Activated(plan.bundle))
    }

    /// Records that the server confirmed the running bundle is current
    /// (a check-in with nothing new), which restarts the staleness window.
    pub fn mark_current(&self, now: Timestamp) {
        self.lock().last_received = Some(now);
    }

    /// Rebuilds the full bundle a delta describes, from the running bundle.
    /// The result must then be wrapped and verified as a whole before
    /// [`Self::activate`] takes it: an unsigned delta never changes the
    /// policy (#325).
    ///
    /// # Errors
    ///
    /// [`DeltaError`] if the running policy is not the delta's base, or the
    /// result does not hash to the delta's target. Ask for a full bundle.
    pub fn rebuild_from_delta(&self, delta: &BundleDelta) -> Result<Vec<u8>, DeltaError> {
        let current = self.current();
        let base = current.bundle_bytes().ok_or(DeltaError::WrongBase)?;
        apply(base, delta, &BundleLimits::DEFAULT).map(|(_, bytes)| bytes)
    }

    /// The policy status at `now` (trusted time, #220).
    pub fn status(&self, now: Timestamp) -> PolicyStatus {
        let locked = self.lock();
        let current = self.current();
        let staleness = match (current.header, locked.last_received) {
            (Some(header), Some(received)) => Some(stale::check(
                now,
                received,
                self.stale_after,
                header.expires_at.map(clamp_timestamp),
            )),
            _ => None,
        };
        PolicyStatus {
            load: current.load,
            staleness,
            last_rejection: locked.last_rejection,
        }
    }
}

/// One cache file, examined.
struct Candidate {
    file: Option<Arc<[u8]>>,
    examination: Examination,
}

impl Candidate {
    fn examine(
        read: Option<Result<Arc<[u8]>, ()>>,
        verifier: &dyn EnvelopeVerifier,
    ) -> Option<Self> {
        Some(match read? {
            Ok(file) => Self::from_bytes(file, verifier),
            Err(()) => Self {
                file: None,
                examination: Examination::UNREADABLE,
            },
        })
    }

    fn from_bytes(file: Arc<[u8]>, verifier: &dyn EnvelopeVerifier) -> Self {
        let examination = verifier.examine(&file);
        Self {
            file: Some(file),
            examination,
        }
    }

    fn clone_file(&self) -> Option<(Arc<[u8]>, std::ops::Range<usize>)> {
        self.file
            .clone()
            .map(|f| (f, self.examination.bundle.clone()))
    }

    /// Decodes, validates and compiles the bundle. `select` has already
    /// accepted the envelope, so the signature verified or the mode
    /// tolerates that it did not.
    fn compile(&self, config: EngineConfig) -> Result<(Engine, Header), ()> {
        let bytes = self
            .file
            .as_deref()
            .and_then(|f| f.get(self.examination.bundle.clone()))
            .ok_or(())?;
        // #355 replaces these three steps with `bundle::load` and
        // `Engine::from_loaded`, which also compiles the bundle's inlined
        // library sets for set-scoped rules.
        let bundle = PolicyBundle::decode(bytes, &BundleLimits::DEFAULT).map_err(|_| ())?;
        let policy = bundle.validate().map_err(|_| ())?;
        let engine = Engine::new(policy, config).map_err(|_| ())?;
        Ok((engine, bundle.header))
    }

    fn refuse_schema(&mut self) {
        if let Examined::Parsed {
            schema_supported, ..
        } = &mut self.examination.examined
        {
            *schema_supported = false;
        } else {
            self.examination = Examination::UNREADABLE;
        }
    }
}

/// `micros` as a [`Timestamp`], clamped to the representable years. Only
/// moves a staleness report, never what runs.
fn clamp_timestamp(micros: i64) -> Timestamp {
    Timestamp::from_unix_micros(micros).unwrap_or(if micros < 0 {
        Timestamp::MIN
    } else {
        Timestamp::MAX
    })
}
