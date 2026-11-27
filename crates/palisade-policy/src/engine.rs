//! The engine the agent decides through (#42): a policy snapshot that is
//! swapped atomically, the decision cache, the lazy fact protocol and the
//! per-decision watchdog.
//!
//! An [`Engine`] holds the current [`Snapshot`]: one validated policy with
//! its compiled [`Evaluator`]. [`Engine::load`] builds a new snapshot off
//! the hot path and swaps it in with one atomic store (`arc-swap`). A
//! decision that started on the old snapshot keeps it until it finishes;
//! the next one sees the new policy. Reading the snapshot takes no lock.
//!
//! [`Engine::evaluate`] decides one object:
//!
//! 1. A cache hit returns the cached decision ([`cache`]).
//! 2. Otherwise the evaluator decides with the facts computed so far, or
//!    returns [`NeedFacts`] with what to compute next
//!    ([`crate::evaluate::index`]).
//! 3. A watchdog bounds the time spent. Mandatory denies are evaluated
//!    first; the budget is checked after each match tree, and once it is
//!    spent no further tree is evaluated. A mandatory deny that already
//!    matched then decides, as always (ADR 0004). If the mandatory tier
//!    was not finished, the object is blocked. Otherwise the decision
//!    falls back to [`TimeoutAction`]: `block` (the default when the
//!    object's type is enforced), or `allow_audit`. The result names the
//!    slow rule for the `policy.eval_timeout` health event
//!    ([`EvalTimeout`]).
//!
//! The engine is `Send + Sync`. Time comes from the caller ([`Clock`]), so
//! the engine stays pure and tests can drive time.

pub mod cache;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;

use crate::decision::{Decision, RuleRef, TraceId};
use crate::demand::FactSet;
use crate::evaluate::index::Stop;
use crate::evaluate::{BuildError, Evaluator, NeedFacts, Subject};
use crate::mode::DeviceState;
use crate::model::Mode;
use crate::validate::ValidatedPolicy;

pub use cache::{
    CacheConfig, CacheKey, CacheStats, DecisionCache, FileIdentity, KeyPlan, KeySeed, object_key,
};

self_cell::self_cell!(
    /// A validated policy and the evaluator compiled from it, owned
    /// together so a snapshot can be shared between threads and outlive
    /// the code that loaded it.
    struct Compiled {
        owner: ValidatedPolicy,
        #[covariant]
        dependent: Evaluator,
    }

    impl {Debug}
);

/// One loaded policy, ready to decide.
#[derive(Debug)]
pub struct Snapshot {
    compiled: Compiled,
    generation: u64,
    plan: KeyPlan,
}

impl Snapshot {
    /// Compiles a validated policy.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a match tree does not compile, which validation
    /// rules out.
    pub fn new(policy: ValidatedPolicy, generation: u64) -> Result<Self, BuildError> {
        let compiled = Compiled::try_new(policy, |p| Evaluator::new(p))?;
        // Only the rules the evaluator uses: enabled rules of the rule sets
        // the policy references.
        let plan = {
            let doc = compiled.borrow_owner().document();
            KeyPlan::of(
                doc.rule_sets
                    .iter()
                    .filter(|s| doc.policy.rule_sets.contains(&s.id))
                    .flat_map(|s| &s.rules)
                    .filter(|r| r.enabled),
            )
        };
        Ok(Self {
            compiled,
            generation,
            plan,
        })
    }

    /// The evaluator.
    #[must_use]
    pub fn evaluator(&self) -> &Evaluator<'_> {
        self.compiled.borrow_dependent()
    }

    /// The validated policy.
    #[must_use]
    pub fn policy(&self) -> &ValidatedPolicy {
        self.compiled.borrow_owner()
    }

    /// The generation: different for every snapshot an engine loads.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// What a decision does when its watchdog budget runs out (#42):
/// `on_eval_timeout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutAction {
    /// Block, with the reason `eval_timeout`.
    Block,
    /// Let the object run, reported as `allowed_audit` with
    /// `would_have_been: blocked` and the reason `eval_timeout`.
    AllowAudit,
}

impl TimeoutAction {
    /// The default when the object's type is decided in `mode`, before any
    /// override session: `block` when it enforces, `allow_audit` otherwise,
    /// since a mode that does not enforce would not have blocked either.
    /// Whichever it is, a mandatory deny always blocks (ADR 0004).
    #[must_use]
    pub const fn default_for(mode: Mode) -> Self {
        match mode {
            Mode::Enforce => Self::Block,
            Mode::Disabled | Mode::Monitor | Mode::Audit | Mode::Learning => Self::AllowAudit,
        }
    }
}

/// How the engine is tuned for the kind of machine it runs on (#42). Only
/// sizes and heuristics change; decisions never do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PerfProfile {
    /// A single-user workstation: the default.
    #[default]
    Workstation,
    /// A server: a smaller cache, and no eager hashing.
    Server,
    /// A multi-session host: a larger cache, shared by every session.
    MultiSession,
}

impl PerfProfile {
    /// The cache configuration of the profile.
    #[must_use]
    pub const fn cache(self) -> CacheConfig {
        match self {
            Self::Workstation => CacheConfig {
                max_bytes: 32 << 20,
                shards: 16,
            },
            Self::Server => CacheConfig {
                max_bytes: 8 << 20,
                shards: 8,
            },
            Self::MultiSession => CacheConfig {
                max_bytes: 64 << 20,
                shards: 64,
            },
        }
    }

    /// Whether the agent should hash every executable when it is created,
    /// rather than wait for the engine to ask, given the policy's needs.
    #[must_use]
    pub const fn hash_eagerly(self, required: crate::evaluate::RequiredFacts) -> bool {
        match self {
            Self::Server => false,
            Self::Workstation | Self::MultiSession => required.hash_eagerly(),
        }
    }
}

/// The engine's settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    /// The tuning profile.
    pub profile: PerfProfile,
    /// The decision cache. Defaults to the profile's.
    pub cache: CacheConfig,
    /// The most time one decision may take, in microseconds. Default
    /// 50,000 (50 ms).
    pub budget_micros: u64,
    /// What happens when it is exceeded. `None` means
    /// [`TimeoutAction::default_for`] the mode the object's type is decided
    /// in.
    pub on_timeout: Option<TimeoutAction>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::for_profile(PerfProfile::Workstation)
    }
}

impl EngineConfig {
    /// The defaults for a profile.
    #[must_use]
    pub const fn for_profile(profile: PerfProfile) -> Self {
        Self {
            profile,
            cache: profile.cache(),
            budget_micros: 50_000,
            on_timeout: None,
        }
    }
}

/// The agent's clocks, as the engine reads them.
pub trait Clock {
    /// Monotonic microseconds since an arbitrary origin, for the watchdog
    /// and cache expiry.
    fn monotonic_micros(&self) -> u64;
    /// Whether wall-clock time can be trusted (#220). While it cannot,
    /// nothing is cached, because cached schedule-dependent decisions
    /// would rest on it.
    fn trusted(&self) -> bool {
        true
    }
}

/// The monotonic clock of the process.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock {
    origin: std::time::Instant,
}

impl SystemClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn monotonic_micros(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

/// A decision request: the object, what has been computed, and how the
/// result may be cached.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// The object and its context.
    pub subject: Subject<'a>,
    /// The fact classes computed so far, besides the cheap ones.
    pub computed: FactSet,
    /// The device's state.
    pub state: &'a DeviceState,
    /// The trace ID.
    pub trace_id: TraceId,
    /// The file's identity, for the cache. `None` skips the cache.
    pub file: Option<FileIdentity>,
    /// The logon session, for per-session invalidation on logoff.
    pub session: Option<u32>,
    /// A monotonic time, in microseconds, after which a cached decision
    /// must not be used: for example the next boundary of a schedule the
    /// policy uses (#38).
    pub expires_before: Option<u64>,
}

/// The name of the health event a timed-out decision raises.
pub const EVAL_TIMEOUT_EVENT: &str = "policy.eval_timeout";

/// A decision that ran out of time (#42): the payload of the
/// [`EVAL_TIMEOUT_EVENT`] health event. Raised whenever the budget is
/// spent, including when a mandatory deny then decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvalTimeout {
    /// The rule whose match tree was evaluated last, when the budget was
    /// found spent: the slow one, or the last of the slow ones.
    pub slow_rule: RuleRef,
    /// How long the decision had taken, in microseconds.
    pub elapsed_micros: u64,
}

/// A decision, made now or shared from the cache.
#[derive(Clone, Debug, PartialEq, Eq)]
// A fresh decision is returned by value, so the decision path does not
// allocate a box for it.
#[allow(clippy::large_enum_variant)]
pub enum Decided {
    /// Made by this evaluation.
    Fresh(Decision),
    /// From the cache. It is the decision of the evaluation that cached
    /// it, including that evaluation's trace ID, so an event about this
    /// launch can link back to the full trace (#41).
    Cached(Arc<Decision>),
}

impl core::ops::Deref for Decided {
    type Target = Decision;

    fn deref(&self) -> &Decision {
        match self {
            Self::Fresh(d) => d,
            Self::Cached(d) => d,
        }
    }
}

/// The result of one [`Engine::evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Decided. `None` when the device is disabled.
    Decided(Option<Decided>),
    /// More facts are needed.
    NeedFacts(NeedFacts),
    /// The budget ran out; `decision` is the fallback.
    TimedOut {
        /// The fallback decision.
        decision: Decision,
        /// The health event to raise.
        event: EvalTimeout,
    },
}

/// The engine.
#[derive(Debug)]
pub struct Engine {
    current: ArcSwap<Snapshot>,
    cache: DecisionCache,
    config: EngineConfig,
    next_generation: AtomicU64,
    /// The key of the subject, context and object key hashes, chosen when
    /// the engine starts.
    seed: cache::KeySeed,
}

impl Engine {
    /// An engine that decides with `policy`.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a match tree does not compile, which validation
    /// rules out.
    pub fn new(policy: ValidatedPolicy, config: EngineConfig) -> Result<Self, BuildError> {
        let snapshot = Snapshot::new(policy, 1)?;
        let seed = cache::KeySeed::new();
        Ok(Self {
            current: ArcSwap::from_pointee(snapshot),
            cache: DecisionCache::new(config.cache),
            config,
            next_generation: AtomicU64::new(2),
            seed,
        })
    }

    /// Compiles `policy` and makes it current. Decisions already running
    /// finish on the old snapshot; the cache is purged, and its keys name
    /// the generation, so no decision of the old policy is ever returned
    /// for the new one.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a match tree does not compile; the current policy
    /// stays.
    pub fn load(&self, policy: ValidatedPolicy) -> Result<(), BuildError> {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let snapshot = Snapshot::new(policy, generation)?;
        self.current.store(Arc::new(snapshot));
        self.cache.retain_generation(generation);
        Ok(())
    }

    /// The current snapshot. Holding it keeps that policy alive.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.current.load_full()
    }

    /// The cache's counters.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// The engine's settings.
    #[must_use]
    pub const fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Forgets every cached decision about a file that was written,
    /// renamed or deleted.
    pub fn invalidate_file(&self, volume_serial: u64, file_id: u128) {
        self.cache.invalidate_file(volume_serial, file_id);
    }

    /// Forgets every cached decision made in a logon session that ended.
    pub fn invalidate_session(&self, session: u32) {
        self.cache.invalidate_session(session);
    }

    /// Forgets every cached decision.
    pub fn purge_cache(&self) {
        self.cache.purge();
    }

    /// Decides one object. See the module documentation.
    pub fn evaluate(&self, request: &Request<'_>, clock: &dyn Clock) -> Outcome {
        let start = clock.monotonic_micros();
        let guard = self.current.load();
        let snapshot: &Snapshot = &guard;
        let evaluator = snapshot.evaluator();
        let policy = evaluator.policy();

        let key = request.file.map(|file| CacheKey {
            file,
            object_type: request.subject.object_type,
            subject: snapshot
                .plan
                .subject_key(request.subject.context, &self.seed),
            context: snapshot
                .plan
                .context_key(request.subject.context, &self.seed)
                ^ state_key(request.state),
            object: cache::object_key(request.subject.facts, request.subject.variables, &self.seed),
            policy: snapshot.generation,
        });
        let ttl = u64::from(policy.settings.decision_cache_ttl_secs);
        let use_cache = ttl > 0 && clock.trusted();
        if let (Some(key), true) = (key.as_ref(), use_cache)
            && let Some(d) = self.cache.get(key, start)
        {
            return Outcome::Decided(Some(Decided::Cached(d)));
        }

        let budget = self.config.budget_micros;
        let mut expired = |_: &RuleRef| clock.monotonic_micros().saturating_sub(start) > budget;
        match evaluator.evaluate_watched(
            &request.subject,
            request.computed,
            request.state,
            request.trace_id,
            &mut expired,
        ) {
            Ok(None) => Outcome::Decided(None),
            Ok(Some((decision, unknown))) => {
                if let (Some(key), true) = (key, use_cache)
                    && cache::cacheable(&decision, unknown, request.state.session.is_some())
                {
                    let mut expires = start.saturating_add(ttl.min(86_400) * 1_000_000);
                    if let Some(deadline) = request.expires_before {
                        expires = expires.min(deadline);
                    }
                    // A deadline that has already passed: nothing to keep.
                    if expires > clock.monotonic_micros() {
                        // The caller gets the decision as made now: only a
                        // later hit is `Cached` (#41 records the trace of a
                        // fresh decision, and links hits back to it).
                        self.cache.insert(
                            key,
                            Arc::new(decision.clone()),
                            request.session,
                            expires,
                        );
                    }
                }
                Outcome::Decided(Some(Decided::Fresh(decision)))
            }
            Err(Stop::Need(need)) => Outcome::NeedFacts(need),
            Err(Stop::Timeout(timeout)) => {
                let elapsed = clock.monotonic_micros().saturating_sub(start);
                // The mode the object's type is decided in, before any
                // override session.
                let mode = crate::mode::object_mode(
                    policy,
                    &DeviceState {
                        session: None,
                        ..*request.state
                    },
                    request.subject.object_type,
                );
                let action = self
                    .config
                    .on_timeout
                    .unwrap_or(TimeoutAction::default_for(mode));
                let decision = evaluator.timed_out(
                    &request.subject,
                    &timeout,
                    action == TimeoutAction::Block,
                    request.trace_id,
                );
                Outcome::TimedOut {
                    decision,
                    event: EvalTimeout {
                        slow_rule: timeout.slow_rule,
                        elapsed_micros: elapsed,
                    },
                }
            }
        }
    }
}

/// A key for the device state, folded into the context key: a decision is
/// only reused in the state it was made in.
fn state_key(state: &DeviceState) -> u64 {
    let mode = match state.mode {
        Mode::Disabled => 0u64,
        Mode::Monitor => 1,
        Mode::Audit => 2,
        Mode::Learning => 3,
        Mode::Enforce => 4,
    };
    let connected = match state.connectivity {
        crate::mode::Connectivity::Connected => 0u64,
        crate::mode::Connectivity::Disconnected => 1,
    };
    let session = match state.session {
        None => 0u64,
        Some(crate::mode::SessionKind::Audit) => 1,
        Some(crate::mode::SessionKind::FullBypass) => 2,
    };
    (mode | connected << 3 | session << 4 | u64::from(state.lockdown) << 6)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

#[cfg(test)]
mod tests;
