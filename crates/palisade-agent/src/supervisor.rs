//! The supervisor: ordered start, restart with backoff, panic containment
//! and ordered shutdown with deadlines.
//!
//! - **Start order** follows the declared dependency graph, which must be
//!   acyclic. Ties keep registration order, so the order is deterministic.
//!   A subsystem starts once all its dependencies are ready.
//! - **Failure** means a run returned an error, returned before a stop was
//!   requested, panicked, or was not ready within its
//!   [`start_timeout`](crate::subsystem::Subsystem::start_timeout). Each run is
//!   its own tokio task, so a panic is caught at the task boundary (the same
//!   `catch_unwind` boundary that `tokio::spawn` provides) and affects that
//!   subsystem only. The process panic hook
//!   ([`crate::host::install_panic_hook`]) logs it with a backtrace.
//! - **Restart** follows exponential backoff from
//!   [`RestartPolicy::initial_backoff`] to [`RestartPolicy::max_backoff`]
//!   (1 s to 5 min). A run that stayed ready for
//!   [`RestartPolicy::stable_after`] resets the backoff.
//! - **Circuit breaker**: [`RestartPolicy::panic_limit`] panics within
//!   [`RestartPolicy::panic_window`] (3 in 10 minutes) mark the subsystem
//!   [`SubsystemStatus::Failed`]; it is not restarted again. Errors alone
//!   never trip the breaker: they keep retrying at the maximum backoff. Panics
//!   that a subsystem catches itself, such as one per parsed file, never reach
//!   the supervisor and do not count (ADR 0012).
//! - **Agent state** is derived from the subsystems. `FailSafe` as soon as
//!   a critical subsystem has failed, even during startup. Otherwise
//!   `Starting` until every subsystem has had its first outcome, then
//!   `Degraded` if any subsystem is not running, and `Running` if all are. A
//!   dependency that fails or restarts does not stop its running dependents.
//! - **Shutdown** first stops every subsystem that is not running (waiting,
//!   restarting or failed), so nothing starts during shutdown. It then stops
//!   the running subsystems in reverse start order, so dependents stop
//!   before what they depend on. Each gets [`Subsystem::stop_timeout`],
//!   capped by the overall budget; a subsystem that misses its deadline is
//!   aborted, so shutdown always finishes within the budget. A running
//!   subsystem that fails while others are still stopping is not restarted,
//!   and its failure is reported in the [`ShutdownReport`].
//! - **Timeouts** longer than about ten years are capped, so no deadline
//!   computation can overflow.

#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    fmt,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use tokio::{
    sync::watch,
    task::{JoinError, JoinHandle},
    time::{Instant, sleep_until},
};

use crate::{
    lifecycle::{AgentState, Lifecycle},
    subsystem::{Criticality, Health, Subsystem, SubsystemContext, wait_stop},
};

/// Restart and circuit-breaker settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// Delay before the first restart.
    pub initial_backoff: Duration,
    /// Upper bound of the delay; it doubles per consecutive failure up to this.
    pub max_backoff: Duration,
    /// A run that stayed ready this long resets the backoff.
    pub stable_after: Duration,
    /// Panics within [`Self::panic_window`] that mark a subsystem failed.
    pub panic_limit: usize,
    /// The sliding window for [`Self::panic_limit`].
    pub panic_window: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5 * 60),
            stable_after: Duration::from_secs(60),
            panic_limit: 3,
            panic_window: Duration::from_secs(10 * 60),
        }
    }
}

impl RestartPolicy {
    /// Whether a panic at `at` has left the panic window by `now`.
    fn expired(&self, now: Instant, at: Instant) -> bool {
        now.duration_since(at) > self.panic_window
    }

    /// The delay before restart number `failures` (1-based) in a row.
    pub fn backoff(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(31);
        self.initial_backoff
            .saturating_mul(1u32 << shift)
            .min(self.max_backoff)
    }
}

/// A subsystem set that cannot be supervised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// Two subsystems have the same name.
    DuplicateName(&'static str),
    /// A subsystem depends on a name that is not registered.
    UnknownDependency {
        /// The subsystem.
        subsystem: &'static str,
        /// The missing dependency.
        dependency: &'static str,
    },
    /// The dependency graph has a cycle through these subsystems.
    DependencyCycle(Vec<&'static str>),
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName(name) => write!(f, "subsystem `{name}` is registered twice"),
            Self::UnknownDependency {
                subsystem,
                dependency,
            } => write!(
                f,
                "subsystem `{subsystem}` depends on unknown subsystem `{dependency}`"
            ),
            Self::DependencyCycle(names) => {
                write!(f, "subsystem dependency cycle among: {}", names.join(", "))
            }
        }
    }
}

impl std::error::Error for SupervisorError {}

/// What the supervisor knows about one subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubsystemStatus {
    /// Waiting for its dependencies to become ready.
    WaitingForDependencies,
    /// Running, not yet ready.
    Starting,
    /// Running and ready.
    Running,
    /// Waiting to restart after a failure.
    Restarting {
        /// Why the last run failed.
        reason: String,
        /// When the next run starts.
        retry_at: Instant,
    },
    /// Stopped for good by the circuit breaker; not restarted.
    Failed {
        /// Why.
        reason: String,
    },
    /// Asked to stop, not finished yet.
    Stopping,
    /// Stopped during shutdown.
    Stopped,
}

/// One row of a [`HealthReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemReport {
    /// The subsystem name.
    pub name: &'static str,
    /// Its criticality.
    pub criticality: Criticality,
    /// Its supervision status.
    pub status: SubsystemStatus,
    /// How many times it was restarted.
    pub restarts: u32,
    /// Panics counted inside the current panic window.
    pub recent_panics: usize,
    /// Its own health, if it is running.
    pub health: Option<Health>,
}

/// A snapshot of the agent state and every subsystem, in start order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    /// The agent operating state.
    pub state: AgentState,
    /// One row per subsystem, in start order.
    pub subsystems: Vec<SubsystemReport>,
}

/// How one subsystem ended during shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// It returned `Ok(())` by its deadline.
    Clean,
    /// It returned an error while stopping.
    Error(String),
    /// It panicked while stopping.
    Panicked(String),
    /// It missed its deadline and was aborted.
    Aborted,
    /// It was not running (waiting, restarting or failed).
    NotRunning,
}

/// The result of [`SupervisorHandle::shutdown`], in stop order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// One entry per subsystem, in the order they were stopped.
    pub outcomes: Vec<(&'static str, StopOutcome)>,
}

impl ShutdownReport {
    /// Whether every subsystem that was running stopped cleanly.
    pub fn is_clean(&self) -> bool {
        self.outcomes
            .iter()
            .all(|(_, o)| matches!(o, StopOutcome::Clean | StopOutcome::NotRunning))
    }
}

/// A validated set of subsystems, ready to start.
pub struct Supervisor {
    inner: Arc<Inner>,
}

impl fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Supervisor")
            .field("start_order", &self.start_order())
            .finish_non_exhaustive()
    }
}

impl Supervisor {
    /// Validates names and dependencies and computes the start order.
    pub fn new(
        subsystems: Vec<Arc<dyn Subsystem>>,
        policy: RestartPolicy,
    ) -> Result<Self, SupervisorError> {
        let names: Vec<&'static str> = subsystems.iter().map(|s| s.name()).collect();
        for (i, name) in names.iter().enumerate() {
            if names[..i].contains(name) {
                return Err(SupervisorError::DuplicateName(name));
            }
        }
        let mut slots = Vec::with_capacity(subsystems.len());
        for subsystem in subsystems {
            let mut deps = Vec::new();
            for dependency in subsystem.dependencies() {
                let index = names.iter().position(|n| n == dependency).ok_or(
                    SupervisorError::UnknownDependency {
                        subsystem: subsystem.name(),
                        dependency,
                    },
                )?;
                if !deps.contains(&index) {
                    deps.push(index);
                }
            }
            slots.push(Slot {
                subsystem,
                deps,
                up: watch::channel(false).0,
                stop: watch::channel(None).0,
            });
        }
        let order = start_order(&slots).map_err(|stuck| {
            SupervisorError::DependencyCycle(stuck.into_iter().map(|i| names[i]).collect())
        })?;
        let shared = Shared {
            lifecycle: Lifecycle::new(),
            slots: slots.iter().map(|_| SlotState::default()).collect(),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                slots,
                order,
                policy,
                shared: Mutex::new(shared),
                state: watch::channel(AgentState::Starting).0,
                draining: watch::channel(false).0,
            }),
        })
    }

    /// Subsystem names in start order.
    pub fn start_order(&self) -> Vec<&'static str> {
        self.inner
            .order
            .iter()
            .map(|&i| self.inner.slots[i].subsystem.name())
            .collect()
    }

    /// Starts supervising. Must be called inside a tokio runtime.
    pub fn start(self) -> SupervisorHandle {
        let inner = self.inner;
        inner.update(|_| {});
        let runners = (0..inner.slots.len())
            .map(|i| Some(tokio::spawn(run_slot(Arc::clone(&inner), i))))
            .collect();
        SupervisorHandle { inner, runners }
    }
}

/// A running supervisor.
#[derive(Debug)]
pub struct SupervisorHandle {
    inner: Arc<Inner>,
    runners: Vec<Option<JoinHandle<()>>>,
}

impl SupervisorHandle {
    /// The current agent state.
    pub fn state(&self) -> AgentState {
        self.inner.state.borrow().clone()
    }

    /// A receiver that sees every agent state change.
    pub fn subscribe(&self) -> watch::Receiver<AgentState> {
        self.inner.state.subscribe()
    }

    /// A health snapshot. Calls [`Subsystem::health`] on running subsystems.
    pub fn report(&self) -> HealthReport {
        let (state, rows) = {
            let shared = self.inner.lock();
            let rows: Vec<_> = self
                .inner
                .order
                .iter()
                .map(|&i| (i, shared.slots[i].clone()))
                .collect();
            (shared.lifecycle.state().clone(), rows)
        };
        let now = Instant::now();
        let subsystems = rows
            .into_iter()
            .map(|(i, slot)| {
                let subsystem = &self.inner.slots[i].subsystem;
                let health = (slot.status == SubsystemStatus::Running).then(|| {
                    std::panic::catch_unwind(AssertUnwindSafe(|| subsystem.health()))
                        .unwrap_or_else(|_| Health::Unhealthy("health check panicked".into()))
                });
                SubsystemReport {
                    name: subsystem.name(),
                    criticality: subsystem.criticality(),
                    status: slot.status,
                    restarts: slot.starts.saturating_sub(1),
                    recent_panics: slot
                        .panics
                        .iter()
                        .filter(|&&t| !self.inner.policy.expired(now, t))
                        .count(),
                    health,
                }
            })
            .collect();
        HealthReport { state, subsystems }
    }

    /// Stops every subsystem in reverse start order within `budget`.
    pub async fn shutdown(mut self, budget: Duration) -> ShutdownReport {
        let overall = after(Instant::now(), budget);
        self.inner.begin_draining();
        self.inner.set_agent_state(AgentState::Stopping);
        let mut outcomes = Vec::with_capacity(self.runners.len());
        for &i in self.inner.order.iter().rev() {
            let slot = &self.inner.slots[i];
            let deadline = overall.min(after(Instant::now(), slot.subsystem.stop_timeout()));
            slot.stop.send_replace(Some(deadline));
            if let Some(runner) = self.runners[i].take() {
                // A runner only awaits timers and channels, and aborts its
                // subsystem at the deadline, so this wait is bounded.
                let _ = runner.await;
            }
            let outcome = self.inner.lock().slots[i]
                .outcome
                .clone()
                .unwrap_or(StopOutcome::Aborted);
            outcomes.push((slot.subsystem.name(), outcome));
        }
        self.inner.set_agent_state(AgentState::Stopped);
        ShutdownReport { outcomes }
    }
}

/// Dropping a handle gives every subsystem that has not been stopped yet an
/// immediate stop deadline, so running subsystems are aborted. That covers a
/// handle dropped without [`SupervisorHandle::shutdown`] and a shutdown
/// future dropped before it finished; after a full shutdown it does nothing.
impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        self.inner.begin_draining();
        let now = Instant::now();
        for slot in &self.inner.slots {
            slot.stop.send_if_modified(|stop| {
                let unset = stop.is_none();
                if unset {
                    *stop = Some(now);
                }
                unset
            });
        }
    }
}

struct Slot {
    subsystem: Arc<dyn Subsystem>,
    deps: Vec<usize>,
    /// Whether the current run is ready. Written only by the slot's runner.
    up: watch::Sender<bool>,
    /// The stop deadline, once shutdown reaches this slot.
    stop: watch::Sender<Option<Instant>>,
}

#[derive(Debug, Clone)]
struct SlotState {
    status: SubsystemStatus,
    /// The first run has had an outcome (ready, failed or stopped).
    settled: bool,
    starts: u32,
    panics: VecDeque<Instant>,
    outcome: Option<StopOutcome>,
}

impl Default for SlotState {
    fn default() -> Self {
        Self {
            status: SubsystemStatus::WaitingForDependencies,
            settled: false,
            starts: 0,
            panics: VecDeque::new(),
            outcome: None,
        }
    }
}

struct Shared {
    lifecycle: Lifecycle,
    slots: Vec<SlotState>,
}

struct Inner {
    slots: Vec<Slot>,
    order: Vec<usize>,
    policy: RestartPolicy,
    shared: Mutex<Shared>,
    state: watch::Sender<AgentState>,
    /// Set when shutdown begins: subsystems that are not running stay down.
    draining: watch::Sender<bool>,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner").finish_non_exhaustive()
    }
}

/// How one run ended.
enum RunEnd {
    Finished(Result<Result<(), crate::subsystem::SubsystemError>, JoinError>),
    StopDeadline,
    StartTimeout,
}

/// Why a run ended before a stop was requested.
enum Failure {
    Error(String),
    Panic(String),
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        // No code panics while holding the lock, but a poisoned lock must not
        // take the supervisor down with it.
        self.shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn name(&self, i: usize) -> &'static str {
        self.slots[i].subsystem.name()
    }

    /// Applies `f` to the shared state and re-derives the agent state.
    fn update(&self, f: impl FnOnce(&mut Shared)) {
        let mut shared = self.lock();
        f(&mut shared);
        if matches!(
            shared.lifecycle.state(),
            AgentState::Stopping | AgentState::Stopped
        ) {
            return;
        }
        let starting = *shared.lifecycle.state() == AgentState::Starting;
        let next = self.derive(&shared.slots, starting);
        self.apply(&mut shared, next);
    }

    /// Starts draining under the shared lock, so it is ordered with the
    /// start decision in `run_slot`.
    fn begin_draining(&self) {
        let _shared = self.lock();
        self.draining.send_replace(true);
    }

    fn set_status(&self, i: usize, status: SubsystemStatus) {
        self.update(|s| s.slots[i].status = status);
    }

    fn set_agent_state(&self, next: AgentState) {
        let mut shared = self.lock();
        self.apply(&mut shared, next);
    }

    fn apply(&self, shared: &mut Shared, next: AgentState) {
        match shared.lifecycle.transition(next) {
            Ok(Some(previous)) => {
                let state = shared.lifecycle.state().clone();
                match &state {
                    AgentState::FailSafe(_) => {
                        tracing::error!(from = %previous, to = %state, "agent state changed")
                    }
                    AgentState::Degraded(_) => {
                        tracing::warn!(from = %previous, to = %state, "agent state changed")
                    }
                    _ => tracing::info!(from = %previous, to = %state, "agent state changed"),
                }
                self.state.send_replace(state);
            }
            Ok(None) => {}
            // `FailSafe` is left only by stopping; a derived `Degraded` or
            // `Running` after it is ignored.
            Err(e) => tracing::debug!(%e, "agent state change ignored"),
        }
    }

    /// The agent state the subsystem statuses imply. `Starting` is only
    /// derived while the agent is still starting; later, a subsystem that is
    /// starting again is reported as a `Degraded` reason.
    fn derive(&self, slots: &[SlotState], starting: bool) -> AgentState {
        let running = |i: usize| slots[i].status == SubsystemStatus::Running;
        // A subsystem still waiting behind a dependency that has had its
        // outcome and is down counts as settled, so startup cannot hang on
        // it. One that has already started settles on its own outcome.
        let mut settled = vec![false; slots.len()];
        for &i in &self.order {
            settled[i] = slots[i].settled
                || (slots[i].status == SubsystemStatus::WaitingForDependencies
                    && self.slots[i]
                        .deps
                        .iter()
                        .any(|&d| settled[d] && !running(d)));
        }
        let critical: Vec<String> = self
            .order
            .iter()
            .filter(|&&i| self.slots[i].subsystem.criticality() == Criticality::Critical)
            .filter_map(|&i| match &slots[i].status {
                SubsystemStatus::Failed { reason } => Some(format!(
                    "critical subsystem {} failed: {reason}",
                    self.name(i)
                )),
                _ => None,
            })
            .collect();
        if !critical.is_empty() {
            return AgentState::FailSafe(critical.join("; "));
        }
        if starting && settled.iter().any(|s| !s) {
            return AgentState::Starting;
        }
        let mut reasons = Vec::new();
        for &i in &self.order {
            let name = self.name(i);
            let reason = match &slots[i].status {
                SubsystemStatus::Running => continue,
                SubsystemStatus::Failed { reason } => format!("{name} failed: {reason}"),
                SubsystemStatus::Restarting { reason, .. } => {
                    format!("{name} restarting after: {reason}")
                }
                SubsystemStatus::WaitingForDependencies => {
                    format!("{name} waiting for dependencies")
                }
                SubsystemStatus::Starting => format!("{name} starting"),
                SubsystemStatus::Stopping | SubsystemStatus::Stopped => {
                    format!("{name} stopped")
                }
            };
            reasons.push(reason);
        }
        if reasons.is_empty() {
            AgentState::Running
        } else {
            AgentState::Degraded(reasons)
        }
    }

    fn deps_up(&self, i: usize) -> bool {
        self.slots[i]
            .deps
            .iter()
            .all(|&d| *self.slots[d].up.borrow())
    }

    async fn wait_deps(&self, i: usize) {
        while !self.deps_up(i) {
            for &d in &self.slots[i].deps {
                let mut up = self.slots[d].up.subscribe();
                // The sender lives as long as `self`, so this cannot fail.
                let _ = up.wait_for(|up| *up).await;
            }
        }
    }

    /// Records a failure and returns when to retry, or `None` if the circuit
    /// breaker has tripped.
    fn record_failure(&self, i: usize, failure: Failure, consecutive: u32) -> Option<Instant> {
        let name = self.name(i);
        let now = Instant::now();
        let mut retry_at = None;
        self.update(|shared| {
            let slot = &mut shared.slots[i];
            slot.settled = true;
            let panicked = matches!(failure, Failure::Panic(_));
            let reason = match failure {
                Failure::Error(message) => {
                    tracing::warn!(subsystem = name, error = %message, "subsystem failed");
                    message
                }
                Failure::Panic(message) => {
                    tracing::error!(subsystem = name, panic = %message, "subsystem panicked");
                    slot.panics.push_back(now);
                    while slot
                        .panics
                        .front()
                        .is_some_and(|&t| self.policy.expired(now, t))
                    {
                        slot.panics.pop_front();
                    }
                    format!("panicked: {message}")
                }
            };
            if panicked && slot.panics.len() >= self.policy.panic_limit {
                tracing::error!(
                    subsystem = name,
                    panics = slot.panics.len(),
                    "subsystem panicked too often; not restarting it"
                );
                slot.status = SubsystemStatus::Failed {
                    reason: format!(
                        "{} panics within {:?}; last {reason}",
                        slot.panics.len(),
                        self.policy.panic_window
                    ),
                };
            } else {
                let at = after(now, self.policy.backoff(consecutive));
                retry_at = Some(at);
                slot.status = SubsystemStatus::Restarting {
                    reason,
                    retry_at: at,
                };
            }
        });
        retry_at
    }

    fn finish(&self, i: usize, outcome: StopOutcome) {
        self.update(|shared| {
            let slot = &mut shared.slots[i];
            slot.status = SubsystemStatus::Stopped;
            slot.outcome = Some(outcome);
        });
    }
}

/// Longest delay the supervisor schedules. Longer timeouts, budgets or
/// backoffs from a custom [`Subsystem`] or [`RestartPolicy`] are capped to
/// this, so adding them to the clock cannot overflow.
const MAX_DELAY: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// `now + delay`, capped at [`MAX_DELAY`] and never panicking.
fn after(now: Instant, delay: Duration) -> Instant {
    now.checked_add(delay.min(MAX_DELAY)).unwrap_or(now)
}

/// Kahn's algorithm, taking the lowest registration index first. Returns the
/// indices left over if there is a cycle.
fn start_order(slots: &[Slot]) -> Result<Vec<usize>, Vec<usize>> {
    let mut placed = vec![false; slots.len()];
    let mut order = Vec::with_capacity(slots.len());
    while order.len() < slots.len() {
        let next =
            (0..slots.len()).find(|&i| !placed[i] && slots[i].deps.iter().all(|&d| placed[d]));
        match next {
            Some(i) => {
                placed[i] = true;
                order.push(i);
            }
            None => return Err(cycle_members(slots, placed)),
        }
    }
    Ok(order)
}

/// The unplaced subsystems left after removing, repeatedly, those that no
/// other unplaced subsystem depends on. What is left lies on a cycle or
/// between two.
fn cycle_members(slots: &[Slot], placed: Vec<bool>) -> Vec<usize> {
    let mut left: Vec<bool> = placed.iter().map(|p| !p).collect();
    loop {
        let sink = (0..slots.len())
            .find(|&i| left[i] && !(0..slots.len()).any(|j| left[j] && slots[j].deps.contains(&i)));
        match sink {
            Some(i) => left[i] = false,
            None => return (0..slots.len()).filter(|&i| left[i]).collect(),
        }
    }
}

fn panic_message(error: JoinError) -> String {
    match error.try_into_panic() {
        Ok(payload) => payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned()),
        Err(error) => format!("task ended without a result: {error}"),
    }
}

/// Resolves when this slot is told to stop or shutdown has begun. Used where
/// the slot has no run in progress, so it must not start a new one.
async fn wait_idle_stop(
    stop: &mut watch::Receiver<Option<Instant>>,
    draining: &mut watch::Receiver<bool>,
) {
    tokio::select! {
        _ = wait_stop(stop) => {}
        // The sender lives as long as the supervisor; if it is gone, stop.
        _ = draining.wait_for(|d| *d) => {}
    }
}

/// The supervision loop for one subsystem.
async fn run_slot(sup: Arc<Inner>, i: usize) {
    let slot = &sup.slots[i];
    let name = slot.subsystem.name();
    let mut stop = slot.stop.subscribe();
    let mut draining = sup.draining.subscribe();
    let mut consecutive: u32 = 0;
    loop {
        if !sup.deps_up(i) {
            sup.set_status(i, SubsystemStatus::WaitingForDependencies);
        }
        tokio::select! {
            biased;
            () = wait_idle_stop(&mut stop, &mut draining) => {
                return sup.finish(i, StopOutcome::NotRunning);
            }
            () = sup.wait_deps(i) => {}
        }

        // Decided under the lock that `shutdown` takes to set `draining`, so
        // no run starts once shutdown has begun.
        let mut claimed = false;
        sup.update(|s| {
            if !*sup.draining.borrow() {
                claimed = true;
                s.slots[i].status = SubsystemStatus::Starting;
                s.slots[i].starts = s.slots[i].starts.saturating_add(1);
            }
        });
        if !claimed {
            return sup.finish(i, StopOutcome::NotRunning);
        }
        tracing::info!(subsystem = name, "starting subsystem");
        let (ready_tx, mut ready_rx) = watch::channel(false);
        let ctx = SubsystemContext::new(name, ready_tx, slot.stop.subscribe());
        let mut task = tokio::spawn(Arc::clone(&slot.subsystem).run(ctx));
        let start_deadline = after(Instant::now(), slot.subsystem.start_timeout());
        let mut ready_open = true;
        let mut ready_since = None;
        let mut deadline = None;
        let end = loop {
            tokio::select! {
                result = &mut task => break RunEnd::Finished(result),
                changed = ready_rx.changed(), if ready_open && ready_since.is_none() && deadline.is_none() => {
                    if changed.is_err() {
                        ready_open = false;
                    } else if *ready_rx.borrow_and_update() {
                        ready_since = Some(Instant::now());
                        slot.up.send_replace(true);
                        sup.update(|s| {
                            s.slots[i].status = SubsystemStatus::Running;
                            s.slots[i].settled = true;
                        });
                        tracing::info!(subsystem = name, "subsystem ready");
                    }
                }
                at = wait_stop(&mut stop), if deadline.is_none() => {
                    deadline = Some(at);
                    sup.set_status(i, SubsystemStatus::Stopping);
                }
                () = sleep_until(deadline.unwrap_or(start_deadline)), if deadline.is_some() => {
                    tracing::warn!(subsystem = name, "subsystem missed its stop deadline; aborting it");
                    task.abort();
                    break RunEnd::StopDeadline;
                }
                () = sleep_until(start_deadline), if deadline.is_none() && ready_since.is_none() => {
                    tracing::warn!(subsystem = name, "subsystem did not become ready in time; aborting it");
                    task.abort();
                    // Wait for the aborted run to end, so two runs never
                    // overlap, unless shutdown arrives first.
                    tokio::select! {
                        biased;
                        () = wait_idle_stop(&mut stop, &mut draining) => {
                            slot.up.send_replace(false);
                            return sup.finish(i, StopOutcome::Aborted);
                        }
                        _ = &mut task => {}
                    }
                    break RunEnd::StartTimeout;
                }
            }
        };
        slot.up.send_replace(false);

        let stopping = deadline.is_some() || stop.borrow().is_some();
        if stopping || *draining.borrow() {
            // Shutdown has begun. A run that ends before its own stop
            // request failed while others were stopping; report it, and do
            // not restart it.
            let outcome = match end {
                RunEnd::StopDeadline | RunEnd::StartTimeout => StopOutcome::Aborted,
                RunEnd::Finished(Ok(Ok(()))) if stopping => StopOutcome::Clean,
                RunEnd::Finished(Ok(Ok(()))) => {
                    StopOutcome::Error("exited before its stop request".to_owned())
                }
                RunEnd::Finished(Ok(Err(e))) => StopOutcome::Error(e.message().to_owned()),
                RunEnd::Finished(Err(e)) if e.is_panic() => StopOutcome::Panicked(panic_message(e)),
                RunEnd::Finished(Err(_)) => StopOutcome::Aborted,
            };
            if !stopping {
                tracing::warn!(
                    subsystem = name,
                    ?outcome,
                    "subsystem ended during shutdown"
                );
            }
            return sup.finish(i, outcome);
        }

        let failure = match end {
            RunEnd::Finished(Ok(Ok(()))) => {
                Failure::Error("exited before a stop was requested".to_owned())
            }
            RunEnd::Finished(Ok(Err(e))) => Failure::Error(e.message().to_owned()),
            RunEnd::Finished(Err(e)) if e.is_panic() => Failure::Panic(panic_message(e)),
            RunEnd::Finished(Err(e)) => Failure::Error(format!("task ended without a result: {e}")),
            RunEnd::StartTimeout => Failure::Error(format!(
                "not ready within {:?}",
                slot.subsystem.start_timeout()
            )),
            // Only reachable after a stop request, handled above.
            RunEnd::StopDeadline => Failure::Error("aborted".to_owned()),
        };
        if ready_since.is_some_and(|t: Instant| t.elapsed() >= sup.policy.stable_after) {
            consecutive = 0;
        }
        consecutive = consecutive.saturating_add(1);
        let Some(retry_at) = sup.record_failure(i, failure, consecutive) else {
            // Tripped: stay down until shutdown.
            wait_idle_stop(&mut stop, &mut draining).await;
            return sup.finish(i, StopOutcome::NotRunning);
        };
        tokio::select! {
            biased;
            () = wait_idle_stop(&mut stop, &mut draining) => {
                return sup.finish(i, StopOutcome::NotRunning);
            }
            () = sleep_until(retry_at) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let p = RestartPolicy::default();
        let secs: Vec<u64> = (1..=11).map(|n| p.backoff(n).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
        assert_eq!(p.backoff(0), Duration::from_secs(1));
        assert_eq!(p.backoff(u32::MAX), Duration::from_secs(300));
    }
}
