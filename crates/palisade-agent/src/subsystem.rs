//! The component model: the [`Subsystem`] trait and its run context.
//!
//! A subsystem is one long-running part of the agent (policy cache, server
//! comms, event pipeline and so on). The [`Supervisor`](crate::supervisor::Supervisor)
//! starts subsystems in dependency order, restarts them when they fail and
//! stops them in reverse order with a deadline.
//!
//! The lifecycle of one run:
//!
//! 1. The supervisor calls [`Subsystem::run`] once every dependency is running.
//! 2. The subsystem initialises and calls [`SubsystemContext::set_ready`].
//!    Dependents start only after that. A run that is not ready within
//!    [`Subsystem::start_timeout`] is aborted and counts as a failure.
//! 3. It works until [`SubsystemContext::stopped`] resolves, then finishes by
//!    the returned deadline and returns `Ok(())`. This is the `stop(deadline)`
//!    step of #56. A subsystem still running at the deadline is aborted at its
//!    next `.await`.
//!
//! While it runs, a subsystem can follow OS notifications (session, power,
//! parameter and time changes) through [`SubsystemContext::host_events`];
//! see [`crate::control`].
//!
//! Returning before a stop is requested, with or without an error, or
//! panicking, is a failure: the supervisor restarts the subsystem with
//! backoff. Subsystems must not block async worker threads; blocking work
//! goes through `tokio::task::spawn_blocking` (ADR 0009).

#![forbid(unsafe_code)]

use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use tokio::{
    sync::{broadcast, watch},
    time::Instant,
};

use crate::control::HostEvent;

/// The default for [`Subsystem::start_timeout`].
pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(60);
/// The default for [`Subsystem::stop_timeout`].
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// A boxed, sendable future, as returned by [`Subsystem::run`].
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Whether the agent can work without a subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Criticality {
    /// If it fails permanently, the agent enters
    /// [`AgentState::FailSafe`](crate::lifecycle::AgentState::FailSafe).
    Critical,
    /// If it fails, the agent is
    /// [`AgentState::Degraded`](crate::lifecycle::AgentState::Degraded) and
    /// carries on.
    NonCritical,
}

/// A subsystem's own view of its health while it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Working normally.
    Healthy,
    /// Working with reduced function, with the reason.
    Degraded(String),
    /// Not working, with the reason.
    Unhealthy(String),
}

/// An error returned by a subsystem run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsystemError {
    message: String,
}

impl SubsystemError {
    /// An error with a message. Messages are logged, so they must not contain
    /// secrets.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SubsystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SubsystemError {}

/// One supervised part of the agent.
pub trait Subsystem: Send + Sync + 'static {
    /// A unique, stable name, used in logs, health and dependency lists.
    fn name(&self) -> &'static str;

    /// Whether the agent can work without this subsystem.
    fn criticality(&self) -> Criticality;

    /// Names of the subsystems that must be ready before this one starts.
    fn dependencies(&self) -> &[&'static str] {
        &[]
    }

    /// How long the subsystem may take to call
    /// [`SubsystemContext::set_ready`]. A run that is not ready by then is
    /// aborted and counts as a failed start.
    fn start_timeout(&self) -> Duration {
        DEFAULT_START_TIMEOUT
    }

    /// How long the subsystem gets to finish after a stop is requested. The
    /// supervisor caps it by what is left of the overall shutdown budget.
    fn stop_timeout(&self) -> Duration {
        DEFAULT_STOP_TIMEOUT
    }

    /// Runs the subsystem until a stop is requested (see the module docs).
    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>>;

    /// The subsystem's own health. Called only while it is running, from
    /// health reports; it must be cheap and must not block.
    fn health(&self) -> Health {
        Health::Healthy
    }
}

/// What a subsystem run gets from the supervisor.
#[derive(Debug)]
pub struct SubsystemContext {
    name: &'static str,
    ready: watch::Sender<bool>,
    stop: watch::Receiver<Option<Instant>>,
    events: broadcast::Sender<HostEvent>,
}

impl SubsystemContext {
    pub(crate) fn new(
        name: &'static str,
        ready: watch::Sender<bool>,
        stop: watch::Receiver<Option<Instant>>,
        events: broadcast::Sender<HostEvent>,
    ) -> Self {
        Self {
            name,
            ready,
            stop,
            events,
        }
    }

    /// A receiver for OS notifications published from now on. Subscribe
    /// before reading the state the events update (for example, list the
    /// sessions after subscribing), so no change falls in between. A
    /// receiver that falls more than
    /// [`HOST_EVENT_CAPACITY`](crate::control::HOST_EVENT_CAPACITY) events
    /// behind gets `Lagged` and must read the state again.
    pub fn host_events(&self) -> broadcast::Receiver<HostEvent> {
        self.events.subscribe()
    }

    /// The subsystem's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Marks the subsystem ready, so its dependents can start. Idempotent.
    pub fn set_ready(&self) {
        self.ready.send_replace(true);
    }

    /// The stop deadline, once a stop has been requested.
    pub fn stop_deadline(&self) -> Option<Instant> {
        *self.stop.borrow()
    }

    /// Resolves when a stop is requested, with the deadline by which the run
    /// must return.
    pub async fn stopped(&self) -> Instant {
        wait_stop(&mut self.stop.clone()).await
    }
}

/// Waits for a stop request and returns its deadline. If the supervisor is
/// gone, the stop is immediate.
pub(crate) async fn wait_stop(stop: &mut watch::Receiver<Option<Instant>>) -> Instant {
    match stop.wait_for(Option::is_some).await {
        Ok(deadline) => (*deadline).unwrap_or_else(Instant::now),
        Err(_) => Instant::now(),
    }
}
