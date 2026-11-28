//! Host notifications and stop gating, independent of the service control
//! manager (SCM).
//!
//! The SCM delivers controls to `palisade_agent::service` on its own thread.
//! That module translates each one into a [`StopRequest`](crate::host::StopRequest)
//! or a [`HostEvent`], and the host publishes host events to every running
//! subsystem through [`SubsystemContext::host_events`](crate::subsystem::SubsystemContext::host_events).
//! This module holds the platform-independent half, so the routing and the
//! gating rules are tested on every OS.
//!
//! | Control | Becomes | Consumed by |
//! |---|---|---|
//! | `STOP` | a stop with a 20 s budget, if [`TamperGuard`] allows it | the host |
//! | `PRESHUTDOWN`, `SHUTDOWN` | a stop with a 10 s budget | the host |
//! | `POWEREVENT` | [`HostEvent::Power`] | server comms (#62): an immediate check-in on resume |
//! | `SESSIONCHANGE` | [`HostEvent::Session`] | ETW (#59), multi-session support (#68) |
//! | `PARAMCHANGE` | [`HostEvent::ParamChange`] | the `config` subsystem: reload the local file |
//! | `TIMECHANGE` | [`HostEvent::TimeChange`] | the clock monitor (ISM-0988) |
//!
//! Volume arrival and removal (`DEVICEEVENT`, for inventory #60) need a
//! device-interface registration that the `windows-service` crate does not
//! offer, so they arrive with a control handler of the agent's own in
//! `palisade_agent::ffi`.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::watch;

/// How many host events a subsystem may fall behind before it misses some.
/// A subsystem that falls further behind gets
/// [`RecvError::Lagged`](tokio::sync::broadcast::error::RecvError::Lagged)
/// and must resynchronise from the OS (for example, enumerate the sessions
/// again) rather than assume nothing changed.
pub const HOST_EVENT_CAPACITY: usize = 256;

/// A change in a Windows session (`SERVICE_CONTROL_SESSIONCHANGE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionChange {
    /// A session connected to the console.
    ConsoleConnect,
    /// A session disconnected from the console.
    ConsoleDisconnect,
    /// A session connected from a remote terminal.
    RemoteConnect,
    /// A session disconnected from a remote terminal.
    RemoteDisconnect,
    /// A user logged on.
    Logon,
    /// A user logged off.
    Logoff,
    /// The session was locked.
    Lock,
    /// The session was unlocked.
    Unlock,
    /// The session's remote-control status changed.
    RemoteControl,
    /// A session was created.
    Create,
    /// A session was terminated.
    Terminate,
}

/// A power change (`SERVICE_CONTROL_POWEREVENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PowerChange {
    /// The machine is about to suspend.
    Suspend,
    /// The machine resumed from a suspend, whether or not a user is present.
    Resume,
}

/// A notification from the OS that subsystems may act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostEvent {
    /// A session changed.
    Session {
        /// What happened.
        change: SessionChange,
        /// The Windows session ID.
        session_id: u32,
    },
    /// The machine is suspending or has resumed.
    Power(PowerChange),
    /// The service's parameters changed: reload the local configuration.
    ParamChange,
    /// The system time was changed.
    TimeChange,
}

/// Decides whether the service accepts `STOP` from the SCM (#56, #220).
///
/// The service offers `STOP` to the SCM only while
/// [`stop_permission`](Self::stop_permission) holds `true`. While it holds
/// `false`, `sc stop` and the services console fail with "the requested
/// control is not valid for this service", and only a system shutdown stops
/// the agent. The service re-reports its status whenever the value changes.
///
/// The gate is applied through the accepted controls, not by refusing a
/// `STOP` that has arrived: the `windows-service` crate frees its handler
/// once a stop control returns, so a refused `STOP` would leave the SCM
/// calling freed memory (see `palisade_agent::service`). A `STOP` already in
/// flight when the gate closes is therefore still honoured, and logged.
///
/// Tamper protection (#220) and the break-glass unlock (#222) implement this.
/// Until they land, [`AllowStop`] is used.
pub trait TamperGuard: Send + Sync + 'static {
    /// Whether a `STOP` is allowed now, and every later change of it.
    fn stop_permission(&self) -> watch::Receiver<bool>;
}

/// A [`TamperGuard`] that always allows `STOP`: the M1 default until #220.
#[derive(Debug)]
pub struct AllowStop {
    allowed: watch::Sender<bool>,
}

impl Default for AllowStop {
    fn default() -> Self {
        Self {
            allowed: watch::channel(true).0,
        }
    }
}

impl TamperGuard for AllowStop {
    fn stop_permission(&self) -> watch::Receiver<bool> {
        self.allowed.subscribe()
    }
}

/// What the service control handler sends to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Stop the agent.
    Stop(crate::host::StopRequest),
    /// Publish an OS notification to the subsystems.
    Event(HostEvent),
}

/// The default guard for this build.
pub fn default_guard() -> Arc<dyn TamperGuard> {
    Arc::new(AllowStop::default())
}

/// The controls the service accepts, by name, independent of the Windows
/// bit flags so the rules can be tested anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AcceptedControls {
    /// `SERVICE_ACCEPT_STOP`.
    pub stop: bool,
    /// `SERVICE_ACCEPT_PRESHUTDOWN`.
    pub preshutdown: bool,
    /// `SERVICE_ACCEPT_POWEREVENT`.
    pub power_event: bool,
    /// `SERVICE_ACCEPT_SESSIONCHANGE`.
    pub session_change: bool,
    /// `SERVICE_ACCEPT_PARAMCHANGE`.
    pub param_change: bool,
    /// `SERVICE_ACCEPT_TIMECHANGE`.
    pub time_change: bool,
}

impl AcceptedControls {
    /// The controls accepted while the service is running. Every other state
    /// (start-pending, stop-pending, stopped) accepts none, so nothing
    /// reaches the handler while the agent is not ready for it, and nothing
    /// after a stop control has freed it.
    pub fn running(stop_allowed: bool) -> Self {
        Self {
            stop: stop_allowed,
            preshutdown: true,
            power_event: true,
            session_change: true,
            param_change: true,
            time_change: true,
        }
    }
}

/// Where the service is in its life, as far as the SCM is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePhase {
    /// Start-pending: no controls accepted.
    Starting,
    /// Running: [`AcceptedControls::running`].
    Running,
    /// Stop-pending or stopped: no controls accepted, for good.
    Stopping,
}

/// Serialises every status report the service makes, so a change of the
/// stop permission can never re-offer `STOP` after a stop has begun.
///
/// Each method runs its `report` callback while holding the gate's lock, and
/// only if the move is legal. Once [`Self::stopping`] has run, no later call
/// reports anything: the `windows-service` crate has freed the control
/// handler by then, and offering a control again would let the SCM call it.
#[derive(Debug)]
pub struct StatusGate {
    state: Mutex<(ServicePhase, bool)>,
}

impl StatusGate {
    /// A gate in [`ServicePhase::Starting`] with the initial stop permission.
    pub fn new(stop_allowed: bool) -> Self {
        Self {
            state: Mutex::new((ServicePhase::Starting, stop_allowed)),
        }
    }

    /// The current phase.
    pub fn phase(&self) -> ServicePhase {
        self.lock().0
    }

    /// Moves from `Starting` to `Running` and reports the running controls.
    /// Does nothing in any other phase.
    pub fn running(&self, report: impl FnOnce(AcceptedControls)) {
        let mut state = self.lock();
        if state.0 == ServicePhase::Starting {
            state.0 = ServicePhase::Running;
            report(AcceptedControls::running(state.1));
        }
    }

    /// Records a new stop permission and, while running, reports the
    /// controls again if it changed.
    pub fn set_stop_allowed(&self, allowed: bool, report: impl FnOnce(AcceptedControls)) {
        let mut state = self.lock();
        let changed = state.1 != allowed;
        state.1 = allowed;
        if changed && state.0 == ServicePhase::Running {
            report(AcceptedControls::running(allowed));
        }
    }

    /// Moves to `Stopping` and reports stop-pending. Returns `false`, without
    /// reporting, if a stop had already begun.
    pub fn stopping(&self, report: impl FnOnce()) -> bool {
        let mut state = self.lock();
        if state.0 == ServicePhase::Stopping {
            return false;
        }
        state.0 = ServicePhase::Stopping;
        report();
        true
    }

    /// Whether `STOP` is allowed now.
    pub fn stop_allowed(&self) -> bool {
        self.lock().1
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (ServicePhase, bool)> {
        // The callbacks only report a status; a poisoned lock must not stop
        // the service from reporting `Stopped`.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_accepts_everything_but_a_locked_stop() {
        let open = AcceptedControls::running(true);
        assert!(open.stop && open.preshutdown && open.power_event);
        assert!(open.session_change && open.param_change && open.time_change);
        let locked = AcceptedControls::running(false);
        assert_eq!(
            locked,
            AcceptedControls {
                stop: false,
                ..open
            }
        );
        assert!(!AcceptedControls::default().stop);
    }

    #[test]
    fn allow_stop_always_allows() {
        let guard = default_guard();
        assert!(*guard.stop_permission().borrow());
        let guard = AllowStop::default();
        let rx = guard.stop_permission();
        assert!(*rx.borrow());
    }

    #[test]
    fn the_gate_never_reoffers_stop_after_stopping() {
        let gate = StatusGate::new(true);
        let mut reports = Vec::new();
        // Nothing is offered while starting.
        gate.set_stop_allowed(false, |c| reports.push(c));
        assert!(reports.is_empty());
        assert!(!gate.stop_allowed());
        gate.running(|c| reports.push(c));
        assert_eq!(reports, [AcceptedControls::running(false)]);
        assert_eq!(gate.phase(), ServicePhase::Running);
        // Running twice, or an unchanged permission, reports nothing.
        gate.running(|c| reports.push(c));
        gate.set_stop_allowed(false, |c| reports.push(c));
        assert_eq!(reports.len(), 1);
        gate.set_stop_allowed(true, |c| reports.push(c));
        assert_eq!(reports[1], AcceptedControls::running(true));

        let mut pending = 0;
        assert!(gate.stopping(|| pending += 1));
        assert!(!gate.stopping(|| pending += 1));
        assert_eq!(pending, 1);
        gate.set_stop_allowed(false, |c| reports.push(c));
        gate.set_stop_allowed(true, |c| reports.push(c));
        gate.running(|c| reports.push(c));
        assert_eq!(reports.len(), 2);
        assert_eq!(gate.phase(), ServicePhase::Stopping);
    }

    #[test]
    fn a_stop_while_starting_skips_running() {
        let gate = StatusGate::new(true);
        assert!(gate.stopping(|| {}));
        let mut reported = false;
        gate.running(|_| reported = true);
        assert!(!reported);
    }
}
