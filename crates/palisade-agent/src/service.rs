//! `--service`: running under the Windows service control manager (SCM).
//!
//! The service is reached through the `windows-service` crate's safe API. Its
//! `define_windows_service!` macro expands to an `unsafe` block, which this
//! crate forbids (ADR 0011), so the entry point is written out by hand and
//! does not read the SCM start arguments. Configuration comes from the
//! service's command line (`ImagePath`), which the installer (#57) sets.
//!
//! Handled controls: `STOP` (20 s budget, offered only while the
//! [`TamperGuard`](crate::control::TamperGuard) allows it) and `PRESHUTDOWN`
//! (10 s budget; also `SHUTDOWN`, which the SCM sends instead if pre-shutdown
//! is not accepted). `POWEREVENT`, `SESSIONCHANGE`, `PARAMCHANGE` and
//! `TIMECHANGE` become [`HostEvent`]s for the subsystems (see
//! [`crate::control`]). `INTERROGATE` is answered.
//!
//! **Stop gating.** The wrapper crate frees the control-handler closure once
//! a `STOP`, `SHUTDOWN` or `PRESHUTDOWN` handler call returns, whatever the
//! result. That is sound only because the handler reports `StopPending`,
//! with no controls accepted, before it returns, so the SCM never calls it
//! again. A `STOP` is therefore never refused: the guard closes the gate by
//! no longer offering `STOP`, and every status report goes through one
//! [`StatusGate`] so nothing is offered again once a stop has begun.

#![forbid(unsafe_code)]

use std::{
    panic::AssertUnwindSafe,
    process::ExitCode,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    time::Duration,
};

use tokio::sync::mpsc;
use windows_service::{
    service::{
        PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType, SessionChangeReason,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

use crate::{
    cli::Args,
    control::{self, AcceptedControls, Control, HostEvent, PowerChange, SessionChange, StatusGate},
    host::{self, StopRequest},
};

/// The service name registered with the SCM.
pub const SERVICE_NAME: &str = "PalisadeAgent";

/// Win32 `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: the process was not
/// started by the SCM.
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
/// Service-specific exit code: configuration or start-up failed.
const EXIT_START_FAILED: u32 = 1;
/// Service-specific exit code: a subsystem did not stop cleanly.
const EXIT_UNCLEAN_STOP: u32 = 2;
/// Service-specific exit code: the service thread panicked.
const EXIT_PANICKED: u32 = 3;
/// Margin added to wait hints on top of the shutdown budget.
const WAIT_HINT_MARGIN: Duration = Duration::from_secs(5);

/// The parsed command line, handed from `main` to the service thread.
static ARGS: OnceLock<Args> = OnceLock::new();
/// The status handle, for the control handler.
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();
/// The exit code chosen by the service thread, read back by `main`.
static EXIT: Mutex<Option<ExitCode>> = Mutex::new(None);

/// Connects to the SCM and runs the service until it stops.
pub fn run_service(args: Args) -> ExitCode {
    let _ = ARGS.set(args);
    match service_dispatcher::start(SERVICE_NAME, service_main_entry) {
        // `service_main` stores the code before it reports `Stopped`, which
        // is what lets the dispatcher return, so it is set by now. If it is
        // not, something went wrong: report failure.
        Ok(()) => EXIT
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or(ExitCode::FAILURE),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) =>
        {
            eprintln!(
                "palisade-agent: --service must be started by the service control manager; \
                 use --console to run in the foreground"
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("palisade-agent: cannot connect to the service control manager: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The `ServiceMain` callback. The SCM start arguments are not read (see the
/// module docs), so no raw pointer is dereferenced.
extern "system" fn service_main_entry(_argc: u32, _argv: *mut *mut u16) {
    // A panic must not unwind into the SCM's thread. If one escapes before
    // the handler is registered, no status was ever reported and the
    // dispatcher returns on its own.
    if std::panic::catch_unwind(service_main).is_err() {
        set_exit(ExitCode::FAILURE);
    }
}

fn set_exit(code: ExitCode) {
    *EXIT.lock().unwrap_or_else(PoisonError::into_inner) = Some(code);
}

/// Registers the control handler, runs the agent and always reports
/// `Stopped` at the end, even after a panic: the dispatcher in
/// [`run_service`] returns only once the service has reported `Stopped`.
/// The exit code is stored first, and nothing else runs after `Stopped` is
/// reported, because the process may exit at any point after that.
fn service_main() {
    let guard = control::default_guard();
    let gate = Arc::new(StatusGate::new(*guard.stop_permission().borrow()));
    let (tx, rx) = mpsc::unbounded_channel();
    let handler_gate = Arc::clone(&gate);
    let handler = move |control| {
        let message = match control {
            ServiceControl::Stop => {
                if !handler_gate.stop_allowed() {
                    // Offered before the gate closed, delivered after.
                    tracing::warn!("STOP arrived after the stop permission was withdrawn");
                }
                StopRequest::REQUESTED
            }
            ServiceControl::Preshutdown | ServiceControl::Shutdown => StopRequest::SYSTEM_SHUTDOWN,
            ServiceControl::Interrogate => return ServiceControlHandlerResult::NoError,
            other => {
                if let Some(event) = host_event(&other) {
                    let _ = tx.send(Control::Event(event));
                }
                return ServiceControlHandlerResult::NoError;
            }
        };
        // The wrapper crate frees this closure after the first stop-type
        // control returns. Reporting `StopPending` with no accepted controls
        // before returning means the SCM delivers no further control (it
        // rejects every control while a service is stop-pending), so the
        // freed closure is never called again.
        if let Some(status) = STATUS.get() {
            handler_gate.stopping(|| {
                Reporter(*status).report(
                    ServiceState::StopPending,
                    AcceptedControls::default(),
                    message.budget + WAIT_HINT_MARGIN,
                    0,
                );
            });
        }
        let _ = tx.send(Control::Stop(message));
        ServiceControlHandlerResult::NoError
    };
    let status = match service_control_handler::register(SERVICE_NAME, handler) {
        Ok(status) => status,
        Err(e) => {
            eprintln!("palisade-agent: cannot register the service control handler: {e}");
            set_exit(ExitCode::FAILURE);
            return;
        }
    };
    // Set before any status is reported, so before any control is accepted.
    let _ = STATUS.set(status);
    let reporter = Reporter(status);
    reporter.report(
        ServiceState::StartPending,
        AcceptedControls::default(),
        WAIT_HINT_MARGIN,
        0,
    );
    let exit = std::panic::catch_unwind(AssertUnwindSafe(|| {
        run(&reporter, &gate, guard.as_ref(), rx)
    }))
    .unwrap_or(EXIT_PANICKED);
    set_exit(if exit == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    });
    // Close the gate so no permission change re-offers a control, then stop.
    gate.stopping(|| {});
    reporter.report(
        ServiceState::Stopped,
        AcceptedControls::default(),
        Duration::ZERO,
        exit,
    );
}

/// The [`HostEvent`] for a notification control, if it is one subsystems
/// act on.
fn host_event(control: &ServiceControl) -> Option<HostEvent> {
    match control {
        ServiceControl::ParamChange => Some(HostEvent::ParamChange),
        ServiceControl::TimeChange => Some(HostEvent::TimeChange),
        ServiceControl::PowerEvent(PowerEventParam::Suspend) => {
            Some(HostEvent::Power(PowerChange::Suspend))
        }
        ServiceControl::PowerEvent(
            PowerEventParam::ResumeSuspend
            | PowerEventParam::ResumeAutomatic
            | PowerEventParam::ResumeCritical,
        ) => Some(HostEvent::Power(PowerChange::Resume)),
        ServiceControl::SessionChange(param) => Some(HostEvent::Session {
            change: session_change(param.reason),
            session_id: param.notification.session_id,
        }),
        _ => None,
    }
}

fn session_change(reason: SessionChangeReason) -> SessionChange {
    match reason {
        SessionChangeReason::ConsoleConnect => SessionChange::ConsoleConnect,
        SessionChangeReason::ConsoleDisconnect => SessionChange::ConsoleDisconnect,
        SessionChangeReason::RemoteConnect => SessionChange::RemoteConnect,
        SessionChangeReason::RemoteDisconnect => SessionChange::RemoteDisconnect,
        SessionChangeReason::SessionLogon => SessionChange::Logon,
        SessionChangeReason::SessionLogoff => SessionChange::Logoff,
        SessionChangeReason::SessionLock => SessionChange::Lock,
        SessionChangeReason::SessionUnlock => SessionChange::Unlock,
        SessionChangeReason::SessionRemoteControl => SessionChange::RemoteControl,
        SessionChangeReason::SessionCreate => SessionChange::Create,
        SessionChangeReason::SessionTerminate => SessionChange::Terminate,
    }
}

/// Runs the agent and returns the service-specific exit code (0 for success).
fn run(
    reporter: &Reporter,
    gate: &StatusGate,
    guard: &dyn control::TamperGuard,
    rx: mpsc::UnboundedReceiver<Control>,
) -> u32 {
    let Some(args) = ARGS.get() else {
        return EXIT_START_FAILED;
    };
    let loaded = match host::prepare(args) {
        Ok(loaded) => loaded,
        Err(_) => return EXIT_START_FAILED,
    };
    let supervisor = match host::agent_supervisor(&loaded) {
        Ok(supervisor) => supervisor,
        Err(e) => {
            tracing::error!(error = %e, "invalid subsystem set");
            return EXIT_START_FAILED;
        }
    };
    let runtime = match host::build_runtime(&loaded.config.runtime) {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return EXIT_START_FAILED;
        }
    };
    let running = |controls| reporter.report(ServiceState::Running, controls, Duration::ZERO, 0);
    let events = supervisor.host_events();
    // `StopPending` was already reported by the control handler.
    let stop = host::serve_controls(rx, events, guard, |allowed| {
        gate.set_stop_allowed(allowed, running);
    });
    let (_, report) = runtime.block_on(host::run_until(supervisor, || gate.running(running), stop));
    host::finish_runtime(runtime);
    if report.is_clean() {
        0
    } else {
        EXIT_UNCLEAN_STOP
    }
}

#[derive(Clone, Copy)]
struct Reporter(ServiceStatusHandle);

impl Reporter {
    /// Reports a state with the controls it accepts. `exit` is the
    /// service-specific exit code; 0 reports success.
    fn report(
        &self,
        state: ServiceState,
        controls: AcceptedControls,
        wait_hint: Duration,
        exit: u32,
    ) {
        let mut controls_accepted = ServiceControlAccept::empty();
        for (on, flag) in [
            (controls.stop, ServiceControlAccept::STOP),
            (controls.preshutdown, ServiceControlAccept::PRESHUTDOWN),
            (controls.power_event, ServiceControlAccept::POWER_EVENT),
            (
                controls.session_change,
                ServiceControlAccept::SESSION_CHANGE,
            ),
            (controls.param_change, ServiceControlAccept::PARAM_CHANGE),
            (controls.time_change, ServiceControlAccept::TIME_CHANGE),
        ] {
            if on {
                controls_accepted |= flag;
            }
        }
        let exit_code = match exit {
            0 => ServiceExitCode::NO_ERROR,
            code => ServiceExitCode::ServiceSpecific(code),
        };
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        };
        if let Err(e) = self.0.set_service_status(status) {
            tracing::warn!(error = %e, ?state, "cannot report service status");
        }
    }
}
