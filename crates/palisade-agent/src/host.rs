//! The service host: runtime, logging, the built-in subsystems and the
//! platform-independent run loop shared by console and service mode.

#![forbid(unsafe_code)]

use std::{
    future::Future,
    io,
    process::ExitCode,
    sync::{Arc, Once, OnceLock},
    time::Duration,
};

use tokio::{
    runtime::Runtime,
    sync::{broadcast, mpsc, watch},
};
use tracing_subscriber::filter::LevelFilter;

use crate::{
    boot::{self, BootMode},
    cli::Args,
    clock::ClockMonitor,
    config::{self, AgentConfig, LoadedConfig, LogLevel, RuntimeConfig},
    control::{Control, HostEvent, TamperGuard},
    platform::SystemClock,
    subsystem::{BoxFuture, Criticality, Subsystem, SubsystemContext, SubsystemError},
    supervisor::{HostEvents, RestartPolicy, ShutdownReport, Supervisor, SupervisorError},
};

/// Budget for a requested stop (service `STOP`, Ctrl-C).
pub const STOP_BUDGET: Duration = Duration::from_secs(20);
/// Budget when the machine is shutting down (`SHUTDOWN`, `PRESHUTDOWN`).
pub const SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

/// Why the agent is stopping, and how long it has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StopRequest {
    /// Why.
    pub reason: StopReason,
    /// The overall shutdown budget.
    pub budget: Duration,
}

/// The source of a [`StopRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// Ctrl-C or `SIGTERM` in console mode, or `STOP` from the service
    /// control manager.
    Requested,
    /// The machine is shutting down.
    SystemShutdown,
    /// Whoever could request a stop has gone away.
    ChannelClosed,
}

impl StopRequest {
    /// A [`StopReason::Requested`] stop with [`STOP_BUDGET`].
    pub const REQUESTED: Self = Self {
        reason: StopReason::Requested,
        budget: STOP_BUDGET,
    };
    /// A [`StopReason::SystemShutdown`] stop with [`SHUTDOWN_BUDGET`].
    pub const SYSTEM_SHUTDOWN: Self = Self {
        reason: StopReason::SystemShutdown,
        budget: SHUTDOWN_BUDGET,
    };
}

/// Builds the multi-threaded runtime: `min(4, cores)` workers unless
/// configured, and a bounded blocking pool for file I/O and hashing.
///
/// Sizes that [`AgentConfig::validate`](crate::config::AgentConfig::validate)
/// rejects are an `InvalidInput` error here too, rather than a panic in the
/// runtime builder.
pub fn build_runtime(runtime: &RuntimeConfig) -> io::Result<Runtime> {
    let check = AgentConfig {
        runtime: *runtime,
        ..AgentConfig::default()
    };
    check
        .validate()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(runtime.effective_worker_threads(cores))
        .max_blocking_threads(runtime.max_blocking_threads)
        .thread_name("palisade-agent")
        .enable_all()
        .build()
}

/// The handle that changes the log level of the subscriber
/// [`init_logging`] installed.
static LOG_LEVEL: OnceLock<
    tracing_subscriber::reload::Handle<LevelFilter, tracing_subscriber::Registry>,
> = OnceLock::new();

fn level_filter(level: LogLevel) -> LevelFilter {
    match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    }
}

/// Sends `tracing` records at or above `level` to standard error. Rotating
/// log files and the event-log channel are still to come (#56). Safe to call
/// more than once; only the first call has an effect. The level can be
/// changed later with [`set_log_level`].
pub fn init_logging(level: LogLevel) {
    use tracing_subscriber::{layer::SubscriberExt, reload};
    let (filter, handle) = reload::Layer::new(level_filter(level));
    let subscriber = tracing_subscriber::registry().with(filter).with(
        tracing_subscriber::fmt::layer()
            .with_writer(io::stderr)
            .with_ansi(false),
    );
    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        let _ = LOG_LEVEL.set(handle);
    }
}

/// Changes the level of the subscriber [`init_logging`] installed, at run
/// time (a reloaded configuration, and later IPC or policy). Returns `false`
/// if this process's subscriber was not installed by [`init_logging`].
pub fn set_log_level(level: LogLevel) -> bool {
    LOG_LEVEL
        .get()
        .is_some_and(|handle| handle.reload(level_filter(level)).is_ok())
}

/// Routes panics to the log, with a backtrace. Panics inside subsystem tasks
/// are then contained by the supervisor; this only records them.
pub fn install_panic_hook() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let backtrace = std::backtrace::Backtrace::force_capture();
            let thread = std::thread::current();
            tracing::error!(
                thread = thread.name().unwrap_or("unnamed"),
                %info,
                %backtrace,
                "panic"
            );
        }));
    });
}

/// The `config` subsystem: holds the effective configuration and publishes
/// every change of it.
///
/// Other subsystems get a receiver from [`ConfigSubsystem::subscribe`] when
/// they are registered, and declare a dependency on [`ConfigSubsystem::NAME`].
///
/// On [`HostEvent::ParamChange`] (the service's `PARAMCHANGE` control), it
/// reads the configuration again from where it was first read: the same
/// file, or the default path if the agent started on built-in defaults. A
/// reload that fails keeps the current configuration and logs the error;
/// it never falls back to the defaults, which could be weaker (ADR 0018).
/// The log level applies at once. Runtime sizes apply at the next start.
///
/// The policy-delivered and local-override layers come with the policy
/// cache (#61).
#[derive(Debug)]
pub struct ConfigSubsystem {
    current: watch::Sender<LoadedConfig>,
}

impl ConfigSubsystem {
    /// The subsystem's name.
    pub const NAME: &'static str = "config";

    /// Wraps a loaded configuration.
    pub fn new(loaded: LoadedConfig) -> Self {
        Self {
            current: watch::channel(loaded).0,
        }
    }

    /// The effective configuration now.
    pub fn config(&self) -> AgentConfig {
        self.current.borrow().config.clone()
    }

    /// A receiver that sees every change of the effective configuration.
    pub fn subscribe(&self) -> watch::Receiver<LoadedConfig> {
        self.current.subscribe()
    }

    /// Reads the configuration again and applies it if it loaded. Returns
    /// whether it changed.
    pub fn reload(&self) -> Result<bool, config::ConfigError> {
        let source = self.current.borrow().source.clone();
        let next = config::load(source.as_deref())?;
        let previous = self.current.borrow().clone();
        if next == previous {
            return Ok(false);
        }
        if next.config.runtime != previous.config.runtime {
            tracing::warn!("runtime sizes changed; they apply when the agent restarts");
        }
        if next.config.log_level != previous.config.log_level {
            set_log_level(next.config.log_level);
        }
        tracing::info!(
            fail_mode = ?next.config.fail_mode,
            safe_mode_behaviour = ?next.config.safe_mode_behaviour,
            log_level = ?next.config.log_level,
            "configuration reloaded"
        );
        self.current.send_replace(next);
        Ok(true)
    }
}

impl Subsystem for ConfigSubsystem {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn criticality(&self) -> Criticality {
        Criticality::Critical
    }

    fn run(self: Arc<Self>, ctx: SubsystemContext) -> BoxFuture<Result<(), SubsystemError>> {
        Box::pin(async move {
            let mut events = ctx.host_events();
            {
                let loaded = self.current.borrow();
                tracing::info!(
                    source = %loaded.source.as_ref().map_or("built-in defaults".into(), |p| p.display().to_string()),
                    fail_mode = ?loaded.config.fail_mode,
                    safe_mode_behaviour = ?loaded.config.safe_mode_behaviour,
                    "configuration loaded"
                );
            }
            ctx.set_ready();
            loop {
                tokio::select! {
                    _ = ctx.stopped() => return Ok(()),
                    event = events.recv() => match event {
                        // A lagged receiver may have missed a reload request.
                        Ok(HostEvent::ParamChange) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            let this = Arc::clone(&self);
                            match tokio::task::spawn_blocking(move || this.reload()).await {
                                Ok(Ok(_)) => {}
                                Ok(Err(e)) => tracing::error!(
                                    error = %e,
                                    "configuration reload failed; keeping the current configuration"
                                ),
                                Err(e) => tracing::error!(error = %e, "configuration reload did not finish"),
                            }
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Closed) => {
                            ctx.stopped().await;
                            return Ok(());
                        }
                    },
                }
            }
        })
    }
}

/// The subsystems the host registers. Subsystems from later issues (policy
/// cache #61, server comms #62, ETW #59 and others) are added here as they
/// land: construct them with what they need (for example a
/// [`ConfigSubsystem::subscribe`] receiver), declare their dependencies, and
/// push them after the subsystems they depend on.
pub fn builtin_subsystems(loaded: &LoadedConfig) -> Vec<Arc<dyn Subsystem>> {
    let config = Arc::new(ConfigSubsystem::new(loaded.clone()));
    let clock = Arc::new(ClockMonitor::new(SystemClock));
    vec![config, clock]
}

/// Starts `supervisor`, runs until `stop` resolves, then shuts down within the
/// requested budget. `on_started` runs once supervision has begun.
pub async fn run_until(
    supervisor: Supervisor,
    on_started: impl FnOnce(),
    stop: impl Future<Output = StopRequest>,
) -> (StopRequest, ShutdownReport) {
    tracing::info!(order = ?supervisor.start_order(), "starting subsystems");
    let handle = supervisor.start();
    on_started();
    let request = stop.await;
    tracing::info!(reason = ?request.reason, budget = ?request.budget, "stopping");
    let report = handle.shutdown(request.budget).await;
    for (name, outcome) in &report.outcomes {
        tracing::info!(subsystem = name, ?outcome, "subsystem stopped");
    }
    (request, report)
}

/// Serves the controls the service control handler sends, until a stop.
///
/// [`Control::Event`]s are published to the subsystems through `events`.
/// Every change of the `guard`'s stop permission, and its value at the
/// start, is passed to `on_permission`, which re-reports the accepted
/// controls. A guard that goes away leaves the last permission in place.
/// Returns the stop request, or a [`StopReason::ChannelClosed`] stop if the
/// handler has gone away.
pub async fn serve_controls(
    mut controls: mpsc::UnboundedReceiver<Control>,
    events: HostEvents,
    guard: &dyn TamperGuard,
    mut on_permission: impl FnMut(bool),
) -> StopRequest {
    let mut permission = guard.stop_permission();
    on_permission(*permission.borrow_and_update());
    let mut guard_open = true;
    loop {
        tokio::select! {
            control = controls.recv() => match control {
                Some(Control::Stop(request)) => return request,
                Some(Control::Event(event)) => {
                    events.publish(event);
                }
                None => {
                    return StopRequest {
                        reason: StopReason::ChannelClosed,
                        budget: STOP_BUDGET,
                    };
                }
            },
            changed = permission.changed(), if guard_open => {
                if changed.is_ok() {
                    let allowed = *permission.borrow_and_update();
                    tracing::info!(allowed, "service stop permission changed");
                    on_permission(allowed);
                } else {
                    tracing::warn!("the tamper guard has gone away; keeping the last stop permission");
                    guard_open = false;
                }
            }
        }
    }
}

/// Grace period for blocking-pool threads after the supervisor has stopped.
pub const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Shuts the runtime down without waiting indefinitely for blocking-pool
/// work that outlived its subsystem.
pub fn finish_runtime(runtime: Runtime) {
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
}

/// The default supervisor for a loaded configuration, with the boot mode
/// of the running system ([`boot::current`]).
pub fn supervisor(loaded: &LoadedConfig) -> Result<Supervisor, SupervisorError> {
    supervisor_for(loaded, boot::current())
}

/// The default supervisor for a loaded configuration and a boot mode. In a
/// safe-mode boot the agent reports [`AgentState::SafeMode`](crate::lifecycle::AgentState::SafeMode),
/// and enforcement applies the configured
/// [`SafeModeBehaviour`](crate::config::SafeModeBehaviour).
pub fn supervisor_for(
    loaded: &LoadedConfig,
    boot_mode: BootMode,
) -> Result<Supervisor, SupervisorError> {
    if boot_mode.is_safe() {
        tracing::warn!(
            ?boot_mode,
            behaviour = ?loaded.config.safe_mode_behaviour,
            "Windows was started in safe mode"
        );
    }
    Ok(
        Supervisor::new(builtin_subsystems(loaded), RestartPolicy::default())?
            .safe_mode(boot_mode.is_safe()),
    )
}

/// Console stop signals: Ctrl-C everywhere, and `SIGTERM` on Unix.
///
/// The OS handlers are installed by [`ConsoleSignals::register`], not when
/// [`ConsoleSignals::recv`] is first polled. Register before starting the
/// supervisor, so a signal sent as soon as the agent reports `Running` is
/// already caught rather than killing the process.
#[derive(Debug)]
pub struct ConsoleSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl ConsoleSignals {
    /// Installs the handlers. Must be called inside a tokio runtime.
    pub fn register() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                ctrl_c: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    /// Resolves on the first signal.
    pub async fn recv(mut self) -> StopRequest {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
        #[cfg(windows)]
        self.ctrl_c.recv().await;
        StopRequest::REQUESTED
    }
}

/// Loads configuration and starts logging. Errors are printed to standard
/// error, since logging may not be set up yet.
pub fn prepare(args: &Args) -> Result<LoadedConfig, ExitCode> {
    match config::load(args.config.as_deref()) {
        Ok(loaded) => {
            init_logging(loaded.config.log_level);
            install_panic_hook();
            Ok(loaded)
        }
        Err(e) => {
            eprintln!("palisade-agent: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// `--console`: runs in the foreground on any OS until Ctrl-C.
pub fn run_console(args: &Args) -> ExitCode {
    let loaded = match prepare(args) {
        Ok(loaded) => loaded,
        Err(code) => return code,
    };
    let supervisor = match supervisor(&loaded) {
        Ok(supervisor) => supervisor,
        Err(e) => {
            tracing::error!(error = %e, "invalid subsystem set");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match build_runtime(&loaded.config.runtime) {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let outcome = runtime.block_on(async {
        let signals = ConsoleSignals::register()?;
        Ok::<_, io::Error>(
            run_until(
                supervisor,
                || tracing::info!("running in console mode; press Ctrl-C to stop"),
                signals.recv(),
            )
            .await,
        )
    });
    let report = match outcome {
        Ok((_, report)) => report,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen for Ctrl-C");
            finish_runtime(runtime);
            return ExitCode::FAILURE;
        }
    };
    finish_runtime(runtime);
    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
