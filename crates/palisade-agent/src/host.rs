//! The service host: runtime, logging, the built-in subsystems and the
//! platform-independent run loop shared by console and service mode.

use std::{
    future::Future,
    io,
    process::ExitCode,
    sync::{Arc, Once},
    time::Duration,
};

use tokio::runtime::Runtime;

use crate::{
    cli::Args,
    config::{self, AgentConfig, LoadedConfig, LogLevel, RuntimeConfig},
    subsystem::{BoxFuture, Criticality, Subsystem, SubsystemContext, SubsystemError},
    supervisor::{RestartPolicy, ShutdownReport, Supervisor, SupervisorError},
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

/// Sends `tracing` records at or above `level` to standard error. Rotating
/// log files and the event-log channel are still to come (#56). Safe to call
/// more than once; only the first call has an effect.
pub fn init_logging(level: LogLevel) {
    let filter = match level {
        LogLevel::Error => tracing::Level::ERROR,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Trace => tracing::Level::TRACE,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_writer(io::stderr)
        .with_ansi(false)
        .try_init();
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

/// The `config` subsystem: holds the effective configuration that other
/// subsystems read. Reloading on `PARAMCHANGE` and the policy-delivered and
/// local-override layers come with the policy cache (#61).
#[derive(Debug)]
pub struct ConfigSubsystem {
    loaded: LoadedConfig,
}

impl ConfigSubsystem {
    /// The subsystem's name.
    pub const NAME: &'static str = "config";

    /// Wraps a loaded configuration.
    pub fn new(loaded: LoadedConfig) -> Self {
        Self { loaded }
    }

    /// The effective configuration.
    pub fn config(&self) -> &AgentConfig {
        &self.loaded.config
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
            let config = &self.loaded.config;
            tracing::info!(
                source = %self.loaded.source.as_ref().map_or("built-in defaults".into(), |p| p.display().to_string()),
                fail_mode = ?config.fail_mode,
                safe_mode_behaviour = ?config.safe_mode_behaviour,
                "configuration loaded"
            );
            ctx.set_ready();
            ctx.stopped().await;
            Ok(())
        })
    }
}

/// The subsystems the host registers. Subsystems from later issues (policy
/// cache #61, server comms #62, ETW #59 and others) are added here as they
/// land.
pub fn builtin_subsystems(loaded: &LoadedConfig) -> Vec<Arc<dyn Subsystem>> {
    vec![Arc::new(ConfigSubsystem::new(loaded.clone()))]
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

/// Grace period for blocking-pool threads after the supervisor has stopped.
pub const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Shuts the runtime down without waiting indefinitely for blocking-pool
/// work that outlived its subsystem.
pub fn finish_runtime(runtime: Runtime) {
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_GRACE);
}

/// The default supervisor for a loaded configuration.
pub fn supervisor(loaded: &LoadedConfig) -> Result<Supervisor, SupervisorError> {
    Supervisor::new(builtin_subsystems(loaded), RestartPolicy::default())
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
