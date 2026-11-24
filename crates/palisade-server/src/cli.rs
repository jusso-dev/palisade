//! The `palisade-server` command line.
//!
//! Exit codes: `0` success (including a completed shutdown), `1` runtime
//! failure, `2` invalid configuration or command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;

use crate::config::{self, Config, ENV_CONFIG, Loaded};
use crate::server::{self, Server, ShutdownOutcome};
use crate::{net, telemetry};

/// Exit code for an invalid configuration or command line.
const EXIT_CONFIG: u8 = 2;

/// Palisade central management server.
#[derive(Debug, Parser)]
#[command(name = "palisade-server", version, about)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, short = 'c', global = true, env = ENV_CONFIG, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server until SIGTERM or Ctrl-C.
    Serve,
    /// Validate the configuration, the TLS files and the certificate names,
    /// then print the effective configuration (secrets redacted).
    CheckConfig,
    /// Print the version.
    Version,
}

/// Parses the command line and runs the chosen command.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Version => {
            println!("palisade-server {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::CheckConfig => check_config(cli.config.as_deref()),
        Command::Serve => serve(cli.config.as_deref()),
    }
}

fn load(path: Option<&Path>) -> Result<Loaded, Vec<String>> {
    let Some(path) = path else {
        return Err(vec![format!(
            "no configuration file given; pass --config <PATH> or set {ENV_CONFIG}"
        )]);
    };
    let env = config::palisade_env().map_err(|e| e.0)?;
    config::load(path, &env).map_err(|e| e.0)
}

fn host_addrs_or_empty() -> Vec<net::HostAddr> {
    net::host_addrs().unwrap_or_default()
}

fn check_config(path: Option<&Path>) -> ExitCode {
    let loaded = match load(path) {
        Ok(l) => l,
        Err(errors) => return report_plain(&errors),
    };
    let prepared = match server::prepare(&loaded.config, &host_addrs_or_empty()) {
        Ok(p) => p,
        Err(errors) => return report_plain(&errors),
    };
    for w in loaded.warnings.iter().chain(&prepared.warnings) {
        eprintln!("warning: {w}");
    }
    match serde_json::to_string_pretty(&loaded.config.effective_json()) {
        Ok(text) => {
            println!("{text}");
            eprintln!("configuration OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: cannot render the configuration: {e}");
            ExitCode::FAILURE
        }
    }
}

fn report_plain(errors: &[String]) -> ExitCode {
    for e in errors {
        eprintln!("error: {e}");
    }
    eprintln!("configuration invalid ({} problem(s))", errors.len());
    ExitCode::from(EXIT_CONFIG)
}

fn serve(path: Option<&Path>) -> ExitCode {
    let loaded = load(path);
    let level = loaded
        .as_ref()
        .map_or(LevelFilter::INFO, |l| l.config.log_level);
    if let Err(e) = telemetry::init_json(level) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    let Loaded { config, warnings } = match loaded {
        Ok(l) => l,
        Err(errors) => return report_logged(&errors),
    };
    for w in &warnings {
        tracing::warn!("{w}");
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("palisade-server")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(serve_async(config))
}

fn report_logged(errors: &[String]) -> ExitCode {
    for e in errors {
        tracing::error!("{e}");
    }
    tracing::error!(
        problems = errors.len(),
        "configuration invalid; not starting"
    );
    ExitCode::from(EXIT_CONFIG)
}

async fn serve_async(config: Config) -> ExitCode {
    let host = tokio::task::spawn_blocking(host_addrs_or_empty)
        .await
        .unwrap_or_default();
    let prepared = match server::prepare(&config, &host) {
        Ok(p) => p,
        Err(errors) => return report_logged(&errors),
    };
    for w in &prepared.warnings {
        tracing::warn!("{w}");
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listeners = config.listeners.len(),
        "starting palisade-server"
    );
    // Signal handlers are registered before any socket is bound, so a
    // signal that arrives as soon as the server is listening is never lost
    // or handled by the default action. The same streams serve the first
    // and the second signal.
    let mut signals = match Signals::new() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "cannot listen for shutdown signals; not starting");
            return ExitCode::FAILURE;
        }
    };
    let running = Server::new(config, prepared).start();

    signals.next().await;
    tracing::info!("shutdown signal received");
    tokio::select! {
        outcome = running.shutdown() => {
            match outcome {
                ShutdownOutcome::Drained => tracing::info!("shutdown complete"),
                ShutdownOutcome::Forced => tracing::warn!("shutdown complete; some connections were dropped"),
            }
            ExitCode::SUCCESS
        }
        () = signals.next() => {
            tracing::warn!("second shutdown signal; exiting without draining");
            ExitCode::FAILURE
        }
    }
}

/// The shutdown requests the server listens for: Ctrl-C everywhere, plus
/// SIGTERM on Unix, and Ctrl-Break and the console close, logoff and
/// shutdown events on Windows.
struct Signals {
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(windows)]
    c: tokio::signal::windows::CtrlC,
    #[cfg(windows)]
    brk: tokio::signal::windows::CtrlBreak,
    #[cfg(windows)]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(windows)]
    logoff: tokio::signal::windows::CtrlLogoff,
    #[cfg(windows)]
    shut: tokio::signal::windows::CtrlShutdown,
}

#[cfg(not(any(unix, windows)))]
compile_error!("palisade-server supports Unix and Windows only");

impl Signals {
    fn new() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                int: signal(SignalKind::interrupt())?,
                term: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows;
            Ok(Self {
                c: windows::ctrl_c()?,
                brk: windows::ctrl_break()?,
                close: windows::ctrl_close()?,
                logoff: windows::ctrl_logoff()?,
                shut: windows::ctrl_shutdown()?,
            })
        }
    }

    /// Resolves on the next request. A stream that has ended (it cannot,
    /// while the runtime runs) never resolves.
    async fn next(&mut self) {
        async fn recv_or_pending(r: Option<()>) {
            if r.is_none() {
                std::future::pending::<()>().await;
            }
        }
        #[cfg(unix)]
        tokio::select! {
            r = self.int.recv() => recv_or_pending(r).await,
            r = self.term.recv() => recv_or_pending(r).await,
        }
        #[cfg(windows)]
        tokio::select! {
            r = self.c.recv() => recv_or_pending(r).await,
            r = self.brk.recv() => recv_or_pending(r).await,
            r = self.close.recv() => recv_or_pending(r).await,
            r = self.logoff.recv() => recv_or_pending(r).await,
            r = self.shut.recv() => recv_or_pending(r).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn missing_config_is_reported() {
        let e = load(None).unwrap_err();
        assert!(e[0].contains("--config"), "{e:?}");
    }
}
