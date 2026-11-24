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
    let running = Server::new(config, prepared).start();

    if let Err(e) = shutdown_signal().await {
        tracing::error!(error = %e, "cannot listen for shutdown signals; shutting down");
    }
    tokio::select! {
        outcome = running.shutdown() => {
            match outcome {
                ShutdownOutcome::Drained => tracing::info!("shutdown complete"),
                ShutdownOutcome::Forced => tracing::warn!("shutdown complete; some connections were dropped"),
            }
            ExitCode::SUCCESS
        }
        r = shutdown_signal() => {
            if r.is_ok() {
                tracing::warn!("second shutdown signal; exiting without draining");
            }
            ExitCode::FAILURE
        }
    }
}

/// Resolves on the first shutdown request: Ctrl-C everywhere, plus SIGTERM
/// on Unix and the console close, logoff and shutdown events on Windows.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = term.recv() => {}
        }
        tracing::info!("shutdown signal received");
        Ok(())
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let mut brk = windows::ctrl_break()?;
        let mut close = windows::ctrl_close()?;
        let mut shut = windows::ctrl_shutdown()?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r?,
            _ = brk.recv() => {}
            _ = close.recv() => {}
            _ = shut.recv() => {}
        }
        tracing::info!("shutdown signal received");
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutdown signal received");
        Ok(())
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
