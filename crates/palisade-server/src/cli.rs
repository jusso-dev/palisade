//! The `palisade-server` command line.
//!
//! Exit codes: `0` success (including a completed shutdown), `1` runtime
//! failure, `2` invalid configuration or command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::level_filters::LevelFilter;

use crate::config::{self, Config, DatabaseSettings, ENV_CONFIG, ListenerKind, Loaded};
use crate::db::{self, DbError, SchemaVerdict};
use crate::health::ClockHealth;
use crate::server::{self, Server, ShutdownOutcome};
use crate::{clock, net, telemetry};

/// Exit code for an invalid configuration or command line.
const EXIT_CONFIG: u8 = 2;
/// Exit code of `migrate status` when migrations are pending.
const EXIT_PENDING: u8 = 3;
/// How often `serve` re-checks the database.
const DB_CHECK_INTERVAL: Duration = Duration::from_secs(5);

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
    /// Manage the database schema. Uses the `[database.migration]` login
    /// (the schema owner) for `up`, and either login for the others.
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    /// Development only: generate a throwaway CA and TLS files in DIR, then
    /// serve enrolment (admin listener) and check-in (agent listener) on
    /// loopback with an in-memory store. Prints the registration code and
    /// the CA pin for the agent. Nothing survives a restart (#223, #334).
    DevServer {
        /// Where to write the TLS files and the server configuration.
        dir: PathBuf,
        /// The admin listener port (enrolment).
        #[arg(long, default_value_t = 8443)]
        admin_port: u16,
        /// The agent listener port (check-in).
        #[arg(long, default_value_t = 8444)]
        agent_port: u16,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum MigrateAction {
    /// Apply every pending migration, then verify the schema.
    Up,
    /// Print the applied and embedded migrations as JSON. Exits 0 when the
    /// schema is current, 3 when migrations are pending, 1 otherwise.
    Status,
    /// Check that the applied migrations match this binary byte for byte,
    /// and that every tenant table has row-level security forced. Exits 0
    /// when everything matches, 1 otherwise.
    Verify,
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
        Command::Migrate { action } => migrate(cli.config.as_deref(), action),
        Command::DevServer {
            dir,
            admin_port,
            agent_port,
        } => dev_server(&dir, admin_port, agent_port),
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
    let prepared = match prepare_all(&loaded.config, &host_addrs_or_empty()) {
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

/// [`server::prepare`] plus the database checks that need no connection
/// ([`db::preflight`]), with every problem reported at once. `check-config`
/// and `serve` both run it before binding.
fn prepare_all(config: &Config, host: &[net::HostAddr]) -> Result<server::Prepared, Vec<String>> {
    let prepared = server::prepare(config, host);
    let db_errors = config
        .database
        .as_ref()
        .map(db::preflight)
        .unwrap_or_default();
    match (prepared, db_errors.is_empty()) {
        (Ok(p), true) => Ok(p),
        (Ok(_), false) => Err(db_errors),
        (Err(mut e), _) => {
            e.extend(db_errors);
            Err(e)
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

fn dev_server(dir: &Path, admin_port: u16, agent_port: u16) -> ExitCode {
    use crate::enrol::{EnrolSettings, dev::DevServer};
    use palisade_proto::events::DnsName;
    if let Err(e) = telemetry::init_json(LevelFilter::INFO) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    let Ok(localhost) = "localhost".parse::<DnsName>() else {
        return ExitCode::FAILURE;
    };
    let dev = match DevServer::create(
        dir,
        &[localhost],
        EnrolSettings {
            checkin_url: Some(format!("https://localhost:{agent_port}")),
            ..EnrolSettings::default()
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let toml = format!(
        "# Written by `palisade-server dev-server`. Development only.\n\
         [tls]\ncert_file = {:?}\nkey_file = {:?}\n\
         [listen.admin]\nbind = \"127.0.0.1\"\nport = {admin_port}\npublic_url = \"https://localhost:{admin_port}\"\n\
         [listen.agent]\nbind = \"127.0.0.1\"\nport = {agent_port}\npublic_url = \"https://localhost:{agent_port}\"\nclient_ca_file = {:?}\n",
        dev.cert_file.display().to_string(),
        dev.key_file.display().to_string(),
        dev.agent_ca_file.display().to_string(),
    );
    let path = dir.join("server.toml");
    if let Err(e) = std::fs::write(&path, toml) {
        eprintln!("error: cannot write {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    let config = match config::load(&path, &[]) {
        Ok(l) => l.config,
        Err(e) => return report_plain(&e.0),
    };
    // The code is printed once, to the terminal that started the server,
    // never logged.
    println!("palisade dev server (development only; nothing persists)");
    println!("  enrol at:  https://localhost:{admin_port}");
    println!("  code:      {}", dev.code.expose());
    println!("  CA pin:    {}", dev.ca_pin);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("palisade-server")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async move {
        let prepared = match server::prepare(&config, &[]) {
            Ok(p) => p,
            Err(errors) => return report_logged(&errors),
        };
        let mut signals = match Signals::new() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "cannot listen for shutdown signals");
                return ExitCode::FAILURE;
            }
        };
        let running = Server::new(config, prepared)
            .with_routes(ListenerKind::Admin, dev.service.admin_routes())
            .with_routes(ListenerKind::Agent, dev.service.agent_routes())
            .start();
        signals.next().await;
        running.shutdown().await;
        ExitCode::SUCCESS
    })
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
    let prepared = match prepare_all(&config, &host) {
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
    let database = match &config.database {
        None => {
            tracing::warn!("no [database] section; running without a database");
            None
        }
        Some(settings) => match db::start(settings).await {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::error!(error = %e, "database start-up failed; not starting");
                return ExitCode::FAILURE;
            }
        },
    };
    let clock_settings = config.clock.clone();
    let mut server = Server::new(config, prepared);
    if database.is_some() {
        server = server.with_database();
    }
    let running = server.start();
    let watcher = database
        .clone()
        .map(|db| tokio::spawn(db::watch(db, running.health().clone(), DB_CHECK_INTERVAL)));
    let clock_watcher = if clock_settings.ntp_servers.is_empty() {
        tracing::warn!(
            "no clock.ntp_servers; the clock offset from NTP is not monitored (ISM-0988)"
        );
        None
    } else {
        // Unknown until the first check answers, so an unmeasured clock is
        // never reported as good.
        running.health().set_clock(ClockHealth::Unknown);
        Some(tokio::spawn(clock::watch(
            clock_settings,
            running.health().clone(),
            clock::system_clock(),
        )))
    };

    signals.next().await;
    tracing::info!("shutdown signal received");
    if let Some(w) = watcher {
        w.abort();
    }
    if let Some(w) = clock_watcher {
        w.abort();
    }
    tokio::select! {
        outcome = running.shutdown() => {
            // In-flight requests have drained, so the pool can close.
            if let Some(db) = &database {
                db.close().await;
            }
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

fn migrate(path: Option<&Path>, action: MigrateAction) -> ExitCode {
    let loaded = match load(path) {
        Ok(l) => l,
        Err(errors) => return report_plain(&errors),
    };
    for w in &loaded.warnings {
        eprintln!("warning: {w}");
    }
    let Some(settings) = loaded.config.database else {
        return report_plain(&["the configuration has no [database] section".to_owned()]);
    };
    let problems = db::preflight(&settings);
    if !problems.is_empty() {
        return report_plain(&problems);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(migrate_async(&settings, action)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn migrate_async(
    settings: &DatabaseSettings,
    action: MigrateAction,
) -> Result<ExitCode, DbError> {
    let options = match (action, &settings.migration) {
        (MigrateAction::Up, _) | (_, Some(_)) => db::migration_options(settings)?,
        // Status and verify only read, so the runtime login is enough.
        (_, None) => db::connect_options(settings, &settings.runtime)?,
    };
    let mut conn = db::connect(&options, settings.connect_timeout).await?;
    let result = migrate_on(&mut conn, action).await;
    let _ = sqlx::Connection::close(conn).await;
    result
}

async fn migrate_on(
    conn: &mut sqlx::PgConnection,
    action: MigrateAction,
) -> Result<ExitCode, DbError> {
    let conn = &mut *conn;
    match action {
        MigrateAction::Up => {
            let state = db::migrate_up(conn).await?;
            let problems = db::verify_structure(conn).await?;
            print_json(&state.to_json());
            if problems.is_empty() {
                eprintln!(
                    "schema is current at version {}",
                    state.applied_version().unwrap_or(0)
                );
                Ok(ExitCode::SUCCESS)
            } else {
                for p in &problems {
                    eprintln!("error: {p}");
                }
                Ok(ExitCode::FAILURE)
            }
        }
        MigrateAction::Status => {
            let state = db::schema_state(conn).await?;
            print_json(&state.to_json());
            Ok(match state.verdict() {
                SchemaVerdict::Current => ExitCode::SUCCESS,
                SchemaVerdict::Behind => ExitCode::from(EXIT_PENDING),
                SchemaVerdict::Newer | SchemaVerdict::Damaged => ExitCode::FAILURE,
            })
        }
        MigrateAction::Verify => {
            let state = db::schema_state(conn).await?;
            let mut problems: Vec<String> = Vec::new();
            for m in &state.migrations {
                if m.checksum_mismatch {
                    problems.push(format!(
                        "migration {} ({}): checksum mismatch",
                        m.version, m.description
                    ));
                }
                if m.failed {
                    problems.push(format!(
                        "migration {} ({}): failed part-way",
                        m.version, m.description
                    ));
                }
                if m.applied && !m.embedded {
                    problems.push(format!(
                        "migration {}: applied but not embedded in this binary",
                        m.version
                    ));
                }
                if m.embedded && !m.applied && !m.failed {
                    problems.push(format!(
                        "migration {} ({}): not applied",
                        m.version, m.description
                    ));
                }
            }
            problems.extend(db::verify_structure(conn).await?);
            print_json(&state.to_json());
            if problems.is_empty() {
                eprintln!("verify OK: {} migration(s) match", state.migrations.len());
                Ok(ExitCode::SUCCESS)
            } else {
                for p in &problems {
                    eprintln!("error: {p}");
                }
                Ok(ExitCode::FAILURE)
            }
        }
    }
}

fn print_json(v: &serde_json::Value) {
    match serde_json::to_string_pretty(v) {
        Ok(t) => println!("{t}"),
        Err(e) => eprintln!("error: cannot render JSON: {e}"),
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
