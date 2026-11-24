//! Server configuration.
//!
//! The configuration is a TOML file, overridden key by key by `PALISADE_*`
//! environment variables, then validated into a [`Config`]. Validation
//! collects every problem it finds, so one run reports all of them.
//!
//! The file holds no secret values. Secrets are only ever referenced by path
//! (`*_file` keys) and read with [`crate::secret::read_secret_file`], so the
//! configuration, its error messages and `check-config` output never contain
//! secret material.

use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::Uri;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::level_filters::LevelFilter;

/// Largest configuration file accepted, in bytes.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// Largest per-listener request body limit, in bytes (1 GiB). Larger
/// uploads belong to a streaming route class of their own.
const MAX_BODY_LIMIT: u64 = 1024 * 1024 * 1024;
const MAX_REQUEST_TIMEOUT_SECS: u64 = 3600;
const MAX_GRACE_SECS: u64 = 3600;
const MAX_CONNECTIONS: u32 = 1_000_000;
/// Longest accepted interface name. Windows friendly names can be long.
const MAX_INTERFACE_NAME: usize = 256;

/// The environment variable prefix for overrides.
pub const ENV_PREFIX: &str = "PALISADE_";
/// The environment variable that names the configuration file. It is read
/// by the command line parser, not treated as an override.
pub const ENV_CONFIG: &str = "PALISADE_CONFIG";

// ---------------------------------------------------------------------------
// Raw (unvalidated) shape, as written in the file.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    deployment: RawDeployment,
    tls: RawTls,
    listen: RawListen,
    shutdown: RawShutdown,
    log: RawLog,
    database: Option<RawDatabase>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDeployment {
    profile: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTls {
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    min_version: Option<String>,
    profile: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawListen {
    admin: Option<RawListener>,
    agent: Option<RawListener>,
    metrics: Option<RawListener>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawListener {
    bind: Option<String>,
    port: Option<u16>,
    public_url: Option<String>,
    body_limit_bytes: Option<u64>,
    request_timeout_secs: Option<u64>,
    max_connections: Option<u32>,
    client_ca_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawShutdown {
    grace_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawLog {
    level: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDatabase {
    host: Option<String>,
    port: Option<u16>,
    name: Option<String>,
    user: Option<String>,
    password_file: Option<PathBuf>,
    tls: Option<String>,
    ca_file: Option<PathBuf>,
    max_connections: Option<u32>,
    connect_timeout_secs: Option<u64>,
    auto_migrate: Option<bool>,
    migration: Option<RawDbLogin>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawDbLogin {
    user: Option<String>,
    password_file: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Validated shape.
// ---------------------------------------------------------------------------

/// The deployment profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// No placement checks beyond the defaults.
    Standard,
    /// Listeners are expected on private overlay addresses only (and metrics
    /// on loopback). Any listener reachable on a public address is reported.
    Overlay,
}

impl Profile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Overlay => "overlay",
        }
    }
}

/// The lowest TLS version the listeners accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2 and 1.3. TLS 1.3 is preferred.
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

/// The cipher suite and key exchange policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoProfile {
    /// AES-GCM suites only; X25519, P-256 and P-384 key exchange.
    Default,
    /// AES-256-GCM with SHA-384 only; P-384 key exchange only.
    AsdStrict,
}

impl CryptoProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AsdStrict => "asd-strict",
        }
    }
}

/// TLS settings shared by every listener.
#[derive(Debug, Clone)]
pub struct TlsSettings {
    /// PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM private key. A secret: read with the secret-file rules and never
    /// logged.
    pub key_file: PathBuf,
    /// Lowest accepted TLS version.
    pub min_version: TlsVersion,
    /// Cipher suite policy.
    pub profile: CryptoProfile,
}

/// Which surface a listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListenerKind {
    /// Console, REST API and SSO callbacks.
    Admin,
    /// Agent traffic. Requires a client certificate.
    Agent,
    /// Probes, and later the metrics exposition. Loopback by default.
    Metrics,
}

impl ListenerKind {
    /// The name used in configuration keys, logs and health indicators.
    pub fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Agent => "agent",
            Self::Metrics => "metrics",
        }
    }

    fn defaults(self) -> ListenerDefaults {
        match self {
            Self::Admin => ListenerDefaults {
                body_limit: 16 * 1024 * 1024,
                max_connections: 4096,
            },
            Self::Agent => ListenerDefaults {
                body_limit: 8 * 1024 * 1024,
                max_connections: 4096,
            },
            Self::Metrics => ListenerDefaults {
                body_limit: 64 * 1024,
                max_connections: 64,
            },
        }
    }
}

impl fmt::Display for ListenerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

struct ListenerDefaults {
    body_limit: u64,
    max_connections: u32,
}

const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_DB_PORT: u16 = 5432;
const DEFAULT_DB_MAX_CONNECTIONS: u32 = 16;
const MAX_DB_CONNECTIONS: u32 = 1000;
const DEFAULT_DB_CONNECT_TIMEOUT_SECS: u64 = 5;
const MAX_DB_CONNECT_TIMEOUT_SECS: u64 = 300;
/// Longest Postgres identifier, in bytes (`NAMEDATALEN - 1`).
const MAX_PG_IDENTIFIER: usize = 63;
/// Longest database host name.
const MAX_DB_HOST: usize = 253;
const DEFAULT_GRACE_SECS: u64 = 30;
const DEFAULT_METRICS_PORT: u16 = 9464;

/// Where a listener binds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindTarget {
    /// A literal address. `0.0.0.0` and `::` bind every interface.
    Ip(IpAddr),
    /// Every usable address of a named network interface, resolved when the
    /// server starts and re-resolved while it runs.
    Interface(String),
}

impl fmt::Display for BindTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Interface(name) => write!(f, "interface {name}"),
        }
    }
}

/// An externally visible `https` URL for a listener.
#[derive(Debug, Clone)]
pub struct PublicUrl {
    /// The URL as configured.
    pub url: String,
    /// The host part, as a TLS server name.
    pub host: ServerName<'static>,
}

/// One validated listener.
#[derive(Debug, Clone)]
pub struct ListenerSettings {
    /// The surface it serves.
    pub kind: ListenerKind,
    /// Where it binds.
    pub bind: BindTarget,
    /// TCP port.
    pub port: u16,
    /// Externally visible URL, checked against the certificate SANs.
    pub public_url: Option<PublicUrl>,
    /// Request body limit, in bytes.
    pub body_limit: usize,
    /// Time allowed to produce a response.
    pub request_timeout: Duration,
    /// Concurrent connections accepted.
    pub max_connections: usize,
    /// CA bundle for client certificates (agent listener only).
    pub client_ca_file: Option<PathBuf>,
}

/// How the connection to Postgres is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbTls {
    /// No TLS. Only for a database on the same host or a private test
    /// network.
    Disable,
    /// TLS, without checking the server certificate.
    Require,
    /// TLS, with the server certificate checked against the trusted roots.
    VerifyCa,
    /// TLS, with the certificate checked and its name matched to `host`.
    VerifyFull,
}

impl DbTls {
    /// The name used in the configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Require => "require",
            Self::VerifyCa => "verify-ca",
            Self::VerifyFull => "verify-full",
        }
    }
}

/// A Postgres login: a role name and the file that holds its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbLogin {
    /// The role name.
    pub user: String,
    /// The password file. A secret: read with the secret-file rules and
    /// never logged.
    pub password_file: PathBuf,
}

/// The validated `[database]` section.
#[derive(Debug, Clone)]
pub struct DatabaseSettings {
    /// Host name or IP address of the Postgres server.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Database name.
    pub name: String,
    /// The runtime login the server uses for every request. It must not
    /// own the tables and must not be able to bypass row-level security.
    pub runtime: DbLogin,
    /// The login that owns the schema and runs migrations. Needed by
    /// `migrate` and by `auto_migrate`; the server never serves requests
    /// with it.
    pub migration: Option<DbLogin>,
    /// Transport protection.
    pub tls: DbTls,
    /// Extra trusted CA certificates (PEM) for the database server.
    pub ca_file: Option<PathBuf>,
    /// Pool size for the runtime login.
    pub max_connections: u32,
    /// Time allowed to get a connection (including connecting).
    pub connect_timeout: Duration,
    /// Apply pending migrations at start, with the migration login. Defaults
    /// to on when `[database.migration]` is configured.
    pub auto_migrate: bool,
}

/// The validated server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Deployment profile.
    pub profile: Profile,
    /// TLS settings.
    pub tls: TlsSettings,
    /// Listeners, in the order admin, agent, metrics.
    pub listeners: Vec<ListenerSettings>,
    /// How long shutdown waits for in-flight requests.
    pub shutdown_grace: Duration,
    /// Log verbosity.
    pub log_level: LevelFilter,
    /// The database, when configured.
    pub database: Option<DatabaseSettings>,
}

/// A loaded configuration plus non-fatal findings.
#[derive(Debug)]
pub struct Loaded {
    /// The configuration.
    pub config: Config,
    /// Warnings, for example ignored environment variables.
    pub warnings: Vec<String>,
}

/// Every problem found while loading. Displayed one per line.
#[derive(Debug)]
pub struct ConfigError(pub Vec<String>);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            f.write_str(e)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Loading.
// ---------------------------------------------------------------------------

/// Collects the `PALISADE_*` variables from the process environment.
/// A variable with that prefix whose name or value is not valid Unicode is
/// an error, because it cannot be applied or reported reliably.
pub fn palisade_env() -> Result<Vec<(String, String)>, ConfigError> {
    let mut vars = Vec::new();
    let mut errors = Vec::new();
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str() else {
            if name.to_string_lossy().starts_with(ENV_PREFIX) {
                errors.push("an environment variable starting with PALISADE_ has a name that is not valid Unicode".to_owned());
            }
            continue;
        };
        if !name.starts_with(ENV_PREFIX) {
            continue;
        }
        match value.into_string() {
            Ok(value) => vars.push((name.to_owned(), value)),
            Err(_) => errors.push(format!("{name}: value is not valid Unicode")),
        }
    }
    if errors.is_empty() {
        Ok(vars)
    } else {
        Err(ConfigError(errors))
    }
}

/// Reads the file at `path`, applies the overrides in `env` and validates
/// the result. Relative paths in the configuration resolve against the
/// directory that contains the file.
pub fn load(path: &Path, env: &[(String, String)]) -> Result<Loaded, ConfigError> {
    let text = read_config_file(path).map_err(|e| ConfigError(vec![e]))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    load_str(&text, &path.display().to_string(), base, env)
}

fn read_config_file(path: &Path) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open config file {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read config file {}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(format!(
            "config file {} is larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| format!("config file {} is not valid UTF-8", path.display()))
}

/// [`load`] without the file read. `origin` names the source in messages.
pub fn load_str(
    text: &str,
    origin: &str,
    base: &Path,
    env: &[(String, String)],
) -> Result<Loaded, ConfigError> {
    let mut raw: RawConfig =
        toml::from_str(text).map_err(|e| ConfigError(vec![format!("{origin}: {e}")]))?;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    for (name, value) in env {
        apply_env(&mut raw, name, value, &mut errors, &mut warnings);
    }
    let config = validate(raw, base, &mut errors, &mut warnings);
    match config {
        Some(config) if errors.is_empty() => Ok(Loaded { config, warnings }),
        _ => Err(ConfigError(errors)),
    }
}

// ---------------------------------------------------------------------------
// Environment overrides.
// ---------------------------------------------------------------------------

/// Applies one `PALISADE_*` variable. The name maps to a key path by
/// splitting on `__` (two underscores): `PALISADE_LISTEN__ADMIN__PORT` sets
/// `listen.admin.port`. Unknown names produce a warning, not an error, so
/// variables meant for other Palisade components do not stop the server.
fn apply_env(
    raw: &mut RawConfig,
    name: &str,
    value: &str,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
        return;
    };
    if name == ENV_CONFIG {
        return;
    }
    let segments: Vec<&str> = rest.split("__").collect();
    let text = || Some(value.to_owned());
    let path = || Some(PathBuf::from(value));
    match segments.as_slice() {
        ["DEPLOYMENT", "PROFILE"] => raw.deployment.profile = text(),
        ["TLS", "CERT_FILE"] => raw.tls.cert_file = path(),
        ["TLS", "KEY_FILE"] => raw.tls.key_file = path(),
        ["TLS", "MIN_VERSION"] => raw.tls.min_version = text(),
        ["TLS", "PROFILE"] => raw.tls.profile = text(),
        ["SHUTDOWN", "GRACE_SECS"] => {
            set_env_int(&mut raw.shutdown.grace_secs, name, value, errors);
        }
        ["LOG", "LEVEL"] => raw.log.level = text(),
        ["DATABASE", "MIGRATION", key] => {
            if !matches!(*key, "USER" | "PASSWORD_FILE") {
                warnings.push(format!("ignoring unknown environment variable {name}"));
                return;
            }
            let db = raw.database.get_or_insert_with(RawDatabase::default);
            let login = db.migration.get_or_insert_with(RawDbLogin::default);
            if *key == "USER" {
                login.user = text();
            } else {
                login.password_file = path();
            }
        }
        ["DATABASE", key] => {
            // As for listeners, the key is checked first, so an unknown
            // variable never enables the database section.
            const KEYS: [&str; 10] = [
                "HOST",
                "PORT",
                "NAME",
                "USER",
                "PASSWORD_FILE",
                "TLS",
                "CA_FILE",
                "MAX_CONNECTIONS",
                "CONNECT_TIMEOUT_SECS",
                "AUTO_MIGRATE",
            ];
            if !KEYS.contains(key) {
                warnings.push(format!("ignoring unknown environment variable {name}"));
                return;
            }
            let db = raw.database.get_or_insert_with(RawDatabase::default);
            match *key {
                "HOST" => db.host = text(),
                "PORT" => set_env_int(&mut db.port, name, value, errors),
                "NAME" => db.name = text(),
                "USER" => db.user = text(),
                "PASSWORD_FILE" => db.password_file = path(),
                "TLS" => db.tls = text(),
                "CA_FILE" => db.ca_file = path(),
                "MAX_CONNECTIONS" => set_env_int(&mut db.max_connections, name, value, errors),
                "CONNECT_TIMEOUT_SECS" => {
                    set_env_int(&mut db.connect_timeout_secs, name, value, errors);
                }
                _ => match value.trim() {
                    "true" => db.auto_migrate = Some(true),
                    "false" => db.auto_migrate = Some(false),
                    _ => errors.push(format!("{name}: expected `true` or `false`, got `{value}`")),
                },
            }
        }
        ["LISTEN", which, key] => {
            // The key is checked before the listener section is created, so
            // an unknown variable never enables a listener.
            const KEYS: [&str; 7] = [
                "BIND",
                "PORT",
                "PUBLIC_URL",
                "BODY_LIMIT_BYTES",
                "REQUEST_TIMEOUT_SECS",
                "MAX_CONNECTIONS",
                "CLIENT_CA_FILE",
            ];
            let slot = match *which {
                "ADMIN" => &mut raw.listen.admin,
                "AGENT" => &mut raw.listen.agent,
                "METRICS" => &mut raw.listen.metrics,
                _ => {
                    warnings.push(format!("ignoring unknown environment variable {name}"));
                    return;
                }
            };
            if !KEYS.contains(key) {
                warnings.push(format!("ignoring unknown environment variable {name}"));
                return;
            }
            let listener = slot.get_or_insert_with(RawListener::default);
            match *key {
                "BIND" => listener.bind = text(),
                "PORT" => set_env_int(&mut listener.port, name, value, errors),
                "PUBLIC_URL" => listener.public_url = text(),
                "BODY_LIMIT_BYTES" => {
                    set_env_int(&mut listener.body_limit_bytes, name, value, errors);
                }
                "REQUEST_TIMEOUT_SECS" => {
                    set_env_int(&mut listener.request_timeout_secs, name, value, errors);
                }
                "MAX_CONNECTIONS" => {
                    set_env_int(&mut listener.max_connections, name, value, errors);
                }
                _ => listener.client_ca_file = path(),
            }
        }
        _ => warnings.push(format!("ignoring unknown environment variable {name}")),
    }
}

/// Parses an integer override into `slot`. On failure the error is
/// recorded and `slot` keeps its value from the file, so validation does not
/// report a second, misleading "is required" error.
fn set_env_int<T: std::str::FromStr>(
    slot: &mut Option<T>,
    name: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    match value.trim().parse::<T>() {
        Ok(v) => *slot = Some(v),
        Err(_) => errors.push(format!(
            "{name}: expected a non-negative integer in range, got `{value}`"
        )),
    }
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

fn validate(
    raw: RawConfig,
    base: &Path,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<Config> {
    let profile = match raw.deployment.profile.as_deref() {
        None | Some("standard") => Some(Profile::Standard),
        Some("overlay") => Some(Profile::Overlay),
        Some(other) => {
            errors.push(format!(
                "deployment.profile: expected `standard` or `overlay`, got `{other}`"
            ));
            None
        }
    };

    let tls = validate_tls(raw.tls, base, errors);

    let mut listeners = Vec::new();
    for (kind, raw_listener) in [
        (ListenerKind::Admin, raw.listen.admin),
        (ListenerKind::Agent, raw.listen.agent),
        (ListenerKind::Metrics, raw.listen.metrics),
    ] {
        match raw_listener {
            Some(l) => {
                if let Some(l) = validate_listener(kind, l, base, errors) {
                    listeners.push(l);
                }
            }
            None if kind == ListenerKind::Metrics => {}
            None => errors.push(format!(
                "listen.{kind}: section is required (set at least `bind` and `port`)"
            )),
        }
    }
    check_overlaps(&listeners, errors);

    let grace_secs = raw.shutdown.grace_secs.unwrap_or(DEFAULT_GRACE_SECS);
    if grace_secs > MAX_GRACE_SECS {
        errors.push(format!(
            "shutdown.grace_secs: must be at most {MAX_GRACE_SECS}, got {grace_secs}"
        ));
    }

    let log_level = match raw.log.level.as_deref().unwrap_or("info") {
        "error" => Some(LevelFilter::ERROR),
        "warn" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        other => {
            errors.push(format!(
                "log.level: expected one of error, warn, info, debug, trace; got `{other}`"
            ));
            None
        }
    };

    let start = errors.len();
    let database = raw
        .database
        .and_then(|d| validate_database(d, base, errors, warnings));
    let database_ok = errors.len() == start;

    let config = Config {
        profile: profile?,
        tls: tls?,
        listeners,
        shutdown_grace: Duration::from_secs(grace_secs),
        log_level: log_level?,
        database,
    };
    database_ok.then_some(config)
}

fn validate_database(
    raw: RawDatabase,
    base: &Path,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Option<DatabaseSettings> {
    let start = errors.len();
    let host = match raw.host.as_deref().map(str::trim) {
        None | Some("") => {
            errors.push("database.host: is required".to_owned());
            None
        }
        // An IP address (IPv6 with or without brackets) or a DNS name. No
        // port (that is `database.port`) and no Unix socket path.
        Some(h) => {
            let unbracketed = h
                .strip_prefix('[')
                .and_then(|x| x.strip_suffix(']'))
                .unwrap_or(h);
            if let Ok(ip) = unbracketed.parse::<IpAddr>() {
                Some(ip.to_string())
            } else if h.len() <= MAX_DB_HOST && ServerName::try_from(h.to_owned()).is_ok() {
                Some(h.to_owned())
            } else {
                errors.push(format!(
                    "database.host: `{h}` is not an IP address or host name; set the port with `database.port`"
                ));
                None
            }
        }
    };
    let port = match raw.port {
        Some(0) => {
            errors.push("database.port: must be between 1 and 65535".to_owned());
            None
        }
        p => Some(p.unwrap_or(DEFAULT_DB_PORT)),
    };
    let name = pg_identifier(raw.name, "database.name", errors);
    let runtime = db_login(raw.user, raw.password_file, "database", base, errors);
    let has_migration_section = raw.migration.is_some();
    let migration = raw
        .migration
        .and_then(|m| db_login(m.user, m.password_file, "database.migration", base, errors));
    if let (Some(r), Some(m)) = (&runtime, &migration) {
        if r.user == m.user {
            errors.push(format!(
                "database.migration.user: must differ from database.user (`{}`); the server must not serve requests as the role that owns the schema (ADR 0006)",
                r.user
            ));
        }
    }
    let tls = match raw.tls.as_deref() {
        None | Some("verify-full") => Some(DbTls::VerifyFull),
        Some("verify-ca") => Some(DbTls::VerifyCa),
        Some("require") => Some(DbTls::Require),
        Some("disable") => Some(DbTls::Disable),
        Some(other) => {
            errors.push(format!(
                "database.tls: expected `verify-full`, `verify-ca`, `require` or `disable`, got `{other}`"
            ));
            None
        }
    };
    let ca_file = match (raw.ca_file, tls) {
        (Some(p), _) if p.as_os_str().is_empty() => {
            errors.push("database.ca_file: must not be empty".to_owned());
            None
        }
        (Some(p), Some(DbTls::VerifyCa | DbTls::VerifyFull)) => Some(resolve_path(base, p)),
        (Some(_), Some(_)) => {
            errors.push(
                "database.ca_file: is only used with tls = \"verify-ca\" or \"verify-full\""
                    .to_owned(),
            );
            None
        }
        _ => None,
    };
    if let Some(mode @ (DbTls::Disable | DbTls::Require)) = tls {
        warnings.push(format!(
            "database.tls = \"{}\": the database server is not authenticated; use \"verify-full\" outside a test setup",
            mode.as_str()
        ));
    }
    let max_connections = raw.max_connections.unwrap_or(DEFAULT_DB_MAX_CONNECTIONS);
    if max_connections == 0 || max_connections > MAX_DB_CONNECTIONS {
        errors.push(format!(
            "database.max_connections: must be between 1 and {MAX_DB_CONNECTIONS}, got {max_connections}"
        ));
    }
    let timeout = raw
        .connect_timeout_secs
        .unwrap_or(DEFAULT_DB_CONNECT_TIMEOUT_SECS);
    if timeout == 0 || timeout > MAX_DB_CONNECT_TIMEOUT_SECS {
        errors.push(format!(
            "database.connect_timeout_secs: must be between 1 and {MAX_DB_CONNECT_TIMEOUT_SECS}, got {timeout}"
        ));
    }
    // On by default when the migration login is configured (#127), so a
    // server that is older than its database's schema never needs a manual
    // step. Explicitly `true` without that login is an error.
    let auto_migrate = raw.auto_migrate.unwrap_or(has_migration_section);
    // A [database.migration] section with its own errors already says so.
    if auto_migrate && !has_migration_section {
        errors.push(
            "database.auto_migrate: needs the [database.migration] login, which owns the schema"
                .to_owned(),
        );
    }
    if errors.len() != start {
        return None;
    }
    Some(DatabaseSettings {
        host: host?,
        port: port?,
        name: name?,
        runtime: runtime?,
        migration,
        tls: tls?,
        ca_file,
        max_connections,
        connect_timeout: Duration::from_secs(timeout),
        auto_migrate,
    })
}

/// A role or database name: 1 to 63 bytes, no control characters. It is
/// only ever passed to Postgres as a connection parameter, never into SQL.
fn pg_identifier(value: Option<String>, key: &str, errors: &mut Vec<String>) -> Option<String> {
    match value {
        None => {
            errors.push(format!("{key}: is required"));
            None
        }
        Some(v)
            if v.is_empty() || v.len() > MAX_PG_IDENTIFIER || v.chars().any(char::is_control) =>
        {
            errors.push(format!(
                "{key}: must be 1 to {MAX_PG_IDENTIFIER} bytes without control characters"
            ));
            None
        }
        Some(v) => Some(v),
    }
}

fn db_login(
    user: Option<String>,
    password_file: Option<PathBuf>,
    section: &str,
    base: &Path,
    errors: &mut Vec<String>,
) -> Option<DbLogin> {
    let user = pg_identifier(user, &format!("{section}.user"), errors);
    let password_file = required_path(
        password_file,
        &format!("{section}.password_file"),
        base,
        errors,
    );
    Some(DbLogin {
        user: user?,
        password_file: password_file?,
    })
}

fn resolve_path(base: &Path, p: PathBuf) -> PathBuf {
    if p.is_absolute() { p } else { base.join(p) }
}

fn validate_tls(raw: RawTls, base: &Path, errors: &mut Vec<String>) -> Option<TlsSettings> {
    let cert_file = required_path(raw.cert_file, "tls.cert_file", base, errors);
    let key_file = required_path(raw.key_file, "tls.key_file", base, errors);
    let min_version = match raw.min_version.as_deref() {
        None | Some("1.2") => Some(TlsVersion::Tls12),
        Some("1.3") => Some(TlsVersion::Tls13),
        Some(other) => {
            errors.push(format!(
                "tls.min_version: expected `1.2` or `1.3`, got `{other}`"
            ));
            None
        }
    };
    let profile = match raw.profile.as_deref() {
        None | Some("default") => Some(CryptoProfile::Default),
        Some("asd-strict") => Some(CryptoProfile::AsdStrict),
        Some(other) => {
            errors.push(format!(
                "tls.profile: expected `default` or `asd-strict`, got `{other}`"
            ));
            None
        }
    };
    Some(TlsSettings {
        cert_file: cert_file?,
        key_file: key_file?,
        min_version: min_version?,
        profile: profile?,
    })
}

fn required_path(
    p: Option<PathBuf>,
    key: &str,
    base: &Path,
    errors: &mut Vec<String>,
) -> Option<PathBuf> {
    match p {
        Some(p) if !p.as_os_str().is_empty() => Some(resolve_path(base, p)),
        _ => {
            errors.push(format!("{key}: is required"));
            None
        }
    }
}

fn validate_listener(
    kind: ListenerKind,
    raw: RawListener,
    base: &Path,
    errors: &mut Vec<String>,
) -> Option<ListenerSettings> {
    let key = |field: &str| format!("listen.{kind}.{field}");
    let start = errors.len();
    let defaults = kind.defaults();

    let bind = match (raw.bind.as_deref(), kind) {
        (Some(b), _) => parse_bind(b).map_err(|e| errors.push(format!("{}: {e}", key("bind")))),
        (None, ListenerKind::Metrics) => Ok(BindTarget::Ip(IpAddr::from([127, 0, 0, 1]))),
        (None, _) => {
            errors.push(format!(
                "{}: is required (an IP address or an interface name)",
                key("bind")
            ));
            Err(())
        }
    };

    let port = match (raw.port, kind) {
        (Some(0), _) => {
            errors.push(format!("{}: must be between 1 and 65535", key("port")));
            None
        }
        (Some(p), _) => Some(p),
        (None, ListenerKind::Metrics) => Some(DEFAULT_METRICS_PORT),
        (None, _) => {
            errors.push(format!("{}: is required", key("port")));
            None
        }
    };

    let public_url = match (raw.public_url, kind) {
        (None, _) => None,
        (Some(_), ListenerKind::Metrics) => {
            errors.push(format!(
                "{}: is not supported on the metrics listener",
                key("public_url")
            ));
            None
        }
        (Some(u), _) => match parse_public_url(&u) {
            Ok(u) => Some(u),
            Err(e) => {
                errors.push(format!("{}: {e}", key("public_url")));
                None
            }
        },
    };

    let body_limit = raw.body_limit_bytes.unwrap_or(defaults.body_limit);
    if body_limit == 0 || body_limit > MAX_BODY_LIMIT {
        errors.push(format!(
            "{}: must be between 1 and {MAX_BODY_LIMIT}, got {body_limit}",
            key("body_limit_bytes")
        ));
    }
    let timeout_secs = raw
        .request_timeout_secs
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS);
    if timeout_secs == 0 || timeout_secs > MAX_REQUEST_TIMEOUT_SECS {
        errors.push(format!(
            "{}: must be between 1 and {MAX_REQUEST_TIMEOUT_SECS}, got {timeout_secs}",
            key("request_timeout_secs")
        ));
    }
    let max_connections = raw.max_connections.unwrap_or(defaults.max_connections);
    if max_connections == 0 || max_connections > MAX_CONNECTIONS {
        errors.push(format!(
            "{}: must be between 1 and {MAX_CONNECTIONS}, got {max_connections}",
            key("max_connections")
        ));
    }

    let client_ca_file = match (raw.client_ca_file, kind) {
        (Some(p), ListenerKind::Agent) if !p.as_os_str().is_empty() => Some(resolve_path(base, p)),
        (_, ListenerKind::Agent) => {
            errors.push(format!(
                "{}: is required; agents authenticate with client certificates",
                key("client_ca_file")
            ));
            None
        }
        (Some(_), _) => {
            errors.push(format!(
                "{}: is only supported on the agent listener",
                key("client_ca_file")
            ));
            None
        }
        (None, _) => None,
    };

    if errors.len() != start {
        return None;
    }
    Some(ListenerSettings {
        kind,
        bind: bind.ok()?,
        port: port?,
        public_url,
        body_limit: usize::try_from(body_limit).ok()?,
        request_timeout: Duration::from_secs(timeout_secs),
        max_connections: usize::try_from(max_connections).ok()?,
        client_ca_file,
    })
}

/// Parses a `bind` value: an IP literal (IPv6 with or without brackets) or
/// an interface name.
pub fn parse_bind(s: &str) -> Result<BindTarget, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("must not be empty".to_owned());
    }
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(trimmed);
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return Ok(BindTarget::Ip(ip));
    }
    if trimmed.contains(':') || trimmed.contains('[') || trimmed.contains(']') {
        return Err(format!(
            "`{trimmed}` is neither an IP address nor an interface name; set the port with `port`, not in `bind`"
        ));
    }
    if trimmed.len() > MAX_INTERFACE_NAME || trimmed.chars().any(char::is_control) {
        return Err(format!("`{trimmed}` is not a valid interface name"));
    }
    if trimmed.contains('/') {
        return Err(format!(
            "`{trimmed}` looks like a network range; bind takes one address or an interface name"
        ));
    }
    Ok(BindTarget::Interface(trimmed.to_owned()))
}

/// Parses a `public_url`: an absolute `https` URL with a host, no userinfo,
/// no query and no fragment.
pub fn parse_public_url(s: &str) -> Result<PublicUrl, String> {
    let uri: Uri = s
        .parse()
        .map_err(|e| format!("`{s}` is not a valid URL: {e}"))?;
    if uri.scheme_str() != Some("https") {
        return Err(format!("`{s}` must use the https scheme"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| format!("`{s}` has no host"))?;
    if authority.as_str().contains('@') {
        return Err(format!("`{s}` must not contain user information"));
    }
    if uri.query().is_some() || s.contains('#') {
        return Err(format!("`{s}` must not have a query or fragment"));
    }
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let server_name = match host.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(host.to_owned())
            .map_err(|_| format!("`{s}` has an invalid host name `{host}`"))?,
    };
    Ok(PublicUrl {
        url: s.to_owned(),
        host: server_name,
    })
}

/// Rejects two listeners that would compete for the same socket: the same
/// port with the same bind target, or the same port where one side is a
/// wildcard of the same address family. Sharing one port between surfaces
/// (path routing) is not supported yet.
fn check_overlaps(listeners: &[ListenerSettings], errors: &mut Vec<String>) {
    for (i, a) in listeners.iter().enumerate() {
        for b in listeners.iter().skip(i + 1) {
            if a.port != b.port {
                continue;
            }
            let clash = match (&a.bind, &b.bind) {
                (x, y) if x == y => true,
                (BindTarget::Ip(x), BindTarget::Ip(y)) => {
                    x.is_ipv4() == y.is_ipv4() && (x.is_unspecified() || y.is_unspecified())
                }
                // An interface can hold addresses of either family, so it
                // may collide with a wildcard of either family.
                (BindTarget::Ip(ip), BindTarget::Interface(_))
                | (BindTarget::Interface(_), BindTarget::Ip(ip)) => ip.is_unspecified(),
                _ => false,
            };
            if clash {
                errors.push(format!(
                    "listen.{} and listen.{} both use {} port {}; give each listener its own address or port (single-port mode is not supported yet)",
                    a.kind, b.kind, a.bind, a.port
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Effective configuration.
// ---------------------------------------------------------------------------

impl Config {
    /// The effective configuration as JSON, for `check-config`. Secret files
    /// are shown by path only; their contents are never read here.
    pub fn effective_json(&self) -> Value {
        let listeners: serde_json::Map<String, Value> = self
            .listeners
            .iter()
            .map(|l| {
                let bind = match &l.bind {
                    BindTarget::Ip(ip) => json!({ "address": ip.to_string() }),
                    BindTarget::Interface(name) => json!({ "interface": name }),
                };
                let mut v = json!({
                    "bind": bind,
                    "port": l.port,
                    "body_limit_bytes": l.body_limit,
                    "request_timeout_secs": l.request_timeout.as_secs(),
                    "max_connections": l.max_connections,
                });
                if let Some(u) = &l.public_url {
                    v["public_url"] = json!(u.url);
                }
                if let Some(ca) = &l.client_ca_file {
                    v["client_ca_file"] = json!(ca.display().to_string());
                }
                (l.kind.name().to_owned(), v)
            })
            .collect();
        json!({
            "deployment": { "profile": self.profile.as_str() },
            "tls": {
                "cert_file": self.tls.cert_file.display().to_string(),
                "key_file": format!("{} (secret file; contents never shown)", self.tls.key_file.display()),
                "min_version": match self.tls.min_version {
                    TlsVersion::Tls12 => "1.2",
                    TlsVersion::Tls13 => "1.3",
                },
                "profile": self.tls.profile.as_str(),
            },
            "listen": listeners,
            "shutdown": { "grace_secs": self.shutdown_grace.as_secs() },
            "log": { "level": self.log_level.to_string().to_lowercase() },
            "database": self.database.as_ref().map(DatabaseSettings::effective_json),
        })
    }
}

impl DatabaseSettings {
    fn effective_json(&self) -> Value {
        let login = |l: &DbLogin| {
            json!({
                "user": l.user,
                "password_file": format!("{} (secret file; contents never shown)", l.password_file.display()),
            })
        };
        let mut v = json!({
            "host": self.host,
            "port": self.port,
            "name": self.name,
            "user": self.runtime.user,
            "password_file": login(&self.runtime)["password_file"],
            "tls": self.tls.as_str(),
            "max_connections": self.max_connections,
            "connect_timeout_secs": self.connect_timeout.as_secs(),
            "auto_migrate": self.auto_migrate,
        });
        if let Some(ca) = &self.ca_file {
            v["ca_file"] = json!(ca.display().to_string());
        }
        if let Some(m) = &self.migration {
            v["migration"] = login(m);
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        [tls]
        cert_file = "server.crt"
        key_file = "server.key"

        [listen.admin]
        bind = "127.0.0.1"
        port = 8443

        [listen.agent]
        bind = "127.0.0.1"
        port = 8444
        client_ca_file = "agent-ca.crt"
    "#;

    fn load_ok(text: &str, env: &[(&str, &str)]) -> Loaded {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        match load_str(text, "test.toml", Path::new("/etc/palisade"), &env) {
            Ok(l) => l,
            Err(e) => panic!("unexpected config error:\n{e}"),
        }
    }

    fn load_err(text: &str, env: &[(&str, &str)]) -> Vec<String> {
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        match load_str(text, "test.toml", Path::new("/etc/palisade"), &env) {
            Ok(_) => panic!("expected a config error"),
            Err(e) => e.0,
        }
    }

    fn listener(c: &Config, kind: ListenerKind) -> &ListenerSettings {
        c.listeners.iter().find(|l| l.kind == kind).unwrap()
    }

    #[test]
    fn minimal_config_gets_defaults() {
        let c = load_ok(MINIMAL, &[]).config;
        assert_eq!(c.profile, Profile::Standard);
        assert_eq!(c.tls.min_version, TlsVersion::Tls12);
        assert_eq!(c.tls.profile, CryptoProfile::Default);
        assert_eq!(c.shutdown_grace, Duration::from_secs(30));
        assert_eq!(c.log_level, LevelFilter::INFO);
        assert_eq!(c.listeners.len(), 2, "metrics is off unless configured");
        let admin = listener(&c, ListenerKind::Admin);
        assert_eq!(admin.body_limit, 16 * 1024 * 1024);
        assert_eq!(admin.request_timeout, Duration::from_secs(30));
        let agent = listener(&c, ListenerKind::Agent);
        assert_eq!(agent.body_limit, 8 * 1024 * 1024);
        assert_eq!(
            agent.client_ca_file.as_deref(),
            Some(Path::new("/etc/palisade/agent-ca.crt"))
        );
        assert_eq!(c.tls.key_file, Path::new("/etc/palisade/server.key"));
    }

    #[test]
    fn metrics_defaults_to_loopback() {
        let text = format!("{MINIMAL}\n[listen.metrics]\n");
        let c = load_ok(&text, &[]).config;
        let m = listener(&c, ListenerKind::Metrics);
        assert_eq!(m.bind, BindTarget::Ip(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(m.port, DEFAULT_METRICS_PORT);
    }

    #[test]
    fn env_overrides_file_values() {
        let c = load_ok(
            MINIMAL,
            &[
                ("PALISADE_LISTEN__ADMIN__BIND", "overlay0"),
                ("PALISADE_LISTEN__ADMIN__PORT", "9443"),
                ("PALISADE_TLS__KEY_FILE", "/run/secrets/server.key"),
                ("PALISADE_TLS__MIN_VERSION", "1.3"),
                ("PALISADE_DEPLOYMENT__PROFILE", "overlay"),
                ("PALISADE_SHUTDOWN__GRACE_SECS", "5"),
                ("PALISADE_LOG__LEVEL", "debug"),
                ("PALISADE_LISTEN__METRICS__PORT", "9100"),
            ],
        )
        .config;
        let admin = listener(&c, ListenerKind::Admin);
        assert_eq!(admin.bind, BindTarget::Interface("overlay0".to_owned()));
        assert_eq!(admin.port, 9443);
        assert_eq!(c.tls.key_file, Path::new("/run/secrets/server.key"));
        assert_eq!(c.tls.min_version, TlsVersion::Tls13);
        assert_eq!(c.profile, Profile::Overlay);
        assert_eq!(c.shutdown_grace, Duration::from_secs(5));
        assert_eq!(c.log_level, LevelFilter::DEBUG);
        let m = listener(&c, ListenerKind::Metrics);
        assert_eq!(m.port, 9100, "an env var can enable the metrics listener");
    }

    #[test]
    fn env_can_supply_a_whole_config() {
        let c = load_ok(
            "",
            &[
                ("PALISADE_TLS__CERT_FILE", "c.pem"),
                ("PALISADE_TLS__KEY_FILE", "k.pem"),
                ("PALISADE_LISTEN__ADMIN__BIND", "::1"),
                ("PALISADE_LISTEN__ADMIN__PORT", "1"),
                ("PALISADE_LISTEN__AGENT__BIND", "[::1]"),
                ("PALISADE_LISTEN__AGENT__PORT", "2"),
                ("PALISADE_LISTEN__AGENT__CLIENT_CA_FILE", "ca.pem"),
            ],
        )
        .config;
        assert_eq!(c.listeners.len(), 2);
    }

    #[test]
    fn unknown_env_vars_warn_and_config_var_is_ignored() {
        let l = load_ok(
            MINIMAL,
            &[
                ("PALISADE_CONFIG", "/elsewhere.toml"),
                ("PALISADE_SERVER", "https://x"),
                ("PALISADE_LISTEN__ADMIN__NOPE", "1"),
                ("PALISADE_LISTEN__RELAY__BIND", "1"),
            ],
        );
        assert_eq!(l.warnings.len(), 3, "{:?}", l.warnings);
        assert!(l.warnings.iter().all(|w| w.starts_with("ignoring unknown")));
    }

    #[test]
    fn bad_env_integers_are_errors() {
        let e = load_err(MINIMAL, &[("PALISADE_LISTEN__ADMIN__PORT", "70000")]);
        assert_eq!(e.len(), 1, "no second 'is required' error: {e:?}");
        assert!(e[0].contains("PALISADE_LISTEN__ADMIN__PORT"), "{e:?}");
    }

    #[test]
    fn unknown_listener_env_var_does_not_enable_the_listener() {
        let l = load_ok(MINIMAL, &[("PALISADE_LISTEN__METRICS__NOPE", "1")]);
        assert_eq!(l.warnings.len(), 1);
        assert!(
            l.config
                .listeners
                .iter()
                .all(|x| x.kind != ListenerKind::Metrics),
            "metrics must stay disabled"
        );
    }

    #[test]
    fn oversized_and_non_utf8_files_are_rejected() {
        let dir = std::env::temp_dir().join(format!("palisade-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let big = dir.join("big.toml");
        std::fs::write(
            &big,
            vec![b'#'; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        let e = load(&big, &[]).unwrap_err();
        assert!(e.0[0].contains("larger than"), "{e}");
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, [0xff, 0xfe]).unwrap();
        let e = load(&bad, &[]).unwrap_err();
        assert!(e.0[0].contains("not valid UTF-8"), "{e}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let e = load_err(
            r#"
            [deployment]
            profile = "cloud"
            [tls]
            min_version = "1.1"
            profile = "weak"
            [listen.admin]
            bind = "10.0.0.1:8443"
            port = 0
            public_url = "http://x"
            body_limit_bytes = 0
            [listen.agent]
            bind = "127.0.0.1"
            port = 1
            [listen.metrics]
            client_ca_file = "x"
            public_url = "https://x"
            [log]
            level = "loud"
            [shutdown]
            grace_secs = 99999
            "#,
            &[],
        );
        let joined = e.join("\n");
        for needle in [
            "deployment.profile",
            "tls.cert_file",
            "tls.key_file",
            "tls.min_version",
            "tls.profile",
            "listen.admin.bind",
            "listen.admin.port",
            "listen.admin.public_url",
            "listen.admin.body_limit_bytes",
            "listen.agent.client_ca_file",
            "listen.metrics.client_ca_file",
            "listen.metrics.public_url",
            "log.level",
            "shutdown.grace_secs",
        ] {
            assert!(joined.contains(needle), "missing {needle} in:\n{joined}");
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let e = load_err(&format!("{MINIMAL}\n[listen.admin.extra]\n"), &[]);
        assert!(e[0].contains("test.toml"), "{e:?}");
        let e = load_err("[tls]\npassword = \"x\"\n", &[]);
        assert!(e[0].contains("unknown field"), "{e:?}");
    }

    #[test]
    fn missing_sections_are_reported() {
        let e = load_err("[tls]\ncert_file = \"a\"\nkey_file = \"b\"\n", &[]);
        assert!(e.iter().any(|m| m.starts_with("listen.admin:")), "{e:?}");
        assert!(e.iter().any(|m| m.starts_with("listen.agent:")), "{e:?}");
    }

    #[test]
    fn overlapping_listeners_are_rejected() {
        let e = load_err(&MINIMAL.replace("port = 8444", "port = 8443"), &[]);
        assert!(e[0].contains("both use"), "{e:?}");
        let e = load_err(
            &MINIMAL.replace("port = 8444", "port = 8443").replacen(
                "bind = \"127.0.0.1\"",
                "bind = \"0.0.0.0\"",
                1,
            ),
            &[],
        );
        assert!(e[0].contains("both use"), "{e:?}");
        // A wildcard and an interface on the same port may clash.
        let e = load_err(
            &MINIMAL
                .replace("port = 8444", "port = 8443")
                .replacen("bind = \"127.0.0.1\"", "bind = \"::\"", 1)
                .replacen("bind = \"127.0.0.1\"", "bind = \"overlay0\"", 1),
            &[],
        );
        assert!(e[0].contains("both use"), "{e:?}");
        // Different address families on the same port do not clash.
        load_ok(
            &MINIMAL.replace("port = 8444", "port = 8443").replacen(
                "bind = \"127.0.0.1\"",
                "bind = \"::\"",
                1,
            ),
            &[],
        );
    }

    #[test]
    fn bind_parsing() {
        assert_eq!(
            parse_bind("100.64.0.7").unwrap(),
            BindTarget::Ip("100.64.0.7".parse().unwrap())
        );
        assert_eq!(
            parse_bind("[fd00::1]").unwrap(),
            BindTarget::Ip("fd00::1".parse().unwrap())
        );
        assert_eq!(
            parse_bind("Ethernet 2").unwrap(),
            BindTarget::Interface("Ethernet 2".to_owned())
        );
        assert!(parse_bind("").is_err());
        assert!(parse_bind("10.0.0.1:8443").is_err());
        assert!(parse_bind("[::1]:8443").is_err());
        assert!(parse_bind("10.0.0.0/8").is_err());
        assert!(parse_bind("bad\nname").is_err());
    }

    #[test]
    fn public_url_parsing() {
        let u = parse_public_url("https://palisade-server.overlay.test:8443/").unwrap();
        assert_eq!(
            u.host,
            ServerName::try_from("palisade-server.overlay.test").unwrap()
        );
        let u = parse_public_url("https://[fd7a:115c::1]:8443").unwrap();
        assert!(matches!(u.host, ServerName::IpAddress(_)));
        let u = parse_public_url("https://100.64.1.2").unwrap();
        assert!(matches!(u.host, ServerName::IpAddress(_)));
        for bad in [
            "http://x",
            "x",
            "https://user@x",
            "https://x/?q=1",
            "https://x/#f",
            "https:///path",
        ] {
            assert!(parse_public_url(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn effective_json_shows_key_path_only() {
        let c = load_ok(MINIMAL, &[]).config;
        let v = c.effective_json();
        let key = v["tls"]["key_file"].as_str().unwrap();
        assert!(key.contains("server.key") && key.contains("never shown"));
        assert_eq!(v["listen"]["admin"]["port"], 8443);
        assert_eq!(v["listen"]["admin"]["bind"]["address"], "127.0.0.1");
        assert_eq!(v["log"]["level"], "info");
    }

    const DB: &str = r#"
        [database]
        host = "db.internal"
        name = "palisade"
        user = "palisade_app"
        password_file = "secrets/db-runtime.password"
        ca_file = "tls/db-ca.crt"

        [database.migration]
        user = "palisade_owner"
        password_file = "secrets/db-owner.password"
    "#;

    #[test]
    fn database_section_gets_defaults() {
        let l = load_ok(&format!("{MINIMAL}{DB}"), &[]);
        assert!(l.warnings.is_empty(), "{:?}", l.warnings);
        let d = l.config.database.unwrap();
        assert_eq!(d.port, 5432);
        assert_eq!(d.tls, DbTls::VerifyFull, "verify-full by default");
        assert_eq!(d.max_connections, 16);
        assert_eq!(d.connect_timeout, Duration::from_secs(5));
        assert!(d.auto_migrate, "on by default with a migration login");
        let off = load_ok(
            &format!("{MINIMAL}{DB}").replace(
                "[database.migration]",
                "auto_migrate = false\n[database.migration]",
            ),
            &[],
        );
        assert!(!off.config.database.unwrap().auto_migrate);
        let no_login = format!("{MINIMAL}{DB}");
        let (runtime_only, _) = no_login.split_once("[database.migration]").unwrap();
        assert!(
            !load_ok(runtime_only, &[])
                .config
                .database
                .unwrap()
                .auto_migrate
        );
        assert_eq!(
            d.runtime.password_file,
            Path::new("/etc/palisade/secrets/db-runtime.password")
        );
        assert_eq!(d.migration.unwrap().user, "palisade_owner");
        assert_eq!(
            d.ca_file.as_deref(),
            Some(Path::new("/etc/palisade/tls/db-ca.crt"))
        );
    }

    #[test]
    fn database_is_optional() {
        assert!(load_ok(MINIMAL, &[]).config.database.is_none());
    }

    #[test]
    fn database_env_overrides() {
        let c = load_ok(
            MINIMAL,
            &[
                ("PALISADE_DATABASE__HOST", "127.0.0.1"),
                ("PALISADE_DATABASE__PORT", "55432"),
                ("PALISADE_DATABASE__NAME", "p"),
                ("PALISADE_DATABASE__USER", "app"),
                ("PALISADE_DATABASE__PASSWORD_FILE", "/run/secrets/app"),
                ("PALISADE_DATABASE__TLS", "disable"),
                ("PALISADE_DATABASE__AUTO_MIGRATE", "true"),
                ("PALISADE_DATABASE__MIGRATION__USER", "owner"),
                (
                    "PALISADE_DATABASE__MIGRATION__PASSWORD_FILE",
                    "/run/secrets/owner",
                ),
            ],
        );
        assert_eq!(c.warnings.len(), 1, "disable warns: {:?}", c.warnings);
        assert!(c.warnings[0].contains("not authenticated"));
        let d = c.config.database.unwrap();
        assert_eq!(
            (d.port, d.tls, d.auto_migrate),
            (55432, DbTls::Disable, true)
        );
        assert_eq!(
            d.migration.unwrap().password_file,
            Path::new("/run/secrets/owner")
        );
    }

    #[test]
    fn unknown_database_env_var_does_not_enable_the_section() {
        let l = load_ok(
            MINIMAL,
            &[
                ("PALISADE_DATABASE__PASSWORD", "hunter2"),
                ("PALISADE_DATABASE__MIGRATION__PASSWORD", "hunter2"),
            ],
        );
        assert_eq!(l.warnings.len(), 2);
        assert!(l.config.database.is_none());
        assert!(l.warnings.iter().all(|w| !w.contains("hunter2")));
    }

    #[test]
    fn database_password_values_are_rejected() {
        let e = load_err(&format!("{MINIMAL}[database]\npassword = \"x\"\n"), &[]);
        assert!(e[0].contains("unknown field"), "{e:?}");
    }

    #[test]
    fn database_problems_are_reported_at_once() {
        let e = load_err(
            &format!(
                "{MINIMAL}[database]\nport = 0\nname = \"\"\ntls = \"prefer\"\nmax_connections = 0\nconnect_timeout_secs = 0\nauto_migrate = true\nca_file = \"x\"\n"
            ),
            &[("PALISADE_DATABASE__AUTO_MIGRATE", "yes")],
        );
        let joined = e.join("\n");
        for needle in [
            "PALISADE_DATABASE__AUTO_MIGRATE",
            "database.host",
            "database.port",
            "database.name",
            "database.user",
            "database.password_file",
            "database.tls",
            "database.max_connections",
            "database.connect_timeout_secs",
            "database.auto_migrate",
        ] {
            assert!(joined.contains(needle), "missing {needle} in:\n{joined}");
        }
    }

    #[test]
    fn database_host_is_an_address_or_a_name() {
        for (host, want) in [
            ("db.internal", "db.internal"),
            ("10.0.0.5", "10.0.0.5"),
            ("[fd00::5]", "fd00::5"),
            ("fd00::5", "fd00::5"),
        ] {
            let text = format!("{MINIMAL}{DB}").replace("db.internal", host);
            let d = load_ok(&text, &[]).config.database.unwrap();
            assert_eq!(d.host, want);
        }
        for bad in [
            "127.0.0.1:5432",
            "db internal",
            "/var/run/postgresql",
            "db..internal",
        ] {
            let text = format!("{MINIMAL}{DB}").replace("db.internal", bad);
            let e = load_err(&text, &[]);
            assert!(
                e.iter().any(|m| m.starts_with("database.host")),
                "{bad}: {e:?}"
            );
        }
    }

    #[test]
    fn an_incomplete_migration_section_is_one_error() {
        let text = format!("{MINIMAL}{DB}").replace("user = \"palisade_owner\"\n", "");
        let e = load_err(&text, &[]);
        assert_eq!(e, ["database.migration.user: is required"], "{e:?}");
    }

    #[test]
    fn runtime_and_migration_roles_must_differ() {
        let text = format!("{MINIMAL}{DB}").replace("palisade_owner", "palisade_app");
        let e = load_err(&text, &[]);
        assert!(e[0].contains("must differ"), "{e:?}");
    }

    #[test]
    fn empty_ca_file_is_its_own_error() {
        let text = format!("{MINIMAL}{DB}").replace("\"tls/db-ca.crt\"", "\"\"");
        let e = load_err(&text, &[]);
        assert_eq!(e, ["database.ca_file: must not be empty"], "{e:?}");
    }

    #[test]
    fn ca_file_needs_a_verifying_mode() {
        let text = format!("{MINIMAL}{DB}").replace(
            "name = \"palisade\"",
            "name = \"palisade\"\ntls = \"require\"",
        );
        let e = load_err(&text, &[]);
        assert!(e.iter().any(|m| m.contains("database.ca_file")), "{e:?}");
    }

    #[test]
    fn effective_json_shows_database_password_paths_only() {
        let v = load_ok(&format!("{MINIMAL}{DB}"), &[])
            .config
            .effective_json();
        let d = &v["database"];
        assert_eq!(d["tls"], "verify-full");
        assert!(d["password_file"].as_str().unwrap().contains("never shown"));
        assert!(
            d["migration"]["password_file"]
                .as_str()
                .unwrap()
                .contains("never shown")
        );
        assert_eq!(
            load_ok(MINIMAL, &[]).config.effective_json()["database"],
            Value::Null
        );
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config/server.example.toml");
        let l = load_ok(text, &[]);
        assert!(l.warnings.is_empty());
        assert_eq!(l.config.listeners.len(), 3);
        let db = l.config.database.unwrap();
        assert!(db.auto_migrate && db.migration.is_some());
        assert_eq!(db.tls, DbTls::VerifyFull);
    }
}
