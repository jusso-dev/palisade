//! Agent configuration: built-in defaults, overlaid by the install-time file.
//!
//! Issue #56 defines four layers, lowest priority first: built-in defaults,
//! the install-time file `%ProgramData%\Palisade\agent.toml`, policy-delivered
//! agent settings, and local overrides. This module implements the first two.
//! The policy and local-override layers arrive with the policy cache (#61).
//!
//! The file is parsed strictly: unknown keys, wrong types and out-of-range
//! values are errors, so a typo cannot silently fall back to a default. A file
//! that exists but cannot be read or parsed stops the agent from starting
//! instead of running with defaults, because the defaults could be weaker
//! than what the file asked for (for example `fail_mode`). The OS-native
//! policy keeps enforcing while the agent is down (ADR 0012).

use std::{
    fmt,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use serde::Deserialize;

/// Largest configuration file accepted, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Upper bound for `runtime.worker_threads`.
pub const MAX_WORKER_THREADS: usize = 64;
/// Upper bound for `runtime.max_blocking_threads`.
pub const MAX_BLOCKING_THREADS: usize = 256;
/// The default worker count is `min(DEFAULT_WORKER_CAP, cores)`.
pub const DEFAULT_WORKER_CAP: usize = 4;
/// Default size of the blocking pool used for file I/O and hashing. The
/// CPU and I/O budgets that refine it are #65.
pub const DEFAULT_BLOCKING_THREADS: usize = 8;

/// What enforcement components do when the decision engine is unavailable.
///
/// The default is [`FailMode::FailOpen`] for M1. That is a security
/// trade-off: while the agent's engine is down, agent-side decisions allow,
/// and the OS-native policy, which the kernel enforces without the agent,
/// remains the baseline (ADR 0002, ADR 0012). Enforcement components (#113)
/// consume this setting; the service host only carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Allow when the engine is unavailable.
    #[default]
    FailOpen,
    /// Block when the engine is unavailable.
    FailClosed,
}

/// How the agent behaves when Windows is booted in safe mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeModeBehaviour {
    /// Enforce the cached policy.
    EnforceCached,
    /// Evaluate and report, but do not block.
    #[default]
    AuditOnly,
    /// Do not evaluate at all.
    Disabled,
}

/// Maximum level of log records that are emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational records and above.
    #[default]
    Info,
    /// Debug records and above.
    Debug,
    /// Everything.
    Trace,
}

/// Async runtime sizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// Worker threads. `None` means `min(4, cores)`.
    pub worker_threads: Option<usize>,
    /// Size of the blocking pool for file I/O and hashing.
    pub max_blocking_threads: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_blocking_threads: DEFAULT_BLOCKING_THREADS,
        }
    }
}

impl RuntimeConfig {
    /// The worker count to use on a machine with `available` cores.
    pub fn effective_worker_threads(&self, available: usize) -> usize {
        self.worker_threads
            .unwrap_or_else(|| available.clamp(1, DEFAULT_WORKER_CAP))
    }
}

/// The effective agent configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentConfig {
    /// See [`FailMode`].
    pub fail_mode: FailMode,
    /// See [`SafeModeBehaviour`].
    pub safe_mode_behaviour: SafeModeBehaviour,
    /// Async runtime sizing.
    pub runtime: RuntimeConfig,
    /// Log level.
    pub log_level: LogLevel,
}

/// The file layer. Every field is optional and overrides the default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    fail_mode: Option<FailMode>,
    safe_mode_behaviour: Option<SafeModeBehaviour>,
    runtime: Option<FileRuntime>,
    log: Option<FileLog>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRuntime {
    worker_threads: Option<usize>,
    max_blocking_threads: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLog {
    level: Option<LogLevel>,
}

impl AgentConfig {
    /// Built-in defaults overlaid with the TOML document `source`.
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let file: FileConfig = toml::from_str(source)
            .map_err(|e| ConfigError::new(ConfigErrorKind::Parse(e.message().to_owned())))?;
        let mut config = Self::default();
        if let Some(v) = file.fail_mode {
            config.fail_mode = v;
        }
        if let Some(v) = file.safe_mode_behaviour {
            config.safe_mode_behaviour = v;
        }
        if let Some(runtime) = file.runtime {
            if runtime.worker_threads.is_some() {
                config.runtime.worker_threads = runtime.worker_threads;
            }
            if let Some(v) = runtime.max_blocking_threads {
                config.runtime.max_blocking_threads = v;
            }
        }
        if let Some(level) = file.log.and_then(|l| l.level) {
            config.log_level = level;
        }
        config.validate()?;
        Ok(config)
    }

    /// Checks value ranges.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(n) = self.runtime.worker_threads {
            check_range("runtime.worker_threads", n, MAX_WORKER_THREADS)?;
        }
        check_range(
            "runtime.max_blocking_threads",
            self.runtime.max_blocking_threads,
            MAX_BLOCKING_THREADS,
        )
    }
}

fn check_range(field: &'static str, value: usize, max: usize) -> Result<(), ConfigError> {
    if (1..=max).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::new(ConfigErrorKind::Invalid {
            field,
            message: format!("must be between 1 and {max}, got {value}"),
        }))
    }
}

/// A configuration and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
    /// The effective configuration.
    pub config: AgentConfig,
    /// The file it was read from, or `None` for built-in defaults only.
    pub source: Option<PathBuf>,
}

/// The install-time configuration path: `%ProgramData%\Palisade\agent.toml`
/// on Windows, `None` elsewhere.
pub fn default_path() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(|dir| PathBuf::from(dir).join("Palisade").join("agent.toml"))
    } else {
        None
    }
}

/// Loads the configuration.
///
/// An `explicit` path (from `--config`) must exist. Otherwise the
/// [`default_path`] is used if it exists, and built-in defaults if not.
pub fn load(explicit: Option<&Path>) -> Result<LoadedConfig, ConfigError> {
    let (path, required) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => match default_path() {
            Some(path) => (path, false),
            None => return Ok(defaults()),
        },
    };
    match read_limited(&path) {
        Ok(Some(text)) => AgentConfig::from_toml(&text)
            .map(|config| LoadedConfig {
                config,
                source: Some(path.clone()),
            })
            .map_err(|e| e.at(&path)),
        Ok(None) if !required => Ok(defaults()),
        Ok(None) => Err(ConfigError::new(ConfigErrorKind::Io(io::Error::from(
            io::ErrorKind::NotFound,
        )))
        .at(&path)),
        Err(e) => Err(e.at(&path)),
    }
}

fn defaults() -> LoadedConfig {
    LoadedConfig {
        config: AgentConfig::default(),
        source: None,
    }
}

/// Reads a UTF-8 file of at most [`MAX_CONFIG_BYTES`]. A missing file is
/// `Ok(None)`.
fn read_limited(path: &Path) -> Result<Option<String>, ConfigError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ConfigError::new(ConfigErrorKind::Io(e))),
    };
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ConfigError::new(ConfigErrorKind::Io(e)))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        return Err(ConfigError::new(ConfigErrorKind::TooLarge {
            limit: MAX_CONFIG_BYTES,
        }));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ConfigError::new(ConfigErrorKind::NotUtf8))
}

/// A configuration that could not be loaded.
#[derive(Debug)]
pub struct ConfigError {
    path: Option<PathBuf>,
    kind: ConfigErrorKind,
}

/// What went wrong while loading a configuration.
#[derive(Debug)]
pub enum ConfigErrorKind {
    /// The file could not be opened or read.
    Io(io::Error),
    /// The file is larger than the limit.
    TooLarge {
        /// The limit in bytes.
        limit: u64,
    },
    /// The file is not UTF-8.
    NotUtf8,
    /// The file is not valid TOML, has an unknown key or a wrong type.
    Parse(String),
    /// A value is out of range.
    Invalid {
        /// The dotted key.
        field: &'static str,
        /// Why it is invalid.
        message: String,
    },
}

impl ConfigError {
    fn new(kind: ConfigErrorKind) -> Self {
        Self { path: None, kind }
    }

    fn at(mut self, path: &Path) -> Self {
        self.path = Some(path.to_path_buf());
        self
    }

    /// The file the error refers to, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// What went wrong.
    pub fn kind(&self) -> &ConfigErrorKind {
        &self.kind
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(f, "{}: ", path.display())?;
        }
        match &self.kind {
            ConfigErrorKind::Io(e) => write!(f, "cannot read configuration: {e}"),
            ConfigErrorKind::TooLarge { limit } => {
                write!(f, "configuration is larger than {limit} bytes")
            }
            ConfigErrorKind::NotUtf8 => f.write_str("configuration is not valid UTF-8"),
            ConfigErrorKind::Parse(message) => write!(f, "invalid configuration: {message}"),
            ConfigErrorKind::Invalid { field, message } => write!(f, "{field} {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ConfigErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_is_the_defaults() {
        let config = AgentConfig::from_toml("").unwrap();
        assert_eq!(config, AgentConfig::default());
        assert_eq!(config.fail_mode, FailMode::FailOpen);
        assert_eq!(config.safe_mode_behaviour, SafeModeBehaviour::AuditOnly);
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.runtime.worker_threads, None);
        assert_eq!(
            config.runtime.max_blocking_threads,
            DEFAULT_BLOCKING_THREADS
        );
    }

    #[test]
    fn file_values_override_defaults() {
        let config = AgentConfig::from_toml(
            r#"
            fail_mode = "fail_closed"
            safe_mode_behaviour = "enforce_cached"
            [runtime]
            worker_threads = 2
            max_blocking_threads = 16
            [log]
            level = "debug"
            "#,
        )
        .unwrap();
        assert_eq!(config.fail_mode, FailMode::FailClosed);
        assert_eq!(config.safe_mode_behaviour, SafeModeBehaviour::EnforceCached);
        assert_eq!(config.runtime.worker_threads, Some(2));
        assert_eq!(config.runtime.max_blocking_threads, 16);
        assert_eq!(config.log_level, LogLevel::Debug);
    }

    #[test]
    fn partial_tables_keep_other_defaults() {
        let config = AgentConfig::from_toml("[runtime]\nworker_threads = 3\n").unwrap();
        assert_eq!(config.runtime.worker_threads, Some(3));
        assert_eq!(
            config.runtime.max_blocking_threads,
            DEFAULT_BLOCKING_THREADS
        );
        assert_eq!(config.fail_mode, FailMode::FailOpen);
    }

    #[test]
    fn unknown_keys_and_bad_values_are_rejected() {
        for source in [
            "fail_mod = \"fail_open\"",
            "fail_mode = \"open\"",
            "fail_mode = 1",
            "[runtime]\nworkers = 2",
            "[runtime]\nworker_threads = -1",
            "[log]\nlevel = \"loud\"",
            "[extra]",
            "not toml",
        ] {
            let err = AgentConfig::from_toml(source).unwrap_err();
            assert!(
                matches!(err.kind(), ConfigErrorKind::Parse(_)),
                "{source:?} gave {err}"
            );
        }
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        for (source, field) in [
            ("[runtime]\nworker_threads = 0", "runtime.worker_threads"),
            ("[runtime]\nworker_threads = 65", "runtime.worker_threads"),
            (
                "[runtime]\nmax_blocking_threads = 0",
                "runtime.max_blocking_threads",
            ),
            (
                "[runtime]\nmax_blocking_threads = 257",
                "runtime.max_blocking_threads",
            ),
        ] {
            let err = AgentConfig::from_toml(source).unwrap_err();
            assert!(
                matches!(err.kind(), ConfigErrorKind::Invalid { field: f, .. } if *f == field),
                "{source:?} gave {err}"
            );
        }
        assert!(AgentConfig::from_toml("[runtime]\nworker_threads = 64").is_ok());
    }

    #[test]
    fn default_worker_count_is_min_four_cores() {
        let runtime = RuntimeConfig::default();
        assert_eq!(runtime.effective_worker_threads(1), 1);
        assert_eq!(runtime.effective_worker_threads(3), 3);
        assert_eq!(runtime.effective_worker_threads(32), 4);
        assert_eq!(runtime.effective_worker_threads(0), 1);
        let fixed = RuntimeConfig {
            worker_threads: Some(8),
            ..RuntimeConfig::default()
        };
        assert_eq!(fixed.effective_worker_threads(2), 8);
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "palisade-agent-config-{tag}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_reads_an_explicit_file() {
        let dir = TempDir::new("explicit");
        let path = dir.0.join("agent.toml");
        std::fs::write(&path, "fail_mode = \"fail_closed\"\n").unwrap();
        let loaded = load(Some(&path)).unwrap();
        assert_eq!(loaded.source.as_deref(), Some(path.as_path()));
        assert_eq!(loaded.config.fail_mode, FailMode::FailClosed);
    }

    #[test]
    fn explicit_file_must_exist() {
        let dir = TempDir::new("missing");
        let path = dir.0.join("absent.toml");
        let err = load(Some(&path)).unwrap_err();
        assert_eq!(err.path(), Some(path.as_path()));
        assert!(
            matches!(err.kind(), ConfigErrorKind::Io(e) if e.kind() == io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn invalid_file_is_an_error_not_defaults() {
        let dir = TempDir::new("invalid");
        let path = dir.0.join("agent.toml");
        std::fs::write(&path, "fail_mode = \"sometimes\"\n").unwrap();
        let err = load(Some(&path)).unwrap_err();
        assert!(err.to_string().starts_with(&path.display().to_string()));
        assert!(matches!(err.kind(), ConfigErrorKind::Parse(_)));
    }

    #[test]
    fn oversized_and_non_utf8_files_are_rejected() {
        let dir = TempDir::new("limits");
        let big = dir.0.join("big.toml");
        let limit = usize::try_from(MAX_CONFIG_BYTES).unwrap();
        std::fs::write(&big, "#".repeat(limit + 1)).unwrap();
        assert!(matches!(
            load(Some(&big)).unwrap_err().kind(),
            ConfigErrorKind::TooLarge { .. }
        ));
        let exact = dir.0.join("exact.toml");
        std::fs::write(&exact, "#".repeat(limit)).unwrap();
        assert!(load(Some(&exact)).is_ok());
        let binary = dir.0.join("binary.toml");
        std::fs::write(&binary, [0xff, 0xfe, 0x00]).unwrap();
        assert!(matches!(
            load(Some(&binary)).unwrap_err().kind(),
            ConfigErrorKind::NotUtf8
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn no_default_path_off_windows() {
        assert_eq!(default_path(), None);
        assert_eq!(load(None).unwrap(), defaults());
    }
}
