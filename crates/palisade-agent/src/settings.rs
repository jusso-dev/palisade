//! Configuration layers and advanced settings (#56).
//!
//! The effective configuration is built from four layers, lowest priority
//! first:
//!
//! 1. built-in defaults ([`AgentConfig::default`]);
//! 2. the install-time file `%ProgramData%\Palisade\agent.toml` (#57);
//! 3. the agent settings delivered with policy ([`PolicySettings`], #61);
//! 4. local overrides, `%ProgramData%\Palisade\overrides.toml`, applied only
//!    while the policy layer sets `allow_local_overrides = true`.
//!
//! [`resolve`] merges them and records where each value came from, for
//! `palctl config show` ([`Effective::render`]). Each layer is parsed
//! strictly (unknown keys and wrong types are errors), and the merged result
//! is range-checked as a whole. Ranges are checked on the merged result,
//! not per layer, so a layer cannot be rejected for a value a higher layer
//! replaces.
//!
//! **Fail closed (ADR 0018).** The policy layer and the overrides are
//! trusted only as far as their source:
//!
//! - Without a policy layer, overrides are not allowed.
//! - An overrides file that exists but cannot be shown to be writable by
//!   SYSTEM and administrators only is ignored and reported
//!   ([`OverrideStatus::Untrusted`]). The check is the caller's
//!   ([`OverrideSource::protected`]); on Windows it is the file's DACL, read
//!   through `palisade_fileid`.
//! - If the merged result is out of range because of the overrides, the
//!   overrides are dropped and reported rather than stopping the agent; if
//!   it is out of range without them, the policy layer is dropped the same
//!   way. The install-time file was range-checked when it loaded.
//!
//! **Advanced settings** (`agent.advanced.*`) are a typed key/value map
//! delivered with policy. [`ADVANCED_SCHEMA`] lists each name, type and
//! range. Unknown keys are logged and ignored, and a value of the wrong type
//! or out of range is logged and replaced by the default, so a bad
//! engineering key never stops the agent and never takes a value nobody
//! validated.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

use palisade_core::platform::FileSystem;
use palisade_fileid::fsctx::{
    acl::{AdminSids, Ancestor, EvaluationOptions, ObjectKind, SecurityDescriptor, assess_path},
    sid::well_known,
};
use serde::Deserialize;

use crate::config::{self, AgentConfig, ConfigError, ConfigLayer, LoadedConfig};

/// Where a configuration value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// The built-in default.
    Default,
    /// The install-time file.
    File,
    /// The policy-delivered agent settings.
    Policy,
    /// A local override.
    Override,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Default => "default",
            Self::File => "file",
            Self::Policy => "policy",
            Self::Override => "override",
        })
    }
}

/// The agent settings delivered with policy (#61): a configuration layer,
/// whether local overrides are allowed, and the advanced settings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicySettings {
    /// The settings that override the install-time file.
    pub layer: ConfigLayer,
    /// `allow_local_overrides`. Default `false`.
    pub allow_local_overrides: bool,
    /// `agent.advanced.*`, as delivered: not yet checked against
    /// [`ADVANCED_SCHEMA`].
    pub advanced: BTreeMap<String, AdvancedValue>,
}

/// The TOML form of [`PolicySettings`]: the layer's keys, plus
/// `allow_local_overrides` and an `[advanced]` table. The layer's keys are
/// listed here rather than flattened in, because serde does not support
/// `deny_unknown_fields` together with `flatten`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicySettingsToml {
    #[serde(default)]
    allow_local_overrides: bool,
    #[serde(default)]
    advanced: BTreeMap<String, AdvancedValue>,
    fail_mode: Option<crate::config::FailMode>,
    safe_mode_behaviour: Option<crate::config::SafeModeBehaviour>,
    runtime: Option<crate::config::RuntimeLayer>,
    log: Option<crate::config::LogLayer>,
}

impl PolicySettings {
    /// Parses the agent-settings section of a policy bundle. The bundle's
    /// format is #61's; until it lands, this TOML form is what the policy
    /// cache hands over.
    pub fn from_toml(source: &str) -> Result<Self, ConfigError> {
        let parsed: PolicySettingsToml = toml::from_str(source).map_err(|e| {
            ConfigError::new(crate::config::ConfigErrorKind::Parse(
                e.message().to_owned(),
            ))
        })?;
        Ok(Self {
            layer: ConfigLayer {
                fail_mode: parsed.fail_mode,
                safe_mode_behaviour: parsed.safe_mode_behaviour,
                runtime: parsed.runtime,
                log: parsed.log,
            },
            allow_local_overrides: parsed.allow_local_overrides,
            advanced: parsed.advanced,
        })
    }
}

/// The local-overrides file, as the caller read it.
#[derive(Debug, Clone, PartialEq)]
pub struct OverrideSource {
    /// Where it was read from.
    pub path: PathBuf,
    /// Its text.
    pub text: String,
    /// Whether only SYSTEM and administrators can write it (and its folder).
    /// `false` when that could not be established.
    pub protected: bool,
}

impl OverrideSource {
    /// Reads the overrides file at `path` through `fs`, and checks that only
    /// SYSTEM, the built-in Administrators and `TrustedInstaller` may write
    /// it or the folders above it. `Ok(None)` if it does not exist.
    ///
    /// `ancestors` are the folders from the file's parent up to the volume
    /// root. A descriptor that cannot be read or parsed, on the file or any
    /// folder, makes the file unprotected: nothing it says is trusted.
    pub fn read<F: FileSystem>(
        fs: &F,
        path: &Path,
        ancestors: &[PathBuf],
    ) -> Result<Option<Self>, ConfigError> {
        let Some(text) = config::read_limited(path).map_err(|e| e.at(path))? else {
            return Ok(None);
        };
        let descriptor = |p: &Path| {
            fs.security_descriptor(&p.to_string_lossy())
                .ok()
                .flatten()
                .and_then(|bytes| SecurityDescriptor::from_self_relative(&bytes).ok())
        };
        let target = descriptor(path);
        let folders: Vec<Ancestor> = ancestors
            .iter()
            .map(|p| Ancestor {
                path: p.display().to_string(),
                descriptor: descriptor(p),
            })
            .collect();
        let options = EvaluationOptions {
            admins: AdminSids::from_sids([
                well_known::LOCAL_SYSTEM,
                well_known::ADMINISTRATORS,
                well_known::TRUSTED_INSTALLER,
            ]),
            ..EvaluationOptions::default()
        };
        let writability = assess_path(target.as_ref(), ObjectKind::File, &folders, &options);
        let protected = target.is_some() && !writability.path_user_writable();
        Ok(Some(Self {
            path: path.to_path_buf(),
            text,
            protected,
        }))
    }
}

/// What happened to the local overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideStatus {
    /// There is no overrides file.
    Absent,
    /// The policy does not allow overrides (or there is no policy), so the
    /// file was not used.
    NotAllowed,
    /// The file may be writable by someone other than SYSTEM and
    /// administrators, so it was not used.
    Untrusted,
    /// The file did not parse, or made the configuration invalid, so it was
    /// not used. The message says why.
    Invalid(String),
    /// The overrides apply.
    Applied,
}

/// The policy layer's fate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyStatus {
    /// No policy settings yet.
    Absent,
    /// They made the configuration invalid and were not used.
    Invalid(String),
    /// They apply.
    Applied,
}

/// The effective configuration and how it was reached.
#[derive(Debug, Clone, PartialEq)]
pub struct Effective {
    /// The merged configuration.
    pub config: AgentConfig,
    /// The install-time file, if one was read.
    pub file: Option<PathBuf>,
    /// The policy layer's fate.
    pub policy: PolicyStatus,
    /// The overrides' fate.
    pub overrides: OverrideStatus,
    /// The validated advanced settings.
    pub advanced: AdvancedSettings,
    /// The layer that set each key; keys not listed are defaults.
    pub sources: BTreeMap<&'static str, Source>,
}

/// Merges the layers (see the module docs).
pub fn resolve(
    base: &LoadedConfig,
    policy: Option<&PolicySettings>,
    overrides: Option<&OverrideSource>,
) -> Effective {
    let file_layer = file_sources(base);
    let mut sources: BTreeMap<&'static str, Source> =
        file_layer.into_iter().map(|k| (k, Source::File)).collect();
    let mut config = base.config.clone();

    let mut policy_status = PolicyStatus::Absent;
    if let Some(policy) = policy {
        let mut next = config.clone();
        let mut keys = Vec::new();
        policy.layer.apply(&mut next, |k| keys.push(k));
        match next.validate() {
            Ok(()) => {
                config = next;
                sources.extend(keys.into_iter().map(|k| (k, Source::Policy)));
                policy_status = PolicyStatus::Applied;
            }
            Err(e) => {
                tracing::error!(error = %e, "policy agent settings are invalid; not applied");
                policy_status = PolicyStatus::Invalid(e.to_string());
            }
        }
    }
    let allowed =
        policy_status == PolicyStatus::Applied && policy.is_some_and(|p| p.allow_local_overrides);

    let override_status = match overrides {
        None => OverrideStatus::Absent,
        Some(_) if !allowed => OverrideStatus::NotAllowed,
        Some(source) if !source.protected => {
            tracing::warn!(
                path = %source.path.display(),
                "local overrides may be writable by non-administrators; not applied"
            );
            OverrideStatus::Untrusted
        }
        Some(source) => match ConfigLayer::from_toml(&source.text) {
            Err(e) => OverrideStatus::Invalid(e.to_string()),
            Ok(layer) => {
                let mut next = config.clone();
                let mut keys = Vec::new();
                layer.apply(&mut next, |k| keys.push(k));
                match next.validate() {
                    Ok(()) => {
                        config = next;
                        sources.extend(keys.into_iter().map(|k| (k, Source::Override)));
                        OverrideStatus::Applied
                    }
                    Err(e) => OverrideStatus::Invalid(e.to_string()),
                }
            }
        },
    };
    if let OverrideStatus::Invalid(e) = &override_status {
        tracing::error!(error = %e, "local overrides are invalid; not applied");
    }

    let advanced = AdvancedSettings::validate(
        policy
            .filter(|_| policy_status == PolicyStatus::Applied)
            .map(|p| &p.advanced),
    );
    Effective {
        config,
        file: base.source.clone(),
        policy: policy_status,
        overrides: override_status,
        advanced,
        sources,
    }
}

/// The keys the install-time file set: those that differ from the
/// defaults. A key set to its default value is shown as a default, which
/// is the same value.
fn file_sources(base: &LoadedConfig) -> Vec<&'static str> {
    let d = AgentConfig::default();
    let c = &base.config;
    let mut keys = Vec::new();
    let mut check = |differs: bool, key| {
        if differs {
            keys.push(key);
        }
    };
    check(c.fail_mode != d.fail_mode, "fail_mode");
    check(
        c.safe_mode_behaviour != d.safe_mode_behaviour,
        "safe_mode_behaviour",
    );
    check(
        c.runtime.worker_threads != d.runtime.worker_threads,
        "runtime.worker_threads",
    );
    check(
        c.runtime.max_blocking_threads != d.runtime.max_blocking_threads,
        "runtime.max_blocking_threads",
    );
    check(c.log_level != d.log_level, "log.level");
    check(c.log_files.files != d.log_files.files, "log.files");
    check(
        c.log_files.file_size_mib != d.log_files.file_size_mib,
        "log.file_size_mib",
    );
    keys
}

impl Effective {
    /// The effective configuration as text for `palctl config show`: one
    /// `key = value  # source` line per setting. Settings marked secret in
    /// [`ADVANCED_SCHEMA`] are shown as `<redacted>`.
    pub fn render(&self) -> String {
        let c = &self.config;
        let worker_threads = c
            .runtime
            .worker_threads
            .map_or_else(|| "\"auto\"".to_owned(), |n| n.to_string());
        let rows: Vec<(&'static str, String)> = vec![
            ("fail_mode", format!("{:?}", c.fail_mode)),
            (
                "safe_mode_behaviour",
                format!("{:?}", c.safe_mode_behaviour),
            ),
            ("runtime.worker_threads", worker_threads),
            (
                "runtime.max_blocking_threads",
                c.runtime.max_blocking_threads.to_string(),
            ),
            ("log.level", format!("{:?}", c.log_level)),
            ("log.files", c.log_files.files.to_string()),
            ("log.file_size_mib", c.log_files.file_size_mib.to_string()),
        ];
        let mut out = String::new();
        for (key, value) in rows {
            let source = self.sources.get(key).copied().unwrap_or(Source::Default);
            out.push_str(&format!("{key} = {value}  # {source}\n"));
        }
        for (spec, value) in self.advanced.iter() {
            let shown = if spec.secret {
                "<redacted>".to_owned()
            } else {
                value.to_string()
            };
            let source = if self.advanced.is_set(spec.name) {
                Source::Policy
            } else {
                Source::Default
            };
            out.push_str(&format!(
                "agent.advanced.{} = {shown}  # {source}\n",
                spec.name
            ));
        }
        out.push_str(&format!(
            "# file: {}\n# policy: {:?}\n# overrides: {:?}\n",
            self.file
                .as_ref()
                .map_or_else(|| "none".to_owned(), |p| p.display().to_string()),
            self.policy,
            self.overrides
        ));
        out
    }
}

/// An advanced-setting value as delivered.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum AdvancedValue {
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string.
    Text(String),
}

impl fmt::Display for AdvancedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Text(s) => write!(f, "{s:?}"),
        }
    }
}

/// The type and range of an advanced setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvancedType {
    /// A boolean.
    Bool,
    /// An integer in `min..=max`.
    Int {
        /// The smallest value accepted.
        min: i64,
        /// The largest value accepted.
        max: i64,
    },
    /// A string of at most `max_len` bytes.
    Text {
        /// The longest value accepted, in bytes.
        max_len: usize,
    },
}

/// One entry of [`ADVANCED_SCHEMA`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdvancedSpec {
    /// The name after `agent.advanced.`.
    pub name: &'static str,
    /// The type and range.
    pub ty: AdvancedType,
    /// The value when it is not set, or set to something invalid.
    pub default: AdvancedDefault,
    /// Whether the value is a secret, redacted in logs and `config show`.
    pub secret: bool,
    /// What it does.
    pub doc: &'static str,
}

/// A schema default; `const`-constructible, unlike [`AdvancedValue`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AdvancedDefault {
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A string.
    Text(&'static str),
}

impl AdvancedDefault {
    fn value(self) -> AdvancedValue {
        match self {
            Self::Bool(b) => AdvancedValue::Bool(b),
            Self::Int(n) => AdvancedValue::Int(n),
            Self::Text(s) => AdvancedValue::Text(s.to_owned()),
        }
    }
}

/// Every advanced setting the agent knows. Later subsystems add theirs here,
/// with a type, range and default, and read them with
/// [`AdvancedSettings::get`].
pub const ADVANCED_SCHEMA: &[AdvancedSpec] = &[
    AdvancedSpec {
        name: "clock_jump_threshold_secs",
        ty: AdvancedType::Int { min: 60, max: 3600 },
        default: AdvancedDefault::Int(300),
        secret: false,
        doc: "Wall-clock change, in seconds, reported as a clock jump (ISM-0988).",
    },
    AdvancedSpec {
        name: "subsystem_panic_limit",
        ty: AdvancedType::Int { min: 1, max: 10 },
        default: AdvancedDefault::Int(3),
        secret: false,
        doc: "Panics within ten minutes that mark a subsystem failed.",
    },
    AdvancedSpec {
        name: "verbose_host_events",
        ty: AdvancedType::Bool,
        default: AdvancedDefault::Bool(false),
        secret: false,
        doc: "Log every session, power and time notification at info level.",
    },
];

/// Validated advanced settings: every schema entry has a value.
#[derive(Debug, Clone, PartialEq)]
pub struct AdvancedSettings {
    values: Vec<(&'static AdvancedSpec, AdvancedValue, bool)>,
}

/// Why a delivered advanced setting was not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvancedIssue {
    /// No such setting.
    Unknown(String),
    /// Wrong type or out of range; the default is used.
    Invalid(&'static str),
}

impl AdvancedSettings {
    /// Every setting at its default.
    pub fn defaults() -> Self {
        Self::validate(None)
    }

    /// Checks `delivered` against [`ADVANCED_SCHEMA`], logging each issue.
    pub fn validate(delivered: Option<&BTreeMap<String, AdvancedValue>>) -> Self {
        let (settings, issues) = Self::check(delivered);
        for issue in issues {
            match issue {
                AdvancedIssue::Unknown(name) => {
                    tracing::warn!(setting = %name, "unknown advanced setting; ignored");
                }
                AdvancedIssue::Invalid(name) => {
                    // The value is not logged: it may be a secret.
                    tracing::warn!(
                        setting = name,
                        "advanced setting has the wrong type or is out of range; using the default"
                    );
                }
            }
        }
        settings
    }

    /// [`Self::validate`] without logging, returning the issues.
    pub fn check(
        delivered: Option<&BTreeMap<String, AdvancedValue>>,
    ) -> (Self, Vec<AdvancedIssue>) {
        let empty = BTreeMap::new();
        let delivered = delivered.unwrap_or(&empty);
        let mut issues: Vec<AdvancedIssue> = delivered
            .keys()
            .filter(|k| !ADVANCED_SCHEMA.iter().any(|s| s.name == k.as_str()))
            .map(|k| AdvancedIssue::Unknown(k.clone()))
            .collect();
        let values = ADVANCED_SCHEMA
            .iter()
            .map(|spec| match delivered.get(spec.name) {
                None => (spec, spec.default.value(), false),
                Some(value) if fits(spec.ty, value) => (spec, value.clone(), true),
                Some(_) => {
                    issues.push(AdvancedIssue::Invalid(spec.name));
                    (spec, spec.default.value(), false)
                }
            })
            .collect();
        (Self { values }, issues)
    }

    /// The value of `name`, or `None` if the schema has no such setting.
    pub fn get(&self, name: &str) -> Option<&AdvancedValue> {
        self.values
            .iter()
            .find(|(s, _, _)| s.name == name)
            .map(|(_, v, _)| v)
    }

    /// Whether `name` was set by policy (and valid).
    pub fn is_set(&self, name: &str) -> bool {
        self.values.iter().any(|(s, _, set)| s.name == name && *set)
    }

    /// Every setting with its spec, in schema order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static AdvancedSpec, &AdvancedValue)> {
        self.values.iter().map(|(s, v, _)| (*s, v))
    }
}

fn fits(ty: AdvancedType, value: &AdvancedValue) -> bool {
    match (ty, value) {
        (AdvancedType::Bool, AdvancedValue::Bool(_)) => true,
        (AdvancedType::Int { min, max }, AdvancedValue::Int(n)) => (min..=max).contains(n),
        (AdvancedType::Text { max_len }, AdvancedValue::Text(s)) => s.len() <= max_len,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FailMode, LogLevel, SafeModeBehaviour};

    fn base(toml: &str) -> LoadedConfig {
        LoadedConfig {
            config: AgentConfig::from_toml(toml).unwrap(),
            source: Some(PathBuf::from("agent.toml")),
        }
    }

    fn overrides(text: &str, protected: bool) -> OverrideSource {
        OverrideSource {
            path: PathBuf::from("overrides.toml"),
            text: text.to_owned(),
            protected,
        }
    }

    #[test]
    fn layers_apply_in_order_and_record_their_source() {
        let policy = PolicySettings::from_toml(
            "allow_local_overrides = true\nfail_mode = \"fail_closed\"\n[log]\nlevel = \"warn\"\n",
        )
        .unwrap();
        let eff = resolve(
            &base("safe_mode_behaviour = \"disabled\"\n[log]\nlevel = \"debug\"\n"),
            Some(&policy),
            Some(&overrides("[log]\nlevel = \"trace\"\n", true)),
        );
        assert_eq!(eff.config.fail_mode, FailMode::FailClosed);
        assert_eq!(eff.config.safe_mode_behaviour, SafeModeBehaviour::Disabled);
        assert_eq!(eff.config.log_level, LogLevel::Trace);
        assert_eq!(eff.policy, PolicyStatus::Applied);
        assert_eq!(eff.overrides, OverrideStatus::Applied);
        assert_eq!(eff.sources["fail_mode"], Source::Policy);
        assert_eq!(eff.sources["safe_mode_behaviour"], Source::File);
        assert_eq!(eff.sources["log.level"], Source::Override);
        assert!(!eff.sources.contains_key("log.files"));
    }

    #[test]
    fn overrides_need_a_policy_that_allows_them_and_a_protected_file() {
        let local = overrides("fail_mode = \"fail_closed\"\n", true);
        let none = resolve(&base(""), None, Some(&local));
        assert_eq!(none.overrides, OverrideStatus::NotAllowed);
        assert_eq!(none.config.fail_mode, FailMode::FailOpen);

        let denied = PolicySettings::default();
        let eff = resolve(&base(""), Some(&denied), Some(&local));
        assert_eq!(eff.overrides, OverrideStatus::NotAllowed);

        let allowed = PolicySettings {
            allow_local_overrides: true,
            ..PolicySettings::default()
        };
        let eff = resolve(
            &base(""),
            Some(&allowed),
            Some(&overrides("fail_mode = \"fail_closed\"\n", false)),
        );
        assert_eq!(eff.overrides, OverrideStatus::Untrusted);
        assert_eq!(eff.config.fail_mode, FailMode::FailOpen);

        let eff = resolve(&base(""), Some(&allowed), None);
        assert_eq!(eff.overrides, OverrideStatus::Absent);
    }

    #[test]
    fn invalid_layers_are_dropped_not_fatal() {
        let allowed = PolicySettings::from_toml(
            "allow_local_overrides = true\nfail_mode = \"fail_closed\"\n",
        )
        .unwrap();
        for text in ["[log]\nfiles = 0\n", "nonsense = 1\n", "not toml"] {
            let eff = resolve(&base(""), Some(&allowed), Some(&overrides(text, true)));
            assert!(
                matches!(eff.overrides, OverrideStatus::Invalid(_)),
                "{text}"
            );
            // The policy layer still applies.
            assert_eq!(eff.config.fail_mode, FailMode::FailClosed);
        }

        let bad_policy = PolicySettings::from_toml(
            "allow_local_overrides = true\n[runtime]\nworker_threads = 0\n",
        )
        .unwrap();
        let eff = resolve(
            &base("fail_mode = \"fail_closed\"\n"),
            Some(&bad_policy),
            Some(&overrides("[log]\nlevel = \"trace\"\n", true)),
        );
        assert!(matches!(eff.policy, PolicyStatus::Invalid(_)));
        // An invalid policy cannot allow overrides.
        assert_eq!(eff.overrides, OverrideStatus::NotAllowed);
        assert_eq!(eff.config.fail_mode, FailMode::FailClosed);
        assert_eq!(eff.config.log_level, LogLevel::Info);
    }

    #[test]
    fn a_higher_layer_can_fix_a_value_a_lower_one_set() {
        // Ranges are checked on the merged result.
        let policy = PolicySettings::from_toml("[runtime]\nworker_threads = 2\n").unwrap();
        let eff = resolve(
            &base("[runtime]\nworker_threads = 8\n"),
            Some(&policy),
            None,
        );
        assert_eq!(eff.config.runtime.worker_threads, Some(2));
        assert_eq!(eff.sources["runtime.worker_threads"], Source::Policy);
    }

    #[test]
    fn policy_settings_parse_strictly() {
        assert!(PolicySettings::from_toml("bogus = 1\n").is_err());
        assert!(PolicySettings::from_toml("[runtime]\nworkers = 1\n").is_err());
        assert!(PolicySettings::from_toml("[advanced]\nx = 1.5\n").is_err());
        assert!(PolicySettings::from_toml("allow_local_overrides = \"yes\"\n").is_err());
        let p =
            PolicySettings::from_toml("[advanced]\nverbose_host_events = true\nmystery = \"x\"\n")
                .unwrap();
        assert!(!p.allow_local_overrides);
        assert_eq!(
            p.advanced.get("verbose_host_events"),
            Some(&AdvancedValue::Bool(true))
        );
    }

    #[test]
    fn advanced_settings_are_validated_against_the_schema() {
        let delivered: BTreeMap<String, AdvancedValue> = [
            ("clock_jump_threshold_secs", AdvancedValue::Int(120)),
            ("subsystem_panic_limit", AdvancedValue::Int(99)),
            ("verbose_host_events", AdvancedValue::Text("yes".into())),
            ("unheard_of", AdvancedValue::Bool(true)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let (settings, issues) = AdvancedSettings::check(Some(&delivered));
        assert_eq!(
            issues,
            [
                AdvancedIssue::Unknown("unheard_of".into()),
                AdvancedIssue::Invalid("subsystem_panic_limit"),
                AdvancedIssue::Invalid("verbose_host_events"),
            ]
        );
        assert_eq!(
            settings.get("clock_jump_threshold_secs"),
            Some(&AdvancedValue::Int(120))
        );
        assert!(settings.is_set("clock_jump_threshold_secs"));
        assert_eq!(
            settings.get("subsystem_panic_limit"),
            Some(&AdvancedValue::Int(3))
        );
        assert!(!settings.is_set("subsystem_panic_limit"));
        assert_eq!(settings.get("unheard_of"), None);
        assert_eq!(
            AdvancedSettings::defaults().iter().count(),
            ADVANCED_SCHEMA.len()
        );
        // Logging path.
        let logged = AdvancedSettings::validate(Some(&delivered));
        assert_eq!(logged, settings);
    }

    #[test]
    fn text_settings_are_length_checked_and_secrets_redacted() {
        static SPEC: AdvancedSpec = AdvancedSpec {
            name: "token",
            ty: AdvancedType::Text { max_len: 4 },
            default: AdvancedDefault::Text(""),
            secret: true,
            doc: "",
        };
        assert!(fits(SPEC.ty, &AdvancedValue::Text("abcd".into())));
        assert!(!fits(SPEC.ty, &AdvancedValue::Text("abcde".into())));
        assert!(!fits(SPEC.ty, &AdvancedValue::Int(1)));
        let settings = AdvancedSettings {
            values: vec![(&SPEC, AdvancedValue::Text("s3cr".into()), true)],
        };
        let eff = Effective {
            config: AgentConfig::default(),
            file: None,
            policy: PolicyStatus::Applied,
            overrides: OverrideStatus::Absent,
            advanced: settings,
            sources: BTreeMap::new(),
        };
        let text = eff.render();
        assert!(text.contains("agent.advanced.token = <redacted>  # policy"));
        assert!(!text.contains("s3cr"));
    }

    #[test]
    fn render_lists_every_setting_with_its_source() {
        let policy = PolicySettings::from_toml(
            "[advanced]\nverbose_host_events = true\n[runtime]\nworker_threads = 2\n",
        )
        .unwrap();
        let eff = resolve(&base("fail_mode = \"fail_closed\"\n"), Some(&policy), None);
        let text = eff.render();
        for line in [
            "fail_mode = FailClosed  # file",
            "safe_mode_behaviour = AuditOnly  # default",
            "runtime.worker_threads = 2  # policy",
            "runtime.max_blocking_threads = 8  # default",
            "log.level = Info  # default",
            "log.files = 10  # default",
            "log.file_size_mib = 10  # default",
            "agent.advanced.clock_jump_threshold_secs = 300  # default",
            "agent.advanced.verbose_host_events = true  # policy",
            "# file: agent.toml",
            "# policy: Applied",
            "# overrides: Absent",
        ] {
            assert!(text.contains(line), "missing {line:?} in\n{text}");
        }
        let auto = resolve(&base(""), None, None).render();
        assert!(auto.contains("runtime.worker_threads = \"auto\"  # default"));
        assert!(auto.contains("# policy: Absent"));
        assert_eq!(Source::Override.to_string(), "override");
        assert_eq!(AdvancedValue::Text("a".into()).to_string(), "\"a\"");
    }

    mod read {
        use palisade_core::test_util::{MockFile, MockFileSystem};
        use palisade_fileid::fsctx::acl::{Ace, mask};

        use super::*;

        struct Dir(PathBuf);

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn locked() -> Vec<u8> {
            SecurityDescriptor::new(
                Some(well_known::LOCAL_SYSTEM),
                Some(vec![
                    Ace::allow(well_known::LOCAL_SYSTEM, mask::FILE_ALL_ACCESS),
                    Ace::allow(well_known::ADMINISTRATORS, mask::FILE_ALL_ACCESS),
                ]),
            )
            .to_self_relative()
            .unwrap()
        }

        fn writable_by(sid: palisade_fileid::fsctx::sid::Sid) -> Vec<u8> {
            SecurityDescriptor::new(
                Some(well_known::LOCAL_SYSTEM),
                Some(vec![
                    Ace::allow(well_known::LOCAL_SYSTEM, mask::FILE_ALL_ACCESS),
                    Ace::allow(sid, mask::FILE_ALL_ACCESS),
                ]),
            )
            .to_self_relative()
            .unwrap()
        }

        fn setup(tag: &str) -> (Dir, PathBuf, Vec<PathBuf>) {
            let dir = std::env::temp_dir().join(format!(
                "palisade-agent-overrides-{tag}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let file = dir.join("overrides.toml");
            std::fs::write(&file, "fail_mode = \"fail_closed\"\n").unwrap();
            let ancestors = vec![dir.clone()];
            (Dir(dir), file, ancestors)
        }

        fn fs(
            file: &Path,
            file_sd: Option<Vec<u8>>,
            dir: &Path,
            dir_sd: Option<Vec<u8>>,
        ) -> MockFileSystem {
            let mut fs = MockFileSystem::new();
            let mut f = MockFile::new(Vec::new());
            if let Some(sd) = file_sd {
                f = f.descriptor(sd);
            }
            fs.insert(&file.to_string_lossy(), f);
            let mut d = MockFile::directory();
            if let Some(sd) = dir_sd {
                d = d.descriptor(sd);
            }
            fs.insert(&dir.to_string_lossy(), d);
            fs
        }

        #[test]
        fn a_locked_down_file_is_protected() {
            let (_d, file, folders) = setup("locked");
            let mock = fs(&file, Some(locked()), &folders[0], Some(locked()));
            let src = OverrideSource::read(&mock, &file, &folders)
                .unwrap()
                .unwrap();
            assert!(src.protected);
            assert_eq!(src.text, "fail_mode = \"fail_closed\"\n");
        }

        #[test]
        fn anything_less_is_unprotected() {
            let (_d, file, folders) = setup("open");
            for (file_sd, dir_sd) in [
                // Users may write the file.
                (Some(writable_by(well_known::USERS)), Some(locked())),
                // A service account the default model treats as admin.
                (
                    Some(writable_by(well_known::NETWORK_SERVICE)),
                    Some(locked()),
                ),
                // The folder lets users replace the file.
                (
                    Some(locked()),
                    Some(writable_by(well_known::AUTHENTICATED_USERS)),
                ),
                // Unreadable descriptors.
                (None, Some(locked())),
                (Some(locked()), None),
                (Some(vec![1, 2, 3]), Some(locked())),
            ] {
                let mock = fs(&file, file_sd, &folders[0], dir_sd);
                let src = OverrideSource::read(&mock, &file, &folders)
                    .unwrap()
                    .unwrap();
                assert!(!src.protected);
            }
        }

        #[test]
        fn a_missing_file_is_none() {
            let (_d, file, folders) = setup("missing");
            std::fs::remove_file(&file).unwrap();
            let mock = MockFileSystem::new();
            assert_eq!(OverrideSource::read(&mock, &file, &folders).unwrap(), None);
        }
    }
}
