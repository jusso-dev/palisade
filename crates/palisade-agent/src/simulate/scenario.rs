//! The scenario file format for `--simulate`.
//!
//! Strict TOML: unknown keys and wrong types are errors, like the agent's
//! configuration. See the crate README for the format and
//! `scenarios/default.toml` for an example.

use std::{collections::BTreeSet, fmt, path::Path};

use palisade_proto::events::{Outcome, Timestamp};
use serde::Deserialize;

/// Largest scenario file accepted, in bytes.
pub const MAX_SCENARIO_BYTES: u64 = 1024 * 1024;
/// Most steps in one scenario.
pub const MAX_STEPS: usize = 10_000;
/// Longest pause between two steps: one day.
pub const MAX_AFTER_MS: u64 = 86_400_000;

/// The built-in scenario.
pub const DEFAULT: &str = include_str!("../../scenarios/default.toml");

/// A parsed, checked scenario.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// The wall-clock time when the simulated agent starts.
    pub start: Timestamp,
    /// The enforcement mode the events report: `audit`, `monitor`,
    /// `learning` or `enforce`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// The device.
    pub device: DeviceSpec,
    /// Every user that a process runs as.
    #[serde(default, rename = "user")]
    pub users: Vec<UserSpec>,
    /// Processes running before the first step.
    #[serde(default)]
    pub running: Vec<ProcessSpec>,
    /// The steps, in order.
    #[serde(default, rename = "step")]
    pub steps: Vec<StepSpec>,
}

fn default_mode() -> String {
    "audit".to_owned()
}

/// The simulated device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSpec {
    /// The host name.
    pub hostname: String,
    /// The DNS domain, if joined to one.
    pub domain: Option<String>,
    /// `major.minor.build.revision`.
    pub os_version: String,
    /// `x64`, `arm64` or `x86`.
    pub architecture: String,
    /// The tenant ID, a UUIDv7.
    pub tenant_id: String,
    /// The device ID from enrolment, a UUIDv7.
    pub host_id: String,
}

/// A user account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    /// The SID.
    pub sid: String,
    /// The account name.
    pub name: String,
    /// The domain or computer name.
    pub domain: Option<String>,
    /// `console`, `remote_desktop` or `services`.
    pub session: String,
    /// Whether the user's processes run elevated.
    #[serde(default)]
    pub elevated: bool,
}

/// A process that is already running.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
    /// The process ID.
    pub pid: u32,
    /// The parent process ID.
    pub parent: Option<u32>,
    /// The image path.
    pub image: String,
    /// The SID of the user it runs as.
    pub user: String,
}

/// One step: time passes, processes may exit, then one process starts and
/// the agent reports its execution.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    /// Milliseconds since the previous step.
    #[serde(default)]
    pub after_ms: u64,
    /// Process IDs that exit before the new process starts.
    #[serde(default)]
    pub exited: Vec<u32>,
    /// The new process ID.
    pub pid: u32,
    /// The parent process ID.
    pub parent: Option<u32>,
    /// The image path.
    pub image: String,
    /// The command line.
    pub command_line: Option<String>,
    /// The SID of the user it runs as.
    pub user: String,
    /// `allowed`, `blocked` or `audited`.
    pub outcome: String,
    /// The publisher of the image's signature, if it is signed.
    pub signer: Option<String>,
}

/// A scenario that could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioError(pub String);

impl fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScenarioError {}

fn err(message: impl Into<String>) -> ScenarioError {
    ScenarioError(message.into())
}

impl Scenario {
    /// Parses and checks a scenario.
    ///
    /// # Errors
    ///
    /// Invalid TOML, an unknown key, or a broken rule: a user that is not
    /// declared, a duplicate or missing process ID, too many steps, or a
    /// value out of range.
    pub fn from_toml(source: &str) -> Result<Self, ScenarioError> {
        let scenario: Self = toml::from_str(source).map_err(|e| err(e.message()))?;
        scenario.check()?;
        Ok(scenario)
    }

    /// Reads and parses the scenario at `path`, of at most
    /// [`MAX_SCENARIO_BYTES`].
    ///
    /// # Errors
    ///
    /// The file cannot be read, is too large or not UTF-8, or
    /// [`Scenario::from_toml`] fails.
    pub fn load(path: &Path) -> Result<Self, ScenarioError> {
        use std::io::Read as _;
        let file =
            std::fs::File::open(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
        let mut bytes = Vec::new();
        file.take(MAX_SCENARIO_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| err(format!("{}: {e}", path.display())))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SCENARIO_BYTES {
            return Err(err(format!(
                "{}: larger than {MAX_SCENARIO_BYTES} bytes",
                path.display()
            )));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| err(format!("{}: not valid UTF-8", path.display())))?;
        Self::from_toml(&text).map_err(|e| err(format!("{}: {e}", path.display())))
    }

    fn check(&self) -> Result<(), ScenarioError> {
        if self.steps.len() > MAX_STEPS {
            return Err(err(format!("more than {MAX_STEPS} steps")));
        }
        if !matches!(
            self.mode.as_str(),
            "audit" | "monitor" | "learning" | "enforce"
        ) {
            return Err(err(format!("mode: unknown mode `{}`", self.mode)));
        }
        let mut sids = BTreeSet::new();
        for user in &self.users {
            if !matches!(
                user.session.as_str(),
                "console" | "remote_desktop" | "services"
            ) {
                return Err(err(format!(
                    "user {}: unknown session `{}`",
                    user.sid, user.session
                )));
            }
            if !sids.insert(user.sid.to_ascii_uppercase()) {
                return Err(err(format!("user {} is declared twice", user.sid)));
            }
        }
        let known_user = |sid: &str, what: &str| {
            if sids.contains(&sid.to_ascii_uppercase()) {
                Ok(())
            } else {
                Err(err(format!("{what}: user {sid} is not declared")))
            }
        };
        let mut live = BTreeSet::new();
        for p in &self.running {
            known_user(&p.user, &format!("running process {}", p.pid))?;
            if !live.insert(p.pid) {
                return Err(err(format!("running process {} is listed twice", p.pid)));
            }
        }
        for (i, step) in self.steps.iter().enumerate() {
            let what = format!("step {}", i + 1);
            known_user(&step.user, &what)?;
            if step.after_ms > MAX_AFTER_MS {
                return Err(err(format!("{what}: after_ms is more than {MAX_AFTER_MS}")));
            }
            if parse_outcome(&step.outcome).is_none() {
                return Err(err(format!("{what}: unknown outcome `{}`", step.outcome)));
            }
            for pid in &step.exited {
                if !live.remove(pid) {
                    return Err(err(format!("{what}: process {pid} is not running")));
                }
            }
            if !live.insert(step.pid) {
                return Err(err(format!(
                    "{what}: process {} is already running; list it in `exited` first",
                    step.pid
                )));
            }
        }
        Ok(())
    }
}

/// The event outcome for a step's `outcome` text.
pub(crate) fn parse_outcome(text: &str) -> Option<Outcome> {
    match text {
        "allowed" => Some(Outcome::Allowed),
        "blocked" => Some(Outcome::Blocked),
        "audited" => Some(Outcome::Audited),
        _ => None,
    }
}
