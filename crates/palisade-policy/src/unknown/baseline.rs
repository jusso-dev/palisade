//! `system_baseline`: the managed, read-only rule set that lets a stock
//! Windows install boot and log on under default-deny (#39).
//!
//! It holds one `allow` rule. An object matches when all of these hold:
//!
//! - a trusted signature from one of the OS publishers the agent reports
//!   ([`SystemBaseline::publishers`]). The publisher names come from the
//!   agent's view of the OS catalogs (#3, #4), not from this crate;
//! - the file is under `%WINDIR%` or `%PROGRAMFILES%`. As in every allow, a
//!   path only identifies an object where no non-administrator can write
//!   it (#31), so a writable file never matches; and
//! - the file is not in one of the **mandatory exceptions**: the known
//!   user-writable folders inside the Windows directory
//!   ([`MANDATORY_EXCEPTIONS`], ISM-1392), every directory the
//!   writable-path scanner flagged ([`SystemBaseline::writable_dirs`]), and
//!   any alternate data stream.
//!
//! The rule set is a `baseline`, `read_only` set with the well-known ID
//! [`SYSTEM_BASELINE_ID`]. It is a **floor** at stage 4: the evaluator
//! decides over its rule only when no other allow or deny matched, so
//! under every precedence model (including `first_match` with
//! `curated_first`) a tenant's rule wins over it. A mandatory deny, at
//! stage 1, still blocks anything it covers, so the baseline cannot
//! re-enable a blocked binary (#35, ADR 0004).
//!
//! Every input value is checked before the rule is built: publishers are
//! trimmed text, and scanner-flagged directories are drive or UNC paths
//! with no stream, so no value can be silently ignored at evaluation.

use crate::model::{
    PolicyDocument, PrecedenceModel, PriorityDirection, RuleSet, RuleSetId, limits,
};

/// The well-known ID of the managed `system_baseline` rule set.
pub const SYSTEM_BASELINE_ID: &str = "00000000-0000-7000-8000-00000000b001";

/// The ID of its rule.
pub const SYSTEM_BASELINE_RULE_ID: &str = "00000000-0000-7000-8000-00000000b101";

/// The user-writable folders inside the OS locations that the baseline
/// never allows, as path wildcards (ISM-1392). `%SYSTEM32%` stands for
/// both the native and the 32-bit system directories. The crypto store is
/// written with a wildcard for the vendor folder above it.
pub const MANDATORY_EXCEPTIONS: [&str; 11] = [
    "%SYSTEM32%\\spool\\drivers\\color\\**",
    "%SYSTEM32%\\Tasks\\**",
    "%WINDIR%\\Tasks\\**",
    "%WINDIR%\\Temp\\**",
    "%SYSTEM32%\\*\\Crypto\\RSA\\MachineKeys\\**",
    "%SYSTEM32%\\Com\\dmp\\**",
    "%SYSTEM32%\\FxsTmp\\**",
    "%SYSTEM32%\\spool\\PRINTERS\\**",
    "%SYSTEM32%\\spool\\SERVERS\\**",
    "%WINDIR%\\Registration\\CRMLog\\**",
    "%WINDIR%\\tracing\\**",
];

/// The most scanner-flagged directories one baseline can hold: the rule's
/// criteria limit, less the criteria the rule always has, times the values
/// per criterion.
pub const MAX_WRITABLE_DIRS: usize =
    (limits::MAX_CRITERIA_PER_RULE - 5) * limits::MAX_VALUES_PER_CRITERION;

/// The facts the baseline is built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemBaseline {
    /// The publishers that sign the operating system, as the agent reports
    /// them: 1 to 25 names.
    pub publishers: Vec<String>,
    /// The directories in OS locations that the writable-path scanner
    /// flagged (#5, #17), as drive or UNC paths.
    pub writable_dirs: Vec<String>,
}

/// Whether `set` is the managed `system_baseline`: its well-known ID, as a
/// read-only `baseline` rule set.
#[must_use]
pub fn is_system_baseline(set: &RuleSet) -> bool {
    set.read_only
        && set.kind == crate::model::RuleSetKind::Baseline
        && set.id.to_string() == SYSTEM_BASELINE_ID
}

/// Why a baseline cannot be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaselineError {
    /// No publisher, or more than 25.
    Publishers(usize),
    /// More scanner-flagged directories than [`MAX_WRITABLE_DIRS`].
    TooManyWritableDirs(usize),
    /// A value is empty or longer than the per-value limit.
    InvalidValue(String),
    /// The rule set does not deserialise. A bug.
    Model(String),
}

impl core::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Publishers(n) => write!(
                f,
                "{n} publishers; 1 to {} are allowed",
                limits::MAX_VALUES_PER_CRITERION
            ),
            Self::TooManyWritableDirs(n) => {
                write!(
                    f,
                    "{n} writable directories; at most {MAX_WRITABLE_DIRS} are allowed"
                )
            }
            Self::InvalidValue(v) => write!(f, "invalid value `{v}`"),
            Self::Model(e) => write!(f, "the baseline does not build: {e}"),
        }
    }
}

impl std::error::Error for BaselineError {}

fn crit(field: &str, operator: &str, values: &[String]) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": values}})
}

/// The `system_baseline` rule set for `facts`, with the `order` and
/// `priority` that make it valid under `policy`'s model: a catch-all
/// `order` under `first_match`, and the weakest priority under `priority`.
/// The evaluator treats it as a floor under every model anyway.
///
/// # Errors
///
/// Returns [`BaselineError`] if the facts do not fit in one rule.
pub fn system_baseline(
    facts: &SystemBaseline,
    model: PrecedenceModel,
    direction: PriorityDirection,
) -> Result<RuleSet, BaselineError> {
    let n = facts.publishers.len();
    if n == 0 || n > limits::MAX_VALUES_PER_CRITERION {
        return Err(BaselineError::Publishers(n));
    }
    if facts.writable_dirs.len() > MAX_WRITABLE_DIRS {
        return Err(BaselineError::TooManyWritableDirs(
            facts.writable_dirs.len(),
        ));
    }
    let bad = |v: &str| {
        v.trim().is_empty()
            || v.trim() != v
            || v.len() > limits::MAX_VALUE_BYTES
            || v.chars().any(char::is_control)
    };
    if let Some(v) = facts.publishers.iter().find(|v| bad(v)) {
        return Err(BaselineError::InvalidValue(v.clone()));
    }
    for v in &facts.writable_dirs {
        let p = palisade_core::path::normalize(v);
        if bad(v) || !p.is_resolved() || p.stream().is_some() || v.contains(['%', '*', '?']) {
            return Err(BaselineError::InvalidValue(v.clone()));
        }
    }
    let exceptions: Vec<String> = MANDATORY_EXCEPTIONS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let mut excluded = vec![
        crit("path.directory", "wildcard", &exceptions),
        // An alternate data stream, including one on a directory.
        crit("path.full", "wildcard", &["**:**".to_owned()]),
    ];
    for chunk in facts.writable_dirs.chunks(limits::MAX_VALUES_PER_CRITERION) {
        excluded.push(crit("path.directory", "starts_with", chunk));
    }
    let tree = serde_json::json!({"all": [
        crit("signer.publisher", "equals", &facts.publishers),
        {"any": [
            crit("path.directory", "wildcard", &["%WINDIR%\\**".to_owned()]),
            crit("path.directory", "wildcard", &["%PROGRAMFILES%\\**".to_owned()]),
        ]},
        {"not": {"any": excluded}},
    ]});
    let mut rule = serde_json::json!({
        "id": SYSTEM_BASELINE_RULE_ID,
        "name": "Operating system binaries",
        "description": "Allows binaries signed by the operating system's publishers in the Windows and program-files directories, except the user-writable folders inside them.",
        "match": tree,
        "action": {"type": "allow"},
    });
    let extra = rule
        .as_object_mut()
        .ok_or_else(|| BaselineError::Model("rule".into()))?;
    match model {
        PrecedenceModel::FirstMatch => {
            extra.insert("order".into(), 999_990.into());
        }
        PrecedenceModel::Priority => {
            let weakest = match direction {
                PriorityDirection::LowerWins => i32::MAX,
                PriorityDirection::HigherWins => i32::MIN,
            };
            extra.insert("priority".into(), weakest.into());
        }
        PrecedenceModel::DenyWins | PrecedenceModel::AllowWins | PrecedenceModel::Specificity => {}
    }
    let set = serde_json::json!({
        "id": SYSTEM_BASELINE_ID,
        "name": "system_baseline",
        "description": "Managed: the platform-critical allow set (#39). Read-only.",
        "kind": "baseline",
        "read_only": true,
        "rules": [rule],
    });
    serde_json::from_value(set).map_err(|e| BaselineError::Model(e.to_string()))
}

impl PolicyDocument {
    /// Adds the `system_baseline` rule set for `facts`, or replaces the one
    /// already there, and references it from the policy.
    ///
    /// # Errors
    ///
    /// Returns [`BaselineError`] if the facts do not fit in one rule.
    pub fn with_system_baseline(mut self, facts: &SystemBaseline) -> Result<Self, BaselineError> {
        let set = system_baseline(
            facts,
            self.policy.precedence_model,
            self.policy.precedence_options.priority_direction,
        )?;
        let id: RuleSetId = set.id;
        self.rule_sets.retain(|s| s.id != id);
        self.rule_sets.push(set);
        if !self.policy.rule_sets.contains(&id) {
            self.policy.rule_sets.push(id);
        }
        Ok(self)
    }
}
