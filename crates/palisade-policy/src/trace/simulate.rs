//! The policy simulator (#41): replays recorded facts against a policy and
//! a candidate, and reports what would change.
//!
//! # Inputs
//!
//! A [`FactsSnapshot`] is one recorded decision's inputs: the object's
//! type, facts and path variables, the user, device and session, and the
//! device's state. Snapshots come from events, from a YAML or JSON test
//! file, or from a facts corpus exported from a device inventory (#5); all
//! three use this one versioned format ([`FACTS_SCHEMA_VERSION`]), read by
//! [`read_snapshots`]. A snapshot of another major version is rejected,
//! never guessed at. A fact a snapshot lacks is absent, so a rule that
//! needs it evaluates to unknown, exactly as on the agent.
//!
//! # Candidates
//!
//! A [`Candidate`] is another policy document (a draft revision), the
//! current document with a [`ChangeSet`] applied, or the current policy in
//! another mode (`audit` to `enforce`). It is validated before it is
//! simulated.
//!
//! # The same evaluator
//!
//! Every decision is made by [`Evaluator::evaluate_in`], the function the
//! agent calls, on the same validated document. The simulator has no logic
//! of its own: given the same facts and device state, it decides what an
//! agent decides. The canonical bundle (#43) will be loaded into the same
//! [`ValidatedPolicy`].
//!
//! # Determinism
//!
//! Events are evaluated in parallel, a chunk per thread, and the results
//! are sorted by event ID, so the report does not depend on the number of
//! threads. Duplicate event IDs are rejected.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::context::{DeviceContext, EvaluationContext, SessionContext, SessionType, UserContext};
use crate::decision::{Decision, Outcome, ReasonCode, RuleRef, TraceId};
use crate::dsl::{self, Limits};
use crate::evaluate::{BuildError, Evaluator, Subject};
use crate::facts::{
    ObjectFacts, PathFact, PathVariable, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use crate::mode::{Connectivity, DeviceState, SessionKind};
use crate::model::{Field, Mode, ObjectType, PolicyDocument, Rule, RuleId, RuleSetId};
use crate::validate::{ValidatedPolicy, ValidationError};

use super::{ObjectExtras, Trace, TraceLevel, TraceOptions, Tracer};

/// The version of the facts snapshot format.
pub const FACTS_SCHEMA_VERSION: &str = "1.0.0";

/// The most snapshots read from one input.
pub const MAX_SNAPSHOTS: usize = 1_000_000;

/// The most entries in each aggregate list of a report.
pub const MAX_AGGREGATE: usize = 1_000;

/// The most threads a simulation uses.
pub const MAX_THREADS: usize = 256;

/// The most changed events listed in a report.
pub const MAX_CHANGES_LISTED: usize = 10_000;

/// A file of snapshots: the format version and the snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFile {
    /// [`FACTS_SCHEMA_VERSION`], or an older minor version of it.
    pub facts_schema_version: String,
    /// The snapshots.
    pub snapshots: Vec<FactsSnapshot>,
}

/// One recorded decision's inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactsSnapshot {
    /// The event's ID, unique within a run.
    pub event_id: String,
    /// The device, for aggregates.
    #[serde(default)]
    pub device_id: Option<String>,
    /// When it happened, in wall-clock seconds, for readiness windows.
    #[serde(default)]
    pub timestamp: Option<i64>,
    /// The object's type.
    pub object_type: ObjectType,
    /// The object's facts.
    #[serde(default)]
    pub facts: SnapshotFacts,
    /// The path variables, for the user the process ran as.
    #[serde(default)]
    pub variables: BTreeMap<String, Vec<String>>,
    /// The user, device and session.
    #[serde(default)]
    pub context: SnapshotContext,
    /// The device's state.
    #[serde(default)]
    pub device_state: SnapshotState,
    /// The decision the agent recorded, if any, for the cross-check
    /// ([`cross_check`]).
    #[serde(default)]
    pub recorded: Option<RecordedDecision>,
}

/// The object's facts in a snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFacts {
    /// Hash, version-resource and version facts, by field name.
    #[serde(default)]
    pub values: BTreeMap<Field, String>,
    /// The path.
    #[serde(default)]
    pub path: Option<SnapshotPath>,
    /// The signatures: `null` if nobody looked, `[]` if unsigned.
    #[serde(default)]
    pub signers: Option<Vec<SnapshotSigner>>,
}

/// A path fact in a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPath {
    /// The final path.
    pub path: String,
    /// The other form of the same path, if any.
    #[serde(default)]
    pub alias: Option<String>,
    /// An 8.3 short name could not be expanded.
    #[serde(default)]
    pub short_name_unresolved: bool,
    /// Whether users can write it: `null` if not determined.
    #[serde(default)]
    pub user_writable: Option<bool>,
    /// The kind of volume it is on: `null` if not recorded (#39). Without
    /// it, stage 6 cannot rule out a removable, optical or network volume.
    #[serde(default)]
    pub volume: Option<SnapshotVolume>,
}

/// The kind of volume a recorded file was on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotVolume {
    /// A fixed disk.
    Fixed,
    /// A removable volume, such as a USB drive.
    Removable,
    /// An optical disc.
    Optical,
    /// A network volume.
    Network,
}

impl From<SnapshotVolume> for crate::unknown::VolumeKind {
    fn from(v: SnapshotVolume) -> Self {
        match v {
            SnapshotVolume::Fixed => Self::Fixed,
            SnapshotVolume::Removable => Self::Removable,
            SnapshotVolume::Optical => Self::Optical,
            SnapshotVolume::Network => Self::Network,
        }
    }
}

/// A signature in a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSigner {
    /// The verification result.
    pub status: SnapshotSignerStatus,
    /// Where it came from: `embedded` (the default) or `catalog`.
    #[serde(default)]
    pub catalog: bool,
    /// The leaf subject's common name.
    #[serde(default)]
    pub publisher: Option<String>,
    /// The leaf issuer's common name.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The leaf thumbprint, SHA-256 hex.
    #[serde(default)]
    pub leaf_thumbprint_sha256: Option<String>,
}

/// [`SignerStatus`], as a snapshot writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum SnapshotSignerStatus {
    Valid,
    ValidExpiredTimestamped,
    CatalogSigned,
    Expired,
    Revoked,
    UntrustedRoot,
    DigestMismatch,
}

/// The context in a snapshot. Every field is optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct SnapshotContext {
    #[serde(default)]
    pub user_sid: Option<String>,
    #[serde(default)]
    pub user_account_name: Option<String>,
    #[serde(default)]
    pub user_upn: Option<String>,
    #[serde(default)]
    pub user_groups: Option<Vec<String>>,
    #[serde(default)]
    pub user_primary_group: Option<String>,
    #[serde(default)]
    pub user_is_admin: Option<bool>,
    #[serde(default)]
    pub user_is_elevated: Option<bool>,
    #[serde(default)]
    pub user_is_service_account: Option<bool>,
    #[serde(default)]
    pub user_is_system: Option<bool>,
    #[serde(default)]
    pub device_hostname: Option<String>,
    #[serde(default)]
    pub device_fqdn: Option<String>,
    #[serde(default)]
    pub device_domain: Option<String>,
    #[serde(default)]
    pub device_netbios: Option<String>,
    #[serde(default)]
    pub device_ad_site: Option<String>,
    #[serde(default)]
    pub device_groups: Option<Vec<String>>,
    #[serde(default)]
    pub device_tags: Option<Vec<String>>,
    #[serde(default)]
    pub device_os_version: Option<String>,
    #[serde(default)]
    pub device_os_edition: Option<String>,
    #[serde(default)]
    pub device_arch: Option<String>,
    #[serde(default)]
    pub device_is_server: Option<bool>,
    #[serde(default)]
    pub device_is_domain_controller: Option<bool>,
    #[serde(default)]
    pub device_is_laptop: Option<bool>,
    #[serde(default)]
    pub device_is_vdi: Option<bool>,
    #[serde(default)]
    pub device_is_terminal_server: Option<bool>,
    #[serde(default)]
    pub session_type: Option<String>,
    #[serde(default)]
    pub session_client_hostname: Option<String>,
    #[serde(default)]
    pub session_is_remote: Option<bool>,
}

/// The device's state in a snapshot. Unset fields are the policy's mode,
/// connected, no session, no lockdown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotState {
    /// The device's base mode; the policy's mode if unset.
    #[serde(default)]
    pub mode: Option<Mode>,
    /// The device was disconnected.
    #[serde(default)]
    pub disconnected: bool,
    /// An override session was active: `audit` or `full_bypass`.
    #[serde(default)]
    pub session: Option<SnapshotSession>,
    /// Emergency lockdown was set.
    #[serde(default)]
    pub lockdown: bool,
}

/// An override session in a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum SnapshotSession {
    Audit,
    FullBypass,
}

/// The decision an agent recorded, for [`cross_check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedDecision {
    /// The outcome.
    pub outcome: SimOutcome,
    /// The deciding rule, if any.
    #[serde(default)]
    pub rule_id: Option<RuleId>,
}

/// An outcome, as a snapshot and a report write it. `not_evaluated` is a
/// disabled device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimOutcome {
    /// It runs.
    Allowed,
    /// It does not run.
    Blocked,
    /// It runs, but enforce mode would block it.
    AllowedAudit,
    /// It runs because of an override session.
    AllowedOverride,
    /// An `ignore` rule excluded it.
    Ignored,
    /// It waits for the user to answer a prompt (#39). It does not run
    /// until then, so it counts as blocked for changes.
    PendingUser,
    /// The device is disabled: nothing was decided.
    NotEvaluated,
}

impl SimOutcome {
    /// The outcome of a decision, or `not_evaluated` for none.
    #[must_use]
    pub fn of(d: Option<&Decision>) -> Self {
        match d.map(Decision::outcome) {
            None => Self::NotEvaluated,
            Some(Outcome::Allowed) => Self::Allowed,
            Some(Outcome::Blocked) => Self::Blocked,
            Some(Outcome::AllowedAudit) => Self::AllowedAudit,
            Some(Outcome::AllowedOverride) => Self::AllowedOverride,
            Some(Outcome::Ignored) => Self::Ignored,
            Some(Outcome::PendingUser) => Self::PendingUser,
        }
    }

    /// Whether the object runs (or is not stopped): everything but
    /// `blocked` and `pending_user`.
    #[must_use]
    pub const fn runs(self) -> bool {
        !matches!(self, Self::Blocked | Self::PendingUser)
    }
}

/// A snapshot could not be read or used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// The input is not a snapshot file.
    Parse(String),
    /// The format version is not one this reader can read.
    UnsupportedVersion(String),
    /// Too many snapshots.
    TooMany(usize),
    /// Two snapshots have the same event ID.
    DuplicateEvent(String),
    /// A snapshot has a value this version cannot use, such as an unknown
    /// path variable or session type.
    Invalid {
        /// The event.
        event_id: String,
        /// What is wrong.
        message: String,
    },
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "not a facts snapshot file: {m}"),
            Self::UnsupportedVersion(v) => write!(
                f,
                "facts_schema_version {v} is not readable by this simulator ({FACTS_SCHEMA_VERSION}); migrate the snapshots first"
            ),
            Self::TooMany(n) => write!(f, "{n} snapshots; at most {MAX_SNAPSHOTS}"),
            Self::DuplicateEvent(e) => write!(f, "event {e} appears more than once"),
            Self::Invalid { event_id, message } => write!(f, "event {event_id}: {message}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Reads a snapshot file, YAML or JSON (YAML is read with the policy
/// reader's strict rules and limits).
///
/// # Errors
///
/// Returns [`SnapshotError`] if the input does not parse, has a major
/// version other than 1, has too many snapshots or duplicate event IDs,
/// or a snapshot has a value this version cannot use.
pub fn read_snapshots(input: &str) -> Result<SnapshotFile, SnapshotError> {
    let value = dsl::to_json_value(input, &Limits::DEFAULT)
        .map_err(|e| SnapshotError::Parse(e.to_string()))?;
    let version = value
        .get("facts_schema_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| SnapshotError::Parse("missing facts_schema_version".to_owned()))?
        .to_owned();
    let readable = version
        .parse::<palisade_core::SchemaVersion>()
        .ok()
        .zip(
            FACTS_SCHEMA_VERSION
                .parse::<palisade_core::SchemaVersion>()
                .ok(),
        )
        .is_some_and(|(v, reader)| readable(v, reader));
    if !readable {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    if let Some(n) = value
        .get("snapshots")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        && n > MAX_SNAPSHOTS
    {
        return Err(SnapshotError::TooMany(n));
    }
    let file: SnapshotFile =
        serde_json::from_value(value).map_err(|e| SnapshotError::Parse(e.to_string()))?;
    check_snapshots(&file.snapshots)?;
    Ok(file)
}

/// Whether a reader at `reader` reads a file at `v`: the same major
/// version and no newer minor version. Patch versions change no meaning.
pub(crate) fn readable(
    v: palisade_core::SchemaVersion,
    reader: palisade_core::SchemaVersion,
) -> bool {
    v.is_readable_by(reader) && v.minor <= reader.minor
}

/// Checks that event IDs are unique and every snapshot can be used.
///
/// # Errors
///
/// The first problem found.
pub fn check_snapshots(snapshots: &[FactsSnapshot]) -> Result<(), SnapshotError> {
    if snapshots.len() > MAX_SNAPSHOTS {
        return Err(SnapshotError::TooMany(snapshots.len()));
    }
    let mut seen = BTreeSet::new();
    for s in snapshots {
        if !seen.insert(s.event_id.as_str()) {
            return Err(SnapshotError::DuplicateEvent(s.event_id.clone()));
        }
        s.inputs()?;
    }
    Ok(())
}

/// The evaluation inputs a snapshot stands for.
#[derive(Clone, Debug)]
pub struct Inputs {
    /// The facts.
    pub facts: ObjectFacts,
    /// The path variables.
    pub variables: PathVariables,
    /// The user, device and session.
    pub context: EvaluationContext,
}

impl FactsSnapshot {
    /// The evaluation inputs.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Invalid`] for an unknown path variable, a
    /// fact recorded under a field that is not stored as a value, or an
    /// unknown session type.
    pub fn inputs(&self) -> Result<Inputs, SnapshotError> {
        let invalid = |message: String| SnapshotError::Invalid {
            event_id: self.event_id.clone(),
            message,
        };
        let volumes = palisade_core::path::VolumeMap::new();
        let mut facts = ObjectFacts::new();
        for (field, v) in &self.facts.values {
            if !facts.set(*field, v.clone()) {
                return Err(invalid(format!(
                    "{} is not a value fact; use path, signers or context",
                    super::record::field_name(*field)
                )));
            }
        }
        if let Some(p) = &self.facts.path {
            let mut fact = PathFact::new(&p.path, &volumes);
            fact.alias = p.alias.as_deref().map(|a| PathFact::new(a, &volumes).path);
            fact.short_name_unresolved = p.short_name_unresolved;
            fact.user_writable = p.user_writable;
            fact.volume = p.volume.map(Into::into);
            facts.path = Some(fact);
        }
        if let Some(signers) = &self.facts.signers {
            facts.signers = Some(
                signers
                    .iter()
                    .map(|s| SignerFact {
                        status: match s.status {
                            SnapshotSignerStatus::Valid => SignerStatus::Valid,
                            SnapshotSignerStatus::ValidExpiredTimestamped => {
                                SignerStatus::ValidExpiredTimestamped
                            }
                            SnapshotSignerStatus::CatalogSigned => SignerStatus::CatalogSigned,
                            SnapshotSignerStatus::Expired => SignerStatus::Expired,
                            SnapshotSignerStatus::Revoked => SignerStatus::Revoked,
                            SnapshotSignerStatus::UntrustedRoot => SignerStatus::UntrustedRoot,
                            SnapshotSignerStatus::DigestMismatch => SignerStatus::DigestMismatch,
                        },
                        source: if s.catalog {
                            SignatureSource::Catalog
                        } else {
                            SignatureSource::Embedded
                        },
                        publisher: s.publisher.clone(),
                        issuer: s.issuer.clone(),
                        leaf_thumbprint_sha256: s.leaf_thumbprint_sha256.clone(),
                        details: Default::default(),
                    })
                    .collect(),
            );
        }
        let mut variables = PathVariables::new();
        let mut seen = BTreeSet::new();
        for (name, values) in &self.variables {
            let v = PathVariable::from_name(name)
                .ok_or_else(|| invalid(format!("unknown path variable {name}")))?;
            // `TEMP` and `TMP`, or `windir` and `WINDIR`, name one variable:
            // two bindings would silently replace each other.
            if !seen.insert(v) {
                return Err(invalid(format!("path variable {name} is bound twice")));
            }
            let refs: Vec<&str> = values.iter().map(String::as_str).collect();
            variables.set(v, &refs);
        }
        let c = &self.context;
        let session_type = match &c.session_type {
            None => None,
            Some(t) => Some(
                SessionType::from_name(t)
                    .ok_or_else(|| invalid(format!("unknown session type {t}")))?,
            ),
        };
        let context = EvaluationContext {
            user: UserContext {
                sid: c.user_sid.clone(),
                account_name: c.user_account_name.clone(),
                upn: c.user_upn.clone(),
                groups: c.user_groups.clone(),
                primary_group: c.user_primary_group.clone(),
                is_admin: c.user_is_admin,
                is_elevated: c.user_is_elevated,
                is_service_account: c.user_is_service_account,
                is_system: c.user_is_system,
                integrity_level: None,
                dn: None,
            },
            device: DeviceContext {
                hostname: c.device_hostname.clone(),
                fqdn: c.device_fqdn.clone(),
                domain: c.device_domain.clone(),
                netbios: c.device_netbios.clone(),
                ad_site: c.device_ad_site.clone(),
                groups: c.device_groups.clone(),
                tags: c.device_tags.clone(),
                os_version: c.device_os_version.clone(),
                os_edition: c.device_os_edition.clone(),
                arch: c.device_arch.clone(),
                is_server: c.device_is_server,
                is_domain_controller: c.device_is_domain_controller,
                is_laptop: c.device_is_laptop,
                is_vdi: c.device_is_vdi,
                is_terminal_server: c.device_is_terminal_server,
                os_build: None,
                dn: None,
                // Not recorded in events yet (#4).
                boot_phase: None,
                containment_available: None,
            },
            session: SessionContext {
                session_type,
                client_hostname: c.session_client_hostname.clone(),
                is_remote: c.session_is_remote,
                id: None,
                client_ip: None,
            },
            // Recorded snapshots carry no network location or scope facts
            // (#38) yet, so a scope that needs one is unknown in a replay:
            // a scoped allow does not apply, as on a device that did not
            // collect them.
            network: crate::context::NetworkContext::default(),
            scope: crate::scope::ScopeFacts::default(),
            // Nor the time facts, the integrity level, the directory units,
            // the OS build or the session ID (#33): a criterion on one is
            // unknown in a replay.
            time: crate::context::TimeContext::default(),
            // Nor probed facts (#329): an `env.*`, `reg.*` or `fs.*`
            // criterion is unknown in a replay.
            probes: crate::context::Probes::default(),
            // Nor the command line, which snapshots do not record for
            // privacy (#18): a `process.*` criterion is unknown in a replay.
            process: crate::context::ProcessContext::default(),
        };
        Ok(Inputs {
            facts,
            variables,
            context,
        })
    }

    /// The device state, for a policy whose mode is `policy_mode`.
    #[must_use]
    pub fn state(&self, policy_mode: Mode) -> DeviceState {
        let s = &self.device_state;
        DeviceState {
            mode: s.mode.unwrap_or(policy_mode),
            connectivity: if s.disconnected {
                Connectivity::Disconnected
            } else {
                Connectivity::Connected
            },
            session: s.session.map(|k| match k {
                SnapshotSession::Audit => SessionKind::Audit,
                SnapshotSession::FullBypass => SessionKind::FullBypass,
            }),
            lockdown: s.lockdown,
        }
    }
}

/// One rule in a [`ChangeSet`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddRule {
    /// The rule set to add it to.
    pub rule_set_id: RuleSetId,
    /// The rule.
    pub rule: Rule,
}

/// A proposed change to a policy document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSet {
    /// Rules to add.
    #[serde(default)]
    pub add_rules: Vec<AddRule>,
    /// Rules to replace, matched by ID.
    #[serde(default)]
    pub replace_rules: Vec<Rule>,
    /// Rules to remove, by ID.
    #[serde(default)]
    pub remove_rules: Vec<RuleId>,
    /// Rules to enable, by ID.
    #[serde(default)]
    pub enable_rules: Vec<RuleId>,
    /// Rules to disable, by ID.
    #[serde(default)]
    pub disable_rules: Vec<RuleId>,
    /// A new policy mode.
    #[serde(default)]
    pub mode: Option<Mode>,
}

/// A change could not be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateError {
    /// A change names a rule or rule set the document does not have.
    UnknownId(String),
    /// The candidate is not a valid policy.
    Invalid(Vec<ValidationError>),
    /// The candidate's trees do not compile.
    Build(BuildError),
}

impl core::fmt::Display for CandidateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownId(id) => {
                write!(f, "the change names {id}, which the policy does not have")
            }
            Self::Invalid(e) => write!(f, "the candidate is not valid: {} findings", e.len()),
            Self::Build(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CandidateError {}

impl ChangeSet {
    /// The document with the change applied, in this order: remove,
    /// replace, add, enable, disable, then the mode. The revision is
    /// incremented. The result is not validated; [`Candidate::resolve`]
    /// does that.
    ///
    /// # Errors
    ///
    /// Returns [`CandidateError::UnknownId`] for a rule or rule set the
    /// document does not have.
    pub fn apply(&self, doc: &PolicyDocument) -> Result<PolicyDocument, CandidateError> {
        let mut doc = doc.clone();
        let find =
            |doc: &mut PolicyDocument, id: RuleId| -> Result<(usize, usize), CandidateError> {
                doc.rule_sets
                    .iter()
                    .enumerate()
                    .find_map(|(s, set)| set.rules.iter().position(|r| r.id == id).map(|r| (s, r)))
                    .ok_or_else(|| CandidateError::UnknownId(id.to_string()))
            };
        for id in &self.remove_rules {
            let (s, r) = find(&mut doc, *id)?;
            doc.rule_sets[s].rules.remove(r);
        }
        for rule in &self.replace_rules {
            let (s, r) = find(&mut doc, rule.id)?;
            doc.rule_sets[s].rules[r] = rule.clone();
        }
        for add in &self.add_rules {
            let set = doc
                .rule_sets
                .iter_mut()
                .find(|s| s.id == add.rule_set_id)
                .ok_or_else(|| CandidateError::UnknownId(add.rule_set_id.to_string()))?;
            set.rules.push(add.rule.clone());
        }
        for (ids, enabled) in [(&self.enable_rules, true), (&self.disable_rules, false)] {
            for id in ids {
                let (s, r) = find(&mut doc, *id)?;
                doc.rule_sets[s].rules[r].enabled = enabled;
            }
        }
        if let Some(m) = self.mode {
            doc.policy.mode = m;
        }
        doc.policy.revision = doc.policy.revision.saturating_add(1);
        Ok(doc)
    }
}

/// What to compare the current policy with.
#[derive(Clone, Debug)]
pub enum Candidate {
    /// Another document, such as a draft revision.
    Document(Box<PolicyDocument>),
    /// The current document with a change applied.
    Change(ChangeSet),
    /// The current policy in another mode: the question "what if we
    /// enforce?". A device that follows the policy's mode (a snapshot
    /// with no `device_state.mode`) moves with it. A device the state
    /// machine moved to its own mode, such as a time-boxed `audit` or a
    /// `disabled` device, keeps that mode, as it would on the agent.
    Mode(Mode),
}

impl Candidate {
    /// The candidate document, validated.
    ///
    /// # Errors
    ///
    /// [`CandidateError`] if a change does not apply or the result is not
    /// valid.
    pub fn resolve(&self, current: &ValidatedPolicy) -> Result<ValidatedPolicy, CandidateError> {
        let mut doc = match self {
            Self::Document(d) => (**d).clone(),
            Self::Change(c) => c.apply(current.document())?,
            Self::Mode(m) => ChangeSet {
                mode: Some(*m),
                ..ChangeSet::default()
            }
            .apply(current.document())?,
        };
        // The managed baseline is added after validation and is never part
        // of an authored document (#40): validate the candidate without
        // it, then give the candidate the current policy's baseline, so
        // both sides are compared with the same one. A draft's own
        // baseline-shaped set is dropped, never trusted.
        let baseline = current
            .document()
            .rule_sets
            .iter()
            .find(|s| crate::unknown::baseline::is_system_baseline(s))
            .cloned();
        crate::unknown::baseline::take_system_baseline(&mut doc);
        let validated = doc.validate().map_err(CandidateError::Invalid)?;
        Ok(match baseline {
            Some(set) => validated.with_baseline_set(set),
            None => validated,
        })
    }
}

/// One snapshot's decision under one policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SimDecision {
    /// The outcome.
    pub outcome: SimOutcome,
    /// The enforce-mode outcome.
    pub would_have_been: Option<SimOutcome>,
    /// The deciding rule.
    pub rule: Option<RuleRef>,
    /// Why.
    pub reason_code: Option<ReasonCode>,
    /// The effective mode.
    pub mode: Mode,
}

impl SimDecision {
    fn of(d: Option<&Decision>) -> Self {
        Self {
            outcome: SimOutcome::of(d),
            would_have_been: d.map(SimOutcome::enforce_of),
            rule: d.and_then(|d| d.matched_rule().copied()),
            reason_code: d.map(Decision::reason_code),
            mode: d.map_or(Mode::Disabled, Decision::mode),
        }
    }
}

impl SimOutcome {
    /// A decision's enforce-mode outcome.
    #[must_use]
    pub const fn enforce_of(d: &Decision) -> Self {
        match d.would_have_been() {
            Outcome::Allowed => Self::Allowed,
            Outcome::Blocked => Self::Blocked,
            Outcome::AllowedAudit => Self::AllowedAudit,
            Outcome::AllowedOverride => Self::AllowedOverride,
            Outcome::Ignored => Self::Ignored,
            Outcome::PendingUser => Self::PendingUser,
        }
    }
}

/// How one event's decision changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// It ran under the current policy and is blocked under the candidate.
    NewlyBlocked,
    /// It was blocked and runs under the candidate.
    NewlyAllowed,
    /// The same outcome, decided by another rule or for another reason.
    ChangedAttribution,
    /// Another outcome that neither blocks nor unblocks, such as `allowed`
    /// to `allowed_audit`.
    ChangedOutcome,
    /// Nothing changed.
    Unchanged,
}

/// One event, under both policies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EventResult {
    /// The event.
    pub event_id: String,
    /// The device.
    pub device_id: Option<String>,
    /// The user (SID, or account name), if the snapshot has one.
    pub user: Option<String>,
    /// The object's best identity: its SHA-256, or its path.
    pub object: Option<String>,
    /// Under the current policy.
    pub current: SimDecision,
    /// Under the candidate, if there is one.
    pub candidate: Option<SimDecision>,
    /// How it changed.
    pub change: Change,
}

/// Counts for one key of an aggregate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Events.
    pub events: u64,
    /// Blocked under the current policy.
    pub blocked: u64,
    /// Would-blocks under the current policy (`allowed_audit`).
    pub would_block: u64,
    /// Newly blocked under the candidate.
    pub newly_blocked: u64,
    /// Newly allowed under the candidate.
    pub newly_allowed: u64,
    /// Changed attribution.
    pub changed_attribution: u64,
    /// Another outcome that neither blocks nor unblocks.
    pub changed_outcome: u64,
}

/// One entry of an aggregate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Aggregate {
    /// The key: a device, user, rule or object.
    pub key: String,
    /// The counts.
    pub counts: Counts,
}

/// The summary of a run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DiffSummary {
    /// Events.
    pub events: u64,
    /// Newly blocked.
    pub newly_blocked: u64,
    /// Newly allowed.
    pub newly_allowed: u64,
    /// Same outcome, another rule or reason.
    pub changed_attribution: u64,
    /// Another outcome that neither blocks nor unblocks.
    pub changed_outcome: u64,
    /// Unchanged.
    pub unchanged: u64,
}

/// The report of a simulation run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SimulationReport {
    /// The current policy's ID and revision.
    pub policy: (String, u64),
    /// The candidate's revision, if any.
    pub candidate_revision: Option<u64>,
    /// The summary.
    pub summary: DiffSummary,
    /// The events whose decision changed, by event ID, at most
    /// [`MAX_CHANGES_LISTED`].
    pub changes: Vec<EventResult>,
    /// Changed events past the limit.
    pub changes_omitted: u64,
    /// By device, most changes first.
    pub by_device: Vec<Aggregate>,
    /// By user.
    pub by_user: Vec<Aggregate>,
    /// By deciding rule, under the current policy and the candidate.
    pub by_rule: Vec<Aggregate>,
    /// By object.
    pub by_object: Vec<Aggregate>,
}

/// A simulation over one current policy.
#[derive(Debug)]
pub struct Simulator<'p> {
    current: &'p ValidatedPolicy,
    /// The library sets scopes reference (#38), for the current policy and
    /// every candidate.
    library: &'p dyn crate::scope::ScopeLibrary,
    evaluator: Evaluator<'p>,
    tracer: Tracer<'p>,
    threads: usize,
}

impl<'p> Simulator<'p> {
    /// A simulator for `current`, using every available core.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a tree does not compile.
    pub fn new(current: &'p ValidatedPolicy) -> Result<Self, BuildError> {
        Self::with_library(current, &crate::scope::NoLibrary)
    }

    /// A simulator for `current` that resolves the library sets scopes
    /// reference through `library` (#37, #38), for the current policy and
    /// every candidate.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a tree does not compile.
    pub fn with_library(
        current: &'p ValidatedPolicy,
        library: &'p dyn crate::scope::ScopeLibrary,
    ) -> Result<Self, BuildError> {
        Ok(Self {
            current,
            library,
            evaluator: Evaluator::with_library(current, library)?,
            tracer: Tracer::with_library(current, library)?,
            threads: std::thread::available_parallelism()
                .map_or(1, std::num::NonZeroUsize::get)
                .min(MAX_THREADS),
        })
    }

    /// The same simulator with at most `n` threads (at least 1).
    #[must_use]
    pub fn with_threads(mut self, n: usize) -> Self {
        self.threads = n.clamp(1, MAX_THREADS);
        self
    }

    /// The decisions of every snapshot under the current policy, in input
    /// order. Exactly what an agent would decide.
    ///
    /// # Errors
    ///
    /// [`SnapshotError`] if a snapshot cannot be used or event IDs repeat.
    pub fn decide_all(
        &self,
        snapshots: &[FactsSnapshot],
    ) -> Result<Vec<Option<Decision>>, SnapshotError> {
        check_snapshots(snapshots)?;
        let mode = self.current.document().policy.mode;
        Ok(parallel(snapshots, self.threads, |s| {
            decide(&self.evaluator, s, mode)
        }))
    }

    /// Runs the snapshots under the current policy and `candidate`, and
    /// reports the differences. With no candidate, every event is
    /// `unchanged` and the aggregates describe the current policy.
    ///
    /// # Errors
    ///
    /// [`SimError`] if a snapshot cannot be used or the candidate is not a
    /// valid policy.
    pub fn run(
        &self,
        snapshots: &[FactsSnapshot],
        candidate: Option<&Candidate>,
    ) -> Result<SimulationReport, SimError> {
        let (revision, results) = self.compare(snapshots, candidate)?;
        Ok(report(self.current, revision, results))
    }

    /// Every event's decision under the current policy and `candidate`,
    /// changed or not, sorted by event ID: the per-event output that
    /// [`run`](Self::run) summarises.
    ///
    /// # Errors
    ///
    /// As [`run`](Self::run).
    pub fn events(
        &self,
        snapshots: &[FactsSnapshot],
        candidate: Option<&Candidate>,
    ) -> Result<Vec<EventResult>, SimError> {
        Ok(self.compare(snapshots, candidate)?.1)
    }

    fn compare(
        &self,
        snapshots: &[FactsSnapshot],
        candidate: Option<&Candidate>,
    ) -> Result<(Option<u64>, Vec<EventResult>), SimError> {
        check_snapshots(snapshots).map_err(SimError::Snapshot)?;
        let resolved = candidate
            .map(|c| c.resolve(self.current))
            .transpose()
            .map_err(SimError::Candidate)?;
        let cand_eval = resolved
            .as_ref()
            .map(|r| Evaluator::with_library(r, self.library))
            .transpose()
            .map_err(|e| SimError::Candidate(CandidateError::Build(e)))?;
        let cur_mode = self.current.document().policy.mode;
        let cand_mode = resolved.as_ref().map(|r| r.document().policy.mode);
        let mut results = parallel(snapshots, self.threads, |s| {
            let cur = decide(&self.evaluator, s, cur_mode);
            let cand = cand_eval
                .as_ref()
                .zip(cand_mode)
                .map(|(e, m)| decide(e, s, m));
            event_result(s, cur.as_ref(), cand.as_ref().map(Option::as_ref))
        });
        results.sort_by(|a, b| a.event_id.cmp(&b.event_id));
        Ok((
            resolved.as_ref().map(|r| r.document().policy.revision),
            results,
        ))
    }

    /// The full trace of one snapshot under the current policy: what the
    /// simulator shows when someone asks why.
    ///
    /// # Errors
    ///
    /// [`SimError::Snapshot`] if the snapshot cannot be used.
    pub fn trace(
        &self,
        snapshot: &FactsSnapshot,
        options: &TraceOptions,
    ) -> Result<Trace, SimError> {
        let inputs = snapshot.inputs().map_err(SimError::Snapshot)?;
        let subject = Subject {
            object_type: snapshot.object_type,
            facts: &inputs.facts,
            variables: &inputs.variables,
            context: &inputs.context,
        };
        let state = snapshot.state(self.current.document().policy.mode);
        let opts = TraceOptions {
            level: TraceLevel::Full,
            ..options.clone()
        };
        Ok(self.tracer.trace(
            &subject,
            &ObjectExtras::default(),
            &state,
            trace_id(&snapshot.event_id),
            &opts,
        ))
    }
}

/// The simulation could not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimError {
    /// A snapshot is unusable.
    Snapshot(SnapshotError),
    /// The candidate is unusable.
    Candidate(CandidateError),
    /// A policy test file is unusable ([`super::policy_test::run`]).
    Tests(super::policy_test::TestFileError),
}

impl core::fmt::Display for SimError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Snapshot(e) => e.fmt(f),
            Self::Candidate(e) => e.fmt(f),
            Self::Tests(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SimError {}

/// A trace ID derived from an event ID, so a re-run gives the same IDs:
/// the first 16 bytes of its SHA-256.
#[must_use]
pub fn trace_id(event_id: &str) -> TraceId {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(event_id.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    TraceId(id)
}

/// One snapshot's decision. Every caller checks the snapshots first
/// (`check_snapshots`), so `inputs` cannot fail here.
fn decide(e: &Evaluator<'_>, s: &FactsSnapshot, policy_mode: Mode) -> Option<Decision> {
    let inputs = s.inputs().ok()?;
    let subject = Subject {
        object_type: s.object_type,
        facts: &inputs.facts,
        variables: &inputs.variables,
        context: &inputs.context,
    };
    e.evaluate_in(&subject, &s.state(policy_mode), trace_id(&s.event_id))
}

fn event_result(
    s: &FactsSnapshot,
    cur: Option<&Decision>,
    cand: Option<Option<&Decision>>,
) -> EventResult {
    let current = SimDecision::of(cur);
    let candidate = cand.map(SimDecision::of);
    let change = match &candidate {
        None => Change::Unchanged,
        Some(c) => classify(&current, c),
    };
    EventResult {
        event_id: s.event_id.clone(),
        device_id: s.device_id.clone(),
        user: s
            .context
            .user_sid
            .clone()
            .or_else(|| s.context.user_account_name.clone()),
        object: object_key(s),
        current,
        candidate,
        change,
    }
}

fn classify(a: &SimDecision, b: &SimDecision) -> Change {
    match (a.outcome.runs(), b.outcome.runs()) {
        (true, false) => Change::NewlyBlocked,
        (false, true) => Change::NewlyAllowed,
        _ if a.outcome != b.outcome => Change::ChangedOutcome,
        _ if a.rule.map(|r| r.rule_id) != b.rule.map(|r| r.rule_id)
            || a.reason_code != b.reason_code =>
        {
            Change::ChangedAttribution
        }
        _ => Change::Unchanged,
    }
}

/// The best identity of a snapshot's object, so that the same object is one
/// key however it was recorded:
///
/// 1. its SHA-256, if the fact is one the matcher accepts (64 hex digits),
///    in lowercase;
/// 2. otherwise its path, if it is a drive or UNC path whose 8.3 short
///    names were all expanded, normalised and folded as path criteria
///    compare it (the matcher treats an unexpanded path as unknown);
/// 3. otherwise the publisher of its first trusted signature, if not
///    empty, folded the same way;
/// 4. otherwise none.
pub(crate) fn object_key(s: &FactsSnapshot) -> Option<String> {
    let hash = s
        .facts
        .values
        .get(&Field::HashSha256)
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if let Some(h) = hash {
        return Some(format!("sha256:{}", h.to_ascii_lowercase()));
    }
    let path = s
        .facts
        .path
        .as_ref()
        .filter(|p| !p.short_name_unresolved)
        .map(|p| palisade_core::path::normalize(&p.path))
        .filter(palisade_core::path::NormalizedPath::is_resolved);
    if let Some(n) = path {
        return Some(format!("path:{}", crate::ops::fold(n.as_str(), false)));
    }
    s.facts
        .signers
        .as_ref()?
        .iter()
        .filter(|x| {
            !matches!(
                x.status,
                SnapshotSignerStatus::Expired
                    | SnapshotSignerStatus::Revoked
                    | SnapshotSignerStatus::UntrustedRoot
                    | SnapshotSignerStatus::DigestMismatch
            )
        })
        .find_map(|x| x.publisher.as_deref().filter(|p| !p.is_empty()))
        .map(|p| format!("publisher:{}", crate::ops::fold(p, false)))
}

fn report(
    current: &ValidatedPolicy,
    candidate_revision: Option<u64>,
    results: Vec<EventResult>,
) -> SimulationReport {
    let p = &current.document().policy;
    let mut summary = DiffSummary::default();
    let mut by_device: BTreeMap<String, Counts> = BTreeMap::new();
    let mut by_user: BTreeMap<String, Counts> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, Counts> = BTreeMap::new();
    let mut by_object: BTreeMap<String, Counts> = BTreeMap::new();
    for r in &results {
        summary.events += 1;
        match r.change {
            Change::NewlyBlocked => summary.newly_blocked += 1,
            Change::NewlyAllowed => summary.newly_allowed += 1,
            Change::ChangedAttribution => summary.changed_attribution += 1,
            Change::ChangedOutcome => summary.changed_outcome += 1,
            Change::Unchanged => summary.unchanged += 1,
        }
        let add = |c: &mut Counts| {
            c.events += 1;
            c.blocked += u64::from(r.current.outcome == SimOutcome::Blocked);
            c.would_block += u64::from(r.current.outcome == SimOutcome::AllowedAudit);
            c.newly_blocked += u64::from(r.change == Change::NewlyBlocked);
            c.newly_allowed += u64::from(r.change == Change::NewlyAllowed);
            c.changed_attribution += u64::from(r.change == Change::ChangedAttribution);
            c.changed_outcome += u64::from(r.change == Change::ChangedOutcome);
        };
        add(by_device
            .entry(
                r.device_id
                    .clone()
                    .unwrap_or_else(|| "(unknown)".to_owned()),
            )
            .or_default());
        add(by_user
            .entry(r.user.clone().unwrap_or_else(|| "(unknown)".to_owned()))
            .or_default());
        add(by_object
            .entry(r.object.clone().unwrap_or_else(|| "(unknown)".to_owned()))
            .or_default());
        let mut rules = BTreeSet::new();
        rules.insert(rule_key(&r.current));
        if let Some(c) = &r.candidate {
            rules.insert(rule_key(c));
        }
        for k in rules {
            add(by_rule.entry(k).or_default());
        }
    }
    let changed: Vec<EventResult> = results
        .into_iter()
        .filter(|r| r.change != Change::Unchanged)
        .collect();
    let changes_omitted = changed.len().saturating_sub(MAX_CHANGES_LISTED) as u64;
    SimulationReport {
        policy: (p.id.to_string(), p.revision),
        candidate_revision,
        summary,
        changes: changed.into_iter().take(MAX_CHANGES_LISTED).collect(),
        changes_omitted,
        by_device: ranked(by_device),
        by_user: ranked(by_user),
        by_rule: ranked(by_rule),
        by_object: ranked(by_object),
    }
}

/// The `by_rule` key of a decision: the deciding rule, the implicit deny,
/// or nothing decided on a disabled device.
fn rule_key(d: &SimDecision) -> String {
    match (d.outcome, d.rule) {
        (SimOutcome::NotEvaluated, _) => "(not evaluated)".to_owned(),
        (_, Some(r)) => r.rule_id.to_string(),
        (_, None) => "(implicit deny)".to_owned(),
    }
}

/// The entries with the most changes, then blocks, then events first, then
/// by key; at most [`MAX_AGGREGATE`].
fn ranked(map: BTreeMap<String, Counts>) -> Vec<Aggregate> {
    let mut v: Vec<Aggregate> = map
        .into_iter()
        .map(|(key, counts)| Aggregate { key, counts })
        .collect();
    v.sort_by(|a, b| {
        let k = |c: &Counts| {
            (
                c.newly_blocked + c.newly_allowed + c.changed_attribution + c.changed_outcome,
                c.blocked + c.would_block,
                c.events,
            )
        };
        k(&b.counts)
            .cmp(&k(&a.counts))
            .then_with(|| a.key.cmp(&b.key))
    });
    v.truncate(MAX_AGGREGATE);
    v
}

/// Maps `f` over `items` on up to `threads` threads, keeping input order.
pub(crate) fn parallel<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    if threads <= 1 || items.len() < 1024 {
        return items.iter().map(f).collect();
    }
    let chunk = items.len().div_ceil(threads);
    std::thread::scope(|scope| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|c| {
                let f = &f;
                scope.spawn(move || c.iter().map(f).collect::<Vec<R>>())
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| match h.join() {
                Ok(v) => v,
                Err(panic) => std::panic::resume_unwind(panic),
            })
            .collect()
    })
}

/// A disagreement between an agent's recorded decision and the simulator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    /// The event.
    pub event_id: String,
    /// What the agent recorded.
    pub recorded: RecordedDecision,
    /// What the simulator decided.
    pub simulated: RecordedDecision,
}

/// Checks recorded agent decisions against the simulator's: the
/// differential test of #41 ("the simulator reproduces agent decisions
/// bit-for-bit"). Snapshots without a recorded decision are skipped.
///
/// # Errors
///
/// [`SnapshotError`] if a snapshot cannot be used.
pub fn cross_check(
    sim: &Simulator<'_>,
    snapshots: &[FactsSnapshot],
) -> Result<Vec<Mismatch>, SnapshotError> {
    let decisions = sim.decide_all(snapshots)?;
    Ok(snapshots
        .iter()
        .zip(&decisions)
        .filter_map(|(s, d)| {
            let recorded = s.recorded?;
            let simulated = RecordedDecision {
                outcome: SimOutcome::of(d.as_ref()),
                rule_id: d.as_ref().and_then(|d| d.matched_rule()).map(|r| r.rule_id),
            };
            (recorded != simulated).then(|| Mismatch {
                event_id: s.event_id.clone(),
                recorded,
                simulated,
            })
        })
        .collect())
}
