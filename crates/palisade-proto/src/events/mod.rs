//! The canonical event schema (#196).
//!
//! Every endpoint decision, agent health signal and policy change that
//! Palisade records is one [`Event`]: a common envelope plus the field sets
//! that its [`EventType`] needs. Every output, the server store and alert
//! rules consume this one structure. Outputs are pure encoders, so a field
//! means the same thing everywhere.
//!
//! The event types and their rules are data, in
//! `crates/palisade-proto/events/registry.yaml`. That file is the source of
//! [`EventType`] (generated into `registry_gen.rs`) and of the reference
//! table `crates/palisade-proto/events/REGISTRY.md`. The `registry` unit tests fail
//! when either generated file is stale.
//!
//! The JSON Schema is generated from these types ([`schema`]) and committed
//! at `schemas/events/v1.json`.
//!
//! # Schema versioning and compatibility
//!
//! Every event carries `schema_version`, `MAJOR.MINOR.PATCH`. Writers always
//! write [`CURRENT`].
//!
//! - **Patch**: documentation only. No event changes.
//! - **Minor**: additive. A minor version may add optional fields, field
//!   sets, event types, enum values (a category, an outcome, a source kind),
//!   and mapping entries. It never adds a required field, never makes an
//!   optional field required, and never changes what an existing field
//!   means.
//! - **Major**: anything else. Renaming or removing a field, changing its
//!   type or meaning, or changing an existing event type's category or
//!   required field sets. A major version gets a new schema file
//!   (`schemas/events/v2.json`) and a converter.
//!
//! Each addition records the version it arrived in: the registry has a
//! `since` for every event type, [`FieldSet::since`] gives it for every
//! field set, and [`Event::min_version`] is the oldest version an event can
//! be labelled with. An event labelled with an older version than a part it
//! uses is invalid ([`EventErrorCode::NewerThanVersion`]), in
//! [`Event::validate`] and in the JSON Schema alike, so a version label
//! always tells a reader which fields it may meet.
//!
//! Version history:
//!
//! - **1.0.0**: the envelope; the `process`, `file`, `script`, `native` and
//!   `agent` field sets; the execution-control, policy and agent types.
//! - **1.1.0**: the `network`, `device`, `registry`, `elevation`, `approval`,
//!   `admin`, `identity`, `audit_policy`, `restriction`, `probe` and `fim`
//!   field sets; the containment, device, storage, network, web, elevation,
//!   approval, exception, override, admin, identity, detection, integrity,
//!   compliance, process-creation and script-logging types; `source.kind`
//!   `third_party` with `source.format`. New fields come after every 1.0
//!   field, so the canonical form of a 1.0 event is unchanged.
//! - **1.2.0**: the policy integrity types of #225
//!   (`policy.signature.invalid`, `policy.rollback_rejected`,
//!   `policy.target_mismatch`, `policy.stale`, `policy.lkg_loaded`,
//!   `policy.emergency_loaded`, `policy.schema_unsupported` and
//!   `tamper.policy.rollback_suspected`). No fields change.
//! - **1.3.0**: `policy.kid`, the key that signed the policy bundle (#325),
//!   so `policy.applied` names its signing key. It comes after every older
//!   `policy` field, so the canonical form of an older event is unchanged.
//!
//! Readers are strict. They reject unknown fields and unknown enum values,
//! because events are hash-chained (`seq`, `prev_hash`) and a reader that
//! silently dropped a field it did not know would hide data from the chain's
//! verifier. A reader accepts events of its own major version and a minor
//! version no newer than its own ([`Event::from_json`]). A newer minor
//! version is refused with [`LoadError::NewerMinorVersion`] rather than read
//! with fields missing. So the deployment rule is: **upgrade the server
//! before the agents.** Down-converting events for older external consumers
//! is the server's job when it exports them (#198, #202).
//!
//! # The hash chain
//!
//! `seq` is the producer's monotonic sequence number and `prev_hash` the
//! chain value of the producer's previous event. The first event of a chain
//! has `seq` 0 and no `prev_hash`; every later event has one. How the chain
//! value is computed (a keyed MAC over [`Event::to_canonical_json`]) and how
//! the chain head is reported belong to #220 and #202.
//!
//! The schema cannot make the chain complete. As the threat model records
//! (T-events-03), events after the last reported chain head can be deleted
//! and the local sequence rolled back without a gap the server can see. The
//! chain only proves that events the server has seen were not altered or
//! reordered. Shorter upload intervals and uploading tamper events first
//! (#197) narrow that window.

pub mod fieldsets;
#[cfg(test)]
mod registry;
#[rustfmt::skip]
mod registry_gen;
pub mod schema;
mod value;

#[cfg(test)]
pub(crate) mod arbitrary;
#[cfg(test)]
mod tests;

use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use fieldsets::{
    Account, Admin, AdminChannel, Approval, ApprovalChannel, ApprovalDecision, ApprovalKind,
    ApprovalScope, AuditCategory, AuditPolicy, AuditPolicyChange, Change, ChangeOp, Device,
    DeviceClass, DeviceInterface, Direction, Elevation, ElevationMethod, EncryptionState, Fim,
    FimChange, GroupScope, Identity, Network, Principal, PrincipalKind, Probe, ProbeStatus,
    Registry, RegistryData, RegistryOperation, RegistryValueType, Remark, ResolutionMethod,
    Restriction,
};
pub use palisade_core::{Mode, ObjectType, PolicyId, RuleId, SchemaVersion, ScriptKind, Uuid7};
pub use registry_gen::EventType;
pub(crate) use value::present;
pub use value::{
    BoundedVec, Description, DnsName, Guid, Hex, HexBytes, HostId, IpAddress, JsonPointer,
    JsonValue, LabelKey, Labels, LongText, Md5Hex, Name, RegistryKey, Severity, Sha1Hex, Sha256Hex,
    Sid, SortedSet, SyslogSeverity, TenantId, Text, Timestamp, Token, ValueError,
};

/// The event schema version this crate writes, and the newest it reads.
pub const CURRENT: SchemaVersion = SchemaVersion::new(1, 3, 0);

/// The first version of the current major: every part of the schema that
/// has no later `since` version is in it.
pub const V1_0: SchemaVersion = SchemaVersion::new(1, 0, 0);

/// Schema version 1.1: the field sets after `agent`, the event types
/// registered with `since: 1.1.0`, `source.kind` `third_party` and
/// `source.format`.
pub const V1_1: SchemaVersion = SchemaVersion::new(1, 1, 0);

/// Schema version 1.2: the policy integrity event types registered with
/// `since: 1.2.0` (#225).
pub const V1_2: SchemaVersion = SchemaVersion::new(1, 2, 0);

/// Schema version 1.3: `policy.kid` (#325).
pub const V1_3: SchemaVersion = SchemaVersion::new(1, 3, 0);

/// Most signatures recorded for one file or process image.
pub const MAX_SIGNERS: usize = 64;

// ---------------------------------------------------------------------------
// Envelope enums
// ---------------------------------------------------------------------------

/// The broad class of an event.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Running an executable.
    Execution,
    /// Running a script.
    Script,
    /// Loading a library into a process.
    Library,
    /// Loading a kernel driver.
    Driver,
    /// Running an installer.
    Installer,
    /// Installing or activating a packaged app.
    PackagedApp,
    /// Application containment.
    Containment,
    /// Device control.
    Device,
    /// Network control.
    Network,
    /// Web access control.
    Web,
    /// Privilege elevation.
    Elevation,
    /// Approval requests.
    Approval,
    /// Policy exceptions.
    Exception,
    /// Policy distribution and activation.
    Policy,
    /// The agent itself.
    Agent,
    /// Administrative actions on the server.
    AdminAudit,
    /// Identity changes, such as local group membership.
    Identity,
    /// Compliance probes.
    Compliance,
    /// Detections.
    Detection,
    /// File integrity monitoring.
    Integrity,
}

/// What happened.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The action was allowed.
    Allowed,
    /// The action was blocked.
    Blocked,
    /// The action was allowed, but would have been blocked if enforced.
    Audited,
    /// The action ran with elevated rights.
    Elevated,
    /// The user or the system cancelled the action.
    Cancelled,
    /// The action failed.
    Failed,
    /// Information only: no allow or block decision.
    Info,
}

/// The enforcement mode in effect when the event happened.
///
/// This is the policy [`Mode`] as seen by an event, plus two states the
/// agent can be in. [`EventMode::from_policy_mode`] converts.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventMode {
    /// Decisions take effect.
    Enforce,
    /// Decisions are evaluated and would-block decisions reported.
    Monitor,
    /// Like `monitor`, with a full event for every decision.
    Audit,
    /// Audit, collecting would-block objects as learning candidates.
    Learning,
    /// An unlocked maintenance window (#222).
    Maintenance,
    /// A simulation of a policy that is not deployed.
    Simulate,
}

impl EventMode {
    /// The event mode for a policy mode. `None` for [`Mode::Disabled`],
    /// because a disabled engine makes no decisions.
    #[must_use]
    pub const fn from_policy_mode(mode: Mode) -> Option<Self> {
        match mode {
            Mode::Disabled => None,
            Mode::Monitor => Some(Self::Monitor),
            Mode::Audit => Some(Self::Audit),
            Mode::Learning => Some(Self::Learning),
            Mode::Enforce => Some(Self::Enforce),
        }
    }
}

/// A group of related fields. The registry lists the field sets each event
/// type requires.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FieldSet {
    /// [`Event::user`].
    User,
    /// [`Event::policy`].
    Policy,
    /// [`Event::process`].
    Process,
    /// [`Event::file`].
    File,
    /// [`Event::script`].
    Script,
    /// [`Event::native`].
    Native,
    /// [`Event::agent`].
    Agent,
    /// [`Event::network`]. Since 1.1.
    Network,
    /// [`Event::device`]. Since 1.1.
    Device,
    /// [`Event::registry`]. Since 1.1.
    Registry,
    /// [`Event::elevation`]. Since 1.1.
    Elevation,
    /// [`Event::approval`]. Since 1.1.
    Approval,
    /// [`Event::admin`]. Since 1.1.
    Admin,
    /// [`Event::identity`]. Since 1.1.
    Identity,
    /// [`Event::audit_policy`]. Since 1.1.
    AuditPolicy,
    /// [`Event::restriction`]. Since 1.1.
    Restriction,
    /// [`Event::probe`]. Since 1.1.
    Probe,
    /// [`Event::fim`]. Since 1.1.
    Fim,
}

impl FieldSet {
    /// Every field set, in envelope order.
    pub const ALL: [Self; 18] = [
        Self::User,
        Self::Policy,
        Self::Process,
        Self::File,
        Self::Script,
        Self::Native,
        Self::Agent,
        Self::Network,
        Self::Device,
        Self::Registry,
        Self::Elevation,
        Self::Approval,
        Self::Admin,
        Self::Identity,
        Self::AuditPolicy,
        Self::Restriction,
        Self::Probe,
        Self::Fim,
    ];

    /// The field name in the envelope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Policy => "policy",
            Self::Process => "process",
            Self::File => "file",
            Self::Script => "script",
            Self::Native => "native",
            Self::Agent => "agent",
            Self::Network => "network",
            Self::Device => "device",
            Self::Registry => "registry",
            Self::Elevation => "elevation",
            Self::Approval => "approval",
            Self::Admin => "admin",
            Self::Identity => "identity",
            Self::AuditPolicy => "audit_policy",
            Self::Restriction => "restriction",
            Self::Probe => "probe",
            Self::Fim => "fim",
        }
    }

    /// The JSON Pointer of the field set in the envelope.
    #[must_use]
    pub const fn pointer(self) -> &'static str {
        match self {
            Self::User => "/user",
            Self::Policy => "/policy",
            Self::Process => "/process",
            Self::File => "/file",
            Self::Script => "/script",
            Self::Native => "/native",
            Self::Agent => "/agent",
            Self::Network => "/network",
            Self::Device => "/device",
            Self::Registry => "/registry",
            Self::Elevation => "/elevation",
            Self::Approval => "/approval",
            Self::Admin => "/admin",
            Self::Identity => "/identity",
            Self::AuditPolicy => "/audit_policy",
            Self::Restriction => "/restriction",
            Self::Probe => "/probe",
            Self::Fim => "/fim",
        }
    }

    /// The schema version the field set was added in.
    #[must_use]
    pub const fn since(self) -> SchemaVersion {
        match self {
            Self::User
            | Self::Policy
            | Self::Process
            | Self::File
            | Self::Script
            | Self::Native
            | Self::Agent => V1_0,
            Self::Network
            | Self::Device
            | Self::Registry
            | Self::Elevation
            | Self::Approval
            | Self::Admin
            | Self::Identity
            | Self::AuditPolicy
            | Self::Restriction
            | Self::Probe
            | Self::Fim => V1_1,
        }
    }
}

/// The parts of the schema added after 1.0, by JSON Pointer, with the
/// version that added them. A pointer covers everything beneath it.
///
/// This one table drives [`Event::min_version`], the version rules of the
/// JSON Schema and the version lint of the mapping files. The test
/// `every_new_schema_path_has_a_version` fails if the schema gains a field
/// that is in neither the 1.0 schema nor this table.
pub const ADDED: &[(&str, SchemaVersion)] = &[
    ("/source/format", V1_1),
    ("/source/rule_name", V1_1),
    ("/script/text", V1_1),
    ("/network", V1_1),
    ("/device", V1_1),
    ("/registry", V1_1),
    ("/elevation", V1_1),
    ("/approval", V1_1),
    ("/admin", V1_1),
    ("/identity", V1_1),
    ("/audit_policy", V1_1),
    ("/restriction", V1_1),
    ("/probe", V1_1),
    ("/fim", V1_1),
    ("/policy/kid", V1_3),
];

/// The schema version that added the field at `pointer`: the newest entry
/// of [`ADDED`] that covers it, or 1.0.
#[must_use]
pub fn pointer_since(pointer: &str) -> SchemaVersion {
    ADDED
        .iter()
        .filter(|(p, _)| {
            pointer
                .strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .map(|(_, v)| *v)
        .max()
        .unwrap_or(V1_0)
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EventType {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, ValueError> {
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or(ValueError::UNKNOWN_EVENT_TYPE)
    }
}

impl Serialize for EventType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        value::deserialize_from_str(
            deserializer,
            "a registered event type such as `exec.decision`",
        )
    }
}

impl JsonSchema for EventType {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "EventType".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|t| t.as_str()).collect();
        json_schema!({
            "description": "A registered event type (`crates/palisade-proto/events/registry.yaml`).",
            "type": "string",
            "enum": names
        })
    }
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// One canonical event.
///
/// Field order here is the serialisation order, so [`Event::to_canonical_json`]
/// is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// The schema version of this event.
    pub schema_version: SchemaVersion,
    /// A unique ID, assigned by the producer.
    pub event_id: Uuid7,
    /// The registered type, for example `exec.decision`.
    pub event_type: EventType,
    /// The type's category. It must match the registry.
    pub category: Category,
    /// The verb, for example `execute`, `load`, `install` or `activate`.
    pub action: Token,
    /// What happened.
    pub outcome: Outcome,
    /// 0 to 10. See [`Severity::syslog`] for the syslog mapping.
    pub severity: Severity,
    /// The enforcement mode, where one applies.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub mode: Option<EventMode>,
    /// A human-readable description of the event (ISM-0585).
    pub description: Description,
    /// When the event happened, in UTC.
    pub ts: Timestamp,
    /// The producer's monotonic clock when the event was recorded, in
    /// microseconds since the agent started. It orders events even when the
    /// wall clock jumps.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ts_agent_monotonic: Option<u64>,
    /// Whether the producer's wall clock was synchronised when `ts` was taken.
    pub clock_synced: bool,
    /// The producer's last measured clock offset, in milliseconds.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub clock_skew_ms: Option<i64>,
    /// The tenant.
    pub tenant_id: TenantId,
    /// The device the event is about (ISM-0585: IT equipment).
    pub host: Host,
    /// The user, if any.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub user: Option<User>,
    /// The Palisade policy and rule that decided, if known.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy: Option<PolicyRef>,
    /// The producer's sequence number, starting at 0.
    pub seq: u64,
    /// The chain value of the producer's previous event. Absent only when
    /// `seq` is 0.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub prev_hash: Option<Sha256Hex>,
    /// Labels from policy tags.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
    /// Where the event came from, for events translated from another log.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub source: Option<Source>,
    /// The process that acted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub process: Option<Process>,
    /// The file acted on.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub file: Option<File>,
    /// The script, for script events.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub script: Option<Script>,
    /// OS-native enforcement details.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub native: Option<Native>,
    /// Agent state, for agent events.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub agent: Option<AgentInfo>,
    /// The network connection or request. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub network: Option<Network>,
    /// The peripheral device. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub device: Option<Device>,
    /// The registry key or value. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub registry: Option<Registry>,
    /// The privilege elevation. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub elevation: Option<Elevation>,
    /// The approval request. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub approval: Option<Approval>,
    /// The administrative action. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub admin: Option<Admin>,
    /// Logon and group membership details. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub identity: Option<Identity>,
    /// The OS audit policy change. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub audit_policy: Option<AuditPolicy>,
    /// The script language restriction. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub restriction: Option<Restriction>,
    /// The compliance probe. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub probe: Option<Probe>,
    /// The file integrity change. Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub fim: Option<Fim>,
}

/// The device an event is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// The device ID from enrolment.
    pub id: HostId,
    /// The host name. Dropped in anonymous mode (#228).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The fully qualified domain name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub fqdn: Option<Name>,
    /// The directory domain the device is joined to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub domain: Option<Name>,
    /// The operating system, for example `Windows 11 Enterprise`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub os: Option<Name>,
    /// The OS build, for example `26100.2314`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub os_build: Option<Name>,
    /// The CPU architecture, for example `x86_64` or `aarch64`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub arch: Option<Name>,
    /// The Palisade agent version.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub agent_version: Option<Name>,
    /// The device's IP addresses, at most 32.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub ips: BoundedVec<IpAddress, 32>,
    /// The device groups it belongs to, at most 64.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub groups: BoundedVec<Name, 64>,
}

/// The user an event is about.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// The security identifier.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sid: Option<Sid>,
    /// The account name. Dropped or pseudonymised by redaction (#228).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The account's domain.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub domain: Option<Name>,
    /// The user principal name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub upn: Option<Name>,
    /// The logon session's terminal-services session ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub session_id: Option<u32>,
    /// The logon ID (locally unique identifier) of the logon session.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub logon_id: Option<u64>,
    /// How the session logged on.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub logon_type: Option<LogonType>,
    /// Whether the user is a local administrator.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub is_admin: Option<bool>,
    /// Whether the acting token was elevated.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub elevated: Option<bool>,
}

/// How a logon session was created. The names follow the OS logon types
/// 2 to 13.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogonType {
    /// 2: at the console.
    Interactive,
    /// 3: from the network.
    Network,
    /// 4: a batch job.
    Batch,
    /// 5: a service.
    Service,
    /// 7: a workstation unlock.
    Unlock,
    /// 8: from the network with a cleartext password.
    NetworkCleartext,
    /// 9: new credentials for outbound connections.
    NewCredentials,
    /// 10: remote desktop.
    RemoteInteractive,
    /// 11: with cached credentials.
    CachedInteractive,
    /// 12: remote desktop with cached credentials.
    CachedRemoteInteractive,
    /// 13: an unlock with cached credentials.
    CachedUnlock,
}

/// The Palisade policy and rule behind a decision.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// The policy ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub id: Option<PolicyId>,
    /// The policy name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub name: Option<Name>,
    /// The policy revision.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub version: Option<u64>,
    /// The SHA-256 of the policy bundle.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub hash: Option<Sha256Hex>,
    /// The rule that decided.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_id: Option<RuleId>,
    /// The rule's name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_name: Option<Name>,
    /// The kind of rule, for example `hash`, `publisher` or `path`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_type: Option<Token>,
    /// The profile the policy was assigned through.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub profile_id: Option<Uuid7>,
    /// The key that signed the policy bundle: its key ID, the first 16
    /// bytes of the SHA-256 of its `SubjectPublicKeyInfo`, in 32 lowercase
    /// hex digits (#325). Since 1.3.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub kid: Option<Hex<16>>,
}

/// The log an event was translated from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The kind of log.
    pub kind: SourceKind,
    /// The source's own event ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub event_id: Option<u32>,
    /// The source's record number.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub record_id: Option<u64>,
    /// The log channel.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub channel: Option<Name>,
    /// The source's correlation activity ID, which groups related records.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub activity_id: Option<Guid>,
    /// For `third_party`: the generic name of the import format, for
    /// example `generic`. Present exactly when `kind` is `third_party`.
    /// Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub format: Option<Token>,
    /// The rule or policy that decided, as the source names it. For events
    /// imported from another product, whose rules have no Palisade ID.
    /// Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_name: Option<Name>,
}

/// A kind of log that events can be translated from.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// The OS code integrity log.
    OsCodeIntegrity,
    /// The OS legacy rule-collection logs.
    OsLegacyRuleCollection,
    /// The OS Security log.
    OsSecurity,
    /// The PowerShell logs.
    OsPowershell,
    /// Events imported from another product, in a generic format named by
    /// `source.format`. Since 1.1.
    ThirdParty,
}

impl SourceKind {
    /// Every source kind, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::OsCodeIntegrity,
        Self::OsLegacyRuleCollection,
        Self::OsSecurity,
        Self::OsPowershell,
        Self::ThirdParty,
    ];

    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OsCodeIntegrity => "os_code_integrity",
            Self::OsLegacyRuleCollection => "os_legacy_rule_collection",
            Self::OsSecurity => "os_security",
            Self::OsPowershell => "os_powershell",
            Self::ThirdParty => "third_party",
        }
    }

    /// The schema version the source kind was added in.
    #[must_use]
    pub const fn since(self) -> SchemaVersion {
        match self {
            Self::ThirdParty => V1_1,
            _ => V1_0,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared file identity
// ---------------------------------------------------------------------------

/// The digests of a file.
///
/// `sha256`, `sha1` and `md5` are flat hashes of the whole file. The
/// `authenticode_*` digests are the digest a signature covers: the
/// Authenticode image hash for PE files, or the subject-interface-package
/// digest for scripts and other signable formats. SHA-1 and MD5 are for
/// matching OS and imported data only, never the sole basis of a decision
/// (ADR 0008).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hashes {
    /// SHA-256 of the file.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sha256: Option<Sha256Hex>,
    /// SHA-1 of the file. Interop only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sha1: Option<Sha1Hex>,
    /// MD5 of the file. Interop only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub md5: Option<Md5Hex>,
    /// SHA-256 signature digest.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub authenticode_sha256: Option<Sha256Hex>,
    /// SHA-1 signature digest. Interop only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub authenticode_sha1: Option<Sha1Hex>,
}

impl Hashes {
    /// Whether no digest is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// One signature on a file, leaf first.
///
/// `signature_type`, `signing_level` and `verification_error` keep the OS
/// codes as numbers, so values the decoder tables (#90) do not know yet are
/// not lost.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    /// The leaf certificate's subject common name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub publisher: Option<Name>,
    /// The issuing certificate's common name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub issuer: Option<Name>,
    /// The leaf certificate's thumbprint.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub leaf_thumbprint: Option<HexBytes>,
    /// The hash of the leaf certificate's to-be-signed part.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub tbs_hash: Option<HexBytes>,
    /// The hash of the issuing certificate's to-be-signed part.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub issuer_tbs_hash: Option<HexBytes>,
    /// Whether the certificate chain verified.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub chain_valid: Option<bool>,
    /// The signing time from a trusted timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub timestamp: Option<Timestamp>,
    /// How the OS verified the signature (code 0 to 7).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub signature_type: Option<u8>,
    /// The signing level the OS validated (code 0 to 14).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub signing_level: Option<u8>,
    /// Why verification failed, or 0 if it succeeded (code 0 to 28).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub verification_error: Option<u8>,
}

impl Signer {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// The version resource of a PE file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VersionInfo {
    /// `OriginalFilename`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub original_filename: Option<Name>,
    /// `InternalName`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub internal_name: Option<Name>,
    /// `ProductName`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub product_name: Option<Name>,
    /// `CompanyName`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub company: Option<Name>,
    /// `FileVersion`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub file_version: Option<Name>,
    /// `ProductVersion`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub product_version: Option<Name>,
    /// `FileDescription`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub description: Option<Name>,
}

impl VersionInfo {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------

/// A process integrity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    /// Untrusted.
    Untrusted,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// Medium plus.
    MediumPlus,
    /// High.
    High,
    /// System.
    System,
    /// Protected process.
    Protected,
}

/// The elevation type of a process token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenElevationType {
    /// No split token (UAC off, or a built-in or service account).
    Default,
    /// The elevated half of a split token.
    Full,
    /// The filtered half of a split token.
    Limited,
}

/// The security zone a file was downloaded from (its mark of the web).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    /// Zone 0: the local machine.
    LocalMachine,
    /// Zone 1: the local intranet.
    Intranet,
    /// Zone 2: trusted sites.
    Trusted,
    /// Zone 3: the internet.
    Internet,
    /// Zone 4: restricted sites.
    Restricted,
}

/// Where a file came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// The zone in the file's mark of the web.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub motw_zone: Option<Zone>,
    /// The download URL.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub host_url: Option<LongText>,
    /// The referring page.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub referrer_url: Option<LongText>,
}

/// Defines a process struct with the fields every process record shares,
/// plus `$extra`.
macro_rules! process_struct {
    ($(#[$meta:meta])* $name:ident { $($extra:tt)* }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            /// The process ID.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub pid: Option<u32>,
            /// A key that identifies the process uniquely on the device, assigned
            /// by the agent's process tracker (#59). Process IDs are reused; this is not.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub process_key: Option<Name>,
            /// The image path as reported, for example a device path.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub image_path: Option<LongText>,
            /// The image path with drive letters and `%ENV%` substitutions.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub image_path_normalised: Option<LongText>,
            /// The command line. Collected only when permitted, and redacted by
            /// default (#228).
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub cmdline: Option<LongText>,
            /// The image's digests.
            #[serde(default, skip_serializing_if = "Hashes::is_empty")]
            pub hashes: Hashes,
            /// The image's signatures, leaf first.
            #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
            pub signers: BoundedVec<Signer, MAX_SIGNERS>,
            /// The image's version resource.
            #[serde(default, skip_serializing_if = "VersionInfo::is_empty")]
            pub version_info: VersionInfo,
            /// The process integrity level.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub integrity_level: Option<IntegrityLevel>,
            /// The token elevation type.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub token_elevation_type: Option<TokenElevationType>,
            /// The SID of the process owner.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub owner_sid: Option<Sid>,
            /// Where the image came from.
            #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
            pub origin: Option<Origin>,
            $($extra)*
        }
    };
}

process_struct!(
    /// The process that acted.
    Process {
        /// The parent process, with the same fields.
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        pub parent: Option<Box<ParentProcess>>,
        /// A summary of the grandparent process.
        #[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "present")]
        pub grandparent: Option<ProcessSummary>,
    }
);

process_struct!(
    /// A parent process. It has no parent of its own: the grandparent is
    /// summarised on the child.
    ParentProcess {}
);

/// A short description of a process.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessSummary {
    /// The process ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub pid: Option<u32>,
    /// The process key (#59).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub process_key: Option<Name>,
    /// The image path.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub image_path: Option<LongText>,
}

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------

/// The kind of device a file is stored on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// A fixed disk.
    Fixed,
    /// A removable drive.
    Removable,
    /// A network share.
    Network,
    /// An optical drive.
    Cdrom,
    /// A virtual disk.
    Virtual,
}

/// The file an event is about: the target of a decision.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct File {
    /// The path as reported, for example a device path.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub path: Option<LongText>,
    /// The path with drive letters and `%ENV%` substitutions.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub path_normalised: Option<LongText>,
    /// For packaged apps: the package family or full name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub package_name: Option<Name>,
    /// The object class.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub object_type: Option<ObjectType>,
    /// The size in bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub size: Option<u64>,
    /// When the file was created.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub created: Option<Timestamp>,
    /// When the file was last modified.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub modified: Option<Timestamp>,
    /// The SID of the file owner.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub owner_sid: Option<Sid>,
    /// The file's digests.
    #[serde(default, skip_serializing_if = "Hashes::is_empty")]
    pub hashes: Hashes,
    /// The file's signatures, leaf first.
    #[serde(default, skip_serializing_if = "BoundedVec::is_empty")]
    pub signers: BoundedVec<Signer, MAX_SIGNERS>,
    /// The file's version resource.
    #[serde(default, skip_serializing_if = "VersionInfo::is_empty")]
    pub version_info: VersionInfo,
    /// Whether a standard user can write to the file's location.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub user_writable_location: Option<bool>,
    /// The kind of device the file is on.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub device_type: Option<DeviceType>,
    /// The alternate data stream name, if the target is a stream.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ads_name: Option<Name>,
}

// ---------------------------------------------------------------------------
// Script
// ---------------------------------------------------------------------------

/// The PowerShell language mode a script ran in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LanguageMode {
    /// Full language.
    FullLanguage,
    /// Constrained language.
    ConstrainedLanguage,
    /// Restricted language.
    RestrictedLanguage,
    /// No language.
    NoLanguage,
}

/// A script.
///
/// A script is either a file (`path`) or inline text (`inline: true`):
/// exactly one of the two.
/// A file-backed script's digests and signatures are in [`Event::file`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Script {
    /// The script file.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub path: Option<LongText>,
    /// The script was inline text, not a file.
    ///
    /// Writers leave it out when it is not set. Readers also accept an
    /// explicit `false`, as 1.0 did, so this flag alone keeps two spellings
    /// until the next major version. The flags added in 1.1 accept only
    /// `true`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub inline: bool,
    /// The kind of script.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub kind: Option<ScriptKind>,
    /// The interpreter that ran it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub interpreter: Option<Name>,
    /// SHA-256 of the script content.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub content_sha256: Option<Sha256Hex>,
    /// The language mode it ran in.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub language_mode: Option<LanguageMode>,
    /// SHA-256 of the content passed to the antimalware scan interface.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub amsi_content_sha256: Option<Sha256Hex>,
    /// The interpreter's script block ID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub script_block_id: Option<Guid>,
    /// The script text as the interpreter logged it. Collected only when
    /// permitted, and redacted by default, like the command line (#228).
    /// Since 1.1.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub text: Option<LongText>,
}

const fn is_false(value: &bool) -> bool {
    !*value
}

/// Reads a flag that is written only when it is set: `true` is accepted,
/// and `false` is rejected because the field is then left out. So a set
/// flag has one spelling, and an unset one has none.
pub(crate) fn flag<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    if bool::deserialize(deserializer)? {
        Ok(true)
    } else {
        Err(serde::de::Error::custom(
            "`false` is not written: leave the field out",
        ))
    }
}

// ---------------------------------------------------------------------------
// Native enforcement
// ---------------------------------------------------------------------------

/// Details from OS-native enforcement: the OS code integrity and legacy
/// rule-collection engines.
///
/// These are the OS's own identifiers. Linking them to the Palisade policy
/// and rule that produced the native policy fills [`Event::policy`] (#90).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Native {
    /// The OS status code (an NTSTATUS value).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub status_code: Option<u32>,
    /// The signing level the caller requested (code 0 to 14).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub requested_signing_level: Option<u8>,
    /// The signing level the OS validated (code 0 to 14).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub validated_signing_level: Option<u8>,
    /// The signing scenario: 0 for kernel mode, 1 for user mode.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub signing_scenario: Option<u32>,
    /// The native policy's name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_name: Option<Name>,
    /// The native policy's ID string.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_id: Option<Name>,
    /// The native policy's GUID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_guid: Option<Guid>,
    /// The native policy's hash.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_hash: Option<HexBytes>,
    /// The native policy's option bits, as the OS reports them on activation.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_options: Option<u32>,
    /// How many policies an activation or refresh covered.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_count: Option<u32>,
    /// The COM class ID, for COM activation events.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub clsid: Option<Guid>,
    /// The native rule's GUID.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_guid: Option<Guid>,
    /// The native rule's name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_name: Option<Name>,
    /// The native rule's security descriptor (SDDL).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_sddl: Option<LongText>,
    /// The hash the rule-collection engine computed for hash rules. Its
    /// algorithm depends on the file type, so it is not one of [`Hashes`].
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub rule_hash: Option<HexBytes>,
    /// The fully qualified binary name (publisher, product, file name and
    /// version), verbatim.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub fqbn: Option<LongText>,
    /// The SHA-256 digest used for catalog lookup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub catalog_sha256: Option<Sha256Hex>,
    /// The SHA-1 digest used for catalog lookup. Interop only.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub catalog_sha1: Option<Sha1Hex>,
    /// Whether the native policy was in audit mode.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub policy_audit_mode: Option<bool>,
    /// Whether the native policy trusts files from a managed installer.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub managed_installer_enabled: Option<bool>,
    /// Whether the file carried a managed-installer origin claim.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub passes_managed_installer: Option<bool>,
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

/// The agent's overall health.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Everything works.
    Healthy,
    /// Working, with a problem that needs attention.
    Degraded,
    /// Not protecting the device.
    Unhealthy,
}

/// Cache counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheStats {
    /// Entries in the cache.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub entries: Option<u64>,
    /// Lookups answered from the cache.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub hits: Option<u64>,
    /// Lookups not answered from the cache.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub misses: Option<u64>,
}

/// Agent state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentInfo {
    /// The overall health.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub health: Option<HealthStatus>,
    /// Identity cache counters.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub cache: Option<CacheStats>,
    /// Events throttled since the last report.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub throttled_count: Option<u64>,
    /// Events dropped since the last report. Drops are always counted, never
    /// silent.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub dropped_count: Option<u64>,
    /// Tamper attempts since the last report.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub tamper_attempts: Option<u64>,
}

// ---------------------------------------------------------------------------
// Reading, writing and checking
// ---------------------------------------------------------------------------

/// An event could not be read.
#[derive(Debug)]
pub enum LoadError {
    /// The input is not JSON, or does not match the schema.
    Json(serde_json::Error),
    /// `schema_version` is missing or not a version string.
    MissingSchemaVersion,
    /// The event's major version is not the one this reader implements.
    UnsupportedSchemaVersion(SchemaVersion),
    /// The event is from a newer minor version than this reader. Upgrade the
    /// reader.
    NewerMinorVersion(SchemaVersion),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "invalid event: {e}"),
            Self::MissingSchemaVersion => {
                f.write_str("invalid event: missing or invalid `schema_version`")
            }
            Self::UnsupportedSchemaVersion(v) => {
                write!(
                    f,
                    "unsupported event schema version {v}: this reader implements {CURRENT}"
                )
            }
            Self::NewerMinorVersion(v) => write!(
                f,
                "event schema version {v} is newer than this reader ({CURRENT}); upgrade the reader"
            ),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

/// Whether a reader at [`CURRENT`] may read an event at `version`.
///
/// # Errors
///
/// Returns the [`LoadError`] that [`Event::from_json`] would return.
pub const fn check_version(version: SchemaVersion) -> Result<(), LoadError> {
    if !version.is_readable_by(CURRENT) {
        return Err(LoadError::UnsupportedSchemaVersion(version));
    }
    if version.minor > CURRENT.minor {
        return Err(LoadError::NewerMinorVersion(version));
    }
    Ok(())
}

/// A rule an event breaks that the type system cannot express.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventError {
    /// What is wrong.
    pub code: EventErrorCode,
    /// The JSON Pointer of the field.
    pub path: &'static str,
}

/// The rules [`Event::validate`] checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventErrorCode {
    /// `schema_version` is not readable by this crate.
    UnsupportedSchemaVersion,
    /// `category` is not the registered category of `event_type`.
    CategoryMismatch,
    /// A field set the event type requires is missing.
    MissingFieldSet(FieldSet),
    /// `prev_hash` is missing although `seq` is not 0, or present although
    /// `seq` is 0.
    ChainLink,
    /// A script has both a `path` and `inline`, or neither.
    ScriptPathXorInline,
    /// The event uses a part of the schema that is newer than its
    /// `schema_version` ([`Event::min_version`]).
    NewerThanVersion,
    /// `source.format` is missing although `source.kind` is `third_party`,
    /// or present although it is not.
    SourceFormat,
    /// `network.resolution` is present without `network.remote_hostname`.
    ResolutionWithoutHostname,
    /// A registry value has both a `value_name` and `default_value`.
    RegistryValueName,
    /// Registry data is marked `truncated` but has no `preview`.
    TruncatedWithoutPreview,
    /// An admin change does not have exactly the `old` and `new` values its
    /// `op` needs.
    ChangeValues,
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            EventErrorCode::UnsupportedSchemaVersion => {
                write!(f, "{}: unsupported schema version", self.path)
            }
            EventErrorCode::CategoryMismatch => {
                write!(
                    f,
                    "{}: does not match the event type's registered category",
                    self.path
                )
            }
            EventErrorCode::MissingFieldSet(set) => {
                write!(
                    f,
                    "{}: the event type requires the `{}` field set",
                    self.path,
                    set.as_str()
                )
            }
            EventErrorCode::ChainLink => {
                write!(f, "{}: required exactly when `seq` is not 0", self.path)
            }
            EventErrorCode::ScriptPathXorInline => {
                write!(
                    f,
                    "{}: a script is either a file (`path`) or `inline`",
                    self.path
                )
            }
            EventErrorCode::NewerThanVersion => write!(
                f,
                "{}: the event uses fields or values newer than this version",
                self.path
            ),
            EventErrorCode::SourceFormat => write!(
                f,
                "{}: required exactly when `source.kind` is `third_party`",
                self.path
            ),
            EventErrorCode::ResolutionWithoutHostname => write!(
                f,
                "{}: needs `remote_hostname`, the name it describes",
                self.path
            ),
            EventErrorCode::RegistryValueName => write!(
                f,
                "{}: a value has a name or is the default value, not both",
                self.path
            ),
            EventErrorCode::TruncatedWithoutPreview => {
                write!(f, "{}: `truncated` needs a `preview`", self.path)
            }
            EventErrorCode::ChangeValues => write!(
                f,
                "{}: `add` has `new` only, `remove` `old` only, and `replace` both",
                self.path
            ),
        }
    }
}

impl std::error::Error for EventError {}

impl Event {
    /// Reads an event from JSON.
    ///
    /// The schema version is checked first ([`check_version`]), so an event
    /// from another version gets a version error rather than a confusing
    /// field error. Unknown fields are rejected. This does not run
    /// [`Event::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`LoadError`] if the input is not an event this reader
    /// understands.
    pub fn from_json(input: &str) -> Result<Self, LoadError> {
        #[derive(Deserialize)]
        struct Header {
            #[serde(default)]
            schema_version: VersionPeek,
        }
        let header: Header = serde_json::from_str(input).map_err(LoadError::Json)?;
        let version = header
            .schema_version
            .0
            .ok_or(LoadError::MissingSchemaVersion)?;
        check_version(version)?;
        serde_json::from_str(input).map_err(LoadError::Json)
    }

    /// The canonical JSON form: compact, fields in schema order, optional
    /// fields that are not set left out, labels sorted by key. Equal events
    /// have equal canonical forms. This is the form producers send and chain.
    ///
    /// # Errors
    ///
    /// Only fails if serialisation itself fails, which these types do not do.
    pub fn to_canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Checks the rules that the types cannot express, and reports every
    /// broken rule.
    ///
    /// # Errors
    ///
    /// Returns every [`EventError`] found.
    pub fn validate(&self) -> Result<(), Vec<EventError>> {
        let mut errors = Vec::new();
        let mut fail = |code, path| errors.push(EventError { code, path });
        if check_version(self.schema_version).is_err() {
            fail(EventErrorCode::UnsupportedSchemaVersion, "/schema_version");
        }
        if self.category != self.event_type.category() {
            fail(EventErrorCode::CategoryMismatch, "/category");
        }
        for &set in self.event_type.required() {
            if !self.has(set) {
                fail(EventErrorCode::MissingFieldSet(set), set.pointer());
            }
        }
        if (self.seq == 0) == self.prev_hash.is_some() {
            fail(EventErrorCode::ChainLink, "/prev_hash");
        }
        if self
            .script
            .as_ref()
            .is_some_and(|s| s.inline == s.path.is_some())
        {
            fail(EventErrorCode::ScriptPathXorInline, "/script");
        }
        if self.min_version() > self.schema_version {
            fail(EventErrorCode::NewerThanVersion, "/schema_version");
        }
        if let Some(source) = &self.source
            && (source.kind == SourceKind::ThirdParty) != source.format.is_some()
        {
            fail(EventErrorCode::SourceFormat, "/source/format");
        }
        if self
            .network
            .as_ref()
            .is_some_and(|n| n.resolution.is_some() && n.remote_hostname.is_none())
        {
            fail(
                EventErrorCode::ResolutionWithoutHostname,
                "/network/resolution",
            );
        }
        if let Some(registry) = &self.registry {
            if registry.default_value && registry.value_name.is_some() {
                fail(EventErrorCode::RegistryValueName, "/registry/default_value");
            }
            for (data, path) in [
                (&registry.old, "/registry/old/truncated"),
                (&registry.new, "/registry/new/truncated"),
            ] {
                if data
                    .as_ref()
                    .is_some_and(|d| d.truncated && d.preview.is_none())
                {
                    fail(EventErrorCode::TruncatedWithoutPreview, path);
                }
            }
        }
        if self
            .admin
            .as_ref()
            .is_some_and(|a| a.changes.iter().any(|c| !c.is_well_formed()))
        {
            fail(EventErrorCode::ChangeValues, "/admin/changes");
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Whether a field set is present.
    #[must_use]
    pub const fn has(&self, set: FieldSet) -> bool {
        match set {
            FieldSet::User => self.user.is_some(),
            FieldSet::Policy => self.policy.is_some(),
            FieldSet::Process => self.process.is_some(),
            FieldSet::File => self.file.is_some(),
            FieldSet::Script => self.script.is_some(),
            FieldSet::Native => self.native.is_some(),
            FieldSet::Agent => self.agent.is_some(),
            FieldSet::Network => self.network.is_some(),
            FieldSet::Device => self.device.is_some(),
            FieldSet::Registry => self.registry.is_some(),
            FieldSet::Elevation => self.elevation.is_some(),
            FieldSet::Approval => self.approval.is_some(),
            FieldSet::Admin => self.admin.is_some(),
            FieldSet::Identity => self.identity.is_some(),
            FieldSet::AuditPolicy => self.audit_policy.is_some(),
            FieldSet::Restriction => self.restriction.is_some(),
            FieldSet::Probe => self.probe.is_some(),
            FieldSet::Fim => self.fim.is_some(),
        }
    }

    /// The oldest schema version that has every field, field set, event
    /// type and enum value this event uses. An event labelled with an older
    /// `schema_version` is invalid.
    #[must_use]
    pub fn min_version(&self) -> SchemaVersion {
        let mut version = self.event_type.since();
        let mut need = |v: SchemaVersion| {
            if v > version {
                version = v;
            }
        };
        for set in FieldSet::ALL {
            if self.has(set) {
                need(set.since());
            }
        }
        if let Some(source) = &self.source {
            need(source.kind.since());
            if source.format.is_some() {
                need(pointer_since("/source/format"));
            }
            if source.rule_name.is_some() {
                need(pointer_since("/source/rule_name"));
            }
        }
        if self.script.as_ref().is_some_and(|s| s.text.is_some()) {
            need(pointer_since("/script/text"));
        }
        if self.policy.as_ref().is_some_and(|p| p.kid.is_some()) {
            need(pointer_since("/policy/kid"));
        }
        version
    }

    /// The ISM-0585 fields this event lacks, by name. Empty when the event
    /// records the date and time, the user or process, the file name, a
    /// description and the device.
    ///
    /// `ts`, `description` and `host` are required by the type, so only the
    /// subject and object can be missing. The "file name" is the name of the
    /// object acted on: a file path, a script path or inline marker, a
    /// packaged app's name, or, for COM activation, the class ID. Since 1.1
    /// it may also be a network destination (URL, UNC path, remote host name
    /// or address), a device (instance ID, friendly name or serial) or a
    /// registry key, for decisions about those objects.
    #[must_use]
    pub fn ism_0585_gaps(&self) -> Vec<&'static str> {
        let mut gaps = Vec::new();
        let user = self
            .user
            .as_ref()
            .is_some_and(|u| u.sid.is_some() || u.name.is_some());
        let process = self
            .process
            .as_ref()
            .is_some_and(|p| p.image_path.is_some() || p.pid.is_some());
        if !user && !process {
            gaps.push("user or process");
        }
        let file = self
            .file
            .as_ref()
            .is_some_and(|f| f.path.is_some() || f.package_name.is_some());
        let script = self
            .script
            .as_ref()
            .is_some_and(|s| s.path.is_some() || s.inline);
        let com_class = self.native.as_ref().is_some_and(|n| n.clsid.is_some());
        let network = self.network.as_ref().is_some_and(|n| {
            n.url.is_some()
                || n.unc.is_some()
                || n.remote_hostname.is_some()
                || n.remote_ip.is_some()
        });
        let device = self.device.as_ref().is_some_and(|d| {
            d.instance_id.is_some() || d.friendly_name.is_some() || d.serial.is_some()
        });
        let registry = self.registry.as_ref().is_some_and(|r| r.key.is_some());
        if !file && !script && !com_class && !network && !device && !registry {
            gaps.push("file name");
        }
        gaps
    }
}

/// The `schema_version` of a document, read without keeping any other value:
/// a string that parses as a version, or `None` for anything else. Values of
/// other types are skipped without being built.
#[derive(Default)]
struct VersionPeek(Option<SchemaVersion>);

impl<'de> Deserialize<'de> for VersionPeek {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = VersionPeek;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<VersionPeek, E> {
                Ok(VersionPeek(v.parse().ok()))
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<VersionPeek, E> {
                Ok(VersionPeek(None))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<VersionPeek, E> {
                Ok(VersionPeek(None))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<VersionPeek, E> {
                Ok(VersionPeek(None))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<VersionPeek, E> {
                Ok(VersionPeek(None))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<VersionPeek, E> {
                Ok(VersionPeek(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<VersionPeek, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(VersionPeek(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<VersionPeek, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(VersionPeek(None))
            }
        }
        deserializer.deserialize_any(V)
    }
}
