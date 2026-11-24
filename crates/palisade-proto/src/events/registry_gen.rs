// @generated from `events/registry.yaml` by `src/events/registry.rs`.
// Do not edit by hand. Regenerate with:
//   PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry

use super::{Category, FieldSet, SchemaVersion, Severity};

/// A registered event type. See `events/REGISTRY.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventType {
    /// `exec.decision`: An executable was allowed, blocked or audited.
    ExecDecision,
    /// `library.decision`: A library load into a process was allowed, blocked or audited.
    LibraryDecision,
    /// `driver.decision`: A kernel driver load was allowed, blocked or audited.
    DriverDecision,
    /// `script.decision`: A script was allowed, blocked or audited.
    ScriptDecision,
    /// `installer.decision`: An installer package was allowed, blocked or audited.
    InstallerDecision,
    /// `packaged_app.decision`: A packaged app's installation or activation was allowed, blocked or audited.
    PackagedAppDecision,
    /// `com.decision`: A COM class activation was allowed, blocked or audited.
    ComDecision,
    /// `exec.origin_check`: The OS checked a file's managed-installer or reputation origin claims. Diagnostic only, not the final decision.
    ExecOriginCheck,
    /// `policy.applied`: A policy was applied, or was already current.
    PolicyApplied,
    /// `policy.failed`: A policy could not be applied or activated.
    PolicyFailed,
    /// `policy.activated`: A policy became active in the enforcement engine.
    PolicyActivated,
    /// `agent.started`: The agent started.
    AgentStarted,
    /// `agent.stopped`: The agent stopped.
    AgentStopped,
    /// `agent.health`: A periodic report of the agent's health and counters.
    AgentHealth,
    /// `agent.tamper`: An attempt to tamper with the agent, its configuration or its data was detected.
    AgentTamper,
    /// `agent.throttled`: The agent throttled events because of their rate.
    AgentThrottled,
    /// `agent.dropped`: The agent dropped events, and reports how many.
    AgentDropped,
    /// `agent.clock_unsynced`: The agent's wall clock is not synchronised, so event times may be wrong.
    AgentClockUnsynced,
    /// `process.created`: The OS reported a new process, with its command line where collected (ISM-1889).
    ProcessCreated,
    /// `script.block_logged`: The script interpreter logged the text of a script block it ran (ISM-1623).
    ScriptBlockLogged,
    /// `script.language_audit`: The script interpreter reported a restriction it would apply in constrained language mode.
    ScriptLanguageAudit,
    /// `containment.decision`: A contained application's access to a file, registry key, process or the network was allowed, blocked or audited.
    ContainmentDecision,
    /// `device.attached`: A peripheral device was connected.
    DeviceAttached,
    /// `device.detached`: A peripheral device was disconnected.
    DeviceDetached,
    /// `storage.decision`: Access to a removable or external storage device was allowed, blocked, made read-only or audited.
    StorageDecision,
    /// `network.app.decision`: An application's network connection was allowed, blocked or audited.
    NetworkAppDecision,
    /// `network.host.decision`: A connection to or from the device was allowed, blocked or audited by host network control.
    NetworkHostDecision,
    /// `web.decision`: Access to a web address was allowed, blocked or audited.
    WebDecision,
    /// `elevation.requested`: A user asked to run something with elevated rights.
    ElevationRequested,
    /// `elevation.decision`: Elevated rights were granted, refused or cancelled.
    ElevationDecision,
    /// `elevation.ended`: An elevation grant ended or expired.
    ElevationEnded,
    /// `approval.requested`: A user asked for an approval.
    ApprovalRequested,
    /// `approval.decided`: An approval request was approved, denied, expired or cancelled.
    ApprovalDecided,
    /// `exception.created`: A policy exception was created.
    ExceptionCreated,
    /// `exception.changed`: A policy exception was changed.
    ExceptionChanged,
    /// `exception.removed`: A policy exception was removed.
    ExceptionRemoved,
    /// `exception.expired`: A policy exception reached its end date.
    ExceptionExpired,
    /// `otp.session.started`: An offline override code started a session in which the policy is relaxed.
    OtpSessionStarted,
    /// `otp.session.ended`: An offline override session ended.
    OtpSessionEnded,
    /// `admin.action`: An administrator, API client or job changed something on the server.
    AdminAction,
    /// `admin.login`: A person or client signed in to the server.
    AdminLogin,
    /// `admin.login_failed`: A sign-in to the server failed.
    AdminLoginFailed,
    /// `identity.logon`: An account logged on to the device.
    IdentityLogon,
    /// `identity.logon_failed`: A logon to the device failed.
    IdentityLogonFailed,
    /// `identity.local_group.changed`: A member was added to or removed from a security group (ISM-1650).
    IdentityLocalGroupChanged,
    /// `identity.group.changed`: A member was added to or removed from a directory global or universal security group (ISM-1650).
    IdentityGroupChanged,
    /// `detection.log_cleared`: An event log was cleared.
    DetectionLogCleared,
    /// `detection.audit_policy_changed`: The OS audit policy was changed.
    DetectionAuditPolicyChanged,
    /// `integrity.fim.changed`: A monitored file was created, changed, renamed or deleted.
    IntegrityFimChanged,
    /// `compliance.probe.result`: A compliance probe reported its result.
    ComplianceProbeResult,
}

impl EventType {
    /// Every registered type, in registry order.
    pub const ALL: [Self; 50] = [
        Self::ExecDecision,
        Self::LibraryDecision,
        Self::DriverDecision,
        Self::ScriptDecision,
        Self::InstallerDecision,
        Self::PackagedAppDecision,
        Self::ComDecision,
        Self::ExecOriginCheck,
        Self::PolicyApplied,
        Self::PolicyFailed,
        Self::PolicyActivated,
        Self::AgentStarted,
        Self::AgentStopped,
        Self::AgentHealth,
        Self::AgentTamper,
        Self::AgentThrottled,
        Self::AgentDropped,
        Self::AgentClockUnsynced,
        Self::ProcessCreated,
        Self::ScriptBlockLogged,
        Self::ScriptLanguageAudit,
        Self::ContainmentDecision,
        Self::DeviceAttached,
        Self::DeviceDetached,
        Self::StorageDecision,
        Self::NetworkAppDecision,
        Self::NetworkHostDecision,
        Self::WebDecision,
        Self::ElevationRequested,
        Self::ElevationDecision,
        Self::ElevationEnded,
        Self::ApprovalRequested,
        Self::ApprovalDecided,
        Self::ExceptionCreated,
        Self::ExceptionChanged,
        Self::ExceptionRemoved,
        Self::ExceptionExpired,
        Self::OtpSessionStarted,
        Self::OtpSessionEnded,
        Self::AdminAction,
        Self::AdminLogin,
        Self::AdminLoginFailed,
        Self::IdentityLogon,
        Self::IdentityLogonFailed,
        Self::IdentityLocalGroupChanged,
        Self::IdentityGroupChanged,
        Self::DetectionLogCleared,
        Self::DetectionAuditPolicyChanged,
        Self::IntegrityFimChanged,
        Self::ComplianceProbeResult,
    ];

    /// The dotted name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecDecision => "exec.decision",
            Self::LibraryDecision => "library.decision",
            Self::DriverDecision => "driver.decision",
            Self::ScriptDecision => "script.decision",
            Self::InstallerDecision => "installer.decision",
            Self::PackagedAppDecision => "packaged_app.decision",
            Self::ComDecision => "com.decision",
            Self::ExecOriginCheck => "exec.origin_check",
            Self::PolicyApplied => "policy.applied",
            Self::PolicyFailed => "policy.failed",
            Self::PolicyActivated => "policy.activated",
            Self::AgentStarted => "agent.started",
            Self::AgentStopped => "agent.stopped",
            Self::AgentHealth => "agent.health",
            Self::AgentTamper => "agent.tamper",
            Self::AgentThrottled => "agent.throttled",
            Self::AgentDropped => "agent.dropped",
            Self::AgentClockUnsynced => "agent.clock_unsynced",
            Self::ProcessCreated => "process.created",
            Self::ScriptBlockLogged => "script.block_logged",
            Self::ScriptLanguageAudit => "script.language_audit",
            Self::ContainmentDecision => "containment.decision",
            Self::DeviceAttached => "device.attached",
            Self::DeviceDetached => "device.detached",
            Self::StorageDecision => "storage.decision",
            Self::NetworkAppDecision => "network.app.decision",
            Self::NetworkHostDecision => "network.host.decision",
            Self::WebDecision => "web.decision",
            Self::ElevationRequested => "elevation.requested",
            Self::ElevationDecision => "elevation.decision",
            Self::ElevationEnded => "elevation.ended",
            Self::ApprovalRequested => "approval.requested",
            Self::ApprovalDecided => "approval.decided",
            Self::ExceptionCreated => "exception.created",
            Self::ExceptionChanged => "exception.changed",
            Self::ExceptionRemoved => "exception.removed",
            Self::ExceptionExpired => "exception.expired",
            Self::OtpSessionStarted => "otp.session.started",
            Self::OtpSessionEnded => "otp.session.ended",
            Self::AdminAction => "admin.action",
            Self::AdminLogin => "admin.login",
            Self::AdminLoginFailed => "admin.login_failed",
            Self::IdentityLogon => "identity.logon",
            Self::IdentityLogonFailed => "identity.logon_failed",
            Self::IdentityLocalGroupChanged => "identity.local_group.changed",
            Self::IdentityGroupChanged => "identity.group.changed",
            Self::DetectionLogCleared => "detection.log_cleared",
            Self::DetectionAuditPolicyChanged => "detection.audit_policy_changed",
            Self::IntegrityFimChanged => "integrity.fim.changed",
            Self::ComplianceProbeResult => "compliance.probe.result",
        }
    }

    /// The category every event of this type has.
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::ExecDecision => Category::Execution,
            Self::LibraryDecision => Category::Library,
            Self::DriverDecision => Category::Driver,
            Self::ScriptDecision => Category::Script,
            Self::InstallerDecision => Category::Installer,
            Self::PackagedAppDecision => Category::PackagedApp,
            Self::ComDecision => Category::Execution,
            Self::ExecOriginCheck => Category::Execution,
            Self::PolicyApplied => Category::Policy,
            Self::PolicyFailed => Category::Policy,
            Self::PolicyActivated => Category::Policy,
            Self::AgentStarted => Category::Agent,
            Self::AgentStopped => Category::Agent,
            Self::AgentHealth => Category::Agent,
            Self::AgentTamper => Category::Agent,
            Self::AgentThrottled => Category::Agent,
            Self::AgentDropped => Category::Agent,
            Self::AgentClockUnsynced => Category::Agent,
            Self::ProcessCreated => Category::Execution,
            Self::ScriptBlockLogged => Category::Script,
            Self::ScriptLanguageAudit => Category::Script,
            Self::ContainmentDecision => Category::Containment,
            Self::DeviceAttached => Category::Device,
            Self::DeviceDetached => Category::Device,
            Self::StorageDecision => Category::Device,
            Self::NetworkAppDecision => Category::Network,
            Self::NetworkHostDecision => Category::Network,
            Self::WebDecision => Category::Web,
            Self::ElevationRequested => Category::Elevation,
            Self::ElevationDecision => Category::Elevation,
            Self::ElevationEnded => Category::Elevation,
            Self::ApprovalRequested => Category::Approval,
            Self::ApprovalDecided => Category::Approval,
            Self::ExceptionCreated => Category::Exception,
            Self::ExceptionChanged => Category::Exception,
            Self::ExceptionRemoved => Category::Exception,
            Self::ExceptionExpired => Category::Exception,
            Self::OtpSessionStarted => Category::Exception,
            Self::OtpSessionEnded => Category::Exception,
            Self::AdminAction => Category::AdminAudit,
            Self::AdminLogin => Category::AdminAudit,
            Self::AdminLoginFailed => Category::AdminAudit,
            Self::IdentityLogon => Category::Identity,
            Self::IdentityLogonFailed => Category::Identity,
            Self::IdentityLocalGroupChanged => Category::Identity,
            Self::IdentityGroupChanged => Category::Identity,
            Self::DetectionLogCleared => Category::Detection,
            Self::DetectionAuditPolicyChanged => Category::Detection,
            Self::IntegrityFimChanged => Category::Integrity,
            Self::ComplianceProbeResult => Category::Compliance,
        }
    }

    /// The severity used when the producer has no better one.
    #[must_use]
    pub const fn default_severity(self) -> Severity {
        match self {
            Self::ExecDecision => Severity::clamped(3),
            Self::LibraryDecision => Severity::clamped(3),
            Self::DriverDecision => Severity::clamped(5),
            Self::ScriptDecision => Severity::clamped(3),
            Self::InstallerDecision => Severity::clamped(3),
            Self::PackagedAppDecision => Severity::clamped(3),
            Self::ComDecision => Severity::clamped(3),
            Self::ExecOriginCheck => Severity::clamped(1),
            Self::PolicyApplied => Severity::clamped(2),
            Self::PolicyFailed => Severity::clamped(7),
            Self::PolicyActivated => Severity::clamped(2),
            Self::AgentStarted => Severity::clamped(2),
            Self::AgentStopped => Severity::clamped(4),
            Self::AgentHealth => Severity::clamped(1),
            Self::AgentTamper => Severity::clamped(9),
            Self::AgentThrottled => Severity::clamped(5),
            Self::AgentDropped => Severity::clamped(7),
            Self::AgentClockUnsynced => Severity::clamped(5),
            Self::ProcessCreated => Severity::clamped(2),
            Self::ScriptBlockLogged => Severity::clamped(2),
            Self::ScriptLanguageAudit => Severity::clamped(4),
            Self::ContainmentDecision => Severity::clamped(4),
            Self::DeviceAttached => Severity::clamped(2),
            Self::DeviceDetached => Severity::clamped(1),
            Self::StorageDecision => Severity::clamped(4),
            Self::NetworkAppDecision => Severity::clamped(3),
            Self::NetworkHostDecision => Severity::clamped(3),
            Self::WebDecision => Severity::clamped(3),
            Self::ElevationRequested => Severity::clamped(4),
            Self::ElevationDecision => Severity::clamped(5),
            Self::ElevationEnded => Severity::clamped(3),
            Self::ApprovalRequested => Severity::clamped(3),
            Self::ApprovalDecided => Severity::clamped(4),
            Self::ExceptionCreated => Severity::clamped(5),
            Self::ExceptionChanged => Severity::clamped(5),
            Self::ExceptionRemoved => Severity::clamped(4),
            Self::ExceptionExpired => Severity::clamped(3),
            Self::OtpSessionStarted => Severity::clamped(7),
            Self::OtpSessionEnded => Severity::clamped(4),
            Self::AdminAction => Severity::clamped(4),
            Self::AdminLogin => Severity::clamped(2),
            Self::AdminLoginFailed => Severity::clamped(5),
            Self::IdentityLogon => Severity::clamped(2),
            Self::IdentityLogonFailed => Severity::clamped(5),
            Self::IdentityLocalGroupChanged => Severity::clamped(6),
            Self::IdentityGroupChanged => Severity::clamped(6),
            Self::DetectionLogCleared => Severity::clamped(9),
            Self::DetectionAuditPolicyChanged => Severity::clamped(7),
            Self::IntegrityFimChanged => Severity::clamped(5),
            Self::ComplianceProbeResult => Severity::clamped(3),
        }
    }

    /// The field sets every event of this type carries.
    #[must_use]
    pub const fn required(self) -> &'static [FieldSet] {
        match self {
            Self::ExecDecision => &[FieldSet::File],
            Self::LibraryDecision => &[FieldSet::File],
            Self::DriverDecision => &[FieldSet::File],
            Self::ScriptDecision => &[FieldSet::Script],
            Self::InstallerDecision => &[FieldSet::File],
            Self::PackagedAppDecision => &[FieldSet::File],
            Self::ComDecision => &[FieldSet::Native],
            Self::ExecOriginCheck => &[FieldSet::File, FieldSet::Native],
            Self::PolicyApplied => &[],
            Self::PolicyFailed => &[],
            Self::PolicyActivated => &[],
            Self::AgentStarted => &[],
            Self::AgentStopped => &[],
            Self::AgentHealth => &[FieldSet::Agent],
            Self::AgentTamper => &[],
            Self::AgentThrottled => &[FieldSet::Agent],
            Self::AgentDropped => &[FieldSet::Agent],
            Self::AgentClockUnsynced => &[],
            Self::ProcessCreated => &[FieldSet::Process],
            Self::ScriptBlockLogged => &[FieldSet::Script],
            Self::ScriptLanguageAudit => &[FieldSet::Restriction],
            Self::ContainmentDecision => &[FieldSet::Process],
            Self::DeviceAttached => &[FieldSet::Device],
            Self::DeviceDetached => &[FieldSet::Device],
            Self::StorageDecision => &[FieldSet::Device],
            Self::NetworkAppDecision => &[FieldSet::Network],
            Self::NetworkHostDecision => &[FieldSet::Network],
            Self::WebDecision => &[FieldSet::Network],
            Self::ElevationRequested => &[FieldSet::Elevation],
            Self::ElevationDecision => &[FieldSet::Elevation],
            Self::ElevationEnded => &[FieldSet::Elevation],
            Self::ApprovalRequested => &[FieldSet::Approval],
            Self::ApprovalDecided => &[FieldSet::Approval],
            Self::ExceptionCreated => &[FieldSet::Admin],
            Self::ExceptionChanged => &[FieldSet::Admin],
            Self::ExceptionRemoved => &[FieldSet::Admin],
            Self::ExceptionExpired => &[],
            Self::OtpSessionStarted => &[FieldSet::Approval],
            Self::OtpSessionEnded => &[FieldSet::Approval],
            Self::AdminAction => &[FieldSet::Admin],
            Self::AdminLogin => &[FieldSet::Admin],
            Self::AdminLoginFailed => &[FieldSet::Admin],
            Self::IdentityLogon => &[FieldSet::User],
            Self::IdentityLogonFailed => &[FieldSet::User],
            Self::IdentityLocalGroupChanged => &[FieldSet::Identity],
            Self::IdentityGroupChanged => &[FieldSet::Identity],
            Self::DetectionLogCleared => &[],
            Self::DetectionAuditPolicyChanged => &[FieldSet::AuditPolicy],
            Self::IntegrityFimChanged => &[FieldSet::File, FieldSet::Fim],
            Self::ComplianceProbeResult => &[FieldSet::Probe],
        }
    }

    /// Whether allowed events of this type may be summarised (#197).
    #[must_use]
    pub const fn summarisable(self) -> bool {
        match self {
            Self::ExecDecision => true,
            Self::LibraryDecision => true,
            Self::DriverDecision => true,
            Self::ScriptDecision => true,
            Self::InstallerDecision => true,
            Self::PackagedAppDecision => true,
            Self::ComDecision => true,
            Self::ExecOriginCheck => true,
            Self::PolicyApplied => false,
            Self::PolicyFailed => false,
            Self::PolicyActivated => false,
            Self::AgentStarted => false,
            Self::AgentStopped => false,
            Self::AgentHealth => false,
            Self::AgentTamper => false,
            Self::AgentThrottled => false,
            Self::AgentDropped => false,
            Self::AgentClockUnsynced => false,
            Self::ProcessCreated => false,
            Self::ScriptBlockLogged => false,
            Self::ScriptLanguageAudit => false,
            Self::ContainmentDecision => true,
            Self::DeviceAttached => false,
            Self::DeviceDetached => false,
            Self::StorageDecision => true,
            Self::NetworkAppDecision => true,
            Self::NetworkHostDecision => true,
            Self::WebDecision => true,
            Self::ElevationRequested => false,
            Self::ElevationDecision => false,
            Self::ElevationEnded => false,
            Self::ApprovalRequested => false,
            Self::ApprovalDecided => false,
            Self::ExceptionCreated => false,
            Self::ExceptionChanged => false,
            Self::ExceptionRemoved => false,
            Self::ExceptionExpired => false,
            Self::OtpSessionStarted => false,
            Self::OtpSessionEnded => false,
            Self::AdminAction => false,
            Self::AdminLogin => false,
            Self::AdminLoginFailed => false,
            Self::IdentityLogon => false,
            Self::IdentityLogonFailed => false,
            Self::IdentityLocalGroupChanged => false,
            Self::IdentityGroupChanged => false,
            Self::DetectionLogCleared => false,
            Self::DetectionAuditPolicyChanged => false,
            Self::IntegrityFimChanged => false,
            Self::ComplianceProbeResult => false,
        }
    }

    /// The schema version the type was added in.
    #[must_use]
    pub const fn since(self) -> SchemaVersion {
        match self {
            Self::ExecDecision => SchemaVersion::new(1, 0, 0),
            Self::LibraryDecision => SchemaVersion::new(1, 0, 0),
            Self::DriverDecision => SchemaVersion::new(1, 0, 0),
            Self::ScriptDecision => SchemaVersion::new(1, 0, 0),
            Self::InstallerDecision => SchemaVersion::new(1, 0, 0),
            Self::PackagedAppDecision => SchemaVersion::new(1, 0, 0),
            Self::ComDecision => SchemaVersion::new(1, 0, 0),
            Self::ExecOriginCheck => SchemaVersion::new(1, 0, 0),
            Self::PolicyApplied => SchemaVersion::new(1, 0, 0),
            Self::PolicyFailed => SchemaVersion::new(1, 0, 0),
            Self::PolicyActivated => SchemaVersion::new(1, 0, 0),
            Self::AgentStarted => SchemaVersion::new(1, 0, 0),
            Self::AgentStopped => SchemaVersion::new(1, 0, 0),
            Self::AgentHealth => SchemaVersion::new(1, 0, 0),
            Self::AgentTamper => SchemaVersion::new(1, 0, 0),
            Self::AgentThrottled => SchemaVersion::new(1, 0, 0),
            Self::AgentDropped => SchemaVersion::new(1, 0, 0),
            Self::AgentClockUnsynced => SchemaVersion::new(1, 0, 0),
            Self::ProcessCreated => SchemaVersion::new(1, 1, 0),
            Self::ScriptBlockLogged => SchemaVersion::new(1, 1, 0),
            Self::ScriptLanguageAudit => SchemaVersion::new(1, 1, 0),
            Self::ContainmentDecision => SchemaVersion::new(1, 1, 0),
            Self::DeviceAttached => SchemaVersion::new(1, 1, 0),
            Self::DeviceDetached => SchemaVersion::new(1, 1, 0),
            Self::StorageDecision => SchemaVersion::new(1, 1, 0),
            Self::NetworkAppDecision => SchemaVersion::new(1, 1, 0),
            Self::NetworkHostDecision => SchemaVersion::new(1, 1, 0),
            Self::WebDecision => SchemaVersion::new(1, 1, 0),
            Self::ElevationRequested => SchemaVersion::new(1, 1, 0),
            Self::ElevationDecision => SchemaVersion::new(1, 1, 0),
            Self::ElevationEnded => SchemaVersion::new(1, 1, 0),
            Self::ApprovalRequested => SchemaVersion::new(1, 1, 0),
            Self::ApprovalDecided => SchemaVersion::new(1, 1, 0),
            Self::ExceptionCreated => SchemaVersion::new(1, 1, 0),
            Self::ExceptionChanged => SchemaVersion::new(1, 1, 0),
            Self::ExceptionRemoved => SchemaVersion::new(1, 1, 0),
            Self::ExceptionExpired => SchemaVersion::new(1, 1, 0),
            Self::OtpSessionStarted => SchemaVersion::new(1, 1, 0),
            Self::OtpSessionEnded => SchemaVersion::new(1, 1, 0),
            Self::AdminAction => SchemaVersion::new(1, 1, 0),
            Self::AdminLogin => SchemaVersion::new(1, 1, 0),
            Self::AdminLoginFailed => SchemaVersion::new(1, 1, 0),
            Self::IdentityLogon => SchemaVersion::new(1, 1, 0),
            Self::IdentityLogonFailed => SchemaVersion::new(1, 1, 0),
            Self::IdentityLocalGroupChanged => SchemaVersion::new(1, 1, 0),
            Self::IdentityGroupChanged => SchemaVersion::new(1, 1, 0),
            Self::DetectionLogCleared => SchemaVersion::new(1, 1, 0),
            Self::DetectionAuditPolicyChanged => SchemaVersion::new(1, 1, 0),
            Self::IntegrityFimChanged => SchemaVersion::new(1, 1, 0),
            Self::ComplianceProbeResult => SchemaVersion::new(1, 1, 0),
        }
    }

    /// One sentence about the type.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ExecDecision => "An executable was allowed, blocked or audited.",
            Self::LibraryDecision => "A library load into a process was allowed, blocked or audited.",
            Self::DriverDecision => "A kernel driver load was allowed, blocked or audited.",
            Self::ScriptDecision => "A script was allowed, blocked or audited.",
            Self::InstallerDecision => "An installer package was allowed, blocked or audited.",
            Self::PackagedAppDecision => "A packaged app's installation or activation was allowed, blocked or audited.",
            Self::ComDecision => "A COM class activation was allowed, blocked or audited.",
            Self::ExecOriginCheck => "The OS checked a file's managed-installer or reputation origin claims. Diagnostic only, not the final decision.",
            Self::PolicyApplied => "A policy was applied, or was already current.",
            Self::PolicyFailed => "A policy could not be applied or activated.",
            Self::PolicyActivated => "A policy became active in the enforcement engine.",
            Self::AgentStarted => "The agent started.",
            Self::AgentStopped => "The agent stopped.",
            Self::AgentHealth => "A periodic report of the agent's health and counters.",
            Self::AgentTamper => "An attempt to tamper with the agent, its configuration or its data was detected.",
            Self::AgentThrottled => "The agent throttled events because of their rate.",
            Self::AgentDropped => "The agent dropped events, and reports how many.",
            Self::AgentClockUnsynced => "The agent's wall clock is not synchronised, so event times may be wrong.",
            Self::ProcessCreated => "The OS reported a new process, with its command line where collected (ISM-1889).",
            Self::ScriptBlockLogged => "The script interpreter logged the text of a script block it ran (ISM-1623).",
            Self::ScriptLanguageAudit => "The script interpreter reported a restriction it would apply in constrained language mode.",
            Self::ContainmentDecision => "A contained application's access to a file, registry key, process or the network was allowed, blocked or audited.",
            Self::DeviceAttached => "A peripheral device was connected.",
            Self::DeviceDetached => "A peripheral device was disconnected.",
            Self::StorageDecision => "Access to a removable or external storage device was allowed, blocked, made read-only or audited.",
            Self::NetworkAppDecision => "An application's network connection was allowed, blocked or audited.",
            Self::NetworkHostDecision => "A connection to or from the device was allowed, blocked or audited by host network control.",
            Self::WebDecision => "Access to a web address was allowed, blocked or audited.",
            Self::ElevationRequested => "A user asked to run something with elevated rights.",
            Self::ElevationDecision => "Elevated rights were granted, refused or cancelled.",
            Self::ElevationEnded => "An elevation grant ended or expired.",
            Self::ApprovalRequested => "A user asked for an approval.",
            Self::ApprovalDecided => "An approval request was approved, denied, expired or cancelled.",
            Self::ExceptionCreated => "A policy exception was created.",
            Self::ExceptionChanged => "A policy exception was changed.",
            Self::ExceptionRemoved => "A policy exception was removed.",
            Self::ExceptionExpired => "A policy exception reached its end date.",
            Self::OtpSessionStarted => "An offline override code started a session in which the policy is relaxed.",
            Self::OtpSessionEnded => "An offline override session ended.",
            Self::AdminAction => "An administrator, API client or job changed something on the server.",
            Self::AdminLogin => "A person or client signed in to the server.",
            Self::AdminLoginFailed => "A sign-in to the server failed.",
            Self::IdentityLogon => "An account logged on to the device.",
            Self::IdentityLogonFailed => "A logon to the device failed.",
            Self::IdentityLocalGroupChanged => "A member was added to or removed from a security group (ISM-1650).",
            Self::IdentityGroupChanged => "A member was added to or removed from a directory global or universal security group (ISM-1650).",
            Self::DetectionLogCleared => "An event log was cleared.",
            Self::DetectionAuditPolicyChanged => "The OS audit policy was changed.",
            Self::IntegrityFimChanged => "A monitored file was created, changed, renamed or deleted.",
            Self::ComplianceProbeResult => "A compliance probe reported its result.",
        }
    }
}
