// @generated from `events/registry.yaml` by `src/events/registry.rs`.
// Do not edit by hand. Regenerate with:
//   PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry

use super::{Category, FieldSet, Severity};

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
}

impl EventType {
    /// Every registered type, in registry order.
    pub const ALL: [Self; 18] = [
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
        }
    }
}
