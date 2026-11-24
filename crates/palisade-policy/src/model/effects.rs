//! Effect flags: what a decision produces besides its outcome (#34).
//!
//! Every rule has an [`Effects`] block. Each field is optional, and an unset
//! field takes the default of the rule's action ([`Effects::resolve`]), so a
//! rule only states what it changes. The defaults are:
//!
//! | Action | `log` | `upload` | `notify` | `severity` | `suppress_duplicates_secs` |
//! |---|---|---|---|---|---|
//! | `allow`, `allow_contained` | `summary` | `batched` | `none` | `info` | 86400 |
//! | `allow_elevated` | `always` | `immediate` | `none` | `info` | 600 |
//! | `deny` | `always` | `immediate` | `default` | `medium` | 600 |
//! | `audit` | `always` | `immediate` | `none` | `low` | 600 |
//! | `trust_source` | `always` | `batched` | `none` | `info` | 600 |
//! | `ignore`, `defer` | `never` | `local_only` | `none` | `info` | 0 |
//!
//! The de-duplication default follows the effective `log`: 86400 for
//! `summary`, 0 for `never`, and 600 otherwise. Rendering notifications is
//! #11, summarising allowed executions is the agent's (#4, #16), and
//! alerting on severity is #16.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::ActionKind;

/// Limits on effect fields, enforced by the schema and validation.
pub mod limits {
    /// Longest notification text, in Unicode scalar values.
    pub const MAX_NOTIFICATION_TEXT_CHARS: usize = 2048;
    /// Longest help URL, in bytes.
    pub const MAX_HELP_URL_BYTES: usize = 2048;
    /// Longest de-duplication window, in seconds (seven days).
    pub const MAX_SUPPRESS_DUPLICATES_SECS: u32 = 604_800;
    /// The placeholders a notification text may use, without braces.
    pub const NOTIFICATION_PLACEHOLDERS: [&str; 5] = ["file", "publisher", "rule", "user", "hash"];
}

use limits::MAX_SUPPRESS_DUPLICATES_SECS;

/// The effect flags of one rule. Unset fields take the action's default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Effects {
    /// Whether the decision produces a local event. `deny`, `audit`,
    /// `allow_elevated` and `trust_source` need an event per decision, so
    /// `summary` and `never` are not allowed on them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<LogLevel>,
    /// When the event is sent to the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<Upload>,
    /// Whether the user is shown a notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<Notify>,
    /// The text of a `custom` notification: at most 2048 characters, with
    /// the placeholders `{file}`, `{publisher}`, `{rule}`, `{user}` and
    /// `{hash}`. Write `{{` and `}}` for literal braces. Required with
    /// `notify: custom`, and only allowed with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 2048))]
    pub notification_text: Option<String>,
    /// A link shown with the notification: an `https` URL of at most 2048
    /// bytes. Only allowed when a notification is shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 2048), regex(pattern = r"^https://"))]
    pub help_url: Option<String>,
    /// How serious the event is, for alerting (#16).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<EventSeverity>,
    /// Labels copied into the event, such as `lolbin` or
    /// `mitre:T1218.005`: each 1 to 128 characters, at most 64.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64), inner(length(min = 1, max = 128)))]
    pub tags: Vec<String>,
    /// The local de-duplication window, in seconds, at most 604800. `0`
    /// turns de-duplication off. Detection counters still count every
    /// occurrence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(max = MAX_SUPPRESS_DUPLICATES_SECS))]
    pub suppress_duplicates_secs: Option<u32>,
}

/// Whether a decision produces a local event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Every decision produces an event.
    Always,
    /// Decisions are aggregated into periodic summaries per device, user,
    /// object and rule. The default for allow rules.
    Summary,
    /// A sample of decisions produces events.
    Sampled,
    /// No event.
    Never,
}

/// When an event is sent to the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Upload {
    /// As soon as possible.
    Immediate,
    /// With the next batch.
    Batched,
    /// Never: kept in the local log only.
    LocalOnly,
}

/// Whether the user is shown a notification (#11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Notify {
    /// No notification.
    None,
    /// The policy's default notification.
    Default,
    /// The rule's `notification_text`.
    Custom,
}

/// How serious an event is (#16).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    /// Informational.
    Info,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

/// The effect flags of a decision, with every default applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedEffects {
    /// Whether the decision produces a local event.
    pub log: LogLevel,
    /// When the event is sent to the server.
    pub upload: Upload,
    /// Whether the user is shown a notification.
    pub notify: Notify,
    /// The text of a `custom` notification, before placeholders are filled in.
    pub notification_text: Option<String>,
    /// A link shown with the notification.
    pub help_url: Option<String>,
    /// How serious the event is.
    pub severity: EventSeverity,
    /// Labels copied into the event.
    pub tags: Vec<String>,
    /// The local de-duplication window, in seconds. `0` is off.
    pub suppress_duplicates_secs: u32,
}

impl Effects {
    /// Whether no field is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The effective log level for a rule with this action.
    #[must_use]
    pub fn log_for(&self, action: ActionKind) -> LogLevel {
        self.log.unwrap_or_else(|| default_log(action))
    }

    /// The effective notification for a rule with this action.
    #[must_use]
    pub fn notify_for(&self, action: ActionKind) -> Notify {
        self.notify.unwrap_or(match action {
            ActionKind::Deny => Notify::Default,
            _ => Notify::None,
        })
    }

    /// Applies the defaults of `action` (see the module documentation).
    #[must_use]
    pub fn resolve(&self, action: ActionKind) -> ResolvedEffects {
        use ActionKind as A;
        let log = self.log_for(action);
        let upload = self.upload.unwrap_or(match action {
            A::Deny | A::Audit | A::AllowElevated => Upload::Immediate,
            A::Allow | A::AllowContained | A::TrustSource => Upload::Batched,
            A::Ignore | A::Defer => Upload::LocalOnly,
        });
        let severity = self.severity.unwrap_or(match action {
            A::Deny => EventSeverity::Medium,
            A::Audit => EventSeverity::Low,
            _ => EventSeverity::Info,
        });
        let suppress_duplicates_secs = self.suppress_duplicates_secs.unwrap_or(match log {
            LogLevel::Summary => 86_400,
            LogLevel::Never => 0,
            LogLevel::Always | LogLevel::Sampled => 600,
        });
        ResolvedEffects {
            log,
            upload,
            notify: self.notify_for(action),
            notification_text: self.notification_text.clone(),
            help_url: self.help_url.clone(),
            severity,
            tags: self.tags.clone(),
            suppress_duplicates_secs,
        }
    }
}

const fn default_log(action: ActionKind) -> LogLevel {
    match action {
        ActionKind::Allow | ActionKind::AllowContained => LogLevel::Summary,
        ActionKind::Deny
        | ActionKind::Audit
        | ActionKind::AllowElevated
        | ActionKind::TrustSource => LogLevel::Always,
        ActionKind::Ignore | ActionKind::Defer => LogLevel::Never,
    }
}

impl LogLevel {
    /// Whether this level is allowed for an action. A block must be
    /// loggable, an audit rule exists only to record, every use of
    /// administrator rights is logged, and so is every grant of trusted
    /// installer status (ISM-1660). Those four need an event per decision
    /// (`always` or `sampled`): not `summary`, and not `never`.
    #[must_use]
    pub const fn allowed_for(self, action: ActionKind) -> bool {
        let per_decision = matches!(
            action,
            ActionKind::Deny
                | ActionKind::Audit
                | ActionKind::AllowElevated
                | ActionKind::TrustSource
        );
        !per_decision || matches!(self, Self::Always | Self::Sampled)
    }
}
