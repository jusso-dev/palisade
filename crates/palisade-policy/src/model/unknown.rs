//! The unknown-application policy: what happens when no rule decides (#39).
//!
//! Stage 6 of the pipeline ([`crate::evaluate`]) runs only when stages 1 to
//! 5 decided nothing, so it never overrides an explicit allow or deny. An
//! [`UnknownPolicy`] chooses a [`Level`] for the object from its type, its
//! location classes and its origins, and [`crate::unknown`] turns that level
//! into a decision.
//!
//! The level is the **most restrictive** of every entry that applies: the
//! `by_type` entry for the object's type, the `by_location` entry of each
//! location class the object is in, and the `by_origin` entry of each
//! origin. `default` applies only when no entry does. The order is
//! `block > restrict > prompt > detect > allow` ([`Level`]'s `Ord`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::settings::unique_keys;
use super::{ContainmentProfileRef, Effects, ObjectType};

/// Ranges of the numeric unknown-handling settings, used by the schema and
/// validation.
pub mod limits {
    /// Shortest prompt timeout, in seconds.
    pub const PROMPT_TIMEOUT_MIN: u32 = 10;
    /// Longest prompt timeout, in seconds.
    pub const PROMPT_TIMEOUT_MAX: u32 = 600;
    /// The default prompt timeout, in seconds.
    pub const PROMPT_TIMEOUT_DEFAULT: u32 = 60;
    /// Shortest temporary approval, in days.
    pub const TEMP_APPROVAL_DAYS_MIN: u16 = 1;
    /// Longest temporary approval, in days.
    pub const TEMP_APPROVAL_DAYS_MAX: u16 = 90;
    /// The default temporary approval, in days.
    pub const TEMP_APPROVAL_DAYS_DEFAULT: u16 = 14;
}

use limits::{
    PROMPT_TIMEOUT_DEFAULT, PROMPT_TIMEOUT_MAX, PROMPT_TIMEOUT_MIN, TEMP_APPROVAL_DAYS_DEFAULT,
    TEMP_APPROVAL_DAYS_MAX, TEMP_APPROVAL_DAYS_MIN,
};

/// How an unknown object is handled. The variants are declared from least
/// to most restrictive, so `Ord` is the restrictiveness order.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// Allowed silently. Validation warns, and Essential Eight presets do
    /// not permit it for user profiles or temporary folders.
    Allow,
    /// Allowed, but logged with severity medium and flagged unhandled.
    Detect,
    /// The user is asked (#11). Not for libraries, drivers, objects that a
    /// blocklist matched, or sessions with no interactive user; those get
    /// the prompt's fallback.
    Prompt,
    /// Allowed inside the `restrict_profile` containment profile (#14).
    /// Only for executables, scripts and installers. It fails closed to
    /// `block` when the containment component is not installed.
    Restrict,
    /// Blocked. The default.
    Block,
}

impl Level {
    /// Every level, least restrictive first.
    pub const ALL: [Self; 5] = [
        Self::Allow,
        Self::Detect,
        Self::Prompt,
        Self::Restrict,
        Self::Block,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Detect => "detect",
            Self::Prompt => "prompt",
            Self::Restrict => "restrict",
            Self::Block => "block",
        }
    }

    /// The least an object at this level can end up with: a `prompt` can
    /// end in its `fallback`, which may be weaker. Used to compare
    /// policies, never to decide.
    #[must_use]
    pub fn floor(self, prompt_fallback: Self) -> Self {
        match self {
            Self::Prompt => self.min(prompt_fallback),
            other => other,
        }
    }
}

impl core::fmt::Display for Level {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where an object is, as the agent classifies its normalised path and ACL
/// facts (#4, [`crate::unknown::location`]). One path can be in several
/// classes: a file under `%TEMP%` is also in `user_profile` and
/// `user_writable_other`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LocationClass {
    /// The user's profile: `%USERPROFILE%`, AppData, Downloads, Desktop,
    /// and the shared `%PUBLIC%` profile.
    UserProfile,
    /// Temporary folders: `%TEMP%`, `%WINDIR%\Temp`, and the OS browser and
    /// attachment caches.
    Temp,
    /// Any path a non-administrator can write, or whose ACL facts are not
    /// known.
    UserWritableOther,
    /// The program-files directories.
    ProgramFiles,
    /// The Windows directory.
    Windows,
    /// A fixed drive, outside the classes above.
    OtherFixed,
    /// A removable volume.
    Removable,
    /// A network share or mapped network drive.
    Network,
    /// An optical disc.
    Optical,
    /// An alternate data stream.
    Ads,
}

impl LocationClass {
    /// Every class.
    pub const ALL: [Self; 10] = [
        Self::UserProfile,
        Self::Temp,
        Self::UserWritableOther,
        Self::ProgramFiles,
        Self::Windows,
        Self::OtherFixed,
        Self::Removable,
        Self::Network,
        Self::Optical,
        Self::Ads,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserProfile => "user_profile",
            Self::Temp => "temp",
            Self::UserWritableOther => "user_writable_other",
            Self::ProgramFiles => "program_files",
            Self::Windows => "windows",
            Self::OtherFixed => "other_fixed",
            Self::Removable => "removable",
            Self::Network => "network",
            Self::Optical => "optical",
            Self::Ads => "ads",
        }
    }
}

/// Where an object came from, as the agent determines it (#4).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OriginClass {
    /// Downloaded: a zone marker or a browser-origin tag.
    Internet,
    /// Saved from an email attachment.
    EmailAttachment,
    /// Copied from a removable volume.
    RemovableCopy,
    /// Copied from a network share.
    NetworkShare,
    /// Written by a trusted source (#9). Trust rules normally allow these;
    /// it is listed so that a policy can say what happens when they do not.
    TrustedSource,
    /// Present when the agent took its baseline.
    Preexisting,
    /// Not known. An object with no origin facts has this origin.
    Unknown,
}

impl OriginClass {
    /// Every origin.
    pub const ALL: [Self; 7] = [
        Self::Internet,
        Self::EmailAttachment,
        Self::RemovableCopy,
        Self::NetworkShare,
        Self::TrustedSource,
        Self::Preexisting,
        Self::Unknown,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::EmailAttachment => "email_attachment",
            Self::RemovableCopy => "removable_copy",
            Self::NetworkShare => "network_share",
            Self::TrustedSource => "trusted_source",
            Self::Preexisting => "preexisting",
            Self::Unknown => "unknown",
        }
    }
}

/// An answer the user may give to a prompt.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PromptOption {
    /// Run this once.
    AllowOnce,
    /// Run it, and approve its hash on this device
    /// ([`crate::unknown::LocalApproval`]). The approval is uploaded for
    /// review, and is temporary for objects from the internet, removable
    /// media or a network.
    AllowAlwaysLocal,
    /// Do not run it, and ask an administrator to approve it (#11).
    RequestApproval,
    /// Do not run it.
    Block,
}

/// What the user must do before an answer counts. Ordered from the
/// weakest to the strongest.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Reauth {
    /// Nothing more.
    #[default]
    None,
    /// Enter their password again.
    Password,
    /// Complete multi-factor authentication.
    Mfa,
}

/// Who a device-local approval applies to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    /// Only the user who approved it. The default.
    #[default]
    User,
    /// Every user of the device.
    Device,
}

/// How the `prompt` level asks the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PromptSettings {
    /// The answers offered, each at most once. The default is
    /// `allow_once`, `request_approval` and `block`.
    #[schemars(length(min = 1, max = 4))]
    pub options: Vec<PromptOption>,
    /// The user must give a reason before an answer counts.
    pub require_justification: bool,
    /// What the user must do again before an answer counts.
    pub reauth: Reauth,
    /// How long the prompt waits, in seconds: 10 to 600, default 60.
    #[schemars(range(min = PROMPT_TIMEOUT_MIN, max = PROMPT_TIMEOUT_MAX))]
    pub timeout_secs: u32,
    /// The level applied when the prompt times out, when there is no
    /// interactive session, and for objects that cannot be prompted for.
    /// Any level but `prompt`; the default is `block`.
    pub fallback: Level,
    /// Who an `allow_always_local` approval applies to.
    pub local_approval_scope: ApprovalScope,
    /// How long an `allow_always_local` approval lasts, in days, for an
    /// object from the internet, removable media or a network, or of
    /// unknown origin: 1 to 90, default 14. Other approvals do not expire.
    #[schemars(range(min = TEMP_APPROVAL_DAYS_MIN, max = TEMP_APPROVAL_DAYS_MAX))]
    pub temp_approval_days: u16,
}

impl Default for PromptSettings {
    fn default() -> Self {
        Self {
            options: vec![
                PromptOption::AllowOnce,
                PromptOption::RequestApproval,
                PromptOption::Block,
            ],
            require_justification: false,
            reauth: Reauth::None,
            timeout_secs: PROMPT_TIMEOUT_DEFAULT,
            fallback: Level::Block,
            local_approval_scope: ApprovalScope::User,
            temp_approval_days: TEMP_APPROVAL_DAYS_DEFAULT,
        }
    }
}

impl PromptSettings {
    /// Whether every setting has its default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// The stricter combination of two layers' prompt settings: see
    /// [`UnknownPolicy::stricter`]. The timeout is the nearer layer's
    /// (`self`).
    #[must_use]
    pub fn stricter(&self, other: &Self) -> Self {
        let mut options: Vec<PromptOption> = self
            .options
            .iter()
            .filter(|o| other.options.contains(o))
            .copied()
            .collect();
        if options.is_empty() {
            options.push(PromptOption::Block);
        }
        Self {
            options,
            require_justification: self.require_justification || other.require_justification,
            reauth: self.reauth.max(other.reauth),
            timeout_secs: self.timeout_secs,
            fallback: self.fallback.max(other.fallback),
            local_approval_scope: if self.local_approval_scope == ApprovalScope::User
                || other.local_approval_scope == ApprovalScope::User
            {
                ApprovalScope::User
            } else {
                ApprovalScope::Device
            },
            temp_approval_days: self.temp_approval_days.min(other.temp_approval_days),
        }
    }
}

/// The stricter combination of two layers' effects. A flag that neither
/// side sets stays unset, so it keeps its per-level default and the merge
/// changes nothing for layers that leave effects alone. Where a side sets
/// a flag, it is compared with what the other side would get (a deny's
/// default where it is unset), so a weaker explicit setting cannot undercut
/// the other side's effective `log`, `upload`, `severity` or
/// de-duplication window:
///
/// - `log`: `always` over `sampled` over the rest;
/// - `upload`: the more immediate; `severity`: the higher;
/// - `suppress_duplicates_secs`: the shorter window;
/// - `notify`, with its text and link: the nearer layer's (`a`) choice if
///   it makes one, else the other's, keeping a text only with `custom` and
///   a link only with a notification, so the result is always valid;
/// - tags are joined, up to the limit.
fn stricter_effects(a: &Effects, b: &Effects) -> Effects {
    use super::{ActionKind, LogLevel, Notify, Upload};
    let ra = a.resolve(ActionKind::Deny);
    let rb = b.resolve(ActionKind::Deny);
    let upload_rank = |u: Upload| match u {
        Upload::Immediate => 2,
        Upload::Batched => 1,
        Upload::LocalOnly => 0,
    };
    let log_rank = |l: LogLevel| match l {
        LogLevel::Always => 3,
        LogLevel::Sampled => 2,
        LogLevel::Summary => 1,
        LogLevel::Never => 0,
    };
    // Set only if either side sets it; then the stronger effective value.
    let either = |x: bool, y: bool| x || y;
    let log = either(a.log.is_some(), b.log.is_some()).then(|| {
        if log_rank(ra.log) >= log_rank(rb.log) {
            ra.log
        } else {
            rb.log
        }
    });
    let upload = either(a.upload.is_some(), b.upload.is_some()).then(|| {
        if upload_rank(ra.upload) >= upload_rank(rb.upload) {
            ra.upload
        } else {
            rb.upload
        }
    });
    let severity =
        either(a.severity.is_some(), b.severity.is_some()).then(|| ra.severity.max(rb.severity));
    let suppress_duplicates_secs = either(
        a.suppress_duplicates_secs.is_some(),
        b.suppress_duplicates_secs.is_some(),
    )
    .then(|| ra.suppress_duplicates_secs.min(rb.suppress_duplicates_secs));
    // The notification comes whole from one side.
    let from = if a.notify.is_some() || a.notification_text.is_some() || a.help_url.is_some() {
        a
    } else {
        b
    };
    let shown = from.notify_for(ActionKind::Deny);
    let notification_text = from
        .notification_text
        .clone()
        .filter(|_| shown == Notify::Custom);
    let help_url = from.help_url.clone().filter(|_| shown != Notify::None);
    let mut tags = a.tags.clone();
    for t in &b.tags {
        if !tags.contains(t) && tags.len() < super::limits::MAX_TAGS {
            tags.push(t.clone());
        }
    }
    Effects {
        log,
        upload,
        notify: from.notify,
        notification_text,
        help_url,
        severity,
        tags,
        suppress_duplicates_secs,
    }
}

/// What happens to files that were on the device when the agent was
/// installed (origin `preexisting`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreexistingPolicy {
    /// They are unknown like any other object.
    TreatAsUnknown,
    /// The agent approves each one locally at install (#69). The engine
    /// then sees the approvals as rules, and treats a file without one as
    /// unknown.
    LocalApprove,
    /// They run only if the approved baseline (#5) allows them: at stage 6
    /// they are blocked, whatever the levels say. The default.
    #[default]
    BaselineOnly,
}

/// How unknown drivers are handled while the device boots, before the agent
/// has fully started (`boot_phase: early`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriverBootPolicy {
    /// Report what would be blocked, and block nothing. The default, until
    /// the tenant enables enforcement explicitly.
    #[default]
    Audit,
    /// Apply the unknown-handling level.
    Enforce,
}

/// A compliance preset: a named starting configuration. Changes that make
/// the policy weaker than its preset raise a compliance warning (#17).
/// Ordered from the least to the most demanding.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CompliancePreset {
    /// Essential Eight maturity level 1: block in user profiles, temporary
    /// folders and other user-writable locations, detect elsewhere
    /// (ISM-1870).
    E8Ml1,
    /// Essential Eight maturity level 2: block in every location
    /// (ISM-1871).
    E8Ml2,
    /// Essential Eight maturity level 3: level 2, drivers blocked, and a
    /// mandatory blocklist required (ISM-1658). Drivers loaded during early
    /// boot are only audited unless `driver_boot_policy` is `enforce`;
    /// validation warns about that exemption.
    E8Ml3,
}

impl CompliancePreset {
    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::E8Ml1 => "e8_ml1",
            Self::E8Ml2 => "e8_ml2",
            Self::E8Ml3 => "e8_ml3",
        }
    }
}

/// The unknown-application policy (#39). Every field is optional in a
/// document; the defaults block every unknown object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UnknownPolicy {
    /// The compliance preset this policy started from, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<CompliancePreset>,
    /// The level when no entry below applies. The default is `block`.
    pub default: Level,
    /// The level per location class.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = location_keys)]
    pub by_location: BTreeMap<LocationClass, Level>,
    /// The level per origin.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = origin_keys)]
    pub by_origin: BTreeMap<OriginClass, Level>,
    /// The level per object type. `restrict` only for executables, scripts
    /// and installers; `prompt` not for libraries or drivers.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(deserialize_with = "unique_keys")]
    #[schemars(transform = object_type_keys)]
    pub by_type: BTreeMap<ObjectType, Level>,
    /// The containment profile of the `restrict` level (#14). Required when
    /// any level, or the prompt's fallback, is `restrict`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restrict_profile: Option<ContainmentProfileRef>,
    /// How the `prompt` level asks.
    #[serde(skip_serializing_if = "PromptSettings::is_default")]
    pub prompt: PromptSettings,
    /// Logging, upload, notification, severity and tags of unknown-object
    /// decisions (#34). `log` must be `always` or `sampled`: an unhandled
    /// object is always reported.
    #[serde(skip_serializing_if = "Effects::is_empty")]
    pub effects: Effects,
    /// When an unknown object is blocked, the user may ask for approval (#11).
    pub allow_request: bool,
    /// What happens to files present at install.
    pub preexisting_policy: PreexistingPolicy,
    /// How unknown drivers are handled during early boot.
    pub driver_boot_policy: DriverBootPolicy,
    /// Where these settings apply, besides the policy's `scope` (#38): a
    /// subject in at least one of these scopes, at most 1000. Empty, the
    /// default, means wherever the policy applies. A subject outside it is
    /// decided by the built-in implicit deny ([`crate::unknown`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<crate::scope::Scope>,
    /// Effective policies only (#37): where these settings apply, one
    /// [`ScopeLimit`] per contributing policy, kept as that policy wrote it.
    /// The settings apply to a subject when **any** entry holds; empty, the
    /// default, means no further limit. An effective policy has no
    /// `policy.scope`, so the hierarchy moves each contributing policy's
    /// `scope` and `scopes` here unexpanded
    /// ([`UnknownPolicy::scope_limit_of`]). The size is therefore linear in
    /// contributing policies, at most `MAX_CONTRIBUTING_POLICIES` (in
    /// `hierarchy::limits`) entries, and building an effective policy from valid policies never
    /// fails on it. Validation rejects it in a document it validates as
    /// authored, which writes `policy.scope` and `unknown.scopes` instead.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scope_limits: Vec<ScopeLimit>,
}

/// One contributing policy's limit on where its unknown settings apply, in
/// an effective policy ([`UnknownPolicy::scope_limits`]). It holds when
/// every scope of `all_of` matches and, if `any_of` is not empty, one of
/// its scopes matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeLimit {
    /// The contributing policy's `policy.scope`, if it has one. At most one
    /// scope: the width of an entry is never more than its source policy's,
    /// so the authored limits apply to it unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all_of: Vec<crate::scope::Scope>,
    /// The contributing policy's `unknown.scopes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any_of: Vec<crate::scope::Scope>,
}

impl ScopeLimit {
    /// A canonical form, for de-duplicating limits without comparing them
    /// pairwise: the limit's JSON, with object keys sorted.
    #[must_use]
    pub fn canonical(&self) -> String {
        serde_json::to_value(self)
            .map(|v| v.to_string())
            .unwrap_or_default()
    }

    /// How many scope values the limit holds.
    #[must_use]
    pub fn size(&self) -> usize {
        self.all_of.len() + self.any_of.len()
    }
}

impl Default for UnknownPolicy {
    fn default() -> Self {
        Self {
            preset: None,
            default: Level::Block,
            by_location: BTreeMap::new(),
            by_origin: BTreeMap::new(),
            by_type: BTreeMap::new(),
            restrict_profile: None,
            prompt: PromptSettings::default(),
            effects: Effects::default(),
            allow_request: false,
            preexisting_policy: PreexistingPolicy::BaselineOnly,
            driver_boot_policy: DriverBootPolicy::Audit,
            scopes: Vec::new(),
            scope_limits: Vec::new(),
        }
    }
}

impl UnknownPolicy {
    /// Whether every field has its default.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// The configuration a compliance preset sets, tagged with the preset.
    /// Every other field has its default.
    ///
    /// - `e8_ml1`: `default: detect`, and `block` for `user_profile`,
    ///   `temp` and `user_writable_other`.
    /// - `e8_ml2`: `default: block`.
    /// - `e8_ml3`: `default: block`, and `block` for `driver`. Validation
    ///   also requires a mandatory blocklist. Early-boot drivers are
    ///   exempt: `driver_boot_policy` stays `audit`, so a driver the device
    ///   loads before the agent has fully started is reported, not
    ///   blocked, because blocking an unrecognised boot-start driver can
    ///   leave the device unable to boot (ADR 0018). Validation warns
    ///   (`compliance_weakened`) while the exemption is in place; set
    ///   `driver_boot_policy: enforce` to close it.
    #[must_use]
    pub fn preset(preset: CompliancePreset) -> Self {
        let mut p = Self {
            preset: Some(preset),
            ..Self::default()
        };
        match preset {
            CompliancePreset::E8Ml1 => {
                p.default = Level::Detect;
                for class in [
                    LocationClass::UserProfile,
                    LocationClass::Temp,
                    LocationClass::UserWritableOther,
                ] {
                    p.by_location.insert(class, Level::Block);
                }
            }
            CompliancePreset::E8Ml2 => {}
            CompliancePreset::E8Ml3 => {
                p.by_type.insert(ObjectType::Driver, Level::Block);
            }
        }
        p
    }

    /// The strictest combination of `self` and `other`, for building an
    /// effective policy from several layers (#37).
    ///
    /// The goal is the **applied** level: in every context (object type,
    /// location classes, origins, whether the session is interactive,
    /// whether containment is available, whether a blocklist rule
    /// matched), the merged policy applies a level at least as strict as
    /// the level each side applies there with its own prompt fallback and
    /// containment profile, and the prompt's timeout ends no weaker. A
    /// level is compared as stage 6 applies it ([`crate::unknown`]): a
    /// prompt that cannot be shown is its side's fallback, and a `restrict`
    /// that cannot contain is `block`.
    ///
    /// One policy cannot always reproduce the strictest of two exactly, so
    /// where it cannot, the merged policy is the stricter. Three cases, all
    /// failing closed:
    ///
    /// - The prompt fallback is one setting for the whole policy, so it is
    ///   the strictest fallback of the sides that prompt anywhere, and at
    ///   least `detect` if the merged policy prompts and either side
    ///   detects anywhere.
    /// - Where a side prompts and falls back to `block`, a merged `restrict`
    ///   becomes `block` unless that side's own entry there is `restrict`
    ///   or stricter: the side blocks wherever no prompt can be shown, and
    ///   a `restrict` there would let the object run. Whether a prompt can
    ///   be shown depends on the session, which a static merge cannot see,
    ///   so the `restrict` becomes `block` everywhere, including where the
    ///   prompt could have been shown: with A `{default: allow}` and B
    ///   `{default: restrict, by_origin: {internet: prompt}, prompt.fallback:
    ///   block}`, an internet script in a console session is blocked,
    ///   though A allows it and B would ask. A merge that carries a
    ///   condition per entry would be exact.
    /// - Entries are merged key by key: an entry only one side sets is
    ///   compared with the other side's `default`, even for an object that
    ///   another entry of that side decides. So when one side matches an
    ///   object by one dimension and the other side by another, the merge
    ///   can block what each side alone only detects. With A `{default:
    ///   block, by_type: {executable: detect}}` and B `{default: detect,
    ///   by_location: {temp: detect}}`, each detects an executable in
    ///   `temp`, but the merged `temp` entry is `block` (B's `detect` against
    ///   A's `block` default), so the merged policy blocks it. Expressing
    ///   each side's decision exactly would need entries keyed by type,
    ///   location and origin together.
    ///
    /// How each part merges:
    ///
    /// - `default` and each entry: the more restrictive level, after each
    ///   side's levels are replaced with what that side applies wherever
    ///   the context does not matter (an entry only one side sets is
    ///   compared with the other side's `default`). So a `prompt` for a
    ///   library or driver counts as that side's own fallback, a `restrict`
    ///   for a type that cannot be contained, or without a containment
    ///   profile, as `block`, and a `prompt` fallback as `block`. No
    ///   assumption is made that an unusable level ends in `block`;
    /// - the prompt: only the answers both sides offer (or `block`), a
    ///   justification if either asks, the stronger re-authentication, a
    ///   user scope if either uses it, and the shorter temporary approval;
    /// - `allow_request` only if both allow it; the stricter
    ///   `preexisting_policy` and `driver_boot_policy`; the more demanding
    ///   compliance preset; where the settings apply: anywhere either side's
    ///   limit holds, as `scope_limits` (everywhere if either side has no
    ///   limit);
    /// - effects: per flag, the nearer layer's value, except that the
    ///   higher severity and the more immediate upload win, and `always`
    ///   logging is kept; tags are joined.
    ///
    /// What cannot be compared, the containment profile and the prompt's
    /// timeout and notification wording, comes from `self`, the nearer
    /// layer, where it sets one.
    #[must_use]
    pub fn stricter(&self, other: &Self) -> Self {
        let mut out = self
            .without_limits()
            .stricter_settings(&other.without_limits());
        out.scope_limits = match (self.limits(), other.limits()) {
            (Some(mut a), Some(b)) => {
                let mut seen: std::collections::HashSet<String> =
                    a.iter().map(ScopeLimit::canonical).collect();
                for l in b {
                    if seen.insert(l.canonical()) {
                        a.push(l);
                    }
                }
                a
            }
            _ => Vec::new(),
        };
        out
    }

    /// This policy without `scopes` or `scope_limits`.
    #[must_use]
    pub fn without_limits(&self) -> Self {
        Self {
            scopes: Vec::new(),
            scope_limits: Vec::new(),
            ..self.clone()
        }
    }

    /// [`stricter`](Self::stricter) of every part but where the settings
    /// apply: the result has no `scopes` and no `scope_limits`. Its cost
    /// does not grow with either side's limits, so the hierarchy can fold
    /// many policies with it and collect their limits separately.
    #[must_use]
    pub fn stricter_settings(&self, other: &Self) -> Self {
        let (a, b) = (
            self.without_limits().as_applied(),
            other.without_limits().as_applied(),
        );
        let mut out = a.merged(&b);
        let has = |p: &Self, level: Level| p.entry_levels().any(|l| l == level);
        let (a_prompts, b_prompts) = (has(&a, Level::Prompt), has(&b, Level::Prompt));
        // Only a side that prompts somewhere ever applies its fallback.
        out.prompt.fallback = match (a_prompts, b_prompts) {
            (true, false) => a.prompt.fallback,
            (false, true) => b.prompt.fallback,
            _ => a.prompt.fallback.max(b.prompt.fallback),
        };
        // Where the merged policy prompts and no prompt can be shown, the
        // object ends in the merged fallback. A side that does not prompt
        // there gave it a level below `prompt`: `allow` or `detect`, which
        // the fallback must not undercut.
        if has(&out, Level::Prompt) && (has(&a, Level::Detect) || has(&b, Level::Detect)) {
            out.prompt.fallback = out.prompt.fallback.max(Level::Detect);
        }
        // A side that prompts and falls back to `block` blocks wherever no
        // prompt can be shown. A merged `restrict` in such a place would let
        // the object run, so it becomes `block` unless that side's own
        // entry there is `restrict` or stricter: then the side's level
        // there is never a prompt.
        let blocking: Vec<&Self> = [(&a, a_prompts), (&b, b_prompts)]
            .into_iter()
            .filter(|(p, prompts)| *prompts && p.prompt.fallback == Level::Block)
            .map(|(p, _)| p)
            .collect();
        fn raise<K: Ord>(merged: &mut BTreeMap<K, Level>, sides: &[&BTreeMap<K, Level>]) {
            for (k, l) in merged.iter_mut() {
                let covered = sides
                    .iter()
                    .all(|s| s.get(k).is_some_and(|x| *x >= Level::Restrict));
                if *l == Level::Restrict && !covered {
                    *l = Level::Block;
                }
            }
        }
        if !blocking.is_empty() {
            let locations: Vec<_> = blocking.iter().map(|p| &p.by_location).collect();
            raise(&mut out.by_location, &locations);
            let origins: Vec<_> = blocking.iter().map(|p| &p.by_origin).collect();
            raise(&mut out.by_origin, &origins);
            let types: Vec<_> = blocking.iter().map(|p| &p.by_type).collect();
            raise(&mut out.by_type, &types);
            // The default applies only where no entry of either side does,
            // so each side is at its own default there.
            if out.default == Level::Restrict && blocking.iter().any(|p| p.default == Level::Prompt)
            {
                out.default = Level::Block;
            }
        }
        out
    }

    /// The same policy, with every level replaced by what stage 6 applies
    /// for it wherever that does not depend on the context: a `prompt`
    /// fallback is never `prompt` (it blocks), `restrict` without a
    /// containment profile blocks, and each `by_type` level the type cannot
    /// take is what stage 6 applies instead, with this policy's own
    /// fallback. So two of these can be compared level by level.
    fn as_applied(&self) -> Self {
        let mut p = self.clone();
        if p.prompt.fallback == Level::Prompt {
            p.prompt.fallback = Level::Block;
        }
        if p.restrict_profile.is_none() {
            p.prompt.fallback = contained(p.prompt.fallback);
            p.map_levels(contained);
        }
        let fallback = p.prompt.fallback;
        for (t, level) in &mut p.by_type {
            *level = for_type(*t, *level, fallback);
        }
        p
    }

    /// Replaces `default` and every entry's level, not the fallback.
    fn map_levels(&mut self, f: impl Fn(Level) -> Level) {
        self.default = f(self.default);
        for l in self
            .by_location
            .values_mut()
            .chain(self.by_origin.values_mut())
            .chain(self.by_type.values_mut())
        {
            *l = f(*l);
        }
    }

    /// Whether the policy can let an unknown object run: any level but
    /// `block` (a prompt's fallback only applies where a level prompts).
    #[must_use]
    pub fn permits(&self) -> bool {
        self.entry_levels().any(|l| l != Level::Block)
    }

    /// Where these settings apply, as [`scope_limits`](Self::scope_limits),
    /// in an authored policy whose `scope` is `policy_scope`: one limit,
    /// `policy_scope` and any of `scopes`, kept unexpanded. `None` means
    /// everywhere. Each scope is passed through `each`, which the hierarchy
    /// uses to drop options that only act on a deciding rule.
    ///
    /// The policy's own `scope_limits` are not read: they belong to
    /// effective policies, which validation rejects as authored input, so
    /// every contributing policy yields at most one limit, of at most one
    /// `all_of` scope and its own `scopes`. That is what keeps an effective
    /// policy linear in contributing policies, and within the authored
    /// limits per entry.
    #[must_use]
    pub fn scope_limit_of(
        &self,
        policy_scope: Option<&crate::scope::Scope>,
        each: impl Fn(crate::scope::Scope) -> crate::scope::Scope,
    ) -> Option<ScopeLimit> {
        let limit = ScopeLimit {
            all_of: policy_scope.cloned().map(&each).into_iter().collect(),
            any_of: self.scopes.iter().cloned().map(&each).collect(),
        };
        (!limit.all_of.is_empty() || !limit.any_of.is_empty()).then_some(limit)
    }

    /// Where these settings apply, as alternatives: this policy's
    /// `scope_limits` if it has any (an effective policy), else its own
    /// `scopes` as one limit. `None` means everywhere.
    fn limits(&self) -> Option<Vec<ScopeLimit>> {
        if self.scope_limits.is_empty() {
            self.scope_limit_of(None, |s| s).map(|l| vec![l])
        } else {
            Some(self.scope_limits.clone())
        }
    }

    /// `default` and every entry's level, without the prompt's fallback.
    fn entry_levels(&self) -> impl Iterator<Item = Level> + '_ {
        core::iter::once(self.default)
            .chain(self.by_location.values().copied())
            .chain(self.by_origin.values().copied())
            .chain(self.by_type.values().copied())
    }

    /// The level-by-level merge of two policies that are each
    /// [`as_applied`](Self::as_applied).
    fn merged(&self, other: &Self) -> Self {
        fn merge<K: Ord + Copy>(
            a: &BTreeMap<K, Level>,
            a_default: Level,
            b: &BTreeMap<K, Level>,
            b_default: Level,
        ) -> BTreeMap<K, Level> {
            let mut out = BTreeMap::new();
            for k in a.keys().chain(b.keys()) {
                let left = a.get(k).copied().unwrap_or(a_default);
                let right = b.get(k).copied().unwrap_or(b_default);
                out.insert(*k, left.max(right));
            }
            out
        }
        let default = self.default.max(other.default);
        Self {
            preset: self.preset.max(other.preset),
            default,
            by_location: merge(
                &self.by_location,
                self.default,
                &other.by_location,
                other.default,
            ),
            by_origin: merge(
                &self.by_origin,
                self.default,
                &other.by_origin,
                other.default,
            ),
            // A side without an entry for the type gives it its default,
            // as that side applies it to the type.
            by_type: {
                let mut out = BTreeMap::new();
                for t in self.by_type.keys().chain(other.by_type.keys()) {
                    let side = |p: &Self| {
                        p.by_type
                            .get(t)
                            .copied()
                            .unwrap_or_else(|| for_type(*t, p.default, p.prompt.fallback))
                    };
                    out.insert(*t, side(self).max(side(other)));
                }
                out
            },
            restrict_profile: self.restrict_profile.or(other.restrict_profile),
            prompt: self.prompt.stricter(&other.prompt),
            effects: stricter_effects(&self.effects, &other.effects),
            allow_request: self.allow_request && other.allow_request,
            preexisting_policy: if self.preexisting_policy == PreexistingPolicy::BaselineOnly
                || other.preexisting_policy == PreexistingPolicy::BaselineOnly
            {
                PreexistingPolicy::BaselineOnly
            } else if self.preexisting_policy == PreexistingPolicy::LocalApprove
                || other.preexisting_policy == PreexistingPolicy::LocalApprove
            {
                PreexistingPolicy::LocalApprove
            } else {
                PreexistingPolicy::TreatAsUnknown
            },
            driver_boot_policy: if self.driver_boot_policy == DriverBootPolicy::Enforce
                || other.driver_boot_policy == DriverBootPolicy::Enforce
            {
                DriverBootPolicy::Enforce
            } else {
                DriverBootPolicy::Audit
            },
            // Where the settings apply is merged by `stricter`.
            scopes: Vec::new(),
            scope_limits: Vec::new(),
        }
    }

    /// Every level the policy sets: `default`, each entry and the prompt's
    /// fallback.
    pub fn levels(&self) -> impl Iterator<Item = Level> + '_ {
        core::iter::once(self.default)
            .chain(self.by_location.values().copied())
            .chain(self.by_origin.values().copied())
            .chain(self.by_type.values().copied())
            .chain(core::iter::once(self.prompt.fallback))
    }
}

/// `restrict` without a containment profile: stage 6 blocks.
fn contained(level: Level) -> Level {
    if level == Level::Restrict {
        Level::Block
    } else {
        level
    }
}

/// What stage 6 applies to an object of type `t` at `level`, as far as the
/// type alone decides: a type that cannot be prompted for gets `fallback`,
/// and a type that cannot be contained is blocked.
fn for_type(t: ObjectType, level: Level, fallback: Level) -> Level {
    let level = match level {
        Level::Prompt if !crate::unknown::prompt_valid_for(t) => fallback,
        other => other,
    };
    match level {
        Level::Restrict if !crate::unknown::restrict_valid_for(t) => Level::Block,
        Level::Prompt if !crate::unknown::prompt_valid_for(t) => Level::Block,
        other => other,
    }
}

/// The schema of `by_location` keys.
fn location_keys(schema: &mut schemars::Schema) {
    let names: Vec<&str> = LocationClass::ALL.iter().map(|c| c.as_str()).collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}

/// The schema of `by_origin` keys.
fn origin_keys(schema: &mut schemars::Schema) {
    let names: Vec<&str> = OriginClass::ALL.iter().map(|c| c.as_str()).collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}

/// The schema of `by_type` keys.
fn object_type_keys(schema: &mut schemars::Schema) {
    let names: Vec<String> = ObjectType::ALL.iter().map(ToString::to_string).collect();
    schema.insert(
        "propertyNames".to_owned(),
        serde_json::json!({ "enum": names }),
    );
}
