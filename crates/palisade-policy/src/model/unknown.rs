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

/// The stricter combination of two layers' effects: per flag, the nearer
/// layer's (`a`) value where it sets one, except that the higher severity,
/// the more immediate upload and `always` logging win. Tags are joined.
fn stricter_effects(a: &Effects, b: &Effects) -> Effects {
    use super::{LogLevel, Upload};
    let upload_rank = |u: Upload| match u {
        Upload::Immediate => 2,
        Upload::Batched => 1,
        Upload::LocalOnly => 0,
    };
    let pick = |x: Option<Upload>, y: Option<Upload>| match (x, y) {
        (Some(x), Some(y)) => Some(if upload_rank(x) >= upload_rank(y) {
            x
        } else {
            y
        }),
        (x, y) => x.or(y),
    };
    let log = match (a.log, b.log) {
        (Some(LogLevel::Always), _) | (_, Some(LogLevel::Always)) => Some(LogLevel::Always),
        (x, y) => x.or(y),
    };
    let mut tags = a.tags.clone();
    for t in &b.tags {
        if !tags.contains(t) && tags.len() < super::limits::MAX_TAGS {
            tags.push(t.clone());
        }
    }
    Effects {
        log,
        upload: pick(a.upload, b.upload),
        notify: a.notify.or(b.notify),
        notification_text: a
            .notification_text
            .clone()
            .or_else(|| b.notification_text.clone()),
        help_url: a.help_url.clone().or_else(|| b.help_url.clone()),
        severity: a.severity.max(b.severity),
        tags,
        suppress_duplicates_secs: a.suppress_duplicates_secs.or(b.suppress_duplicates_secs),
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
    /// mandatory blocklist required (ISM-1658).
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
    ///   also requires a mandatory blocklist.
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
    /// effective policy from several layers (#37). Every part that can
    /// let an unknown object run takes the more restrictive side, so the
    /// result is never weaker than either side for any object or answer:
    ///
    /// - levels, entries and the prompt fallback: the more restrictive (an
    ///   entry only one side sets is compared with the other side's
    ///   `default`); a level a type cannot take becomes `block`;
    /// - the prompt: only the answers both sides offer (or `block`), a
    ///   justification if either asks, the stronger re-authentication, a
    ///   user scope if either uses it, and the shorter temporary approval;
    /// - `allow_request` only if both allow it; the stricter
    ///   `preexisting_policy` and `driver_boot_policy`; the more demanding
    ///   compliance preset;
    /// - effects: per flag, the nearer layer's value, except that the
    ///   higher severity and the more immediate upload win, and `always`
    ///   logging is kept; tags are joined.
    ///
    /// What cannot be compared, the containment profile and the prompt's
    /// timeout and notification wording, comes from `self`, the nearer
    /// layer, where it sets one.
    #[must_use]
    pub fn stricter(&self, other: &Self) -> Self {
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
            // A level a type cannot take is the block it falls back to
            // anyway (a prompt's fallback can only be weaker, so blocking
            // is at least as strict).
            by_type: merge(&self.by_type, self.default, &other.by_type, other.default)
                .into_iter()
                .map(|(t, l)| {
                    let usable = match l {
                        Level::Prompt => crate::unknown::prompt_valid_for(t),
                        Level::Restrict => crate::unknown::restrict_valid_for(t),
                        _ => true,
                    };
                    (t, if usable { l } else { Level::Block })
                })
                .collect(),
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
