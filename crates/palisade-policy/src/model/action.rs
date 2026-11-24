//! Rule actions and their options (#34).
//!
//! An [`Action`] says what a matching rule asks the engine to do. It is a
//! closed set: every action is an object with a `type`, and the options of
//! that action as optional keys. The directives that some actions carry
//! (containment, elevation, trust source) are references and settings that
//! the engine passes through unchanged; their meaning belongs to the
//! epics that own them (#9, #12, #14).
//!
//! The directive types are typed and strict, like the rest of the model, so
//! a misspelt option is an error rather than a silently ignored key. The
//! owning epics add options as optional fields in a minor schema version.
//!
//! [`ActionKind::valid_for_object_type`] and
//! [`ActionKind::valid_in_rule_set`] are the static validity matrix that
//! validation applies.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ObjectType, RuleSetKind};
use palisade_core::Uuid7;

/// Defines a reference to an object that another epic owns, by its ID.
macro_rules! reference {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
            JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid7);

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

reference!(
    /// The ID of an approval request template (#11).
    RequestTemplateRef
);
reference!(
    /// The ID of a containment profile (#14, #173).
    ContainmentProfileRef
);
reference!(
    /// The ID of an access token profile for elevation (#12, #150).
    TokenProfileRef
);

/// Limits on action options, enforced by validation.
pub mod limits {
    /// Most entries in a trust source's `scope_paths`.
    pub const MAX_SCOPE_PATHS: usize = 32;
    /// Longest scope path, in UTF-8 bytes.
    pub const MAX_SCOPE_PATH_BYTES: usize = 1024;
    /// Longest elevation reason prompt, in Unicode scalar values.
    pub const MAX_REASON_PROMPT_CHARS: usize = 256;
}

/// The action of a rule (#34).
///
/// Each action is an object with a `type`, and its options as optional
/// keys, so options can be added later without a breaking change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Permit execution.
    Allow {},
    /// Block execution.
    Deny(DenyOptions),
    /// Record the match without changing the outcome. A non-terminal
    /// annotation, used for detection and tagging.
    Audit {},
    /// Permit execution inside a containment profile (#14). The engine only
    /// carries the reference.
    AllowContained(ContainmentDirective),
    /// Permit execution with an elevated token (#12). The engine only
    /// carries the directive.
    AllowElevated(ElevationDirective),
    /// Mark the matching process as a trusted installer, updater or source
    /// (#9, #114). This does not permit the process itself to run; an allow
    /// rule decides that. The engine returns the directive.
    TrustSource(TrustSourceDirective),
    /// Skip the object entirely: no decision is logged. Only for performance
    /// exclusions, never for executables or drivers, and validation always
    /// warns.
    Ignore {},
    /// No opinion. A first-match model continues with the next rule (#35).
    Defer {},
}

impl Action {
    /// A deny with default options.
    #[must_use]
    pub fn deny() -> Self {
        Self::Deny(DenyOptions::default())
    }

    /// Which action this is, without its options.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::Allow {} => ActionKind::Allow,
            Self::Deny(_) => ActionKind::Deny,
            Self::Audit {} => ActionKind::Audit,
            Self::AllowContained(_) => ActionKind::AllowContained,
            Self::AllowElevated(_) => ActionKind::AllowElevated,
            Self::TrustSource(_) => ActionKind::TrustSource,
            Self::Ignore {} => ActionKind::Ignore,
            Self::Defer {} => ActionKind::Defer,
        }
    }
}

/// The options of a `deny` action.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DenyOptions {
    /// Terminate already-running instances that match when the policy is
    /// applied. Not valid for drivers or libraries.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub kill_running: bool,
    /// The end user may raise an approval request (#11). Needs a
    /// notification, and is not valid in a mandatory rule set.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub allow_request: bool,
    /// The approval request template to use. Only with `allow_request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_template: Option<RequestTemplateRef>,
    /// Whether the rule blocks when its match tree is `Unknown` because a
    /// fact is missing or cannot be trusted (#32, #35). `no_match`, the
    /// default, means an unknown fact does not block; `match` makes the
    /// deny fail closed.
    #[serde(default, skip_serializing_if = "UnknownAs::is_no_match")]
    pub unknown_as: UnknownAs,
    /// Whether a version fact that is not a version counts towards the
    /// rule applying (#32, #35). With `match`, each version criterion on
    /// such a fact is taken in whichever direction makes the deny apply,
    /// also under `not`. The rest of the tree is evaluated as usual.
    /// `no_match`, the default, leaves the criterion `Unknown`, which
    /// `unknown_as` then decides.
    #[serde(default, skip_serializing_if = "UnknownAs::is_no_match")]
    pub on_unparseable: UnknownAs,
}

/// How a deny rule treats a result it cannot decide (#32, #35).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnknownAs {
    /// The rule does not apply. The default.
    #[default]
    NoMatch,
    /// The rule applies, so the deny blocks.
    Match,
}

impl UnknownAs {
    const fn is_no_match(&self) -> bool {
        matches!(self, Self::NoMatch)
    }
}

/// The directive of an `allow_contained` action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainmentDirective {
    /// The containment profile the process runs under.
    pub profile_id: ContainmentProfileRef,
}

/// The directive of an `allow_elevated` action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ElevationDirective {
    /// The access token profile to build the token from.
    pub token_profile: TokenProfileRef,
    /// When to elevate.
    pub condition: ElevationCondition,
    /// If set, the user must give a reason, and this is the prompt shown:
    /// one line of 1 to 256 characters, trimmed, with no control characters
    /// (including tab and line breaks) and no bidirectional formatting
    /// characters, so the prompt cannot be made to read differently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub reason_prompt: Option<String>,
    /// What the user must do to confirm.
    #[serde(default, skip_serializing_if = "ElevationAuth::is_none")]
    pub auth: ElevationAuth,
}

/// When an `allow_elevated` action elevates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElevationCondition {
    /// Every time the object runs.
    Always,
    /// Only when the object asks for administrator rights.
    IfRequired,
}

/// The confirmation an `allow_elevated` action asks for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ElevationAuth {
    /// No confirmation. The default.
    #[default]
    None,
    /// The user authenticates again.
    Reauth,
    /// The user completes a multi-factor challenge.
    Mfa,
}

impl ElevationAuth {
    const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// The directive of a `trust_source` action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustSourceDirective {
    /// Which writes are trusted.
    pub mode: TrustMode,
    /// The folders whose new content becomes trusted: 1 to 32 absolute paths
    /// (`C:\...`, `\\server\share\...`, or a known path variable such as
    /// `%PROGRAMFILES%\...`), each at most 1024 bytes, written with `\`, and
    /// unique (compared as the engine compares paths).
    #[schemars(length(min = 1, max = 32), inner(length(min = 1, max = 1024)))]
    pub scope_paths: Vec<String>,
    /// Tag the files written with a persistent trust claim, so they stay
    /// trusted after the process exits. Off by default.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub tag_output: bool,
}

/// How far trust from a `trust_source` action reaches (#114).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Only files the designated process writes itself.
    Direct,
    /// Files the designated process and all its descendants write.
    Chained,
}

/// Which action a rule has, without its options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// `allow`.
    Allow,
    /// `deny`.
    Deny,
    /// `audit`.
    Audit,
    /// `allow_contained`.
    AllowContained,
    /// `allow_elevated`.
    AllowElevated,
    /// `trust_source`.
    TrustSource,
    /// `ignore`.
    Ignore,
    /// `defer`.
    Defer,
}

impl ActionKind {
    /// Every action, in declaration order.
    pub const ALL: [Self; 8] = [
        Self::Allow,
        Self::Deny,
        Self::Audit,
        Self::AllowContained,
        Self::AllowElevated,
        Self::TrustSource,
        Self::Ignore,
        Self::Defer,
    ];

    /// The `snake_case` name, as written in a document.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
            Self::AllowContained => "allow_contained",
            Self::AllowElevated => "allow_elevated",
            Self::TrustSource => "trust_source",
            Self::Ignore => "ignore",
            Self::Defer => "defer",
        }
    }

    /// The option keys this action accepts, besides `type`.
    #[must_use]
    pub const fn option_keys(self) -> &'static [&'static str] {
        match self {
            Self::Deny => &[
                "kill_running",
                "allow_request",
                "request_template",
                "unknown_as",
                "on_unparseable",
            ],
            Self::AllowContained => &["profile_id"],
            Self::AllowElevated => &["token_profile", "condition", "reason_prompt", "auth"],
            Self::TrustSource => &["mode", "scope_paths", "tag_output"],
            Self::Allow | Self::Audit | Self::Ignore | Self::Defer => &[],
        }
    }

    /// Whether a matching rule with this action decides the outcome.
    ///
    /// `audit` rules are collected as annotations and `defer` rules have no
    /// opinion. A `trust_source` rule only attaches its directive: whether
    /// the process may run is decided by another rule (#114). How the
    /// terminal rules are combined is #35.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Audit | Self::Defer | Self::TrustSource)
    }

    /// Whether the action lets the object run when it decides.
    #[must_use]
    pub const fn permits(self) -> bool {
        matches!(
            self,
            Self::Allow | Self::AllowContained | Self::AllowElevated
        )
    }

    /// Whether a rule with this action must identify the object (the
    /// identity-anchor and weak-hash checks, ADR 0008): every action that
    /// lets an object run, trusts it, or excludes it. A deny, an audit or
    /// a defer only narrows or observes, so it may match broadly.
    #[must_use]
    pub const fn needs_identity(self) -> bool {
        self.permits() || matches!(self, Self::TrustSource | Self::Ignore)
    }

    /// Whether the action may apply to an object type. Part of the static
    /// validity matrix.
    ///
    /// - `allow_elevated`: executables, installers, scripts and control
    ///   panel applets only. Only those start a process that can be given a
    ///   token.
    /// - `allow_contained`: not drivers or libraries. A driver runs in the
    ///   kernel, and a library runs inside its host process, so neither can
    ///   be contained on its own.
    /// - `trust_source`: executables and installers only, the processes
    ///   that install and update software.
    /// - `ignore`: not executables or drivers. Whether a path is
    ///   user-writable is only known at evaluation (#54), so an exclusion
    ///   for code that starts a process or runs in the kernel is never
    ///   accepted.
    /// - Every other action applies to every type. Deny's `kill_running`
    ///   option is checked by [`kill_running_valid_for`](Self::kill_running_valid_for).
    #[must_use]
    pub const fn valid_for_object_type(self, object_type: ObjectType) -> bool {
        use ObjectType as T;
        match self {
            Self::AllowElevated => matches!(
                object_type,
                T::Executable | T::Installer | T::Script(_) | T::ControlPanelApplet
            ),
            Self::AllowContained => !matches!(object_type, T::Driver | T::Library),
            Self::TrustSource => matches!(object_type, T::Executable | T::Installer),
            Self::Ignore => !matches!(object_type, T::Executable | T::Driver),
            Self::Allow | Self::Deny | Self::Audit | Self::Defer => true,
        }
    }

    /// Whether deny's `kill_running` option may apply to an object type. A
    /// driver or a library is not a process of its own, so there is nothing
    /// to terminate.
    #[must_use]
    pub const fn kill_running_valid_for(object_type: ObjectType) -> bool {
        !matches!(object_type, ObjectType::Driver | ObjectType::Library)
    }

    /// Whether the action may appear in a rule set of this kind. Part of the
    /// static validity matrix. `audit` and `defer` are valid everywhere;
    /// `mixed` accepts every action. A mandatory rule set must also deny
    /// (ADR 0004).
    #[must_use]
    pub const fn valid_in_rule_set(self, kind: RuleSetKind) -> bool {
        use RuleSetKind as K;
        match self {
            Self::Audit | Self::Defer => true,
            Self::Allow => matches!(kind, K::Allowlist | K::Baseline | K::Mixed),
            Self::Deny => matches!(kind, K::Blocklist | K::Mixed),
            Self::AllowContained => matches!(kind, K::Allowlist | K::Containment | K::Mixed),
            Self::AllowElevated => matches!(kind, K::Elevation | K::Mixed),
            Self::TrustSource => matches!(kind, K::Trust | K::Mixed),
            Self::Ignore => matches!(kind, K::Mixed),
        }
    }
}

impl core::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads an [`Action`] key by key, as a derived struct reader does.
///
/// The derived reader for an internally tagged enum buffers the whole map
/// before it looks at the keys. That accepts a sequence (`["deny"]`, read as
/// its first item), takes the tag by variant index (`type: 1` as `deny`),
/// and reports an unknown key only after the map is read, without that
/// key's location. This reader checks each key as it reads it: a key that
/// no action has, or one that the action named by an earlier `type` does
/// not have, is reported at the key. A key that comes before `type` and
/// turns out not to belong to the action is reported at the action.
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(de::ActionVisitor)
    }
}

mod de {
    use core::fmt;

    use serde::Deserialize;
    use serde::de::{self, DeserializeSeed, MapAccess, Visitor};

    use super::{
        Action, ActionKind, ContainmentDirective, ContainmentProfileRef, DenyOptions,
        ElevationAuth, ElevationCondition, ElevationDirective, RequestTemplateRef, TokenProfileRef,
        TrustMode, TrustSourceDirective, UnknownAs,
    };

    /// Every key any action has.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Key {
        Type,
        KillRunning,
        AllowRequest,
        RequestTemplate,
        ProfileId,
        TokenProfile,
        Condition,
        ReasonPrompt,
        Auth,
        Mode,
        ScopePaths,
        TagOutput,
        UnknownAs,
        OnUnparseable,
    }

    const KEYS: [(&str, Key); 14] = [
        ("type", Key::Type),
        ("kill_running", Key::KillRunning),
        ("allow_request", Key::AllowRequest),
        ("request_template", Key::RequestTemplate),
        ("profile_id", Key::ProfileId),
        ("token_profile", Key::TokenProfile),
        ("condition", Key::Condition),
        ("reason_prompt", Key::ReasonPrompt),
        ("auth", Key::Auth),
        ("mode", Key::Mode),
        ("scope_paths", Key::ScopePaths),
        ("tag_output", Key::TagOutput),
        ("unknown_as", Key::UnknownAs),
        ("on_unparseable", Key::OnUnparseable),
    ];

    const KEY_NAMES: [&str; 14] = [
        "type",
        "kill_running",
        "allow_request",
        "request_template",
        "profile_id",
        "token_profile",
        "condition",
        "reason_prompt",
        "auth",
        "mode",
        "scope_paths",
        "tag_output",
        "unknown_as",
        "on_unparseable",
    ];

    impl Key {
        fn name(self) -> &'static str {
            KEYS.iter()
                .find(|(_, k)| *k == self)
                .map_or("?", |(name, _)| name)
        }

        fn belongs_to(self, kind: ActionKind) -> bool {
            self == Self::Type || kind.option_keys().contains(&self.name())
        }
    }

    /// Reads a key, and rejects it at once if the action is already known
    /// and does not have it.
    struct KeySeed(Option<ActionKind>);

    impl<'de> DeserializeSeed<'de> for KeySeed {
        type Value = Key;

        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Key, D::Error> {
            d.deserialize_identifier(self)
        }
    }

    impl Visitor<'_> for KeySeed {
        type Value = Key;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an action key")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Key, E> {
            let key = KEYS
                .iter()
                .find(|(name, _)| *name == v)
                .map(|(_, k)| *k)
                .ok_or_else(|| E::unknown_field(v, &KEY_NAMES))?;
            match self.0 {
                Some(kind) if !key.belongs_to(kind) => Err(unknown_for(v, kind)),
                _ => Ok(key),
            }
        }
    }

    fn unknown_for<E: de::Error>(key: &str, kind: ActionKind) -> E {
        let options = kind.option_keys();
        if options.is_empty() {
            E::custom(format_args!(
                "unknown field `{key}`: action `{kind}` takes no options"
            ))
        } else {
            E::custom(format_args!(
                "unknown field `{key}` for action `{kind}`, expected one of {}",
                options
                    .iter()
                    .map(|o| format!("`{o}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        }
    }

    /// The action name. Read only from a string: serde's derived
    /// identifiers also accept an integer as a variant index.
    struct Kind(ActionKind);

    impl<'de> Deserialize<'de> for Kind {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Name;
            impl Visitor<'_> for Name {
                type Value = Kind;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("the name of an action")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Kind, E> {
                    const NAMES: [&str; 8] = [
                        "allow",
                        "deny",
                        "audit",
                        "allow_contained",
                        "allow_elevated",
                        "trust_source",
                        "ignore",
                        "defer",
                    ];
                    ActionKind::ALL
                        .into_iter()
                        .find(|k| k.as_str() == v)
                        .map(Kind)
                        .ok_or_else(|| E::unknown_variant(v, &NAMES))
                }
            }
            d.deserialize_str(Name)
        }
    }

    /// Every option read so far.
    #[derive(Default)]
    struct Options {
        kill_running: Option<bool>,
        allow_request: Option<bool>,
        request_template: Option<RequestTemplateRef>,
        profile_id: Option<ContainmentProfileRef>,
        token_profile: Option<TokenProfileRef>,
        condition: Option<ElevationCondition>,
        reason_prompt: Option<String>,
        auth: Option<ElevationAuth>,
        mode: Option<TrustMode>,
        scope_paths: Option<Vec<String>>,
        tag_output: Option<bool>,
        unknown_as: Option<UnknownAs>,
        on_unparseable: Option<UnknownAs>,
    }

    /// Reads the value of a key that has no default into its slot.
    fn read<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
        map: &mut A,
        slot: &mut Option<T>,
    ) -> Result<(), A::Error> {
        *slot = Some(map.next_value()?);
        Ok(())
    }

    /// Reads the value of an optional key, where `null` means unset, as it
    /// does for the derived readers and in the schema.
    fn read_nullable<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
        map: &mut A,
        slot: &mut Option<T>,
    ) -> Result<(), A::Error> {
        *slot = map.next_value()?;
        Ok(())
    }

    fn required<T, E: de::Error>(value: Option<T>, key: &'static str) -> Result<T, E> {
        value.ok_or_else(|| E::missing_field(key))
    }

    pub(super) struct ActionVisitor;

    impl<'de> Visitor<'de> for ActionVisitor {
        type Value = Action;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map with a `type` key naming the action")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Action, A::Error> {
            let mut kind: Option<ActionKind> = None;
            let mut seen: Vec<Key> = Vec::new();
            let mut o = Options::default();
            while let Some(key) = map.next_key_seed(KeySeed(kind))? {
                if seen.contains(&key) {
                    return Err(de::Error::duplicate_field(key.name()));
                }
                seen.push(key);
                let m = &mut map;
                match key {
                    Key::Type => kind = Some(m.next_value::<Kind>()?.0),
                    Key::KillRunning => read(m, &mut o.kill_running)?,
                    Key::AllowRequest => read(m, &mut o.allow_request)?,
                    Key::RequestTemplate => read_nullable(m, &mut o.request_template)?,
                    Key::ProfileId => read(m, &mut o.profile_id)?,
                    Key::TokenProfile => read(m, &mut o.token_profile)?,
                    Key::Condition => read(m, &mut o.condition)?,
                    Key::ReasonPrompt => read_nullable(m, &mut o.reason_prompt)?,
                    Key::Auth => read(m, &mut o.auth)?,
                    Key::Mode => read(m, &mut o.mode)?,
                    Key::ScopePaths => read(m, &mut o.scope_paths)?,
                    Key::TagOutput => read(m, &mut o.tag_output)?,
                    Key::UnknownAs => read(m, &mut o.unknown_as)?,
                    Key::OnUnparseable => read(m, &mut o.on_unparseable)?,
                }
            }
            let kind = kind.ok_or_else(|| de::Error::missing_field("type"))?;
            // Keys read before `type` could not be checked as they came.
            if let Some(key) = seen.iter().find(|k| !k.belongs_to(kind)) {
                return Err(unknown_for(key.name(), kind));
            }
            Ok(match kind {
                ActionKind::Allow => Action::Allow {},
                ActionKind::Audit => Action::Audit {},
                ActionKind::Ignore => Action::Ignore {},
                ActionKind::Defer => Action::Defer {},
                ActionKind::Deny => Action::Deny(DenyOptions {
                    kill_running: o.kill_running.unwrap_or_default(),
                    allow_request: o.allow_request.unwrap_or_default(),
                    request_template: o.request_template,
                    unknown_as: o.unknown_as.unwrap_or_default(),
                    on_unparseable: o.on_unparseable.unwrap_or_default(),
                }),
                ActionKind::AllowContained => Action::AllowContained(ContainmentDirective {
                    profile_id: required(o.profile_id, "profile_id")?,
                }),
                ActionKind::AllowElevated => Action::AllowElevated(ElevationDirective {
                    token_profile: required(o.token_profile, "token_profile")?,
                    condition: required(o.condition, "condition")?,
                    reason_prompt: o.reason_prompt,
                    auth: o.auth.unwrap_or_default(),
                }),
                ActionKind::TrustSource => Action::TrustSource(TrustSourceDirective {
                    mode: required(o.mode, "mode")?,
                    scope_paths: required(o.scope_paths, "scope_paths")?,
                    tag_output: o.tag_output.unwrap_or_default(),
                }),
            })
        }
    }
}

#[cfg(test)]
mod tests;
