//! Unknown and unhandled applications: stage 6 of the pipeline (#39).
//!
//! When no rule decides, the policy's [`UnknownPolicy`] does. Stage 6 runs
//! only after stages 1 to 5 decided nothing, so it can never override an
//! explicit deny or allow. The default configuration blocks every unknown
//! object, which is the implicit deny of #35 and ADR 0004.
//!
//! # Level
//!
//! The level is the most restrictive of the entries that apply to the
//! object ([`resolve_level`]): its type's `by_type` entry, the `by_location`
//! entry of each location class it is in, and the `by_origin` entry of each
//! origin. `default` applies only when no entry does. The location classes
//! come from [`ObjectFacts::location_class`], or, when the agent did not
//! set them, from the path ([`location::classify`]). The origins come from
//! [`ObjectFacts::origin`].
//!
//! # Missing facts never make an object look safer
//!
//! Each location class and origin is three-valued: the facts establish it
//! (`Match`), rule it out (`NoMatch`), or a missing fact could make it true
//! (`Unknown`). The level above is resolved from the `Match` classes and
//! applied; then each `Unknown` class's entry (or `default` where it has
//! none) is applied too, and the most restrictive applied level wins, with
//! [`FallbackReason::MissingFact`]. Removing a fact can only turn a class
//! `Unknown`, so it never lowers the level (ADR 0018). The decision lists
//! the `Unknown` classes and the missing facts ([`UnknownHandling`]), and the
//! explanation names them. [`location`] says what makes a location class
//! `Unknown`.
//!
//! Origins: when the agent's origin collection did not report
//! ([`ObjectFacts::origin`] is `None`), the origin is `unknown`, and every
//! other origin is `Unknown`, so the strictest matching `by_origin` entry
//! applies. Under the default `preexisting_policy: baseline_only`, the
//! `preexisting` origin then blocks: **an agent that sends no origin facts
//! gets every unknown object blocked in enforce mode** (in `audit`,
//! `monitor` and `learning` it shows as would-block), and `missing_facts`
//! names `origin`. A reported set is complete; an empty one means no
//! evidence was found, which is exactly `{unknown}`.
//!
//! # What each level decides
//!
//! | Level | Outcome | Reason | Action | Directives |
//! |---|---|---|---|---|
//! | `block` | `blocked` | `implicit_deny_unknown` | `deny` | `request` if `allow_request` |
//! | `restrict` | `allowed` | `unknown_restricted` | `allow_contained` | `containment` |
//! | `prompt` | `pending_user` | `unknown_prompt` | `deny` | `prompt` |
//! | `detect` | `allowed` | `unknown_detected` | `allow` | none |
//! | `allow` | `allowed` | `unknown_allowed` | `allow` | none |
//!
//! Every stage-6 decision is *unhandled* ([`Decision::unhandled`]) and
//! carries an [`UnknownHandling`] that says which entries applied and why a
//! fallback was taken. The policy's `unknown.effects` apply to every level.
//! A field left unset takes the level's default: `block` and `prompt` take
//! a deny's defaults, except that `prompt` shows no notification (the
//! prompt is the notification). `restrict` and `detect` log every
//! decision at once with severity medium. `allow` takes an allow's
//! defaults, so it is silent.
//!
//! # Fallbacks, all closed
//!
//! Some levels cannot apply. Each case is recorded in
//! [`UnknownHandling::fallback`]:
//!
//! - `prompt` is never offered for an object that a blocklist rule matched
//!   (a deny, or any rule of a `blocklist` rule set, including one that a
//!   non-enforcing mode set aside), for a library or a driver, or when the
//!   session has no interactive user ([`SessionContext`](crate::context::SessionContext):
//!   only `console` and `rdp` sessions of a user who is not the system
//!   account are interactive). Those use the prompt's `fallback`.
//! - `restrict` needs the containment component
//!   ([`DeviceContext::containment_available`](crate::context::DeviceContext::containment_available)).
//!   If it is not known to be installed, or the object's type cannot be
//!   contained, the object is blocked with `restrict_unavailable`.
//! - With `preexisting_policy: baseline_only` (the default), an object
//!   whose origin is `preexisting` is blocked: only the approved baseline,
//!   whose rules decide at stage 4, lets it run.
//!
//! # Modes
//!
//! Stage 6 decides as enforce mode sees it. [`Evaluator::evaluate_in`]
//! relaxes a `blocked` or `pending_user` result in a mode that does not
//! enforce, as it relaxes the implicit deny (#36): no prompt is shown in
//! `audit`, `monitor` or `learning`. In `learning`, every object stage 6
//! decides is a learning candidate, whatever its level. An object that a
//! deny rule would block never is.
//!
//! A driver loaded during early boot ([`BootPhase::Early`]) follows
//! `driver_boot_policy`: with `audit`, the default, stage 6 only reports
//! what it would block. Explicit rules still apply.
//!
//! # Palisade's own images
//!
//! [`Evaluator::with_self_images`] pins the agent's own binaries by hash
//! and signer. A pinned image is allowed right after stage 1, whatever
//! the tenant's ordinary rules say. The mandatory tier still runs first
//! (ADR 0004), so [`PolicyDocument::validate_with_self_images`] rejects
//! every deny that could match one ([`selfpin`]).
//!
//! [`Evaluator::evaluate_in`]: crate::evaluate::Evaluator::evaluate_in
//! [`Evaluator::with_self_images`]: crate::evaluate::Evaluator::with_self_images
//! [`PolicyDocument::validate_with_self_images`]: crate::model::PolicyDocument::validate_with_self_images

pub mod baseline;
pub mod location;
pub mod selfpin;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;

use crate::context::{BootPhase, EvaluationContext, SessionType};
use crate::decision::{
    Containment, Decision, Directives, Outcome, ReasonCode, RequestDirective, TraceId,
};
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{
    ActionKind, ApprovalScope, DriverBootPolicy, Effects, EventSeverity, Field, Level,
    LocationClass, LogLevel, Notify, ObjectType, OriginClass, PreexistingPolicy, PromptOption,
    Reauth, UnknownPolicy, Upload,
};
use crate::ops::Tri;
use crate::scope::{Bias, CompiledScope, ScopeLevel, ScopeNotes, eval_chain};

pub use baseline::{SystemBaseline, system_baseline};
pub use location::{Classified, VolumeKind, classify};
pub use selfpin::SelfImage;

/// Which kind of entry of an [`UnknownPolicy`] applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// `default`: no other entry applied.
    Default,
    /// A `by_type` entry.
    Type,
    /// A `by_location` entry.
    Location,
    /// A `by_origin` entry.
    Origin,
}

/// One entry that applied to the object, for the decision trace (#41).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct AppliedEntry {
    /// Which map the entry is in.
    pub kind: EntryKind,
    /// The key: an object type, location class or origin name. `default`
    /// for the default.
    pub key: String,
    /// The entry's level.
    pub level: Level,
    /// The entry belongs to a class a missing fact left `Unknown`, and it
    /// made the decision stricter: the object might not be in that class
    /// ([`FallbackReason::MissingFact`]). `false` for an entry of a class the
    /// facts establish.
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub possible: bool,
}

/// Why stage 6 did not apply the level it resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    /// A blocklist rule matched the object, so it cannot be prompted for.
    Blocklisted,
    /// Libraries and drivers cannot be prompted for.
    NotPromptableType,
    /// The session has no interactive user to ask.
    NonInteractive,
    /// The object's type cannot be contained.
    RestrictNotValidForType,
    /// The containment component is not known to be installed.
    RestrictUnavailable,
    /// The object was present at install, and only the baseline may allow
    /// it (`preexisting_policy: baseline_only`).
    PreexistingBaselineOnly,
    /// The subject is outside the policy's `scope` (or, in an effective
    /// policy, outside every contributing policy's scope), or a fact the
    /// scope needs is unknown. The policy's unknown settings do not apply,
    /// so the built-in implicit deny decides (#38).
    PolicyOutOfScope,
    /// A fact stage 6 needed was missing, so a location or origin class it
    /// could not rule out applied, and the object got a stricter level than
    /// the classes it is known to be in would give it. The facts are in
    /// [`UnknownHandling::missing_facts`].
    MissingFact,
}

/// A fact whose absence left a location or origin class `Unknown` (#39).
/// A missing fact never makes an object look safer: stage 6 applies the
/// level of every class it cannot rule out ([`UnknownHandling`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingFact {
    /// The object's path, or a usable (drive or UNC, fully expanded) path.
    Path,
    /// The kind of volume the file is on ([`crate::facts::PathFact::volume`]).
    VolumeKind,
    /// Whether a non-administrator can write the file
    /// ([`crate::facts::PathFact::user_writable`]). Without it,
    /// `user_writable_other` is `Unknown`.
    UserWritable,
    /// `%WINDIR%`.
    Windir,
    /// `%PROGRAMFILES%`.
    ProgramFiles,
    /// `%USERPROFILE%`.
    UserProfile,
    /// `%APPDATA%`.
    AppData,
    /// `%LOCALAPPDATA%`.
    LocalAppData,
    /// `%PUBLIC%`.
    Public,
    /// `%TEMP%`.
    Temp,
    /// Where the object came from ([`ObjectFacts::origin`]).
    Origin,
}

impl MissingFact {
    /// The missing fact of an unset path variable the classifier reads.
    #[must_use]
    pub const fn variable(v: crate::facts::PathVariable) -> Option<Self> {
        use crate::facts::PathVariable as V;
        Some(match v {
            V::Windir => Self::Windir,
            V::ProgramFiles => Self::ProgramFiles,
            V::UserProfile => Self::UserProfile,
            V::AppData => Self::AppData,
            V::LocalAppData => Self::LocalAppData,
            V::Public => Self::Public,
            V::Temp => Self::Temp,
            V::System32 | V::ProgramData | V::OsDrive => return None,
        })
    }

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::VolumeKind => "volume_kind",
            Self::UserWritable => "user_writable",
            Self::Windir => "windir",
            Self::ProgramFiles => "program_files",
            Self::UserProfile => "user_profile",
            Self::AppData => "app_data",
            Self::LocalAppData => "local_app_data",
            Self::Public => "public",
            Self::Temp => "temp",
            Self::Origin => "origin",
        }
    }
}

/// What the facts say about each class of one kind (location or origin):
/// `Match` (the facts establish it), `NoMatch` (they rule it out) or
/// `Unknown` (a missing fact could make it true), with the crate's Kleene
/// logic ([`Tri`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Classes<K: Ord + Copy> {
    map: BTreeMap<K, Tri>,
}

impl<K: Ord + Copy> Classes<K> {
    /// `f` of every class in `all`.
    #[must_use]
    pub fn new(all: &[K], f: impl Fn(K) -> Tri) -> Self {
        Self {
            map: all.iter().map(|k| (*k, f(*k))).collect(),
        }
    }

    /// The classes the facts establish: those in `set`, and none of the
    /// others.
    #[must_use]
    pub fn certain(all: &[K], set: &BTreeSet<K>) -> Self {
        Self::new(all, |k| Tri::from_bool(set.contains(&k)))
    }

    /// What the facts say about `k`. A class not listed is `NoMatch`.
    #[must_use]
    pub fn get(&self, k: K) -> Tri {
        self.map.get(&k).copied().unwrap_or(Tri::NoMatch)
    }

    /// The classes that are `Match`.
    #[must_use]
    pub fn matching(&self) -> BTreeSet<K> {
        self.with(Tri::Match)
    }

    /// The classes that are `Unknown`.
    #[must_use]
    pub fn unknown(&self) -> BTreeSet<K> {
        self.with(Tri::Unknown)
    }

    fn with(&self, t: Tri) -> BTreeSet<K> {
        self.map
            .iter()
            .filter(|(_, v)| **v == t)
            .map(|(k, _)| *k)
            .collect()
    }
}

/// How stage 6 handled an object, carried by its [`Decision`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct UnknownHandling {
    /// The level the entries resolved to.
    pub resolved: Level,
    /// The level applied, after any fallback.
    pub applied: Level,
    /// Why the applied level differs from the resolved one, if it does.
    pub fallback: Option<FallbackReason>,
    /// The entries that applied, sorted. Only `default` when none did.
    pub entries: Vec<AppliedEntry>,
    /// The location classes the facts establish, sorted.
    pub locations: Vec<LocationClass>,
    /// The origins the facts establish, sorted.
    pub origins: Vec<OriginClass>,
    /// The location classes a missing fact left `Unknown`, sorted. Each
    /// one's entry, or `default` if it has none, was applied too.
    pub unknown_locations: Vec<LocationClass>,
    /// The origins a missing fact left `Unknown`, sorted, applied the same
    /// way.
    pub unknown_origins: Vec<OriginClass>,
    /// The facts that were missing, sorted. When one of them made the
    /// object stricter, `fallback` is `missing_fact`.
    pub missing_facts: Vec<MissingFact>,
}

/// The level of an object of type `t` in `locations` with `origins`: the
/// most restrictive entry that applies, or `default` when none does. The
/// entries are returned sorted.
#[must_use]
pub fn resolve_level(
    policy: &UnknownPolicy,
    t: ObjectType,
    locations: &BTreeSet<LocationClass>,
    origins: &BTreeSet<OriginClass>,
) -> (Level, Vec<AppliedEntry>) {
    let mut entries = Vec::new();
    if let Some(&level) = policy.by_type.get(&t) {
        entries.push(AppliedEntry {
            kind: EntryKind::Type,
            key: t.to_string(),
            level,
            possible: false,
        });
    }
    for class in locations {
        if let Some(&level) = policy.by_location.get(class) {
            entries.push(AppliedEntry {
                kind: EntryKind::Location,
                key: class.as_str().to_owned(),
                level,
                possible: false,
            });
        }
    }
    for origin in origins {
        if let Some(&level) = policy.by_origin.get(origin) {
            entries.push(AppliedEntry {
                kind: EntryKind::Origin,
                key: origin.as_str().to_owned(),
                level,
                possible: false,
            });
        }
    }
    let Some(level) = entries.iter().map(|e| e.level).max() else {
        return (
            policy.default,
            vec![AppliedEntry {
                kind: EntryKind::Default,
                key: "default".to_owned(),
                level: policy.default,
                possible: false,
            }],
        );
    };
    entries.sort();
    (level, entries)
}

/// The object types `restrict` may contain: executables, scripts and
/// installers.
#[must_use]
pub const fn restrict_valid_for(t: ObjectType) -> bool {
    matches!(
        t,
        ObjectType::Executable | ObjectType::Script(_) | ObjectType::Installer
    )
}

/// The object types a prompt may be shown for: every type but libraries and
/// drivers, which load without a user action to answer.
#[must_use]
pub const fn prompt_valid_for(t: ObjectType) -> bool {
    !matches!(t, ObjectType::Library | ObjectType::Driver)
}

/// Whether the session has an interactive user who can answer a prompt:
/// a `console` or `rdp` session of a user who is not the system account.
/// A session whose type is not known has none.
#[must_use]
pub fn interactive(context: &EvaluationContext) -> bool {
    matches!(
        context.session.session_type,
        Some(SessionType::Console | SessionType::Rdp)
    ) && context.user.is_system != Some(true)
}

/// The origins that make an `allow_always_local` approval temporary:
/// internet, email attachments, removable media and network shares, and
/// an unknown origin.
const TEMPORARY_ORIGINS: [OriginClass; 5] = [
    OriginClass::Internet,
    OriginClass::EmailAttachment,
    OriginClass::RemovableCopy,
    OriginClass::NetworkShare,
    OriginClass::Unknown,
];

/// The locations that make an `allow_always_local` approval temporary.
const TEMPORARY_LOCATIONS: [LocationClass; 3] = [
    LocationClass::Removable,
    LocationClass::Network,
    LocationClass::Optical,
];

/// What happens when a prompt is not answered, or cannot be shown.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PromptFallback {
    /// The level applied.
    pub level: Level,
    /// What happens to the object.
    pub outcome: Outcome,
    /// Why.
    pub reason_code: ReasonCode,
    /// The containment profile, when the fallback is `restrict`.
    pub containment: Option<Containment>,
}

/// The prompt a `pending_user` decision asks the agent to show (#11).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PromptDirective {
    /// The answers offered, in the policy's order. `allow_always_local` is
    /// left out when the object's SHA-256 is not known, because the
    /// approval pins that hash.
    pub options: Vec<PromptOption>,
    /// The user must give a reason.
    pub require_justification: bool,
    /// What the user must do again before an answer counts.
    pub reauth: Reauth,
    /// How long the prompt waits, in seconds.
    pub timeout_secs: u32,
    /// What happens on a timeout, or when the prompt cannot be shown.
    pub fallback: PromptFallback,
    /// Who an `allow_always_local` approval applies to.
    pub local_approval_scope: ApprovalScope,
    /// How long an `allow_always_local` approval lasts, in days, or `null`
    /// if it does not expire. Set for objects from the internet, removable
    /// media or a network, or of unknown origin.
    pub temp_approval_days: Option<u16>,
    /// The object's SHA-256, lowercase hex, if known: what an approval pins.
    pub sha256: Option<String>,
}

/// Where a policy's unknown settings apply (#38): its `scope`, its
/// `unknown.scopes` and its `unknown.scope_limits`, compiled. The settings
/// apply to a subject only when the `scope` is `Match`, one of `scopes` is
/// `Match` (if there are any), and one limit holds (if there are any): all
/// of its `all_of` and, if it has any, one of its `any_of`. Facts are read so that the settings apply less,
/// and an `Unknown` result counts as out of scope, so a missing fact never
/// lets the settings allow what the built-in implicit deny would block.
#[derive(Debug, Default)]
pub(crate) struct UnknownScope {
    policy: Option<Arc<CompiledScope>>,
    any_of: Vec<Arc<CompiledScope>>,
    limits: Vec<CompiledLimit>,
}

/// One compiled [`ScopeLimit`](crate::model::ScopeLimit): `all_of`, then
/// `any_of`.
pub(crate) type CompiledLimit = (Vec<Arc<CompiledScope>>, Vec<Arc<CompiledScope>>);

impl UnknownScope {
    /// The compiled policy `scope`, `unknown.scopes` and
    /// `unknown.scope_limits`.
    pub(crate) const fn new(
        policy: Option<Arc<CompiledScope>>,
        any_of: Vec<Arc<CompiledScope>>,
        limits: Vec<CompiledLimit>,
    ) -> Self {
        Self {
            policy,
            any_of,
            limits,
        }
    }

    /// Whether the settings apply in `context`, and what the scopes noticed.
    fn applies(&self, context: &EvaluationContext) -> (bool, ScopeNotes) {
        let eval = |s: &Arc<CompiledScope>| {
            eval_chain(
                &[(ScopeLevel::Policy, Arc::clone(s))],
                context,
                Bias::Permissive,
            )
        };
        let mut notes = ScopeNotes::default();
        let mut result = Tri::Match;
        if let Some(s) = &self.policy {
            let e = eval(s);
            notes.extend(e.notes);
            result = result.and(e.result);
        }
        if !self.any_of.is_empty() {
            let mut any = Tri::NoMatch;
            for s in &self.any_of {
                let e = eval(s);
                notes.extend(e.notes);
                any = any.or(e.result);
            }
            result = result.and(any);
        }
        if !self.limits.is_empty() {
            let mut any = Tri::NoMatch;
            for (all_of, any_of) in &self.limits {
                let mut holds = Tri::Match;
                for s in all_of {
                    let e = eval(s);
                    notes.extend(e.notes);
                    holds = holds.and(e.result);
                }
                if !any_of.is_empty() {
                    let mut one = Tri::NoMatch;
                    for s in any_of {
                        let e = eval(s);
                        notes.extend(e.notes);
                        one = one.or(e.result);
                    }
                    holds = holds.and(one);
                }
                any = any.or(holds);
            }
            result = result.and(any);
        }
        (result == Tri::Match, notes)
    }
}

/// What stage 6 needs about one evaluation. The location classes, origins
/// and hash are only computed when stage 6 runs, so an object that a rule
/// decides pays nothing for them.
#[derive(Debug)]
pub(crate) struct StageSix<'a> {
    policy: &'a UnknownPolicy,
    scope: &'a UnknownScope,
    object_type: ObjectType,
    facts: &'a ObjectFacts,
    variables: &'a PathVariables,
    context: &'a EvaluationContext,
    blocklisted: bool,
    /// Early boot, a driver, and `driver_boot_policy: audit`.
    pub(crate) boot_audit: bool,
}

/// The facts stage 6 decides on, computed when it runs.
struct Known<'a> {
    six: &'a StageSix<'a>,
    /// The settings that decide: the policy's, or the built-in default
    /// when the subject is out of the policy's scope.
    policy: &'a UnknownPolicy,
    /// The subject is out of the policy's scope.
    out_of_scope: bool,
    locations: Classes<LocationClass>,
    origins: Classes<OriginClass>,
    missing: BTreeSet<MissingFact>,
    interactive: bool,
    containment: bool,
    sha256: Option<String>,
}

impl<'a> StageSix<'a> {
    /// The inputs of stage 6 for one object. `blocklisted` says whether any
    /// rule that would block it matched.
    pub(crate) fn new(
        policy: &'a UnknownPolicy,
        scope: &'a UnknownScope,
        object_type: ObjectType,
        facts: &'a ObjectFacts,
        variables: &'a PathVariables,
        context: &'a EvaluationContext,
        blocklisted: bool,
    ) -> Self {
        Self {
            policy,
            scope,
            object_type,
            facts,
            variables,
            context,
            blocklisted,
            // From the policy even out of its scope: the built-in default is
            // `audit` too, so the policy's choice is never weaker.
            boot_audit: object_type == ObjectType::Driver
                && context.device.boot_phase == Some(BootPhase::Early)
                && policy.driver_boot_policy == DriverBootPolicy::Audit,
        }
    }

    /// The stage-6 decision, as enforce mode sees it. Out of the policy's
    /// scope, the built-in default decides: the implicit deny.
    pub(crate) fn decide(&self, trace_id: TraceId) -> Decision {
        let (in_scope, notes) = self.scope.applies(self.context);
        if in_scope {
            return self.decide_with(self.policy, false, trace_id);
        }
        let builtin = UnknownPolicy::default();
        self.decide_with(&builtin, true, trace_id)
            .with_scope_notes(notes)
    }

    fn decide_with(
        &self,
        policy: &UnknownPolicy,
        out_of_scope: bool,
        trace_id: TraceId,
    ) -> Decision {
        let facts = self.facts;
        let Classified {
            classes: locations,
            mut missing,
        } = match &facts.location_class {
            // The agent's classes are facts: those, and no others.
            Some(set) if !set.is_empty() => Classified {
                classes: Classes::certain(&LocationClass::ALL, set),
                missing: BTreeSet::new(),
            },
            _ => facts
                .path
                .as_ref()
                .map_or_else(location::unclassified, |p| {
                    classify(p, self.variables, p.volume, &[])
                }),
        };
        let origins = match &facts.origin {
            // Collection ran, and its set is complete.
            Some(set) if !set.is_empty() => Classes::certain(&OriginClass::ALL, set),
            // Collection ran and found no evidence: exactly `{unknown}`.
            Some(_) => Classes::certain(&OriginClass::ALL, &BTreeSet::from([OriginClass::Unknown])),
            // Collection did not run or report: the object could have any
            // origin, `unknown` included, so every origin is `Unknown`.
            None => {
                missing.insert(MissingFact::Origin);
                Classes::new(&OriginClass::ALL, |_| Tri::Unknown)
            }
        };
        let sha256 = facts
            .get(Field::HashSha256)
            .and_then(crate::ops::normalize_hex)
            .filter(|h| h.len() == 64);
        Known {
            six: self,
            policy,
            out_of_scope,
            locations,
            origins,
            missing,
            interactive: interactive(self.context),
            containment: self.context.device.containment_available == Some(true),
            sha256,
        }
        .decide(trace_id)
    }
}

impl Known<'_> {
    /// The level applied, the reason for any fallback, and the entries.
    ///
    /// The level is resolved from the classes the facts establish, as
    /// [`resolve_level`] does, and applied ([`Known::applicable`]). Then
    /// every class a missing fact left `Unknown` is applied on its own: its
    /// entry, or `default` if it has none. The most restrictive of all these
    /// applied levels is the one applied. Each is applied before the
    /// maximum is taken, so a `prompt` that a missing fact brings in cannot
    /// undercut, through its fallback, a level the known classes give.
    /// Removing a fact only turns a `Match` or `NoMatch` class into
    /// `Unknown`, which only adds levels to that maximum, so a missing fact
    /// never makes the object look safer (ADR 0018).
    fn levels(&self) -> (Level, Level, Option<FallbackReason>, Vec<AppliedEntry>) {
        let t = self.six.object_type;
        let known_locations = self.locations.matching();
        let known_origins = self.origins.matching();
        // The trace shows what the policy's own entries resolved to, even
        // when the policy does not apply.
        let (resolved, entries) =
            resolve_level(self.six.policy, t, &known_locations, &known_origins);
        if self.out_of_scope {
            // The built-in default, the implicit deny, blocks everything.
            return (
                resolved,
                Level::Block,
                Some(FallbackReason::PolicyOutOfScope),
                entries,
            );
        }
        let baseline_only = self.policy.preexisting_policy == PreexistingPolicy::BaselineOnly;
        let (mut applied, mut fallback) = if baseline_only
            && known_origins.contains(&OriginClass::Preexisting)
            && resolved != Level::Block
        {
            (Level::Block, Some(FallbackReason::PreexistingBaselineOnly))
        } else {
            self.applicable(resolved)
        };
        // Each class a missing fact left `Unknown` is a candidate: its
        // entry, or `default` where it has none.
        let entry = |kind: EntryKind, key: &str, level: Option<Level>| AppliedEntry {
            kind: if level.is_some() {
                kind
            } else {
                EntryKind::Default
            },
            key: if level.is_some() {
                key.to_owned()
            } else {
                "default".to_owned()
            },
            level: level.unwrap_or(self.policy.default),
            possible: true,
        };
        let mut candidates: Vec<AppliedEntry> = self
            .locations
            .unknown()
            .into_iter()
            .map(|c| {
                entry(
                    EntryKind::Location,
                    c.as_str(),
                    self.policy.by_location.get(&c).copied(),
                )
            })
            .chain(self.origins.unknown().into_iter().map(|o| {
                entry(
                    EntryKind::Origin,
                    o.as_str(),
                    self.policy.by_origin.get(&o).copied(),
                )
            }))
            .collect();
        // An origin that could be `preexisting` is blocked under
        // `baseline_only`, as a known one is.
        let possibly_preexisting =
            baseline_only && self.origins.get(OriginClass::Preexisting) == Tri::Unknown;
        if possibly_preexisting {
            candidates.push(AppliedEntry {
                kind: EntryKind::Origin,
                key: OriginClass::Preexisting.as_str().to_owned(),
                level: Level::Block,
                possible: true,
            });
        }
        // The level the facts alone give; a candidate changes the decision
        // only if it applies a stricter one.
        let definite = applied;
        let mut decisive: Vec<(AppliedEntry, Option<FallbackReason>)> = Vec::new();
        for c in candidates {
            let (candidate, reason) = self.applicable(c.level);
            if candidate > definite {
                if candidate > applied {
                    applied = candidate;
                    decisive.clear();
                }
                if candidate == applied {
                    decisive.push((c, reason));
                }
            }
        }
        if applied > definite {
            // A possible `restrict` that cannot contain keeps its own reason,
            // so the decision says why it blocked; the missing facts are in
            // `missing_facts`.
            fallback = decisive
                .iter()
                .find_map(|(_, r)| match r {
                    Some(
                        r @ (FallbackReason::RestrictUnavailable
                        | FallbackReason::RestrictNotValidForType),
                    ) => Some(*r),
                    _ => None,
                })
                .filter(|_| decisive.iter().all(|(c, _)| c.level == Level::Restrict))
                .or(Some(FallbackReason::MissingFact));
        }
        let mut entries = entries;
        for (e, _) in decisive {
            if !entries.contains(&e) {
                entries.push(e);
            }
        }
        entries.sort();
        (resolved, applied, fallback, entries)
    }

    /// `level`, or the level that replaces it when it cannot apply.
    fn applicable(&self, level: Level) -> (Level, Option<FallbackReason>) {
        match level {
            Level::Prompt => {
                let reason = if self.six.blocklisted {
                    Some(FallbackReason::Blocklisted)
                } else if !prompt_valid_for(self.six.object_type) {
                    Some(FallbackReason::NotPromptableType)
                } else if !self.interactive {
                    Some(FallbackReason::NonInteractive)
                } else {
                    None
                };
                match reason {
                    None => (Level::Prompt, None),
                    Some(reason) => {
                        // Validation keeps `prompt` out of the fallback; if
                        // it is there anyway, it blocks.
                        let fallback = match self.policy.prompt.fallback {
                            Level::Prompt => Level::Block,
                            other => other,
                        };
                        let (applied, second) = self.applicable(fallback);
                        (applied, second.or(Some(reason)))
                    }
                }
            }
            Level::Restrict if !restrict_valid_for(self.six.object_type) => {
                (Level::Block, Some(FallbackReason::RestrictNotValidForType))
            }
            Level::Restrict if !self.containment || self.policy.restrict_profile.is_none() => {
                (Level::Block, Some(FallbackReason::RestrictUnavailable))
            }
            other => (other, None),
        }
    }

    fn decide(&self, trace_id: TraceId) -> Decision {
        let (resolved, applied, fallback, entries) = self.levels();
        let handling = UnknownHandling {
            resolved,
            applied,
            fallback,
            entries,
            locations: self.locations.matching().into_iter().collect(),
            origins: self.origins.matching().into_iter().collect(),
            unknown_locations: self.locations.unknown().into_iter().collect(),
            unknown_origins: self.origins.unknown().into_iter().collect(),
            missing_facts: self.missing.iter().copied().collect(),
        };
        let restrict_unavailable = matches!(
            fallback,
            Some(FallbackReason::RestrictUnavailable | FallbackReason::RestrictNotValidForType)
        );
        let (outcome, action, reason) = self.shape(applied, restrict_unavailable);
        let effects = self.effects(applied);
        let mut directives = Directives::default();
        match applied {
            Level::Block => {
                if self.policy.allow_request && effects.notify != Notify::None {
                    directives.request = Some(RequestDirective { template: None });
                }
            }
            Level::Restrict => {
                directives.containment = self
                    .six
                    .policy
                    .restrict_profile
                    .map(|profile_id| Containment { profile_id });
            }
            Level::Prompt => directives.prompt = Some(self.prompt_directive()),
            Level::Detect | Level::Allow => {}
        }
        Decision::unknown_handling(
            outcome, action, directives, effects, reason, handling, trace_id,
        )
    }

    /// The outcome, action and reason of an applied level.
    const fn shape(
        &self,
        applied: Level,
        restrict_unavailable: bool,
    ) -> (Outcome, ActionKind, ReasonCode) {
        match applied {
            Level::Block if restrict_unavailable => (
                Outcome::Blocked,
                ActionKind::Deny,
                ReasonCode::RestrictUnavailable,
            ),
            Level::Block => (
                Outcome::Blocked,
                ActionKind::Deny,
                ReasonCode::ImplicitDenyUnknown,
            ),
            Level::Restrict => (
                Outcome::Allowed,
                ActionKind::AllowContained,
                ReasonCode::UnknownRestricted,
            ),
            Level::Prompt => (
                Outcome::PendingUser,
                ActionKind::Deny,
                ReasonCode::UnknownPrompt,
            ),
            Level::Detect => (
                Outcome::Allowed,
                ActionKind::Allow,
                ReasonCode::UnknownDetected,
            ),
            Level::Allow => (
                Outcome::Allowed,
                ActionKind::Allow,
                ReasonCode::UnknownAllowed,
            ),
        }
    }

    /// The policy's effects, with the level's defaults for unset fields.
    /// A decision that shows no notification carries no notification text
    /// or link either.
    fn effects(&self, applied: Level) -> crate::model::ResolvedEffects {
        let mut e: Effects = self.policy.effects.clone();
        let kind = match applied {
            Level::Block | Level::Prompt => ActionKind::Deny,
            Level::Restrict => ActionKind::AllowContained,
            Level::Detect | Level::Allow => ActionKind::Allow,
        };
        if matches!(applied, Level::Restrict | Level::Detect) {
            e.log.get_or_insert(LogLevel::Always);
            e.upload.get_or_insert(Upload::Immediate);
            e.severity.get_or_insert(EventSeverity::Medium);
        }
        let mut r = e.resolve(kind);
        if applied == Level::Prompt {
            // The prompt is the notification.
            r.notify = Notify::None;
        }
        if r.notify == Notify::None {
            r.notification_text = None;
            r.help_url = None;
        }
        r
    }

    fn prompt_directive(&self) -> PromptDirective {
        let p = &self.policy.prompt;
        let fallback_level = match p.fallback {
            Level::Prompt => Level::Block,
            other => other,
        };
        let (level, reason) = self.applicable(fallback_level);
        let restrict_unavailable = reason.is_some();
        let (outcome, _, reason_code) = self.shape(level, restrict_unavailable);
        let fallback = PromptFallback {
            level,
            outcome,
            reason_code,
            containment: (level == Level::Restrict)
                .then_some(self.policy.restrict_profile)
                .flatten()
                .map(|profile_id| Containment { profile_id }),
        };
        let mut options: Vec<PromptOption> = Vec::new();
        for o in &p.options {
            if (*o != PromptOption::AllowAlwaysLocal || self.sha256.is_some())
                && !options.contains(o)
            {
                options.push(*o);
            }
        }
        if options.is_empty() {
            options.push(PromptOption::Block);
        }
        PromptDirective {
            options,
            require_justification: p.require_justification,
            reauth: p.reauth,
            timeout_secs: p.timeout_secs,
            fallback,
            local_approval_scope: p.local_approval_scope,
            temp_approval_days: self.temporary().then_some(p.temp_approval_days),
            sha256: self.sha256.clone(),
        }
    }

    /// Whether an approval of this object is temporary: it is, or could
    /// be, from a temporary origin or in a temporary location.
    fn temporary(&self) -> bool {
        TEMPORARY_ORIGINS
            .iter()
            .any(|o| self.origins.get(*o) != Tri::NoMatch)
            || TEMPORARY_LOCATIONS
                .iter()
                .any(|l| self.locations.get(*l) != Tri::NoMatch)
    }
}

/// The user's answer to a prompt, or why there is none.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PromptAnswer {
    /// The user chose an option.
    Chose {
        /// The option.
        option: PromptOption,
        /// The reason the user gave, if any.
        justification: Option<String>,
        /// Whether the user completed the re-authentication the prompt asks
        /// for.
        reauthenticated: bool,
    },
    /// The prompt timed out.
    TimedOut,
    /// The prompt could not be shown.
    NotShown,
}

/// What the agent does after a prompt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AnswerResult {
    /// What happens to the object.
    pub outcome: Outcome,
    /// Why.
    pub reason_code: ReasonCode,
    /// The containment profile to run it under, if any.
    pub containment: Option<Containment>,
    /// The device-local approval to store and upload for review, for
    /// `allow_always_local`.
    pub approval: Option<LocalApproval>,
    /// Raise an approval request (#11).
    pub request_approval: bool,
}

/// A device-local approval of one exact file, from `allow_always_local`
/// (#39). The agent stores it (#69) and uploads it for review (#10, #11).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct LocalApproval {
    /// The approved file's SHA-256, lowercase hex.
    pub sha256: String,
    /// Who it applies to.
    pub scope: ApprovalScope,
    /// The user it applies to, for scope `user`.
    pub user_sid: Option<String>,
    /// When it was given, in wall-clock seconds since 1970.
    pub approved_at: i64,
    /// When it ends, in wall-clock seconds, or `null` if it does not.
    pub expires_at: Option<i64>,
    /// The reason the user gave.
    pub justification: Option<String>,
    /// The approval is uploaded to the server for review. Always `true`.
    pub upload_for_review: bool,
}

impl LocalApproval {
    /// Whether the approval applies to a file with `sha256`, run by the
    /// user with `user_sid`, at wall-clock time `now`. An approval whose
    /// end is at or before `now` never applies again; the agent keeps the
    /// floor of ADR 0012 so that setting the clock back cannot revive it.
    #[must_use]
    pub fn applies(&self, sha256: &str, user_sid: Option<&str>, now: i64) -> bool {
        let hash = crate::ops::normalize_hex(sha256).filter(|h| h.len() == 64);
        hash.is_some()
            && hash == crate::ops::normalize_hex(&self.sha256)
            && self.expires_at.is_none_or(|end| now < end)
            && match self.scope {
                ApprovalScope::Device => true,
                ApprovalScope::User => {
                    let want = self
                        .user_sid
                        .as_deref()
                        .and_then(crate::context::normalize_sid);
                    want.is_some() && want == user_sid.and_then(crate::context::normalize_sid)
                }
            }
    }
}

/// An answer that does not count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnswerError {
    /// The decision is not a prompt.
    NotAPrompt,
    /// The option was not offered.
    NotOffered,
    /// A reason is required, and none was given.
    JustificationRequired,
    /// The user did not re-authenticate as required.
    ReauthRequired,
    /// A user-scoped approval needs the user's SID.
    UserUnknown,
    /// The approval's end is past the largest representable time.
    TimeOverflow,
    /// The reason is longer than 4096 characters, or holds control or
    /// bidirectional formatting characters other than tab and line breaks.
    InvalidJustification,
}

impl core::fmt::Display for AnswerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotAPrompt => "the decision is not a prompt",
            Self::NotOffered => "the option was not offered",
            Self::JustificationRequired => "a reason is required",
            Self::ReauthRequired => "re-authentication is required",
            Self::UserUnknown => "a user-scoped approval needs the user's SID",
            Self::TimeOverflow => "the approval's end is out of range",
            Self::InvalidJustification => "the reason is too long or holds control characters",
        })
    }
}

impl std::error::Error for AnswerError {}

/// What the user's answer to a `pending_user` decision does.
///
/// `now` is the wall-clock time, in seconds since 1970, on the agent's
/// anchored clock (ADR 0012); `user_sid` is the user who answered. A
/// timeout or a prompt that could not be shown applies the prompt's
/// fallback. An answer that does not count is an error; the agent then
/// applies the fallback too.
///
/// # Errors
///
/// Returns [`AnswerError`] if the decision is not a prompt, or the answer
/// does not satisfy it.
pub fn answer(
    decision: &Decision,
    answer: &PromptAnswer,
    user_sid: Option<&str>,
    now: i64,
) -> Result<AnswerResult, AnswerError> {
    let prompt = decision
        .directives()
        .prompt
        .as_ref()
        .filter(|_| decision.outcome() == Outcome::PendingUser)
        .ok_or(AnswerError::NotAPrompt)?;
    let fallback = || AnswerResult {
        outcome: prompt.fallback.outcome,
        reason_code: prompt.fallback.reason_code,
        containment: prompt.fallback.containment,
        approval: None,
        request_approval: false,
    };
    let PromptAnswer::Chose {
        option,
        justification,
        reauthenticated,
    } = answer
    else {
        return Ok(fallback());
    };
    if !prompt.options.contains(option) {
        return Err(AnswerError::NotOffered);
    }
    let justification = justification
        .as_deref()
        .map(str::trim)
        .filter(|j| !j.is_empty())
        .map(str::to_owned);
    if let Some(j) = &justification
        && (j.chars().count() > crate::model::limits::MAX_TEXT_CHARS
            || j.chars().any(|c| {
                (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
                    || crate::validate::is_bidi_control(c)
            }))
    {
        return Err(AnswerError::InvalidJustification);
    }
    if prompt.require_justification
        && justification.is_none()
        && matches!(
            option,
            PromptOption::AllowOnce
                | PromptOption::AllowAlwaysLocal
                | PromptOption::RequestApproval
        )
    {
        return Err(AnswerError::JustificationRequired);
    }
    if prompt.reauth != Reauth::None && !reauthenticated && *option != PromptOption::Block {
        return Err(AnswerError::ReauthRequired);
    }
    let allowed = |approval| AnswerResult {
        outcome: Outcome::Allowed,
        reason_code: ReasonCode::UnknownPrompt,
        containment: None,
        approval,
        request_approval: false,
    };
    let blocked = |request_approval| AnswerResult {
        outcome: Outcome::Blocked,
        reason_code: ReasonCode::UnknownPrompt,
        containment: None,
        approval: None,
        request_approval,
    };
    Ok(match option {
        PromptOption::AllowOnce => allowed(None),
        PromptOption::Block => blocked(false),
        PromptOption::RequestApproval => blocked(true),
        PromptOption::AllowAlwaysLocal => {
            // Only offered when the hash is known.
            let sha256 = prompt.sha256.clone().ok_or(AnswerError::NotOffered)?;
            let user_sid = match prompt.local_approval_scope {
                ApprovalScope::Device => None,
                ApprovalScope::User => Some(
                    user_sid
                        .and_then(crate::context::normalize_sid)
                        .ok_or(AnswerError::UserUnknown)?,
                ),
            };
            let expires_at = match prompt.temp_approval_days {
                None => None,
                Some(days) => Some(
                    now.checked_add(i64::from(days) * 86_400)
                        .ok_or(AnswerError::TimeOverflow)?,
                ),
            };
            allowed(Some(LocalApproval {
                sha256,
                scope: prompt.local_approval_scope,
                user_sid,
                approved_at: now,
                expires_at,
                justification,
                upload_for_review: true,
            }))
        }
    })
}

#[cfg(test)]
mod previous_classifier;
#[cfg(test)]
mod tests;
