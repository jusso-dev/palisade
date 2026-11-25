//! Rule scoping: who, where and when a rule applies (#38).
//!
//! A [`Scope`] narrows a rule to some users and groups (`principals`),
//! devices (`devices`), network locations (`network`), sessions
//! (`sessions`) and times (`schedule`). Scopes are attached at three levels:
//! a [`Rule`](crate::model::Rule)'s own `scope`, the scopes of a rule set's
//! assignment to the policy ([`RuleSetScope`]), and the policy's `scope`.
//! They **intersect** down the chain: a rule applies only when its match
//! tree matches and every scope on the way to it matches.
//!
//! # Scopes are not match trees
//!
//! The match tree identifies the object; a scope says where that rule is in
//! force. They are kept apart on purpose. A rule's tree must always have a
//! positive identity (#33, the identity-anchor rule), and context criteria
//! never count as one. A scope holds only context (who, where, when), so a
//! "user is in Users and the session is RDP" filter belongs in a scope and
//! never makes a tree valid on its own. A scope is also never part of a
//! rule's specificity (#35): it decides whether a rule is a candidate, and
//! the precedence model then chooses among the candidates as before.
//!
//! # Evaluation
//!
//! A scope evaluates to a [`Tri`], with the Kleene logic of
//! [`crate::condition`]:
//!
//! - Each dimension that is set is an `include` and an `exclude` list. An
//!   empty `include` means everyone or everything. A match in `exclude`
//!   always wins: the dimension is `include AND NOT exclude`.
//! - `combine: all` (the default) is the `AND` of the dimensions that are
//!   set, and `combine: any` their `OR`. A scope with no dimension is
//!   `Match`.
//! - `negate: true` applies the rule when the scope does **not** match.
//!
//! The rule then applies when `scope AND tree` is `Match`, so an out-of-scope
//! rule behaves exactly as if it were absent: it never decides, and it is
//! not listed as overridden. `Unknown` follows the rule's action, as an
//! unknown tree does: an allow, trust source or exclusion never applies
//! (it fails closed), and a deny applies only with `unknown_as: match`.
//! Because a scope is only ever `AND`ed in, it can narrow a rule but never
//! widen it.
//!
//! # Restrictive readings
//!
//! Some facts have two readings, and the engine takes the one that is safer
//! for the rule's action. A rule **permits** when it lets an object run,
//! trusts it or excludes it ([`ActionKind::needs_identity`]); every other
//! rule (`deny`, `audit`) **restricts**. A position in a scope is
//! *positive* when a match there makes the rule apply more: an `include`
//! of a scope without `negate`, or an `exclude` of one with it.
//!
//! - **Deny-only groups.** UAC marks the administrator groups of a filtered
//!   token deny-only. Such a group may be read as membership or as none,
//!   and the scopes of a rule are evaluated both ways. A permitting rule
//!   takes the reading that makes it apply less, and a restricting rule
//!   the one that makes it apply more (`deny_only_group`). So a
//!   non-elevated administrator never gets an administrators-only allow,
//!   is never let off a deny that excludes administrators, and an
//!   administrators-only deny still applies to them. Each reading is
//!   consistent, so an `exclude` that holds the `include` still never
//!   matches.
//! - **Clock integrity.** If the agent's trusted time (#18) is missing or
//!   flagged, or the time zone a schedule needs is unknown, a schedule
//!   reads as whatever keeps a permitting rule inactive and a restricting
//!   rule active, so scheduled allows go inactive and scheduled denies
//!   stay in force (`clock_untrusted`).
//! - **Names.** `user_pattern` matches the `DOMAIN\user` name, which can
//!   be spoofed more easily than a SID. Validation only accepts it in a
//!   position where matching it makes the rules it covers apply less if
//!   they permit, or more if they restrict, so a spoofed name can never
//!   gain anything. That rules it out of allow includes. Audit rules take it anywhere.
//!
//! # Group membership
//!
//! Principals are tested against the subject's access token
//! ([`ScopeFacts::process_token`] by default; see [`ScopeSubject`]). A
//! token's group SIDs already include nested directory groups and local
//! groups, and a membership test is a binary search over them. Cloud-directory groups
//! are not in the token: the agent caches them with `cached_at`. A cached
//! membership older than the policy's `group_cache_max_age_secs` (default
//! 24 hours), cached in the future, or read while the clock is untrusted
//! is `Unknown` (`scope_stale`).
//!
//! # Schedules
//!
//! See [`schedule`]. Windows may wrap midnight, and daylight-saving
//! changes follow one rule (the "compatible" rule of the ECMAScript
//! Temporal proposal): a local time that occurs twice means its first
//! occurrence, and a local time skipped by a change is moved forward by
//! the length of the change.
//!
//! # Facts
//!
//! The facts are in [`EvaluationContext`](crate::context::EvaluationContext):
//! the user, device, session and network context, and the facts only
//! scopes read ([`ScopeFacts`]). As everywhere in this crate, the agent
//! collects them (#4), and a fact that was not collected is unknown.

pub mod facts;
pub mod location;
pub mod model;
pub mod schedule;
pub mod text;

pub(crate) mod compile;

pub(crate) use compile::{Bias, CompiledScope, eval_chain};
pub use facts::{CachedGroups, Gap, Held, LocalGroup, ScopeFacts, Token, TrustedTime};
pub use location::{CompiledProfiles, DEBOUNCE_MS, HEARTBEAT_SECS, LocationTracker};
pub use model::{
    ClientFilter, CloudObject, Combine, Date, DateRange, DeviceRef, DirectoryGroup,
    LocationProfile, NetworkRef, OnWindowClose, OuRef, Pin, PrincipalRef, RefList, RuleSetScope,
    Schedule, Scope, ScopeSubject, SessionFilter, SetRef, TimeOfDay, Weekday, WellKnown, Window,
    limits,
};
pub use schedule::CompiledSchedule;

use serde::Serialize;

use crate::model::ActionKind;
use crate::ops::Tri;

/// The default `group_cache_max_age_secs`: 24 hours.
pub const DEFAULT_GROUP_CACHE_MAX_AGE_SECS: u32 = 86_400;
/// The shortest `group_cache_max_age_secs`: 1 hour.
pub const MIN_GROUP_CACHE_MAX_AGE_SECS: u32 = 3_600;

/// The library sets (#37) scopes may reference. Sets are resolved once,
/// when an [`Evaluator`](crate::evaluate::Evaluator) is built; a reference
/// the library cannot resolve evaluates to `Unknown` (`set_unresolved`).
pub trait ScopeLibrary: core::fmt::Debug + Sync {
    /// The members of a principal set: SIDs and cloud-directory object IDs.
    fn principal_set(&self, set: &SetRef) -> Option<Vec<String>>;
    /// The entries of a network set: address blocks, ranges and DNS
    /// suffixes.
    fn network_set(&self, set: &SetRef) -> Option<Vec<String>>;
    /// A schedule from a schedule set.
    fn schedule_set(&self, set: &SetRef) -> Option<Schedule>;
}

/// Every library set a scope references, with its JSON Pointer relative to
/// the scope and the kind it must be.
#[must_use]
pub fn set_refs(scope: &Scope) -> Vec<(String, SetRef, crate::library::LibraryKind)> {
    use crate::library::LibraryKind as K;
    let mut out = Vec::new();
    if let Some(p) = &scope.principals {
        for (list, entries) in [("include", &p.include), ("exclude", &p.exclude)] {
            for (i, r) in entries.iter().enumerate() {
                if let PrincipalRef::PrincipalSet(s) = r {
                    out.push((
                        format!("/principals/{list}/{i}/principal_set"),
                        *s,
                        K::PrincipalSet,
                    ));
                }
            }
        }
    }
    if let Some(d) = &scope.devices {
        for (list, entries) in [("include", &d.include), ("exclude", &d.exclude)] {
            for (i, r) in entries.iter().enumerate() {
                if let DeviceRef::DeviceSet(s) = r {
                    out.push((format!("/devices/{list}/{i}/device_set"), *s, K::DeviceSet));
                }
            }
        }
    }
    if let Some(n) = &scope.network {
        for (list, entries) in [("include", &n.include), ("exclude", &n.exclude)] {
            for (i, r) in entries.iter().enumerate() {
                if let NetworkRef::NetworkSet(s) = r {
                    out.push((
                        format!("/network/{list}/{i}/network_set"),
                        *s,
                        K::NetworkSet,
                    ));
                }
            }
        }
    }
    if let Some(c) = scope.sessions.as_ref().and_then(|s| s.client.as_ref()) {
        for (i, s) in c.device_sets.iter().enumerate() {
            out.push((
                format!("/sessions/client/device_sets/{i}"),
                *s,
                K::DeviceSet,
            ));
        }
    }
    if let Some(s) = &scope.schedule_set {
        out.push(("/schedule_set".to_owned(), *s, K::ScheduleSet));
    }
    out
}

/// Calls `f` on every library set reference in `scope`, in the order of
/// [`set_refs`].
pub fn for_each_set_ref(scope: &mut Scope, mut f: impl FnMut(&mut SetRef)) {
    if let Some(p) = &mut scope.principals {
        for r in p.include.iter_mut().chain(p.exclude.iter_mut()) {
            if let PrincipalRef::PrincipalSet(s) = r {
                f(s);
            }
        }
    }
    if let Some(d) = &mut scope.devices {
        for r in d.include.iter_mut().chain(d.exclude.iter_mut()) {
            if let DeviceRef::DeviceSet(s) = r {
                f(s);
            }
        }
    }
    if let Some(n) = &mut scope.network {
        for r in n.include.iter_mut().chain(n.exclude.iter_mut()) {
            if let NetworkRef::NetworkSet(s) = r {
                f(s);
            }
        }
    }
    if let Some(c) = scope.sessions.as_mut().and_then(|s| s.client.as_mut()) {
        c.device_sets.iter_mut().for_each(&mut f);
    }
    if let Some(s) = &mut scope.schedule_set {
        f(s);
    }
}

/// Every scope of a policy document, with its JSON Pointer: the policy's,
/// each rule set assignment's, and each rule's.
#[must_use]
pub fn document_scopes(doc: &crate::model::PolicyDocument) -> Vec<(String, &Scope)> {
    let mut out = Vec::new();
    if let Some(s) = &doc.policy.scope {
        out.push(("/policy/scope".to_owned(), s));
    }
    for (i, a) in doc.policy.rule_set_scopes.iter().enumerate() {
        for (j, s) in a.scopes.iter().enumerate() {
            out.push((format!("/policy/rule_set_scopes/{i}/scopes/{j}"), s));
        }
    }
    for (i, set) in doc.rule_sets.iter().enumerate() {
        out.extend(
            rule_set_scopes(set)
                .into_iter()
                .map(|(p, s)| (format!("/rule_sets/{i}{p}"), s)),
        );
    }
    out
}

/// The scopes of a rule set's rules, with JSON Pointers relative to the
/// rule set.
#[must_use]
pub fn rule_set_scopes(set: &crate::model::RuleSet) -> Vec<(String, &Scope)> {
    set.rules
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.scope.as_ref().map(|s| (format!("/rules/{i}/scope"), s)))
        .collect()
}

/// The library catalogue (#37), seen from one tenant or the installation:
/// a set the catalogue does not hold, holds at another version, cannot
/// show from here, or holds as another kind is unresolved.
#[derive(Clone, Copy, Debug)]
pub struct CatalogueLibrary<'c> {
    /// The catalogue.
    pub catalogue: &'c crate::library::Catalogue,
    /// Whose libraries it may use.
    pub from: crate::library::Visibility,
}

impl ScopeLibrary for CatalogueLibrary<'_> {
    fn principal_set(&self, set: &SetRef) -> Option<Vec<String>> {
        match &self.catalogue.resolve(set, self.from).ok()?.content {
            crate::library::LibraryContent::PrincipalSet { principals } => Some(principals.clone()),
            _ => None,
        }
    }

    fn network_set(&self, set: &SetRef) -> Option<Vec<String>> {
        match &self.catalogue.resolve(set, self.from).ok()?.content {
            crate::library::LibraryContent::NetworkSet { entries } => Some(entries.clone()),
            _ => None,
        }
    }

    fn schedule_set(&self, set: &SetRef) -> Option<Schedule> {
        match &self.catalogue.resolve(set, self.from).ok()?.content {
            // A validated set holds exactly one schedule.
            crate::library::LibraryContent::ScheduleSet { entries } if entries.len() == 1 => {
                serde_json::from_str(&entries[0]).ok()
            }
            _ => None,
        }
    }
}

/// Why an entry of a network set (#37) is not an address block, a range
/// or a DNS suffix, if it is not.
#[must_use]
pub fn network_entry_problem(entry: &str) -> Option<String> {
    (text::IpRange::block_or_range(entry).is_err() && text::dns_suffix(entry).is_err())
        .then(|| format!("`{entry}` is not an address block, an address range or a DNS suffix"))
}

/// The largest schedule-set entry, in bytes: room for 64 windows and two
/// lists of 1000 date ranges, with whitespace.
pub const MAX_SCHEDULE_ENTRY_BYTES: usize = 1 << 20;

/// Why an entry of a schedule set (#37) is not a well-formed schedule, if
/// it is not: it must be one schedule written as JSON, with the rules a
/// scope's `schedule` follows, and without `on_window_close`, which
/// belongs to the scope that uses it.
#[must_use]
pub fn schedule_entry_problem(entry: &str) -> Option<String> {
    if entry.len() > MAX_SCHEDULE_ENTRY_BYTES {
        return Some(format!(
            "{} bytes; a schedule entry is at most {MAX_SCHEDULE_ENTRY_BYTES}",
            entry.len()
        ));
    }
    let schedule: Schedule = match serde_json::from_str(entry) {
        Ok(s) => s,
        Err(e) => return Some(format!("not a schedule: {e}")),
    };
    if schedule.on_window_close != OnWindowClose::None || schedule.grace_secs.is_some() {
        return Some(
            "a schedule set cannot set `on_window_close` or `grace_secs`; set them on an inline schedule"
                .to_owned(),
        );
    }
    if CompiledSchedule::compile(&schedule, crate::model::TimeZoneBasis::Utc).is_valid() {
        None
    } else {
        Some("the schedule is not well formed: check its windows (days, start, and one of `end` or `duration_mins`), its date ranges and its limits".to_owned())
    }
}

/// A library that resolves nothing: every set reference is unknown.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoLibrary;

impl ScopeLibrary for NoLibrary {
    fn principal_set(&self, _: &SetRef) -> Option<Vec<String>> {
        None
    }
    fn network_set(&self, _: &SetRef) -> Option<Vec<String>> {
        None
    }
    fn schedule_set(&self, _: &SetRef) -> Option<Schedule> {
        None
    }
}

/// Something worth recording about a scope evaluation. The `snake_case`
/// name is part of the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ScopeNote {
    /// A fact a scope needs was not collected.
    FactMissing = 0,
    /// A fact was not in the form its test needs.
    FactMalformed = 1,
    /// Cached group membership was too old, from the future, or read with
    /// an untrusted clock, so it was unknown.
    ScopeStale = 2,
    /// The trusted time was missing or flagged, or a schedule's time zone
    /// was unknown, so schedules took their restrictive reading.
    ClockUntrusted = 3,
    /// A deny-only group of a filtered token was read restrictively.
    DenyOnlyGroup = 4,
    /// A library set could not be resolved.
    SetUnresolved = 5,
    /// A `user_local` schedule used the device's time zone, because the
    /// session's was not known.
    TimezoneFallback = 6,
    /// An allow's per-session instance limit blocked the object, or could
    /// not be checked.
    InstanceLimit = 7,
}

impl ScopeNote {
    /// Every note, in code order.
    pub const ALL: [Self; 8] = [
        Self::FactMissing,
        Self::FactMalformed,
        Self::ScopeStale,
        Self::ClockUntrusted,
        Self::DenyOnlyGroup,
        Self::SetUnresolved,
        Self::TimezoneFallback,
        Self::InstanceLimit,
    ];

    /// The stable `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FactMissing => "fact_missing",
            Self::FactMalformed => "fact_malformed",
            Self::ScopeStale => "scope_stale",
            Self::ClockUntrusted => "clock_untrusted",
            Self::DenyOnlyGroup => "deny_only_group",
            Self::SetUnresolved => "set_unresolved",
            Self::TimezoneFallback => "timezone_fallback",
            Self::InstanceLimit => "instance_limit",
        }
    }
}

/// A set of [`ScopeNote`]s.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ScopeNotes(u16);

impl ScopeNotes {
    /// Adds a note.
    pub fn insert(&mut self, note: ScopeNote) {
        self.0 |= 1 << (note as u8);
    }

    /// Adds every note in `other`.
    pub fn extend(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Whether the set holds `note`.
    #[must_use]
    pub const fn contains(self, note: ScopeNote) -> bool {
        self.0 & (1 << (note as u8)) != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The notes in the set, in code order.
    pub fn iter(self) -> impl Iterator<Item = ScopeNote> {
        ScopeNote::ALL
            .into_iter()
            .filter(move |n| self.contains(*n))
    }
}

/// Where a scope is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLevel {
    /// The policy's `scope`.
    Policy,
    /// A scope of the rule set's assignment (`rule_set_scopes`).
    RuleSet,
    /// The rule's own `scope`.
    Rule,
}

/// A dimension of a scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    /// `principals`.
    Principals,
    /// `devices`.
    Devices,
    /// `network`.
    Network,
    /// `sessions`.
    Sessions,
    /// `schedule` or `schedule_set`.
    Schedule,
}

/// Which scope did not match, for the decision trace (#41).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct ScopeFailure {
    /// The level of the first scope on the chain that did not match.
    pub level: ScopeLevel,
    /// The dimension that did not match, when one decided alone: a scope
    /// with `combine: all` and no `negate`. Otherwise `None`.
    pub dimension: Option<Dimension>,
}

/// The result of evaluating the scopes of one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeEvaluation {
    /// The three-valued result: the `AND` of every scope on the chain.
    pub result: Tri,
    /// What the evaluation noticed.
    pub notes: ScopeNotes,
    /// Which scope did not match, if the result is `NoMatch`.
    pub failure: Option<ScopeFailure>,
}

impl ScopeEvaluation {
    /// A chain with no scope: `Match`.
    pub const MATCH: Self = Self {
        result: Tri::Match,
        notes: ScopeNotes(0),
        failure: None,
    };
}

/// Truth order: `NoMatch` below `Unknown` below `Match`.
pub(crate) const fn rank(t: Tri) -> u8 {
    match t {
        Tri::NoMatch => 0,
        Tri::Unknown => 1,
        Tri::Match => 2,
    }
}

impl Bias {
    /// The bias of a rule's action: permitting actions read facts
    /// restrictively against themselves.
    #[must_use]
    pub(crate) const fn of(kind: ActionKind) -> Self {
        if kind.needs_identity() {
            Self::Permissive
        } else {
            Self::Restrictive
        }
    }
}

#[cfg(test)]
mod tests;
