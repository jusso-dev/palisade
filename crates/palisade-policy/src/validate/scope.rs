//! Validation of scopes (#38).

use std::collections::{BTreeMap, BTreeSet};

use super::{ErrorCode, Validator};
use crate::context::{normalize_object_id, normalize_sid};
use crate::model::limits::MAX_NAME_CHARS;
use crate::model::{ActionKind, PolicyDocument, RuleSetId};
use crate::scope::limits::{
    MAX_ASSIGNMENT_SCOPES, MAX_DATE_RANGES, MAX_EFFECTIVE_ASSIGNMENT_SCOPES, MAX_GRACE_SECS,
    MAX_LOCATION_PROFILES, MAX_PROFILE_REFS, MAX_SCOPE_ENTRIES, MAX_WINDOWS,
};
use crate::scope::text::{self, IpRange, Wildcard};
use crate::scope::{
    ClientFilter, CloudObject, DateRange, DeviceRef, NetworkRef, OnWindowClose, PrincipalRef,
    RefList, Schedule, Scope,
};

/// What the rules a scope covers do: which positions a name pattern may
/// take, and whether the per-session options apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Covered {
    /// Some covered rule lets an object run, trusts it or excludes it.
    pub(super) permits: bool,
    /// Some covered rule denies.
    pub(super) restricts: bool,
    /// Every covered rule is an allow that decides (`allow`,
    /// `allow_contained`, `allow_elevated`).
    pub(super) only_allows: bool,
}

impl Covered {
    /// The rules of one action.
    pub(super) const fn of(kind: ActionKind) -> Self {
        Self {
            permits: kind.needs_identity(),
            restricts: matches!(kind, ActionKind::Deny),
            only_allows: kind.permits(),
        }
    }

    /// The rules of several actions. With none, the scope covers nothing
    /// yet, so nothing it sets can be misapplied: it is read as covering
    /// only allows, the most restricted reading of `user_pattern` and the
    /// one under which the per-session options are valid. A rule added
    /// later is validated again with the scope.
    pub(super) fn of_all(kinds: impl IntoIterator<Item = ActionKind>) -> Self {
        let mut out = Self {
            permits: false,
            restricts: false,
            only_allows: true,
        };
        let mut any = false;
        for k in kinds {
            any = true;
            let c = Self::of(k);
            out.permits |= c.permits;
            out.restricts |= c.restricts;
            out.only_allows &= c.only_allows;
        }
        if !any {
            out.permits = true;
        }
        out
    }
}

impl Validator {
    /// Checks the policy's scope, the rule set assignment scopes and the
    /// location profiles, and returns the profiles' folded names.
    pub(super) fn policy_scopes(&mut self, doc: &PolicyDocument) -> BTreeSet<String> {
        let policy = &doc.policy;
        let sets: BTreeMap<RuleSetId, &crate::model::RuleSet> =
            doc.rule_sets.iter().map(|s| (s.id, s)).collect();
        let referenced: BTreeSet<RuleSetId> = policy.rule_sets.iter().copied().collect();
        let profiles = self.location_profiles(doc);

        let kinds_of = |ids: &mut dyn Iterator<Item = &RuleSetId>| -> Vec<ActionKind> {
            ids.filter_map(|id| sets.get(id))
                // Disabled rules count too: a suppressed or disabled rule
                // is still in the document, and may be enabled again.
                .flat_map(|s| s.rules.iter())
                .map(|r| r.action.kind())
                .collect()
        };
        if let Some(scope) = &policy.scope {
            let covered = Covered::of_all(kinds_of(&mut policy.rule_sets.iter()));
            self.scope("/policy/scope", scope, covered, &profiles);
        }
        let mut seen = BTreeSet::new();
        for (i, a) in policy.rule_set_scopes.iter().enumerate() {
            let base = format!("/policy/rule_set_scopes/{i}");
            if !referenced.contains(&a.rule_set) {
                self.push(
                    ErrorCode::UnknownRuleSet,
                    &format!("{base}/rule_set"),
                    format!("rule set {} is not referenced by the policy", a.rule_set),
                );
            }
            if !seen.insert(a.rule_set) {
                self.push(
                    ErrorCode::DuplicateRuleSetRef,
                    &format!("{base}/rule_set"),
                    format!(
                        "rule set {} already has an assignment scope; put every scope in one `scopes` list",
                        a.rule_set
                    ),
                );
            }
            let max = if self.compile_values {
                MAX_ASSIGNMENT_SCOPES
            } else {
                MAX_EFFECTIVE_ASSIGNMENT_SCOPES
            };
            if a.scopes.is_empty() || a.scopes.len() > max {
                self.push(
                    ErrorCode::InvalidScope,
                    &format!("{base}/scopes"),
                    format!("{} scopes; from 1 to {max} are allowed", a.scopes.len()),
                );
            }
            let covered = Covered::of_all(kinds_of(&mut core::iter::once(&a.rule_set)));
            for (j, scope) in a.scopes.iter().enumerate() {
                self.scope(&format!("{base}/scopes/{j}"), scope, covered, &profiles);
            }
        }
        profiles
    }

    /// Checks the location profiles and returns their folded names.
    fn location_profiles(&mut self, doc: &PolicyDocument) -> BTreeSet<String> {
        let profiles = &doc.policy.location_profiles;
        let mut names = BTreeSet::new();
        if profiles.len() > MAX_LOCATION_PROFILES {
            self.push(
                ErrorCode::InvalidScope,
                "/policy/location_profiles",
                format!(
                    "{} profiles; at most {MAX_LOCATION_PROFILES} are allowed",
                    profiles.len()
                ),
            );
        }
        for (i, p) in profiles.iter().enumerate() {
            let base = format!("/policy/location_profiles/{i}");
            if !is_profile_name(&p.name) {
                self.push(
                    ErrorCode::InvalidScope,
                    &format!("{base}/name"),
                    "a profile name is 1 to 64 ASCII letters, digits, `_`, `.` or `-`",
                );
            } else if !names.insert(text::group_name(&p.name)) {
                self.push(
                    ErrorCode::DuplicateId,
                    &format!("{base}/name"),
                    format!("location profile `{}` is defined more than once", p.name),
                );
            }
            if p.all.is_empty() || p.all.len() > MAX_PROFILE_REFS {
                self.push(
                    ErrorCode::InvalidScope,
                    &format!("{base}/all"),
                    format!(
                        "{} tests; from 1 to {MAX_PROFILE_REFS} are allowed",
                        p.all.len()
                    ),
                );
            }
            for (j, r) in p.all.iter().enumerate() {
                let path = format!("{base}/all/{j}");
                if matches!(r, NetworkRef::LocationProfile(_)) {
                    self.push(
                        ErrorCode::InvalidScope,
                        &path,
                        "a location profile cannot test another profile",
                    );
                } else {
                    self.network_ref(&path, r, &BTreeSet::new());
                }
            }
        }
        names
    }

    /// Checks one scope. `covered` says what the rules it covers do.
    pub(super) fn scope(
        &mut self,
        base: &str,
        scope: &Scope,
        covered: Covered,
        profiles: &BTreeSet<String>,
    ) {
        if let Some(p) = &scope.principals {
            let path = format!("{base}/principals");
            self.list_len(&path, p);
            // A position is positive when a match there makes the rule
            // apply more.
            for (list, include) in [("include", true), ("exclude", false)] {
                let entries = if include { &p.include } else { &p.exclude };
                let positive = include != scope.negate;
                for (i, r) in entries.iter().enumerate() {
                    let at = format!("{path}/{list}/{i}");
                    self.principal_ref(&at, r);
                    if let PrincipalRef::UserPattern(_) = r {
                        // A spoofed name must never make a permitting rule
                        // apply, nor keep a deny from applying.
                        let widens_permit = covered.permits && positive;
                        let narrows_deny = covered.restricts && !positive;
                        if widens_permit || narrows_deny {
                            self.push(
                                ErrorCode::UserPatternNotAllowed,
                                &at,
                                "account names can be spoofed, so `user_pattern` may only exclude principals from a rule that lets an object run, and only add principals to a deny; use a SID or a group for this position",
                            );
                        }
                    }
                }
            }
        }
        if let Some(d) = &scope.devices {
            let path = format!("{base}/devices");
            self.list_len(&path, d);
            for (list, entries) in [("include", &d.include), ("exclude", &d.exclude)] {
                for (i, r) in entries.iter().enumerate() {
                    self.device_ref(&format!("{path}/{list}/{i}"), r);
                }
            }
        }
        if let Some(n) = &scope.network {
            let path = format!("{base}/network");
            self.list_len(&path, n);
            for (list, entries) in [("include", &n.include), ("exclude", &n.exclude)] {
                for (i, r) in entries.iter().enumerate() {
                    self.network_ref(&format!("{path}/{list}/{i}"), r, profiles);
                }
            }
        }
        if let Some(s) = &scope.sessions {
            let path = format!("{base}/sessions");
            let mut seen = BTreeSet::new();
            for (i, t) in s.types.iter().enumerate() {
                if !seen.insert(t.as_str()) {
                    self.push(
                        ErrorCode::InvalidScope,
                        &format!("{path}/types/{i}"),
                        format!("session type `{}` is listed more than once", t.as_str()),
                    );
                }
            }
            if let Some(c) = &s.client {
                self.client(&format!("{path}/client"), c);
            }
        }
        if scope.schedule.is_some() && scope.schedule_set.is_some() {
            self.push(
                ErrorCode::InvalidScope,
                &format!("{base}/schedule_set"),
                "set `schedule` or `schedule_set`, not both",
            );
        }
        if let Some(s) = &scope.schedule {
            self.schedule(&format!("{base}/schedule"), s, covered);
            // The close of a schedule only ends the rule's match when every
            // dimension must match and the scope is not negated.
            if s.on_window_close != OnWindowClose::None
                && (scope.negate || scope.combine == crate::scope::Combine::Any)
            {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{base}/schedule/on_window_close"),
                    "`on_window_close` needs `combine: all` and no `negate`, so that the rule stops applying when the schedule closes",
                );
            }
        }
        if scope.max_instances_per_session > 0 && !covered.only_allows {
            self.push(
                ErrorCode::InvalidScope,
                &format!("{base}/max_instances_per_session"),
                "an instance limit only applies to rules that allow (`allow`, `allow_contained`, `allow_elevated`)",
            );
        }
        if scope.negate && !scope.has_dimension() {
            self.push(
                ErrorCode::InvalidScope,
                &format!("{base}/negate"),
                "a negated scope with no dimension never matches; remove `negate` or the rule",
            );
        }
    }

    fn list_len<T>(&mut self, path: &str, list: &RefList<T>) {
        for (name, len) in [
            ("include", list.include.len()),
            ("exclude", list.exclude.len()),
        ] {
            if len > MAX_SCOPE_ENTRIES {
                self.push(
                    ErrorCode::InvalidScope,
                    &format!("{path}/{name}"),
                    format!(
                        "{len} entries; at most {MAX_SCOPE_ENTRIES} are allowed, so use a library set (#37) for larger lists"
                    ),
                );
            }
        }
    }

    fn scope_value(&mut self, path: &str, result: Result<(), String>) {
        if let Err(problem) = result {
            self.push(ErrorCode::InvalidScope, path, problem);
        }
    }

    fn principal_ref(&mut self, path: &str, r: &PrincipalRef) {
        let sid = |s: &str, what: &str| {
            normalize_sid(s)
                .map(|_| ())
                .ok_or_else(|| format!("`{s}` is not a {what} SID"))
        };
        let result = match r {
            PrincipalRef::Sid(s) => sid(s, "user or group"),
            PrincipalRef::WellKnown(_) | PrincipalRef::PrincipalSet(_) => Ok(()),
            PrincipalRef::LocalGroup(name) => text::plain(name),
            PrincipalRef::DirectoryGroup(g) => sid(&g.sid, "group").and_then(|()| match &g.name {
                Some(n) if n.chars().count() > MAX_NAME_CHARS => Err(format!(
                    "{} characters; at most {MAX_NAME_CHARS} are allowed",
                    n.chars().count()
                )),
                Some(n) => text::plain(n),
                None => Ok(()),
            }),
            PrincipalRef::CloudGroup(c) => cloud(c),
            PrincipalRef::UserPattern(p) => user_pattern(p),
        };
        self.scope_value(path, result);
    }

    fn device_ref(&mut self, path: &str, r: &DeviceRef) {
        let result = match r {
            DeviceRef::DeviceId(_) | DeviceRef::DeviceSet(_) => Ok(()),
            DeviceRef::HostnamePattern(p) => Wildcard::new(p, false).map(|_| ()),
            DeviceRef::DirectoryComputerGroup(s) => normalize_sid(s)
                .map(|_| ())
                .ok_or_else(|| format!("`{s}` is not a group SID")),
            DeviceRef::CloudDeviceGroup(c) => cloud(c),
            // A policy value: the plain-value rules (length, no control or
            // bidirectional characters, trimmed), then the DN form.
            DeviceRef::Ou(ou) => text::plain(&ou.dn).and_then(|()| {
                text::dn(&ou.dn).map(|_| ()).ok_or_else(|| {
                    format!(
                        "`{}` is not a distinguished name such as `OU=Finance,DC=corp,DC=example`",
                        ou.dn
                    )
                })
            }),
            DeviceRef::Tag(t) => text::plain(t),
        };
        self.scope_value(path, result);
    }

    fn network_ref(&mut self, path: &str, r: &NetworkRef, profiles: &BTreeSet<String>) {
        let result = match r {
            NetworkRef::Cidr(s) => IpRange::cidr(s).map(|_| ()),
            NetworkRef::Range(s) => IpRange::range(s).map(|_| ()),
            NetworkRef::DnsSuffix(s) => text::dns_suffix(s).map(|_| ()),
            NetworkRef::GatewayMac(s) => text::mac(s).map(|_| ()),
            NetworkRef::ServerReachable(_) | NetworkRef::NetworkSet(_) => Ok(()),
            NetworkRef::LocationProfile(name) => {
                if profiles.contains(&text::group_name(name)) {
                    Ok(())
                } else {
                    Err(format!(
                        "location profile `{name}` is not defined in `policy.location_profiles`"
                    ))
                }
            }
        };
        self.scope_value(path, result);
    }

    fn client(&mut self, path: &str, c: &ClientFilter) {
        for (name, len) in [
            ("hostname", c.hostname.len()),
            ("ip", c.ip.len()),
            ("device_sets", c.device_sets.len()),
        ] {
            if len > MAX_SCOPE_ENTRIES {
                self.push(
                    ErrorCode::InvalidScope,
                    &format!("{path}/{name}"),
                    format!("{len} entries; at most {MAX_SCOPE_ENTRIES} are allowed"),
                );
            }
        }
        for (i, p) in c.hostname.iter().enumerate() {
            let r = Wildcard::new(p, false).map(|_| ());
            self.scope_value(&format!("{path}/hostname/{i}"), r);
        }
        for (i, s) in c.ip.iter().enumerate() {
            let r = IpRange::block_or_range(s).map(|_| ());
            self.scope_value(&format!("{path}/ip/{i}"), r);
        }
    }

    fn schedule(&mut self, path: &str, s: &Schedule, covered: Covered) {
        if s.windows.len() > MAX_WINDOWS {
            self.push(
                ErrorCode::InvalidSchedule,
                &format!("{path}/windows"),
                format!(
                    "{} windows; at most {MAX_WINDOWS} are allowed",
                    s.windows.len()
                ),
            );
        }
        for (i, w) in s.windows.iter().enumerate() {
            let at = format!("{path}/windows/{i}");
            let mut days = BTreeSet::new();
            if w.days.is_empty() || w.days.iter().any(|d| !days.insert(*d)) {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{at}/days"),
                    "a window needs at least one day, each listed once",
                );
            }
            if w.start.minutes() >= 1440 {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{at}/start"),
                    "a window starts from 00:00 to 23:59",
                );
            }
            // Days and the start are reported above; this is the length.
            let shape_ok =
                !w.days.is_empty() && days.len() == w.days.len() && w.start.minutes() < 1440;
            if shape_ok && w.minutes().is_none() {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &at,
                    "a window needs exactly one of `end` and `duration_mins`, and lasts from 1 minute to 7 days",
                );
            }
        }
        for (name, ranges) in [("dates", &s.dates), ("except_dates", &s.except_dates)] {
            self.date_ranges(&format!("{path}/{name}"), ranges);
        }
        if s.on_window_close != OnWindowClose::None && !covered.only_allows {
            self.push(
                ErrorCode::InvalidSchedule,
                &format!("{path}/on_window_close"),
                "`on_window_close` only applies to rules that allow (`allow`, `allow_contained`, `allow_elevated`)",
            );
        }
        if let Some(g) = s.grace_secs {
            if s.on_window_close != OnWindowClose::WarnThenTerminate {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{path}/grace_secs"),
                    "`grace_secs` only applies with `on_window_close: warn_then_terminate`",
                );
            } else if g > MAX_GRACE_SECS {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{path}/grace_secs"),
                    format!("{g} seconds; at most {MAX_GRACE_SECS} are allowed"),
                );
            }
        }
    }

    fn date_ranges(&mut self, path: &str, ranges: &[DateRange]) {
        if ranges.len() > MAX_DATE_RANGES {
            self.push(
                ErrorCode::InvalidSchedule,
                path,
                format!(
                    "{} date ranges; at most {MAX_DATE_RANGES} are allowed",
                    ranges.len()
                ),
            );
        }
        for (i, r) in ranges.iter().enumerate() {
            if r.last() < r.from {
                self.push(
                    ErrorCode::InvalidSchedule,
                    &format!("{path}/{i}/to"),
                    format!(
                        "the range ends ({}) before it starts ({})",
                        r.last(),
                        r.from
                    ),
                );
            }
        }
    }
}

fn cloud(c: &CloudObject) -> Result<(), String> {
    for v in [&c.tenant_id, &c.object_id] {
        if normalize_object_id(v).is_none() {
            return Err(format!("`{v}` is not a GUID"));
        }
    }
    Ok(())
}

/// A `DOMAIN\user` wildcard: one `\`, with a domain part and a user part.
fn user_pattern(p: &str) -> Result<(), String> {
    Wildcard::new(p, false)?;
    match p.split_once('\\') {
        Some((domain, user)) if !domain.is_empty() && !user.is_empty() && !user.contains('\\') => {
            Ok(())
        }
        _ => Err(format!(
            "`{p}` is not a `DOMAIN\\user` pattern such as `*\\svc_*`"
        )),
    }
}

fn is_profile_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests;
