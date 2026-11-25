//! Compiling and evaluating scopes.

use std::sync::Arc;

use crate::context::{
    EvaluationContext, SessionType, normalize_object_id, normalize_principal, normalize_sid,
};
use crate::library::LibraryId;
use crate::model::TimeZoneBasis;
use crate::ops::Tri;
use palisade_core::Uuid7;

use super::facts::{CachedGroups, Gap, Held, Token};
use super::model::{
    ClientFilter, Combine, DeviceRef, NetworkRef, PrincipalRef, RefList, Scope, ScopeSubject,
    WellKnown,
};
use super::schedule::CompiledSchedule;
use super::text::{self, IpRange, Wildcard};
use super::{
    Dimension, ScopeEvaluation, ScopeFailure, ScopeLevel, ScopeLibrary, ScopeNote, ScopeNotes,
};

/// How a rule reads facts that have a safer and a less safe reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Bias {
    /// The rule lets an object run, trusts it or excludes it: read facts so
    /// that it applies less.
    Permissive,
    /// The rule denies or audits: read facts so that it applies more.
    Restrictive,
}

/// What compiling a scope needs from the policy.
#[derive(Clone, Copy)]
pub(crate) struct Env<'a> {
    pub(crate) library: &'a dyn ScopeLibrary,
    pub(crate) basis: TimeZoneBasis,
}

/// A scope ready to evaluate.
///
/// Compiling never fails: an entry that does not compile, which validation
/// rules out, and a library set that cannot be resolved evaluate to
/// `Unknown`, so they never let a rule allow.
#[derive(Clone, Debug)]
pub(crate) struct CompiledScope {
    dims: Vec<Dim>,
    combine: Combine,
    negate: bool,
    subject: ScopeSubject,
    max_instances: u32,
    group_cache_max_age: i64,
}

#[derive(Clone, Debug)]
enum Dim {
    Principals(Lists<Principal>),
    Devices(Lists<Device>),
    Network(Lists<Net>),
    Sessions {
        types: Vec<SessionType>,
        client: Option<Client>,
    },
    /// `None` when the schedule set could not be resolved.
    Schedule(Option<CompiledSchedule>),
}

impl Dim {
    const fn dimension(&self) -> Dimension {
        match self {
            Self::Principals(_) => Dimension::Principals,
            Self::Devices(_) => Dimension::Devices,
            Self::Network(_) => Dimension::Network,
            Self::Sessions { .. } => Dimension::Sessions,
            Self::Schedule(_) => Dimension::Schedule,
        }
    }
}

#[derive(Clone, Debug)]
struct Lists<T> {
    include: Vec<T>,
    exclude: Vec<T>,
}

impl<T> Lists<T> {
    fn compile<R>(list: &RefList<R>, f: impl Fn(&R) -> T) -> Self {
        Self {
            include: list.include.iter().map(&f).collect(),
            exclude: list.exclude.iter().map(&f).collect(),
        }
    }

    /// `include AND NOT exclude`, where an empty `include` is `Match`.
    fn eval(&self, mut test: impl FnMut(&T) -> Tri) -> Tri {
        let include = if self.include.is_empty() {
            Tri::Match
        } else {
            any(self.include.iter().map(&mut test))
        };
        let exclude = any(self.exclude.iter().map(&mut test));
        include.and(exclude.not())
    }
}

/// Kleene OR over every item, without stopping early, so every note is
/// gathered.
fn any(items: impl Iterator<Item = Tri>) -> Tri {
    items.fold(Tri::NoMatch, Tri::or)
}

#[derive(Clone, Debug)]
enum Principal {
    Sid(String),
    DomainControllers,
    LocalGroup(String),
    Cloud {
        tenant: String,
        object: String,
    },
    Pattern(Wildcard),
    Set {
        sids: Vec<String>,
        objects: Vec<String>,
    },
    Unresolved,
    Invalid,
}

#[derive(Clone, Debug)]
enum Device {
    Id(Uuid7),
    Hostname(Wildcard),
    Set(LibraryId),
    Group(String),
    Cloud { tenant: String, object: String },
    Ou { dn: Vec<String>, sub: bool },
    Tag(String),
    Invalid,
}

#[derive(Clone, Debug)]
enum Net {
    Range(IpRange),
    Suffix(String),
    Mac([u8; 6]),
    Reachable(bool),
    Location(String),
    Set(Vec<Net>),
    Unresolved,
    Invalid,
}

#[derive(Clone, Debug)]
struct Client {
    /// `None` for a pattern that did not compile, which is unknown.
    hostname: Vec<Option<Wildcard>>,
    ip: Vec<Option<IpRange>>,
    sets: Vec<LibraryId>,
}

impl CompiledScope {
    /// Compiles a scope. `group_cache_max_age_secs` is the policy's
    /// staleness limit for cached group memberships.
    pub(crate) fn compile(scope: &Scope, env: Env<'_>, group_cache_max_age_secs: u32) -> Self {
        let mut dims = Vec::new();
        if let Some(p) = &scope.principals {
            dims.push(Dim::Principals(Lists::compile(p, |r| principal(r, env))));
        }
        if let Some(d) = &scope.devices {
            dims.push(Dim::Devices(Lists::compile(d, device)));
        }
        if let Some(n) = &scope.network {
            dims.push(Dim::Network(Lists::compile(n, |r| net(r, env))));
        }
        if let Some(s) = &scope.sessions {
            dims.push(Dim::Sessions {
                types: s.types.clone(),
                client: s.client.as_ref().map(client),
            });
        }
        if let Some(schedule) = &scope.schedule {
            dims.push(Dim::Schedule(Some(CompiledSchedule::compile(
                schedule, env.basis,
            ))));
        } else if let Some(set) = &scope.schedule_set {
            dims.push(Dim::Schedule(
                env.library
                    .schedule_set(set)
                    .map(|s| CompiledSchedule::compile(&s, env.basis)),
            ));
        }
        Self {
            dims,
            combine: scope.combine,
            negate: scope.negate,
            subject: scope.subject,
            max_instances: scope.max_instances_per_session,
            group_cache_max_age: i64::from(group_cache_max_age_secs),
        }
    }

    /// A scope that matches when every network test matches: a location
    /// profile.
    pub(crate) fn all_of_network(tests: &[NetworkRef], env: Env<'_>) -> Self {
        Self {
            dims: tests
                .iter()
                .map(|t| {
                    Dim::Network(Lists {
                        include: vec![net(t, env)],
                        exclude: Vec::new(),
                    })
                })
                .collect(),
            combine: Combine::All,
            negate: false,
            subject: ScopeSubject::ProcessUser,
            max_instances: 0,
            group_cache_max_age: 0,
        }
    }

    /// The per-session instance limit, `0` for none.
    #[must_use]
    pub const fn max_instances_per_session(&self) -> u32 {
        self.max_instances
    }

    /// The scope's schedule, if it has one that resolved.
    #[must_use]
    pub fn schedule(&self) -> Option<&CompiledSchedule> {
        self.dims.iter().find_map(|d| match d {
            Dim::Schedule(s) => s.as_ref(),
            _ => None,
        })
    }

    /// Evaluates the scope on its own, and names the dimension that failed
    /// when one decided alone. See [`eval_chain`].
    pub(crate) fn eval(
        &self,
        ctx: &EvaluationContext,
        bias: Bias,
        notes: &mut ScopeNotes,
    ) -> (Tri, Option<Dimension>) {
        let e = eval_scopes(&[(ScopeLevel::Rule, self)], ctx, bias);
        notes.extend(e.notes);
        (e.result, e.failure.and_then(|f| f.dimension))
    }

    /// Whether the scope tests principals against a token that holds a
    /// deny-only group, which has two readings.
    fn reads_deny_only(&self, ctx: &EvaluationContext) -> bool {
        self.dims.iter().any(|d| matches!(d, Dim::Principals(_)))
            && self.token(ctx).is_some_and(Token::has_deny_only)
    }

    /// The token `principals` tests.
    fn token<'c>(&self, ctx: &'c EvaluationContext) -> Option<&'c Token> {
        let facts = &ctx.scope;
        match self.subject {
            ScopeSubject::ProcessUser => facts.process_token.as_ref(),
            ScopeSubject::SessionUser => facts.session_token.as_ref(),
            ScopeSubject::ParentProcessUser => facts.parent_token.as_ref(),
        }
    }

    /// Evaluates the scope with deny-only groups read as membership
    /// (`member`) or not.
    fn eval_as(
        &self,
        ctx: &EvaluationContext,
        bias: Bias,
        member: bool,
        notes: &mut ScopeNotes,
    ) -> (Tri, Option<Dimension>) {
        let positive = !self.negate;
        let mut result = match self.combine {
            Combine::All => Tri::Match,
            Combine::Any if self.dims.is_empty() => Tri::Match,
            Combine::Any => Tri::NoMatch,
        };
        let mut failed = None;
        for dim in &self.dims {
            let r = self.eval_dim(dim, ctx, positive, bias, member, notes);
            match self.combine {
                Combine::All => {
                    if r == Tri::NoMatch && failed.is_none() {
                        failed = Some(dim.dimension());
                    }
                    result = result.and(r);
                }
                Combine::Any => result = result.or(r),
            }
        }
        if self.negate {
            result = result.not();
        }
        let named = result == Tri::NoMatch && self.combine == Combine::All && !self.negate;
        (result, if named { failed } else { None })
    }

    /// The schedule whose closing ends the scope's match: only a scope
    /// with `combine: all` and no `negate`, where the rule applies only
    /// while the schedule is active.
    pub(crate) fn closing_schedule(&self) -> Option<&CompiledSchedule> {
        if self.combine == Combine::All && !self.negate {
            self.schedule()
        } else {
            None
        }
    }

    fn eval_dim(
        &self,
        dim: &Dim,
        ctx: &EvaluationContext,
        positive: bool,
        bias: Bias,
        member: bool,
        notes: &mut ScopeNotes,
    ) -> Tri {
        match dim {
            Dim::Principals(lists) => {
                let token = self.token(ctx);
                lists.eval(|p| {
                    let Some(token) = token else {
                        return missing(notes);
                    };
                    self.principal(p, token, ctx, member, notes)
                })
            }
            Dim::Devices(lists) => lists.eval(|d| self.device_eval(d, ctx, notes)),
            Dim::Network(lists) => lists.eval(|n| net_eval(n, ctx, notes)),
            Dim::Sessions { types, client } => {
                let types = if types.is_empty() {
                    Tri::Match
                } else {
                    match ctx.session.session_type {
                        Some(t) => Tri::from_bool(types.contains(&t)),
                        None => missing(notes),
                    }
                };
                let client = client
                    .as_ref()
                    .map_or(Tri::Match, |c| client_eval(c, ctx, notes));
                types.and(client)
            }
            Dim::Schedule(Some(schedule)) => {
                let (r, n) = schedule.eval(&ctx.scope, positive, bias);
                notes.extend(n);
                r
            }
            Dim::Schedule(None) => {
                notes.insert(ScopeNote::SetUnresolved);
                Tri::Unknown
            }
        }
    }

    fn principal(
        &self,
        p: &Principal,
        token: &Token,
        ctx: &EvaluationContext,
        member: bool,
        notes: &mut ScopeNotes,
    ) -> Tri {
        let held = |h: Result<Held, Gap>, notes: &mut ScopeNotes| match h {
            Ok(Held::Yes) => Tri::Match,
            Ok(Held::No) => Tri::NoMatch,
            Ok(Held::DenyOnly) => {
                // Read one way for the whole chain in this pass; the chain
                // is evaluated both ways ([`eval_chain`]).
                notes.insert(ScopeNote::DenyOnlyGroup);
                Tri::from_bool(member)
            }
            Err(Gap::Missing) => missing(notes),
            Err(Gap::Malformed) => malformed(notes),
        };
        match p {
            Principal::Sid(sid) => held(token.holds(sid), notes),
            Principal::DomainControllers => held(
                token.holds_any(|s| {
                    s == WellKnown::DomainControllers.sid() || is_domain_controllers(s)
                }),
                notes,
            ),
            Principal::LocalGroup(name) => match &ctx.scope.local_groups {
                None => missing(notes),
                Some(groups) => {
                    let mut result = Tri::NoMatch;
                    for g in groups.iter().filter(|g| text::group_name(&g.name) == *name) {
                        result = result.or(match normalize_sid(&g.sid) {
                            Some(sid) => held(token.holds(&sid), notes),
                            None => malformed(notes),
                        });
                    }
                    result
                }
            },
            Principal::Cloud { tenant, object } => {
                self.cached(token.cloud_groups(), Some(tenant), object, ctx, notes)
            }
            Principal::Pattern(w) => match token.account_name() {
                Some(name) => Tri::from_bool(w.matches(name)),
                None => missing(notes),
            },
            Principal::Set { sids, objects } => {
                let by_sid = if sids.is_empty() {
                    Tri::NoMatch
                } else {
                    held(token.holds_any_of(sids), notes)
                };
                if by_sid == Tri::Match || objects.is_empty() {
                    return by_sid;
                }
                let by_object = match self.fresh(token.cloud_groups(), ctx, notes) {
                    Ok(cache) => match cache.contains_any(objects) {
                        Some(found) => Tri::from_bool(found),
                        None => malformed(notes),
                    },
                    Err(t) => t,
                };
                by_sid.or(by_object)
            }
            Principal::Unresolved => {
                notes.insert(ScopeNote::SetUnresolved);
                Tri::Unknown
            }
            Principal::Invalid => malformed(notes),
        }
    }

    /// Cached cloud-directory membership: `Unknown` when the cache is
    /// missing, stale, from the future, or the clock is not trusted.
    fn cached(
        &self,
        cache: Option<&CachedGroups>,
        tenant: Option<&str>,
        object: &str,
        ctx: &EvaluationContext,
        notes: &mut ScopeNotes,
    ) -> Tri {
        match self.fresh(cache, ctx, notes) {
            Ok(cache) => match cache.contains(tenant, object) {
                Some(found) => Tri::from_bool(found),
                None => malformed(notes),
            },
            Err(t) => t,
        }
    }

    /// The cache, if it is present and fresh; otherwise the result to use.
    fn fresh<'c>(
        &self,
        cache: Option<&'c CachedGroups>,
        ctx: &EvaluationContext,
        notes: &mut ScopeNotes,
    ) -> Result<&'c CachedGroups, Tri> {
        let Some(cache) = cache else {
            return Err(missing(notes));
        };
        let fresh = ctx
            .scope
            .time
            .filter(|t| t.trusted)
            .and_then(|t| t.unix_secs.checked_sub(cache.cached_at))
            .is_some_and(|age| (0..=self.group_cache_max_age).contains(&age));
        if !fresh {
            notes.insert(ScopeNote::ScopeStale);
            return Err(Tri::Unknown);
        }
        Ok(cache)
    }
}

/// Evaluates the scopes on the way to one rule: their `AND`, the notes
/// they gathered, and the first one that did not match.
///
/// A deny-only group of a filtered token has two readings: as membership
/// and as none. When a scope on the chain tests one, the chain is
/// evaluated both ways and the reading that makes the rule apply less is
/// taken for a permitting rule, and the one that makes it apply more for a
/// restricting rule. Each reading is a consistent set of facts, so every
/// property of one reading (an `exclude` that holds the `include` never
/// matches; a scope only narrows) holds for the result.
pub(crate) fn eval_chain(
    chain: &[(ScopeLevel, Arc<CompiledScope>)],
    ctx: &EvaluationContext,
    bias: Bias,
) -> ScopeEvaluation {
    let refs: Vec<(ScopeLevel, &CompiledScope)> = chain.iter().map(|(l, s)| (*l, &**s)).collect();
    eval_scopes(&refs, ctx, bias)
}

fn eval_scopes(
    chain: &[(ScopeLevel, &CompiledScope)],
    ctx: &EvaluationContext,
    bias: Bias,
) -> ScopeEvaluation {
    let pass = |member: bool| {
        let mut notes = ScopeNotes::default();
        let mut result = Tri::Match;
        let mut failure = None;
        for (level, scope) in chain {
            let (r, dimension) = scope.eval_as(ctx, bias, member, &mut notes);
            if r == Tri::NoMatch && failure.is_none() {
                failure = Some(ScopeFailure {
                    level: *level,
                    dimension,
                });
            }
            result = result.and(r);
        }
        ScopeEvaluation {
            result,
            notes,
            failure: if result == Tri::NoMatch {
                failure
            } else {
                None
            },
        }
    };
    let absent = pass(false);
    if !chain.iter().any(|(_, s)| s.reads_deny_only(ctx)) {
        return absent;
    }
    let member = pass(true);
    let mut notes = absent.notes;
    notes.extend(member.notes);
    let member_lower = super::rank(member.result) < super::rank(absent.result);
    let mut chosen = match (bias, member_lower) {
        (Bias::Permissive, true) | (Bias::Restrictive, false) => member,
        (Bias::Permissive, false) | (Bias::Restrictive, true) => absent,
    };
    // Equal results: either reading, deterministically.
    if member.result == absent.result {
        chosen = absent;
    }
    chosen.notes = notes;
    chosen
}

fn missing(notes: &mut ScopeNotes) -> Tri {
    notes.insert(ScopeNote::FactMissing);
    Tri::Unknown
}

fn malformed(notes: &mut ScopeNotes) -> Tri {
    notes.insert(ScopeNote::FactMalformed);
    Tri::Unknown
}

/// Whether a canonical SID is a domain's Domain Controllers group:
/// `S-1-5-21-a-b-c-516`.
fn is_domain_controllers(sid: &str) -> bool {
    let parts: Vec<&str> = sid.split('-').collect();
    parts.len() == 8 && parts[..4] == ["S", "1", "5", "21"] && parts[7] == "516"
}

fn principal(r: &PrincipalRef, env: Env<'_>) -> Principal {
    let sid = |s: &str| normalize_sid(s).map_or(Principal::Invalid, Principal::Sid);
    match r {
        PrincipalRef::Sid(s) => sid(s),
        PrincipalRef::WellKnown(WellKnown::DomainControllers) => Principal::DomainControllers,
        PrincipalRef::WellKnown(w) => Principal::Sid(w.sid().to_owned()),
        PrincipalRef::LocalGroup(name) => Principal::LocalGroup(text::group_name(name)),
        PrincipalRef::DirectoryGroup(g) => sid(&g.sid),
        PrincipalRef::CloudGroup(c) => {
            match (
                normalize_object_id(&c.tenant_id),
                normalize_object_id(&c.object_id),
            ) {
                (Some(tenant), Some(object)) => Principal::Cloud { tenant, object },
                _ => Principal::Invalid,
            }
        }
        PrincipalRef::UserPattern(p) => {
            Wildcard::new(p, false).map_or(Principal::Invalid, Principal::Pattern)
        }
        PrincipalRef::PrincipalSet(set) => match env.library.principal_set(set) {
            None => Principal::Unresolved,
            Some(members) => {
                let mut sids = Vec::new();
                let mut objects = Vec::new();
                for m in &members {
                    if let Some(s) = normalize_sid(m) {
                        sids.push(s);
                    } else if let Some(o) = normalize_object_id(m) {
                        objects.push(o);
                    } else {
                        // A member that is neither can never be matched,
                        // so the set cannot say who is not in it.
                        return Principal::Invalid;
                    }
                }
                sids.sort();
                sids.dedup();
                objects.sort();
                objects.dedup();
                Principal::Set { sids, objects }
            }
        },
    }
}

fn device(r: &DeviceRef) -> Device {
    match r {
        DeviceRef::DeviceId(id) => Device::Id(*id),
        DeviceRef::HostnamePattern(p) => {
            Wildcard::new(p, false).map_or(Device::Invalid, Device::Hostname)
        }
        DeviceRef::DeviceSet(set) => Device::Set(set.id),
        DeviceRef::DirectoryComputerGroup(s) => {
            normalize_sid(s).map_or(Device::Invalid, Device::Group)
        }
        DeviceRef::CloudDeviceGroup(c) => {
            match (
                normalize_object_id(&c.tenant_id),
                normalize_object_id(&c.object_id),
            ) {
                (Some(tenant), Some(object)) => Device::Cloud { tenant, object },
                _ => Device::Invalid,
            }
        }
        DeviceRef::Ou(ou) => match text::plain(&ou.dn).ok().and_then(|()| text::dn(&ou.dn)) {
            Some(dn) => Device::Ou {
                dn,
                sub: ou.include_sub_ous,
            },
            None => Device::Invalid,
        },
        DeviceRef::Tag(t) => match text::plain(t) {
            Ok(()) => Device::Tag(text::group_name(t)),
            Err(_) => Device::Invalid,
        },
    }
}

impl CompiledScope {
    fn device_eval(&self, d: &Device, ctx: &EvaluationContext, notes: &mut ScopeNotes) -> Tri {
        let dev = &ctx.device;
        match d {
            Device::Id(id) => match ctx.scope.device_id {
                Some(own) => Tri::from_bool(own == *id),
                None => missing(notes),
            },
            Device::Hostname(w) => {
                let names = [dev.hostname.as_deref(), dev.fqdn.as_deref()];
                if names.iter().all(Option::is_none) {
                    return missing(notes);
                }
                let r = any(names.iter().map(|n| match n {
                    Some(n) => Tri::from_bool(w.matches(n)),
                    None => Tri::Unknown,
                }));
                if r == Tri::Unknown {
                    notes.insert(ScopeNote::FactMissing);
                }
                r
            }
            Device::Set(id) => match &ctx.scope.device_sets {
                Some(sets) => Tri::from_bool(sets.contains(id)),
                None => missing(notes),
            },
            Device::Group(g) => match &dev.groups {
                Some(groups) => {
                    let mut malformed_seen = false;
                    for fact in groups {
                        match normalize_principal(fact) {
                            Some(f) if f == *g => return Tri::Match,
                            Some(_) => {}
                            None => malformed_seen = true,
                        }
                    }
                    if malformed_seen {
                        malformed(notes)
                    } else {
                        Tri::NoMatch
                    }
                }
                None => missing(notes),
            },
            Device::Cloud { tenant, object } => self.cached(
                ctx.scope.device_cloud_groups.as_ref(),
                Some(tenant),
                object,
                ctx,
                notes,
            ),
            Device::Ou { dn, sub } => match dev.dn.as_deref() {
                Some(fact) => match text::dn(fact) {
                    Some(object) => Tri::from_bool(text::in_ou(&object, dn, *sub)),
                    None => malformed(notes),
                },
                None => missing(notes),
            },
            Device::Tag(t) => match &dev.tags {
                Some(tags) => Tri::from_bool(tags.iter().any(|x| text::group_name(x) == *t)),
                None => missing(notes),
            },
            Device::Invalid => malformed(notes),
        }
    }
}

fn net(r: &NetworkRef, env: Env<'_>) -> Net {
    match r {
        NetworkRef::Cidr(s) => IpRange::cidr(s).map_or(Net::Invalid, Net::Range),
        NetworkRef::Range(s) => IpRange::range(s).map_or(Net::Invalid, Net::Range),
        NetworkRef::DnsSuffix(s) => text::dns_suffix(s).map_or(Net::Invalid, Net::Suffix),
        NetworkRef::GatewayMac(s) => text::mac(s).map_or(Net::Invalid, Net::Mac),
        NetworkRef::ServerReachable(b) => Net::Reachable(*b),
        NetworkRef::LocationProfile(name) => Net::Location(text::group_name(name)),
        NetworkRef::NetworkSet(set) => match env.library.network_set(set) {
            None => Net::Unresolved,
            Some(entries) => Net::Set(entries.iter().map(|e| set_entry(e)).collect()),
        },
    }
}

/// A network set entry: an address block or range, or a DNS suffix.
fn set_entry(entry: &str) -> Net {
    if let Ok(r) = IpRange::block_or_range(entry) {
        Net::Range(r)
    } else if let Ok(s) = text::dns_suffix(entry) {
        Net::Suffix(s)
    } else {
        Net::Invalid
    }
}

fn net_eval(n: &Net, ctx: &EvaluationContext, notes: &mut ScopeNotes) -> Tri {
    let net = &ctx.network;
    match n {
        Net::Range(r) => match &net.addresses {
            Some(a) => Tri::from_bool(a.iter().any(|ip| r.contains(*ip))),
            None => missing(notes),
        },
        Net::Suffix(s) => match &net.dns_suffixes {
            Some(d) => Tri::from_bool(d.iter().any(|x| text::dns_within(x, s))),
            None => missing(notes),
        },
        Net::Mac(m) => match &net.gateway_macs {
            Some(g) => Tri::from_bool(g.contains(m)),
            None => missing(notes),
        },
        Net::Reachable(b) => match net.server_reachable {
            Some(r) => Tri::from_bool(r == *b),
            None => missing(notes),
        },
        Net::Location(name) => match &net.locations {
            Some(l) => Tri::from_bool(l.iter().any(|x| text::group_name(x) == *name)),
            None => missing(notes),
        },
        Net::Set(entries) => any(entries.iter().map(|e| net_eval(e, ctx, notes))),
        Net::Unresolved => {
            notes.insert(ScopeNote::SetUnresolved);
            Tri::Unknown
        }
        Net::Invalid => malformed(notes),
    }
}

fn client(c: &ClientFilter) -> Client {
    Client {
        hostname: c
            .hostname
            .iter()
            .map(|p| Wildcard::new(p, false).ok())
            .collect(),
        ip: c
            .ip
            .iter()
            .map(|s| IpRange::block_or_range(s).ok())
            .collect(),
        sets: c.device_sets.iter().map(|s| s.id).collect(),
    }
}

/// Every list that is set must match; each matches when any entry does.
fn client_eval(c: &Client, ctx: &EvaluationContext, notes: &mut ScopeNotes) -> Tri {
    let s = &ctx.session;
    let mut result = Tri::Match;
    if !c.hostname.is_empty() {
        result = result.and(match s.client_hostname.as_deref() {
            Some(h) => any(c.hostname.iter().map(|w| match w {
                Some(w) => Tri::from_bool(w.matches(h)),
                None => malformed(notes),
            })),
            None => missing(notes),
        });
    }
    if !c.ip.is_empty() {
        result = result.and(match s.client_ip {
            Some(ip) => any(c.ip.iter().map(|r| match r {
                Some(r) => Tri::from_bool(r.contains(ip)),
                None => malformed(notes),
            })),
            None => missing(notes),
        });
    }
    if !c.sets.is_empty() {
        result = result.and(match &ctx.scope.client_device_sets {
            Some(sets) => Tri::from_bool(c.sets.iter().any(|x| sets.contains(x))),
            None => missing(notes),
        });
    }
    result
}
