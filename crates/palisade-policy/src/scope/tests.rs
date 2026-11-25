//! Scope tests: every dimension's include and exclude, `combine`,
//! `negate`, restrictive readings, and the properties that an exclude
//! covering the include never matches and that a scope only narrows.

use std::sync::Arc;

use proptest::prelude::*;

use super::compile::{Bias, CompiledScope, Env, eval_chain};
use super::*;
use crate::context::{EvaluationContext, SessionType};
use crate::model::TimeZoneBasis;
use crate::ops::Tri::{self, Match, NoMatch, Unknown};

const ADMINS: &str = "S-1-5-32-544";
const USERS: &str = "S-1-5-32-545";
const FINANCE: &str = "S-1-5-21-1004336348-1177238915-682003330-1105";
const ALICE: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
const TENANT: &str = "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const CLOUD_GROUP: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e";
/// 2026-09-21T10:00:00Z, a Monday.
const MONDAY_10: i64 = 1_789_948_800 + 10 * 3600;

/// A library with one principal set, one network set and one schedule.
#[derive(Debug)]
struct Library;

const PSET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70";
const NSET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e71";
const SSET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e72";

impl ScopeLibrary for Library {
    fn principal_set(&self, set: &SetRef) -> Option<Vec<String>> {
        (set.id.0.to_string() == PSET).then(|| vec![FINANCE.to_owned(), CLOUD_GROUP.to_owned()])
    }
    fn network_set(&self, set: &SetRef) -> Option<Vec<String>> {
        (set.id.0.to_string() == NSET)
            .then(|| vec!["192.168.10.0/24".to_owned(), "corp.example.org".to_owned()])
    }
    fn schedule_set(&self, set: &SetRef) -> Option<Schedule> {
        (set.id.0.to_string() == SSET).then(|| Schedule {
            windows: vec![Window {
                days: vec![Weekday::Mon],
                start: "00:00".parse().unwrap(),
                end: Some("00:00".parse().unwrap()),
                duration_mins: None,
            }],
            ..Schedule::default()
        })
    }
}

fn set(id: &str) -> SetRef {
    SetRef {
        id: crate::library::LibraryId(id.parse().unwrap()),
        pin: Pin::Latest,
    }
}

fn compile(scope: &Scope) -> CompiledScope {
    CompiledScope::compile(
        scope,
        Env {
            library: &Library,
            basis: TimeZoneBasis::Utc,
        },
        DEFAULT_GROUP_CACHE_MAX_AGE_SECS,
    )
}

fn eval_with(scope: &Scope, ctx: &EvaluationContext, bias: Bias) -> (Tri, ScopeNotes) {
    let mut notes = ScopeNotes::default();
    let r = compile(scope).eval(ctx, bias, &mut notes).0;
    (r, notes)
}

fn allow(scope: &Scope, ctx: &EvaluationContext) -> Tri {
    eval_with(scope, ctx, Bias::Permissive).0
}

fn deny(scope: &Scope, ctx: &EvaluationContext) -> Tri {
    eval_with(scope, ctx, Bias::Restrictive).0
}

/// A context with every fact: a non-elevated administrator in Finance,
/// over RDP from a thin client, on the corporate network, on a Monday.
fn ctx() -> EvaluationContext {
    let mut c = EvaluationContext::default();
    c.device.hostname = Some("FIN-WS-07".to_owned());
    c.device.fqdn = Some("fin-ws-07.corp.example.org".to_owned());
    c.device.groups = Some(vec!["S-1-5-21-1-2-3-4001".to_owned()]);
    c.device.tags = Some(vec!["Site=Sydney".to_owned()]);
    c.device.dn = Some("CN=FIN-WS-07,OU=Laptops,OU=Finance,DC=corp,DC=example,DC=org".to_owned());
    c.session.session_type = Some(SessionType::Rdp);
    c.session.client_hostname = Some("THIN-07".to_owned());
    c.session.client_ip = Some("10.9.8.7".parse().unwrap());
    c.network.addresses = Some(vec!["192.168.10.42".parse().unwrap()]);
    c.network.dns_suffixes = Some(vec!["corp.example.org".to_owned()]);
    c.network.gateway_macs = Some(vec![[0, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]]);
    c.network.server_reachable = Some(true);
    c.network.locations = Some(vec!["corporate".to_owned()]);
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), Some("CORP\\alice"))
            .with_groups([(USERS, false), (FINANCE, false), (ADMINS, true)])
            .with_cloud_groups(MONDAY_10 - 3600, [(TENANT, CLOUD_GROUP)]),
    );
    c.scope.session_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([(USERS, false)]),
    );
    c.scope.local_groups = Some(vec![LocalGroup {
        name: "Backup Operators".to_owned(),
        sid: "S-1-5-32-551".to_owned(),
    }]);
    c.scope.time = Some(TrustedTime {
        unix_secs: MONDAY_10,
        trusted: true,
    });
    c.scope.device_time_zone = Some("Australia/Sydney".to_owned());
    c.scope.device_id = Some("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e99".parse().unwrap());
    c.scope.device_sets = Some(vec![set(PSET).id]);
    c.scope.client_device_sets = Some(vec![set(NSET).id]);
    c.scope.device_cloud_groups = Some(CachedGroups::new(MONDAY_10 - 60, [(TENANT, CLOUD_GROUP)]));
    c
}

fn principals(include: Vec<PrincipalRef>, exclude: Vec<PrincipalRef>) -> Scope {
    Scope {
        principals: Some(RefList { include, exclude }),
        ..Scope::default()
    }
}

fn sid(s: &str) -> PrincipalRef {
    PrincipalRef::Sid(s.to_owned())
}

#[test]
fn an_empty_scope_matches_everything() {
    assert_eq!(
        allow(&Scope::default(), &EvaluationContext::default()),
        Match
    );
    let any = Scope {
        combine: Combine::Any,
        ..Scope::default()
    };
    assert_eq!(allow(&any, &EvaluationContext::default()), Match);
    let empty_lists = principals(vec![], vec![]);
    assert_eq!(allow(&empty_lists, &ctx()), Match);
}

#[test]
fn principal_include_and_exclude_table() {
    let c = ctx();
    // (include, exclude, expected for an allow)
    let cases: Vec<(Vec<PrincipalRef>, Vec<PrincipalRef>, Tri)> = vec![
        (vec![sid(FINANCE)], vec![], Match),
        (
            vec![sid("s-1-5-21-1004336348-1177238915-682003330-01105")],
            vec![],
            Match,
        ),
        (vec![sid("S-1-5-21-9-9-9-9")], vec![], NoMatch),
        (vec![sid(FINANCE)], vec![sid(FINANCE)], NoMatch),
        (vec![], vec![sid(FINANCE)], NoMatch),
        (vec![], vec![sid("S-1-5-21-9-9-9-9")], Match),
        (
            vec![PrincipalRef::WellKnown(WellKnown::Users)],
            vec![],
            Match,
        ),
        (
            vec![PrincipalRef::WellKnown(WellKnown::System)],
            vec![],
            NoMatch,
        ),
        (
            vec![sid("S-1-5-21-1004336348-1177238915-682003330-1001")],
            vec![],
            Match,
        ),
        (
            vec![PrincipalRef::DirectoryGroup(DirectoryGroup {
                sid: FINANCE.to_owned(),
                name: Some("Finance".to_owned()),
            })],
            vec![],
            Match,
        ),
        (
            vec![PrincipalRef::CloudGroup(CloudObject {
                tenant_id: TENANT.to_uppercase(),
                object_id: CLOUD_GROUP.to_owned(),
            })],
            vec![],
            Match,
        ),
        (vec![PrincipalRef::PrincipalSet(set(PSET))], vec![], Match),
        (vec![PrincipalRef::PrincipalSet(set(NSET))], vec![], Unknown),
        (
            vec![sid(FINANCE)],
            vec![PrincipalRef::UserPattern("*\\alice".to_owned())],
            NoMatch,
        ),
        (
            vec![PrincipalRef::LocalGroup("backup operators".to_owned())],
            vec![],
            NoMatch,
        ),
    ];
    for (i, (include, exclude, expected)) in cases.into_iter().enumerate() {
        assert_eq!(
            allow(&principals(include, exclude), &c),
            expected,
            "case {i}"
        );
    }
}

#[test]
fn deny_only_groups_are_read_restrictively() {
    let c = ctx();
    let admins = || {
        principals(
            vec![PrincipalRef::WellKnown(WellKnown::Administrators)],
            vec![],
        )
    };
    let (r, notes) = eval_with(&admins(), &c, Bias::Permissive);
    assert_eq!(
        r, NoMatch,
        "a filtered admin never gets an admins-only allow"
    );
    assert!(notes.contains(ScopeNote::DenyOnlyGroup));
    assert_eq!(deny(&admins(), &c), Match, "but an admins deny applies");
    // Whatever the position, the reading is the one that makes an allow
    // apply less and a deny apply more: an allow for everyone but
    // administrators does not apply, and a deny for everyone but
    // administrators does.
    let not_admins = principals(
        vec![],
        vec![PrincipalRef::WellKnown(WellKnown::Administrators)],
    );
    assert_eq!(allow(&not_admins, &c), NoMatch);
    assert_eq!(deny(&not_admins, &c), Match);
    let negated = Scope {
        negate: true,
        ..admins()
    };
    assert_eq!(allow(&negated, &c), NoMatch);
    assert_eq!(deny(&negated, &c), Match);
    // An enabled Administrators group is a member for both.
    let mut elevated = ctx();
    elevated.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([(ADMINS, false)]),
    );
    assert_eq!(allow(&admins(), &elevated), Match);
    // Two copies of one SID, one deny-only, read as deny-only.
    let mut both = ctx();
    both.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([(ADMINS, false), (ADMINS, true)]),
    );
    assert_eq!(allow(&admins(), &both), NoMatch);
}

#[test]
fn cached_cloud_groups_go_unknown_when_stale() {
    let cloud = principals(
        vec![PrincipalRef::CloudGroup(CloudObject {
            tenant_id: TENANT.to_owned(),
            object_id: CLOUD_GROUP.to_owned(),
        })],
        vec![],
    );
    let mut c = ctx();
    let now = c.scope.time.unwrap().unix_secs;
    let cache_at = |c: &mut EvaluationContext, at: i64| {
        c.scope.process_token = Some(Token::new().with_cloud_groups(at, [(TENANT, CLOUD_GROUP)]));
    };
    cache_at(&mut c, now - 86_400);
    assert_eq!(allow(&cloud, &c), Match, "exactly the maximum age is fresh");
    cache_at(&mut c, now - 86_401);
    let (r, notes) = eval_with(&cloud, &c, Bias::Permissive);
    assert_eq!(r, Unknown);
    assert!(notes.contains(ScopeNote::ScopeStale));
    cache_at(&mut c, now + 60);
    assert_eq!(
        allow(&cloud, &c),
        Unknown,
        "a cache from the future is stale"
    );
    cache_at(&mut c, now);
    c.scope.time = Some(TrustedTime {
        unix_secs: now,
        trusted: false,
    });
    assert_eq!(
        allow(&cloud, &c),
        Unknown,
        "an untrusted clock cannot judge age"
    );
    // A shorter policy limit applies.
    let mut fresh = ctx();
    cache_at(&mut fresh, now - 7200);
    let short = CompiledScope::compile(
        &cloud,
        Env {
            library: &NoLibrary,
            basis: TimeZoneBasis::Utc,
        },
        MIN_GROUP_CACHE_MAX_AGE_SECS,
    );
    let mut notes = ScopeNotes::default();
    assert_eq!(short.eval(&fresh, Bias::Permissive, &mut notes).0, Unknown);
}

#[test]
fn unknown_membership_fails_allows_closed() {
    let mut c = ctx();
    c.scope.process_token = None;
    let finance = principals(vec![sid(FINANCE)], vec![]);
    assert_eq!(allow(&finance, &c), Unknown);
    let excluded = principals(vec![], vec![sid(FINANCE)]);
    assert_eq!(allow(&excluded, &c), Unknown);
    // A token whose groups include a malformed SID cannot prove absence.
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([("not-a-sid", false)]),
    );
    let (r, notes) = eval_with(&excluded, &c, Bias::Permissive);
    assert_eq!(r, Unknown);
    assert!(notes.contains(ScopeNote::FactMalformed));
    assert_eq!(allow(&finance, &c), Unknown);
    // Nor can one whose user SID is malformed, or was not collected: the
    // user SID is not among the groups, and could be the excluded one.
    let alice_out = principals(vec![], vec![sid(ALICE)]);
    for user in [Some("not-a-sid"), None] {
        c.scope.process_token = Some(
            Token::new()
                .with_user(user, None)
                .with_groups([(USERS, false)]),
        );
        let (r, notes) = eval_with(&alice_out, &c, Bias::Permissive);
        assert_eq!(r, Unknown, "{user:?}");
        let expected = if user.is_some() {
            ScopeNote::FactMalformed
        } else {
            ScopeNote::FactMissing
        };
        assert!(notes.contains(expected), "{user:?}");
        // A group the token does hold still matches.
        let users = principals(vec![sid(USERS)], vec![]);
        assert_eq!(allow(&users, &c), Match);
    }
    // A principal set of cloud objects only does not need the groups.
    let mut cloud_only = ctx();
    cloud_only.scope.process_token =
        Some(Token::new().with_cloud_groups(MONDAY_10, [(TENANT, CLOUD_GROUP)]));
    #[derive(Debug)]
    struct CloudSet;
    impl ScopeLibrary for CloudSet {
        fn principal_set(&self, _: &SetRef) -> Option<Vec<String>> {
            Some(vec!["1a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4f".to_owned()])
        }
        fn network_set(&self, _: &SetRef) -> Option<Vec<String>> {
            None
        }
        fn schedule_set(&self, _: &SetRef) -> Option<Schedule> {
            None
        }
    }
    let scope = CompiledScope::compile(
        &principals(vec![], vec![PrincipalRef::PrincipalSet(set(PSET))]),
        Env {
            library: &CloudSet,
            basis: TimeZoneBasis::Utc,
        },
        DEFAULT_GROUP_CACHE_MAX_AGE_SECS,
    );
    let mut notes = ScopeNotes::default();
    assert_eq!(
        scope.eval(&cloud_only, Bias::Permissive, &mut notes).0,
        Match
    );
}

#[test]
fn the_subject_selects_the_token() {
    let c = ctx();
    let finance = |subject| Scope {
        subject,
        ..principals(vec![sid(FINANCE)], vec![])
    };
    assert_eq!(allow(&finance(ScopeSubject::ProcessUser), &c), Match);
    assert_eq!(allow(&finance(ScopeSubject::SessionUser), &c), NoMatch);
    assert_eq!(
        allow(&finance(ScopeSubject::ParentProcessUser), &c),
        Unknown
    );
}

#[test]
fn domain_controllers_match_by_relative_id() {
    let mut c = ctx();
    let dcs = principals(
        vec![PrincipalRef::WellKnown(WellKnown::DomainControllers)],
        vec![],
    );
    assert_eq!(allow(&dcs, &c), NoMatch);
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([("S-1-5-21-1-2-3-516", false)]),
    );
    assert_eq!(allow(&dcs, &c), Match);
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([("S-1-5-9", false)]),
    );
    assert_eq!(allow(&dcs, &c), Match);
}

#[test]
fn local_groups_resolve_by_name_on_the_device() {
    let mut c = ctx();
    let backup = principals(
        vec![PrincipalRef::LocalGroup("BACKUP operators".to_owned())],
        vec![],
    );
    assert_eq!(allow(&backup, &c), NoMatch);
    c.scope.process_token = Some(
        Token::new()
            .with_user(Some(ALICE), None)
            .with_groups([("S-1-5-32-551", false)]),
    );
    assert_eq!(allow(&backup, &c), Match);
    c.scope.local_groups = None;
    assert_eq!(allow(&backup, &c), Unknown);
}

#[test]
fn device_dimension_table() {
    let c = ctx();
    let dev = |r: DeviceRef| Scope {
        devices: Some(RefList {
            include: vec![r],
            exclude: vec![],
        }),
        ..Scope::default()
    };
    let cases = [
        (
            DeviceRef::DeviceId("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e99".parse().unwrap()),
            Match,
        ),
        (
            DeviceRef::DeviceId("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e98".parse().unwrap()),
            NoMatch,
        ),
        (DeviceRef::HostnamePattern("fin-*".to_owned()), Match),
        (
            DeviceRef::HostnamePattern("*.corp.example.org".to_owned()),
            Match,
        ),
        (DeviceRef::HostnamePattern("HR-*".to_owned()), NoMatch),
        (DeviceRef::DeviceSet(set(PSET)), Match),
        (DeviceRef::DeviceSet(set(SSET)), NoMatch),
        (
            DeviceRef::DirectoryComputerGroup("S-1-5-21-1-2-3-4001".to_owned()),
            Match,
        ),
        (
            DeviceRef::Ou(OuRef {
                dn: "OU=Finance,DC=corp,DC=example,DC=org".to_owned(),
                include_sub_ous: false,
            }),
            NoMatch,
        ),
        (
            DeviceRef::Ou(OuRef {
                dn: "ou=finance,dc=corp,dc=example,dc=org".to_owned(),
                include_sub_ous: true,
            }),
            Match,
        ),
        (
            DeviceRef::CloudDeviceGroup(CloudObject {
                tenant_id: TENANT.to_owned(),
                object_id: CLOUD_GROUP.to_uppercase(),
            }),
            Match,
        ),
        (
            DeviceRef::CloudDeviceGroup(CloudObject {
                tenant_id: "7f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_owned(),
                object_id: CLOUD_GROUP.to_owned(),
            }),
            NoMatch,
        ),
        (DeviceRef::Tag("site=SYDNEY".to_owned()), Match),
        (DeviceRef::Tag("site=perth".to_owned()), NoMatch),
    ];
    for (i, (r, expected)) in cases.into_iter().enumerate() {
        assert_eq!(allow(&dev(r), &c), expected, "case {i}");
    }
    assert_eq!(
        allow(
            &dev(DeviceRef::Tag("x".to_owned())),
            &EvaluationContext::default()
        ),
        Unknown
    );
}

#[test]
fn cloud_device_groups_go_unknown_when_stale_and_name_missing_hosts() {
    let group = Scope {
        devices: Some(RefList {
            include: vec![],
            exclude: vec![DeviceRef::CloudDeviceGroup(CloudObject {
                tenant_id: TENANT.to_owned(),
                object_id: CLOUD_GROUP.to_owned(),
            })],
        }),
        ..Scope::default()
    };
    let mut c = ctx();
    assert_eq!(allow(&group, &c), NoMatch);
    c.scope.device_cloud_groups = Some(CachedGroups::new(
        MONDAY_10 - 2 * 86_400,
        [(TENANT, CLOUD_GROUP)],
    ));
    let (r, notes) = eval_with(&group, &c, Bias::Permissive);
    assert_eq!(r, Unknown);
    assert!(notes.contains(ScopeNote::ScopeStale));
    c.scope.device_cloud_groups = None;
    assert_eq!(allow(&group, &c), Unknown);
    // A host name that does not match, and no FQDN: unknown, and noted.
    let mut host = ctx();
    host.device.fqdn = None;
    let other = Scope {
        devices: Some(RefList {
            include: vec![DeviceRef::HostnamePattern("HR-*".to_owned())],
            exclude: vec![],
        }),
        ..Scope::default()
    };
    let (r, notes) = eval_with(&other, &host, Bias::Permissive);
    assert_eq!(r, Unknown);
    assert!(notes.contains(ScopeNote::FactMissing));
}

#[test]
fn network_dimension_table() {
    let c = ctx();
    let net = |include: Vec<NetworkRef>, exclude: Vec<NetworkRef>| Scope {
        network: Some(RefList { include, exclude }),
        ..Scope::default()
    };
    let one = |r: NetworkRef| net(vec![r], vec![]);
    let cases = [
        (one(NetworkRef::Cidr("192.168.0.0/16".to_owned())), Match),
        (one(NetworkRef::Cidr("10.0.0.0/8".to_owned())), NoMatch),
        (
            one(NetworkRef::Range("192.168.10.40-192.168.10.50".to_owned())),
            Match,
        ),
        (one(NetworkRef::DnsSuffix("example.org".to_owned())), Match),
        (
            one(NetworkRef::DnsSuffix("other.example".to_owned())),
            NoMatch,
        ),
        (
            one(NetworkRef::GatewayMac("00:1A:2B:3C:4D:5E".to_owned())),
            Match,
        ),
        (one(NetworkRef::ServerReachable(true)), Match),
        (one(NetworkRef::ServerReachable(false)), NoMatch),
        (
            one(NetworkRef::LocationProfile("Corporate".to_owned())),
            Match,
        ),
        (one(NetworkRef::NetworkSet(set(NSET))), Match),
        (one(NetworkRef::NetworkSet(set(PSET))), Unknown),
        (
            net(
                vec![NetworkRef::LocationProfile("corporate".to_owned())],
                vec![NetworkRef::Cidr("192.168.10.0/24".to_owned())],
            ),
            NoMatch,
        ),
    ];
    for (i, (scope, expected)) in cases.into_iter().enumerate() {
        assert_eq!(allow(&scope, &c), expected, "case {i}");
    }
}

#[test]
fn sessions_and_connecting_clients() {
    let c = ctx();
    let sessions = |types: Vec<SessionType>, client: Option<ClientFilter>| Scope {
        sessions: Some(SessionFilter { types, client }),
        ..Scope::default()
    };
    assert_eq!(allow(&sessions(vec![SessionType::Rdp], None), &c), Match);
    assert_eq!(
        allow(&sessions(vec![SessionType::Console], None), &c),
        NoMatch
    );
    assert_eq!(allow(&sessions(vec![], None), &c), Match);
    let client = |hostname: &[&str], ip: &[&str], sets: Vec<SetRef>| ClientFilter {
        hostname: hostname.iter().map(|s| (*s).to_owned()).collect(),
        ip: ip.iter().map(|s| (*s).to_owned()).collect(),
        device_sets: sets,
    };
    let cases = [
        (client(&["thin-*"], &[], vec![]), Match),
        (client(&["kiosk-*"], &[], vec![]), NoMatch),
        (client(&[], &["10.9.0.0/16"], vec![]), Match),
        (client(&[], &["10.9.8.1-10.9.8.6"], vec![]), NoMatch),
        (client(&[], &[], vec![set(NSET)]), Match),
        (
            client(&["thin-*"], &["10.0.0.0/8"], vec![set(PSET)]),
            NoMatch,
        ),
        (client(&["thin-*"], &["10.0.0.0/8"], vec![set(NSET)]), Match),
    ];
    for (i, (filter, expected)) in cases.into_iter().enumerate() {
        let s = sessions(vec![SessionType::Rdp], Some(filter));
        assert_eq!(allow(&s, &c), expected, "case {i}");
    }
    let mut no_client = c;
    no_client.session.client_ip = None;
    let s = sessions(vec![], Some(client(&[], &["10.0.0.0/8"], vec![])));
    assert_eq!(allow(&s, &no_client), Unknown);
}

#[test]
fn schedules_in_scopes_and_clock_integrity() {
    let mut c = ctx();
    let monday = Scope {
        schedule_set: Some(set(SSET)),
        ..Scope::default()
    };
    // 10:00 UTC on a Monday; the library schedule is all of Monday, UTC.
    assert_eq!(allow(&monday, &c), Match);
    let unresolved = Scope {
        schedule_set: Some(set(PSET)),
        ..Scope::default()
    };
    let (r, notes) = eval_with(&unresolved, &c, Bias::Permissive);
    assert_eq!(r, Unknown);
    assert!(notes.contains(ScopeNote::SetUnresolved));
    c.scope.time = Some(TrustedTime {
        unix_secs: c.scope.time.unwrap().unix_secs,
        trusted: false,
    });
    assert_eq!(allow(&monday, &c), NoMatch, "scheduled allows go inactive");
    assert_eq!(deny(&monday, &c), Match, "scheduled denies stay active");
}

#[test]
fn combine_and_negate_table() {
    let c = ctx();
    let yes = || {
        Some(RefList {
            include: vec![sid(FINANCE)],
            exclude: vec![],
        })
    };
    let no_net = || {
        Some(RefList {
            include: vec![NetworkRef::Cidr("10.0.0.0/8".to_owned())],
            exclude: vec![],
        })
    };
    let unknown_dev = || {
        Some(RefList {
            include: vec![DeviceRef::DeviceSet(set(SSET))],
            exclude: vec![],
        })
    };
    let mut no_sets = c.clone();
    no_sets.scope.device_sets = None;
    // (combine, negate, principals match?, network, devices unknown?, context, expected)
    let scope = |combine, negate, with_dev: bool| Scope {
        principals: yes(),
        network: no_net(),
        devices: if with_dev { unknown_dev() } else { None },
        combine,
        negate,
        ..Scope::default()
    };
    let cases = [
        (scope(Combine::All, false, false), &c, NoMatch),
        (scope(Combine::Any, false, false), &c, Match),
        (scope(Combine::All, true, false), &c, Match),
        (scope(Combine::Any, true, false), &c, NoMatch),
        (scope(Combine::All, false, true), &no_sets, NoMatch),
        (scope(Combine::Any, false, true), &no_sets, Match),
        (scope(Combine::All, true, true), &no_sets, Match),
    ];
    for (i, (s, ctx, expected)) in cases.into_iter().enumerate() {
        assert_eq!(allow(&s, ctx), expected, "case {i}");
    }
    // `all` of a match and an unknown is unknown, and its negation too.
    let unknown = Scope {
        principals: yes(),
        devices: unknown_dev(),
        ..Scope::default()
    };
    assert_eq!(allow(&unknown, &no_sets), Unknown);
    let negated = Scope {
        negate: true,
        ..unknown
    };
    assert_eq!(allow(&negated, &no_sets), Unknown);
}

#[test]
fn the_chain_names_the_failing_level_and_dimension() {
    let c = ctx();
    let ok = Arc::new(compile(&Scope::default()));
    let net = Arc::new(compile(&Scope {
        principals: Some(RefList {
            include: vec![sid(FINANCE)],
            exclude: vec![],
        }),
        network: Some(RefList {
            include: vec![NetworkRef::ServerReachable(false)],
            exclude: vec![],
        }),
        ..Scope::default()
    }));
    let chain = vec![
        (ScopeLevel::Policy, Arc::clone(&ok)),
        (ScopeLevel::RuleSet, net),
        (ScopeLevel::Rule, ok),
    ];
    let e = eval_chain(&chain, &c, Bias::Permissive);
    assert_eq!(e.result, NoMatch);
    assert_eq!(
        e.failure,
        Some(ScopeFailure {
            level: ScopeLevel::RuleSet,
            dimension: Some(Dimension::Network),
        })
    );
    assert_eq!(eval_chain(&[], &c, Bias::Permissive).result, Match);
}

#[test]
fn location_profiles_and_the_debounce() {
    let profiles = CompiledProfiles::compile_without_library(&[
        LocationProfile {
            name: "Corporate".to_owned(),
            all: vec![
                NetworkRef::DnsSuffix("corp.example.org".to_owned()),
                NetworkRef::ServerReachable(true),
            ],
        },
        LocationProfile {
            name: "home".to_owned(),
            all: vec![NetworkRef::ServerReachable(false)],
        },
    ]);
    let mut net = ctx().network;
    assert_eq!(profiles.active(&net), vec!["CORPORATE".to_owned()]);
    net.server_reachable = None;
    assert!(
        profiles.active(&net).is_empty(),
        "an unknown test is not active"
    );
    net.server_reachable = Some(false);
    assert_eq!(profiles.active(&net), vec!["HOME".to_owned()]);

    let mut tracker = LocationTracker::new();
    let corp = vec!["CORPORATE".to_owned()];
    let home = vec!["HOME".to_owned()];
    assert_eq!(tracker.observe(corp.clone(), 0), corp.as_slice());
    // A flap shorter than the debounce changes nothing.
    assert_eq!(tracker.observe(home.clone(), 1_000), corp.as_slice());
    assert_eq!(tracker.observe(corp.clone(), 2_000), corp.as_slice());
    assert_eq!(tracker.observe(home.clone(), 3_000), corp.as_slice());
    assert_eq!(tracker.observe(home.clone(), 7_999), corp.as_slice());
    // Stable for the debounce: it applies.
    assert_eq!(tracker.observe(home.clone(), 8_000), home.as_slice());
    assert_eq!(tracker.current(), Some(home.as_slice()));
}

// --- Properties ------------------------------------------------------------

fn principal_ref() -> impl Strategy<Value = PrincipalRef> + Clone {
    prop_oneof![
        proptest::sample::select(vec![ADMINS, USERS, FINANCE, "S-1-5-21-9-9-9-9"])
            .prop_map(|s| PrincipalRef::Sid(s.to_owned())),
        proptest::sample::select(WellKnown::ALL.to_vec()).prop_map(PrincipalRef::WellKnown),
        Just(PrincipalRef::UserPattern("*\\alice".to_owned())),
        Just(PrincipalRef::PrincipalSet(set(PSET))),
        Just(PrincipalRef::CloudGroup(CloudObject {
            tenant_id: TENANT.to_owned(),
            object_id: CLOUD_GROUP.to_owned(),
        })),
    ]
}

fn network_ref() -> impl Strategy<Value = NetworkRef> + Clone {
    prop_oneof![
        Just(NetworkRef::Cidr("192.168.0.0/16".to_owned())),
        Just(NetworkRef::Cidr("10.0.0.0/8".to_owned())),
        Just(NetworkRef::DnsSuffix("corp.example.org".to_owned())),
        any::<bool>().prop_map(NetworkRef::ServerReachable),
        Just(NetworkRef::NetworkSet(set(NSET))),
    ]
}

fn device_ref() -> impl Strategy<Value = DeviceRef> + Clone {
    prop_oneof![
        Just(DeviceRef::HostnamePattern("FIN-*".to_owned())),
        Just(DeviceRef::Tag("site=sydney".to_owned())),
        Just(DeviceRef::DeviceSet(set(PSET))),
        Just(DeviceRef::DeviceSet(set(SSET))),
    ]
}

fn list<T: core::fmt::Debug + Clone>(
    s: impl Strategy<Value = T> + Clone,
) -> impl Strategy<Value = Option<RefList<T>>> {
    proptest::option::of(
        (
            proptest::collection::vec(s.clone(), 0..3),
            proptest::collection::vec(s, 0..3),
        )
            .prop_map(|(include, exclude)| RefList { include, exclude }),
    )
}

fn scope() -> impl Strategy<Value = Scope> {
    (
        list(principal_ref()),
        list(device_ref()),
        list(network_ref()),
        proptest::option::of(proptest::collection::vec(
            proptest::sample::select(SessionType::ALL.to_vec()),
            0..3,
        )),
        proptest::option::of(Just(set(SSET))),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(principals, devices, network, types, schedule_set, any, negate)| Scope {
                principals,
                devices,
                network,
                sessions: types.map(|types| SessionFilter {
                    types,
                    client: None,
                }),
                schedule_set,
                combine: if any { Combine::Any } else { Combine::All },
                negate,
                ..Scope::default()
            },
        )
}

/// The full context with some facts removed, and the clock sometimes
/// untrusted.
fn context() -> impl Strategy<Value = EvaluationContext> {
    (any::<u16>(), any::<bool>(), any::<bool>()).prop_map(|(mask, trusted, admin)| {
        let mut c = ctx();
        if mask & 1 != 0 {
            c.scope.process_token = None;
        }
        if mask & 2 != 0 {
            c.network.addresses = None;
        }
        if mask & 4 != 0 {
            c.scope.device_sets = None;
        }
        if mask & 8 != 0 {
            c.session.session_type = None;
        }
        if mask & 16 != 0 {
            c.network.server_reachable = Some(false);
        }
        if mask & 32 != 0 {
            c.device.hostname = Some("HR-01".to_owned());
            c.device.fqdn = None;
        }
        if admin {
            c.scope.process_token = Some(
                Token::new()
                    .with_user(Some(ALICE), None)
                    .with_groups([(ADMINS, false)]),
            );
        }
        if let Some(t) = &mut c.scope.time {
            t.trusted = trusted;
        }
        c
    })
}

fn bias() -> impl Strategy<Value = Bias> {
    prop_oneof![Just(Bias::Permissive), Just(Bias::Restrictive)]
}

/// Truth order: `NoMatch < Unknown < Match`.
fn rank(t: Tri) -> u8 {
    match t {
        NoMatch => 0,
        Unknown => 1,
        Match => 2,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// When `exclude` holds every entry of `include`, a dimension never
    /// matches: whatever matches the include is excluded.
    #[test]
    fn exclude_covering_include_never_matches(
        include in proptest::collection::vec(principal_ref(), 0..4),
        extra in proptest::collection::vec(principal_ref(), 0..3),
        net in proptest::collection::vec(network_ref(), 0..4),
        c in context(),
        b in bias(),
    ) {
        let mut exclude = include.clone();
        exclude.extend(extra);
        // An empty include means everyone, so the exclude must cover a
        // non-empty include for the property to hold.
        prop_assume!(!include.is_empty());
        let p = principals(include, exclude);
        prop_assert_ne!(eval_with(&p, &c, b).0, Match);
        let mut net_ex = net.clone();
        net_ex.reverse();
        prop_assume!(!net.is_empty());
        let n = Scope {
            network: Some(RefList { include: net, exclude: net_ex }),
            ..Scope::default()
        };
        prop_assert_ne!(eval_with(&n, &c, b).0, Match);
    }

    /// Adding a scope to a chain never raises its result: a scope can only
    /// narrow a rule, never widen it.
    #[test]
    fn a_scope_only_narrows(
        chain in proptest::collection::vec(scope(), 0..3),
        extra in scope(),
        c in context(),
        b in bias(),
    ) {
        let compiled: Vec<(ScopeLevel, Arc<CompiledScope>)> = chain
            .iter()
            .map(|s| (ScopeLevel::RuleSet, Arc::new(compile(s))))
            .collect();
        let before = eval_chain(&compiled, &c, b).result;
        let mut with = compiled.clone();
        with.push((ScopeLevel::Rule, Arc::new(compile(&extra))));
        let after = eval_chain(&with, &c, b).result;
        prop_assert!(rank(after) <= rank(before), "{before:?} -> {after:?}");
        // And the order of the chain does not matter.
        with.reverse();
        prop_assert_eq!(eval_chain(&with, &c, b).result, after);
    }

    /// `negate` is exactly the Kleene negation of the scope without it.
    #[test]
    fn negate_is_kleene_not(s in scope(), c in context()) {
        // An untrusted clock and a deny-only group are read by what
        // makes the rule apply less or more, so compare without them.
        let mut c = c;
        if let Some(t) = &mut c.scope.time { t.trusted = true; }
        if c.scope.process_token.as_ref().is_some_and(Token::has_deny_only) {
            c.scope.process_token = Some(Token::new().with_user(Some(ALICE), None).with_groups([(USERS, false)]));
        }
        let plain = Scope { negate: false, ..s.clone() };
        let negated = Scope { negate: true, ..s };
        prop_assume!(plain.has_dimension());
        for b in [Bias::Permissive, Bias::Restrictive] {
            prop_assert_eq!(
                eval_with(&negated, &c, b).0,
                eval_with(&plain, &c, b).0.not()
            );
        }
    }

    /// With no deny-only groups, a permitting rule never reads a fact
    /// more permissively than a restricting one: for the same scope and
    /// facts, an allow's result is at most a deny's. (An untrusted clock
    /// is the case this covers.)
    #[test]
    fn allows_read_no_more_than_denies(s in scope(), c in context()) {
        prop_assert!(rank(allow(&s, &c)) <= rank(deny(&s, &c)));
    }

    /// A deny-only group takes, for each rule, the reading of the token
    /// (as if it were enabled, or absent) that makes an allow apply less
    /// and a deny apply more.
    #[test]
    fn deny_only_takes_the_restrictive_reading(
        s in scope(),
        groups in proptest::collection::vec(
            (proptest::sample::select(vec![ADMINS, USERS, FINANCE]), any::<bool>()),
            0..4,
        ),
    ) {
        let token = |gs: &[(&str, bool)]| {
            let mut c = ctx();
            c.scope.process_token =
                Some(Token::new().with_user(Some(ALICE), None).with_groups(gs.iter().copied()));
            c
        };
        let filtered = token(&groups);
        // A SID held both ways reads as deny-only.
        let deny_only: Vec<&str> = groups.iter().filter(|g| g.1).map(|g| g.0).collect();
        let absent: Vec<(&str, bool)> =
            groups.iter().filter(|g| !deny_only.contains(&g.0)).copied().collect();
        let enabled: Vec<(&str, bool)> = groups.iter().map(|g| (g.0, false)).collect();
        let (a, e) = (token(&absent), token(&enabled));
        let low = |x: Tri, y: Tri| if rank(x) <= rank(y) { x } else { y };
        let high = |x: Tri, y: Tri| if rank(x) >= rank(y) { x } else { y };
        prop_assert_eq!(allow(&s, &filtered), low(allow(&s, &a), allow(&s, &e)));
        prop_assert_eq!(deny(&s, &filtered), high(deny(&s, &a), deny(&s, &e)));
    }

    /// For the same facts, an allow never reads a scope more permissively
    /// than a deny.
    #[test]
    fn allows_read_no_more_than_denies_with_deny_only_groups(
        s in scope(),
        c in context(),
        filtered in any::<bool>(),
    ) {
        let mut c = c;
        if filtered {
            c.scope.process_token = Some(
                Token::new().with_user(Some(ALICE), None).with_groups([(USERS, false), (ADMINS, true)]),
            );
        }
        prop_assert!(rank(allow(&s, &c)) <= rank(deny(&s, &c)));
    }
}
