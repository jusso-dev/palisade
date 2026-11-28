//! Tests for context criteria (#33), with a mock context.

use proptest::prelude::*;

use super::{
    Date, DeviceContext, EvaluationContext, IntegrityLevel, NetworkContext, SessionContext,
    SessionType, TimeContext, UserContext, Weekday, normalize_object_id, normalize_principal,
    normalize_sid, parse_time_of_day,
};
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{ActionKind, Criterion, Field, FieldClass, Operator};
use crate::ops::{CompileErrorKind, CompiledCriterion, EvalContext, Note, Tri};

use Tri::{Match, NoMatch, Unknown};

const ADMINS: &str = "S-1-5-32-544";
const USERS: &str = "S-1-5-32-545";
const GROUP_ID: &str = "6F1C2A3B-4D5E-4F60-8A9B-0C1D2E3F4A5B";

fn crit(field: Field, operator: Operator, values: &[&str]) -> Criterion {
    Criterion::new(field, operator, values.iter().copied())
}

fn compile(field: Field, operator: Operator, values: &[&str]) -> CompiledCriterion {
    CompiledCriterion::compile(&crit(field, operator, values))
        .unwrap_or_else(|e| panic!("{field:?} {operator:?} {values:?}: {e:?}"))
}

fn compile_err(field: Field, operator: Operator, values: &[&str]) -> CompileErrorKind {
    match CompiledCriterion::compile(&crit(field, operator, values)) {
        Ok(_) => panic!("{field:?} {operator:?} {values:?} compiled"),
        Err(mut e) => e.remove(0).kind,
    }
}

fn eval_in(c: &CompiledCriterion, context: &EvaluationContext, action: ActionKind) -> (Tri, bool) {
    let variables = PathVariables::new();
    let ctx = EvalContext {
        action,
        variables: &variables,
        context,
    };
    let e = c.eval(&ObjectFacts::new(), &ctx);
    (e.result, e.notes.contains(Note::FactMissing))
}

fn eval(c: &CompiledCriterion, context: &EvaluationContext) -> Tri {
    eval_in(c, context, ActionKind::Deny).0
}

/// A context with every fact collected.
fn full() -> EvaluationContext {
    EvaluationContext {
        user: UserContext {
            sid: Some("S-1-5-21-1004336348-1177238915-682003330-1001".to_owned()),
            account_name: Some("EXAMPLE\\alice".to_owned()),
            upn: Some("alice@example.org".to_owned()),
            groups: Some(vec![
                USERS.to_owned(),
                "s-1-5-32-0544".to_owned(),
                GROUP_ID.to_ascii_lowercase(),
            ]),
            primary_group: Some("S-1-5-21-1004336348-1177238915-682003330-513".to_owned()),
            is_admin: Some(true),
            is_elevated: Some(false),
            is_service_account: Some(false),
            is_system: Some(false),
            integrity_level: Some(IntegrityLevel::Medium),
            dn: Some("CN=alice,OU=Accounts,OU=Finance,DC=corp,DC=example,DC=org".to_owned()),
        },
        device: DeviceContext {
            hostname: Some("WS-0042".to_owned()),
            fqdn: Some("ws-0042.corp.example.org".to_owned()),
            domain: Some("corp.example.org".to_owned()),
            netbios: Some("WS-0042".to_owned()),
            ad_site: Some("Sydney".to_owned()),
            groups: Some(vec!["S-1-5-21-1-2-3-4001".to_owned()]),
            tags: Some(vec!["Finance".to_owned(), "env.prod".to_owned()]),
            os_version: Some("10.0.22631.4460".to_owned()),
            os_edition: Some("Enterprise".to_owned()),
            arch: Some("x64".to_owned()),
            is_server: Some(false),
            is_domain_controller: Some(false),
            is_laptop: Some(true),
            is_vdi: Some(false),
            is_terminal_server: Some(false),
            os_build: Some(22631),
            dn: Some("CN=WS-0042,OU=Workstations,DC=corp,DC=example,DC=org".to_owned()),
            boot_phase: None,
            containment_available: None,
        },
        session: SessionContext {
            session_type: Some(SessionType::Rdp),
            client_hostname: Some("THIN-07".to_owned()),
            is_remote: Some(true),
            id: Some(3),
            client_ip: Some("192.168.10.25".parse().unwrap()),
        },
        network: NetworkContext {
            addresses: Some(vec![
                "10.20.30.40".parse().unwrap(),
                "fe80::1".parse().unwrap(),
            ]),
            macs: Some(vec![[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]]),
            dns_suffixes: Some(vec!["corp.example.org".to_owned()]),
            gateway_macs: Some(vec![[0xaa, 0xbb, 0xcc, 0xff, 0xff, 0x01]]),
            server_reachable: Some(true),
            locations: Some(vec!["corporate".to_owned()]),
        },
        time: TimeContext {
            weekday: Some(Weekday::Wed),
            minute_of_day: Some(9 * 60 + 30),
            date: Date::new(2026, 11, 25),
        },
        probes: crate::context::Probes::default()
            .with(
                Field::EnvVar,
                "BUILD",
                None,
                crate::context::Probe::Text("x".to_owned()),
            )
            .with(
                Field::RegKey,
                "HKLM\\Software\\X",
                None,
                crate::context::Probe::Present,
            )
            .with(
                Field::RegValue,
                "HKLM\\Software\\X",
                None,
                crate::context::Probe::Number(1),
            )
            .with(Field::FsFile, "C:\\x", None, crate::context::Probe::Absent)
            .with(
                Field::FsFolder,
                "C:\\x",
                None,
                crate::context::Probe::Present,
            ),
        process: crate::context::ProcessContext::with_command_line("a.exe x"),
        ..EvaluationContext::default()
    }
}

/// A valid criterion for each context field, with an operator that takes
/// values where the field has any.
fn sample(field: Field) -> Criterion {
    let target = match field {
        Field::EnvVar => "BUILD",
        Field::RegKey | Field::RegValue => "HKLM\\Software\\X",
        Field::FsFile | Field::FsFolder => "C:\\x",
        _ => "",
    };
    if field.is_probe() {
        let (operator, values): (Operator, &[&str]) = if field.class() == FieldClass::Presence {
            (Operator::Exists, &[])
        } else {
            (Operator::Equals, &["x"])
        };
        return Criterion {
            target: Some(target.to_owned()),
            ..crit(field, operator, values)
        };
    }
    match field.class() {
        FieldClass::Sid => crit(field, Operator::Equals, &[ADMINS]),
        FieldClass::PrincipalSet => crit(field, Operator::MemberOf, &[ADMINS]),
        FieldClass::TagSet => crit(field, Operator::MemberOf, &["finance"]),
        FieldClass::Bool => crit(field, Operator::IsTrue, &[]),
        FieldClass::SessionType => crit(field, Operator::Equals, &["console"]),
        FieldClass::Version => crit(field, Operator::VersionGe, &["10.0"]),
        FieldClass::Number => crit(field, Operator::Ge, &["1"]),
        FieldClass::IntegrityLevel => crit(field, Operator::Ge, &["medium"]),
        FieldClass::Date => crit(field, Operator::Ge, &["2026-01-01"]),
        FieldClass::DistinguishedName => crit(field, Operator::Equals, &["DC=example,DC=org"]),
        FieldClass::Ip => crit(field, Operator::IpInCidr, &["192.168.0.0/16"]),
        FieldClass::IpSet => crit(field, Operator::IpInCidr, &["10.0.0.0/8"]),
        FieldClass::MacSet => crit(field, Operator::MemberOf, &["aa:bb:cc:01:02:03"]),
        FieldClass::NameSet => crit(field, Operator::MemberOf, &["x"]),
        FieldClass::Weekday => crit(field, Operator::WeekdayIn, &["mon"]),
        FieldClass::TimeOfDay => crit(field, Operator::TimeBetween, &["08:00", "17:00"]),
        _ => crit(field, Operator::Equals, &["x"]),
    }
}

/// The negation of `sample`'s operator, where there is one.
fn negated(c: &Criterion) -> Option<Criterion> {
    let operator = match c.operator {
        Operator::Equals => Operator::NotEquals,
        Operator::MemberOf => Operator::NotMemberOf,
        Operator::IsTrue => Operator::IsFalse,
        Operator::Ge => Operator::Ne,
        Operator::Exists => Operator::NotExists,
        _ => return None,
    };
    Some(Criterion {
        operator,
        ..c.clone()
    })
}

#[test]
fn every_context_field_is_unknown_when_not_collected() {
    let empty = EvaluationContext::new();
    let fields: Vec<Field> = Field::ALL.into_iter().filter(|f| f.is_context()).collect();
    assert_eq!(fields.len(), 47);
    for field in fields {
        let c = sample(field);
        for c in std::iter::once(c.clone()).chain(negated(&c)) {
            let compiled = CompiledCriterion::compile(&c).unwrap();
            for action in [ActionKind::Allow, ActionKind::Deny, ActionKind::Audit] {
                let (result, missing) = eval_in(&compiled, &empty, action);
                assert_eq!(result, Unknown, "{field:?} {:?}", c.operator);
                assert!(missing, "{field:?}");
            }
            // And every collected fact gives a definite answer.
            assert_ne!(
                eval(&compiled, &full()),
                Unknown,
                "{field:?} {:?}",
                c.operator
            );
        }
    }
}

#[test]
fn context_fields_never_read_object_facts() {
    // An object fact recorded under a context field is ignored.
    let facts = ObjectFacts::new().with(Field::DeviceHostname, "WS-0042");
    assert_eq!(facts.get(Field::DeviceHostname), None);
    for field in Field::ALL {
        assert_eq!(field.is_context(), field.strength().is_none(), "{field:?}");
    }
}

#[test]
fn sids_compare_in_canonical_form() {
    for (raw, canonical) in [
        ("S-1-5-32-544", Some("S-1-5-32-544")),
        ("s-1-5-32-544", Some("S-1-5-32-544")),
        ("S-1-5-032-0544", Some("S-1-5-32-544")),
        ("S-1-0x000000000005-32-544", Some("S-1-5-32-544")),
        ("S-1-0X00000000000A-1", Some("S-1-10-1")),
        ("S-1-5-18", Some("S-1-5-18")),
        ("S-1-4294967295-1", Some("S-1-4294967295-1")),
        ("S-1-4294967296-1", None),
        ("S-1-5-4294967295", Some("S-1-5-4294967295")),
        ("S-1-5-4294967296", None),
        ("S-1-5", None),
        ("S-2-5-32", None),
        ("S-1-5--32", None),
        ("S-1-5-+32", None),
        ("S-1-0x5-32", None),
        (
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
            Some("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"),
        ),
        ("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", None),
        // Leading zeros never count towards the 10 significant digits.
        (
            "S-1-5-21-01004336348-1177238915-682003330-513",
            Some("S-1-5-21-1004336348-1177238915-682003330-513"),
        ),
        ("S-1-00000000005-32-0000000544", Some("S-1-5-32-544")),
        ("S-1-5-0", Some("S-1-5-0")),
        ("S-1-5-000", Some("S-1-5-0")),
        ("S-1-5-04294967295", Some("S-1-5-4294967295")),
        ("S-1-5-14294967295", None),
        // A 48-bit authority of 2^32 or more stays in hex, lowercase.
        ("S-1-0x000100000000-1", Some("S-1-0x000100000000-1")),
        ("s-1-0XFFFFFFFFFFFF-7", Some("S-1-0xffffffffffff-7")),
        ("S-1-0x0000FFFFFFFF-1", Some("S-1-4294967295-1")),
        ("S-1-0x00010000000-1", None),
        ("Administrators", None),
        ("", None),
    ] {
        assert_eq!(normalize_sid(raw).as_deref(), canonical, "{raw}");
        // The canonical form is canonical.
        if let Some(c) = canonical {
            assert_eq!(normalize_sid(c).as_deref(), Some(c), "{c}");
        }
    }
    let c = compile(
        Field::UserPrimaryGroup,
        Operator::Equals,
        &["s-1-5-21-1004336348-1177238915-682003330-0513"],
    );
    assert_eq!(eval(&c, &full()), Match);
    let c = compile(Field::UserSid, Operator::NotEquals, &["S-1-5-18"]);
    assert_eq!(eval(&c, &full()), Match);
    // A fact that is not a SID is unknown, never a mismatch.
    let mut odd = full();
    odd.user.sid = Some("alice".to_owned());
    let compiled = compile(Field::UserSid, Operator::NotEquals, &["S-1-5-18"]);
    let variables = PathVariables::new();
    let e = compiled.eval(
        &ObjectFacts::new(),
        &EvalContext {
            action: ActionKind::Deny,
            variables: &variables,
            context: &odd,
        },
    );
    assert_eq!(e.result, Unknown);
    assert!(e.notes.contains(Note::FactMalformed));
    // Values must be SIDs.
    assert!(matches!(
        compile_err(
            Field::UserSid,
            Operator::Equals,
            &["BUILTIN\\Administrators"]
        ),
        CompileErrorKind::InvalidValue(_)
    ));
}

#[test]
fn object_ids_are_guids_in_any_case() {
    assert_eq!(
        normalize_object_id(GROUP_ID).as_deref(),
        Some("6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b")
    );
    for bad in [
        "6f1c2a3b4d5e4f608a9b0c1d2e3f4a5b",
        "{6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5b}",
        "6f1c2a3b-4d5e-4f60-8a9b-0c1d2e3f4a5",
        "6f1c2a3g-4d5e-4f60-8a9b-0c1d2e3f4a5b",
    ] {
        assert_eq!(normalize_object_id(bad), None, "{bad}");
    }
    assert_eq!(normalize_principal(ADMINS).as_deref(), Some(ADMINS));
}

#[test]
fn group_membership() {
    let ctx = full();
    for (operator, values, expected) in [
        // The fact holds `s-1-5-32-0544`, the same SID.
        (Operator::MemberOf, vec![ADMINS], Match),
        (Operator::MemberOf, vec!["S-1-5-32-551", USERS], Match),
        (Operator::MemberOf, vec!["S-1-5-32-551"], NoMatch),
        (Operator::MemberOf, vec![GROUP_ID], Match),
        (Operator::NotMemberOf, vec![ADMINS], NoMatch),
        // Neither value: every value must be absent.
        (
            Operator::NotMemberOf,
            vec!["S-1-5-32-551", "S-1-5-32-552"],
            Match,
        ),
        (Operator::NotMemberOf, vec!["S-1-5-32-551", USERS], NoMatch),
    ] {
        let c = compile(Field::UserGroups, operator, &values);
        assert_eq!(eval(&c, &ctx), expected, "{operator:?} {values:?}");
    }
    // A known empty set holds nothing.
    let mut none = full();
    none.user.groups = Some(Vec::new());
    assert_eq!(
        eval(
            &compile(Field::UserGroups, Operator::MemberOf, &[ADMINS]),
            &none
        ),
        NoMatch
    );
    assert_eq!(
        eval(
            &compile(Field::UserGroups, Operator::NotMemberOf, &[ADMINS]),
            &none
        ),
        Match
    );
    // A member that is neither a SID nor an object ID is unknown, so it
    // cannot make `not_member_of` match; a readable member still decides.
    let mut junk = full();
    junk.user.groups = Some(vec!["Administrators".to_owned()]);
    let member = compile(Field::UserGroups, Operator::MemberOf, &[ADMINS]);
    let not_member = compile(Field::UserGroups, Operator::NotMemberOf, &[ADMINS]);
    assert_eq!(eval(&member, &junk), Unknown);
    assert_eq!(eval(&not_member, &junk), Unknown);
    junk.user.groups = Some(vec!["Administrators".to_owned(), ADMINS.to_owned()]);
    assert_eq!(eval(&member, &junk), Match);
    assert_eq!(eval(&not_member, &junk), NoMatch);
    // Device groups work the same way.
    let c = compile(
        Field::DeviceGroups,
        Operator::MemberOf,
        &["S-1-5-21-1-2-3-4001"],
    );
    assert_eq!(eval(&c, &ctx), Match);
    // Values must be SIDs or object IDs, and names are rejected.
    assert!(matches!(
        compile_err(Field::UserGroups, Operator::MemberOf, &["Domain Admins"]),
        CompileErrorKind::InvalidValue(_)
    ));
}

#[test]
fn tags_fold_case_unless_asked() {
    let ctx = full();
    assert_eq!(
        eval(
            &compile(Field::DeviceTags, Operator::MemberOf, &["FINANCE"]),
            &ctx
        ),
        Match
    );
    assert_eq!(
        eval(
            &compile(Field::DeviceTags, Operator::MemberOf, &["lab"]),
            &ctx
        ),
        NoMatch
    );
    assert_eq!(
        eval(
            &compile(Field::DeviceTags, Operator::NotMemberOf, &["lab"]),
            &ctx
        ),
        Match
    );
    let mut c = crit(Field::DeviceTags, Operator::MemberOf, &["FINANCE"]);
    c.case_sensitive = Some(true);
    let compiled = CompiledCriterion::compile(&c).unwrap();
    assert_eq!(eval(&compiled, &ctx), NoMatch);
}

#[test]
fn user_name_matches_either_form() {
    let ctx = full();
    for (operator, value, expected) in [
        (Operator::Equals, "example\\ALICE", Match),
        (Operator::Equals, "Alice@Example.org", Match),
        (Operator::Equals, "EXAMPLE\\bob", NoMatch),
        (Operator::EndsWith, "@example.org", Match),
        (Operator::Wildcard, "EXAMPLE\\*", Match),
        (Operator::NotEquals, "EXAMPLE\\alice", NoMatch),
        (Operator::NotEquals, "EXAMPLE\\bob", Match),
    ] {
        let c = compile(Field::UserName, operator, &[value]);
        assert_eq!(eval(&c, &ctx), expected, "{operator:?} {value}");
    }
    // With one form missing, a negative test cannot be satisfied: the
    // missing form might be the excluded name.
    let mut account_only = full();
    account_only.user.upn = None;
    let c = compile(Field::UserName, Operator::NotEquals, &["bob@example.org"]);
    assert_eq!(
        eval_in(&c, &account_only, ActionKind::Deny),
        (Unknown, true)
    );
    let c = compile(Field::UserName, Operator::Equals, &["EXAMPLE\\alice"]);
    // The account name decides, so the missing form is not even looked at.
    assert_eq!(eval_in(&c, &account_only, ActionKind::Deny), (Match, false));
    // Regular expressions are not allowed on principal names (#32).
    assert_eq!(
        compile_err(Field::UserName, Operator::Regex, &["EXAMPLE\\\\.*"]),
        CompileErrorKind::OperatorFieldMismatch
    );
    assert_eq!(
        compile_err(Field::UserName, Operator::NotRegex, &["x"]),
        CompileErrorKind::OperatorFieldMismatch
    );
}

#[test]
fn yes_or_no_facts() {
    let ctx = full();
    for (field, operator, expected) in [
        (Field::UserIsAdmin, Operator::IsTrue, Match),
        (Field::UserIsAdmin, Operator::IsFalse, NoMatch),
        (Field::UserIsElevated, Operator::IsTrue, NoMatch),
        (Field::UserIsElevated, Operator::IsFalse, Match),
        (Field::DeviceIsLaptop, Operator::IsTrue, Match),
        (Field::SessionIsRemote, Operator::IsFalse, NoMatch),
    ] {
        assert_eq!(
            eval(&compile(field, operator, &[]), &ctx),
            expected,
            "{field:?} {operator:?}"
        );
    }
    // They take no values.
    assert_eq!(
        compile_err(Field::UserIsAdmin, Operator::IsTrue, &["true"]),
        CompileErrorKind::ValueCount
    );
    assert_eq!(
        compile_err(Field::UserIsAdmin, Operator::Equals, &["true"]),
        CompileErrorKind::OperatorFieldMismatch
    );
}

#[test]
fn session_type_names() {
    let ctx = full();
    assert_eq!(
        eval(
            &compile(Field::SessionType, Operator::Equals, &["console", "rdp"]),
            &ctx
        ),
        Match
    );
    assert_eq!(
        eval(
            &compile(Field::SessionType, Operator::NotEquals, &["rdp"]),
            &ctx
        ),
        NoMatch
    );
    assert_eq!(
        eval(
            &compile(Field::SessionType, Operator::NotEquals, &["console"]),
            &ctx
        ),
        Match
    );
    for t in SessionType::ALL {
        assert_eq!(SessionType::from_name(t.as_str()), Some(t));
    }
    // Names are exact.
    assert!(matches!(
        compile_err(Field::SessionType, Operator::Equals, &["RDP"]),
        CompileErrorKind::InvalidValue(_)
    ));
}

#[test]
fn device_text_and_version_facts() {
    let ctx = full();
    for (field, operator, values, expected) in [
        (
            Field::DeviceHostname,
            Operator::Wildcard,
            vec!["ws-*"],
            Match,
        ),
        (
            Field::DeviceHostname,
            Operator::Regex,
            vec!["WS-[0-9]{4}"],
            Match,
        ),
        (
            Field::DeviceFqdn,
            Operator::EndsWith,
            vec![".corp.example.org"],
            Match,
        ),
        (
            Field::DeviceDomain,
            Operator::Equals,
            vec!["CORP.EXAMPLE.ORG"],
            Match,
        ),
        (
            Field::DeviceNetbios,
            Operator::NotEquals,
            vec!["WS-0042"],
            NoMatch,
        ),
        (
            Field::DeviceAdSite,
            Operator::Equals,
            vec!["Melbourne"],
            NoMatch,
        ),
        (
            Field::DeviceOsEdition,
            Operator::Contains,
            vec!["enter"],
            Match,
        ),
        (Field::DeviceArch, Operator::Equals, vec!["arm64"], NoMatch),
        (
            Field::DeviceOsVersion,
            Operator::VersionGe,
            vec!["10.0.22000"],
            Match,
        ),
        (
            Field::DeviceOsVersion,
            Operator::VersionBetween,
            vec!["10.0", "10.0.19045.9999"],
            NoMatch,
        ),
        (
            Field::DeviceOsVersion,
            Operator::Equals,
            vec!["10.0.22631.4460"],
            Match,
        ),
        (
            Field::SessionClientHostname,
            Operator::StartsWith,
            vec!["thin-"],
            Match,
        ),
    ] {
        let c = compile(field, operator, &values);
        assert_eq!(
            eval(&c, &ctx),
            expected,
            "{field:?} {operator:?} {values:?}"
        );
    }
    let mut odd = full();
    odd.device.os_version = Some("unknown".to_owned());
    let c = compile(Field::DeviceOsVersion, Operator::VersionGe, &["10.0"]);
    assert_eq!(eval(&c, &odd), Unknown);
}

#[test]
fn context_compatibility_table() {
    for field in Field::ALL.into_iter().filter(|f| f.is_context()) {
        let class = field.class();
        for op in Operator::ALL {
            let expected = match class {
                FieldClass::Sid | FieldClass::SessionType => {
                    matches!(op, Operator::Equals | Operator::NotEquals)
                }
                FieldClass::PrincipalSet
                | FieldClass::TagSet
                | FieldClass::NameSet
                | FieldClass::MacSet => matches!(
                    op,
                    Operator::MemberOf | Operator::NotMemberOf | Operator::AnyOf | Operator::AllOf
                ),
                FieldClass::Number | FieldClass::IntegrityLevel => op.is_ordered(),
                FieldClass::Date => op.is_ordered() || op == Operator::DateBetween,
                FieldClass::DistinguishedName => {
                    matches!(op, Operator::Equals | Operator::NotEquals)
                }
                FieldClass::Ip => {
                    op.is_network() || matches!(op, Operator::Equals | Operator::NotEquals)
                }
                FieldClass::IpSet => op.is_network() || op.is_set(),
                FieldClass::Weekday => op == Operator::WeekdayIn,
                FieldClass::TimeOfDay => op == Operator::TimeBetween,
                FieldClass::Bool => matches!(op, Operator::IsTrue | Operator::IsFalse),
                FieldClass::PrincipalName => op.is_text() && !op.is_regex(),
                FieldClass::Text => op.is_text(),
                FieldClass::Version => {
                    op.is_version() || matches!(op, Operator::Equals | Operator::NotEquals)
                }
                // Probed facts (#329).
                FieldClass::Presence => matches!(op, Operator::Exists | Operator::NotExists),
                FieldClass::ProbeValue => {
                    op.is_text()
                        || op.is_ordered()
                        || matches!(op, Operator::Exists | Operator::NotExists)
                }
                other => panic!("{field:?} has identity class {other:?}"),
            };
            assert_eq!(op.applies_to(class), expected, "{field:?} {op:?}");
        }
    }
    // The set, yes-or-no, ordered, network and time operators apply to no
    // identity field, except the set operators to `signer.eku` (#31), the
    // ordered ones to `meta.file_size` and the yes-or-no ones to
    // `meta.is_dotnet` and the yes-or-no `path.*` facts (#328).
    for field in Field::ALL
        .into_iter()
        .filter(|f| !f.is_context() && *f != Field::SignerEku)
    {
        for op in Operator::ALL.into_iter().filter(|op| {
            op.is_set()
                || op.is_ordered()
                || op.is_network()
                || matches!(
                    op,
                    Operator::IsTrue
                        | Operator::IsFalse
                        | Operator::Exists
                        | Operator::NotExists
                        | Operator::WeekdayIn
                        | Operator::TimeBetween
                        | Operator::DateBetween
                )
        }) {
            let expected = match field {
                Field::MetaFileSize => op.is_ordered(),
                Field::MetaIsDotnet
                | Field::PathIsUnc
                | Field::PathIsAds
                | Field::PathUserCanChangeAcl => matches!(op, Operator::IsTrue | Operator::IsFalse),
                _ => false,
            };
            assert_eq!(op.applies_to(field.class()), expected, "{field:?} {op:?}");
        }
    }
}

proptest! {
    #[test]
    fn sid_normalisation_is_idempotent(
        lower in any::<bool>(),
        authority in prop_oneof![0u64..64, 0u64..(1 << 32), 0u64..(1 << 48)],
        hex in any::<bool>(),
        zeros in 0usize..4,
        subs in proptest::collection::vec(any::<u32>(), 1..=15),
    ) {
        let pad = "0".repeat(zeros);
        let authority = if hex {
            format!("0x{authority:012X}")
        } else if authority < 1 << 32 {
            format!("{pad}{authority}")
        } else {
            format!("0x{authority:012x}")
        };
        let mut raw = format!("{}-1-{authority}", if lower { "s" } else { "S" });
        for sub in &subs {
            raw.push_str(&format!("-{pad}{sub}"));
        }
        let once = normalize_sid(&raw);
        prop_assert!(once.is_some(), "{}", raw);
        let once = once.unwrap();
        prop_assert_eq!(normalize_sid(&once), Some(once.clone()));
        // Every sub-authority survives, without its leading zeros.
        let tail: Vec<String> = subs.iter().map(u32::to_string).collect();
        prop_assert!(once.ends_with(&format!("-{}", tail.join("-"))), "{}", once);
    }

    #[test]
    fn sid_normalisation_never_panics(s in "\\PC{0,80}") {
        if let Some(once) = normalize_sid(&s) {
            prop_assert_eq!(normalize_sid(&once), Some(once.clone()));
        }
    }
}

/// One row per new operator on its context field: match, no match, and
/// unknown when the fact was not collected, with several values.
#[test]
fn numeric_level_date_operators() {
    let ctx = full();
    for (field, operator, values, expected) in [
        (
            Field::DeviceOsBuild,
            Operator::Eq,
            vec!["19045", "22631"],
            Match,
        ),
        (
            Field::DeviceOsBuild,
            Operator::Ne,
            vec!["19045", "22631"],
            NoMatch,
        ),
        (
            Field::DeviceOsBuild,
            Operator::Ne,
            vec!["19045", "22000"],
            Match,
        ),
        (Field::DeviceOsBuild, Operator::Gt, vec!["22631"], NoMatch),
        (Field::DeviceOsBuild, Operator::Ge, vec!["22631"], Match),
        (Field::DeviceOsBuild, Operator::Lt, vec!["22632"], Match),
        (Field::DeviceOsBuild, Operator::Le, vec!["22630"], NoMatch),
        (
            Field::DeviceOsBuild,
            Operator::Between,
            vec!["22000", "22631"],
            Match,
        ),
        (
            Field::DeviceOsBuild,
            Operator::Between,
            vec!["22632", "30000"],
            NoMatch,
        ),
        (Field::SessionId, Operator::Eq, vec!["0", "3"], Match),
        (
            Field::UserIntegrityLevel,
            Operator::Ge,
            vec!["medium"],
            Match,
        ),
        (
            Field::UserIntegrityLevel,
            Operator::Ge,
            vec!["high"],
            NoMatch,
        ),
        (Field::UserIntegrityLevel, Operator::Lt, vec!["high"], Match),
        (
            Field::UserIntegrityLevel,
            Operator::Between,
            vec!["low", "medium_plus"],
            Match,
        ),
        (Field::TimeDate, Operator::Ge, vec!["2026-11-25"], Match),
        (Field::TimeDate, Operator::Gt, vec!["2026-11-25"], NoMatch),
        (
            Field::TimeDate,
            Operator::DateBetween,
            vec!["2026-11-01", "2026-11-30"],
            Match,
        ),
        (
            Field::TimeDate,
            Operator::DateBetween,
            vec!["2026-12-01", "2026-12-31"],
            NoMatch,
        ),
    ] {
        let c = compile(field, operator, &values);
        assert_eq!(
            eval(&c, &ctx),
            expected,
            "{field:?} {operator:?} {values:?}"
        );
        assert_eq!(
            eval(&c, &EvaluationContext::new()),
            Unknown,
            "{field:?} {operator:?} on a missing fact"
        );
    }
    // Values must parse, and ranges be ordered.
    for (field, operator, values) in [
        (Field::DeviceOsBuild, Operator::Eq, vec!["-1"]),
        (Field::DeviceOsBuild, Operator::Eq, vec!["+1"]),
        (Field::DeviceOsBuild, Operator::Eq, vec!["1.5"]),
        (
            Field::DeviceOsBuild,
            Operator::Eq,
            vec!["99999999999999999999999"],
        ),
        (Field::DeviceOsBuild, Operator::Between, vec!["9", "1"]),
        (Field::UserIntegrityLevel, Operator::Eq, vec!["Medium"]),
        (Field::TimeDate, Operator::Ge, vec!["2026-02-30"]),
        (Field::TimeDate, Operator::Ge, vec!["26-1-1"]),
        (
            Field::TimeDate,
            Operator::DateBetween,
            vec!["2026-12-01", "2026-01-01"],
        ),
    ] {
        assert!(
            matches!(
                compile_err(field, operator, &values),
                CompileErrorKind::InvalidValue(_)
            ),
            "{field:?} {operator:?} {values:?}"
        );
    }
    assert_eq!(
        compile_err(Field::DeviceOsBuild, Operator::Gt, &["1", "2"]),
        CompileErrorKind::ValueCount
    );
    assert_eq!(
        compile_err(Field::DeviceOsBuild, Operator::VersionGe, &["1"]),
        CompileErrorKind::OperatorFieldMismatch
    );
    // Leap years.
    assert!(Date::parse("2024-02-29").is_some());
    assert!(Date::parse("2100-02-29").is_none());
    assert!(Date::parse("2000-02-29").is_some());
    assert!(Date::parse("0000-01-01").is_none());
    assert_eq!(Date::parse("2026-11-25").unwrap().to_string(), "2026-11-25");
}

#[test]
fn network_operators() {
    let ctx = full();
    for (field, operator, values, expected) in [
        (
            Field::SessionClientIp,
            Operator::IpInCidr,
            vec!["10.0.0.0/8", "192.168.0.0/16"],
            Match,
        ),
        (
            Field::SessionClientIp,
            Operator::IpInCidr,
            vec!["10.0.0.0/8"],
            NoMatch,
        ),
        (
            Field::SessionClientIp,
            Operator::IpBetween,
            vec!["192.168.10.20-30"],
            Match,
        ),
        (
            Field::SessionClientIp,
            Operator::IpBetween,
            vec!["192.168.10.26-30"],
            NoMatch,
        ),
        (
            Field::SessionClientIp,
            Operator::IpWildcard,
            vec!["192.168.*.*"],
            Match,
        ),
        (
            Field::SessionClientIp,
            Operator::IpWildcard,
            vec!["10.*.*.*"],
            NoMatch,
        ),
        (
            Field::SessionClientIp,
            Operator::Equals,
            vec!["::ffff:192.168.10.25"],
            Match,
        ),
        (
            Field::SessionClientIp,
            Operator::NotEquals,
            vec!["192.168.10.25"],
            NoMatch,
        ),
        // Any local address may match.
        (
            Field::NetIp,
            Operator::IpInCidr,
            vec!["10.20.0.0/16"],
            Match,
        ),
        (Field::NetIp, Operator::IpInCidr, vec!["fe80::/10"], Match),
        (
            Field::NetIp,
            Operator::IpInCidr,
            vec!["172.16.0.0/12"],
            NoMatch,
        ),
        (Field::NetIp, Operator::MemberOf, vec!["10.20.30.40"], Match),
        (
            Field::NetIp,
            Operator::AllOf,
            vec!["10.20.30.40", "fe80::1"],
            Match,
        ),
        (
            Field::NetIp,
            Operator::AllOf,
            vec!["10.20.30.40", "fe80::2"],
            NoMatch,
        ),
        (
            Field::NetMac,
            Operator::AnyOf,
            vec!["AA-BB-CC-01-02-03"],
            Match,
        ),
        (
            Field::NetMac,
            Operator::NotMemberOf,
            vec!["aabbcc010203"],
            NoMatch,
        ),
    ] {
        let c = compile(field, operator, &values);
        assert_eq!(
            eval(&c, &ctx),
            expected,
            "{field:?} {operator:?} {values:?}"
        );
        assert_eq!(
            eval(&c, &EvaluationContext::new()),
            Unknown,
            "{field:?} {operator:?}"
        );
    }
    for (field, operator, value) in [
        (Field::NetIp, Operator::IpInCidr, "10.1.2.3/8"),
        (Field::NetIp, Operator::IpBetween, "10.0.0.9-1"),
        (Field::NetIp, Operator::IpWildcard, "10.*"),
        (Field::SessionClientIp, Operator::Equals, "server01"),
        (Field::NetMac, Operator::MemberOf, "aa:bb:cc"),
    ] {
        assert!(
            matches!(
                compile_err(field, operator, &[value]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{field:?} {operator:?} {value}"
        );
    }
    // A known empty set of addresses holds none.
    let mut none = full();
    none.network.addresses = Some(Vec::new());
    assert_eq!(
        eval(
            &compile(Field::NetIp, Operator::IpInCidr, &["0.0.0.0/0"]),
            &none
        ),
        NoMatch
    );
}

#[test]
fn set_operators_any_and_all() {
    let ctx = full();
    for (operator, values, expected) in [
        (Operator::AnyOf, vec!["S-1-5-32-551", USERS], Match),
        (Operator::AnyOf, vec!["S-1-5-32-551"], NoMatch),
        (Operator::AllOf, vec![ADMINS, USERS], Match),
        (Operator::AllOf, vec![ADMINS, "S-1-5-32-551"], NoMatch),
        (Operator::AllOf, vec![GROUP_ID, USERS], Match),
    ] {
        let c = compile(Field::UserGroups, operator, &values);
        assert_eq!(eval(&c, &ctx), expected, "{operator:?} {values:?}");
    }
    // `all_of` with an unreadable member is unknown unless a value is
    // missing from what can be read.
    let mut junk = full();
    junk.user.groups = Some(vec!["Administrators".to_owned(), ADMINS.to_owned()]);
    assert_eq!(
        eval(
            &compile(Field::UserGroups, Operator::AllOf, &[ADMINS]),
            &junk
        ),
        Match
    );
    assert_eq!(
        eval(
            &compile(Field::UserGroups, Operator::AllOf, &[ADMINS, USERS]),
            &junk
        ),
        Unknown
    );
    // Tags and names.
    for (field, operator, values, expected) in [
        (
            Field::DeviceTags,
            Operator::AllOf,
            vec!["finance", "ENV.PROD"],
            Match,
        ),
        (
            Field::DeviceTags,
            Operator::AllOf,
            vec!["finance", "lab"],
            NoMatch,
        ),
        (
            Field::NetDnsSuffix,
            Operator::AnyOf,
            vec!["CORP.example.org"],
            Match,
        ),
        (
            Field::NetLocation,
            Operator::MemberOf,
            vec!["corporate"],
            Match,
        ),
        (
            Field::NetLocation,
            Operator::NotMemberOf,
            vec!["offline", "remote"],
            Match,
        ),
    ] {
        let c = compile(field, operator, &values);
        assert_eq!(
            eval(&c, &ctx),
            expected,
            "{field:?} {operator:?} {values:?}"
        );
    }
}

#[test]
fn time_operators() {
    let mut ctx = full();
    let day = |values: &[&str]| compile(Field::TimeWeekday, Operator::WeekdayIn, values);
    assert_eq!(eval(&day(&["mon", "wed"]), &ctx), Match);
    assert_eq!(eval(&day(&["sat", "sun"]), &ctx), NoMatch);
    assert!(matches!(
        compile_err(Field::TimeWeekday, Operator::WeekdayIn, &["Monday"]),
        CompileErrorKind::InvalidValue(_)
    ));
    let window = |a: &str, b: &str| compile(Field::TimeLocalTime, Operator::TimeBetween, &[a, b]);
    // 09:30: inside a day window, outside a night window that wraps.
    assert_eq!(eval(&window("08:00", "17:00"), &ctx), Match);
    assert_eq!(eval(&window("22:00", "06:00"), &ctx), NoMatch);
    // The end is excluded and the start included.
    assert_eq!(eval(&window("09:30", "10:00"), &ctx), Match);
    assert_eq!(eval(&window("08:00", "09:30"), &ctx), NoMatch);
    for (minute, expected) in [
        (23 * 60, Match),
        (0, Match),
        (5 * 60 + 59, Match),
        (6 * 60, NoMatch),
    ] {
        ctx.time.minute_of_day = Some(minute);
        assert_eq!(eval(&window("22:00", "06:00"), &ctx), expected, "{minute}");
    }
    // A minute past the end of the day is not a time.
    ctx.time.minute_of_day = Some(24 * 60);
    assert_eq!(eval(&window("00:00", "23:59"), &ctx), Unknown);
    for bad in [
        ["24:00", "01:00"],
        ["9:00", "10:00"],
        ["09:60", "10:00"],
        ["10:00", "10:00"],
    ] {
        assert!(
            matches!(
                compile_err(Field::TimeLocalTime, Operator::TimeBetween, &bad),
                CompileErrorKind::InvalidValue(_)
            ),
            "{bad:?}"
        );
    }
    assert_eq!(parse_time_of_day("23:59"), Some(1439));
    assert_eq!(parse_time_of_day("00:00"), Some(0));
    assert_eq!(parse_time_of_day("0:00"), None);
}

#[test]
fn organisational_units() {
    let ctx = full();
    // alice is in OU=Accounts,OU=Finance,DC=corp,DC=example,DC=org.
    let ou = |field, value: &str, sub: Option<bool>| {
        let mut c = crit(field, Operator::Equals, &[value]);
        c.include_sub_ous = sub;
        CompiledCriterion::compile(&c).unwrap()
    };
    let finance = "OU=Finance,DC=corp,DC=example,DC=org";
    let accounts = "ou=accounts, OU=Finance,dc=CORP,DC=example,DC=org";
    assert_eq!(eval(&ou(Field::UserOu, accounts, None), &ctx), Match);
    assert_eq!(eval(&ou(Field::UserOu, finance, None), &ctx), NoMatch);
    assert_eq!(eval(&ou(Field::UserOu, finance, Some(true)), &ctx), Match);
    assert_eq!(
        eval(
            &ou(Field::UserOu, "OU=Fin,DC=example,DC=org", Some(true)),
            &ctx
        ),
        NoMatch
    );
    assert_eq!(
        eval(
            &ou(
                Field::DeviceOu,
                "OU=Workstations,DC=corp,DC=example,DC=org",
                None
            ),
            &ctx
        ),
        Match
    );
    // A distinguished name that cannot be read is unknown.
    let mut odd = full();
    odd.user.dn = Some("not a dn".to_owned());
    assert_eq!(eval(&ou(Field::UserOu, finance, Some(true)), &odd), Unknown);
    // The option only applies to these fields.
    let mut c = crit(Field::DeviceHostname, Operator::Equals, &["x"]);
    c.include_sub_ous = Some(true);
    assert!(matches!(
        CompiledCriterion::compile(&c).unwrap_err()[0].kind,
        CompileErrorKind::OptionNotApplicable("include_sub_ous", _)
    ));
    assert!(matches!(
        compile_err(Field::UserOu, Operator::Equals, &["Finance"]),
        CompileErrorKind::InvalidValue(_)
    ));
}

#[test]
fn distinguished_names_compare_after_decoding_their_escapes() {
    let unit = |value: &str| {
        CompiledCriterion::compile(&crit(Field::UserOu, Operator::Equals, &[value])).unwrap()
    };
    let in_dn = |dn: &str| {
        let mut ctx = full();
        ctx.user.dn = Some(dn.to_owned());
        ctx
    };
    // `\,` and `\2C` are the same comma, kept inside the component.
    let rule = unit(r"OU=Sales\, West,DC=corp");
    assert_eq!(
        eval(&rule, &in_dn(r"CN=Alice,OU=Sales\2C West,DC=corp")),
        Match
    );
    assert_eq!(
        eval(&rule, &in_dn(r"CN=Alice,OU=Sales\, West,DC=corp")),
        Match
    );
    assert_eq!(
        eval(
            &unit(r"OU=Sales\2c West,DC=corp"),
            &in_dn(r"CN=Alice,OU=Sales\, West,DC=corp")
        ),
        Match
    );
    // The escaped comma does not split the unit.
    assert_eq!(
        eval(&rule, &in_dn("CN=Alice,OU=Sales,OU= West,DC=corp")),
        NoMatch
    );
    // Hex escapes decode as UTF-8, and other special characters escape too.
    assert_eq!(
        eval(
            &unit("OU=Caf\\C3\\A9,DC=corp"),
            &in_dn("CN=x,OU=café,DC=corp")
        ),
        Match
    );
    assert_eq!(
        eval(
            &unit(r"OU=a\+b\=c,DC=corp"),
            &in_dn("CN=x,OU=a\\2Bb\\3Dc,DC=corp")
        ),
        Match
    );
    // An escape RFC 4514 does not define: an invalid rule value, and an
    // unknown fact.
    for bad in [
        r"OU=Sa\qles,DC=corp",
        r"OU=Sales\",
        r"OU=Sales\2,DC=corp",
        r"OU=\FF,DC=corp",
    ] {
        assert!(
            matches!(
                compile_err(Field::UserOu, Operator::Equals, &[bad]),
                CompileErrorKind::InvalidValue(_)
            ),
            "{bad}"
        );
        let mut c = crit(Field::UserOu, Operator::Equals, &["OU=Sales,DC=corp"]);
        c.safety_critical = true;
        let c = CompiledCriterion::compile(&c).unwrap();
        let (result, _) = eval_in(&c, &in_dn(&format!("CN=x,{bad}")), ActionKind::Deny);
        assert_eq!(result, Unknown, "{bad}");
    }
}

#[test]
fn new_facts_are_read_from_their_place() {
    let ctx = full();
    assert_eq!(
        eval(
            &compile(Field::NetConnectedToServer, Operator::IsTrue, &[]),
            &ctx
        ),
        Match
    );
    let mut off = full();
    off.network.server_reachable = Some(false);
    assert_eq!(
        eval(
            &compile(Field::NetConnectedToServer, Operator::IsTrue, &[]),
            &off
        ),
        NoMatch
    );
    for level in IntegrityLevel::ALL {
        assert_eq!(IntegrityLevel::from_name(level.as_str()), Some(level));
    }
    for day in Weekday::ALL {
        assert_eq!(Weekday::from_name(day.as_str()), Some(day));
    }
    assert_eq!(EvaluationContext::EMPTY, EvaluationContext::new());
}

/// Every ordered operator against a value below, at and above the fact,
/// for each kind of ordered fact, so no comparison can point the wrong way.
#[test]
fn ordered_operators_compare_in_the_right_direction() {
    let ctx = full();
    // (field, below, at, above) for facts 22631, `medium` and 2026-11-25.
    let kinds = [
        (Field::DeviceOsBuild, "22630", "22631", "22632"),
        (Field::UserIntegrityLevel, "low", "medium", "medium_plus"),
        (Field::TimeDate, "2026-11-24", "2026-11-25", "2026-11-26"),
    ];
    for (field, below, at, above) in kinds {
        for (operator, expect) in [
            (Operator::Eq, [NoMatch, Match, NoMatch]),
            (Operator::Ne, [Match, NoMatch, Match]),
            (Operator::Gt, [Match, NoMatch, NoMatch]),
            (Operator::Ge, [Match, Match, NoMatch]),
            (Operator::Lt, [NoMatch, NoMatch, Match]),
            (Operator::Le, [NoMatch, Match, Match]),
        ] {
            for (value, expected) in [below, at, above].into_iter().zip(expect) {
                let c = compile(field, operator, &[value]);
                assert_eq!(eval(&c, &ctx), expected, "{field:?} {operator:?} {value}");
            }
        }
        // `between` includes both ends, and excludes a range beside the fact.
        for (range, expected) in [
            ([below, at], Match),
            ([at, above], Match),
            ([at, at], Match),
            ([below, below], NoMatch),
            ([above, above], NoMatch),
        ] {
            let c = compile(field, Operator::Between, &range);
            assert_eq!(eval(&c, &ctx), expected, "{field:?} between {range:?}");
        }
    }
}
