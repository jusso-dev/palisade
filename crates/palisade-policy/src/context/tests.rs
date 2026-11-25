//! Tests for context criteria (#33), with a mock context.

use proptest::prelude::*;

use super::{
    DeviceContext, EvaluationContext, SessionContext, SessionType, UserContext,
    normalize_object_id, normalize_principal, normalize_sid,
};
use crate::facts::{ObjectFacts, PathVariables};
use crate::model::{ActionKind, Criterion, Field, FieldClass, Operator};
use crate::ops::{CompileErrorKind, CompiledCriterion, EvalContext, Note, Tri};

use Tri::{Match, NoMatch, Unknown};

const ADMINS: &str = "S-1-5-32-544";
const USERS: &str = "S-1-5-32-545";
const GROUP_ID: &str = "6F1C2A3B-4D5E-4F60-8A9B-0C1D2E3F4A5B";

fn crit(field: Field, operator: Operator, values: &[&str]) -> Criterion {
    Criterion {
        field,
        operator,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: None,
    }
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
            dn: Some("CN=WS-0042,OU=Finance,DC=corp,DC=example,DC=org".to_owned()),
        },
        session: SessionContext {
            session_type: Some(SessionType::Rdp),
            client_hostname: Some("THIN-07".to_owned()),
            is_remote: Some(true),
            client_ip: Some("10.1.2.3".parse().unwrap()),
        },
        ..EvaluationContext::default()
    }
}

/// A valid criterion for each context field, with an operator that takes
/// values where the field has any.
fn sample(field: Field) -> Criterion {
    match field.class() {
        FieldClass::Sid => crit(field, Operator::Equals, &[ADMINS]),
        FieldClass::PrincipalSet => crit(field, Operator::MemberOf, &[ADMINS]),
        FieldClass::TagSet => crit(field, Operator::MemberOf, &["finance"]),
        FieldClass::Bool => crit(field, Operator::IsTrue, &[]),
        FieldClass::SessionType => crit(field, Operator::Equals, &["console"]),
        FieldClass::Version => crit(field, Operator::VersionGe, &["10.0"]),
        _ => crit(field, Operator::Equals, &["x"]),
    }
}

/// The negation of `sample`'s operator, where there is one.
fn negated(c: &Criterion) -> Option<Criterion> {
    let operator = match c.operator {
        Operator::Equals => Operator::NotEquals,
        Operator::MemberOf => Operator::NotMemberOf,
        Operator::IsTrue => Operator::IsFalse,
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
    assert_eq!(fields.len(), 26);
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
                FieldClass::PrincipalSet | FieldClass::TagSet => {
                    matches!(op, Operator::MemberOf | Operator::NotMemberOf)
                }
                FieldClass::Bool => matches!(op, Operator::IsTrue | Operator::IsFalse),
                FieldClass::PrincipalName => op.is_text() && !op.is_regex(),
                FieldClass::Text => op.is_text(),
                FieldClass::Version => {
                    op.is_version() || matches!(op, Operator::Equals | Operator::NotEquals)
                }
                other => panic!("{field:?} has identity class {other:?}"),
            };
            assert_eq!(op.applies_to(class), expected, "{field:?} {op:?}");
        }
    }
    // The set and yes-or-no operators apply to no identity field.
    for field in Field::ALL.into_iter().filter(|f| !f.is_context()) {
        for op in [
            Operator::MemberOf,
            Operator::NotMemberOf,
            Operator::IsTrue,
            Operator::IsFalse,
        ] {
            assert!(!op.applies_to(field.class()), "{field:?} {op:?}");
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
