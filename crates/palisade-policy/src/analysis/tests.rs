//! Tests of the policy assistant (#40): a positive and a negative fixture
//! per check, the publish gate, and property tests that conflict findings
//! are true.

use proptest::prelude::*;

use super::*;
use crate::context::EvaluationContext;
use crate::decision::TraceId;
use crate::evaluate::{Evaluator, Subject};
use crate::facts::{
    ObjectFacts, PathFact, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use crate::model::ObjectType;

const POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";
const SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001";
const MANDATORY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0002";
const CURATED: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0003";
/// 2026-11-25T00:00:00Z.
const NOW: Timestamp = Timestamp(1_795_564_800);

fn t(days: i64) -> Timestamp {
    Timestamp(NOW.0 + days * 86_400)
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn rule_id(n: u32) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61")
}

fn crit(field: &str, op: &str, values: &[&str]) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": op, "values": values}})
}

fn hash(c: char) -> serde_json::Value {
    crit("hash.sha256", "equals", &[&sha(c)])
}

fn rule(n: u32, tree: serde_json::Value, action: &str) -> serde_json::Value {
    serde_json::json!({"id": rule_id(n), "name": format!("R{n}"), "match": tree, "action": {"type": action}})
}

fn with(mut r: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    for (k, v) in extra.as_object().unwrap() {
        r.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    r
}

/// `(id, kind, mandatory, read_only, rules)`.
type Set = (
    &'static str,
    &'static str,
    bool,
    bool,
    Vec<serde_json::Value>,
);

fn doc(policy: serde_json::Value, sets: Vec<Set>) -> PolicyDocument {
    let mut p = serde_json::json!({
        "id": POLICY, "name": "Lint", "revision": 1, "mode": "enforce",
        "rule_sets": sets.iter().map(|s| s.0).collect::<Vec<_>>(),
    });
    for (k, v) in policy.as_object().unwrap() {
        p.as_object_mut().unwrap().insert(k.clone(), v.clone());
    }
    let rule_sets: Vec<serde_json::Value> = sets
        .iter()
        .map(|(id, kind, m, ro, rules)| serde_json::json!({"id": id, "name": "S", "kind": kind, "mandatory": m, "read_only": ro, "rules": rules}))
        .collect();
    let json = serde_json::json!({"schema_version": "1.0.0", "policy": p, "rule_sets": rule_sets});
    let d = PolicyDocument::from_json(&json.to_string()).unwrap();
    // Every fixture is a policy that validation accepts.
    d.clone().validate().unwrap_or_else(|e| panic!("{e:#?}"));
    d
}

fn mixed(rules: Vec<serde_json::Value>) -> PolicyDocument {
    doc(
        serde_json::json!({}),
        vec![(SET, "mixed", false, false, rules)],
    )
}

fn lint(d: &PolicyDocument, facts: &Facts) -> Vec<(FindingCode, Vec<String>)> {
    analyse(d, facts, NOW)
        .into_iter()
        .map(|f| {
            (
                f.code,
                f.rule_refs.iter().map(|r| r.rule_id.to_string()).collect(),
            )
        })
        .collect()
}

fn has(found: &[(FindingCode, Vec<String>)], code: FindingCode, first: u32) -> bool {
    found
        .iter()
        .any(|(c, r)| *c == code && r.first() == Some(&rule_id(first)))
}

fn none_of(found: &[(FindingCode, Vec<String>)], code: FindingCode) -> bool {
    !found.iter().any(|(c, _)| *c == code)
}

// ----------------------------------------------------------- identity

#[test]
fn weak_identity() {
    let name = serde_json::json!({"all": [crit("path.file_name", "equals", &["a.exe"]), crit("meta.product_name", "equals", &["A"])]});
    let path = crit("path.directory", "starts_with", &["C:\\Tools"]);
    let found = lint(
        &mixed(vec![
            rule(1, name, "allow"),
            rule(2, path, "allow"),
            rule(3, hash('a'), "allow"),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::WeakIdentity, 1));
    assert!(has(&found, FindingCode::WeakIdentity, 2));
    assert!(!has(&found, FindingCode::WeakIdentity, 3));
}

#[test]
fn user_writable_path_allow() {
    let facts = Facts {
        writable_dirs: vec!["C:\\Tools\\Drop".into()],
        ..Facts::default()
    };
    let found = lint(
        &mixed(vec![
            rule(
                1,
                crit("path.directory", "starts_with", &["C:\\Tools"]),
                "allow",
            ),
            rule(
                2,
                crit("path.directory", "starts_with", &["C:\\Other"]),
                "allow",
            ),
            rule(
                3,
                crit("path.directory", "starts_with", &["c:\\tools\\drop\\x"]),
                "allow",
            ),
        ]),
        &facts,
    );
    assert!(has(&found, FindingCode::UserWritablePathAllow, 1));
    assert!(has(&found, FindingCode::UserWritablePathAllow, 3));
    assert!(!has(&found, FindingCode::UserWritablePathAllow, 2));
    assert!(has(&found, FindingCode::WeakIdentity, 2));
}

#[test]
fn restricted_publisher_broad() {
    let facts = Facts {
        restricted_publishers: vec!["OS Publisher".into()],
        ..Facts::default()
    };
    let broad = crit("signer.publisher", "equals", &["os publisher"]);
    let narrow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["OS Publisher"]), crit("meta.product_name", "equals", &["Calculator"])]});
    let other = crit("signer.publisher", "equals", &["Example Ltd"]);
    let found = lint(
        &mixed(vec![
            rule(1, broad.clone(), "allow"),
            rule(2, narrow, "allow"),
            rule(3, other, "allow"),
            rule(4, broad, "deny"),
        ]),
        &facts,
    );
    assert!(has(&found, FindingCode::RestrictedPublisherBroad, 1));
    assert!(!has(&found, FindingCode::RestrictedPublisherBroad, 2));
    assert!(!has(&found, FindingCode::RestrictedPublisherBroad, 3));
    assert!(!has(&found, FindingCode::RestrictedPublisherBroad, 4));
}

/// CodeRabbit (analysis/mod.rs:706): a restricted publisher is named by
/// any operator that matches it, not only by an equal value.
#[test]
fn restricted_publishers_are_matched_with_the_criterion_operator() {
    let facts = Facts {
        restricted_publishers: vec!["Example Ltd".into()],
        ..Facts::default()
    };
    let found = lint(
        &mixed(vec![
            rule(
                1,
                crit("signer.publisher", "starts_with", &["Example"]),
                "allow",
            ),
            rule(
                2,
                crit("signer.publisher", "wildcard", &["*ample*"]),
                "allow",
            ),
            rule(
                3,
                crit("signer.publisher", "starts_with", &["Other"]),
                "allow",
            ),
            rule(
                4,
                crit("signer.publisher", "equals", &["example ltd"]),
                "allow",
            ),
        ]),
        &facts,
    );
    for n in [1, 2, 4] {
        assert!(
            has(&found, FindingCode::RestrictedPublisherBroad, n),
            "{n}: {found:?}"
        );
    }
    assert!(!has(&found, FindingCode::RestrictedPublisherBroad, 3));
}

#[test]
fn broad_wildcard() {
    let with_pub = |w: &str| serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("path.full", "wildcard", &[w])]});
    let found = lint(
        &mixed(vec![
            rule(1, with_pub("C:\\*"), "allow"),
            rule(2, with_pub("*\\*.exe"), "allow"),
            rule(3, with_pub("**"), "allow"),
            rule(4, with_pub("C:\\Program Files\\Example\\**"), "allow"),
            rule(5, with_pub("C:\\**\\*.exe"), "allow"),
        ]),
        &Facts::default(),
    );
    for n in [1, 2, 3, 5] {
        assert!(has(&found, FindingCode::BroadWildcard, n), "{n}: {found:?}");
    }
    assert!(!has(&found, FindingCode::BroadWildcard, 4));
    // A regular expression that matches much of a sample corpus.
    let corpus: Vec<String> = (0..10).map(|i| format!("C:\\App{i}\\a.exe")).collect();
    let re = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("path.full", "regex", &["C:\\\\App[0-4]\\\\.*"])]});
    let narrow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("path.full", "regex", &["C:\\\\App1\\\\.*"])]});
    let found = lint(
        &mixed(vec![rule(1, re, "allow"), rule(2, narrow, "allow")]),
        &Facts {
            path_corpus: corpus,
            ..Facts::default()
        },
    );
    assert!(has(&found, FindingCode::BroadWildcard, 1));
    assert!(!has(&found, FindingCode::BroadWildcard, 2));
}

#[test]
fn regex_cost() {
    let big = serde_json::json!({"all": [hash('a'), crit("meta.product_name", "regex", &["(\\w{20}){1}"])]});
    let small =
        serde_json::json!({"all": [hash('b'), crit("meta.product_name", "regex", &["ab+c"])]});
    let found = lint(
        &mixed(vec![rule(1, big, "deny"), rule(2, small, "deny")]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::RegexCost, 1), "{found:?}");
    assert!(!has(&found, FindingCode::RegexCost, 2));
    assert!(regex_near_limit("(\\w{20}){1}", false));
    assert!(!regex_near_limit("ab+c", false));
    // Over the limit is validation's error, not this warning.
    assert!(!regex_near_limit("(\\w{20}){10}", false));
}

#[test]
fn revoked_or_expired_signer() {
    let facts = Facts {
        certificates: BTreeMap::from([
            ("Gone Ltd".into(), CertificateState::Revoked),
            (sha('C'), CertificateState::Expired),
        ]),
        ..Facts::default()
    };
    let found = lint(
        &mixed(vec![
            rule(
                1,
                crit("signer.publisher", "equals", &["gone ltd"]),
                "allow",
            ),
            rule(
                2,
                crit("signer.leaf_thumbprint", "equals", &[&sha('c')]),
                "allow",
            ),
            rule(
                3,
                crit("signer.publisher", "equals", &["Example Ltd"]),
                "allow",
            ),
            rule(4, crit("signer.publisher", "equals", &["Gone Ltd"]), "deny"),
        ]),
        &facts,
    );
    assert!(has(&found, FindingCode::RevokedOrExpiredSigner, 1));
    assert!(has(&found, FindingCode::RevokedOrExpiredSigner, 2));
    assert!(!has(&found, FindingCode::RevokedOrExpiredSigner, 3));
    assert!(!has(&found, FindingCode::RevokedOrExpiredSigner, 4));
}

// ---------------------------------------------------------- duplicates

#[test]
fn duplicate_rule() {
    let a =
        serde_json::json!({"all": [hash('A'), crit("signer.publisher", "equals", &["X", "y"])]});
    let b =
        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Y", "x"]), hash('a')]});
    let found = lint(
        &mixed(vec![
            rule(1, a, "allow"),
            rule(2, b.clone(), "allow"),
            rule(3, b.clone(), "deny"),
            with(
                rule(4, b, "allow"),
                serde_json::json!({"object_types": ["installer"]}),
            ),
        ]),
        &Facts::default(),
    );
    assert!(
        found
            .iter()
            .any(|(c, r)| *c == FindingCode::DuplicateRule && r == &vec![rule_id(2), rule_id(1)]),
        "{found:?}"
    );
    assert!(!has(&found, FindingCode::DuplicateRule, 3));
    assert!(!has(&found, FindingCode::DuplicateRule, 4));
}

#[test]
fn duplicate_principal() {
    let both = serde_json::json!({"all": [hash('a'),
        {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-544"]}},
        {"criterion": {"field": "user.groups", "operator": "not_member_of", "values": ["s-1-5-32-0544"]}}]});
    let repeated = serde_json::json!({"all": [hash('b'),
        {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-545", "S-1-5-32-545"]}}]});
    let fine = serde_json::json!({"all": [hash('c'),
        {"criterion": {"field": "user.groups", "operator": "member_of", "values": ["S-1-5-32-545"]}},
        {"criterion": {"field": "user.groups", "operator": "not_member_of", "values": ["S-1-5-32-544"]}}]});
    let found = lint(
        &mixed(vec![
            rule(1, both, "deny"),
            rule(2, repeated, "deny"),
            rule(3, fine, "deny"),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::DuplicatePrincipal, 1));
    assert!(has(&found, FindingCode::DuplicatePrincipal, 2));
    assert!(!has(&found, FindingCode::DuplicatePrincipal, 3));
}

// ----------------------------------------------------------- conflicts

#[test]
fn ineffective_vs_mandatory() {
    let d = doc(
        serde_json::json!({}),
        vec![
            (
                MANDATORY,
                "blocklist",
                true,
                false,
                vec![rule(
                    1,
                    crit("signer.publisher", "equals", &["Bad Ltd"]),
                    "deny",
                )],
            ),
            (
                SET,
                "mixed",
                false,
                false,
                vec![
                    rule(
                        2,
                        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Bad Ltd"]), hash('a')]}),
                        "allow",
                    ),
                    rule(
                        3,
                        crit("signer.publisher", "equals", &["Good Ltd"]),
                        "allow",
                    ),
                ],
            ),
        ],
    );
    let found = lint(&d, &Facts::default());
    assert!(
        has(&found, FindingCode::IneffectiveVsMandatory, 2),
        "{found:?}"
    );
    assert!(!has(&found, FindingCode::IneffectiveVsMandatory, 3));
}

#[test]
fn a_scoped_rule_is_not_called_shadowed_or_a_duplicate_of_an_unscoped_one() {
    let admins = serde_json::json!({"scope": {"principals": {"include": [{"well_known": "administrators"}]}}});
    let found = lint(
        &mixed(vec![
            // A deny scoped to administrators never shadows the allow
            // outside that scope.
            with(rule(1, hash('a'), "deny"), admins.clone()),
            rule(2, hash('a'), "allow"),
            // The same match, action and type, in different scopes.
            with(rule(3, hash('b'), "allow"), admins.clone()),
            rule(4, hash('b'), "allow"),
            // The same scope: still a duplicate.
            with(rule(5, hash('c'), "allow"), admins.clone()),
            with(rule(6, hash('c'), "allow"), admins),
        ]),
        &Facts::default(),
    );
    assert!(!has(&found, FindingCode::Shadowed, 2), "{found:?}");
    assert!(!has(&found, FindingCode::DuplicateRule, 4), "{found:?}");
    assert!(has(&found, FindingCode::DuplicateRule, 6), "{found:?}");
}

#[test]
fn shadowed_under_deny_wins() {
    let found = lint(
        &mixed(vec![
            rule(
                1,
                crit("signer.publisher", "equals", &["Example Ltd", "Other Ltd"]),
                "deny",
            ),
            rule(
                2,
                serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]}),
                "allow",
            ),
            rule(
                3,
                crit("signer.publisher", "equals", &["Third Ltd"]),
                "allow",
            ),
            // A deny that a more specific deny beats is not shadowed: the
            // other way round, the less specific one is.
            rule(
                4,
                serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('b')]}),
                "deny",
            ),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::Shadowed, 2), "{found:?}");
    assert!(!has(&found, FindingCode::Shadowed, 3));
    // Rule 4 is more specific than rule 1, so it wins and is not shadowed.
    assert!(!has(&found, FindingCode::Shadowed, 4));
    // Under deny_wins, the covered allow is reported as shadowed, not as a
    // contradiction.
    assert!(
        !found
            .iter()
            .any(|(c, r)| *c == FindingCode::Contradiction && r.contains(&rule_id(2)))
    );
}

#[test]
fn shadowed_under_first_match_and_contradiction() {
    let d = doc(
        serde_json::json!({"precedence_model": "first_match"}),
        vec![(
            SET,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(
                        1,
                        crit("signer.publisher", "equals", &["Example Ltd"]),
                        "allow",
                    ),
                    serde_json::json!({"order": 100_100}),
                ),
                with(
                    rule(
                        2,
                        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]}),
                        "deny",
                    ),
                    serde_json::json!({"order": 100_200}),
                ),
                with(
                    rule(
                        3,
                        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('b')]}),
                        "deny",
                    ),
                    serde_json::json!({"order": 100_050}),
                ),
            ],
        )],
    );
    let found = lint(&d, &Facts::default());
    assert!(has(&found, FindingCode::Shadowed, 2), "{found:?}");
    assert!(!has(&found, FindingCode::Shadowed, 3));
    // Rule 3 comes first and is covered by rule 1: they contradict.
    assert!(found.iter().any(|(c, r)| *c == FindingCode::Contradiction
        && r.contains(&rule_id(1))
        && r.contains(&rule_id(3))));
}

#[test]
fn rules_that_differ_in_time_types_or_unknown_handling_are_not_shadowed() {
    let deny = |extra: serde_json::Value| {
        with(
            rule(
                1,
                crit("signer.publisher", "equals", &["Example Ltd"]),
                "deny",
            ),
            extra,
        )
    };
    let allow = || {
        rule(
            2,
            serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]}),
            "allow",
        )
    };
    for d in [
        deny(serde_json::json!({"expires_at": t(10).to_string()})),
        deny(serde_json::json!({"object_types": ["installer"]})),
    ] {
        let found = lint(&mixed(vec![d, allow()]), &Facts::default());
        assert!(none_of(&found, FindingCode::Shadowed), "{found:?}");
    }
    // A covered deny with `unknown_as: match` also applies where the cover
    // does not.
    let cover = rule(
        1,
        crit("signer.publisher", "equals", &["Example Ltd"]),
        "deny",
    );
    let victim = serde_json::json!({"id": rule_id(2), "name": "V",
        "match": {"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]},
        "action": {"type": "deny", "unknown_as": "match"}});
    let found = lint(&mixed(vec![cover, victim]), &Facts::default());
    assert!(none_of(&found, FindingCode::Shadowed), "{found:?}");
}

// ------------------------------------------------------- lifecycle checks

#[test]
fn expiry_and_review_findings() {
    let found = lint(
        &mixed(vec![
            with(
                rule(1, hash('a'), "allow"),
                serde_json::json!({"expires_at": t(-1).to_string()}),
            ),
            with(
                rule(2, hash('b'), "allow"),
                serde_json::json!({"expires_at": t(5).to_string()}),
            ),
            with(
                rule(3, hash('c'), "allow"),
                serde_json::json!({"expires_at": t(60).to_string()}),
            ),
            with(
                rule(4, hash('d'), "allow"),
                serde_json::json!({"metadata": {"review_by": "2026-01-01"}}),
            ),
            with(
                rule(5, hash('e'), "allow"),
                serde_json::json!({"metadata": {"review_by": "2027-01-01"}}),
            ),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::ExpiredRulePresent, 1));
    assert!(has(&found, FindingCode::ExpiringSoon, 2));
    assert!(!has(&found, FindingCode::ExpiringSoon, 3));
    assert!(has(&found, FindingCode::ReviewOverdue, 4));
    assert!(!has(&found, FindingCode::ReviewOverdue, 5));
}

#[test]
fn stale_rule() {
    let created = serde_json::json!({"metadata": {"created_at": t(-365).to_string()}});
    let d = mixed(vec![
        with(rule(1, hash('a'), "allow"), created.clone()),
        with(rule(2, hash('b'), "allow"), created.clone()),
        with(rule(3, hash('c'), "allow"), created.clone()),
        with(
            rule(4, hash('d'), "allow"),
            serde_json::json!({"metadata": {"created_at": t(-10).to_string()}}),
        ),
    ]);
    let id = |n| rule_id(n).parse().unwrap();
    let facts = Facts {
        usage: BTreeMap::from([
            (
                id(1),
                Usage {
                    last_matched_at: Some(t(-200)),
                    devices_online: true,
                },
            ),
            (
                id(2),
                Usage {
                    last_matched_at: Some(t(-5)),
                    devices_online: true,
                },
            ),
            (
                id(3),
                Usage {
                    last_matched_at: None,
                    devices_online: false,
                },
            ),
            (
                id(4),
                Usage {
                    last_matched_at: None,
                    devices_online: true,
                },
            ),
        ]),
        ..Facts::default()
    };
    let found = lint(&d, &facts);
    assert!(has(&found, FindingCode::StaleRule, 1));
    assert!(!has(&found, FindingCode::StaleRule, 2));
    assert!(!has(&found, FindingCode::StaleRule, 3));
    assert!(!has(&found, FindingCode::StaleRule, 4));
    let f = analyse(&d, &facts, NOW)
        .into_iter()
        .find(|f| f.code == FindingCode::StaleRule)
        .unwrap();
    assert_eq!(f.fix, Some(Fix::ConvertToAudit));
}

#[test]
fn governance_findings() {
    // The validator rejects these in governance mode; the assistant also
    // reports them, so a lint run before saving shows them.
    let mut d = mixed(vec![
        rule(1, hash('a'), "allow"),
        with(
            rule(2, hash('b'), "allow"),
            serde_json::json!({"metadata": {"justification": "needed", "created_at": NOW.to_string()}}),
        ),
        with(
            rule(3, hash('c'), "allow"),
            serde_json::json!({"metadata": {"exception": true, "justification": "x", "created_at": NOW.to_string()}}),
        ),
    ]);
    d.policy.governance.require_justification = Some(true);
    let found = lint(&d, &Facts::default());
    assert!(has(&found, FindingCode::MissingJustification, 1));
    assert!(!has(&found, FindingCode::MissingJustification, 2));
    assert!(has(&found, FindingCode::ExceptionWithoutExpiry, 3));
    assert!(!has(&found, FindingCode::ExceptionWithoutExpiry, 2));
}

#[test]
fn vulnerable_version_allowed() {
    let vuln = rule(
        1,
        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]),
        {"criterion": {"field": "meta.file_version", "operator": "version_lt", "values": ["2.0"]}}]}),
        "deny",
    );
    let wide = rule(
        2,
        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("meta.product_name", "equals", &["Tool"]),
        {"criterion": {"field": "meta.file_version", "operator": "version_ge", "values": ["1.0"]}}]}),
        "allow",
    );
    let safe = rule(
        3,
        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("meta.product_name", "equals", &["Tool"]),
        {"criterion": {"field": "meta.file_version", "operator": "version_ge", "values": ["2.0"]}}]}),
        "allow",
    );
    let d = doc(
        serde_json::json!({}),
        vec![
            (CURATED, "blocklist", false, true, vec![vuln]),
            (SET, "mixed", false, false, vec![wide, safe]),
        ],
    );
    let found = lint(&d, &Facts::default());
    assert!(
        has(&found, FindingCode::VulnerableVersionAllowed, 2),
        "{found:?}"
    );
    assert!(!has(&found, FindingCode::VulnerableVersionAllowed, 3));
}

#[test]
fn hash_with_other_criteria() {
    let with = |other: serde_json::Value| serde_json::json!({"all": [hash('a'), other]});
    let found = lint(
        &mixed(vec![
            // A hash alone, or with a context criterion: nothing to say.
            rule(1, hash('a'), "allow"),
            rule(
                2,
                with(crit("user.groups", "member_of", &["S-1-5-32-544"])),
                "allow",
            ),
            // A hash with a path, a publisher or metadata only narrows.
            rule(
                3,
                with(crit("path.directory", "starts_with", &["C:\\Tools"])),
                "allow",
            ),
            rule(
                4,
                with(crit("signer.publisher", "equals", &["Example"])),
                "deny",
            ),
            rule(
                5,
                serde_json::json!({"all": [crit("meta.product_name", "equals", &["A"]), {"any": [hash('b')]}]}),
                "allow",
            ),
            // A hash on one branch of an `any`, or under `not`, does not
            // name the file for every match.
            rule(
                6,
                serde_json::json!({"any": [hash('c'), crit("path.file_name", "equals", &["a.exe"])]}),
                "deny",
            ),
            rule(
                7,
                serde_json::json!({"all": [crit("path.file_name", "equals", &["a.exe"]), {"not": hash('d')}]}),
                "deny",
            ),
            // A SHA-1 does not name one file (ADR 0008).
            rule(
                8,
                serde_json::json!({"all": [crit("hash.sha1", "equals", &[&"e".repeat(40)]), crit("path.file_name", "equals", &["a.exe"])]}),
                "deny",
            ),
        ]),
        &Facts::default(),
    );
    for n in [3, 4, 5] {
        assert!(
            has(&found, FindingCode::HashWithOtherCriteria, n),
            "{n} {found:?}"
        );
    }
    let flagged: Vec<u32> = (1..=8)
        .filter(|n| has(&found, FindingCode::HashWithOtherCriteria, *n))
        .collect();
    assert_eq!(flagged, [3, 4, 5]);
    assert_eq!(
        FindingCode::HashWithOtherCriteria.default_severity(),
        FindingSeverity::Info
    );
    assert_eq!(
        FindingCode::from_name("hash_with_other_criteria"),
        Some(FindingCode::HashWithOtherCriteria)
    );
}

#[test]
fn too_many_hash_rules() {
    let rules: Vec<serde_json::Value> = (0..12u32)
        .map(|n| {
            rule(
                n + 1,
                crit("hash.sha256", "equals", &[&format!("{:064x}", n)]),
                "allow",
            )
        })
        .collect();
    let d = mixed(rules);
    let opts = Options {
        max_inline_hashes: 10,
        ..Options::default()
    };
    let found = analyse_with(&d, &Facts::default(), NOW, &opts);
    assert!(
        found
            .iter()
            .any(|f| f.code == FindingCode::TooManyHashRules)
    );
    assert!(
        !analyse(&d, &Facts::default(), NOW)
            .iter()
            .any(|f| f.code == FindingCode::TooManyHashRules)
    );
}

// ------------------------------------------------------ severity and gate

#[test]
fn severities_are_configurable_and_errors_block_publishing() {
    let mut d = mixed(vec![rule(
        1,
        crit("path.file_name", "equals", &["a.exe"]),
        "allow",
    )]);
    let f = analyse(&d, &Facts::default(), NOW);
    assert_eq!(f[0].severity, FindingSeverity::Warning);
    assert_eq!(publish_gate(&f, None), Gate::Pass);
    d.policy
        .governance
        .severity
        .insert("weak_identity".into(), FindingSeverity::Error);
    let f = analyse(&d, &Facts::default(), NOW);
    assert_eq!(f[0].severity, FindingSeverity::Error);
    assert!(matches!(publish_gate(&f, None), Gate::Blocked(ref e) if e.len() == 1));
    let blank = Override {
        actor: "admin".into(),
        reason: " ".into(),
    };
    assert!(matches!(publish_gate(&f, Some(&blank)), Gate::Blocked(_)));
    let ok = Override {
        actor: "admin".into(),
        reason: "accepted risk, ticket CHG-1".into(),
    };
    assert!(
        matches!(publish_gate(&f, Some(&ok)), Gate::Overridden { ref reason, .. } if reason == "accepted risk, ticket CHG-1")
    );
}

#[test]
fn every_code_has_a_unique_stable_name() {
    let names: BTreeSet<&str> = FindingCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(names.len(), FindingCode::ALL.len());
    for c in FindingCode::ALL {
        assert_eq!(FindingCode::from_name(c.as_str()), Some(c));
        assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
    }
}

#[test]
fn findings_do_not_depend_on_rule_order() {
    let rules = vec![
        rule(
            1,
            crit("signer.publisher", "equals", &["Example Ltd"]),
            "deny",
        ),
        rule(
            2,
            serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]}),
            "allow",
        ),
        rule(3, crit("path.file_name", "equals", &["a.exe"]), "allow"),
        rule(4, crit("path.file_name", "equals", &["a.exe"]), "allow"),
    ];
    let mut reversed = rules.clone();
    reversed.reverse();
    let a = analyse(&mixed(rules), &Facts::default(), NOW);
    let b = analyse(&mixed(reversed), &Facts::default(), NOW);
    let key = |f: &[Finding]| -> Vec<(FindingCode, Vec<RuleRef>)> {
        let mut v: Vec<_> = f
            .iter()
            .map(|f| {
                let mut r = f.rule_refs.clone();
                if f.code == FindingCode::DuplicateRule || f.code == FindingCode::Contradiction {
                    r.sort();
                }
                (f.code, r)
            })
            .collect();
        v.sort();
        v
    };
    assert_eq!(key(&a), key(&b));
}

// ------------------------------------------- shadowed rules never decide

/// The objects the property tests decide: every combination of three
/// hashes, three publishers and two product names.
fn objects() -> Vec<ObjectFacts> {
    let mut out = Vec::new();
    for h in ['a', 'b', 'c'] {
        for p in ["P1", "P2", "P3"] {
            for prod in ["X", "Y"] {
                out.push(
                    ObjectFacts::new()
                        .with(crate::model::Field::HashSha256, sha(h))
                        .with(crate::model::Field::MetaProductName, prod)
                        .with_path(
                            PathFact::new(
                                "C:\\Tools\\a.exe",
                                &palisade_core::path::VolumeMap::new(),
                            )
                            .with_user_writable(false)
                            .with_volume(crate::unknown::VolumeKind::Fixed),
                        )
                        .with_signers(vec![SignerFact {
                            status: SignerStatus::Valid,
                            source: SignatureSource::Embedded,
                            publisher: Some(p.into()),
                            issuer: None,
                            leaf_thumbprint_sha256: None,
                            details: Default::default(),
                        }]),
                );
            }
        }
    }
    out
}

fn arb_leaf() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        prop::sample::subsequence(vec!['a', 'b', 'c'], 1..=3).prop_map(|v| {
            let v: Vec<String> = v.into_iter().map(sha).collect();
            serde_json::json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": v}})
        }),
        prop::sample::subsequence(vec!["P1", "P2", "P3"], 1..=3).prop_map(|v| crit("signer.publisher", "equals", &v)),
    ]
}

fn arb_tree() -> impl Strategy<Value = serde_json::Value> {
    let extra = prop::sample::subsequence(vec!["X", "Y"], 1..=2)
        .prop_map(|v| crit("meta.product_name", "equals", &v));
    prop_oneof![
        arb_leaf(),
        (arb_leaf(), arb_leaf()).prop_map(|(a, b)| serde_json::json!({"all": [a, b]})),
        (arb_leaf(), arb_leaf()).prop_map(|(a, b)| serde_json::json!({"any": [a, b]})),
        (arb_leaf(), extra).prop_map(|(a, b)| serde_json::json!({"all": [a, b]})),
    ]
}

fn arb_rules() -> impl Strategy<Value = Vec<(serde_json::Value, bool, bool, u32)>> {
    prop::collection::vec(
        (
            arb_tree(),
            any::<bool>(),
            any::<bool>(),
            100_001u32..100_100,
        ),
        2..7,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A rule reported as `shadowed` or `ineffective_vs_mandatory` never
    /// decides any object, under `deny_wins` and `first_match`.
    #[test]
    fn shadowed_and_ineffective_rules_never_decide(
        rules in arb_rules(),
        first_match in any::<bool>(),
    ) {
        let model = if first_match { "first_match" } else { "deny_wins" };
        let mut mandatory = Vec::new();
        let mut ordinary = Vec::new();
        for (i, (tree, deny, mand, order)) in rules.iter().enumerate() {
            let n = u32::try_from(i).unwrap() + 1;
            let action = if *deny || *mand { "deny" } else { "allow" };
            let r = with(rule(n, tree.clone(), action), serde_json::json!({"order": order}));
            if *mand { mandatory.push(r) } else { ordinary.push(r) }
        }
        let mut sets: Vec<Set> = vec![(SET, "mixed", false, false, ordinary)];
        if !mandatory.is_empty() {
            sets.push((MANDATORY, "blocklist", true, false, mandatory));
        }
        let d = doc(serde_json::json!({"precedence_model": model}), sets);
        let never: BTreeSet<RuleId> = analyse(&d, &Facts::default(), NOW)
            .iter()
            .filter(|f| matches!(f.code, FindingCode::Shadowed | FindingCode::IneffectiveVsMandatory))
            .map(|f| f.rule_refs[0].rule_id)
            .collect();
        let v = d.validate().unwrap();
        let e = Evaluator::new(&v).unwrap();
        let variables = PathVariables::new();
        let context = EvaluationContext::new();
        for facts in objects() {
            let decision = e.evaluate(
                &Subject { object_type: ObjectType::Executable, facts: &facts, variables: &variables, context: &context },
                TraceId([0; 16]),
            );
            if let Some(r) = decision.matched_rule() {
                prop_assert!(!never.contains(&r.rule_id), "rule {} decided but was reported as never deciding", r.rule_id);
            }
        }
    }

    /// `covers(a, b)` is sound: whenever it holds, every object `b`
    /// matches also matches `a`.
    #[test]
    fn covers_is_sound(a in arb_tree(), b in arb_tree()) {
        let a: Match = serde_json::from_value(a).unwrap();
        let b: Match = serde_json::from_value(b).unwrap();
        if covers(&a, &b) {
            let ca = crate::condition::CompiledMatch::compile(&a).unwrap();
            let cb = crate::condition::CompiledMatch::compile(&b).unwrap();
            let variables = PathVariables::new();
            let context = EvaluationContext::new();
            let ctx = crate::ops::EvalContext { action: ActionKind::Deny, variables: &variables, context: &context };
            for facts in objects() {
                if cb.eval(&facts, &ctx).matches() {
                    prop_assert!(ca.eval(&facts, &ctx).matches());
                }
            }
        }
    }
}

#[test]
fn analyse_scales_to_a_large_policy() {
    // 20k hash rules and 2k publisher rules: the index keeps the conflict
    // pass from comparing every pair. The 50k benchmark is in benches/.
    let mut rules = Vec::new();
    for n in 0..20_000u32 {
        rules.push(serde_json::json!({"id": format!("01936b2e-{:04x}-7{:03x}-9f21-0a1b2c3d4e61", n >> 12, n & 0xfff), "name": "H",
            "match": crit("hash.sha256", "equals", &[&format!("{n:064x}")]), "action": {"type": "allow"}}));
    }
    for n in 0..2_000u32 {
        rules.push(serde_json::json!({"id": format!("01936b2e-ffff-7{:03x}-9f21-0a1b2c3d{:04x}", n & 0xfff, n), "name": "P",
            "match": crit("signer.publisher", "equals", &[&format!("Publisher {n}")]), "action": {"type": "allow"}}));
    }
    let json = serde_json::json!({"schema_version": "1.0.0",
        "policy": {"id": POLICY, "name": "Big", "revision": 1, "mode": "enforce", "rule_sets": [SET]},
        "rule_sets": [{"id": SET, "name": "S", "kind": "allowlist", "rules": rules}]});
    let d = PolicyDocument::from_json(&json.to_string()).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = std::time::Instant::now();
    let f = analyse(&d, &Facts::default(), NOW);
    let took = start.elapsed();
    assert!(f.iter().all(|f| f.code != FindingCode::Shadowed));
    // Generous for debug builds on shared runners; the release benchmark
    // is the real budget.
    assert!(took < std::time::Duration::from_secs(30), "{took:?}");
}

/// The lint output of the example policies is a committed snapshot, so a
/// change to any check shows up in review. Regenerate with
/// `PALISADE_BLESS=1 cargo test -p palisade-policy analysis::`.
#[test]
fn lint_snapshot_of_the_example_policies() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("../../docs/examples/policies");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    names.sort();
    let mut text = String::new();
    for path in names {
        let yaml = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let d = PolicyDocument::from_yaml(&yaml).unwrap();
        text.push_str(&format!(
            "# {}\n",
            path.file_name().unwrap().to_string_lossy()
        ));
        for f in analyse(&d, &Facts::default(), NOW) {
            let rules: Vec<String> = f.rule_refs.iter().map(|r| r.rule_id.to_string()).collect();
            text.push_str(&format!(
                "{} {:?} {}\n",
                f.code,
                f.severity,
                rules.join(" ")
            ));
        }
    }
    let snap = root.join("tests/snapshots/lint/examples.txt");
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::create_dir_all(snap.parent().unwrap()).unwrap();
        std::fs::write(&snap, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&snap)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(committed == text, "{} differs:\n{text}", snap.display());
}

// ------------------------------------------------- review regressions

#[test]
fn negated_tests_never_count_as_trusted_or_broad() {
    let facts = Facts {
        certificates: BTreeMap::from([("Gone Ltd".into(), CertificateState::Revoked)]),
        restricted_publishers: vec!["OS Publisher".into()],
        ..Facts::default()
    };
    let excludes_revoked = serde_json::json!({"all": [hash('a'), {"not": crit("signer.publisher", "equals", &["Gone Ltd"])}]});
    let excludes_wildcard = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]),
        {"not": crit("path.directory", "wildcard", &["C:\\*"])}]});
    // Excluding one file still trusts everything else the OS signs.
    let not_narrowed = serde_json::json!({"all": [crit("signer.publisher", "equals", &["OS Publisher"]),
        {"not": crit("path.file_name", "equals", &["cmd.exe"])}]});
    // One branch is narrowed, the other is not.
    let any_branch = serde_json::json!({"any": [
        {"all": [crit("signer.publisher", "equals", &["OS Publisher"]), crit("meta.product_name", "equals", &["Calc"])]},
        crit("signer.publisher", "equals", &["OS Publisher"]),
    ]});
    let trusts_revoked =
        serde_json::json!({"all": [hash('b'), crit("signer.publisher", "equals", &["Gone Ltd"])]});
    let found = lint(
        &mixed(vec![
            rule(1, excludes_revoked, "allow"),
            rule(2, excludes_wildcard, "allow"),
            rule(3, not_narrowed, "allow"),
            rule(4, any_branch, "allow"),
            rule(5, trusts_revoked, "allow"),
        ]),
        &facts,
    );
    assert!(
        !has(&found, FindingCode::RevokedOrExpiredSigner, 1),
        "{found:?}"
    );
    assert!(!has(&found, FindingCode::BroadWildcard, 2));
    assert!(has(&found, FindingCode::RestrictedPublisherBroad, 3));
    assert!(has(&found, FindingCode::RestrictedPublisherBroad, 4));
    // Requiring the revoked signer is reported.
    assert!(has(&found, FindingCode::RevokedOrExpiredSigner, 5));
}

#[test]
fn broad_wildcards_are_read_as_matching_reads_them() {
    for (v, broad) in [
        ("C:\\.\\*", true),
        ("C:\\a\\..\\*", true),
        ("C:\\Windows\\**.exe", true),
        ("%WINDIR%\\**", true),
        ("\\\\server\\share\\**", true),
        ("%TEMP%\\**", false),
        ("%PROGRAMFILES%\\Example\\**", false),
        ("C:\\Program Files\\Example\\*.exe", false),
    ] {
        assert_eq!(is_broad_path_wildcard(v), broad, "{v}");
    }
}

#[test]
fn writable_directories_are_found_through_roots_patterns_and_branches() {
    let facts = Facts {
        writable_dirs: vec!["C:\\Tools\\Drop".into()],
        ..Facts::default()
    };
    let found = lint(
        &mixed(vec![
            rule(1, crit("path.directory", "starts_with", &["C:\\"]), "allow"),
            rule(
                2,
                crit("path.full", "wildcard", &["C:\\Tools\\**\\*.exe"]),
                "allow",
            ),
            rule(
                3,
                serde_json::json!({"any": [crit("path.directory", "starts_with", &["C:\\Safe"]), crit("path.directory", "starts_with", &["C:\\Tools\\Drop"])]}),
                "allow",
            ),
            rule(
                4,
                crit("path.directory", "starts_with", &["C:\\Safe"]),
                "allow",
            ),
        ]),
        &facts,
    );
    for n in [1, 2, 3] {
        assert!(
            has(&found, FindingCode::UserWritablePathAllow, n),
            "{n}: {found:?}"
        );
    }
    assert!(!has(&found, FindingCode::UserWritablePathAllow, 4));
}

#[test]
fn principals_track_negation_and_repeats_across_criteria() {
    let g = |op: &str, v: &str| serde_json::json!({"criterion": {"field": "user.groups", "operator": op, "values": [v]}});
    let found = lint(
        &mixed(vec![
            rule(
                1,
                serde_json::json!({"all": [hash('a'), g("member_of", "S-1-5-32-544"), {"not": g("member_of", "S-1-5-32-544")}]}),
                "deny",
            ),
            rule(
                2,
                serde_json::json!({"all": [hash('b'), g("member_of", "S-1-5-32-545"), g("member_of", "S-1-5-32-545")]}),
                "deny",
            ),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::DuplicatePrincipal, 1));
    assert!(has(&found, FindingCode::DuplicatePrincipal, 2));
}

/// F1: `read_only` on a policy's own rule set gave it no governance at
/// all, so the publish gate passed. Only the managed baseline the engine
/// built is exempt.
#[test]
fn read_only_does_not_exempt_a_rule_set_from_governance() {
    let curated = (
        CURATED,
        "baseline",
        false,
        true,
        vec![rule(
            1,
            crit("signer.publisher", "equals", &["OS Publisher"]),
            "allow",
        )],
    );
    // The reviewer's scenario: validation rejects it ...
    let json = serde_json::json!({"schema_version": "1.0.0",
        "policy": {"id": POLICY, "name": "Lint", "revision": 1, "mode": "enforce",
                   "unknown": {"preset": "e8_ml2"}, "rule_sets": [CURATED]},
        "rule_sets": [{"id": curated.0, "name": "S", "kind": curated.1, "read_only": true, "rules": curated.4}]});
    let d = PolicyDocument::from_json(&json.to_string()).unwrap();
    let errors = d.clone().validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code == crate::validate::ErrorCode::JustificationRequired),
        "{errors:#?}"
    );
    // ... the assistant reports it, the gate blocks, and it is due for
    // review.
    let findings = analyse(&d, &Facts::default(), NOW);
    assert!(
        findings
            .iter()
            .any(|f| f.code == FindingCode::MissingJustification),
        "{findings:?}"
    );
    assert!(matches!(publish_gate(&findings, None), Gate::Blocked(_)));
    assert_eq!(crate::lifecycle::review_due(&d, NOW.date()).len(), 1);
}

/// F1: the baseline the engine adds after validation stays exempt; a
/// document that writes a set with its ID, even the exact generated shape
/// with an arbitrary publisher, is rejected, and if analysed anyway it is
/// governed.
#[test]
fn only_the_engine_built_baseline_is_exempt() {
    use crate::unknown::baseline::{SystemBaseline, system_baseline};
    let base = || {
        let json = serde_json::json!({"schema_version": "1.0.0",
            "policy": {"id": POLICY, "name": "Lint", "revision": 1, "mode": "enforce",
                       "unknown": {"preset": "e8_ml2"}, "rule_sets": []}});
        PolicyDocument::from_json(&json.to_string()).unwrap()
    };
    // The way the engine adds it: after validation.
    let real = base()
        .validate()
        .unwrap()
        .with_system_baseline(&SystemBaseline {
            publishers: vec!["OS Publisher".into()],
            writable_dirs: vec!["C:\\Windows\\Flagged".into()],
        })
        .unwrap();
    let findings = analyse(real.document(), &Facts::default(), NOW);
    assert!(
        !findings.iter().any(|f| matches!(
            f.code,
            FindingCode::MissingJustification
                | FindingCode::ExceptionWithoutExpiry
                | FindingCode::ReviewOverdue
        )),
        "{findings:?}"
    );
    assert_eq!(publish_gate(&findings, None), Gate::Pass);
    assert!(crate::lifecycle::review_due(real.document(), NOW.date()).is_empty());
    // The forgery: the exact generated shape for any publisher.
    let mut forged = base();
    let set = system_baseline(
        &SystemBaseline {
            publishers: vec!["Any Vendor Ltd".into()],
            writable_dirs: vec![],
        },
        forged.policy.precedence_model,
        forged.policy.precedence_options.priority_direction,
    )
    .unwrap();
    forged.policy.rule_sets.push(set.id);
    forged.rule_sets.push(set);
    let errors = forged.clone().validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code == crate::validate::ErrorCode::ReservedRuleSetId
                && e.path == "/rule_sets/0/id"),
        "{errors:#?}"
    );
    // A copy of the real one, submitted as a document, is rejected too.
    let errors = real.document().clone().validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code == crate::validate::ErrorCode::ReservedRuleSetId),
        "{errors:#?}"
    );
}

/// F3: approval, creation or review dates in the future are reported.
#[test]
fn future_dated_metadata_is_reported() {
    let d = mixed(vec![
        with(
            rule(1, hash('a'), "allow"),
            serde_json::json!({"metadata": {"created_at": t(10).to_string()}}),
        ),
        with(
            rule(2, hash('b'), "allow"),
            serde_json::json!({"metadata": {"approved_at": t(1).to_string(), "last_reviewed_at": t(2).to_string()}}),
        ),
        with(
            rule(3, hash('c'), "allow"),
            serde_json::json!({"metadata": {"created_at": NOW.to_string(), "approved_at": t(-1).to_string()}}),
        ),
    ]);
    let found = analyse(&d, &Facts::default(), NOW);
    let future: Vec<(String, &str)> = found
        .iter()
        .filter(|f| f.code == FindingCode::FutureDatedMetadata)
        .map(|f| (f.rule_refs[0].rule_id.to_string(), f.message.as_str()))
        .collect();
    assert_eq!(future.len(), 3, "{future:?}");
    assert!(future.iter().all(|(r, _)| *r != rule_id(3)));
    assert!(future[0].1.contains("created_at"));
}

/// F6: a policy may raise a finding's severity, never lower it.
#[test]
fn a_policy_cannot_lower_a_finding_below_its_default() {
    let mut d = mixed(vec![rule(
        1,
        crit("path.file_name", "equals", &["a.exe"]),
        "allow",
    )]);
    d.policy.governance.require_justification = Some(true);
    d.policy
        .governance
        .severity
        .insert("missing_justification".into(), FindingSeverity::Info);
    let errors = d.clone().validate().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.code == crate::validate::ErrorCode::InvalidGovernance
                && e.path == "/policy/governance/severity/missing_justification"
                && e.message.contains("missing_justification")),
        "{errors:#?}"
    );
    // Even unvalidated, the assistant keeps the default.
    let found = analyse(&d, &Facts::default(), NOW);
    let f = found
        .iter()
        .find(|f| f.code == FindingCode::MissingJustification)
        .unwrap();
    assert_eq!(f.severity, FindingSeverity::Error);
    assert!(matches!(publish_gate(&found, None), Gate::Blocked(_)));
    // Raising is accepted and applied.
    d.policy.governance.require_justification = None;
    d.policy.governance.severity.clear();
    d.policy
        .governance
        .severity
        .insert("weak_identity".into(), FindingSeverity::Error);
    d.policy
        .governance
        .severity
        .insert("expiring_soon".into(), FindingSeverity::Info);
    d.clone().validate().unwrap();
    let found = analyse(&d, &Facts::default(), NOW);
    assert_eq!(
        found
            .iter()
            .find(|f| f.code == FindingCode::WeakIdentity)
            .unwrap()
            .severity,
        FindingSeverity::Error
    );
}

#[test]
fn duplicates_respect_patterns_scope_and_timing_and_keep_the_winner() {
    let re =
        |p: &str| serde_json::json!({"all": [hash('a'), crit("meta.product_name", "regex", &[p])]});
    let found = lint(
        &mixed(vec![
            rule(1, re("\\w+"), "deny"),
            rule(2, re("\\W+"), "deny"),
        ]),
        &Facts::default(),
    );
    assert!(none_of(&found, FindingCode::DuplicateRule));
    let timed = with(
        rule(4, hash('c'), "allow"),
        serde_json::json!({"expires_at": t(30).to_string()}),
    );
    let found = lint(
        &mixed(vec![rule(3, hash('c'), "allow"), timed]),
        &Facts::default(),
    );
    assert!(none_of(&found, FindingCode::DuplicateRule));
    // Three copies: both later ones are reported against the lowest ID,
    // whatever the order.
    let copies = vec![
        rule(7, hash('d'), "allow"),
        rule(5, hash('d'), "allow"),
        rule(6, hash('d'), "allow"),
    ];
    let found = lint(&mixed(copies), &Facts::default());
    let dups: Vec<&Vec<String>> = found
        .iter()
        .filter(|(c, _)| *c == FindingCode::DuplicateRule)
        .map(|(_, r)| r)
        .collect();
    assert_eq!(
        dups,
        vec![&vec![rule_id(6), rule_id(5)], &vec![rule_id(7), rule_id(5)]]
    );
    // Under first_match, rules at different positions are not duplicates.
    let d = doc(
        serde_json::json!({"precedence_model": "first_match"}),
        vec![(
            SET,
            "mixed",
            false,
            false,
            vec![
                with(
                    rule(1, hash('e'), "allow"),
                    serde_json::json!({"order": 100_100}),
                ),
                with(
                    rule(2, hash('e'), "allow"),
                    serde_json::json!({"order": 100_200}),
                ),
            ],
        )],
    );
    assert!(none_of(
        &lint(&d, &Facts::default()),
        FindingCode::DuplicateRule
    ));
}

#[test]
fn vulnerable_versions_intersect_bounds_and_respect_identity() {
    let ver = |op: &str, v: &[&str]| serde_json::json!({"criterion": {"field": "meta.file_version", "operator": op, "values": v}});
    let vuln = rule(
        1,
        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("meta.product_name", "equals", &["Tool"]),
        ver("version_ge", &["1.2"]), ver("version_lt", &["2.0"])]}),
        "deny",
    );
    let tool = |n: u32, extra: Vec<serde_json::Value>| {
        let mut all = vec![
            crit("signer.publisher", "equals", &["Example Ltd"]),
            crit("meta.product_name", "equals", &["Tool"]),
        ];
        all.extend(extra);
        rule(n, serde_json::json!({"all": all}), "allow")
    };
    let d = doc(
        serde_json::json!({}),
        vec![
            (CURATED, "blocklist", false, true, vec![vuln]),
            (
                SET,
                "mixed",
                false,
                false,
                vec![
                    tool(2, vec![ver("version_ge", &["2.0"])]),
                    tool(
                        3,
                        vec![ver("version_le", &["3.0"]), ver("version_ge", &["2.0"])],
                    ),
                    tool(4, vec![ver("version_eq", &["2.0", "2.1"])]),
                    tool(5, vec![ver("version_ge", &["1.0"])]),
                    tool(6, vec![ver("version_eq", &["1.0", "1.5"])]),
                    rule(
                        7,
                        serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), crit("meta.product_name", "equals", &["Other"])]}),
                        "allow",
                    ),
                    with(
                        tool(8, vec![ver("version_ge", &["1.0"])]),
                        serde_json::json!({"expires_at": t(-1).to_string()}),
                    ),
                ],
            ),
        ],
    );
    let found = lint(&d, &Facts::default());
    for n in [2, 3, 4, 7, 8] {
        assert!(
            !has(&found, FindingCode::VulnerableVersionAllowed, n),
            "{n}: {found:?}"
        );
    }
    assert!(has(&found, FindingCode::VulnerableVersionAllowed, 5));
    assert!(has(&found, FindingCode::VulnerableVersionAllowed, 6));
}

#[test]
fn exception_rules_without_a_start_are_reported_as_validation_does() {
    let mut d = mixed(vec![with(
        rule(1, hash('a'), "allow"),
        serde_json::json!({
            "expires_at": t(30).to_string(),
            "metadata": {"exception": true, "justification": "x", "approved_by": "ciso", "risk_rating": "low", "review_by": "2027-01-01"},
        }),
    )]);
    d.policy.governance.require_justification = Some(true);
    assert!(has(
        &lint(&d, &Facts::default()),
        FindingCode::ExceptionWithoutExpiry,
        1
    ));
    assert!(
        d.validate()
            .unwrap_err()
            .iter()
            .any(|e| e.code == crate::validate::ErrorCode::ExceptionIncomplete)
    );
}

#[test]
fn trust_sources_are_never_stale() {
    let trust = serde_json::json!({"id": rule_id(1), "name": "T", "object_types": ["installer"],
        "match": hash('a'), "action": {"type": "trust_source", "mode": "direct", "scope_paths": ["C:\\Apps"]},
        "metadata": {"created_at": t(-365).to_string()}});
    let d = mixed(vec![trust]);
    let facts = Facts {
        usage: BTreeMap::from([(
            rule_id(1).parse().unwrap(),
            Usage {
                last_matched_at: None,
                devices_online: true,
            },
        )]),
        ..Facts::default()
    };
    assert!(none_of(&lint(&d, &facts), FindingCode::StaleRule));
}

#[test]
fn rules_sharing_a_common_scope_do_not_explode_the_conflict_pass() {
    // 5,000 rules that all require the same context criterion first.
    let rules: Vec<serde_json::Value> = (0..5_000u32)
        .map(|n| serde_json::json!({"id": format!("01936b2e-{:04x}-7{:03x}-9f21-0a1b2c3d4e61", n >> 12, n & 0xfff), "name": "R",
            "match": {"all": [{"criterion": {"field": "user.is_admin", "operator": "is_false"}}, crit("hash.sha256", "equals", &[&format!("{n:064x}")])]},
            "action": {"type": "deny"}}))
        .collect();
    let json = serde_json::json!({"schema_version": "1.0.0",
        "policy": {"id": POLICY, "name": "Scoped", "revision": 1, "mode": "enforce", "rule_sets": [SET]},
        "rule_sets": [{"id": SET, "name": "S", "kind": "blocklist", "rules": rules}]});
    let d = PolicyDocument::from_json(&json.to_string()).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = std::time::Instant::now();
    let _ = analyse(&d, &Facts::default(), NOW);
    assert!(start.elapsed() < std::time::Duration::from_secs(30));
    // A tiny budget still finishes and finds nothing false.
    let opts = Options {
        max_pair_checks: 10,
        ..Options::default()
    };
    assert!(
        analyse_with(&d, &Facts::default(), NOW, &opts)
            .iter()
            .all(|f| f.code != FindingCode::Shadowed)
    );
}

// --------------------------------------------- CodeRabbit review (#301)

fn ver(field: &str, op: &str, values: &[&str]) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": op, "values": values}})
}

fn vuln_doc(deny: serde_json::Value, allow: serde_json::Value) -> PolicyDocument {
    doc(
        serde_json::json!({}),
        vec![
            (
                CURATED,
                "blocklist",
                false,
                true,
                vec![rule(1, deny, "deny")],
            ),
            (SET, "mixed", false, false, vec![rule(2, allow, "allow")]),
        ],
    )
}

/// analysis/mod.rs:454: an expired `convert_to_audit` rule still audits,
/// so it is not offered for removal.
#[test]
fn an_expired_rule_that_converts_to_audit_is_not_offered_for_removal() {
    let d = mixed(vec![
        with(
            rule(1, hash('a'), "deny"),
            serde_json::json!({"expires_at": t(-1).to_string(), "on_expire": "convert_to_audit"}),
        ),
        with(
            rule(2, hash('b'), "deny"),
            serde_json::json!({"expires_at": t(-1).to_string()}),
        ),
    ]);
    let found = analyse(&d, &Facts::default(), NOW);
    let expired = |n: u32| {
        found
            .iter()
            .find(|f| {
                f.code == FindingCode::ExpiredRulePresent
                    && f.rule_refs[0].rule_id.to_string() == rule_id(n)
            })
            .unwrap()
    };
    assert_eq!(expired(1).fix, None);
    assert!(expired(1).message.contains("still audits"));
    assert_eq!(expired(2).fix, Some(Fix::RemoveRule));
}

/// analysis/mod.rs:963: one shared bucket far larger than the cap is
/// read only up to the cap, and every entry read costs budget.
#[test]
fn candidate_collection_is_capped_and_budgeted() {
    let bucket: Vec<usize> = (0..100_000).collect();
    let index = BTreeMap::from([(key(Field::SignerPublisher, "Example Ltd"), bucket)]);
    let tree: Match =
        serde_json::from_value(crit("signer.publisher", "equals", &["Example Ltd"])).unwrap();
    let mut budget = 1_000_000;
    let got = candidates(&tree, &index, &[], &mut budget).unwrap();
    assert_eq!(got.len(), MAX_CANDIDATES);
    // Deterministic: the first entries in index order.
    assert_eq!(got.iter().next_back(), Some(&(MAX_CANDIDATES - 1)));
    assert_eq!(1_000_000 - budget, MAX_CANDIDATES);
    // A budget smaller than the cap ends the pass.
    let mut small = 10;
    assert_eq!(candidates(&tree, &index, &[], &mut small), None);
}

/// analysis/mod.rs:1129: the vulnerable-version pass is indexed and
/// budgeted: with no pair budget it compares nothing, and an allow for
/// another publisher is never compared at all.
#[test]
fn the_vulnerable_version_pass_is_indexed_and_budgeted() {
    let deny = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), ver("meta.file_version", "version_lt", &["2.0"])]});
    let allow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), ver("meta.file_version", "version_ge", &["1.0"])]});
    let d = vuln_doc(deny, allow);
    assert!(has(
        &lint(&d, &Facts::default()),
        FindingCode::VulnerableVersionAllowed,
        2
    ));
    let none = Options {
        max_pair_checks: 0,
        ..Options::default()
    };
    assert!(
        !analyse_with(&d, &Facts::default(), NOW, &none)
            .iter()
            .any(|f| f.code == FindingCode::VulnerableVersionAllowed)
    );
    // Not indexed together: a different publisher.
    assert!(
        identity_name_keys(&d.rule_sets[0].rules[0].match_)
            .iter()
            .all(|k| !identity_name_keys(
                &serde_json::from_value(crit("signer.publisher", "equals", &["Other Ltd"]))
                    .unwrap()
            )
            .contains(k))
    );
}

/// analysis/mod.rs:1313: `time_between` is positional: 22:00 to 06:00
/// (overnight) is not 06:00 to 22:00 (daytime), so they are no duplicate.
#[test]
fn positional_operators_keep_their_order_for_duplicates() {
    let at = |a: &str, b: &str| serde_json::json!({"all": [hash('a'), ver("time.local_time", "time_between", &[a, b])]});
    let found = lint(
        &mixed(vec![
            rule(1, at("22:00", "06:00"), "allow"),
            rule(2, at("06:00", "22:00"), "allow"),
        ]),
        &Facts::default(),
    );
    assert!(none_of(&found, FindingCode::DuplicateRule), "{found:?}");
    // The same window twice still is.
    let found = lint(
        &mixed(vec![
            rule(1, at("22:00", "06:00"), "allow"),
            rule(2, at("22:00", "06:00"), "allow"),
        ]),
        &Facts::default(),
    );
    assert!(has(&found, FindingCode::DuplicateRule, 2), "{found:?}");
}

/// analysis/mod.rs:1488: a blocklist deny with no version test is not
/// vulnerable-version evidence.
#[test]
fn a_deny_without_versions_is_no_vulnerable_version_entry() {
    let deny = crit("signer.publisher", "equals", &["Example Ltd"]);
    let allow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), ver("meta.file_version", "version_ge", &["1.0"])]});
    let found = lint(&vuln_doc(deny, allow), &Facts::default());
    assert!(
        !has(&found, FindingCode::VulnerableVersionAllowed, 2),
        "{found:?}"
    );
}

/// analysis/mod.rs:1495: every field either side constrains must overlap.
#[test]
fn disjoint_product_versions_are_no_overlap() {
    let deny = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]),
        ver("meta.file_version", "version_lt", &["2.0"]), ver("meta.product_version", "version_lt", &["5.0"])]});
    let allow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]),
        ver("meta.file_version", "version_ge", &["1.0"]), ver("meta.product_version", "version_ge", &["5.0"])]});
    let found = lint(&vuln_doc(deny, allow), &Facts::default());
    assert!(
        !has(&found, FindingCode::VulnerableVersionAllowed, 2),
        "{found:?}"
    );
}

/// analysis/mod.rs:1551: a version test no version can pass is an empty
/// range, not "unconstrained".
#[test]
fn an_impossible_version_test_is_an_empty_range() {
    let c = |op: &str, v: &[&str]| -> Criterion {
        serde_json::from_value(
            serde_json::json!({"field": "meta.file_version", "operator": op, "values": v}),
        )
        .unwrap()
    };
    assert_eq!(version_ranges(&c("version_lt", &["0.0.0.0"])), Some(vec![]));
    assert_eq!(
        version_ranges(&c("version_gt", &["65535.65535.65535.65535"])),
        Some(vec![])
    );
    let deny = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), ver("meta.file_version", "version_lt", &["0.0.0.0"])]});
    let allow = serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), ver("meta.file_version", "version_ge", &["1.0"])]});
    let found = lint(&vuln_doc(deny, allow), &Facts::default());
    assert!(
        !has(&found, FindingCode::VulnerableVersionAllowed, 2),
        "{found:?}"
    );
}

/// analysis/subsume.rs:117: signer options make a criterion narrower, so a
/// publisher deny with `min_key_bits` does not shadow an allow without it.
#[test]
fn signer_options_are_compared_in_proofs() {
    let strict = serde_json::json!({"criterion": {"field": "signer.publisher", "operator": "equals",
        "values": ["Example Ltd"], "signer": {"min_key_bits": 4096}}});
    let found = lint(
        &mixed(vec![
            rule(1, strict, "deny"),
            rule(
                2,
                serde_json::json!({"all": [crit("signer.publisher", "equals", &["Example Ltd"]), hash('a')]}),
                "allow",
            ),
        ]),
        &Facts::default(),
    );
    assert!(!has(&found, FindingCode::Shadowed, 2), "{found:?}");
}
