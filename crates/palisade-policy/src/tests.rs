use proptest::prelude::*;

use crate::model::arbitrary;
use crate::model::{
    Action, Criterion, Field, LoadError, Match, Operator, PolicyDocument, PolicySettings,
    RuleSetKind,
};
use crate::schema::CURRENT;
use crate::validate::{ErrorCode, Severity, ValidationError};

/// The smallest valid document, used as a base by tests that break one thing.
const MINIMAL: &str = r#"{
  "schema_version": "1.0.0",
  "policy": {
    "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
    "name": "Minimal",
    "revision": 1,
    "mode": "audit"
  }
}"#;

fn minimal() -> PolicyDocument {
    PolicyDocument::from_json(MINIMAL).unwrap()
}

fn sha256(seed: char) -> String {
    std::iter::repeat_n(seed, 64).collect()
}

fn leaf(field: Field, operator: Operator, values: &[&str]) -> Match {
    Match::Criterion(Criterion {
        field,
        operator,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
        case_sensitive: None,
    })
}

/// Builds a document with one rule set holding one rule with this tree and action.
fn with_rule(tree: Match, action: Action) -> PolicyDocument {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "One rule",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"]
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
            "name": "Set",
            "kind": "mixed",
            "rules": [{
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
                "name": "Rule",
                "match": tree,
                "action": action
            }]
        }]
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn codes(errors: &[ValidationError]) -> Vec<(ErrorCode, &str)> {
    errors.iter().map(|e| (e.code, e.path.as_str())).collect()
}

#[test]
fn minimal_document_gets_documented_defaults() {
    let doc = minimal();
    assert_eq!(doc.policy.settings, PolicySettings::default());
    assert_eq!(doc.policy.settings.poll_interval_secs, 900);
    assert_eq!(doc.policy.settings.max_ancestor_depth, 8);
    assert!(!doc.policy.settings.capture_command_line);
    assert_eq!(
        doc.policy.precedence_model,
        crate::model::PrecedenceModel::DenyWins
    );
    let validated = doc.validate().unwrap();
    assert!(validated.warnings().is_empty());
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    let base: serde_json::Value = serde_json::from_str(MINIMAL).unwrap();
    for pointer in ["", "/policy", "/policy/settings"] {
        let mut doc = base.clone();
        if pointer == "/policy/settings" {
            doc["policy"]["settings"] = serde_json::json!({});
        }
        doc.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("surprise".to_owned(), true.into());
        let err = PolicyDocument::from_json(&doc.to_string()).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "{pointer}: {err}"
        );
    }
}

#[test]
fn enums_are_strings_not_integers() {
    let text = MINIMAL.replace("\"audit\"", "2");
    assert!(PolicyDocument::from_json(&text).is_err());
    let json = minimal().to_json_pretty().unwrap();
    assert!(json.contains("\"mode\": \"audit\""));
}

#[test]
fn schema_version_is_checked_before_the_body() {
    let newer = MINIMAL
        .replace("\"1.0.0\"", "\"2.0.0\"")
        .replace("\"revision\"", "\"renamed_in_v2\"");
    assert!(matches!(
        PolicyDocument::from_json(&newer),
        Err(LoadError::UnsupportedSchemaVersion(v)) if v.major == 2
    ));
    let minor = MINIMAL.replace("\"1.0.0\"", "\"1.7.0\"");
    assert!(PolicyDocument::from_json(&minor).is_ok());
    let missing = MINIMAL.replace("\"schema_version\": \"1.0.0\",", "");
    assert!(matches!(
        PolicyDocument::from_json(&missing),
        Err(LoadError::MissingSchemaVersion)
    ));
    let bad = MINIMAL.replace("\"1.0.0\"", "\"v1\"");
    assert!(matches!(
        PolicyDocument::from_json(&bad),
        Err(LoadError::MissingSchemaVersion)
    ));
}

#[test]
fn rename_keeps_id_and_ids_are_canonical() {
    let mut doc = minimal();
    let id = doc.policy.id;
    doc.policy.name = "Renamed".to_owned();
    let back = PolicyDocument::from_json(&doc.to_json_pretty().unwrap()).unwrap();
    assert_eq!(back.policy.id, id);
    let upper = MINIMAL.replace("0a1b2c3d4e5f", "0A1B2C3D4E5F");
    assert!(PolicyDocument::from_json(&upper).is_err());
}

#[test]
fn validation_reports_every_error_in_one_pass() {
    let mut doc = with_rule(
        Match::All(vec![
            leaf(Field::HashSha256, Operator::Wildcard, &["ABC"]),
            leaf(Field::MetaFileVersion, Operator::VersionGe, &["1.0", "2.0"]),
        ]),
        Action::Allow {},
    );
    doc.policy.name = " padded".to_owned();
    doc.policy.settings.poll_interval_secs = 10;
    doc.policy.rule_sets.push(doc.policy.rule_sets[0]);
    let errors = doc.validate().unwrap_err();
    let base = "/rule_sets/0/rules/0/match/all";
    assert_eq!(
        codes(&errors),
        vec![
            (ErrorCode::InvalidName, "/policy/name"),
            (
                ErrorCode::SettingOutOfRange,
                "/policy/settings/poll_interval_secs"
            ),
            (ErrorCode::DuplicateRuleSetRef, "/policy/rule_sets/1"),
            (
                ErrorCode::OperatorFieldMismatch,
                "/rule_sets/0/rules/0/match/all/0/criterion/operator"
            ),
            (
                ErrorCode::InvalidValue,
                &*format!("{base}/0/criterion/values/0")
            ),
            (
                ErrorCode::InvalidValueCount,
                &*format!("{base}/1/criterion/values")
            ),
        ]
    );
    assert!(errors.iter().all(|e| e.severity == Severity::Error));
}

#[test]
fn references_must_resolve_and_ids_must_be_unique() {
    let mut doc = with_rule(
        leaf(Field::HashSha256, Operator::Equals, &[&sha256('a')]),
        Action::Deny {},
    );
    let mut copy = doc.rule_sets[0].clone();
    copy.name = "Copy".to_owned();
    doc.rule_sets.push(copy);
    doc.policy.rule_sets.push(crate::model::RuleSetId(
        "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e99".parse().unwrap(),
    ));
    let errors = doc.validate().unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![
            (ErrorCode::DuplicateId, "/rule_sets/1/id"),
            (ErrorCode::UnknownRuleSet, "/policy/rule_sets/1"),
            (ErrorCode::DuplicateId, "/rule_sets/1/rules/0/id"),
        ]
    );
}

#[test]
fn tree_limits_are_enforced() {
    let hash = sha256('b');
    let mut deep = leaf(Field::HashSha256, Operator::Equals, &[&hash]);
    for _ in 0..8 {
        deep = Match::All(vec![deep]);
    }
    assert_eq!(deep.depth(), 9);
    let errors = with_rule(deep, Action::Deny {}).validate().unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(ErrorCode::TreeTooDeep, "/rule_sets/0/rules/0/match")]
    );

    let wide = Match::Any(
        (0..33)
            .map(|_| leaf(Field::HashSha256, Operator::Equals, &[&hash]))
            .collect(),
    );
    let errors = with_rule(wide, Action::Deny {}).validate().unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(ErrorCode::TooManyCriteria, "/rule_sets/0/rules/0/match")]
    );

    let values: Vec<&str> = std::iter::repeat_n(hash.as_str(), 26).collect();
    let errors = with_rule(
        leaf(Field::HashSha256, Operator::Equals, &values),
        Action::Deny {},
    )
    .validate()
    .unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(
            ErrorCode::InvalidValueCount,
            "/rule_sets/0/rules/0/match/criterion/values"
        )]
    );
}

#[test]
fn value_length_is_measured_in_bytes() {
    // 683 three-byte characters: 683 characters but 2049 bytes.
    let long: String = std::iter::repeat_n('\u{4e2d}', 683).collect();
    let errors = with_rule(
        Match::All(vec![
            leaf(Field::HashSha256, Operator::Equals, &[&sha256('c')]),
            leaf(Field::MetaProductName, Operator::Equals, &[&long]),
        ]),
        Action::Allow {},
    )
    .validate()
    .unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(
            ErrorCode::InvalidValue,
            "/rule_sets/0/rules/0/match/all/1/criterion/values/0"
        )]
    );
}

#[test]
fn allow_rules_need_a_strong_positive_identity() {
    // Only a negated identity: nothing identifies the object.
    let negated = Match::Not(Box::new(leaf(
        Field::HashSha256,
        Operator::Equals,
        &[&sha256('d')],
    )));
    let errors = with_rule(negated.clone(), Action::Allow {})
        .validate()
        .unwrap_err();
    assert_eq!(errors[0].code, ErrorCode::NoIdentityAnchor);
    // The same tree is fine on a deny rule.
    assert!(with_rule(negated, Action::Deny {}).validate().is_ok());

    // SHA-1 alone cannot allow (ADR 0008), but can deny.
    let sha1: String = std::iter::repeat_n('e', 40).collect();
    let weak = leaf(Field::HashSha1, Operator::Equals, &[&sha1]);
    let errors = with_rule(weak.clone(), Action::Allow {})
        .validate()
        .unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(ErrorCode::WeakHashOnlyAllow, "/rule_sets/0/rules/0/match")]
    );
    assert!(with_rule(weak.clone(), Action::Deny {}).validate().is_ok());

    // `any` needs an identity on every branch.
    let path = leaf(Field::PathFull, Operator::Equals, &["C:\\Tools\\a.exe"]);
    let either = Match::Any(vec![weak.clone(), path.clone()]);
    let errors = with_rule(either, Action::Allow {}).validate().unwrap_err();
    assert_eq!(errors[0].code, ErrorCode::WeakHashOnlyAllow);
    let open_branch = Match::Any(vec![
        path.clone(),
        Match::Not(Box::new(leaf(
            Field::HashSha256,
            Operator::Equals,
            &[&sha256('9')],
        ))),
    ]);
    let errors = with_rule(open_branch, Action::Allow {})
        .validate()
        .unwrap_err();
    assert_eq!(errors[0].code, ErrorCode::NoIdentityAnchor);
    // A negative operator does not identify anything either.
    let negative = leaf(Field::PathFull, Operator::NotEquals, &["C:\\x.exe"]);
    let errors = with_rule(negative, Action::Allow {})
        .validate()
        .unwrap_err();
    assert_eq!(errors[0].code, ErrorCode::NoIdentityAnchor);
    // `all` takes the strongest child.
    let both_paths = Match::All(vec![Match::Any(vec![weak.clone(), path.clone()]), path]);
    assert!(with_rule(both_paths, Action::Allow {}).validate().is_ok());

    // SHA-1 together with SHA-256 is fine.
    let both = Match::All(vec![
        weak,
        leaf(Field::HashSha256, Operator::Equals, &[&sha256('f')]),
    ]);
    assert!(with_rule(both, Action::Allow {}).validate().is_ok());
}

#[test]
fn mandatory_is_only_for_blocklists_of_denies() {
    let mut doc = with_rule(
        leaf(Field::HashSha256, Operator::Equals, &[&sha256('1')]),
        Action::Audit {},
    );
    doc.rule_sets[0].mandatory = true;
    let errors = doc.clone().validate().unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![
            (ErrorCode::MandatoryNotBlocklist, "/rule_sets/0/mandatory"),
            (
                ErrorCode::MandatoryRuleNotDeny,
                "/rule_sets/0/rules/0/action"
            ),
        ]
    );
    doc.rule_sets[0].kind = RuleSetKind::Blocklist;
    doc.rule_sets[0].rules[0].action = Action::Deny {};
    assert!(doc.validate().is_ok());
}

#[test]
fn allow_wins_is_a_warning_not_an_error() {
    let mut doc = minimal();
    doc.policy.precedence_model = crate::model::PrecedenceModel::AllowWins;
    let validated = doc.validate().unwrap();
    assert_eq!(
        validated.warnings()[0].code,
        ErrorCode::AllowWinsNotRecommended
    );
    assert_eq!(validated.warnings()[0].severity, Severity::Warning);
}

#[test]
fn advanced_keys_need_the_registry_or_the_opt_in() {
    let mut doc = minimal();
    doc.policy
        .settings
        .advanced
        .insert("a/b~c".to_owned(), crate::model::AdvancedValue::Bool(true));
    let errors = doc.clone().validate().unwrap_err();
    assert_eq!(
        codes(&errors),
        vec![(
            ErrorCode::UnknownAdvancedKey,
            "/policy/settings/advanced/a~1b~0c"
        )]
    );
    doc.policy.settings.allow_unknown_advanced = true;
    assert!(doc.validate().is_ok());
}

#[test]
fn error_display_is_stable() {
    let mut doc = minimal();
    doc.policy.name = String::new();
    let errors = doc.validate().unwrap_err();
    assert_eq!(
        errors[0].to_string(),
        "error[invalid_name] /policy/name: must not be empty or only whitespace"
    );
}

#[test]
fn schema_version_constant_matches_written_documents() {
    let json = minimal().to_json_pretty().unwrap();
    assert!(json.contains(&format!("\"schema_version\": \"{CURRENT}\"")));
}

struct CompiledSchema {
    schemas: boon::Schemas,
    index: boon::SchemaIndex,
}

thread_local! {
    static SCHEMA: CompiledSchema = {
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler.enable_format_assertions();
        compiler.add_resource(crate::schema::SCHEMA_ID, crate::schema::generate()).unwrap();
        let index = compiler.compile(crate::schema::SCHEMA_ID, &mut schemas).unwrap();
        CompiledSchema { schemas, index }
    };
}

fn cases(default: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    ProptestConfig::with_cases(cases)
}

proptest! {
    #![proptest_config(cases(512))]

    #[test]
    fn generated_documents_are_valid(doc in arbitrary::document()) {
        let result = doc.validate();
        prop_assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn generated_documents_match_the_json_schema(doc in arbitrary::document()) {
        let value = serde_json::to_value(&doc).unwrap();
        let result = SCHEMA.with(|s| s.schemas.validate(&value, s.index).map_err(|e| format!("{e:#}")));
        prop_assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
    }

    #[test]
    fn from_json_never_panics(text in "\\PC{0,200}") {
        let _ = PolicyDocument::from_json(&text);
    }
}

proptest! {
    // The acceptance criterion in #30: 10k random policies round-trip.
    #![proptest_config(cases(10_000))]

    #[test]
    fn json_round_trip_is_lossless(doc in arbitrary::document()) {
        let text = doc.to_json_pretty().unwrap();
        let back = PolicyDocument::from_json(&text).unwrap();
        prop_assert_eq!(&back, &doc);
        // Serialising again gives the same bytes.
        prop_assert_eq!(back.to_json_pretty().unwrap(), text);
    }
}
