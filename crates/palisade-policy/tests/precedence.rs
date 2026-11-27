//! The precedence conformance suite (#35).
//!
//! Every file in `tests/precedence/` describes rule sets, one object, and
//! the decision expected under each of the five precedence models. One
//! fixture is checked under every model, so the differences between the
//! models are visible side by side. The format:
//!
//! - `description`: what the case shows.
//! - `rule_sets`: rule sets as in a policy document, without IDs. Rules are
//!   named, and the expected decision refers to them by name. The suite
//!   gives rule set `i` and rule `j` (counting over the whole file) fixed
//!   IDs, so rule IDs grow in file order.
//! - `object`: the object's type and facts (see [`Object`]).
//! - `expect`: one entry per model, with optional `options`, and the
//!   expected `outcome`, `reason`, deciding `rule` (absent for the implicit
//!   deny), `overridden` rules, `annotations` and `trust_sources`. The lists
//!   are compared without order; the decision itself sorts them by rule ID.
//!
//! Each document is read with the strict JSON reader and validated, so a
//! fixture can only describe a policy a real author could write.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use palisade_core::ObjectType;
use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::{Decision, RuleRef, TraceId};
use palisade_policy::dsl::{self, Limits};
use palisade_policy::evaluate::{Evaluator, Subject};
use palisade_policy::facts::{
    ObjectFacts, PathFact, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use palisade_policy::model::{Field, PolicyDocument};
use serde::Deserialize;

const MODELS: [&str; 5] = [
    "deny_wins",
    "allow_wins",
    "specificity",
    "first_match",
    "priority",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    description: String,
    rule_sets: Vec<serde_json::Value>,
    object: Object,
    expect: Vec<Expect>,
}

/// The object a fixture decides. Every fact not given is unknown.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    /// The object type, as in `object_types`.
    #[serde(rename = "type")]
    object_type: String,
    sha256: Option<String>,
    /// The publisher of one valid embedded signature.
    publisher: Option<String>,
    path: Option<String>,
    /// Whether users can write the path. Unknown if absent.
    user_writable: Option<bool>,
    file_version: Option<String>,
    product_name: Option<String>,
    original_filename: Option<String>,
    /// The groups in the user's token.
    user_groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expect {
    model: String,
    #[serde(default)]
    options: serde_json::Map<String, serde_json::Value>,
    outcome: String,
    reason: String,
    rule: Option<String>,
    #[serde(default)]
    overridden: Vec<String>,
    #[serde(default)]
    annotations: Vec<String>,
    #[serde(default)]
    trust_sources: Vec<String>,
}

fn uuid(group: &str, n: usize) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d{group}")
}

/// The policy document of a fixture under one model, with IDs filled in,
/// and the rule names by rule ID.
fn document(f: &Fixture, e: &Expect) -> (PolicyDocument, BTreeMap<String, String>) {
    let mut names = BTreeMap::new();
    let mut rule_number = 0usize;
    let mut sets = Vec::new();
    for (i, set) in f.rule_sets.iter().enumerate() {
        let mut set = set.clone();
        let object = set.as_object_mut().unwrap();
        object.insert("id".into(), uuid("4e60", i).into());
        let rules = object
            .get_mut("rules")
            .and_then(serde_json::Value::as_array_mut)
            .unwrap();
        for rule in rules {
            let id = uuid("4e61", rule_number);
            rule_number += 1;
            let name = rule["name"].as_str().unwrap().to_owned();
            assert!(
                names.insert(id.clone(), name).is_none(),
                "duplicate rule ID"
            );
            rule.as_object_mut().unwrap().insert("id".into(), id.into());
        }
        sets.push(set);
    }
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Conformance",
            "revision": 1,
            "mode": "enforce",
            "precedence_model": e.model,
            "precedence_options": e.options,
            "rule_sets": (0..f.rule_sets.len()).map(|i| uuid("4e60", i)).collect::<Vec<_>>(),
        },
        "rule_sets": sets,
    });
    (PolicyDocument::from_json(&json.to_string()).unwrap(), names)
}

fn facts(o: &Object) -> ObjectFacts {
    let mut facts = ObjectFacts::new();
    for (field, value) in [
        (Field::HashSha256, &o.sha256),
        (Field::MetaFileVersion, &o.file_version),
        (Field::MetaProductName, &o.product_name),
        (Field::MetaOriginalFilename, &o.original_filename),
    ] {
        if let Some(v) = value {
            facts.set(field, v.clone());
        }
    }
    if let Some(path) = &o.path {
        let mut fact = PathFact::new(path, &VolumeMap::new());
        fact.user_writable = o.user_writable;
        facts.path = Some(fact);
    }
    if let Some(publisher) = &o.publisher {
        facts.signers = Some(vec![SignerFact {
            status: SignerStatus::Valid,
            source: SignatureSource::Embedded,
            publisher: Some(publisher.clone()),
            issuer: None,
            leaf_thumbprint_sha256: None,
            details: Default::default(),
        }]);
    }
    facts
}

fn names(refs: &[RuleRef], names: &BTreeMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = refs
        .iter()
        .map(|r| names[&r.rule_id.to_string()].clone())
        .collect();
    out.sort();
    out
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v
}

fn check(path: &Path) {
    let text = fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let value = dsl::to_json_value(&text, &Limits::DEFAULT)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let f: Fixture =
        serde_json::from_value(value).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert!(!f.description.trim().is_empty());
    for model in MODELS {
        assert!(
            f.expect.iter().any(|e| e.model == model),
            "{}: no expectation for {model}",
            path.display()
        );
    }
    let object_type: ObjectType = f.object.object_type.parse().unwrap();
    let facts = facts(&f.object);
    let variables = PathVariables::new();
    let mut context = EvaluationContext::new();
    context.user.groups.clone_from(&f.object.user_groups);
    for e in &f.expect {
        let at = format!("{} under {} {:?}", path.display(), e.model, e.options);
        let (doc, rule_names) = document(&f, e);
        let policy = doc
            .validate()
            .unwrap_or_else(|errors| panic!("{at}: {errors:#?}"));
        let d: Decision = Evaluator::new(&policy).unwrap().evaluate(
            &Subject {
                object_type,
                facts: &facts,
                variables: &variables,
                context: &context,
            },
            TraceId([0; 16]),
        );
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["outcome"], e.outcome.as_str(), "{at}");
        assert_eq!(json["reason_code"], e.reason.as_str(), "{at}");
        let rule = d
            .matched_rule()
            .map(|r| rule_names[&r.rule_id.to_string()].clone());
        assert_eq!(rule, e.rule, "{at}");
        assert_eq!(
            names(d.overridden(), &rule_names),
            sorted(&e.overridden),
            "{at}: overridden"
        );
        assert_eq!(
            names(d.annotations(), &rule_names),
            sorted(&e.annotations),
            "{at}: annotations"
        );
        let grants: Vec<RuleRef> = d
            .directives()
            .trust_sources
            .iter()
            .map(|g| g.rule)
            .collect();
        assert_eq!(
            names(&grants, &rule_names),
            sorted(&e.trust_sources),
            "{at}: trust sources"
        );
    }
}

#[test]
fn conformance_fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/precedence");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    paths.sort();
    assert!(
        paths.len() >= 6,
        "fixtures are missing from {}",
        dir.display()
    );
    for path in paths {
        check(&path);
    }
}
