//! The trace's redactor covers the policy's own values, not only the
//! facts (#41, #18). A path criterion can name a user as easily as a fact
//! can, so the expected values of the deciding rule and of near misses pass
//! the same redactor.

#![allow(clippy::unwrap_used)]

use palisade_core::path::VolumeMap;
use palisade_policy::context::EvaluationContext;
use palisade_policy::decision::{Outcome, TraceId};
use palisade_policy::evaluate::Subject;
use palisade_policy::facts::{ObjectFacts, PathFact, PathVariables};
use palisade_policy::mode::DeviceState;
use palisade_policy::model::{Field, ObjectType, PolicyDocument};
use palisade_policy::trace::{
    Catalog, ObjectExtras, Redactor, TraceLevel, TraceOptions, Tracer, Verbosity, explain,
    render_markdown, render_text,
};
use palisade_policy::validate::ValidatedPolicy;

const SENSITIVE: &str = "alice";

fn policy() -> ValidatedPolicy {
    let rule = |n: u32, name: &str, tree: serde_json::Value, action: &str| {
        serde_json::json!({
            "id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"),
            "display_id": format!("R-{n:06}"),
            "name": name,
            "object_types": ["executable"],
            "match": tree,
            "action": {"type": action},
        })
    };
    let path = |p: &str| serde_json::json!({"criterion": {"field": "path.full", "operator": "equals", "values": [p]}});
    let hash = serde_json::json!({"criterion": {
        "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)],
    }});
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Privacy",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001"],
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001",
            "name": "Set",
            "kind": "mixed",
            "rules": [
                // Decides: blocks this user's copy of the tool.
                rule(1, "Block a user's copy", path(&format!("C:\\Users\\{SENSITIVE}\\tool.exe")), "deny"),
                // A near miss: the hash anchor matches, the user path does not.
                rule(2, "Pinned build in a profile", serde_json::json!({"all": [
                    hash,
                    path(&format!("C:\\Users\\{SENSITIVE}\\other.exe")),
                ]}), "allow"),
            ],
        }],
    });
    PolicyDocument::from_json(&json.to_string())
        .unwrap()
        .validate()
        .unwrap()
}

#[test]
fn policy_values_in_a_trace_pass_the_redactor() {
    let p = policy();
    let tracer = Tracer::new(&p).unwrap();
    let mut path = PathFact::new(
        &format!("C:\\Users\\{SENSITIVE}\\tool.exe"),
        &VolumeMap::new(),
    );
    path.user_writable = Some(false);
    let facts = ObjectFacts::new()
        .with(Field::HashSha256, "a".repeat(64))
        .with_path(path);
    let vars = PathVariables::new();
    let context = EvaluationContext::default();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &context,
    };
    let state = DeviceState::of(&p.document().policy);
    let mut options = TraceOptions::at(TraceLevel::Full);

    // Without a redactor, the policy's value is written as it is.
    let plain = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TraceId([1; 16]),
        &options,
    );
    let json = serde_json::to_string(&plain).unwrap();
    assert!(json.contains(SENSITIVE), "the fixture names the user");

    options.privacy.redactor = Redactor::new(&[r"\\Users\\[^\\]+"]).unwrap();
    let t = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TraceId([1; 16]),
        &options,
    );
    // Redaction changes what is written, never what is decided.
    assert_eq!(t.decision, plain.decision);
    assert_eq!(t.decision.as_ref().unwrap().outcome(), Outcome::Blocked);

    let decisive = t.decisive.as_ref().unwrap();
    assert_eq!(decisive.criteria[0].expected, ["C:[redacted]\\tool.exe"]);
    assert!(!decisive.criteria[0].expected_truncated);
    let near = t
        .near_misses
        .iter()
        .find(|n| n.name == "Pinned build in a profile")
        .unwrap();
    assert_eq!(near.failing[0].expected, ["C:[redacted]\\other.exe"]);

    // Nowhere in the trace or its explanations.
    let json = serde_json::to_string(&t).unwrap();
    assert!(!json.contains(SENSITIVE), "{json}");
    let doc = explain(&t, Verbosity::Detailed);
    let c = Catalog::english();
    for out in [render_text(&doc, &c), render_markdown(&doc, &c)] {
        assert!(!out.contains(SENSITIVE), "{out}");
    }
}

#[test]
fn a_redacted_expected_value_is_still_cut_and_flagged() {
    // A long criterion value is cut after redaction, and the flag says so.
    let p = policy();
    let mut doc = p.into_document();
    let long = format!("C:\\Users\\{SENSITIVE}\\{}.exe", "x".repeat(300));
    doc.rule_sets[0].rules[0].match_ = serde_json::from_value(serde_json::json!({
        "criterion": {"field": "path.full", "operator": "equals", "values": [long]},
    }))
    .unwrap();
    let p = doc.validate().unwrap();
    let tracer = Tracer::new(&p).unwrap();
    let facts = ObjectFacts::new().with_path(PathFact::new(&long, &VolumeMap::new()));
    let vars = PathVariables::new();
    let context = EvaluationContext::default();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &context,
    };
    let mut options = TraceOptions::at(TraceLevel::Standard);
    options.privacy.redactor = Redactor::new(&[r"\\Users\\[^\\]+"]).unwrap();
    let state = DeviceState::of(&p.document().policy);
    let t = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TraceId([2; 16]),
        &options,
    );
    let c = &t.decisive.as_ref().unwrap().criteria[0];
    assert!(c.expected_truncated);
    assert!(
        c.expected[0].starts_with("C:[redacted]\\xxx"),
        "{:?}",
        c.expected
    );
    assert!(!c.expected[0].contains(SENSITIVE));
}
