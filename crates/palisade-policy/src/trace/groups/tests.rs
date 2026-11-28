//! Group provenance in traces and the effective view (#41, #37).
//!
//! The JSON is snapshot-tested in `tests/snapshots/trace/` with the other
//! trace snapshots (`PALISADE_BLESS=1 cargo test -p palisade-policy trace::`).

use std::path::PathBuf;

use serde_json::{Value, json};

use super::*;
use crate::decision::TraceId;
use crate::evaluate::Subject;
use crate::facts::{ObjectFacts, PathVariables};
use crate::hierarchy::tests::{base_nodes, id, policy, rule, set, snapshot, validated};
use crate::hierarchy::{Membership, ValidatedHierarchy};
use crate::mode::DeviceState;
use crate::model::{Field, ObjectType};
use crate::trace::effective::{effective_view, effective_view_with_groups};
use crate::trace::{ObjectExtras, Redactor, Trace, TraceLevel, TraceOptions, Tracer};

const TRACE: TraceId = TraceId([0x37; 16]);

fn node_id(n: u32) -> NodeId {
    NodeId(id(n).parse().unwrap())
}

fn set_node(nodes: &mut [Value], n: u32, extra: Value) {
    let target = json!(id(n));
    for v in nodes.iter_mut().filter(|v| v["id"] == target) {
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
    }
}

fn assign(policy: u32) -> Value {
    json!([{"policy": id(policy), "slot_order": 0}])
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

/// The hierarchy of the snapshots:
///
/// - the global node assigns policy 50 with an allowlist (rules 70 for
///   hash `a`, 71 for hash `b`);
/// - group 10 (`Finance`) assigns policy 51 with a blocklist (rule 72 for
///   hash `c`), and suppresses rule 71;
/// - template 40 (`Kiosk baseline`), linked from group 11, assigns
///   policy 52 with an allowlist (rule 73 for hash `e`);
/// - device 20 is in group 11, under group 10.
fn hierarchy() -> ValidatedHierarchy {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        1,
        json!({"name": "Global", "assignments": assign(50)}),
    );
    set_node(
        &mut nodes,
        10,
        json!({"name": "Finance", "assignments": assign(51), "suppress_inherited": [id(71)]}),
    );
    set_node(
        &mut nodes,
        11,
        json!({"name": "Finance kiosks", "template": id(40)}),
    );
    set_node(&mut nodes, 20, json!({"name": "KIOSK-07"}));
    nodes.push(crate::hierarchy::tests::node(
        40,
        "template",
        Some(2),
        json!({"name": "Kiosk baseline", "assignments": assign(52)}),
    ));
    validated(&snapshot(
        nodes,
        vec![
            policy(
                50,
                "enforce",
                vec![set(
                    60,
                    "allowlist",
                    false,
                    vec![rule(70, "allow", 'a'), rule(71, "allow", 'b')],
                )],
            ),
            policy(
                51,
                "enforce",
                vec![set(61, "blocklist", false, vec![rule(72, "deny", 'c')])],
            ),
            policy(
                52,
                "enforce",
                vec![set(62, "allowlist", false, vec![rule(73, "allow", 'e')])],
            ),
        ],
        vec![],
    ))
}

fn device(h: &ValidatedHierarchy) -> EffectivePolicy {
    h.effective_policy_as(node_id(20), &Membership::default())
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn trace(e: &EffectivePolicy, h: &ValidatedHierarchy, hash: char, options: &TraceOptions) -> Trace {
    let policy = e.policy().unwrap();
    let facts = ObjectFacts::new().with(Field::HashSha256, sha(hash));
    let vars = PathVariables::new();
    let context = crate::context::EvaluationContext::default();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &context,
    };
    Tracer::new(policy)
        .unwrap()
        .with_groups(GroupProvenance::new(e, h))
        .trace(
            &subject,
            &ObjectExtras::default(),
            &DeviceState::of(&policy.document().policy),
            TRACE,
            options,
        )
}

fn snapshot_json(name: &str, value: &impl serde::Serialize) {
    let mut text = serde_json::to_string_pretty(value).unwrap();
    text.push('\n');
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/trace")
        .join(format!("{name}.json"));
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == text,
        "{} differs:\n{text}\nRegenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-policy trace::",
        path.display()
    );
}

fn kinds(steps: &[InheritanceStep]) -> Vec<(&'static str, Option<&'static str>)> {
    steps.iter().map(|s| (s.node, s.outcome)).collect()
}

#[test]
fn the_deciding_rule_names_the_groups_it_came_from() {
    let h = hierarchy();
    let e = device(&h);
    let t = trace(&e, &h, 'c', &TraceOptions::at(TraceLevel::Standard));
    assert_eq!(
        t.decision.as_ref().unwrap().outcome(),
        crate::decision::Outcome::Blocked
    );
    // Rule 72 comes from Finance through policy 51, then the document.
    assert_eq!(
        kinds(&t.inheritance),
        [
            ("group", Some("contributed")),
            ("policy", None),
            ("rule_set", None),
            ("rule", None),
        ]
    );
    let finance = &t.inheritance[0];
    assert_eq!(finance.id, id(10));
    assert_eq!(finance.name, "Finance");
    assert_eq!(
        finance.via.as_deref(),
        Some(format!("policy {} (slot 0)", id(51)).as_str())
    );
    snapshot_json("inheritance-groups", &t.inheritance);
}

#[test]
fn a_template_layer_names_the_node_that_links_it() {
    let h = hierarchy();
    let e = device(&h);
    let t = trace(&e, &h, 'e', &TraceOptions::at(TraceLevel::Standard));
    let first = &t.inheritance[0];
    assert_eq!(
        (first.node, first.name.as_str()),
        ("template", "Kiosk baseline")
    );
    assert_eq!(first.template_for.as_deref(), Some(id(11).as_str()));
}

#[test]
fn a_suppressed_rule_names_the_group_that_suppressed_it() {
    let h = hierarchy();
    let e = device(&h);
    let g = GroupProvenance::new(&e, &h);
    let p = e
        .rule(crate::model::RuleId(id(71).parse().unwrap()))
        .unwrap();
    let steps = g.steps(p.rule_set_id, p.rule_id, &Privacy::DEFAULT);
    assert_eq!(
        kinds(&steps),
        [
            ("global", Some("contributed")),
            ("group", Some("suppressed"))
        ]
    );
    assert_eq!(steps[1].name, "Finance");
}

#[test]
fn a_reasserted_rule_says_the_suppression_was_overridden() {
    // Group 10 suppresses rule 70, but the device assigns its rule set
    // again, so it stays active.
    let s = set(60, "allowlist", false, vec![rule(70, "allow", 'a')]);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(50)}));
    set_node(&mut nodes, 10, json!({"suppress_inherited": [id(70)]}));
    set_node(&mut nodes, 20, json!({"assignments": assign(51)}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![s.clone()]),
            policy(51, "enforce", vec![s]),
        ],
        vec![],
    ));
    let e = device(&h);
    let t = trace(&e, &h, 'a', &TraceOptions::at(TraceLevel::Standard));
    assert_eq!(
        kinds(&t.inheritance)[..3],
        [
            ("global", Some("contributed")),
            ("device", Some("contributed")),
            ("group", Some("suppression_overridden")),
        ]
    );
}

#[test]
fn group_names_follow_the_trace_redaction() {
    let h = hierarchy();
    let e = device(&h);
    let options = TraceOptions {
        privacy: Privacy {
            redactor: Redactor::new(&["Finance"]).unwrap(),
            ..Privacy::DEFAULT
        },
        ..TraceOptions::at(TraceLevel::Standard)
    };
    let t = trace(&e, &h, 'c', &options);
    assert_eq!(t.inheritance[0].name, "[redacted]");
    // The ID is always written, so the step can still be looked up.
    assert_eq!(t.inheritance[0].id, id(10));
    // Names pass the same writer as every value: a redaction pattern
    // that matches part of a name redacts that part.
    let options = TraceOptions {
        privacy: Privacy {
            redactor: Redactor::new(&["ance$"]).unwrap(),
            ..Privacy::DEFAULT
        },
        ..TraceOptions::at(TraceLevel::Standard)
    };
    let t = trace(&e, &h, 'c', &options);
    assert_eq!(t.inheritance[0].name, "Fin[redacted]");
}

#[test]
fn a_minimal_trace_has_no_provenance() {
    let h = hierarchy();
    let e = device(&h);
    let t = trace(&e, &h, 'c', &TraceOptions::at(TraceLevel::Minimal));
    assert!(t.inheritance.is_empty());
}

#[test]
fn a_tracer_without_groups_names_only_the_document() {
    let h = hierarchy();
    let e = device(&h);
    let policy = e.policy().unwrap();
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('c'));
    let vars = PathVariables::new();
    let context = crate::context::EvaluationContext::default();
    let t = Tracer::new(policy).unwrap().trace(
        &Subject {
            object_type: ObjectType::Executable,
            facts: &facts,
            variables: &vars,
            context: &context,
        },
        &ObjectExtras::default(),
        &DeviceState::of(&policy.document().policy),
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
    );
    assert_eq!(
        kinds(&t.inheritance),
        [("policy", None), ("rule_set", None), ("rule", None)]
    );
}

#[test]
fn the_effective_view_shows_group_provenance_for_every_rule() {
    let h = hierarchy();
    let e = device(&h);
    let policy = e.policy().unwrap();
    let state = DeviceState::of(&policy.document().policy);
    let g = GroupProvenance::new(&e, &h);
    let v = effective_view_with_groups(policy, &state, None, &g, &Privacy::DEFAULT);
    let by_rule = |n: u32| {
        v.rules
            .iter()
            .find(|r| r.rule.rule_id.to_string() == id(n))
            .unwrap()
    };
    assert_eq!(by_rule(70).provenance[0].node, "global");
    assert_eq!(by_rule(72).provenance[0].name, "Finance");
    assert_eq!(by_rule(73).provenance[0].node, "template");
    // The suppressed rule shows who suppressed it, and is inactive.
    let suppressed = by_rule(71);
    assert!(!suppressed.active);
    assert_eq!(suppressed.inactive_reason, Some("suppressed"));
    assert!(
        suppressed
            .provenance
            .iter()
            .any(|s| s.outcome == Some("suppressed") && s.name == "Finance")
    );
    // Every rule ends with its policy and rule set.
    for r in &v.rules {
        let tail: Vec<&str> = r.provenance.iter().rev().take(2).map(|s| s.node).collect();
        assert_eq!(tail, ["rule_set", "policy"]);
    }
    // Without groups, the same view lists only the document, and the
    // suppressed rule is only `disabled`.
    let plain = effective_view(policy, &state, None);
    assert!(plain.rules.iter().all(|r| r.provenance.len() == 2));
    assert!(
        plain
            .rules
            .iter()
            .any(|r| r.inactive_reason == Some("disabled"))
    );
    assert_eq!(plain.rules.len(), v.rules.len());
    snapshot_json("effective-view-groups", &v);
}

#[test]
fn unknown_nodes_and_rules_are_handled() {
    // Provenance from one hierarchy, names from another that lacks the
    // nodes: each is named by its ID, with the kind `node`.
    let h = hierarchy();
    let e = device(&h);
    let empty = validated(&snapshot(base_nodes(), vec![], vec![]));
    let g = GroupProvenance::new(&e, &empty);
    let p = e
        .rule(crate::model::RuleId(id(73).parse().unwrap()))
        .unwrap();
    let steps = g.steps(p.rule_set_id, p.rule_id, &Privacy::DEFAULT);
    assert_eq!(steps[0].node, "node");
    assert_eq!(steps[0].name, id(40));
    // A rule set the provenance does not hold has no group steps.
    let none = g.steps(
        crate::model::RuleSetId(id(999).parse().unwrap()),
        crate::model::RuleId(id(998).parse().unwrap()),
        &Privacy::DEFAULT,
    );
    assert!(none.is_empty());
}

#[test]
fn each_way_a_node_contributes_is_described() {
    let lib = crate::library::LibraryId(id(5).parse().unwrap());
    let c = |via| Contribution {
        node: node_id(1),
        template_for: None,
        via,
    };
    assert_eq!(
        super::via(&c(Via::Library {
            library: lib,
            version: 3
        })),
        format!("library {} v3", id(5))
    );
    assert_eq!(
        super::via(&c(Via::Category {
            category: "Security".to_owned(),
            library: lib,
            version: 2,
        })),
        format!("category Security: library {} v2", id(5))
    );
    assert_eq!(super::via(&c(Via::Node)), "node settings");
}
