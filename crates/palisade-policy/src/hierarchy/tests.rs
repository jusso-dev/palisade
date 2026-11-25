//! Tests of the hierarchy and the effective policy (#37).
//!
//! Snapshots are written as JSON with short helpers. Node, policy, rule
//! set and rule IDs are numbered: `id(n)` is a UUIDv7 whose leading bits
//! grow with `n`.

use proptest::prelude::*;
use serde_json::{Value, json};

use super::*;
use crate::context::EvaluationContext;
use crate::decision::Outcome;
use crate::decision::TraceId;
use crate::evaluate::{Evaluator, Subject};
use crate::facts::{ObjectFacts, PathFact, PathVariables};
use crate::library::LibraryId;
use crate::mode::{DeviceState, strictness};
use crate::model::{ControlLevel, Field, ObjectType, RuleSetId};
use palisade_core::path::VolumeMap;

pub(crate) fn id(n: u32) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e5f")
}

fn node_id(n: u32) -> NodeId {
    NodeId(id(n).parse().unwrap())
}

fn rule_id(n: u32) -> RuleId {
    RuleId(id(n).parse().unwrap())
}

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn hash_crit(c: char) -> Value {
    json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha(c)]}})
}

pub(crate) fn rule(n: u32, action: &str, c: char) -> Value {
    json!({
        "id": id(n),
        "name": format!("Rule {n}"),
        "object_types": ["executable"],
        "match": hash_crit(c),
        "action": {"type": action},
    })
}

pub(crate) fn set(n: u32, kind: &str, mandatory: bool, rules: Vec<Value>) -> Value {
    json!({
        "id": id(n),
        "name": format!("Set {n}"),
        "kind": kind,
        "mandatory": mandatory,
        "rules": rules,
    })
}

/// A global policy entry.
pub(crate) fn policy(n: u32, mode: &str, sets: Vec<Value>) -> Value {
    policy_with(n, mode, sets, json!({}))
}

fn policy_with(n: u32, mode: &str, sets: Vec<Value>, extra: Value) -> Value {
    let mut p = json!({
        "id": id(n),
        "name": format!("Policy {n}"),
        "revision": 1,
        "mode": mode,
        "rule_sets": sets.iter().map(|s| s["id"].clone()).collect::<Vec<_>>(),
    });
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    json!({
        "realm": "global",
        "document": {"schema_version": "1.0.0", "policy": p, "rule_sets": sets},
    })
}

pub(crate) fn node(n: u32, kind: &str, parent: Option<u32>, extra: Value) -> Value {
    let mut v = json!({"id": id(n), "name": format!("Node {n}"), "kind": kind});
    if let Some(p) = parent {
        v["parent"] = json!(id(p));
    }
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

fn assign(policies: &[(u32, u32)]) -> Value {
    json!(
        policies
            .iter()
            .map(|(p, slot)| json!({"policy": id(*p), "slot_order": slot}))
            .collect::<Vec<_>>()
    )
}

/// The standard tree: global 1, tenant 2 (unassigned 3), group 10 below
/// the tenant, group 11 below 10, device 20 in 11.
pub(crate) fn base_nodes() -> Vec<Value> {
    vec![
        node(1, "global", None, json!({})),
        node(2, "tenant", Some(1), json!({})),
        node(3, "group", Some(2), json!({"builtin": "unassigned"})),
        node(10, "group", Some(2), json!({})),
        node(11, "group", Some(10), json!({})),
        node(20, "device", Some(11), json!({})),
    ]
}

pub(crate) fn snapshot(nodes: Vec<Value>, policies: Vec<Value>, libraries: Vec<Value>) -> Value {
    json!({
        "schema_version": "1.0.0",
        "revision": 7,
        "nodes": nodes,
        "policies": policies,
        "libraries": libraries,
    })
}

/// Replaces the node with `n`'s ID in `nodes` with one that has `extra`.
fn set_node(nodes: &mut [Value], n: u32, extra: Value) {
    let target = json!(id(n));
    for v in nodes.iter_mut() {
        if v["id"] == target {
            for (k, x) in extra.as_object().unwrap() {
                v[k] = x.clone();
            }
        }
    }
}

pub(crate) fn validated(v: &Value) -> ValidatedHierarchy {
    HierarchyDocument::from_json(&v.to_string())
        .unwrap()
        .validate()
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn errors(v: &Value) -> Vec<(String, String)> {
    match HierarchyDocument::from_json(&v.to_string())
        .unwrap()
        .validate()
    {
        Ok(_) => Vec::new(),
        Err(e) => e
            .into_iter()
            .map(|e| (e.code.to_string(), e.path))
            .collect(),
    }
}

fn effective(h: &ValidatedHierarchy, n: u32) -> EffectivePolicy {
    h.effective_policy_as(node_id(n), &Membership::default())
        .unwrap_or_else(|e| panic!("{e:#?}"))
}

fn facts(c: char) -> ObjectFacts {
    ObjectFacts::new()
        .with(Field::HashSha256, sha(c))
        .with_path(
            PathFact::new("C:\\Tools\\tool.exe", &VolumeMap::new()).with_user_writable(false),
        )
}

/// The decision of the effective policy for an executable with hash
/// `c`×64, in its own mode.
fn decide(e: &EffectivePolicy, c: char) -> Outcome {
    let p = e.policy().unwrap();
    let variables = PathVariables::new();
    let context = EvaluationContext::new();
    let f = facts(c);
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &f,
        variables: &variables,
        context: &context,
    };
    let ev = Evaluator::new(p).unwrap();
    ev.evaluate_in(
        &subject,
        &DeviceState::of(&p.document().policy),
        TraceId([1; 16]),
    )
    .map_or(Outcome::Allowed, |d| d.outcome())
}

/// A blocklist library (100) at version `v` with deny rule 500 on hash
/// `a`, in `realm`.
fn blocklist_library(v: u32, mandatory: bool, realm: Value) -> Value {
    json!({
        "id": id(100),
        "version": v,
        "name": "Blocklist",
        "realm": realm,
        "content": {"kind": "rule_set", "rule_set": set(100, "blocklist", mandatory, vec![rule(500 + v, "deny", 'a')])},
    })
}

#[test]
fn rules_are_the_union_of_every_layer_with_provenance() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 10, json!({"assignments": assign(&[(51, 0)])}));
    set_node(&mut nodes, 20, json!({"assignments": assign(&[(52, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy(
                50,
                "enforce",
                vec![set(60, "blocklist", false, vec![rule(70, "deny", 'a')])],
            ),
            policy(
                51,
                "enforce",
                vec![set(61, "allowlist", false, vec![rule(71, "allow", 'b')])],
            ),
            policy(
                52,
                "enforce",
                vec![set(62, "allowlist", false, vec![rule(72, "allow", 'c')])],
            ),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    let doc = e.policy().unwrap().document();
    assert_eq!(doc.rule_sets.len(), 3);
    assert_eq!(
        e.rule(rule_id(70)).unwrap().inherited_from(),
        Some(node_id(1))
    );
    assert_eq!(
        e.rule(rule_id(71)).unwrap().inherited_from(),
        Some(node_id(10))
    );
    assert_eq!(
        e.rule(rule_id(72)).unwrap().inherited_from(),
        Some(node_id(20))
    );
    assert_eq!(decide(&e, 'a'), Outcome::Blocked);
    assert_eq!(decide(&e, 'b'), Outcome::Allowed);
    assert_eq!(decide(&e, 'c'), Outcome::Allowed);
    assert_eq!(decide(&e, 'd'), Outcome::Blocked, "the implicit deny");
    assert_eq!(doc.policy.id.0, node_id(20).0);
    assert_eq!(doc.policy.revision, 7);
    // The group sees only its own and inherited rules.
    let g = effective(&h, 10);
    assert!(g.rule(rule_id(72)).is_none());
    assert_eq!(decide(&g, 'c'), Outcome::Blocked);
}

#[test]
fn a_rule_set_two_layers_contribute_is_included_once() {
    let shared = set(60, "allowlist", false, vec![rule(70, "allow", 'b')]);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![shared.clone()]),
            policy(51, "enforce", vec![shared]),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(e.policy().unwrap().document().rule_sets.len(), 1);
    let p = e.rule(rule_id(70)).unwrap();
    let nodes: Vec<NodeId> = p.contributions.iter().map(|c| c.node).collect();
    assert_eq!(nodes, [node_id(1), node_id(11)]);
}

#[test]
fn two_different_rule_sets_with_one_id_are_rejected() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![
            policy(
                50,
                "enforce",
                vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
            ),
            policy(
                51,
                "enforce",
                vec![set(60, "allowlist", false, vec![rule(71, "allow", 'c')])],
            ),
        ],
        vec![],
    ));
    assert!(
        found
            .iter()
            .any(|(c, p)| c == "rule_set_conflict" && p.starts_with("/nodes/4")),
        "{found:?}"
    );
}

#[test]
fn suppression_disables_an_inherited_allow_and_shows_in_provenance() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"suppress_inherited": [id(70)]}));
    let h = validated(&snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(
        e.rule(rule_id(70)).unwrap().status,
        RuleStatus::Suppressed { by: node_id(11) }
    );
    assert_eq!(decide(&e, 'b'), Outcome::Blocked);
    // Above the suppressing node the rule still applies.
    assert_eq!(decide(&effective(&h, 10), 'b'), Outcome::Allowed);
    // The rule stays in the document, disabled.
    let doc = e.policy().unwrap().document();
    assert!(!doc.rule_sets[0].rules[0].enabled);
}

#[test]
fn a_blocklist_cannot_be_suppressed_by_default_and_a_mandatory_one_never() {
    for mandatory in [false, true] {
        let s = set(60, "blocklist", mandatory, vec![rule(70, "deny", 'a')]);
        let mut nodes = base_nodes();
        set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
        set_node(&mut nodes, 11, json!({"suppress_inherited": [id(70)]}));
        let found = errors(&snapshot(
            nodes,
            vec![policy(50, "enforce", vec![s])],
            vec![],
        ));
        assert!(
            found.contains(&(
                "suppress_not_allowed".to_owned(),
                "/nodes/4/suppress_inherited/0".to_owned()
            )),
            "{found:?}"
        );
    }
    // A mandatory set that claims to allow it is rejected outright.
    let mut s = set(60, "blocklist", true, vec![rule(70, "deny", 'a')]);
    s["allow_child_suppress"] = json!(true);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![policy(50, "enforce", vec![s])],
        vec![],
    ));
    assert!(
        found
            .iter()
            .any(|(c, p)| c == "suppress_not_allowed" && p.ends_with("/allow_child_suppress")),
        "{found:?}"
    );
    // An ordinary blocklist that opts in can be suppressed.
    let mut s = set(60, "blocklist", false, vec![rule(70, "deny", 'a')]);
    s["allow_child_suppress"] = json!(true);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"suppress_inherited": [id(70)]}));
    let h = validated(&snapshot(
        nodes,
        vec![policy(50, "enforce", vec![s])],
        vec![],
    ));
    assert_eq!(
        decide(&effective(&h, 20), 'a'),
        Outcome::Blocked,
        "the implicit deny still blocks"
    );
}

#[test]
fn suppressing_a_rule_that_is_not_inherited_is_rejected() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        11,
        json!({
            "assignments": assign(&[(50, 0)]),
            "suppress_inherited": [id(70), id(999)],
        }),
    );
    let found = errors(&snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
        )],
        vec![],
    ));
    assert!(
        found.contains(&(
            "suppress_unknown_rule".to_owned(),
            "/nodes/4/suppress_inherited/0".to_owned()
        )),
        "{found:?}"
    );
    assert!(
        found.contains(&(
            "suppress_unknown_rule".to_owned(),
            "/nodes/4/suppress_inherited/1".to_owned()
        )),
        "{found:?}"
    );
}

#[test]
fn a_nearer_layer_that_assigns_the_set_again_reasserts_a_suppressed_rule() {
    let s = set(60, "allowlist", false, vec![rule(70, "allow", 'b')]);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 10, json!({"suppress_inherited": [id(70)]}));
    set_node(&mut nodes, 20, json!({"assignments": assign(&[(51, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![s.clone()]),
            policy(51, "enforce", vec![s]),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(
        e.rule(rule_id(70)).unwrap().status,
        RuleStatus::Reasserted {
            suppressed_by: node_id(10)
        }
    );
    assert_eq!(decide(&e, 'b'), Outcome::Allowed);
    assert_eq!(decide(&effective(&h, 11), 'b'), Outcome::Blocked);
}

#[test]
fn settings_are_override_by_nearest_and_locks_hold() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        1,
        json!({
            "settings": {"poll_interval_secs": 600, "capture_command_line": true},
            "locked_settings": ["capture_command_line"],
        }),
    );
    set_node(
        &mut nodes,
        10,
        json!({"settings": {"poll_interval_secs": 300, "capture_command_line": false}}),
    );
    set_node(
        &mut nodes,
        20,
        json!({"settings": {"poll_interval_secs": 120}}),
    );
    let h = validated(&snapshot(nodes, vec![], vec![]));
    let e = effective(&h, 20);
    let s = &e.policy().unwrap().document().policy.settings;
    assert_eq!(s.poll_interval_secs, 120);
    assert!(s.capture_command_line, "locked at the global node");
    let p = e.setting("capture_command_line").unwrap();
    assert_eq!(p.source, Some(node_id(1)));
    assert_eq!(p.locked_at, Some(node_id(1)));
    assert_eq!(
        p.steps[1].outcome,
        StepOutcome::BlockedByLock {
            locked_at: node_id(1)
        }
    );
    let poll = e.setting("poll_interval_secs").unwrap();
    assert_eq!(poll.source, Some(node_id(20)));
    assert_eq!(
        poll.steps
            .iter()
            .map(|s| s.outcome.clone())
            .collect::<Vec<_>>(),
        [
            StepOutcome::Overridden,
            StepOutcome::Overridden,
            StepOutcome::Applied
        ]
    );
    // Unset settings come from the default.
    assert_eq!(e.setting("dll_control").unwrap().source, None);
}

#[test]
fn a_lower_slot_wins_a_conflict_on_one_node_and_node_settings_beat_policies() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        10,
        json!({"assignments": assign(&[(51, 5), (50, 1)])}),
    );
    let h = validated(&snapshot(
        nodes.clone(),
        vec![
            policy_with(
                50,
                "audit",
                vec![],
                json!({"settings": {"poll_interval_secs": 300}}),
            ),
            policy_with(
                51,
                "enforce",
                vec![],
                json!({"settings": {"poll_interval_secs": 600}}),
            ),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    let doc = e.policy().unwrap().document();
    assert_eq!(doc.policy.settings.poll_interval_secs, 300);
    assert_eq!(doc.policy.mode, Mode::Audit, "closest: the lowest slot");
    set_node(
        &mut nodes,
        10,
        json!({"settings": {"poll_interval_secs": 900}}),
    );
    let h = validated(&snapshot(
        nodes,
        vec![
            policy_with(
                50,
                "audit",
                vec![],
                json!({"settings": {"poll_interval_secs": 300}}),
            ),
            policy_with(
                51,
                "enforce",
                vec![],
                json!({"settings": {"poll_interval_secs": 600}}),
            ),
        ],
        vec![],
    ));
    assert_eq!(
        effective(&h, 20)
            .policy()
            .unwrap()
            .document()
            .policy
            .settings
            .poll_interval_secs,
        900
    );
}

#[test]
fn mode_merge_strictest_takes_the_strictest_policy_and_layer() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        2,
        json!({"tenant_options": {"mode_merge": "strictest"}}),
    );
    set_node(&mut nodes, 1, json!({"mode": "enforce"}));
    set_node(
        &mut nodes,
        10,
        json!({"assignments": assign(&[(50, 0), (51, 1)])}),
    );
    let h = validated(&snapshot(
        nodes,
        vec![policy(50, "monitor", vec![]), policy(51, "audit", vec![])],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(e.mode().unwrap().mode, Mode::Enforce);
    assert_eq!(e.mode().unwrap().source, Some(node_id(1)));
}

#[test]
fn a_locked_mode_is_a_floor_for_everything_below() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        10,
        json!({"mode": "enforce", "lock_mode": true}),
    );
    set_node(
        &mut nodes,
        20,
        json!({
            "assignments": assign(&[(50, 0)]),
            "mode": "audit",
            "settings": {"script_control": "off", "dll_control": "audit"},
        }),
    );
    let mut deny = rule(70, "deny", 'a');
    deny["enforcement_override"] = json!("never_enforce");
    let mut bl = set(60, "blocklist", false, vec![deny]);
    bl["mode_override"] = json!("monitor");
    let h = validated(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "audit",
            vec![bl],
            json!({"mode_options": {"mode_by_type": {"script.powershell": "monitor"}}}),
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    let doc = e.policy().unwrap().document();
    assert_eq!(doc.policy.mode, Mode::Enforce);
    assert_eq!(
        doc.policy
            .mode_options
            .mode_by_type
            .get(&ObjectType::Script(crate::model::ScriptKind::Powershell)),
        Some(&Mode::Enforce)
    );
    assert_eq!(doc.policy.settings.script_control, ControlLevel::Enforce);
    assert_eq!(doc.policy.settings.dll_control, ControlLevel::Enforce);
    assert_eq!(doc.rule_sets[0].mode_override, Some(Mode::Enforce));
    assert_eq!(
        doc.rule_sets[0].rules[0].enforcement_override,
        crate::model::EnforcementOverride::Inherit
    );
    let m = e.mode().unwrap();
    assert_eq!(m.floor, Some((Mode::Enforce, node_id(10))));
    assert_eq!(m.adjustments.len(), 6, "{:#?}", m.adjustments);
    assert!(e.setting("script_control").unwrap().raised_by_floor);
    assert_eq!(decide(&e, 'a'), Outcome::Blocked);
}

#[test]
fn a_lock_without_any_mode_above_floors_at_audit_and_raising_is_allowed() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 10, json!({"lock_mode": true}));
    set_node(&mut nodes, 11, json!({"mode": "monitor"}));
    let h = validated(&snapshot(nodes.clone(), vec![], vec![]));
    assert_eq!(effective(&h, 20).mode().unwrap().mode, Mode::Audit);
    set_node(&mut nodes, 11, json!({"mode": "enforce"}));
    let h = validated(&snapshot(nodes, vec![], vec![]));
    assert_eq!(effective(&h, 20).mode().unwrap().mode, Mode::Enforce);
}

#[test]
fn with_no_mode_anywhere_the_device_audits_and_unassigned_audits() {
    let mut nodes = base_nodes();
    nodes.push(node(21, "device", Some(3), json!({})));
    let h = validated(&snapshot(nodes, vec![], vec![]));
    let e = effective(&h, 20);
    assert_eq!(e.mode().unwrap().mode, Mode::Audit);
    assert_eq!(e.mode().unwrap().source, None);
    let u = effective(&h, 21);
    assert_eq!(u.mode().unwrap().mode, Mode::Audit);
    assert_eq!(u.mode().unwrap().source, Some(node_id(3)));
}

#[test]
fn an_unmanaged_device_has_no_policy() {
    let mut nodes = base_nodes();
    nodes.push(node(4, "group", Some(2), json!({"builtin": "unmanaged"})));
    nodes.push(node(22, "device", Some(4), json!({})));
    let h = validated(&snapshot(nodes, vec![], vec![]));
    let e = effective(&h, 22);
    assert_eq!(e.management(), Management::Unmanaged);
    assert!(e.policy().is_none());
    assert_eq!(e.content_hash().len(), 64);
}

#[test]
fn the_precedence_model_comes_from_the_tenant_and_groups_need_permission() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        2,
        json!({"precedence": {"model": "first_match"}}),
    );
    let h = validated(&snapshot(nodes.clone(), vec![], vec![]));
    let e = effective(&h, 20);
    assert_eq!(
        e.policy().unwrap().document().policy.precedence_model,
        PrecedenceModel::FirstMatch
    );
    assert_eq!(e.precedence(), Some(PrecedenceSource::Node(node_id(2))));

    set_node(
        &mut nodes,
        10,
        json!({"precedence": {"model": "specificity"}}),
    );
    let found = errors(&snapshot(nodes.clone(), vec![], vec![]));
    assert_eq!(
        found,
        [(
            "precedence_not_allowed".to_owned(),
            "/nodes/3/precedence".to_owned()
        )]
    );
    set_node(
        &mut nodes,
        2,
        json!({"tenant_options": {"allow_group_precedence": true}}),
    );
    let h = validated(&snapshot(nodes, vec![], vec![]));
    assert_eq!(
        effective(&h, 20)
            .policy()
            .unwrap()
            .document()
            .policy
            .precedence_model,
        PrecedenceModel::Specificity
    );
}

#[test]
fn policies_with_another_model_than_the_effective_one_are_rejected() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 10, json!({"assignments": assign(&[(51, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![]),
            policy_with(
                51,
                "enforce",
                vec![],
                json!({"precedence_model": "allow_wins"}),
            ),
        ],
        vec![],
    ));
    assert!(
        found.iter().any(|(c, _)| c == "precedence_conflict"),
        "{found:?}"
    );
}

#[test]
fn policies_whose_options_differ_from_the_effective_ones_are_rejected() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        2,
        json!({"precedence": {"model": "allow_wins"}}),
    );
    set_node(&mut nodes, 10, json!({"assignments": assign(&[(50, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "enforce",
            vec![],
            json!({"precedence_model": "allow_wins", "precedence_options": {"granularity_tiebreak": true}}),
        )],
        vec![],
    ));
    assert!(
        found.contains(&(
            "precedence_conflict".to_owned(),
            "/nodes/3/assignments".to_owned()
        )),
        "{found:?}"
    );
}

#[test]
fn first_match_bands_put_global_rules_first_unless_flat() {
    // The device allows `a` with a low order; the global node denies it
    // with a high order.
    let mut allow = rule(71, "allow", 'a');
    allow["order"] = json!(100_001);
    let mut deny = rule(70, "deny", 'a');
    deny["order"] = json!(900_000);
    let fm = json!({"precedence_model": "first_match"});
    let build = |level: &str| {
        let mut nodes = base_nodes();
        set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
        set_node(
            &mut nodes,
            2,
            json!({"tenant_options": {"level_order": level}}),
        );
        set_node(&mut nodes, 20, json!({"assignments": assign(&[(51, 0)])}));
        validated(&snapshot(
            nodes,
            vec![
                policy_with(
                    50,
                    "enforce",
                    vec![set(60, "blocklist", false, vec![deny.clone()])],
                    fm.clone(),
                ),
                policy_with(
                    51,
                    "enforce",
                    vec![set(61, "allowlist", false, vec![allow.clone()])],
                    fm.clone(),
                ),
            ],
            vec![],
        ))
    };
    assert_eq!(
        decide(&effective(&build("top_down"), 20), 'a'),
        Outcome::Blocked
    );
    assert_eq!(
        decide(&effective(&build("bottom_up"), 20), 'a'),
        Outcome::Allowed
    );
    assert_eq!(
        decide(&effective(&build("flat"), 20), 'a'),
        Outcome::Allowed
    );
    let e = effective(&build("top_down"), 20);
    let bands: Vec<u8> = e
        .policy()
        .unwrap()
        .document()
        .rule_sets
        .iter()
        .map(|s| s.band)
        .collect();
    assert_eq!(bands, [0, 11]);
}

#[test]
fn a_band_written_in_a_policy_is_replaced() {
    let mut s = set(60, "allowlist", false, vec![rule(70, "allow", 'b')]);
    s["band"] = json!(0);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 20, json!({"assignments": assign(&[(50, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![policy(50, "enforce", vec![s])],
        vec![],
    ));
    assert_eq!(
        effective(&h, 20).policy().unwrap().document().rule_sets[0].band,
        11
    );
}

#[test]
fn parent_cycles_are_rejected_with_their_path() {
    let nodes = vec![
        node(1, "global", None, json!({})),
        node(2, "tenant", Some(1), json!({})),
        node(3, "group", Some(2), json!({"builtin": "unassigned"})),
        node(10, "group", Some(12), json!({})),
        node(11, "group", Some(10), json!({})),
        node(12, "group", Some(11), json!({})),
    ];
    let result = HierarchyDocument::from_json(&snapshot(nodes, vec![], vec![]).to_string())
        .unwrap()
        .validate()
        .unwrap_err();
    let cycle: Vec<&HierarchyError> = result
        .iter()
        .filter(|e| e.code == HierarchyCode::NodeCycle)
        .collect();
    assert_eq!(cycle.len(), 1, "{result:#?}");
    assert_eq!(
        cycle[0].message,
        "parents form a cycle: `Node 10` -> `Node 12` -> `Node 11` -> `Node 10`"
    );
}

#[test]
fn groups_nest_at_most_eight_deep() {
    let mut nodes = vec![
        node(1, "global", None, json!({})),
        node(2, "tenant", Some(1), json!({})),
        node(3, "group", Some(2), json!({"builtin": "unassigned"})),
    ];
    for i in 0..8 {
        nodes.push(node(
            10 + i,
            "group",
            Some(if i == 0 { 2 } else { 9 + i }),
            json!({}),
        ));
    }
    assert!(errors(&snapshot(nodes.clone(), vec![], vec![])).is_empty());
    nodes.push(node(18, "group", Some(17), json!({})));
    assert_eq!(
        errors(&snapshot(nodes, vec![], vec![])),
        [("group_too_deep".to_owned(), "/nodes/11/parent".to_owned())]
    );
}

#[test]
fn structure_errors_are_reported() {
    let nodes = vec![
        node(1, "global", None, json!({})),
        node(2, "tenant", Some(1), json!({})),
        node(10, "group", Some(2), json!({"rank": 1})),
        node(20, "device", Some(2), json!({})),
        node(21, "device", Some(99), json!({})),
    ];
    let found = errors(&snapshot(nodes, vec![], vec![]));
    for want in [
        ("invalid_builtin", "/nodes/1"),
        ("field_not_allowed", "/nodes/2/rank"),
        ("invalid_parent", "/nodes/3/parent"),
        ("unknown_node", "/nodes/4/parent"),
    ] {
        assert!(
            found.contains(&(want.0.to_owned(), want.1.to_owned())),
            "{want:?} in {found:?}"
        );
    }
}

#[test]
fn staging_holds_no_devices_but_can_be_dry_run() {
    let mut nodes = base_nodes();
    nodes.push(node(
        4,
        "group",
        Some(2),
        json!({"builtin": "staging", "mode": "enforce"}),
    ));
    let h = validated(&snapshot(nodes.clone(), vec![], vec![]));
    assert_eq!(effective(&h, 4).mode().unwrap().mode, Mode::Enforce);
    nodes.push(node(22, "device", Some(4), json!({})));
    assert!(
        errors(&snapshot(nodes, vec![], vec![]))
            .iter()
            .any(|(c, _)| c == "invalid_parent")
    );
}

#[test]
fn dynamic_groups_add_rules_and_rank_decides_settings() {
    let mut nodes = base_nodes();
    nodes.push(node(
        30,
        "dynamic_group",
        Some(2),
        json!({"rank": 1, "settings": {"poll_interval_secs": 300}}),
    ));
    nodes.push(node(
        31,
        "dynamic_group",
        Some(2),
        json!({
            "rank": 2,
            "settings": {"poll_interval_secs": 600},
            "assignments": assign(&[(50, 0)]),
        }),
    ));
    let h = validated(&snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
        )],
        vec![],
    ));
    let m = Membership {
        dynamic_groups: vec![node_id(31), node_id(30)],
    };
    let e = h.effective_policy(node_id(20), &m).unwrap();
    assert_eq!(
        e.policy()
            .unwrap()
            .document()
            .policy
            .settings
            .poll_interval_secs,
        300
    );
    assert_eq!(decide(&e, 'b'), Outcome::Allowed);
    // The order of the membership does not matter.
    let m2 = Membership {
        dynamic_groups: vec![node_id(30), node_id(31)],
    };
    assert_eq!(
        h.effective_policy(node_id(20), &m2).unwrap().content_hash(),
        e.content_hash()
    );
    // A group that is not a dynamic group of the tenant is rejected.
    let bad = Membership {
        dynamic_groups: vec![node_id(10)],
    };
    assert_eq!(
        h.effective_policy(node_id(20), &bad).unwrap_err()[0].code,
        HierarchyCode::InvalidMembership
    );
}

#[test]
fn a_linked_template_applies_before_its_node_and_a_copy_does_not_link() {
    let mut nodes = base_nodes();
    nodes.push(node(
        40,
        "template",
        Some(2),
        json!({
            "assignments": assign(&[(50, 0)]),
            "settings": {"poll_interval_secs": 300},
        }),
    ));
    set_node(
        &mut nodes,
        11,
        json!({"template": id(40), "settings": {"poll_interval_secs": 600}}),
    );
    let h = validated(&snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(
        e.policy()
            .unwrap()
            .document()
            .policy
            .settings
            .poll_interval_secs,
        600
    );
    let c = &e.rule(rule_id(70)).unwrap().contributions[0];
    assert_eq!((c.node, c.template_for), (node_id(40), Some(node_id(11))));
    let copy = h
        .copy_from_template(
            node_id(40),
            node_id(12),
            "Copy".to_owned(),
            NodeKind::Group,
            node_id(10),
        )
        .unwrap();
    assert_eq!(copy.template, None);
    assert_eq!(copy.assignments.len(), 1);
    assert_eq!(copy.settings.get("poll_interval_secs"), Some(&json!(300)));
}

#[test]
fn template_links_are_checked() {
    let mut nodes = base_nodes();
    nodes.push(node(40, "template", Some(2), json!({"template": id(41)})));
    nodes.push(node(41, "template", Some(2), json!({})));
    set_node(&mut nodes, 11, json!({"template": id(10)}));
    let found = errors(&snapshot(nodes, vec![], vec![]));
    assert!(
        found.contains(&(
            "invalid_template".to_owned(),
            "/nodes/4/template".to_owned()
        )),
        "{found:?}"
    );
    assert!(
        found.contains(&(
            "invalid_template".to_owned(),
            "/nodes/6/template".to_owned()
        )),
        "{found:?}"
    );
}

#[test]
fn settings_keys_and_values_are_checked() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        10,
        json!({
            "settings": {"poll_interval_secs": "often", "no_such_setting": 1},
            "locked_settings": ["nope"],
        }),
    );
    let found = errors(&snapshot(nodes, vec![], vec![]));
    for want in [
        "/nodes/3/settings/poll_interval_secs",
        "/nodes/3/settings/no_such_setting",
        "/nodes/3/locked_settings/0",
    ] {
        assert!(
            found.contains(&("invalid_setting".to_owned(), want.to_owned())),
            "{want} in {found:?}"
        );
    }
}

#[test]
fn an_out_of_range_merged_setting_is_reported_for_the_effective_policy() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        10,
        json!({"settings": {"poll_interval_secs": 5}}),
    );
    let found = errors(&snapshot(nodes, vec![], vec![]));
    assert!(
        found.iter().any(|(c, p)| c == "setting_out_of_range"
            && p == "/nodes/3/effective/policy/settings/poll_interval_secs"),
        "{found:?}"
    );
}

#[test]
fn rule_set_libraries_version_pins_and_categories() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        1,
        json!({"rule_sets": [{"id": id(100), "pin": 1}]}),
    );
    let mut v2 = blocklist_library(2, false, json!("global"));
    v2["content"]["rule_set"]["category_path"] = json!("Security/Blocklists");
    let h = validated(&snapshot(
        nodes.clone(),
        vec![],
        vec![blocklist_library(1, false, json!("global")), v2.clone()],
    ));
    let e = effective(&h, 20);
    assert!(e.rule(rule_id(501)).is_some(), "pinned to version 1");
    assert!(
        e.libraries()
            .contains(&(LibraryId(id(100).parse().unwrap()), 1))
    );

    // Latest tracks version 2.
    set_node(&mut nodes, 1, json!({"rule_sets": [{"id": id(100)}]}));
    let h = validated(&snapshot(
        nodes.clone(),
        vec![],
        vec![blocklist_library(1, false, json!("global")), v2.clone()],
    ));
    assert!(effective(&h, 20).rule(rule_id(502)).is_some());

    // A category assigns every rule set library in or below it.
    set_node(
        &mut nodes,
        1,
        json!({"rule_sets": [], "categories": ["Security"]}),
    );
    let h = validated(&snapshot(
        nodes.clone(),
        vec![],
        vec![blocklist_library(1, false, json!("global")), v2.clone()],
    ));
    let e = effective(&h, 20);
    let c = &e.rule(rule_id(502)).unwrap().contributions[0];
    assert!(matches!(&c.via, Via::Category { category, .. } if category == "Security"));

    // A child cannot pin an older version of an inherited library.
    set_node(
        &mut nodes,
        11,
        json!({"rule_sets": [{"id": id(100), "pin": 1}]}),
    );
    let found = errors(&snapshot(
        nodes,
        vec![],
        vec![blocklist_library(1, false, json!("global")), v2],
    ));
    assert!(
        found.iter().any(|(c, _)| c == "library_version_conflict"),
        "{found:?}"
    );
}

#[test]
fn tenant_libraries_are_invisible_to_other_tenants() {
    let mut nodes = base_nodes();
    nodes.push(node(5, "tenant", Some(1), json!({})));
    nodes.push(node(
        6,
        "group",
        Some(5),
        json!({"builtin": "unassigned", "rule_sets": [{"id": id(100)}]}),
    ));
    let found = errors(&snapshot(
        nodes,
        vec![],
        vec![blocklist_library(1, false, json!({"tenant": id(2)}))],
    ));
    assert!(
        found
            .iter()
            .any(|(c, p)| c == "library_not_visible" && p == "/nodes/7/rule_sets/0"),
        "{found:?}"
    );
}

#[test]
fn match_fragments_are_inlined_and_cycles_are_named() {
    let fragment = |n: u32, v: u32, tree: Value| {
        json!({
            "id": id(n),
            "version": v,
            "name": format!("Fragment {n}"),
            "realm": "global",
            "content": {"kind": "match_fragment", "tree": tree},
        })
    };
    let mut r = rule(70, "allow", 'b');
    r["match"] = json!({"ref": {"id": id(200)}});
    let mut nodes = base_nodes();
    set_node(&mut nodes, 10, json!({"assignments": assign(&[(50, 0)])}));
    let libs = vec![
        fragment(
            200,
            1,
            json!({"all": [{"ref": {"id": id(201)}}, {"criterion": {"field": "path.directory", "operator": "starts_with", "values": ["C:\\Tools"]}}]}),
        ),
        fragment(201, 1, hash_crit('b')),
    ];
    let h = validated(&snapshot(
        nodes.clone(),
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![r.clone()])],
        )],
        libs,
    ));
    let e = effective(&h, 20);
    assert_eq!(decide(&e, 'b'), Outcome::Allowed);
    assert_eq!(e.libraries().len(), 2);

    let libs = vec![
        fragment(
            200,
            1,
            json!({"all": [{"ref": {"id": id(201)}}, hash_crit('b')]}),
        ),
        fragment(
            201,
            1,
            json!({"any": [{"ref": {"id": id(202)}}, hash_crit('b')]}),
        ),
        fragment(202, 1, json!({"not": {"ref": {"id": id(200)}}})),
    ];
    let result = HierarchyDocument::from_json(&snapshot(nodes, vec![], libs).to_string())
        .unwrap()
        .validate()
        .unwrap_err();
    let cycles: Vec<&HierarchyError> = result
        .iter()
        .filter(|e| e.code == HierarchyCode::Library(crate::library::LibraryCode::LibraryCycle))
        .collect();
    assert_eq!(cycles.len(), 1, "{result:#?}");
    assert_eq!(
        cycles[0].message,
        "references form a cycle: `Fragment 200` v1 -> `Fragment 201` v1 -> `Fragment 202` v1 -> `Fragment 200` v1"
    );
}

#[test]
fn a_library_in_use_cannot_be_deleted() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 10, json!({"rule_sets": [{"id": id(100)}]}));
    let h = validated(&snapshot(
        nodes,
        vec![],
        vec![blocklist_library(1, false, json!("global"))],
    ));
    let e = h
        .check_delete(LibraryId(id(100).parse().unwrap()))
        .unwrap_err();
    assert_eq!(e.code, HierarchyCode::InUse);
    assert!(e.message.contains("node `Node 10`"), "{}", e.message);
    assert!(h.check_delete(LibraryId(id(101).parse().unwrap())).is_ok());
}

#[test]
fn placement_is_first_match_with_an_undeletable_catch_all() {
    let mut nodes = base_nodes();
    nodes.push(node(
        12,
        "group",
        Some(2),
        json!({"allow_auto_assignment": false}),
    ));
    let mut snap = snapshot(nodes, vec![], vec![]);
    snap["placement"] = json!([
        {"id": id(80), "tenant": id(2), "order": 2, "target": id(10), "conditions": {"hostname": ["ws-*"]}},
        {"id": id(81), "tenant": id(2), "order": 1, "target": id(11), "conditions": {"hostname": ["ws-1*"]}},
    ]);
    let h = validated(&snap);
    let place = |host: &str, current: Option<u32>| {
        h.place(
            node_id(2),
            current.map(node_id),
            &PlacementFacts {
                hostname: Some(host.to_owned()),
                ..PlacementFacts::default()
            },
            PlacementTrigger::FirstContact,
        )
        .unwrap()
    };
    assert_eq!(
        place("ws-100", None),
        PlacementOutcome::Place {
            group: node_id(11),
            rule: Some(id(81).parse().unwrap())
        }
    );
    assert_eq!(
        place("ws-200", None),
        PlacementOutcome::Place {
            group: node_id(10),
            rule: Some(id(80).parse().unwrap())
        }
    );
    assert_eq!(
        place("srv-1", None),
        PlacementOutcome::Place {
            group: node_id(3),
            rule: None
        }
    );
    assert_eq!(place("ws-100", Some(12)), PlacementOutcome::Kept);
    assert_eq!(
        h.place(
            node_id(2),
            None,
            &PlacementFacts::default(),
            PlacementTrigger::UserChange
        )
        .unwrap(),
        PlacementOutcome::NotEvaluated
    );
    // An opted-out or built-in target is rejected.
    snap["placement"][0]["target"] = json!(id(12));
    snap["placement"][1]["target"] = json!(id(3));
    let found = errors(&snap);
    assert!(
        found.contains(&(
            "invalid_placement".to_owned(),
            "/placement/0/target".to_owned()
        )),
        "{found:?}"
    );
    assert!(
        found.contains(&(
            "invalid_placement".to_owned(),
            "/placement/1/target".to_owned()
        )),
        "{found:?}"
    );
}

#[test]
fn duplicate_keys_are_rejected_at_any_depth_in_json() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        10,
        json!({"settings": {"dll_control": "audit"}}),
    );
    let text = snapshot(nodes, vec![], vec![]).to_string().replace(
        "\"dll_control\":\"audit\"",
        "\"script_control_by_kind\":{\"powershell\":\"enforce\",\"powershell\":\"off\"}",
    );
    assert!(text.contains("\"powershell\":\"off\""));
    let e = HierarchyDocument::from_json(&text).unwrap_err();
    assert!(e.contains("duplicate") || e.contains("repeated"), "{e}");
}

#[test]
fn a_library_rule_set_over_the_policy_limits_is_rejected_not_dropped() {
    // 2,001 regular expressions in one rule set library, spread over rules
    // of at most 25 values: over the per-policy cap.
    let rules: Vec<Value> = (0..81)
        .map(|i| {
            json!({
                "id": id(3000 + i),
                "name": format!("Regex {i}"),
                "object_types": ["executable"],
                "match": {"all": [
                    hash_crit('a'),
                    {"criterion": {"field": "path.file_name", "operator": "regex",
                        "values": (0..25).map(|j| format!("^t{i}x{j}\\.exe$")).collect::<Vec<_>>()}},
                ]},
                "action": {"type": "deny"},
            })
        })
        .collect();
    let mut lib = blocklist_library(1, true, json!("global"));
    lib["content"]["rule_set"]["rules"] = json!(rules);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"rule_sets": [{"id": id(100)}]}));
    let found = errors(&snapshot(nodes, vec![], vec![lib]));
    assert!(
        found.contains(&(
            "invalid_rule_set".to_owned(),
            "/libraries/0/content/rule_set".to_owned()
        )),
        "{found:?}"
    );
}

#[test]
fn a_disabled_rule_stays_disabled_whatever_suppressions_say() {
    let mut off = rule(70, "allow", 'b');
    off["enabled"] = json!(false);
    let s = set(60, "allowlist", false, vec![off]);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 10, json!({"suppress_inherited": [id(70)]}));
    set_node(&mut nodes, 20, json!({"assignments": assign(&[(51, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![s.clone()]),
            policy(51, "enforce", vec![s]),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(e.rule(rule_id(70)).unwrap().status, RuleStatus::Disabled);
    assert_eq!(decide(&e, 'b'), Outcome::Blocked);
}

#[test]
fn defaulted_collection_settings_report_their_empty_value() {
    let h = validated(&snapshot(base_nodes(), vec![], vec![]));
    let e = effective(&h, 20);
    assert_eq!(e.setting("override_durations").unwrap().value, json!([]));
    assert_eq!(
        e.setting("script_control_by_kind").unwrap().value,
        json!({})
    );
    assert_eq!(e.setting("advanced").unwrap().value, json!({}));
}

#[test]
fn mode_options_can_be_locked() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        2,
        json!({
            "assignments": assign(&[(50, 0)]),
            "locked_settings": ["mode_options.mode_disconnected", "mode_options.mode_by_type"],
        }),
    );
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![
            policy_with(
                50,
                "audit",
                vec![],
                json!({"mode_options": {
                    "mode_disconnected": "enforce",
                    "mode_by_type": {"script.powershell": "enforce"},
                }}),
            ),
            policy_with(
                51,
                "audit",
                vec![],
                json!({"mode_options": {
                    "mode_disconnected": "audit",
                    "mode_by_type": {"script.powershell": "monitor", "script.batch": "monitor"},
                }}),
            ),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    let o = &e.policy().unwrap().document().policy.mode_options;
    assert_eq!(o.mode_disconnected, Some(Mode::Enforce));
    assert_eq!(
        o.mode_by_type
            .get(&ObjectType::Script(crate::model::ScriptKind::Powershell)),
        Some(&Mode::Enforce)
    );
    assert_eq!(
        o.mode_by_type
            .get(&ObjectType::Script(crate::model::ScriptKind::Batch)),
        None,
        "a type the locking node did not set is locked at unset"
    );
    let p = e.setting("mode_options.mode_disconnected").unwrap();
    assert_eq!(p.locked_at, Some(node_id(2)));
    assert_eq!(
        p.steps[1].outcome,
        StepOutcome::BlockedByLock {
            locked_at: node_id(2)
        }
    );
}

#[test]
fn a_long_parent_chain_validates_quickly() {
    // A chain of 20,000 groups: each walk to the root is memoised, so
    // validation is O(n log n) rather than quadratic. Group IDs fit the
    // 16-bit field of `id`.
    let mut nodes = base_nodes();
    for i in 0..20_000u32 {
        assert!(30_000 + i < 0x1_0000);
        let parent = if i == 0 { 10 } else { 30_000 + i - 1 };
        nodes.push(node(30_000 + i, "group", Some(parent), json!({})));
    }
    let start = std::time::Instant::now();
    let found = errors(&snapshot(nodes, vec![], vec![]));
    assert!(found.iter().any(|(c, _)| c == "group_too_deep"));
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn a_locked_mode_option_reports_its_lock_without_any_override() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        2,
        json!({
            "assignments": assign(&[(50, 0)]),
            "locked_settings": ["mode_options.mode_disconnected", "mode_options.disconnected_after_secs"],
        }),
    );
    let h = validated(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "audit",
            vec![],
            json!({"mode_options": {"mode_disconnected": "enforce"}}),
        )],
        vec![],
    ));
    let e = effective(&h, 10);
    let p = e.setting("mode_options.mode_disconnected").unwrap();
    assert_eq!(p.locked_at, Some(node_id(2)));
    assert_eq!(p.value, json!("enforce"));
    // Locked at unset: reported, with no value.
    let p = e.setting("mode_options.disconnected_after_secs").unwrap();
    assert_eq!(p.locked_at, Some(node_id(2)));
    assert_eq!(p.value, Value::Null);
}

#[test]
fn every_offer_below_a_lock_is_blocked() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        1,
        json!({
            "settings": {"poll_interval_secs": 600},
            "locked_settings": ["poll_interval_secs"],
        }),
    );
    set_node(
        &mut nodes,
        10,
        json!({
            "settings": {"poll_interval_secs": 300},
            "assignments": assign(&[(50, 0)]),
        }),
    );
    let h = validated(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "audit",
            vec![],
            json!({"settings": {"poll_interval_secs": 120}}),
        )],
        vec![],
    ));
    let p = effective(&h, 20)
        .setting("poll_interval_secs")
        .unwrap()
        .clone();
    let blocked = StepOutcome::BlockedByLock {
        locked_at: node_id(1),
    };
    assert_eq!(
        p.steps
            .iter()
            .map(|s| s.outcome.clone())
            .collect::<Vec<_>>(),
        [StepOutcome::Applied, blocked.clone(), blocked]
    );
}

#[test]
fn no_node_can_be_disabled() {
    for n in [1, 2, 10, 20] {
        let mut nodes = base_nodes();
        set_node(&mut nodes, 1, json!({"mode": "enforce", "lock_mode": true}));
        set_node(&mut nodes, n, json!({"mode": "disabled"}));
        let found = errors(&snapshot(nodes, vec![], vec![]));
        assert!(
            found
                .iter()
                .any(|(c, p)| c == "mode_not_allowed" && p.ends_with("/mode")),
            "{n}: {found:?}"
        );
    }
    // Nor a template or dynamic group, which could otherwise reset a floor.
    let mut nodes = base_nodes();
    nodes.push(node(
        30,
        "dynamic_group",
        Some(2),
        json!({"mode": "disabled", "lock_mode": true}),
    ));
    nodes.push(node(40, "template", Some(2), json!({"mode": "disabled"})));
    let found = errors(&snapshot(nodes, vec![], vec![]));
    assert!(
        found.contains(&("mode_not_allowed".to_owned(), "/nodes/6/mode".to_owned())),
        "{found:?}"
    );
    assert!(
        found.contains(&("mode_not_allowed".to_owned(), "/nodes/7/mode".to_owned())),
        "{found:?}"
    );
}

#[test]
fn a_flat_tenant_of_many_groups_validates_quickly() {
    // 20,000 groups directly below the tenant, with the global node last
    // in ID order: no lookup walks every node per group, and unconfigured
    // groups are not computed.
    let mut nodes = vec![
        node(
            0xfff0,
            "global",
            None,
            json!({"assignments": assign(&[(50, 0)])}),
        ),
        node(2, "tenant", Some(0xfff0), json!({})),
        node(3, "group", Some(2), json!({"builtin": "unassigned"})),
    ];
    for i in 0..20_000u32 {
        let extra = if i % 1000 == 0 {
            json!({"mode": "enforce"})
        } else {
            json!({})
        };
        nodes.push(node(10 + i, "group", Some(2), extra));
    }
    let snap = snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "blocklist", true, vec![rule(70, "deny", 'a')])],
        )],
        vec![],
    );
    let start = std::time::Instant::now();
    let h = validated(&snap);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(decide(&effective(&h, 12_000), 'a'), Outcome::Blocked);
}

#[test]
fn snapshots_read_from_yaml() {
    let yaml = "schema_version: 1.0.0\nrevision: 1\nnodes:\n  - {id: 01936b2e-0001-7b3d-9f21-0a1b2c3d4e5f, name: Global, kind: global}\n";
    let doc = HierarchyDocument::from_yaml(yaml).unwrap();
    assert_eq!(doc.nodes.len(), 1);
    assert!(HierarchyDocument::from_yaml("revision: 1\nrevision: 2\n").is_err());
}

// --- Properties ----------------------------------------------------------

/// A random snapshot: a tree of groups below the standard tenant, random
/// policies and suppressions, and a device in a random group.
#[derive(Clone, Debug)]
struct Random {
    parents: Vec<usize>,
    /// `(group, policy kind, mode)` per assignment.
    assignments: Vec<(usize, u8, u8)>,
    modes: Vec<Option<u8>>,
    locks: Vec<bool>,
    suppress: Vec<(usize, u8)>,
    device_group: usize,
    seed: u64,
}

const MODES: [&str; 4] = ["monitor", "audit", "learning", "enforce"];

fn random() -> impl Strategy<Value = Random> {
    (1usize..7).prop_flat_map(|groups| {
        (
            proptest::collection::vec(any::<prop::sample::Index>(), groups),
            proptest::collection::vec((0..groups, 0u8..4, 0u8..4), 1..10),
            proptest::collection::vec(proptest::option::of(0u8..4), groups),
            proptest::collection::vec(any::<bool>(), groups),
            proptest::collection::vec((0..groups, 0u8..4), 1..8),
            0..groups,
            any::<u64>(),
        )
            .prop_map(
                move |(p, assignments, modes, locks, suppress, device_group, seed)| Random {
                    // Group i's parent is the tenant or an earlier group.
                    parents: p
                        .iter()
                        .enumerate()
                        .map(|(i, ix)| ix.index(i + 1))
                        .collect(),
                    assignments,
                    modes,
                    locks,
                    suppress,
                    device_group,
                    seed,
                },
            )
    })
}

/// Policy kinds: 0 a mandatory blocklist denying `a`, 1 an ordinary
/// blocklist denying `b`, 2 an allowlist allowing `a`, `b` and `c`, 3 a
/// blocklist that opts into suppression, denying `c`.
fn policy_of(kind: u8, n: u32, mode: u8) -> Value {
    let m = MODES[usize::from(mode)];
    match kind {
        0 => policy(
            n,
            m,
            vec![set(1000, "blocklist", true, vec![rule(2000, "deny", 'a')])],
        ),
        1 => policy(
            n,
            m,
            vec![set(1001, "blocklist", false, vec![rule(2001, "deny", 'b')])],
        ),
        2 => policy(
            n,
            m,
            vec![set(
                1002,
                "allowlist",
                false,
                vec![
                    rule(2002, "allow", 'a'),
                    rule(2003, "allow", 'b'),
                    rule(2004, "allow", 'c'),
                ],
            )],
        ),
        _ => {
            let mut s = set(1003, "blocklist", false, vec![rule(2005, "deny", 'c')]);
            s["allow_child_suppress"] = json!(true);
            policy(n, m, vec![s])
        }
    }
}

const SUPPRESSIBLE: [u32; 4] = [2000, 2001, 2002, 2005];

fn build(r: &Random, shuffle: bool) -> Value {
    let mut nodes = vec![
        node(1, "global", None, json!({})),
        node(2, "tenant", Some(1), json!({})),
        node(3, "group", Some(2), json!({"builtin": "unassigned"})),
    ];
    let group = |i: usize| 10 + u32::try_from(i).unwrap();
    let mut assignments: Vec<Vec<(u32, u32)>> = vec![Vec::new(); r.parents.len()];
    let mut policies = Vec::new();
    for (k, (g, kind, mode)) in r.assignments.iter().enumerate() {
        let n = 500 + u32::try_from(k).unwrap();
        assignments[*g].push((n, u32::try_from(k).unwrap()));
        policies.push(policy_of(*kind, n, *mode));
    }
    for (i, parent) in r.parents.iter().enumerate() {
        let parent = if *parent == 0 { 2 } else { group(parent - 1) };
        let mut extra = json!({"assignments": assign(&assignments[i])});
        if let Some(m) = r.modes[i] {
            extra["mode"] = json!(MODES[usize::from(m)]);
        }
        if r.locks[i] {
            extra["lock_mode"] = json!(true);
        }
        nodes.push(node(group(i), "group", Some(parent), extra));
    }
    nodes.push(node(9000, "device", Some(group(r.device_group)), json!({})));
    let mut snap = snapshot(nodes, policies, vec![]);
    if shuffle {
        let mut seed = r.seed;
        for key in ["nodes", "policies"] {
            let list = snap[key].as_array_mut().unwrap();
            for i in (1..list.len()).rev() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let j = usize::try_from((seed >> 33) % (i as u64 + 1)).unwrap();
                list.swap(i, j);
            }
        }
    }
    snap
}

/// Adds the suppressions that are allowed; the rest are kept to test that
/// they are rejected.
fn with_suppressions(mut snap: Value, r: &Random) -> Value {
    for (g, which) in &r.suppress {
        let target = json!(id(10 + u32::try_from(*g).unwrap()));
        for n in snap["nodes"].as_array_mut().unwrap() {
            if n["id"] == target {
                let list = n
                    .as_object_mut()
                    .unwrap()
                    .entry("suppress_inherited")
                    .or_insert(json!([]));
                let rid = json!(id(SUPPRESSIBLE[usize::from(*which)]));
                if !list.as_array().unwrap().contains(&rid) {
                    list.as_array_mut().unwrap().push(rid);
                }
            }
        }
    }
    snap
}

/// Drops every suppression the validator rejects as `suppress_unknown_rule`
/// until none is left, then every one it rejects as `suppress_not_allowed`.
/// Returns the snapshot and the `(code, rule ID)` of each suppression that
/// was refused although the rule is inherited.
fn prune(mut snap: Value) -> (Value, Vec<(String, String)>) {
    let mut refused = Vec::new();
    for _ in 0..64 {
        let Err(found) = HierarchyDocument::from_json(&snap.to_string())
            .unwrap()
            .validate()
        else {
            break;
        };
        let mut removed = false;
        for wanted in ["suppress_unknown_rule", "suppress_not_allowed"] {
            for e in &found {
                let code = e.code.to_string();
                if code != wanted {
                    continue;
                }
                let Some(at) = e.path.strip_prefix("/nodes/") else {
                    continue;
                };
                let parts: Vec<&str> = at.split('/').collect();
                let [n, "suppress_inherited", k] = parts.as_slice() else {
                    continue;
                };
                let (n, k): (usize, usize) = (n.parse().unwrap(), k.parse().unwrap());
                let list = snap["nodes"][n]["suppress_inherited"]
                    .as_array_mut()
                    .unwrap();
                if k < list.len() && !list[k].is_null() {
                    if wanted == "suppress_not_allowed" {
                        refused.push((code, list[k].as_str().unwrap().to_owned()));
                    }
                    list[k] = Value::Null;
                    removed = true;
                }
            }
            if removed {
                break;
            }
        }
        for n in snap["nodes"].as_array_mut().unwrap() {
            if let Some(list) = n
                .get_mut("suppress_inherited")
                .and_then(Value::as_array_mut)
            {
                list.retain(|v| !v.is_null());
            }
        }
        if !removed {
            break;
        }
    }
    (snap, refused)
}

/// The modes in force along the device's chain, and every floor.
fn floor_of(h: &ValidatedHierarchy) -> Option<Mode> {
    let e = h
        .effective_policy_as(node_id(9000), &Membership::default())
        .ok()?;
    e.mode()?.floor.map(|(m, _)| m)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The content hash does not depend on the order of nodes or policies.
    #[test]
    fn the_content_hash_is_independent_of_input_order(r in random()) {
        let a = HierarchyDocument::from_json(&build(&r, false).to_string()).unwrap().validate();
        let b = HierarchyDocument::from_json(&build(&r, true).to_string()).unwrap().validate();
        match (a, b) {
            (Ok(a), Ok(b)) => {
                let ea = a.effective_policy_as(node_id(9000), &Membership::default());
                let eb = b.effective_policy_as(node_id(9000), &Membership::default());
                match (ea, eb) {
                    (Ok(ea), Ok(eb)) => {
                        prop_assert_eq!(ea.content_hash(), eb.content_hash());
                        prop_assert_eq!(ea.canonical_json(), eb.canonical_json());
                    }
                    (Err(x), Err(y)) => prop_assert_eq!(x.len(), y.len()),
                    _ => prop_assert!(false, "one order failed and the other did not"),
                }
            }
            (Err(x), Err(y)) => prop_assert_eq!(x.len(), y.len()),
            _ => prop_assert!(false, "one order failed and the other did not"),
        }
    }

    /// No suppression can remove an inherited mandatory deny or a default
    /// blocklist rule. Suppressions of rules a group does not inherit are
    /// dropped first. Every remaining rejection is `suppress_not_allowed`
    /// on one of those two rules; once those are dropped too, the snapshot
    /// validates, every accepted suppression is of a suppressible rule, and
    /// an inherited mandatory deny still blocks.
    #[test]
    fn a_child_can_never_remove_an_inherited_mandatory_deny(r in random()) {
        let (snap, refused) = prune(with_suppressions(build(&r, false), &r));
        for (code, rule) in &refused {
            prop_assert_eq!(code.as_str(), "suppress_not_allowed");
            prop_assert!(
                *rule == id(2000) || *rule == id(2001),
                "only the mandatory deny and the default blocklist are refused, not {}",
                rule
            );
        }
        let h = HierarchyDocument::from_json(&snap.to_string()).unwrap().validate();
        prop_assert!(h.is_ok(), "{:#?}", h.as_ref().err());
        let h = h.unwrap();
        let e = h.effective_policy_as(node_id(9000), &Membership::default()).unwrap();
        for p in e.rules().values() {
            if let RuleStatus::Suppressed { .. } = p.status {
                prop_assert!(p.rule_id == rule_id(2002) || p.rule_id == rule_id(2005));
            }
        }
        if let Some(p) = e.rule(rule_id(2000)) {
            prop_assert_eq!(p.status, RuleStatus::Active);
            prop_assert_eq!(decide(&e, 'a'), Outcome::Blocked);
        }
        if let Some(p) = e.rule(rule_id(2001)) {
            let suppressed = matches!(p.status, RuleStatus::Suppressed { .. });
            prop_assert!(!suppressed);
        }
    }

    /// No layer below a lock lowers the mode: the effective mode, every
    /// type mode and every rule set override is at least the floor.
    #[test]
    fn a_child_can_never_lower_a_locked_mode(r in random()) {
        let Ok(h) = HierarchyDocument::from_json(&build(&r, false).to_string()).unwrap().validate() else {
            return Ok(());
        };
        let Some(floor) = floor_of(&h) else { return Ok(()) };
        let e = h.effective_policy_as(node_id(9000), &Membership::default()).unwrap();
        let doc = e.policy().unwrap().document();
        prop_assert!(strictness(doc.policy.mode) >= strictness(floor));
        for m in doc.policy.mode_options.mode_by_type.values() {
            prop_assert!(strictness(*m) >= strictness(floor));
        }
        for s in &doc.rule_sets {
            if let Some(m) = s.mode_override {
                prop_assert!(strictness(m) >= strictness(floor));
            }
        }
        // And the floor is the strictest mode in force at a locking node:
        // the lock at the device's nearest locking ancestor holds too.
        let mut chain = Vec::new();
        let mut at = Some(node_id(9000));
        while let Some(n) = at {
            chain.push(n);
            at = h.node(n).and_then(|x| x.parent);
        }
        for n in chain.iter().filter(|n| h.node(**n).is_some_and(|x| x.lock_mode)) {
            let above = h.effective_policy_as(*n, &Membership::default()).unwrap();
            let m = above.mode().unwrap().mode;
            prop_assert!(strictness(doc.policy.mode) >= strictness(m));
        }
    }

    /// The effective policy of the same inputs is the same every time.
    #[test]
    fn computing_twice_gives_the_same_policy(r in random()) {
        let Ok(h) = HierarchyDocument::from_json(&build(&r, false).to_string()).unwrap().validate() else {
            return Ok(());
        };
        let a = h.effective_policy_as(node_id(9000), &Membership::default()).unwrap();
        let b = h.effective_policy_as(node_id(9000), &Membership::default()).unwrap();
        prop_assert_eq!(a.content_hash(), b.content_hash());
        prop_assert_eq!(a.policy().unwrap().document(), b.policy().unwrap().document());
    }
}

#[test]
fn a_rule_set_id_maps_to_its_contributions() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    let set_id = RuleSetId(id(60).parse().unwrap());
    assert_eq!(e.rule_set(set_id).unwrap().len(), 1);
}

// --- Scopes (#38) ------------------------------------------------------------

#[test]
fn policy_and_assignment_scopes_move_onto_the_rule_sets() {
    let admins = json!({"principals": {"include": [{"well_known": "administrators"}]}});
    let console = json!({"sessions": {"types": ["console"]}});
    let mut nodes = base_nodes();
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(50, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
            json!({
                "scope": admins,
                "rule_set_scopes": [{"rule_set": id(60), "scopes": [console]}],
                "location_profiles": [{"name": "corporate", "all": [{"server_reachable": true}]}]
            }),
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    let p = &e.policy().unwrap().document().policy;
    assert!(p.scope.is_none());
    assert_eq!(p.rule_set_scopes.len(), 1);
    assert_eq!(p.rule_set_scopes[0].rule_set.0.to_string(), id(60));
    assert_eq!(p.rule_set_scopes[0].scopes.len(), 2);
    assert!(p.rule_set_scopes[0].scopes[0].principals.is_some());
    assert!(p.rule_set_scopes[0].scopes[1].sessions.is_some());
    assert_eq!(p.location_profiles.len(), 1);
}

#[test]
fn one_rule_set_with_two_scopes_is_a_conflicting_scope() {
    let shared = set(60, "allowlist", false, vec![rule(70, "allow", 'b')]);
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![
            policy_with(
                50,
                "enforce",
                vec![shared.clone()],
                json!({"scope": {"sessions": {"types": ["console"]}}}),
            ),
            policy(51, "enforce", vec![shared]),
        ],
        vec![],
    ));
    assert!(
        found.iter().any(|(c, _)| c == "conflicting_scope"),
        "{found:?}"
    );
}

#[test]
fn location_profiles_with_one_name_must_agree() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let profile = |reachable: bool| json!({"location_profiles": [{"name": "corporate", "all": [{"server_reachable": reachable}]}]});
    let found = errors(&snapshot(
        nodes,
        vec![
            policy_with(
                50,
                "enforce",
                vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
                profile(true),
            ),
            policy_with(
                51,
                "enforce",
                vec![set(61, "allowlist", false, vec![rule(71, "allow", 'c')])],
                profile(false),
            ),
        ],
        vec![],
    ));
    assert!(
        found
            .iter()
            .any(|(c, p)| c == "conflicting_scope" && p.contains("location_profiles")),
        "{found:?}"
    );
}

#[test]
fn scopes_resolve_library_sets_through_the_catalogue() {
    use crate::library::Visibility;
    use crate::scope::{CatalogueLibrary, ScopeLibrary, SetRef};
    let schedule =
        json!({"windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}]}).to_string();
    let lib = |n: u32, content: Value| json!({"id": id(n), "version": 1, "name": format!("Set {n}"), "realm": "global", "content": content});
    let h = validated(&snapshot(
        base_nodes(),
        vec![],
        vec![
            lib(
                100,
                json!({"kind": "principal_set", "principals": ["S-1-5-32-544"]}),
            ),
            lib(
                101,
                json!({"kind": "network_set", "entries": ["10.0.0.0/8", "corp.example.org"]}),
            ),
            lib(102, json!({"kind": "schedule_set", "entries": [schedule]})),
        ],
    ));
    let library = CatalogueLibrary {
        catalogue: &h.catalogue,
        from: Visibility::Global,
    };
    let r = |n: u32| SetRef {
        id: LibraryId(id(n).parse().unwrap()),
        pin: crate::library::Pin::Latest,
    };
    assert_eq!(
        library.principal_set(&r(100)),
        Some(vec!["S-1-5-32-544".to_owned()])
    );
    assert_eq!(library.network_set(&r(101)).map(|v| v.len()), Some(2));
    assert_eq!(
        library.schedule_set(&r(102)).map(|s| s.windows.len()),
        Some(1)
    );
    // The wrong kind, or a set that does not exist, is unresolved.
    assert_eq!(library.network_set(&r(100)), None);
    assert_eq!(library.principal_set(&r(103)), None);
}

#[test]
fn set_libraries_check_their_entries() {
    let lib = |content: Value| json!({"id": id(100), "version": 1, "name": "Set", "realm": "global", "content": content});
    for content in [
        json!({"kind": "network_set", "entries": ["10.0.0.1/8"]}),
        json!({"kind": "network_set", "entries": ["not a network"]}),
        json!({"kind": "schedule_set", "entries": ["{}x"]}),
        json!({"kind": "schedule_set", "entries": [json!({"windows": [{"days": [], "start": "09:00", "end": "17:00"}]}).to_string()]}),
        json!({"kind": "schedule_set", "entries": [json!({"on_window_close": "warn"}).to_string()]}),
        json!({"kind": "schedule_set", "entries": ["{}", "{}"]}),
    ] {
        let found = errors(&snapshot(base_nodes(), vec![], vec![lib(content.clone())]));
        assert!(
            found.iter().any(|(c, _)| c == "invalid_entry"),
            "{content}: {found:?}"
        );
    }
}

/// A policy (50) whose allow (70) is scoped to principal set 100, at
/// `pin`, assigned at group 11.
fn scoped_by_set(pin: Value) -> (Vec<Value>, Value) {
    let scoped = {
        let mut r = rule(70, "allow", 'b');
        r["scope"] =
            json!({"principals": {"include": [{"principal_set": {"id": id(100), "pin": pin}}]}});
        r
    };
    let mut nodes = base_nodes();
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(50, 0)])}));
    (
        nodes,
        policy(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![scoped])],
        ),
    )
}

fn principal_set_library(version: u32, sid: &str) -> Value {
    json!({"id": id(100), "version": version, "name": "Admins", "realm": "global",
           "content": {"kind": "principal_set", "principals": [sid]}})
}

#[test]
fn scope_sets_must_exist_and_be_the_right_kind() {
    let (nodes, p) = scoped_by_set(json!("latest"));
    let found = errors(&snapshot(nodes.clone(), vec![p.clone()], vec![]));
    assert!(
        found.iter().any(|(c, path)| c == "unknown_library"
            && path.ends_with("/scope/principals/include/0/principal_set")),
        "{found:?}"
    );
    let wrong = json!({"id": id(100), "version": 1, "name": "Nets", "realm": "global",
                       "content": {"kind": "network_set", "entries": ["10.0.0.0/8"]}});
    let found = errors(&snapshot(nodes, vec![p], vec![wrong]));
    assert!(
        found.iter().any(|(c, _)| c == "ref_kind_not_allowed"),
        "{found:?}"
    );
}

#[test]
fn scope_sets_are_pinned_counted_and_in_use() {
    let (nodes, p) = scoped_by_set(json!("latest"));
    let h = validated(&snapshot(
        nodes.clone(),
        vec![p.clone()],
        vec![principal_set_library(1, "S-1-5-32-544")],
    ));
    let e = effective(&h, 20);
    // Pinned to the version used, and listed with it.
    let doc = e.policy().unwrap().document();
    let r = &doc.rule_sets[0].rules[0];
    let scope = serde_json::to_value(r.scope.as_ref().unwrap()).unwrap();
    assert_eq!(
        scope["principals"]["include"][0]["principal_set"]["pin"],
        json!(1)
    );
    assert!(
        e.libraries()
            .contains(&(LibraryId(id(100).parse().unwrap()), 1))
    );
    // A new version changes the content hash.
    let h2 = validated(&snapshot(
        nodes,
        vec![p],
        vec![
            principal_set_library(1, "S-1-5-32-544"),
            principal_set_library(2, "S-1-5-32-545"),
        ],
    ));
    assert_ne!(effective(&h2, 20).content_hash(), e.content_hash());
    // And the set cannot be deleted while the policy uses it.
    let err = h
        .check_delete(LibraryId(id(100).parse().unwrap()))
        .unwrap_err();
    assert_eq!(err.code.as_str(), "in_use");
}

#[test]
fn two_pins_of_one_scope_set_conflict() {
    let shared = |n: u32, rid: u32, pin: u32| {
        let mut r = rule(rid, "allow", 'b');
        r["scope"] =
            json!({"principals": {"include": [{"principal_set": {"id": id(100), "pin": pin}}]}});
        set(n, "allowlist", false, vec![r])
    };
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(51, 0)])}));
    let found = errors(&snapshot(
        nodes,
        vec![
            policy(50, "enforce", vec![shared(60, 70, 1)]),
            policy(51, "enforce", vec![shared(61, 71, 2)]),
        ],
        vec![
            principal_set_library(1, "S-1-5-32-544"),
            principal_set_library(2, "S-1-5-32-545"),
        ],
    ));
    assert!(
        found.iter().any(|(c, _)| c == "library_version_conflict"),
        "{found:?}"
    );
}

#[test]
fn an_effective_assignment_holds_the_policy_scope_too() {
    let console = json!({"sessions": {"types": ["console"]}});
    let scopes: Vec<Value> = (0..8).map(|_| console.clone()).collect();
    let mut nodes = base_nodes();
    set_node(&mut nodes, 11, json!({"assignments": assign(&[(50, 0)])}));
    let h = validated(&snapshot(
        nodes,
        vec![policy_with(
            50,
            "enforce",
            vec![set(60, "allowlist", false, vec![rule(70, "allow", 'b')])],
            json!({"scope": console, "rule_set_scopes": [{"rule_set": id(60), "scopes": scopes}]}),
        )],
        vec![],
    ));
    let e = effective(&h, 20);
    assert_eq!(
        e.policy().unwrap().document().policy.rule_set_scopes[0]
            .scopes
            .len(),
        9
    );
}

#[test]
fn the_effective_unknown_policy_is_the_strictest_of_the_layers() {
    let mut nodes = base_nodes();
    set_node(&mut nodes, 1, json!({"assignments": assign(&[(50, 0)])}));
    set_node(&mut nodes, 20, json!({"assignments": assign(&[(52, 0)])}));
    // The global policy blocks unknown objects in temporary folders and
    // detects elsewhere; the device's policy tries to allow them in
    // temporary folders and to detect drivers.
    let h = validated(&snapshot(
        nodes,
        vec![
            policy_with(
                50,
                "enforce",
                vec![],
                json!({"unknown": {"default": "detect", "by_location": {"temp": "block"}}}),
            ),
            policy_with(
                52,
                "enforce",
                vec![],
                json!({"unknown": {"default": "detect", "by_location": {"temp": "allow", "network": "block"}}}),
            ),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    let u = &e.policy().unwrap().document().policy.unknown;
    assert_eq!(u.default, crate::model::Level::Detect);
    assert_eq!(
        u.by_location.get(&crate::model::LocationClass::Temp),
        Some(&crate::model::Level::Block)
    );
    assert_eq!(
        u.by_location.get(&crate::model::LocationClass::Network),
        Some(&crate::model::Level::Block)
    );
    // A node with no policy gets the default, which blocks.
    let none = validated(&snapshot(base_nodes(), vec![], vec![]));
    assert!(
        effective(&none, 20)
            .policy()
            .unwrap()
            .document()
            .policy
            .unknown
            .is_default()
    );
}

#[test]
fn within_a_layer_the_lowest_slot_gives_what_cannot_be_compared() {
    let mut nodes = base_nodes();
    set_node(
        &mut nodes,
        20,
        json!({"assignments": assign(&[(50, 0), (51, 1)])}),
    );
    let profile = |n: u32| json!({"default": "detect", "restrict_profile": id(n)});
    let h = validated(&snapshot(
        nodes,
        vec![
            policy_with(50, "enforce", vec![], json!({"unknown": profile(80)})),
            policy_with(51, "enforce", vec![], json!({"unknown": profile(81)})),
        ],
        vec![],
    ));
    let e = effective(&h, 20);
    let u = &e.policy().unwrap().document().policy.unknown;
    assert_eq!(u.restrict_profile.unwrap().to_string(), id(80));
}
