//! Tests of the decision trace, explain and simulation (#41).
//!
//! The JSON shape of traces and the explain output are snapshot-tested in
//! `tests/snapshots/trace/`, one case per kind of decision. Regenerate
//! after a deliberate change with:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-policy trace::
//! ```

use std::path::PathBuf;

use palisade_core::path::VolumeMap;
use proptest::prelude::*;

use super::simulate::{
    Candidate, ChangeSet, FactsSnapshot, SimOutcome, Simulator, SnapshotFacts, SnapshotPath,
    SnapshotSigner, SnapshotSignerStatus, SnapshotState, read_snapshots,
};
use super::*;
use crate::context::EvaluationContext;
use crate::decision::Outcome;
use crate::decision::ReasonCode;
use crate::facts::{
    ObjectFacts, PathFact, PathVariables, SignatureSource, SignerFact, SignerStatus,
};
use crate::mode::{Connectivity, SessionKind};
use crate::model::PolicyDocument;

const TRACE: TraceId = TraceId([0x41; 16]);
const POLICY: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f";

fn sha(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn rule_id(n: u32) -> String {
    format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61")
}

fn set_id(n: u32) -> String {
    format!("01936b2e-8c4a-7b3d-9f21-0a1b2c3d{n:04x}")
}

fn crit(field: &str, operator: &str, values: &[&str]) -> serde_json::Value {
    serde_json::json!({"criterion": {"field": field, "operator": operator, "values": values}})
}

fn rule(
    n: u32,
    name: &str,
    tree: serde_json::Value,
    action: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "id": rule_id(n),
        "display_id": format!("R-{:06}", n),
        "name": name,
        "object_types": ["executable"],
        "match": tree,
        "action": action,
    })
}

fn with(mut v: serde_json::Value, k: &str, x: serde_json::Value) -> serde_json::Value {
    v.as_object_mut().unwrap().insert(k.to_owned(), x);
    v
}

/// `(number, kind, mandatory, rules)`.
type Set = (u32, &'static str, bool, Vec<serde_json::Value>);

fn policy_doc(mode: &str, sets: Vec<Set>) -> PolicyDocument {
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": POLICY,
            "name": "Trace",
            "revision": 7,
            "mode": mode,
            "rule_sets": sets.iter().map(|s| set_id(s.0)).collect::<Vec<_>>(),
        },
        "rule_sets": sets.iter().map(|(n, kind, mandatory, rules)| serde_json::json!({
            "id": set_id(*n),
            "name": format!("Set {n}"),
            "kind": kind,
            "mandatory": mandatory,
            "rules": rules,
        })).collect::<Vec<_>>(),
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn validated(doc: PolicyDocument) -> ValidatedPolicy {
    doc.validate().unwrap_or_else(|e| panic!("{e:#?}"))
}

const IT_ADMINS: &str = "S-1-5-21-1000-2000-3000-1100";

/// The fixture policy:
///
/// - R-000001 allows publisher `Example Ltd` with product `Example Tools`.
/// - R-000002 allows hash `c…` (a near miss on nothing: its anchor never
///   matches).
/// - R-000003 allows `Example Ltd` from `C:\Tools` (a path rule).
/// - R-000004 blocks script hosts for users not in IT-Admins (deny on
///   file name `script.exe`, `not member_of`).
/// - R-000005 is a disabled allow for hash `a…`.
/// - R-000006 audits everything signed by `Example Ltd`.
/// - R-000010, mandatory, blocks hash `d…`.
fn fixture() -> ValidatedPolicy {
    validated(policy_doc(
        "enforce",
        vec![
            (
                1,
                "mixed",
                false,
                vec![
                    rule(
                        1,
                        "Example signed tools",
                        serde_json::json!({"all": [
                            crit("signer.publisher", "equals", &["Example Ltd"]),
                            crit("meta.product_name", "equals", &["Example Tools"]),
                        ]}),
                        serde_json::json!({"type": "allow"}),
                    ),
                    rule(
                        2,
                        "Pinned build",
                        crit("hash.sha256", "equals", &[&sha('c')]),
                        serde_json::json!({"type": "allow"}),
                    ),
                    rule(
                        3,
                        "Tools folder",
                        serde_json::json!({"all": [
                            crit("signer.publisher", "equals", &["Example Ltd"]),
                            crit("path.directory", "starts_with", &["C:\\Tools"]),
                        ]}),
                        serde_json::json!({"type": "allow"}),
                    ),
                    rule(
                        4,
                        "Block script hosts for standard users",
                        serde_json::json!({"all": [
                            crit("path.file_name", "equals", &["script.exe"]),
                            {"not": crit("user.groups", "member_of", &[IT_ADMINS])},
                        ]}),
                        serde_json::json!({"type": "deny"}),
                    ),
                    with(
                        rule(
                            5,
                            "Retired allow",
                            crit("hash.sha256", "equals", &[&sha('a')]),
                            serde_json::json!({"type": "allow"}),
                        ),
                        "enabled",
                        false.into(),
                    ),
                    rule(
                        6,
                        "Watch Example",
                        crit("signer.publisher", "equals", &["Example Ltd"]),
                        serde_json::json!({"type": "audit"}),
                    ),
                ],
            ),
            (
                2,
                "blocklist",
                true,
                vec![rule(
                    10,
                    "Known bad",
                    crit("hash.sha256", "equals", &[&sha('d')]),
                    serde_json::json!({"type": "deny"}),
                )],
            ),
        ],
    ))
}

struct Obj {
    facts: ObjectFacts,
    context: EvaluationContext,
}

fn signer(publisher: &str, status: SignerStatus) -> SignerFact {
    SignerFact {
        status,
        source: SignatureSource::Embedded,
        publisher: Some(publisher.to_owned()),
        issuer: None,
        leaf_thumbprint_sha256: None,
        details: Default::default(),
    }
}

fn object(hash: char, publisher: &str, product: &str, path: &str, writable: Option<bool>) -> Obj {
    let mut p = PathFact::new(path, &VolumeMap::new());
    p.user_writable = writable;
    Obj {
        facts: ObjectFacts::new()
            .with(Field::HashSha256, sha(hash))
            .with(Field::MetaProductName, product)
            .with(Field::MetaFileVersion, "2.1.0.7")
            .with_path(p)
            .with_signers(vec![signer(publisher, SignerStatus::Valid)]),
        context: EvaluationContext::default(),
    }
}

fn in_group(mut o: Obj, groups: &[&str]) -> Obj {
    o.context.user.groups = Some(groups.iter().map(|g| (*g).to_owned()).collect());
    o
}

fn trace_of(policy: &ValidatedPolicy, o: &Obj, state: &DeviceState, level: TraceLevel) -> Trace {
    trace_with(
        policy,
        o,
        state,
        &TraceOptions::at(level),
        &ObjectExtras::default(),
    )
}

fn trace_with(
    policy: &ValidatedPolicy,
    o: &Obj,
    state: &DeviceState,
    options: &TraceOptions,
    extras: &ObjectExtras,
) -> Trace {
    let vars = PathVariables::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &o.facts,
        variables: &vars,
        context: &o.context,
    };
    Tracer::new(policy)
        .unwrap()
        .trace(&subject, extras, state, TRACE, options)
}

fn enforce(policy: &ValidatedPolicy) -> DeviceState {
    DeviceState::of(&policy.document().policy)
}

fn snapshot(name: &str, value: &impl Serialize) {
    snapshot_text(&format!("{name}.json"), &{
        let mut t = serde_json::to_string_pretty(value).unwrap();
        t.push('\n');
        t
    });
}

fn snapshot_text(file: &str, text: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/trace")
        .join(file);
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
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

fn explained(name: &str, t: &Trace) {
    let doc = explain(t, Verbosity::Detailed);
    let c = Catalog::english();
    snapshot_text(&format!("{name}.txt"), &render_text(&doc, &c));
    snapshot_text(&format!("{name}.md"), &render_markdown(&doc, &c));
    snapshot_text(
        &format!("{name}.tray.txt"),
        &format!("{}\n", render_tray(&doc, &c)),
    );
}

// Snapshot cases: allow, deny, mandatory deny, unknown, scope-rejected
// (with the scope tests below), inactive, path-ACL-unsafe, override
// session.

#[test]
fn allow_is_explained() {
    let p = fixture();
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let d = t.decision.as_ref().unwrap();
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(
        t.decisive
            .as_ref()
            .unwrap()
            .rule
            .display_id
            .unwrap()
            .to_string(),
        "R-000001"
    );
    // R-000006 annotates; R-000003 is a near miss on the folder.
    assert!(t.matched.iter().any(|m| m.role == MatchRole::Annotation));
    let nm: Vec<_> = t.near_misses.iter().map(|n| n.name.as_str()).collect();
    assert!(nm.contains(&"Tools folder"), "{nm:?}");
    snapshot("allow", &t);
    explained("allow", &t);
}

#[test]
fn deny_names_the_rule_and_the_group_reason() {
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[],
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert_eq!(
        t.decision.as_ref().unwrap().reason_code(),
        ReasonCode::ExplicitDeny
    );
    let doc = explain(&t, Verbosity::Short);
    let tray = render_tray(&doc, &Catalog::english());
    assert_eq!(
        tray,
        format!(
            "Blocked by rule 'Block script hosts for standard users' (R-000004). This is because you are not in {IT_ADMINS}."
        )
    );
    // Standard records no near misses and no facts.
    assert!(t.near_misses.is_empty());
    assert!(t.facts_used.is_empty());
    snapshot("deny", &t);
    explained("deny", &t);
}

#[test]
fn an_admin_is_not_blocked_by_the_script_host_rule() {
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[IT_ADMINS],
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    // The implicit deny decides; R-000004 is a near miss whose failing
    // criterion is the group test under `not`.
    assert!(t.decisive.is_none());
    let n = t
        .near_misses
        .iter()
        .find(|n| n.name.starts_with("Block"))
        .unwrap();
    assert_eq!(n.failing.len(), 1);
    assert_eq!(n.failing[0].field, Field::UserGroups);
    assert!(n.failing[0].under_not);
    assert_eq!(n.failing[0].needed, TriState::NoMatch);
    assert_eq!(n.failing[0].result, TriState::Match);
}

#[test]
fn mandatory_deny_is_explained() {
    let p = fixture();
    let o = object(
        'd',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert_eq!(
        t.decision.as_ref().unwrap().reason_code(),
        ReasonCode::MandatoryDeny
    );
    let s = t
        .stages
        .iter()
        .find(|s| s.name == StageName::MandatoryDeny)
        .unwrap();
    assert_eq!(s.outcome, StageOutcome::Decided);
    assert!(
        t.stages
            .iter()
            .filter(|s| s.name != StageName::MandatoryDeny)
            .all(|s| s.outcome == StageOutcome::Skipped)
    );
    let draft = t.allow_suggestion.as_ref().unwrap();
    assert_eq!(draft.caveats, vec!["mandatory_deny_matched"]);
    snapshot("mandatory", &t);
    explained("mandatory", &t);
}

#[test]
fn a_safety_critical_unknown_fails_closed_in_the_trace_as_in_the_evaluator() {
    let version = with(
        crit("meta.file_version", "version_lt", &["3.2"]),
        "criterion",
        serde_json::json!({
            "field": "meta.file_version",
            "operator": "version_lt",
            "values": ["3.2"],
            "safety_critical": true,
        }),
    );
    let p = validated(policy_doc(
        "enforce",
        vec![(
            10,
            "blocklist",
            true,
            vec![rule(
                10,
                "Vulnerable versions",
                serde_json::json!({"all": [
                    crit("signer.publisher", "equals", &["Example Ltd"]),
                    version,
                ]}),
                serde_json::json!({"type": "deny"}),
            )],
        )],
    ));
    let mut o = object(
        'b',
        "Example Ltd",
        "Example Driver",
        "C:\\Drivers\\x.sys",
        Some(false),
    );
    // The version resource was not read.
    o.facts = ObjectFacts::new()
        .with(Field::HashSha256, sha('b'))
        .with_signers(vec![signer("Example Ltd", SignerStatus::Valid)]);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert_eq!(
        t.decision.as_ref().unwrap().reason_code(),
        ReasonCode::MandatoryDeny
    );
    let decisive = t.decisive.as_ref().unwrap();
    let leaf = decisive
        .criteria
        .iter()
        .find(|c| c.field == Field::MetaFileVersion)
        .unwrap();
    assert_eq!(leaf.raw_result, TriState::Unknown);
    assert_eq!(leaf.result, TriState::Match);
    assert!(t.matched.iter().any(|m| m.rule == decisive.rule));
}

#[test]
fn near_misses_name_the_failing_leaf_with_observed_and_expected() {
    let p = fixture();
    // Publisher off by one word: R-000001 and R-000003 both miss on it.
    let o = object(
        'b',
        "Example Pty Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert!(t.decisive.is_none());
    let r1 = t
        .near_misses
        .iter()
        .find(|n| n.name == "Example signed tools")
        .unwrap();
    assert_eq!(r1.matched_criteria, 1);
    assert_eq!(r1.total_criteria, 2);
    assert_eq!(r1.failing.len(), 1);
    let f = &r1.failing[0];
    assert_eq!(f.pointer, "/match/all/0/criterion");
    assert_eq!(f.field, Field::SignerPublisher);
    assert_eq!(f.expected, vec!["Example Ltd"]);
    assert_eq!(f.observed.as_ref().unwrap().values, vec!["Example Pty Ltd"]);
    // R-000003 fails on both criteria, but its anchor (the path) matched.
    let r3 = t.near_misses.iter().find(|n| n.name == "Tools folder");
    assert!(
        r3.is_none(),
        "path C:\\Apps does not match C:\\Tools, and the publisher failed: no anchor"
    );
    let why = explain(&t, Verbosity::Normal);
    let text = Catalog::english().format(&why.why_not[0]);
    assert_eq!(
        text,
        "Rule 'Example signed tools' (R-000001) would allow this file, but the signer.publisher on this file is `Example Pty Ltd` (expected equals `Example Ltd`)."
    );
    snapshot("near-miss", &t);
    explained("near-miss", &t);
}

#[test]
fn near_misses_are_ranked_and_capped() {
    // Twelve allows on the same hash, each with i extra failing criteria.
    let rules: Vec<serde_json::Value> = (1..=12)
        .map(|i| {
            let mut all = vec![crit("hash.sha256", "equals", &[&sha('a')])];
            for j in 0..i {
                all.push(crit("meta.product_name", "equals", &[&format!("P{j}")]));
            }
            rule(
                i,
                &format!("R{i}"),
                serde_json::json!({"all": all}),
                serde_json::json!({"type": "allow"}),
            )
        })
        .collect();
    let p = validated(policy_doc("enforce", vec![(1, "allowlist", false, rules)]));
    let o = object('a', "X", "Q", "C:\\a.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert_eq!(t.near_misses.len(), limits::MAX_NEAR_MISSES);
    assert_eq!(t.omitted.near_misses, 2);
    // All have one matched criterion; ties go to the lowest rule ID.
    let names: Vec<&str> = t.near_misses.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names[..3], ["R1", "R2", "R3"]);
    let r12 = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert_eq!(r12, t, "deterministic");
    // The failing list is capped too.
    assert!(
        t.near_misses
            .iter()
            .all(|n| n.failing.len() <= limits::MAX_FAILING)
    );
}

#[test]
fn unknown_facts_are_reported_with_their_effect() {
    let p = fixture();
    let mut o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Tools\\tool.exe",
        Some(false),
    );
    o.facts = ObjectFacts::new()
        .with(Field::HashSha256, sha('b'))
        // No volume kind either: it is one of the unknown facts reported.
        .with_path(
            PathFact::new("C:\\Tools\\script.exe", &VolumeMap::new()).with_user_writable(false),
        );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    // No signers: R-000001/3/6 are unknown, and no groups: R-000004 too.
    let fields: Vec<Field> = t.unknown_facts.iter().map(|u| u.field).collect();
    assert!(fields.contains(&Field::SignerPublisher), "{fields:?}");
    assert!(fields.contains(&Field::UserGroups), "{fields:?}");
    let s = t
        .unknown_facts
        .iter()
        .find(|u| u.field == Field::SignerPublisher)
        .unwrap();
    assert!(s.effects.contains(&UnknownEffect::AllowNotApplied));
    assert!(s.notes.contains(&"fact_missing"));
    let g = t
        .unknown_facts
        .iter()
        .find(|u| u.field == Field::UserGroups)
        .unwrap();
    assert_eq!(g.effects, vec![UnknownEffect::DenyNotApplied]);
    snapshot("unknown", &t);
    explained("unknown", &t);
}

#[test]
fn inactive_rules_that_would_match_are_listed() {
    let p = fixture();
    let o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert_eq!(t.inactive_matches.len(), 1);
    assert_eq!(t.inactive_matches[0].name, "Retired allow");
    assert_eq!(t.inactive_matches[0].reason, InactiveReason::Disabled);
    // No rule in the fixture has a scope (#38).
    assert!(t.scope_rejections.is_empty());
    snapshot("inactive", &t);
    explained("inactive", &t);
}

#[test]
fn a_user_writable_path_warns_and_is_why_not() {
    let p = fixture();
    let o = object(
        'b',
        "Example Ltd",
        "Other",
        "C:\\Tools\\tool.exe",
        Some(true),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert!(t.decisive.is_none());
    let w = t
        .warnings
        .iter()
        .find(|w| w.code == WarningCode::PathAclUnsafe)
        .unwrap();
    assert_eq!(w.rules[0].display_id.unwrap().to_string(), "R-000003");
    let doc = explain(&t, Verbosity::Normal);
    let lines: Vec<String> = doc
        .why_not
        .iter()
        .map(|m| Catalog::english().format(m))
        .collect();
    assert!(
        lines.iter().any(|l| l == "Rule 'Tools folder' (R-000003) would allow this file, but the path may be user-writable or is not on a fixed local disk."),
        "{lines:?}"
    );
    snapshot("path-acl-unsafe", &t);
    explained("path-acl-unsafe", &t);
}

#[test]
fn an_override_session_is_traced_with_its_mode_steps() {
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[],
    );
    let state = DeviceState {
        session: Some(SessionKind::Audit),
        ..enforce(&p)
    };
    let t = trace_of(&p, &o, &state, TraceLevel::Standard);
    let d = t.decision.as_ref().unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedOverride);
    assert_eq!(t.effective_mode, Mode::Audit);
    let kinds: Vec<ModeStepKind> = t.mode_resolution.iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        [
            ModeStepKind::DeviceMode,
            ModeStepKind::Session,
            ModeStepKind::Effective,
            ModeStepKind::Applied
        ]
    );
    let session = t
        .stages
        .iter()
        .find(|s| s.name == StageName::SessionOverride)
        .unwrap();
    assert_eq!(session.outcome, StageOutcome::Passed);
    snapshot("override-session", &t);
    explained("override-session", &t);
}

#[test]
fn audit_mode_would_block_is_traced() {
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    let p = validated(doc);
    let o = object('b', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let d = t.decision.as_ref().unwrap();
    assert_eq!(d.outcome(), Outcome::AllowedAudit);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
    assert!(t.allow_suggestion.is_some(), "a would-block gets a draft");
    snapshot("would-block", &t);
    explained("would-block", &t);
}

#[test]
fn a_disabled_device_has_no_decision() {
    let p = fixture();
    let o = object('d', "X", "Y", "C:\\a.exe", Some(false));
    let state = DeviceState {
        mode: Mode::Disabled,
        ..enforce(&p)
    };
    let t = trace_of(&p, &o, &state, TraceLevel::Full);
    assert!(t.decision.is_none());
    assert_eq!(t.effective_mode, Mode::Disabled);
    assert!(t.matched.is_empty() && t.near_misses.is_empty() && t.unknown_facts.is_empty());
    assert_eq!(
        t.mode_resolution.last().unwrap().kind,
        ModeStepKind::Effective
    );
    assert!(t.stages.iter().all(|s| s.outcome == StageOutcome::Skipped));
    assert_eq!(
        render_tray(&explain(&t, Verbosity::Short), &Catalog::english()),
        "Protection is disabled on this device: nothing was decided."
    );
}

#[test]
fn minimal_is_the_decision_alone() {
    let p = fixture();
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Minimal);
    assert!(t.decisive.is_some());
    assert!(t.decisive.as_ref().unwrap().criteria.is_empty());
    assert!(t.matched.is_empty() && t.stages.is_empty() && t.mode_resolution.is_empty());
    snapshot("minimal", &t);
}

#[test]
fn level_policy_follows_the_issue_defaults() {
    let p = fixture();
    let allowed = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\a.exe",
        Some(false),
    );
    let blocked = object('d', "X", "Y", "C:\\a.exe", Some(false));
    let t1 = trace_of(&p, &allowed, &enforce(&p), TraceLevel::Minimal);
    let t2 = trace_of(&p, &blocked, &enforce(&p), TraceLevel::Minimal);
    let l = LevelPolicy::default();
    assert_eq!(l.level_for(t1.decision.as_ref(), 0), TraceLevel::Minimal);
    assert_eq!(l.level_for(t2.decision.as_ref(), 0), TraceLevel::Standard);
    assert_eq!(l.level_for(None, 0), TraceLevel::Minimal);
    let debug = LevelPolicy {
        debug_full: true,
        ..l
    };
    assert_eq!(debug.level_for(t1.decision.as_ref(), 0), TraceLevel::Full);
    let diag = l.with_diagnostic_session(100, DIAGNOSTIC_SESSION_SECS);
    assert_eq!(
        diag.level_for(t1.decision.as_ref(), 100 + 1799),
        TraceLevel::Full
    );
    assert_eq!(
        diag.level_for(t1.decision.as_ref(), 100 + 1800),
        TraceLevel::Minimal
    );
    // A would-block is standard too.
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    let audit = validated(doc);
    let t3 = trace_of(&audit, &blocked, &enforce(&audit), TraceLevel::Minimal);
    assert_eq!(
        t3.decision.as_ref().unwrap().outcome(),
        Outcome::Blocked,
        "mandatory deny"
    );
    let other = object('b', "X", "Y", "C:\\a.exe", Some(false));
    let t4 = trace_of(&audit, &other, &enforce(&audit), TraceLevel::Minimal);
    assert_eq!(
        t4.decision.as_ref().unwrap().outcome(),
        Outcome::AllowedAudit
    );
    assert_eq!(l.level_for(t4.decision.as_ref(), 0), TraceLevel::Standard);
}

#[test]
fn privacy_withholds_context_and_digests_with_a_key() {
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Users\\alice\\script.exe",
            Some(false),
        ),
        &["S-1-5-21-9"],
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let g = t
        .facts_used
        .iter()
        .find(|f| f.field == "user.groups")
        .unwrap();
    assert!(g.withheld && g.values.is_empty() && g.digests.is_empty());
    let mut options = TraceOptions::at(TraceLevel::Full);
    options.privacy.digest_key = Some([7; 32]);
    options.privacy.redactor = Redactor::new(&[r"\\Users\\[^\\]+"]).unwrap();
    let t = trace_with(&p, &o, &enforce(&p), &options, &ObjectExtras::default());
    let g = t
        .facts_used
        .iter()
        .find(|f| f.field == "user.groups")
        .unwrap();
    assert_eq!(g.digests.len(), 1);
    assert!(g.digests[0].starts_with("hmac-sha256:") && g.digests[0].len() == 12 + 64);
    let path = t
        .facts_used
        .iter()
        .find(|f| f.field == "path.file_name")
        .unwrap();
    assert_eq!(path.values, vec!["script.exe"]);
    let json = serde_json::to_string(&t).unwrap();
    assert!(!json.contains("alice"), "{json}");
    assert!(
        !json.contains("S-1-5-21-9\""),
        "the raw group never appears"
    );
    // The key never appears in a debug dump.
    let debug = format!("{:?}", options.privacy);
    assert!(
        debug.contains("[set]") && !debug.contains("7, 7"),
        "{debug}"
    );
    // The same value under the same key gives the same digest.
    let again = trace_with(&p, &o, &enforce(&p), &options, &ObjectExtras::default());
    assert_eq!(again, t);
}

#[test]
fn redaction_applies_to_every_written_value() {
    let r = Redactor::new(&["secret=[^ ]+", "token"]).unwrap();
    assert_eq!(
        r.redact("run --secret=abc --x token y"),
        "run --[redacted] --x [redacted] y"
    );
    assert_eq!(r.redact("SECRET=X"), "[redacted]");
    assert!(
        Redactor::new(&["(?<=a)b"]).is_err(),
        "look-around is rejected"
    );
    let many: Vec<String> = (0..=privacy::MAX_REDACTION_PATTERNS)
        .map(|i| format!("p{i}"))
        .collect();
    assert!(Redactor::new(&many).is_err());
}

#[test]
fn signature_relaxations_warn() {
    let p = fixture();
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let extras = ObjectExtras {
        signature_relaxations: vec![SignatureRelaxation {
            signature: 0,
            flag: RelaxationFlag::AllowUntrustedRoot,
            suppressed: palisade_core::VerificationError::UntrustedRoot,
        }],
    };
    let t = trace_with(
        &p,
        &o,
        &enforce(&p),
        &TraceOptions::at(TraceLevel::Standard),
        &extras,
    );
    let w = t
        .warnings
        .iter()
        .find(|w| w.code == WarningCode::SignatureRelaxed)
        .unwrap();
    assert_eq!(
        w.details,
        vec!["signature 0: allow_untrusted_root suppressed untrusted_root (7)"]
    );
    let names: Vec<String> = w
        .rules
        .iter()
        .map(|r| r.display_id.unwrap().to_string())
        .collect();
    assert_eq!(names, ["R-000001", "R-000006"]);
}

#[test]
fn stage_timing_uses_the_given_clock() {
    struct Tick(std::cell::Cell<u64>);
    impl NanoClock for Tick {
        fn now_ns(&self) -> u64 {
            let v = self.0.get();
            self.0.set(v + 10);
            v
        }
    }
    let p = fixture();
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let vars = PathVariables::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &o.facts,
        variables: &vars,
        context: &o.context,
    };
    let tracer = Tracer::new(&p).unwrap();
    let t = tracer.trace_timed(
        &subject,
        &ObjectExtras::default(),
        &enforce(&p),
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
        &Tick(std::cell::Cell::new(0)),
    );
    for s in &t.stages {
        match s.name {
            StageName::MandatoryDeny | StageName::Exclusion | StageName::Policy => {
                assert_eq!(s.duration_ns, Some(10));
            }
            _ => assert_eq!(s.duration_ns, None),
        }
    }
    let untimed = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert!(untimed.stages.iter().all(|s| s.duration_ns.is_none()));
}

#[test]
fn the_largest_trace_stays_within_its_byte_bound() {
    // Every list at its limit, every value at its longest.
    let long = "x".repeat(2040);
    let mut rules = Vec::new();
    for i in 1..=200u32 {
        let mut all = vec![crit("hash.sha256", "equals", &[&sha('a')])];
        for j in 0..20 {
            all.push(crit(
                "meta.product_name",
                "equals",
                &[&format!("{long}{i}-{j}"), &long, &long, &long, &long, &long],
            ));
        }
        rules.push(rule(
            i,
            &"n".repeat(128),
            serde_json::json!({"all": all}),
            serde_json::json!({"type": "allow"}),
        ));
        rules.push(rule(
            1000 + i,
            &"m".repeat(128),
            crit("hash.sha256", "equals", &[&sha('a')]),
            serde_json::json!({"type": "audit"}),
        ));
        rules.push(with(
            rule(
                2000 + i,
                "d",
                crit("hash.sha256", "equals", &[&sha('a')]),
                serde_json::json!({"type": "allow"}),
            ),
            "enabled",
            false.into(),
        ));
    }
    let p = validated(policy_doc("enforce", vec![(1, "mixed", false, rules)]));
    // The product never matches, so every allow is a near miss with 20
    // failing criteria.
    let mut o = object(
        'a',
        &long,
        &"y".repeat(2040),
        &format!("C:\\{}\\a.exe", "p".repeat(200)),
        Some(true),
    );
    o.facts.signers = Some(
        (0..20)
            .map(|_| signer(&long, SignerStatus::Revoked))
            .collect(),
    );
    let mut options = TraceOptions::at(TraceLevel::Full);
    options.bundle_hash = Some(long.clone());
    let t = trace_with(&p, &o, &enforce(&p), &options, &ObjectExtras::default());
    let bytes = serde_json::to_vec(&t).unwrap().len();
    assert!(bytes <= limits::MAX_TRACE_BYTES, "{bytes}");
    assert_eq!(t.matched.len(), limits::MAX_MATCHED);
    assert!(t.omitted.matched > 0);
    assert_eq!(t.near_misses.len(), limits::MAX_NEAR_MISSES);
    assert_eq!(t.inactive_matches.len(), limits::MAX_INACTIVE);
    let v = serde_json::to_value(&t).unwrap();
    let d = &v["decision"];
    assert_eq!(
        d["annotations"].as_array().unwrap().len(),
        limits::MAX_DECISION_LIST
    );
    assert_eq!(d["annotations_omitted"], 190);
    // The Rust decision is never cut.
    assert_eq!(t.decision.as_ref().unwrap().annotations().len(), 200);
}

/// Every message ID `explain.rs` can build has an English template. IDs
/// are the string literals of the form `word-word` in the source; the
/// summaries `summary-would-block` and `summary-override` pick a variant by
/// their `cause` argument.
#[test]
fn explain_messages_all_have_english_templates() {
    let ids: std::collections::BTreeSet<&str> = explain::ENGLISH.iter().map(|(k, _)| *k).collect();
    assert_eq!(ids.len(), explain::ENGLISH.len(), "duplicate IDs");
    let src = include_str!("explain.rs");
    let code = &src[..src.find("pub const ENGLISH").unwrap()];
    let prefixes = [
        "summary-",
        "reason-",
        "why-not-",
        "suggest-",
        "warning-",
        "unknown-",
        "heading-",
        "column-",
        "mode-step",
    ];
    let singles = [
        "mode",
        "stage",
        "overridden",
        "inactive",
        "scope-rejected",
        "scope-rejected-schedule",
        "inactive-not-yet",
        "inactive-expired",
        "tray-with-reason",
    ];
    let mut checked = 0;
    for literal in code.split('"').skip(1).step_by(2) {
        let is_id = !literal.contains(' ')
            && (prefixes.iter().any(|p| literal.starts_with(p)) || singles.contains(&literal));
        if !is_id {
            continue;
        }
        checked += 1;
        if let Some(base) = ["summary-would-block", "summary-override"]
            .iter()
            .find(|b| **b == literal)
        {
            for v in ["-rule", "-implicit"] {
                assert!(ids.contains(format!("{base}{v}").as_str()), "{base}{v}");
            }
            continue;
        }
        assert!(ids.contains(literal), "no English template for {literal}");
    }
    assert!(checked > 40, "{checked}");
    // And the snapshot explanations never render a bare ID.
    let p = fixture();
    let o = object(
        'b',
        "Example Pty Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let doc = explain(&t, Verbosity::Detailed);
    let c = Catalog::english();
    for m in std::iter::once(&doc.summary)
        .chain(&doc.paragraphs)
        .chain(&doc.why_not)
    {
        assert_ne!(c.format(m), m.id);
    }
}

#[test]
fn a_translation_overlays_english() {
    let c = Catalog::with_translation("# Test\nsummary-blocked = Bloqué par { $rule }.\n").unwrap();
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[],
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let doc = explain(&t, Verbosity::Short);
    assert_eq!(
        c.format(&doc.summary),
        "Bloqué par 'Block script hosts for standard users' (R-000004)."
    );
    // Untranslated messages fall back to English.
    assert!(
        c.format(doc.reason.as_ref().unwrap())
            .starts_with("you are not in")
    );
    assert!(Catalog::with_translation("nope = x").is_err());
    assert!(Catalog::with_translation("just text").is_err());
}

#[test]
fn markdown_escapes_policy_text() {
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "blocklist",
            false,
            vec![rule(
                1,
                "[click](https://evil.example) <b>*x*</b>",
                crit("hash.sha256", "equals", &[&sha('a')]),
                serde_json::json!({"type": "deny"}),
            )],
        )],
    ));
    let o = object('a', "X", "Y", "C:\\a.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let md = render_markdown(&explain(&t, Verbosity::Normal), &Catalog::english());
    assert!(!md.contains("[click](https"), "{md}");
    assert!(!md.contains("<b>"), "{md}");
    assert!(md.contains(r"\[click\]\(https://evil.example\)"), "{md}");
}

#[test]
fn the_draft_uses_the_strongest_identity() {
    let p = validated(policy_doc("enforce", vec![(1, "blocklist", false, vec![])]));
    let mut o = object(
        'a',
        "Example Ltd",
        "Example Tools",
        "C:\\a.exe",
        Some(false),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert_eq!(
        t.allow_suggestion.as_ref().unwrap().identity,
        DraftIdentity::Hash
    );
    o.facts = ObjectFacts::new()
        .with(Field::MetaProductName, "Example Tools")
        .with(Field::MetaFileVersion, "2.1 (beta)")
        .with_signers(vec![signer("Example Ltd", SignerStatus::Valid)]);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let d = t.allow_suggestion.unwrap();
    assert_eq!(d.identity, DraftIdentity::PublisherProductVersion);
    // The draft is a valid rule.
    let mut doc = p.into_document();
    doc.rule_sets[0].kind = crate::model::RuleSetKind::Mixed;
    let r: crate::model::Rule = serde_json::from_value(serde_json::json!({
        "id": rule_id(99),
        "name": "Draft",
        "object_types": d.object_types,
        "match": d.r#match,
        "action": {"type": "allow"},
    }))
    .unwrap();
    doc.rule_sets[0].rules.push(r);
    let p2 = validated(doc);
    let t2 = trace_of(&p2, &o, &enforce(&p2), TraceLevel::Minimal);
    assert_eq!(
        t2.decision.unwrap().outcome(),
        Outcome::Allowed,
        "the draft allows the object"
    );
    // An untrusted signer and a writable path give no draft.
    o.facts = ObjectFacts::new()
        .with_path(PathFact::new("C:\\a.exe", &VolumeMap::new()).with_user_writable(true))
        .with_signers(vec![signer("Example Ltd", SignerStatus::Revoked)]);
    let p3 = validated(policy_doc("enforce", vec![(1, "blocklist", false, vec![])]));
    assert!(
        trace_of(&p3, &o, &enforce(&p3), TraceLevel::Standard)
            .allow_suggestion
            .is_none()
    );
}

#[test]
fn mode_steps_cover_type_modes_rule_overrides_and_offline() {
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    doc.policy
        .mode_options
        .mode_by_type
        .insert(ObjectType::Executable, Mode::Monitor);
    doc.policy.mode_options.mode_disconnected = Some(Mode::Enforce);
    doc.rule_sets[0].rules[3].enforcement_override =
        crate::model::EnforcementOverride::NeverEnforce;
    let p = validated(doc);
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[],
    );
    // Offline, the type mode is raised to enforce. R-000004 never enforces,
    // so it is set aside, and the enforcing implicit deny blocks: the steps
    // are those of the implicit deny.
    let offline = DeviceState {
        connectivity: Connectivity::Disconnected,
        ..enforce(&p)
    };
    let t = trace_of(&p, &o, &offline, TraceLevel::Standard);
    let d = t.decision.as_ref().unwrap();
    assert_eq!(
        (d.outcome(), d.reason_code()),
        (Outcome::Blocked, ReasonCode::ImplicitDenyUnknown)
    );
    let steps: Vec<(ModeStepKind, Mode)> =
        t.mode_resolution.iter().map(|s| (s.kind, s.mode)).collect();
    assert_eq!(
        steps,
        [
            (ModeStepKind::DeviceMode, Mode::Audit),
            (ModeStepKind::Disconnected, Mode::Enforce),
            (ModeStepKind::ObjectType, Mode::Enforce),
            (ModeStepKind::Effective, Mode::Enforce),
            (ModeStepKind::Applied, Mode::Enforce),
        ]
    );
    let r4 = t
        .matched
        .iter()
        .find(|m| m.name.starts_with("Block"))
        .unwrap();
    assert_eq!(r4.role, MatchRole::Overridden);
    // Lockdown comes first and fixes the mode.
    let lockdown = DeviceState {
        lockdown: true,
        ..offline
    };
    let t = trace_of(&p, &o, &lockdown, TraceLevel::Standard);
    assert_eq!(t.mode_resolution[0].kind, ModeStepKind::Lockdown);
    // Connected, in audit with no type mode: `always_enforce` makes R-000004
    // enforce.
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    doc.rule_sets[0].rules[3].enforcement_override =
        crate::model::EnforcementOverride::AlwaysEnforce;
    let p = validated(doc);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let steps: Vec<(ModeStepKind, bool, Mode)> = t
        .mode_resolution
        .iter()
        .map(|s| (s.kind, s.applied, s.mode))
        .collect();
    assert_eq!(
        steps,
        [
            (ModeStepKind::DeviceMode, false, Mode::Audit),
            (ModeStepKind::RuleOverride, true, Mode::Enforce),
            (ModeStepKind::Effective, true, Mode::Enforce),
            (ModeStepKind::Applied, false, Mode::Enforce),
        ]
    );
}

// Property tests: the trace agrees with the evaluator.

fn any_state() -> impl Strategy<Value = DeviceState> {
    (
        proptest::sample::select(vec![
            Mode::Disabled,
            Mode::Monitor,
            Mode::Audit,
            Mode::Learning,
            Mode::Enforce,
        ]),
        any::<bool>(),
        proptest::sample::select(vec![
            None,
            Some(SessionKind::Audit),
            Some(SessionKind::FullBypass),
        ]),
        proptest::bool::weighted(0.2),
    )
        .prop_map(|(mode, offline, session, lockdown)| DeviceState {
            mode,
            connectivity: if offline {
                Connectivity::Disconnected
            } else {
                Connectivity::Connected
            },
            session,
            lockdown,
        })
}

fn any_facts() -> impl Strategy<Value = ObjectFacts> {
    (
        proptest::option::of(proptest::sample::select(vec!['a', 'b'])),
        proptest::option::of(proptest::sample::select(vec!["Example Ltd", "Other"])),
        proptest::option::of(any::<bool>()),
        proptest::option::of(proptest::sample::select(vec![
            "1.0",
            "2.5.1",
            "not a version",
        ])),
    )
        .prop_map(|(h, p, w, v)| {
            let mut f = ObjectFacts::new();
            if let Some(h) = h {
                f.set(Field::HashSha256, sha(h));
            }
            if let Some(v) = v {
                f.set(Field::MetaFileVersion, v);
            }
            if let Some(p) = p {
                f.signers = Some(vec![signer(p, SignerStatus::Valid)]);
            }
            let mut path = PathFact::new("C:\\Tools\\Sub\\tool.exe", &VolumeMap::new());
            path.user_writable = w;
            f.with_path(path)
        })
}

/// Replaces each generated rule's tree with one built from a few anchors
/// that the generated facts can match, under random `all`/`any`/`not`.
fn retree(doc: &mut PolicyDocument, picks: &[u8]) {
    let leaves = [
        crit("hash.sha256", "equals", &[&sha('a')]),
        crit("signer.publisher", "equals", &["Example Ltd"]),
        crit("path.directory", "starts_with", &["C:\\Tools"]),
        crit("meta.file_version", "version_ge", &["2.0"]),
    ];
    for (i, r) in doc
        .rule_sets
        .iter_mut()
        .flat_map(|s| s.rules.iter_mut())
        .enumerate()
    {
        let p = picks.get(i % picks.len().max(1)).copied().unwrap_or(0);
        let a = leaves[usize::from(p % 3)].clone();
        let b = leaves[usize::from((p / 3) % 4)].clone();
        let tree = match (p / 12) % 4 {
            0 => a,
            1 => serde_json::json!({"all": [a, b]}),
            2 => serde_json::json!({"any": [a, b]}),
            _ => serde_json::json!({"all": [a, {"not": b}]}),
        };
        r.match_ = serde_json::from_value(tree).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The trace embeds the evaluator's decision unchanged, lists exactly
    /// the rules the evaluator matched, agrees with the compiled tree on
    /// every rule's result, and its last mode step is the decision's mode.
    #[test]
    fn the_trace_agrees_with_the_evaluator(
        doc in crate::model::arbitrary::document(),
        picks in proptest::collection::vec(any::<u8>(), 1..16),
        facts in any_facts(),
        state in any_state(),
        t in proptest::sample::select(ObjectType::ALL.to_vec()),
        early in any::<bool>(),
        clock in proptest::option::of((-20i64..20, -20i64..20, any::<bool>())),
        windows in proptest::collection::vec(proptest::option::of((-10i64..10, 1i64..10, any::<bool>())), 1..6),
    ) {
        let mut doc = doc;
        retree(&mut doc, &picks);
        // Give rules activity windows (#40), judged at `clock` below: each
        // rule takes the next window, and `None` leaves it untimed.
        for (r, w) in doc
            .rule_sets
            .iter_mut()
            .flat_map(|s| s.rules.iter_mut())
            .zip(windows.iter().cycle())
        {
            // Windows of a few days around 2026-11-25, and a clock (now,
            // floor) a few days either side, so activity really varies.
            if let Some((start, len, open_start)) = w {
                let day = |d: i64| crate::model::Timestamp(1_795_564_800 + d * 86_400);
                r.activates_at = (!open_start).then_some(day(*start));
                r.expires_at = Some(day(start + len));
            }
        }
        let policy = doc.validate();
        prop_assume!(policy.is_ok());
        let policy = policy.unwrap();
        let vars = PathVariables::new();
        let mut ctx = EvaluationContext::new();
        // Early boot, so a driver decided at stage 6 follows
        // `driver_boot_policy` (#39).
        if early {
            ctx.device.boot_phase = Some(crate::context::BootPhase::Early);
        }
        let subject = Subject { object_type: t, facts: &facts, variables: &vars, context: &ctx };
        // Activity windows, judged at a random clock (or none) in both.
        let rule_clock = clock.map(|(now, floor, anchored)| crate::lifecycle::RuleClock {
            now: crate::model::Timestamp(1_795_564_800 + now * 86_400),
            floor: crate::model::Timestamp(1_795_564_800 + floor * 86_400),
            anchored,
        });
        let mut tracer = Tracer::new(&policy).unwrap();
        let mut evaluator = Evaluator::new(&policy).unwrap();
        if let Some(c) = rule_clock {
            tracer.set_clock(c);
            evaluator.set_clock(c);
        }
        let tr = tracer.trace(&subject, &ObjectExtras::default(), &state, TRACE, &TraceOptions::at(TraceLevel::Full));
        let direct = evaluator.evaluate_in(&subject, &state, TRACE);
        // Every inactive rule listed is one the evaluator left out.
        for i in &tr.inactive_matches {
            let r = policy.document().rule_sets.iter().flat_map(|s| &s.rules).find(|r| r.id == i.rule.rule_id).unwrap();
            prop_assert!(!evaluator.activity_of(r).is_active());
        }
        prop_assert_eq!(&tr.decision, &direct);
        let ids: Vec<RuleId> = tr.matched.iter().map(|m| m.rule.rule_id).collect();
        // A disabled device consults no rule, so nothing is listed.
        let mut expect = if direct.is_some() { tracer.evaluator().matching_ids(&subject) } else { Vec::new() };
        expect.sort();
        expect.truncate(limits::MAX_MATCHED);
        prop_assert_eq!(ids, expect);
        // Per-rule results agree with `CompiledMatch` on every rule.
        for r in &tracer.rules {
            let res = r.evaluate(&subject);
            if !res.type_applies { continue; }
            let compiled = crate::condition::CompiledMatch::compile(&r.rule.match_).unwrap();
            let ctx2 = crate::ops::EvalContext { action: r.action(), variables: &vars, context: &ctx };
            let un = match &r.rule.action {
                crate::model::Action::Deny(o) if o.on_unparseable == UnknownAs::Match => crate::condition::Unparseable::FavourMatch,
                _ => crate::condition::Unparseable::Unknown,
            };
            prop_assert_eq!(res.tree, compiled.eval_with(&facts, &ctx2, un).result);
            // A rule that did not match has a failing criterion; one that
            // matched has none.
            prop_assert_eq!(r.failing(&res).is_empty(), res.tree == Tri::Match);
        }
        if let Some(d) = &tr.decision {
            let last = tr.mode_resolution.iter().rev().nth(1).unwrap();
            prop_assert_eq!(last.kind, ModeStepKind::Effective);
            prop_assert_eq!(tr.mode_resolution.last().unwrap().mode, d.mode());
            // The step before `effective` reaches the same mode.
            let before = &tr.mode_resolution[tr.mode_resolution.len() - 3];
            prop_assert_eq!(before.mode, last.mode, "{:?}", tr.mode_resolution);
            // The effective step is the mode the decision was made in.
            prop_assert_eq!(last.mode, tr.effective_mode, "{:?}", tr.mode_resolution);
            // Exactly one stage decided, and it is the decider's.
            prop_assert_eq!(tr.stages.iter().filter(|s| s.outcome == StageOutcome::Decided).count(), 1);
        }
        prop_assert!(serde_json::to_vec(&tr).unwrap().len() <= limits::MAX_TRACE_BYTES);
    }

    /// The simulator decides exactly what the agent's evaluator decides
    /// (the differential test of #41), whatever the number of threads.
    #[test]
    fn the_simulator_reproduces_agent_decisions(
        doc in crate::model::arbitrary::document(),
        picks in proptest::collection::vec(any::<u8>(), 1..16),
        events in proptest::collection::vec((any_facts(), any_state(), proptest::sample::select(ObjectType::ALL.to_vec())), 1..24),
    ) {
        let mut doc = doc;
        retree(&mut doc, &picks);
        let policy = doc.validate();
        prop_assume!(policy.is_ok());
        let policy = policy.unwrap();
        let snaps: Vec<FactsSnapshot> = events.iter().enumerate().map(|(i, (f, s, t))| to_snapshot(i, f, s, *t)).collect();
        let evaluator = Evaluator::new(&policy).unwrap();
        let mut recorded = snaps.clone();
        for (snap, (f, s, t)) in recorded.iter_mut().zip(&events) {
            let vars = PathVariables::new();
            let ctx = EvaluationContext::new();
            let d = evaluator.evaluate_in(&Subject { object_type: *t, facts: f, variables: &vars, context: &ctx }, s, simulate::trace_id(&snap.event_id));
            snap.recorded = Some(simulate::RecordedDecision {
                outcome: SimOutcome::of(d.as_ref()),
                rule_id: d.as_ref().and_then(|d| d.matched_rule()).map(|r| r.rule_id),
            });
            let sim = Simulator::new(&policy).unwrap();
            let got = sim.decide_all(std::slice::from_ref(snap)).unwrap().remove(0);
            prop_assert_eq!(got, d);
        }
        let one = Simulator::new(&policy).unwrap().with_threads(1);
        let many = Simulator::new(&policy).unwrap().with_threads(4);
        prop_assert!(simulate::cross_check(&one, &recorded).unwrap().is_empty());
        prop_assert_eq!(one.run(&recorded, None).unwrap(), many.run(&recorded, None).unwrap());
    }
}

fn to_snapshot(i: usize, f: &ObjectFacts, s: &DeviceState, t: ObjectType) -> FactsSnapshot {
    FactsSnapshot {
        event_id: format!("e{i:04}"),
        device_id: Some(format!("d{}", i % 3)),
        timestamp: Some(1_000 + i64::try_from(i).unwrap()),
        object_type: t,
        facts: SnapshotFacts {
            values: [Field::HashSha256, Field::MetaFileVersion]
                .into_iter()
                .filter_map(|k| f.get(k).map(|v| (k, v.to_owned())))
                .collect(),
            path: f.path.as_ref().map(|p| SnapshotPath {
                path: p.path.as_str().to_owned(),
                alias: None,
                short_name_unresolved: p.short_name_unresolved,
                user_writable: p.user_writable,
                volume: None,
            }),
            signers: f.signers.as_ref().map(|v| {
                v.iter()
                    .map(|s| SnapshotSigner {
                        status: SnapshotSignerStatus::Valid,
                        catalog: false,
                        publisher: s.publisher.clone(),
                        issuer: None,
                        leaf_thumbprint_sha256: None,
                    })
                    .collect()
            }),
        },
        variables: Default::default(),
        context: Default::default(),
        device_state: SnapshotState {
            mode: Some(s.mode),
            disconnected: s.connectivity == Connectivity::Disconnected,
            session: s.session.map(|k| match k {
                SessionKind::Audit => simulate::SnapshotSession::Audit,
                SessionKind::FullBypass => simulate::SnapshotSession::FullBypass,
            }),
            lockdown: s.lockdown,
        },
        recorded: None,
    }
}

// Simulator, readiness and policy tests.

const SNAPSHOTS: &str = include_str!("../../tests/fixtures/trace/snapshots.yaml");

fn audit_fixture() -> ValidatedPolicy {
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    validated(doc)
}

#[test]
fn snapshots_load_and_reject_other_versions() {
    let f = read_snapshots(SNAPSHOTS).unwrap();
    assert_eq!(f.snapshots.len(), 7);
    let v2 = SNAPSHOTS.replacen(
        "facts_schema_version: \"1.0.0\"",
        "facts_schema_version: \"2.0.0\"",
        1,
    );
    assert!(matches!(
        read_snapshots(&v2),
        Err(simulate::SnapshotError::UnsupportedVersion(_))
    ));
    let newer = SNAPSHOTS.replacen("\"1.0.0\"", "\"1.1.0\"", 1);
    assert!(
        matches!(
            read_snapshots(&newer),
            Err(simulate::SnapshotError::UnsupportedVersion(_))
        ),
        "a newer minor is not guessed at"
    );
    let dup = format!("{SNAPSHOTS}  - event_id: e1\n    object_type: executable\n");
    assert!(matches!(
        read_snapshots(&dup),
        Err(simulate::SnapshotError::DuplicateEvent(_))
    ));
    let bad = SNAPSHOTS.replacen(
        "object_type: executable",
        "object_type: executable\n    unknown_field: 1",
        1,
    );
    assert!(read_snapshots(&bad).is_err(), "unknown fields are rejected");
    let var = format!(
        "{SNAPSHOTS}  - event_id: e99\n    object_type: executable\n    variables: {{NOPE: ['C:\\\\x']}}\n"
    );
    assert!(matches!(
        read_snapshots(&var),
        Err(simulate::SnapshotError::Invalid { .. })
    ));
}

#[test]
fn a_missing_fact_is_unknown_not_guessed() {
    // A candidate rule needs the product name, which no snapshot has.
    let f = read_snapshots(SNAPSHOTS).unwrap();
    let p = fixture();
    let sim = Simulator::new(&p).unwrap();
    let t = sim
        .trace(&f.snapshots[3], &TraceOptions::at(TraceLevel::Full))
        .unwrap();
    assert!(
        t.unknown_facts
            .iter()
            .any(|u| u.field == Field::MetaProductName)
    );
}

#[test]
fn the_diff_summary_and_aggregates_are_correct() {
    let f = read_snapshots(SNAPSHOTS).unwrap();
    let p = audit_fixture();
    let sim = Simulator::new(&p).unwrap();
    let r = sim
        .run(&f.snapshots, Some(&Candidate::Mode(Mode::Enforce)))
        .unwrap();
    // e1 and e7 allowed by R-000001; e2 would-block (implicit) -> blocked;
    // e3 mandatory in both; e4 would-block (R-000004) -> blocked; e5
    // would-block -> blocked; e6 is a disabled device, which a policy mode
    // change does not touch.
    assert_eq!(r.summary.events, 7);
    assert_eq!(r.summary.newly_blocked, 3);
    assert_eq!(r.summary.newly_allowed, 0);
    assert_eq!(r.summary.unchanged, 4);
    let ids: Vec<&str> = r.changes.iter().map(|c| c.event_id.as_str()).collect();
    assert_eq!(ids, ["e2", "e4", "e5"]);
    let d1 = r.by_device.iter().find(|a| a.key == "dev-1").unwrap();
    assert_eq!(d1.counts.newly_blocked, 2);
    assert_eq!(r.by_device[0].key, "dev-1", "most changes first");
    snapshot("simulation", &r);

    // A change set: allow the pinned build, remove the script host rule.
    let change = ChangeSet {
        remove_rules: vec![rule_id(4).parse().unwrap()],
        enable_rules: vec![rule_id(5).parse().unwrap()],
        ..ChangeSet::default()
    };
    let r = Simulator::new(&fixture())
        .unwrap()
        .run(&f.snapshots, Some(&Candidate::Change(change)))
        .unwrap();
    // e4 (script.exe) was blocked by R-000004 and now gets the implicit
    // deny: same outcome, other attribution. e5 has hash a: newly allowed.
    let by: std::collections::BTreeMap<&str, simulate::Change> = r
        .changes
        .iter()
        .map(|c| (c.event_id.as_str(), c.change))
        .collect();
    assert_eq!(by.get("e4"), Some(&simulate::Change::ChangedAttribution));
    assert_eq!(by.get("e5"), Some(&simulate::Change::NewlyAllowed));
    assert_eq!(r.candidate_revision, Some(8));
    let events = Simulator::new(&fixture())
        .unwrap()
        .events(&f.snapshots, Some(&Candidate::Mode(Mode::Audit)))
        .unwrap();
    assert_eq!(events.len(), 7, "every event, changed or not");
    let e3 = events.iter().find(|e| e.event_id == "e3").unwrap();
    assert_eq!(e3.current.reason_code, Some(ReasonCode::MandatoryDeny));
    assert_eq!(
        e3.candidate.as_ref().unwrap().outcome,
        SimOutcome::Blocked,
        "mandatory in audit"
    );

    let bad = ChangeSet {
        remove_rules: vec![rule_id(77).parse().unwrap()],
        ..ChangeSet::default()
    };
    assert!(
        Simulator::new(&fixture())
            .unwrap()
            .run(&f.snapshots, Some(&Candidate::Change(bad)))
            .is_err()
    );
}

#[test]
fn the_readiness_report_and_gate_are_correct() {
    let f = read_snapshots(SNAPSHOTS).unwrap();
    let p = audit_fixture();
    let opts = readiness::ReadinessOptions {
        until: 1_700_000_000 + 86_400,
        days: 1,
        max_would_block: 1,
        ack_threshold: Some(2),
        top_objects: 5,
    };
    let r = readiness::readiness(&p, &f.snapshots, &opts).unwrap();
    assert_eq!(r.gate.would_block_events, 3);
    assert_eq!(r.gate.devices_affected, 2);
    assert!(r.gate.ack_required);
    assert_eq!(
        r.gate.message,
        "3 would-block events across 2 devices in the last 1 day"
    );
    let ready: Vec<(&str, bool)> = r
        .devices
        .iter()
        .map(|d| (d.device_id.as_str(), d.ready))
        .collect();
    assert_eq!(ready, [("dev-1", false), ("dev-2", true), ("dev-3", true)]);
    assert_eq!(r.events_outside_window, 1);
    assert!(r.top_objects[0].recommended_rule.is_some());
    snapshot("readiness", &r);
    let lax = readiness::ReadinessOptions {
        ack_threshold: Some(3),
        ..opts
    };
    assert!(
        !readiness::readiness(&p, &f.snapshots, &lax)
            .unwrap()
            .gate
            .ack_required
    );
    let none = readiness::ReadinessOptions {
        ack_threshold: None,
        ..opts
    };
    assert!(
        !readiness::readiness(&p, &f.snapshots, &none)
            .unwrap()
            .gate
            .ack_required
    );
}

#[test]
fn policy_tests_pass_fail_and_write_junit() {
    let file =
        policy_test::read_tests(include_str!("../../tests/fixtures/trace/policy-tests.yaml"))
            .unwrap();
    let r = policy_test::run(&fixture(), "fixture", &file).unwrap();
    assert_eq!(r.failed(), 1, "{r:#?}");
    assert_eq!(r.exit_code(), 1);
    let failed = r.results.iter().find(|x| !x.passed).unwrap();
    assert_eq!(failed.name, "a deliberately wrong expectation");
    assert_eq!(failed.failures, ["outcome: expected allowed, got blocked"]);
    assert!(
        failed
            .explanation
            .as_deref()
            .unwrap()
            .starts_with("Blocked: no rule allows")
    );
    snapshot_text("policy-tests.junit.xml", &r.junit());
    let passing = policy_test::TestFile {
        tests: file
            .tests
            .into_iter()
            .filter(|t| t.name != "a deliberately wrong expectation")
            .collect(),
        ..file
    };
    assert_eq!(
        policy_test::run(&fixture(), "fixture", &passing)
            .unwrap()
            .exit_code(),
        0
    );
    assert!(policy_test::read_tests("policy_tests_version: \"1.0.0\"\ntests:\n  - name: x\n    given: {object_type: executable}\n    expect: {}\n").is_err());
}

#[test]
fn the_effective_view_shows_what_a_device_enforces() {
    let p = audit_fixture();
    let state = DeviceState {
        session: Some(SessionKind::Audit),
        ..DeviceState::of(&p.document().policy)
    };
    let v = effective::effective_view(&p, &state, None);
    assert_eq!(v.device_mode, Mode::Audit);
    assert_eq!(v.protection, crate::mode::ProtectionStatus::OverrideActive);
    assert_eq!(v.override_session, Some("audit"));
    assert_eq!(v.rules.len(), 7);
    let retired = v.rules.iter().find(|r| r.name == "Retired allow").unwrap();
    assert!(!retired.active);
    assert_eq!(retired.inactive_reason, Some("disabled"));
    assert!(
        v.settings
            .iter()
            .any(|s| s.key == "mode" && s.source == "policy")
    );
    assert_eq!(v.modes.len(), ObjectType::ALL.len());
    snapshot("effective-view", &v);
}

/// Minor: the effective view judges activity windows as the evaluator
/// does: expired and not-yet-active rules are inactive, with the reason.
#[test]
fn the_effective_view_shows_rules_outside_their_window_as_inactive() {
    use crate::lifecycle::RuleClock;
    use crate::model::Timestamp;
    let day = |d: i64| Timestamp(1_795_564_800 + d * 86_400);
    let hash = serde_json::json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}});
    let rule = |n: u32, action: &str, extra: serde_json::Value| {
        let mut r = serde_json::json!({"id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"), "name": format!("R{n}"),
            "match": hash, "action": {"type": action}});
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    let doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce",
                   "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001"]},
        "rule_sets": [{"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001", "name": "S", "kind": "mixed", "rules": [
            rule(1, "allow", serde_json::json!({"expires_at": day(-1).to_string()})),
            rule(2, "allow", serde_json::json!({"activates_at": day(1).to_string()})),
            rule(3, "deny", serde_json::json!({"expires_at": day(5).to_string()})),
            rule(4, "allow", serde_json::json!({})),
        ]}],
    }).to_string()).unwrap();
    let policy = doc.validate().unwrap();
    let state = DeviceState::of(&policy.document().policy);
    let reasons = |clock: Option<&RuleClock>| -> Vec<(bool, Option<&'static str>)> {
        effective::effective_view(&policy, &state, clock)
            .rules
            .iter()
            .map(|r| (r.active, r.inactive_reason))
            .collect()
    };
    assert_eq!(
        reasons(Some(&RuleClock::at(day(0)))),
        vec![
            (false, Some("expired")),
            (false, Some("not_yet_active")),
            (true, None),
            (true, None),
        ]
    );
    // Without a clock, as an evaluator without one: timed allows are
    // inactive, a timed deny active.
    assert_eq!(
        reasons(None),
        vec![
            (false, Some("not_yet_active")),
            (false, Some("not_yet_active")),
            (true, None),
            (true, None),
        ]
    );
    // It agrees with the evaluator.
    let mut evaluator = Evaluator::new(&policy).unwrap();
    evaluator.set_clock(RuleClock::at(day(0)));
    let view = effective::effective_view(&policy, &state, Some(&RuleClock::at(day(0))));
    for (r, rule) in view.rules.iter().zip(&policy.document().rule_sets[0].rules) {
        assert_eq!(r.active, evaluator.activity_of(rule).is_active());
    }
}

#[test]
fn a_simulated_run_is_fast_enough() {
    // A smoke check, not the benchmark (`benches/simulate.rs` measures
    // throughput): 20k decisions must finish well within a CI budget.
    let p = fixture();
    let base = read_snapshots(SNAPSHOTS).unwrap().snapshots;
    let snaps: Vec<FactsSnapshot> = (0..20_000)
        .map(|i| FactsSnapshot {
            event_id: format!("x{i}"),
            ..base[i % base.len()].clone()
        })
        .collect();
    let sim = Simulator::new(&p).unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = std::time::Instant::now();
    let r = sim
        .run(&snaps, Some(&Candidate::Mode(Mode::Audit)))
        .unwrap();
    assert_eq!(r.summary.events, 20_000);
    assert!(start.elapsed() < std::time::Duration::from_secs(60));
}

// Council round 1 regressions.

#[test]
fn the_draft_falls_back_when_a_criterion_would_not_validate() {
    let p = validated(policy_doc("enforce", vec![(1, "blocklist", false, vec![])]));
    let draft = |facts: ObjectFacts| {
        let o = Obj {
            facts,
            context: EvaluationContext::default(),
        };
        trace_of(&p, &o, &enforce(&p), TraceLevel::Standard).allow_suggestion
    };
    let path = || {
        PathFact::new("C:\\Apps\\a.exe", &VolumeMap::new())
            .with_user_writable(false)
            .with_volume(crate::unknown::VolumeKind::Fixed)
    };
    // A digest of the wrong length is not a hash identity: fall back.
    let d = draft(
        ObjectFacts::new()
            .with(Field::HashSha256, "abcd")
            .with_signers(vec![signer("Example Ltd", SignerStatus::Valid)]),
    )
    .unwrap();
    assert_eq!(d.identity, DraftIdentity::Publisher);
    // An empty product, or one with a control character, is left out.
    for product in ["", "Tools\tX"] {
        let d = draft(
            ObjectFacts::new()
                .with(Field::MetaProductName, product)
                .with_signers(vec![signer("Example Ltd", SignerStatus::Valid)]),
        )
        .unwrap();
        assert_eq!(d.identity, DraftIdentity::Publisher, "{product:?}");
    }
    // A path with a literal `%TEMP%` component does not compile as a
    // criterion value: no draft rather than an invalid one.
    let weird = PathFact::new("C:\\Tools\\%TEMP%\\a.exe", &VolumeMap::new())
        .with_user_writable(false)
        .with_volume(crate::unknown::VolumeKind::Fixed);
    assert!(draft(ObjectFacts::new().with_path(weird)).is_none());
    assert_eq!(
        draft(ObjectFacts::new().with_path(path()))
            .unwrap()
            .identity,
        DraftIdentity::Path
    );
    // A redacted version is not used, and a relaxed signature is not
    // offered as a publisher identity.
    let mut options = TraceOptions::at(TraceLevel::Standard);
    options.privacy.redactor = Redactor::new(&["beta"]).unwrap();
    let o = Obj {
        facts: ObjectFacts::new()
            .with(Field::MetaProductName, "Tools")
            .with(Field::MetaFileVersion, "2.0 beta")
            .with_signers(vec![signer("Example Ltd", SignerStatus::Valid)])
            .with_path(path()),
        context: EvaluationContext::default(),
    };
    let t = trace_with(&p, &o, &enforce(&p), &options, &ObjectExtras::default());
    assert_eq!(
        t.allow_suggestion.unwrap().identity,
        DraftIdentity::PublisherProduct
    );
    let relaxed = ObjectExtras {
        signature_relaxations: vec![SignatureRelaxation {
            signature: 0,
            flag: RelaxationFlag::IgnoreExpiry,
            suppressed: palisade_core::VerificationError::Expired,
        }],
    };
    let t = trace_with(
        &p,
        &o,
        &enforce(&p),
        &TraceOptions::at(TraceLevel::Standard),
        &relaxed,
    );
    assert_eq!(t.allow_suggestion.unwrap().identity, DraftIdentity::Path);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every draft is a valid allow rule that, added to the policy, allows
    /// the object (or a mandatory deny still blocks it).
    #[test]
    fn every_draft_is_a_valid_rule_that_allows(
        hash in proptest::option::of(proptest::sample::select(vec![
            "abcd".to_owned(), sha('a'), String::new(), format!("0x{}", sha('a')), sha('A'),
        ])),
        product in proptest::option::of(proptest::sample::select(vec!["".to_owned(), "Tools".to_owned(), "a\u{7}b".to_owned()])),
        version in proptest::option::of(proptest::sample::select(vec!["2.0".to_owned(), "x".to_owned(), "1.2 (b)".to_owned()])),
        publisher in proptest::option::of(proptest::sample::select(vec!["Example Ltd".to_owned(), "".to_owned()])),
        path in proptest::sample::select(vec!["C:\\Apps\\a.exe", "C:\\%TEMP%\\a.exe", "relative.exe"]),
    ) {
        let p = validated(policy_doc("enforce", vec![(1, "mixed", false, vec![])]));
        let mut f = ObjectFacts::new().with_path(PathFact::new(path, &VolumeMap::new()).with_user_writable(false)
                .with_volume(crate::unknown::VolumeKind::Fixed));
        if let Some(h) = &hash { f.set(Field::HashSha256, h.clone()); }
        if let Some(v) = &product { f.set(Field::MetaProductName, v.clone()); }
        if let Some(v) = &version { f.set(Field::MetaFileVersion, v.clone()); }
        if let Some(v) = &publisher { f.signers = Some(vec![signer(v, SignerStatus::Valid)]); }
        let o = Obj { facts: f, context: EvaluationContext::default() };
        let Some(d) = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard).allow_suggestion else { return Ok(()) };
        let mut doc = p.into_document();
        let r: crate::model::Rule = serde_json::from_value(serde_json::json!({
            "id": rule_id(99), "name": "Draft", "object_types": d.object_types,
            "match": d.r#match, "action": {"type": "allow"},
        })).unwrap();
        doc.rule_sets[0].rules.push(r);
        let p2 = doc.validate();
        prop_assert!(p2.is_ok(), "{:?}", p2.err());
        let p2 = p2.unwrap();
        let t = trace_of(&p2, &o, &enforce(&p2), TraceLevel::Minimal);
        prop_assert_eq!(t.decision.unwrap().outcome(), Outcome::Allowed);
    }
}

#[test]
fn unknown_facts_ignore_unknowns_that_the_tree_absorbed() {
    // any[ all[hash = a, product = Suite], publisher = Example Ltd ]: with
    // hash b, the `all` is no_match whatever the product is, so only the
    // missing publisher left the rule unknown.
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "allowlist",
            false,
            vec![rule(
                1,
                "Nested",
                serde_json::json!({"any": [
                    {"all": [crit("hash.sha256", "equals", &[&sha('a')]), crit("meta.product_name", "equals", &["Suite"])]},
                    crit("signer.publisher", "equals", &["Example Ltd"]),
                ]}),
                serde_json::json!({"type": "allow"}),
            )],
        )],
    ));
    let o = Obj {
        facts: ObjectFacts::new().with(Field::HashSha256, sha('b')),
        context: EvaluationContext::default(),
    };
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let fields: Vec<Field> = t.unknown_facts.iter().map(|u| u.field).collect();
    assert_eq!(fields, [Field::SignerPublisher]);
}

#[test]
fn yes_or_no_criteria_read_as_sentences() {
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "blocklist",
            false,
            vec![rule(
                1,
                "No elevated tools",
                serde_json::json!({"all": [
                    crit("hash.sha256", "equals", &[&sha('a')]),
                    {"criterion": {"field": "user.is_elevated", "operator": "is_true"}},
                ]}),
                serde_json::json!({"type": "deny"}),
            )],
        )],
    ));
    let mut o = object('a', "X", "Y", "C:\\a.exe", Some(false));
    o.context.user.is_elevated = Some(true);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let c = Catalog::english();
    let doc = explain(&t, Verbosity::Short);
    assert_eq!(
        render_tray(&doc, &c),
        "Blocked by rule 'No elevated tools' (R-000001). This is because user.is_elevated is true."
    );
    let md = render_markdown(&doc, &c);
    assert!(md.contains("_user.is\\_elevated is true_"), "{md}");
    o.context.user.is_elevated = Some(false);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let doc = explain(&t, Verbosity::Detailed);
    let lines: Vec<String> = doc
        .paragraphs
        .iter()
        .chain(&doc.why_not)
        .map(|m| c.format(m))
        .collect();
    assert!(
        lines.contains(&"Rule 'No elevated tools' (R-000001) would block this file, but user.is_elevated is not true.".to_owned()),
        "{lines:?}"
    );
}

#[test]
fn a_relaxation_without_a_signer_rule_still_reads_well() {
    let p = validated(policy_doc("enforce", vec![(1, "blocklist", false, vec![])]));
    let o = object('a', "X", "Y", "C:\\a.exe", Some(false));
    let extras = ObjectExtras {
        signature_relaxations: vec![SignatureRelaxation {
            signature: 0,
            flag: RelaxationFlag::IgnoreExpiry,
            suppressed: palisade_core::VerificationError::Expired,
        }],
    };
    let t = trace_with(
        &p,
        &o,
        &enforce(&p),
        &TraceOptions::at(TraceLevel::Standard),
        &extras,
    );
    let doc = explain(&t, Verbosity::Normal);
    let lines: Vec<String> = doc
        .paragraphs
        .iter()
        .map(|m| Catalog::english().format(m))
        .collect();
    assert!(
        lines.contains(
            &"Warning: a signature was accepted only because a certificate option relaxed a check."
                .to_owned()
        ),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"Detail: signature 0: ignore_expiry suppressed expired (5).".to_owned()),
        "{lines:?}"
    );
    assert!(lines.iter().all(|l| !l.contains(": .")), "{lines:?}");
}

#[test]
fn redaction_matches_every_pattern_against_the_original() {
    // An earlier pattern cannot hide part of a later one's secret.
    let r = Redactor::new(&["token", r"token=\S+"]).unwrap();
    assert_eq!(r.redact("x --token=supersecret y"), "x --[redacted] y");
    // A pattern never re-matches a marker, so output never grows.
    // Adjacent matches merge into one marker.
    let r = Redactor::new(&["secret", "red", "e", r"\."]).unwrap();
    assert_eq!(r.redact("a secret."), "a [redacted]");
    // One call is linear: each input byte is replaced at most once, so the
    // output is at most `REDACTED.len()` times the input, even when every
    // byte matches.
    let every = Redactor::new(&["."]).unwrap();
    let input = "x".repeat(1000);
    let out = every.redact(&input);
    assert_eq!(
        out,
        privacy::REDACTED,
        "adjacent matches merge into one marker"
    );
    assert!(r.redact(&input).len() <= input.len() * privacy::REDACTED.len());
    let r = Redactor::new(&["a", "b"]).unwrap();
    assert_eq!(r.redact("abab cab"), "[redacted] c[redacted]");
    assert!(Redactor::new(&["x".repeat(privacy::MAX_PATTERN_BYTES + 1)]).is_err());
}

#[test]
fn snapshot_variables_and_versions_are_strict() {
    let base = "facts_schema_version: \"1.0.0\"\nsnapshots:\n  - event_id: e1\n    object_type: executable\n";
    let dup = format!("{base}    variables: {{TEMP: ['C:\\\\t'], TMP: ['C:\\\\u']}}\n");
    assert!(matches!(
        read_snapshots(&dup),
        Err(simulate::SnapshotError::Invalid { .. })
    ));
    let case = format!("{base}    variables: {{windir: ['C:\\\\w'], WINDIR: ['C:\\\\w']}}\n");
    assert!(matches!(
        read_snapshots(&case),
        Err(simulate::SnapshotError::Invalid { .. })
    ));
    // A newer patch version changes no meaning, so it is read.
    assert!(read_snapshots(&base.replace("1.0.0", "1.0.7")).is_ok());
    assert!(read_snapshots(&base.replace("1.0.0", "1.1.0")).is_err());
}

#[test]
fn changed_outcomes_rank_aggregates() {
    // Under audit, removing an allow turns allowed into allowed_audit:
    // a changed outcome, which must rank its device first.
    let mut doc = fixture().into_document();
    doc.policy.mode = Mode::Audit;
    let p = validated(doc);
    let mut snaps = Vec::new();
    for i in 0..5 {
        let mut s = read_snapshots(SNAPSHOTS).unwrap().snapshots.remove(0);
        s.event_id = format!("a{i}");
        s.device_id = Some("dev-a".to_owned());
        snaps.push(s);
    }
    let mut other = read_snapshots(SNAPSHOTS).unwrap().snapshots.remove(1);
    other.device_id = Some("dev-b".to_owned());
    snaps.push(other);
    let change = Candidate::Change(ChangeSet {
        remove_rules: vec![rule_id(1).parse().unwrap()],
        ..ChangeSet::default()
    });
    let r = Simulator::new(&p)
        .unwrap()
        .run(&snaps, Some(&change))
        .unwrap();
    assert_eq!(r.summary.changed_outcome, 5);
    assert_eq!(r.by_device[0].key, "dev-a");
    assert_eq!(r.by_device[0].counts.changed_outcome, 5);
}

#[test]
fn lockdown_skips_the_session_stage() {
    let p = fixture();
    let o = in_group(
        object(
            'b',
            "Other Ltd",
            "Other",
            "C:\\Apps\\script.exe",
            Some(false),
        ),
        &[],
    );
    let state = DeviceState {
        session: Some(SessionKind::Audit),
        lockdown: true,
        ..enforce(&p)
    };
    let t = trace_of(&p, &o, &state, TraceLevel::Standard);
    let s = t
        .stages
        .iter()
        .find(|s| s.name == StageName::SessionOverride)
        .unwrap();
    assert_eq!(s.outcome, StageOutcome::Skipped);
}

#[test]
fn object_keys_identify_one_object_across_spellings() {
    let snap = |facts: SnapshotFacts| FactsSnapshot {
        event_id: "e".to_owned(),
        device_id: None,
        timestamp: None,
        object_type: ObjectType::Executable,
        facts,
        variables: Default::default(),
        context: Default::default(),
        device_state: SnapshotState::default(),
        recorded: None,
    };
    let key = |f| simulate::object_key(&snap(f));
    let hashed = |h: String| SnapshotFacts {
        values: [(Field::HashSha256, h)].into_iter().collect(),
        ..SnapshotFacts::default()
    };
    assert_eq!(key(hashed(sha('A'))), key(hashed(sha('a'))));
    // A digest the matcher would reject is not an identity.
    assert_eq!(key(hashed(format!("0x{}", sha('a')))), None);
    let pathed = |p: &str| SnapshotFacts {
        path: Some(SnapshotPath {
            path: p.to_owned(),
            alias: None,
            short_name_unresolved: false,
            user_writable: None,
            volume: None,
        }),
        ..SnapshotFacts::default()
    };
    assert_eq!(
        key(pathed("C:/Apps/Tool.exe")),
        key(pathed("c:\\apps\\tool.exe"))
    );
    assert_eq!(key(pathed("relative.exe")), None);
    let signed = |status, p: &str| SnapshotFacts {
        signers: Some(vec![SnapshotSigner {
            status,
            catalog: false,
            publisher: Some(p.to_owned()),
            issuer: None,
            leaf_thumbprint_sha256: None,
        }]),
        ..SnapshotFacts::default()
    };
    assert_eq!(
        key(signed(SnapshotSignerStatus::Valid, "Example Ltd")),
        key(signed(SnapshotSignerStatus::Valid, "EXAMPLE LTD"))
    );
    assert_eq!(
        key(signed(SnapshotSignerStatus::Revoked, "Example Ltd")),
        None
    );
    assert_eq!(key(signed(SnapshotSignerStatus::Valid, "")), None);
}

// Review follow-ups (#41): each test below fails without its fix.

#[test]
fn the_effective_view_marks_every_rule_inactive_on_a_disabled_device() {
    // The evaluator runs no rule on a disabled device, so the view must not
    // report any as active; lockdown overrides a disabled device mode.
    let p = fixture();
    let disabled = DeviceState {
        mode: Mode::Disabled,
        ..enforce(&p)
    };
    let v = effective::effective_view(&p, &disabled, None);
    assert_eq!(v.device_mode, Mode::Disabled);
    assert!(v.rules.iter().all(|r| !r.active), "{:#?}", v.rules);
    let retired = v.rules.iter().find(|r| r.name == "Retired allow").unwrap();
    assert_eq!(retired.inactive_reason, Some("disabled"));
    assert!(
        v.rules
            .iter()
            .filter(|r| r.name != "Retired allow")
            .all(|r| r.inactive_reason == Some("device_disabled"))
    );
    // The view agrees with the evaluator: nothing is decided.
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    assert!(
        trace_of(&p, &o, &disabled, TraceLevel::Standard)
            .decision
            .is_none()
    );

    let locked = DeviceState {
        lockdown: true,
        ..disabled
    };
    let v = effective::effective_view(&p, &locked, None);
    assert_eq!(v.device_mode, Mode::Enforce);
    assert!(
        v.rules
            .iter()
            .all(|r| r.active == (r.name != "Retired allow"))
    );
    assert!(
        trace_of(&p, &o, &locked, TraceLevel::Standard)
            .decision
            .is_some()
    );
}

#[test]
fn why_not_counts_the_failing_criteria_the_trace_left_out() {
    // One allow on hash `a` with MAX_FAILING + 2 product criteria that all
    // fail: `failing` keeps MAX_FAILING, and two more are omitted.
    let extra = limits::MAX_FAILING + 2;
    let mut all = vec![crit("hash.sha256", "equals", &[&sha('a')])];
    for j in 0..extra {
        all.push(crit("meta.product_name", "equals", &[&format!("P{j}")]));
    }
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "allowlist",
            false,
            vec![rule(
                1,
                "Wide",
                serde_json::json!({"all": all}),
                serde_json::json!({"type": "allow"}),
            )],
        )],
    ));
    let o = object('a', "X", "Q", "C:\\a.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    let n = &t.near_misses[0];
    assert_eq!(n.failing.len(), limits::MAX_FAILING);
    assert_eq!(n.failing_omitted, 2);
    let doc = explain(&t, Verbosity::Normal);
    assert_eq!(doc.why_not[0].args["more"], (extra - 1).to_string());
    let text = render_text(&doc, &Catalog::english());
    assert!(
        text.contains(&format!(
            "{} more criteria of that rule also failed.",
            extra - 1
        )),
        "{text}"
    );

    // Only omitted failures beyond the first: one kept, more omitted is
    // still counted. A single failure gives no extra sentence.
    let mut one = n.clone();
    one.failing.truncate(1);
    one.failing_omitted = 2;
    let mut t2 = t.clone();
    t2.near_misses = vec![one.clone()];
    assert_eq!(explain(&t2, Verbosity::Normal).why_not[0].args["more"], "2");
    one.failing_omitted = 0;
    t2.near_misses = vec![one];
    let text = render_text(&explain(&t2, Verbosity::Normal), &Catalog::english());
    assert!(!text.contains("more criteria"), "{text}");
}

#[test]
fn run_rejects_a_test_file_built_in_code_that_expects_nothing() {
    let given = policy_test::Given {
        object_type: ObjectType::Executable,
        facts: SnapshotFacts::default(),
        variables: Default::default(),
        context: Default::default(),
        device_state: SnapshotState::default(),
    };
    let case = |name: &str, expect: policy_test::Expect| policy_test::TestCase {
        name: name.to_owned(),
        given: given.clone(),
        expect,
    };
    let file = |tests| policy_test::TestFile {
        policy_tests_version: policy_test::POLICY_TESTS_VERSION.to_owned(),
        tests,
    };
    let empty = file(vec![case("nothing", policy_test::Expect::default())]);
    assert!(matches!(
        policy_test::run(&fixture(), "s", &empty),
        Err(simulate::SimError::Tests(
            policy_test::TestFileError::Invalid(_)
        ))
    ));
    let both = file(vec![case(
        "both",
        policy_test::Expect {
            rule: Some("R-000001".to_owned()),
            no_rule: true,
            ..Default::default()
        },
    )]);
    assert!(policy_test::run(&fixture(), "s", &both).is_err());
    let twice = file(vec![
        case(
            "a",
            policy_test::Expect {
                no_rule: true,
                ..Default::default()
            },
        ),
        case(
            "a",
            policy_test::Expect {
                no_rule: true,
                ..Default::default()
            },
        ),
    ]);
    assert!(policy_test::run(&fixture(), "s", &twice).is_err());
    let newer = policy_test::TestFile {
        policy_tests_version: "2.0.0".to_owned(),
        ..file(vec![])
    };
    assert!(matches!(
        policy_test::run(&fixture(), "s", &newer),
        Err(simulate::SimError::Tests(
            policy_test::TestFileError::UnsupportedVersion(_)
        ))
    ));
    // A test with a supported expectation still runs.
    let ok = file(vec![case(
        "implicit deny",
        policy_test::Expect {
            outcome: Some(SimOutcome::Blocked),
            no_rule: true,
            ..Default::default()
        },
    )]);
    let r = policy_test::run(&fixture(), "s", &ok).unwrap();
    assert_eq!(r.exit_code(), 0, "{r:#?}");
}

#[test]
fn an_unexpanded_short_name_is_not_an_object_identity() {
    let snap = |facts: SnapshotFacts| FactsSnapshot {
        event_id: "e".to_owned(),
        device_id: None,
        timestamp: None,
        object_type: ObjectType::Executable,
        facts,
        variables: Default::default(),
        context: Default::default(),
        device_state: SnapshotState::default(),
        recorded: None,
    };
    let signer = SnapshotSigner {
        status: SnapshotSignerStatus::Valid,
        catalog: false,
        publisher: Some("Example Ltd".to_owned()),
        issuer: None,
        leaf_thumbprint_sha256: None,
    };
    let short = SnapshotFacts {
        path: Some(SnapshotPath {
            path: "C:\\PROGRA~1\\Tools\\x.exe".to_owned(),
            alias: None,
            short_name_unresolved: true,
            user_writable: None,
            volume: None,
        }),
        signers: Some(vec![signer.clone()]),
        ..SnapshotFacts::default()
    };
    // The matcher reads the path as unknown, so the key falls through to
    // the publisher, as for the same object recorded without a path.
    let only_signer = SnapshotFacts {
        signers: Some(vec![signer]),
        ..SnapshotFacts::default()
    };
    assert_eq!(
        simulate::object_key(&snap(short.clone())),
        simulate::object_key(&snap(only_signer))
    );
    assert_eq!(
        simulate::object_key(&snap(short.clone())).as_deref(),
        Some("publisher:EXAMPLE LTD")
    );
    // With no other identity, there is none.
    let bare = SnapshotFacts {
        signers: None,
        ..short
    };
    assert_eq!(simulate::object_key(&snap(bare)), None);
}

/// The suggestion never claims an allow that precedence would override.
#[test]
fn the_suggestion_follows_the_precedence_model() {
    let deny = |model: &str| {
        let mut doc = policy_doc(
            "enforce",
            vec![(
                1,
                "mixed",
                false,
                vec![rule(
                    1,
                    "Block tool",
                    crit("path.file_name", "equals", &["tool.exe"]),
                    serde_json::json!({"type": "deny"}),
                )],
            )],
        );
        doc.policy.precedence_model = serde_json::from_value(model.into()).unwrap();
        validated(doc)
    };
    let o = object(
        'b',
        "Example Ltd",
        "Example Tools",
        "C:\\Apps\\tool.exe",
        Some(false),
    );
    let suggestion = |p: &ValidatedPolicy| {
        let t = trace_of(p, &o, &enforce(p), TraceLevel::Standard);
        assert_eq!(
            t.allow_suggestion.as_ref().unwrap().caveats,
            ["deny_rule_matched"]
        );
        let doc = explain(&t, Verbosity::Normal);
        let c = Catalog::english();
        let s = doc.suggestion.clone().unwrap();
        // The suggestion line of the rendered text, after its heading.
        let text = render_text(&doc, &c);
        let heading = c.format(&explain::Message {
            id: "heading-suggestion",
            args: Default::default(),
        });
        let line = text
            .lines()
            .skip_while(|l| *l != heading)
            .nth(1)
            .unwrap()
            .to_owned();
        (s.args["effect"].clone(), line)
    };

    // deny_wins: the deny always blocks, so no allow is claimed.
    let p = deny("deny_wins");
    let (effect, text) = suggestion(&p);
    assert_eq!(effect, "deny_wins");
    assert!(!text.contains("would allow"), "{text}");
    assert!(text.contains("no allow rule can stop it"), "{text}");
    // And that is what the evaluator decides with the draft added.
    let draft = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard)
        .allow_suggestion
        .unwrap();
    let with_draft = |p: ValidatedPolicy| {
        let mut doc = p.into_document();
        doc.rule_sets[0].rules.push(
            serde_json::from_value(serde_json::json!({
                "id": rule_id(99), "name": "Draft", "object_types": draft.object_types,
                "match": draft.r#match, "action": {"type": "allow"},
            }))
            .unwrap(),
        );
        validated(doc)
    };
    let p2 = with_draft(p);
    assert_eq!(
        trace_of(&p2, &o, &enforce(&p2), TraceLevel::Minimal)
            .decision
            .unwrap()
            .outcome(),
        Outcome::Blocked
    );

    // allow_wins: the draft does win, and the text only says it may.
    let p = deny("allow_wins");
    let (effect, text) = suggestion(&p);
    assert_eq!(effect, "deny");
    assert!(text.contains("may allow"), "{text}");
    let p2 = with_draft(p);
    assert_eq!(
        trace_of(&p2, &o, &enforce(&p2), TraceLevel::Minimal)
            .decision
            .unwrap()
            .outcome(),
        Outcome::Allowed
    );

    // No deny matched: the draft allows under every model.
    let p = fixture();
    let o = object('b', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert!(t.allow_suggestion.as_ref().unwrap().caveats.is_empty());
    let doc = explain(&t, Verbosity::Normal);
    assert_eq!(doc.suggestion.as_ref().unwrap().args["effect"], "allow");
    assert!(render_text(&doc, &Catalog::english()).contains("it would allow this file"));
}

// --- Scopes (#38) ------------------------------------------------------------

/// A policy with one allow for hash `a` scoped to `scope`, and an allow for
/// hash `a` from publisher `Example Ltd`, unscoped, as a fallback.
fn scoped_policy(scope: serde_json::Value) -> ValidatedPolicy {
    validated(policy_doc(
        "enforce",
        vec![(
            1,
            "allowlist",
            false,
            vec![
                with(
                    rule(
                        1,
                        "Admins only",
                        crit("hash.sha256", "equals", &[&sha('a')]),
                        serde_json::json!({"type": "allow"}),
                    ),
                    "scope",
                    scope,
                ),
                rule(
                    2,
                    "Example publisher",
                    serde_json::json!({"all": [
                        crit("signer.publisher", "equals", &["Example Ltd"]),
                        crit("meta.product_name", "equals", &["Example Tools"]),
                    ]}),
                    serde_json::json!({"type": "allow"}),
                ),
            ],
        )],
    ))
}

#[test]
fn rules_out_of_scope_are_listed_as_rejected_and_nowhere_else() {
    let p = scoped_policy(serde_json::json!({
        "principals": {"include": [{"sid": IT_ADMINS}]}
    }));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.process_token = Some(
        crate::scope::Token::new()
            .with_user(Some("S-1-5-21-1000-2000-3000-1001"), None)
            .with_groups([("S-1-5-32-545", false)]),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert_eq!(t.decision.as_ref().unwrap().outcome(), Outcome::Blocked);
    assert_eq!(t.scope_rejections.len(), 1);
    let r = &t.scope_rejections[0];
    assert_eq!(r.name, "Admins only");
    assert_eq!(r.level, "rule");
    assert_eq!(r.dimension, Some("principals"));
    // It behaves as absent: not matched, and not a near miss.
    assert!(t.matched.iter().all(|m| m.name != "Admins only"));
    assert!(t.near_misses.iter().all(|m| m.name != "Admins only"));
    let doc = explain(&t, Verbosity::Detailed);
    let c = Catalog::english();
    assert!(
        doc.paragraphs
            .iter()
            .any(|m| m.id == "scope-rejected" && c.format(m).contains("principals")),
        "{doc:?}"
    );
    // An administrator is in scope: the rule decides and is not rejected.
    o.context.scope.process_token = Some(
        crate::scope::Token::new()
            .with_user(Some("S-1-5-21-1000-2000-3000-1001"), None)
            .with_groups([(IT_ADMINS, false)]),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert!(t.scope_rejections.is_empty());
    assert_eq!(t.decisive.as_ref().unwrap().name, "Admins only");
}

/// The scope-rejected snapshot (#41 test plan): the administrators-only
/// allow matched a standard user's object, and its scope took it out.
#[test]
fn a_scope_rejection_is_snapshotted() {
    let p = scoped_policy(serde_json::json!({
        "principals": {"include": [{"sid": IT_ADMINS}]}
    }));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.process_token = Some(
        crate::scope::Token::new()
            .with_user(Some("S-1-5-21-1000-2000-3000-1001"), None)
            .with_groups([("S-1-5-32-545", false)]),
    );
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert_eq!(t.scope_rejections.len(), 1);
    snapshot("scope-rejected", &t);
    explained("scope-rejected", &t);
}

/// A rule outside its schedule is a scope rejection with dimension
/// `schedule`, not an inactive match, and the explanation says "outside
/// its schedule" (see [`ScopeRejection`]).
#[test]
fn a_rule_outside_its_schedule_is_a_scope_rejection_not_inactive() {
    // Mondays 09:00 to 17:00 UTC; the time is Monday 00:00 UTC, before it.
    let p = scoped_policy(serde_json::json!({
        "schedule": {"timezone_basis": "utc", "windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}]}
    }));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.time = Some(crate::scope::TrustedTime {
        unix_secs: 1_789_948_800,
        trusted: true,
    });
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    assert!(t.inactive_matches.is_empty(), "{:?}", t.inactive_matches);
    assert_eq!(t.scope_rejections.len(), 1);
    assert_eq!(t.scope_rejections[0].dimension, Some("schedule"));
    let doc = explain(&t, Verbosity::Detailed);
    let c = Catalog::english();
    assert!(
        doc.paragraphs
            .iter()
            .any(|m| m.id == "scope-rejected-schedule"
                && c.format(m).contains("outside its schedule")),
        "{doc:?}"
    );
}

#[test]
fn stale_groups_and_an_untrusted_clock_warn() {
    let p = scoped_policy(serde_json::json!({
        "principals": {"include": [{"cloud_group": {
            "tenant_id": "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "object_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e"
        }}]},
        "schedule": {"timezone_basis": "utc", "windows": [{"days": ["mon"], "start": "00:00", "end": "00:00"}]}
    }));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.process_token = Some(crate::scope::Token::new().with_cloud_groups(
        0,
        [(
            "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e",
        )],
    ));
    o.context.scope.time = Some(crate::scope::TrustedTime {
        unix_secs: 1_789_948_800,
        trusted: false,
    });
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let codes: Vec<WarningCode> = t.warnings.iter().map(|w| w.code).collect();
    assert!(codes.contains(&WarningCode::ScopeStale), "{codes:?}");
    assert!(codes.contains(&WarningCode::ClockUntrusted), "{codes:?}");
    assert_eq!(
        t.decision.as_ref().unwrap().scope_notes(),
        &[
            crate::scope::ScopeNote::ScopeStale,
            crate::scope::ScopeNote::ClockUntrusted
        ]
    );
}

#[test]
fn the_trace_agrees_with_the_evaluator_on_scoped_rules() {
    // Whatever the scope does, the matched list is the evaluator's.
    for scope in [
        serde_json::json!({"principals": {"include": [{"sid": IT_ADMINS}]}}),
        serde_json::json!({"principals": {"exclude": [{"sid": IT_ADMINS}]}}),
        serde_json::json!({"sessions": {"types": ["console"]}, "negate": true}),
    ] {
        let p = scoped_policy(scope);
        for groups in [vec![], vec![(IT_ADMINS, false)], vec![(IT_ADMINS, true)]] {
            let mut o = object(
                'a',
                "Example Ltd",
                "Example Tools",
                "C:\\Apps\\x.exe",
                Some(false),
            );
            o.context.scope.process_token = Some(
                crate::scope::Token::new()
                    .with_user(Some("S-1-5-21-1000-2000-3000-1001"), None)
                    .with_groups(groups.iter().copied()),
            );
            o.context.session.session_type = Some(crate::context::SessionType::Rdp);
            let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
            let vars = PathVariables::new();
            let subject = Subject {
                object_type: ObjectType::Executable,
                facts: &o.facts,
                variables: &vars,
                context: &o.context,
            };
            let tracer = Tracer::new(&p).unwrap();
            let mut expect = tracer.evaluator().matching_ids(&subject);
            expect.sort();
            let got: Vec<_> = t.matched.iter().map(|m| m.rule.rule_id).collect();
            assert_eq!(got, expect);
            // A rejected rule never also matched.
            for r in &t.scope_rejections {
                assert!(!got.contains(&r.rule.rule_id));
            }
        }
    }
}

#[test]
fn an_unknown_scope_is_no_near_miss_and_warnings_name_only_matching_rules() {
    // The scoped allow's tree matches; its cloud group is stale, so its
    // scope is unknown. An unrelated rule with a stale scope and a tree
    // that does not match gets no warning.
    let stale_scope = serde_json::json!({"principals": {"include": [{"cloud_group": {
        "tenant_id": "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
        "object_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e"
    }}]}});
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "mixed",
            false,
            vec![
                with(
                    rule(
                        1,
                        "Stale allow",
                        crit("hash.sha256", "equals", &[&sha('a')]),
                        serde_json::json!({"type": "allow"}),
                    ),
                    "scope",
                    stale_scope.clone(),
                ),
                with(
                    rule(
                        2,
                        "Unrelated",
                        crit("hash.sha256", "equals", &[&sha('f')]),
                        serde_json::json!({"type": "allow"}),
                    ),
                    "scope",
                    stale_scope.clone(),
                ),
                with(
                    rule(
                        3,
                        "Fail-closed deny",
                        crit("hash.sha256", "equals", &[&sha('a')]),
                        serde_json::json!({"type": "deny", "unknown_as": "match"}),
                    ),
                    "scope",
                    stale_scope,
                ),
            ],
        )],
    ));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.process_token = Some(crate::scope::Token::new().with_cloud_groups(
        0,
        [(
            "6f1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
            "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e",
        )],
    ));
    o.context.scope.time = Some(crate::scope::TrustedTime {
        unix_secs: 1_789_948_800,
        trusted: true,
    });
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Full);
    assert!(
        t.near_misses.iter().all(|n| n.name != "Stale allow"),
        "{:?}",
        t.near_misses
    );
    let stale = t
        .warnings
        .iter()
        .find(|w| w.code == WarningCode::ScopeStale)
        .unwrap();
    let names: Vec<u32> = stale
        .rules
        .iter()
        .map(|r| r.display_id.unwrap().to_string()[2..].parse().unwrap())
        .collect();
    assert_eq!(names, vec![1, 3]);
    let deny = t
        .matched
        .iter()
        .find(|m| m.name == "Fail-closed deny")
        .unwrap();
    assert!(deny.via_unknown);
}

#[test]
fn an_instance_limit_block_suggests_no_allow() {
    let p = validated(policy_doc(
        "enforce",
        vec![(
            1,
            "allowlist",
            false,
            vec![with(
                rule(
                    1,
                    "Licensed",
                    crit("hash.sha256", "equals", &[&sha('a')]),
                    serde_json::json!({"type": "allow"}),
                ),
                "scope",
                serde_json::json!({"max_instances_per_session": 1}),
            )],
        )],
    ));
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.instances_in_session = Some(1);
    let t = trace_of(&p, &o, &enforce(&p), TraceLevel::Standard);
    let d = t.decision.as_ref().unwrap();
    assert_eq!(d.reason_code(), ReasonCode::InstanceLimit);
    assert!(t.allow_suggestion.is_none());
    let doc = explain(&t, Verbosity::Detailed);
    assert_eq!(doc.summary.id, "summary-instance-limit");
}

#[test]
fn the_tracer_resolves_library_sets() {
    #[derive(Debug)]
    struct Admins;
    impl crate::scope::ScopeLibrary for Admins {
        fn principal_set(&self, _: &crate::scope::SetRef) -> Option<Vec<String>> {
            Some(vec![IT_ADMINS.to_owned()])
        }
        fn network_set(&self, _: &crate::scope::SetRef) -> Option<Vec<String>> {
            None
        }
        fn schedule_set(&self, _: &crate::scope::SetRef) -> Option<crate::scope::Schedule> {
            None
        }
    }
    let p = scoped_policy(
        serde_json::json!({"principals": {"include": [{"principal_set": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70"
        }}]}}),
    );
    let mut o = object('a', "Other Ltd", "Other", "C:\\Apps\\x.exe", Some(false));
    o.context.scope.process_token = Some(
        crate::scope::Token::new()
            .with_user(Some("S-1-5-21-1000-2000-3000-1001"), None)
            .with_groups([(IT_ADMINS, false)]),
    );
    let vars = PathVariables::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &o.facts,
        variables: &vars,
        context: &o.context,
    };
    let state = enforce(&p);
    let opts = TraceOptions::at(TraceLevel::Standard);
    let with = Tracer::with_library(&p, &Admins).unwrap().trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TRACE,
        &opts,
    );
    assert_eq!(with.decisive.as_ref().unwrap().name, "Admins only");
    let without =
        Tracer::new(&p)
            .unwrap()
            .trace(&subject, &ObjectExtras::default(), &state, TRACE, &opts);
    assert_eq!(
        without.decision.as_ref().unwrap().outcome(),
        Outcome::Blocked
    );
}

#[test]
fn early_boot_drivers_and_prompts_are_traced_as_decided() {
    use crate::context::BootPhase;
    use crate::model::unknown::Level;
    let mut doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce"},
    }).to_string()).unwrap();
    let policy = doc.clone().validate().unwrap();
    let vars = PathVariables::new();
    let mut ctx = EvaluationContext::new();
    ctx.device.boot_phase = Some(BootPhase::Early);
    // The origin collection ran and found nothing (not a missing fact).
    let facts = ObjectFacts::new().with_origin([]);
    let subject = Subject {
        object_type: ObjectType::Driver,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let state = DeviceState::of(&policy.document().policy);
    let tracer = Tracer::new(&policy).unwrap();
    let tr = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
    );
    assert_eq!(tr.effective_mode, Mode::Audit);
    let kinds: Vec<ModeStepKind> = tr.mode_resolution.iter().map(|s| s.kind).collect();
    assert!(kinds.contains(&ModeStepKind::BootPhase), "{kinds:?}");
    // A prompt relaxed by audit mode says it would have asked.
    doc.policy.unknown.default = Level::Prompt;
    doc.policy.mode = Mode::Audit;
    let policy = doc.validate().unwrap();
    let mut ctx = EvaluationContext::new();
    ctx.session.session_type = Some(crate::context::SessionType::Console);
    ctx.user.is_system = Some(false);
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let state = DeviceState::of(&policy.document().policy);
    let tracer = Tracer::new(&policy).unwrap();
    let tr = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
    );
    let applied = tr.mode_resolution.last().unwrap();
    assert!(
        applied.detail.starts_with("would have asked the user"),
        "{}",
        applied.detail
    );
    let doc = explain(&tr, Verbosity::Short);
    assert_eq!(doc.summary.id, "summary-would-ask");
}

#[test]
fn an_override_session_that_lets_a_prompt_run_names_the_session() {
    use crate::model::unknown::Level;
    let mut doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce"},
    }).to_string()).unwrap();
    doc.policy.unknown.default = Level::Prompt;
    let policy = doc.validate().unwrap();
    let vars = PathVariables::new();
    let mut ctx = EvaluationContext::new();
    ctx.session.session_type = Some(crate::context::SessionType::Console);
    ctx.user.is_system = Some(false);
    // The origin collection ran and found nothing (not a missing fact).
    let facts = ObjectFacts::new().with_origin([]);
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let opts = TraceOptions::at(TraceLevel::Standard);
    let tracer = Tracer::new(&policy).unwrap();
    let session = DeviceState {
        session: Some(SessionKind::Audit),
        ..DeviceState::of(&policy.document().policy)
    };
    let tr = tracer.trace(&subject, &ObjectExtras::default(), &session, TRACE, &opts);
    let d = tr.decision.as_ref().unwrap();
    assert_eq!(d.reason_code(), ReasonCode::OverrideSession);
    assert_eq!(d.would_have_been(), Outcome::PendingUser);
    let doc = explain(&tr, Verbosity::Short);
    assert_eq!(doc.summary.id, "summary-override-ask");
    let text = Catalog::english().format(&doc.summary);
    assert!(text.contains("override session"), "{text}");
    // Audit mode without a session keeps its summary.
    let mut audit = policy.document().clone();
    audit.policy.mode = Mode::Audit;
    let audit = audit.validate().unwrap();
    let tr = Tracer::new(&audit).unwrap().trace(
        &subject,
        &ObjectExtras::default(),
        &DeviceState::of(&audit.document().policy),
        TRACE,
        &opts,
    );
    assert_eq!(
        explain(&tr, Verbosity::Short).summary.id,
        "summary-would-ask"
    );
}

#[test]
fn an_out_of_scope_unknown_decision_explains_the_policy_scope() {
    let mut doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce",
                   "scope": {"sessions": {"types": ["console"]}},
                   "unknown": {"default": "detect"}},
    }).to_string()).unwrap();
    doc.policy.name = "P".into();
    let policy = doc.validate().unwrap();
    let vars = PathVariables::new();
    let mut ctx = EvaluationContext::new();
    ctx.session.session_type = Some(crate::context::SessionType::Batch);
    // The origin collection ran and found nothing (not a missing fact).
    let facts = ObjectFacts::new().with_origin([]);
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let tr = Tracer::new(&policy).unwrap().trace(
        &subject,
        &ObjectExtras::default(),
        &DeviceState::of(&policy.document().policy),
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
    );
    assert_eq!(
        tr.decision.as_ref().unwrap().reason_code(),
        ReasonCode::ImplicitDenyUnknown
    );
    let doc = explain(&tr, Verbosity::Normal);
    assert_eq!(doc.summary.id, "summary-implicit");
    assert!(
        doc.paragraphs
            .iter()
            .any(|p| p.id == "unknown-out-of-scope"),
        "{:?}",
        doc.paragraphs
    );
}

#[test]
fn expired_and_future_rules_are_listed_as_inactive_with_their_reason() {
    use crate::lifecycle::RuleClock;
    use crate::model::Timestamp;
    let now = Timestamp(1_795_564_800);
    let hash = |c: char| serde_json::json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [std::iter::repeat_n(c, 64).collect::<String>()]}});
    let rule = |n: u32, extra: serde_json::Value| {
        let mut r = serde_json::json!({"id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"), "name": format!("R{n}"),
            "match": hash('a'), "action": {"type": "allow"}});
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    let doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce",
                   "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001"]},
        "rule_sets": [{"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001", "name": "S", "kind": "allowlist", "rules": [
            rule(1, serde_json::json!({"expires_at": "2026-01-01T00:00:00Z"})),
            rule(2, serde_json::json!({"activates_at": "2027-01-01T00:00:00Z"})),
            rule(3, serde_json::json!({"enabled": false})),
        ]}],
    }).to_string()).unwrap();
    let policy = doc.validate().unwrap();
    let facts = ObjectFacts::new().with(
        Field::HashSha256,
        std::iter::repeat_n('a', 64).collect::<String>(),
    );
    let vars = PathVariables::new();
    let ctx = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let state = DeviceState::of(&policy.document().policy);
    let tracer = Tracer::new(&policy).unwrap().at(RuleClock::at(now));
    let tr = tracer.trace(
        &subject,
        &ObjectExtras::default(),
        &state,
        TRACE,
        &TraceOptions::at(TraceLevel::Standard),
    );
    assert_eq!(tr.decision.as_ref().unwrap().outcome(), Outcome::Blocked);
    let reasons: Vec<InactiveReason> = tr.inactive_matches.iter().map(|i| i.reason).collect();
    assert_eq!(
        reasons,
        vec![
            InactiveReason::Expired,
            InactiveReason::NotYetActive,
            InactiveReason::Disabled
        ]
    );
    let c = Catalog::english();
    let text = render_text(&explain(&tr, Verbosity::Detailed), &c);
    assert!(text.contains("but it has expired"), "{text}");
    assert!(text.contains("but it is not active yet"), "{text}");
}

/// The trace and the evaluator judge activity at the same clock: with the
/// clock before, inside and after each rule's window, the traced decision
/// is the evaluator's, and a rule listed as inactive is one the evaluator
/// left out. A tracer without the clock would disagree on several of
/// these cases.
#[test]
fn the_trace_judges_activity_at_the_evaluators_clock() {
    use crate::lifecycle::RuleClock;
    use crate::model::Timestamp;
    let day = |d: i64| Timestamp(1_795_564_800 + d * 86_400);
    let hash = serde_json::json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [sha('a')]}});
    let rule = |n: u32, action: &str, from: i64, to: i64| {
        serde_json::json!({
            "id": format!("01936b2e-{n:04x}-7b3d-9f21-0a1b2c3d4e61"), "name": format!("R{n}"),
            "match": hash, "action": {"type": action},
            "activates_at": day(from).to_string(), "expires_at": day(to).to_string(),
        })
    };
    let doc = crate::model::PolicyDocument::from_json(&serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f", "name": "P", "revision": 1, "mode": "enforce",
                   "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001"]},
        "rule_sets": [{"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d0001", "name": "S", "kind": "mixed", "rules": [
            rule(1, "allow", 0, 10),
            rule(2, "deny", 5, 15),
        ]}],
    }).to_string()).unwrap();
    let policy = doc.validate().unwrap();
    let facts = ObjectFacts::new().with(Field::HashSha256, sha('a'));
    let vars = PathVariables::new();
    let ctx = EvaluationContext::new();
    let subject = Subject {
        object_type: ObjectType::Executable,
        facts: &facts,
        variables: &vars,
        context: &ctx,
    };
    let state = DeviceState::of(&policy.document().policy);
    let mut seen = std::collections::BTreeSet::new();
    for (now, floor) in [
        (-1, -1),
        (2, 2),
        (7, 7),
        (12, 12),
        (20, 20),
        (7, 12),
        (2, 7),
    ] {
        let clock = RuleClock {
            now: day(now),
            floor: day(floor),
            anchored: true,
        };
        let mut tracer = Tracer::new(&policy).unwrap();
        tracer.set_clock(clock);
        let mut evaluator = Evaluator::new(&policy).unwrap();
        evaluator.set_clock(clock);
        let tr = tracer.trace(
            &subject,
            &ObjectExtras::default(),
            &state,
            TRACE,
            &TraceOptions::at(TraceLevel::Standard),
        );
        let direct = evaluator.evaluate_in(&subject, &state, TRACE);
        assert_eq!(tr.decision, direct, "at {now}/{floor}");
        for i in &tr.inactive_matches {
            let r = policy.document().rule_sets[0]
                .rules
                .iter()
                .find(|r| r.id == i.rule.rule_id)
                .unwrap();
            assert!(!evaluator.activity_of(r).is_active(), "at {now}/{floor}");
        }
        let d = direct.unwrap();
        seen.insert((
            d.outcome() == Outcome::Allowed,
            d.reason_code() == crate::decision::ReasonCode::ExplicitDeny,
        ));
    }
    // The clock really changes the decision across these cases: allowed,
    // explicitly denied, and the implicit deny all occur.
    assert_eq!(seen.len(), 3, "{seen:?}");
}
