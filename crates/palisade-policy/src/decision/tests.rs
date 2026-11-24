//! `Decision` construction and its stable JSON form.
//!
//! Each case is compared with a committed snapshot in
//! `tests/snapshots/decision/<name>.json`. After a deliberate change to the
//! JSON form, regenerate them with:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-policy decision::
//! ```

use std::path::PathBuf;

use super::*;
use crate::model::{
    ContainmentProfileRef, DenyOptions, Effects, ElevationAuth, ElevationCondition, EventSeverity,
    LogLevel, Notify, PolicyDocument, TokenProfileRef, TrustMode, Upload,
};

const TRACE: TraceId = TraceId([
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
]);

/// A validated document with one rule set holding one rule.
fn document(kind: &str, mandatory: bool, rule: serde_json::Value) -> PolicyDocument {
    let mut rule = rule;
    let object = rule.as_object_mut().unwrap();
    object.insert("id".into(), "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61".into());
    object.insert("name".into(), "Rule".into());
    object.entry("match").or_insert(serde_json::json!({
        "criterion": {
            "field": "hash.sha256",
            "operator": "equals",
            "values": ["a".repeat(64)]
        }
    }));
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Snapshot",
            "revision": 42,
            "mode": "enforce",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"]
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
            "name": "Set",
            "kind": kind,
            "mandatory": mandatory,
            "rules": [rule]
        }]
    });
    let doc = PolicyDocument::from_json(&json.to_string()).unwrap();
    // Only valid documents are snapshotted, so the snapshots show
    // decisions a real policy can produce.
    doc.clone().validate().unwrap();
    doc
}

fn decide(doc: &PolicyDocument) -> Option<Decision> {
    let set = &doc.rule_sets[0];
    Decision::from_rule(&doc.policy, set, &set.rules[0], TRACE)
}

fn snapshot(name: &str, decision: &Decision) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/decision")
        .join(format!("{name}.json"));
    let mut text = serde_json::to_string_pretty(decision).unwrap();
    text.push('\n');
    if std::env::var_os("PALISADE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &text).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == text,
        "{} differs from the decision:\n{text}\nRegenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-policy decision::",
        path.display()
    );
}

#[test]
fn explicit_allow() {
    let doc = document(
        "allowlist",
        false,
        serde_json::json!({"display_id": "R-000123", "action": {"type": "allow"}}),
    );
    let d = decide(&doc).unwrap();
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(d.would_have_been(), Outcome::Allowed);
    assert_eq!(d.reason_code(), ReasonCode::ExplicitAllow);
    assert_eq!(d.effects().log, LogLevel::Summary);
    assert_eq!(d.effects().upload, Upload::Batched);
    assert_eq!(d.effects().suppress_duplicates_secs, 86_400);
    let rule = d.matched_rule().unwrap();
    assert_eq!(rule.display_id.unwrap().to_string(), "R-000123");
    assert_eq!(rule.policy_revision, 42);
    snapshot("allowed", &d);
}

#[test]
fn allow_contained_carries_its_profile() {
    let doc = document(
        "containment",
        false,
        serde_json::json!({
            "object_types": ["executable"],
            "action": {"type": "allow_contained", "profile_id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e80"}
        }),
    );
    let d = decide(&doc).unwrap();
    assert_eq!(d.outcome(), Outcome::Allowed);
    assert_eq!(d.action(), ActionKind::AllowContained);
    assert_eq!(
        d.directives().containment.as_ref().unwrap().profile_id,
        ContainmentProfileRef("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e80".parse().unwrap())
    );
    snapshot("allowed-contained", &d);
}

#[test]
fn allow_elevated_carries_its_directive_and_always_logs() {
    let doc = document(
        "elevation",
        false,
        serde_json::json!({
            "object_types": ["installer"],
            "action": {
                "type": "allow_elevated",
                "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e81",
                "condition": "if_required",
                "reason_prompt": "Why do you need this?",
                "auth": "reauth"
            }
        }),
    );
    let d = decide(&doc).unwrap();
    let e = d.directives().elevation.as_ref().unwrap();
    assert_eq!(
        e.token_profile,
        TokenProfileRef("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e81".parse().unwrap())
    );
    assert_eq!(e.condition, ElevationCondition::IfRequired);
    assert_eq!(e.auth, ElevationAuth::Reauth);
    assert_eq!(d.effects().log, LogLevel::Always);
    assert_eq!(d.effects().upload, Upload::Immediate);
    snapshot("allowed-elevated", &d);
}

#[test]
fn explicit_deny_with_options_and_effects() {
    let doc = document(
        "blocklist",
        false,
        serde_json::json!({
            "object_types": ["executable", "script.powershell"],
            "action": {
                "type": "deny",
                "kill_running": true,
                "allow_request": true,
                "request_template": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e82"
            },
            "effects": {
                "notify": "custom",
                "notification_text": "{file} from {publisher} is blocked by {rule}.",
                "help_url": "https://help.example/blocked",
                "severity": "high",
                "tags": ["lolbin", "mitre:T1218.005"]
            }
        }),
    );
    let d = decide(&doc).unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::ExplicitDeny);
    assert!(d.directives().kill_running);
    assert!(d.directives().request.unwrap().template.is_some());
    assert_eq!(d.effects().notify, Notify::Custom);
    assert_eq!(d.effects().severity, EventSeverity::High);
    assert_eq!(d.effects().log, LogLevel::Always);
    assert_eq!(d.effects().upload, Upload::Immediate);
    assert_eq!(d.effects().suppress_duplicates_secs, 600);
    snapshot("blocked", &d);
}

#[test]
fn mandatory_deny() {
    let doc = document(
        "blocklist",
        true,
        serde_json::json!({"action": {"type": "deny"}}),
    );
    let d = decide(&doc).unwrap();
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.reason_code(), ReasonCode::MandatoryDeny);
    assert_eq!(d.effects().notify, Notify::Default);
    assert_eq!(d.effects().severity, EventSeverity::Medium);
    snapshot("blocked-mandatory", &d);
}

#[test]
fn implicit_deny() {
    let d = Decision::implicit_deny(TRACE);
    assert_eq!(d.outcome(), Outcome::Blocked);
    assert_eq!(d.would_have_been(), Outcome::Blocked);
    assert_eq!(d.action(), ActionKind::Deny);
    assert!(d.matched_rule().is_none());
    assert_eq!(d.reason_code(), ReasonCode::ImplicitDenyUnknown);
    assert_eq!(d.effects(), &Effects::default().resolve(ActionKind::Deny));
    snapshot("blocked-implicit", &d);
}

#[test]
fn ignore_is_an_exclusion_that_logs_nothing() {
    let doc = document(
        "mixed",
        false,
        serde_json::json!({
            "object_types": ["library"],
            "action": {"type": "ignore"}
        }),
    );
    let d = decide(&doc).unwrap();
    assert_eq!(d.outcome(), Outcome::Ignored);
    assert_eq!(d.reason_code(), ReasonCode::Exclusion);
    assert_eq!(d.effects().log, LogLevel::Never);
    assert_eq!(d.effects().upload, Upload::LocalOnly);
    assert_eq!(d.effects().suppress_duplicates_secs, 0);
    snapshot("ignored", &d);
}

#[test]
fn non_terminal_and_disabled_rules_do_not_decide() {
    for action in [
        serde_json::json!({"type": "audit"}),
        serde_json::json!({"type": "defer"}),
        serde_json::json!({"type": "trust_source", "mode": "direct", "scope_paths": ["C:\\Apps"]}),
    ] {
        let doc = document(
            "mixed",
            false,
            serde_json::json!({"object_types": ["installer"], "action": action}),
        );
        assert!(decide(&doc).is_none(), "{action}");
    }
    let doc = document(
        "allowlist",
        false,
        serde_json::json!({"enabled": false, "action": {"type": "allow"}}),
    );
    assert!(decide(&doc).is_none());
}

#[test]
fn directive_defaults_are_written_out() {
    // The model leaves defaults out when written; a decision does not.
    let d = Directives::of(&Action::AllowElevated(crate::model::ElevationDirective {
        token_profile: TokenProfileRef("01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e81".parse().unwrap()),
        condition: ElevationCondition::Always,
        reason_prompt: None,
        auth: ElevationAuth::None,
    }));
    let value = serde_json::to_value(&d).unwrap();
    assert_eq!(
        value["elevation"],
        serde_json::json!({
            "token_profile": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e81",
            "condition": "always",
            "reason_prompt": null,
            "auth": "none"
        })
    );
    let doc = document(
        "trust",
        false,
        serde_json::json!({
            "object_types": ["installer"],
            "action": {"type": "trust_source", "mode": "direct", "scope_paths": ["C:\\Apps"]}
        }),
    );
    let set = &doc.rule_sets[0];
    let rule = &set.rules[0];
    let Action::TrustSource(t) = &rule.action else {
        panic!("not a trust source");
    };
    let grant = TrustGrant::new(RuleRef::new(&doc.policy, set, rule), t);
    let value = serde_json::to_value(&grant).unwrap();
    assert_eq!(value["tag_output"], false);
    assert_eq!(value["mode"], "direct");
    assert_eq!(value["scope_paths"], serde_json::json!(["C:\\Apps"]));
    assert_eq!(value["rule"]["display_id"], serde_json::Value::Null);
}

#[test]
fn every_field_is_always_present() {
    // A consumer can rely on the shape: absent values are `null`, never
    // missing keys.
    let d = Decision::implicit_deny(TRACE);
    let value = serde_json::to_value(&d).unwrap();
    let keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut expected = [
        "outcome",
        "would_have_been",
        "action",
        "matched_rule",
        "annotations",
        "mode",
        "directives",
        "effects",
        "reason_code",
        "trace_id",
    ];
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    expected.sort_unstable();
    assert_eq!(sorted, expected);
    assert!(value["matched_rule"].is_null());
    assert_eq!(value["trace_id"], "0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    for key in [
        "containment",
        "elevation",
        "trust_source",
        "kill_running",
        "request",
    ] {
        assert!(value["directives"].get(key).is_some(), "{key}");
    }
}

#[test]
fn enum_names_are_stable() {
    let names = |values: &[serde_json::Value]| -> Vec<String> {
        values
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let outcomes: Vec<_> = [
        Outcome::Allowed,
        Outcome::Blocked,
        Outcome::AllowedAudit,
        Outcome::AllowedOverride,
        Outcome::Ignored,
    ]
    .iter()
    .map(|o| serde_json::to_value(o).unwrap())
    .collect();
    assert_eq!(
        names(&outcomes),
        [
            "allowed",
            "blocked",
            "allowed_audit",
            "allowed_override",
            "ignored"
        ]
    );
    let reasons: Vec<_> = [
        ReasonCode::ExplicitAllow,
        ReasonCode::ExplicitDeny,
        ReasonCode::MandatoryDeny,
        ReasonCode::ImplicitDenyUnknown,
        ReasonCode::AuditModeWouldBlock,
        ReasonCode::OverrideSession,
        ReasonCode::Exclusion,
    ]
    .iter()
    .map(|r| serde_json::to_value(r).unwrap())
    .collect();
    assert_eq!(
        names(&reasons),
        [
            "explicit_allow",
            "explicit_deny",
            "mandatory_deny",
            "implicit_deny_unknown",
            "audit_mode_would_block",
            "override_session",
            "exclusion"
        ]
    );
}

#[test]
fn display_ids_keep_their_digits() {
    for text in ["R-000001", "R-123456789012", "R-000000"] {
        assert_eq!(DisplayId::parse(text).unwrap().to_string(), text);
    }
    for text in [
        "R-12345",
        "R-1234567890123",
        "r-000001",
        "R-00000a",
        "R-+12345",
        "000001",
    ] {
        assert!(DisplayId::parse(text).is_none(), "{text}");
    }
}

#[test]
fn rule_refs_are_small_and_copy() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<RuleRef>();
    // Three 16-byte IDs, a revision and the display ID.
    assert!(core::mem::size_of::<RuleRef>() <= 80);
}

#[test]
fn directives_of_each_action() {
    let d = Directives::of(&Action::Deny(DenyOptions {
        kill_running: false,
        allow_request: true,
        request_template: None,
    }));
    assert_eq!(d.request, Some(RequestDirective { template: None }));
    assert!(!d.kill_running);
    // A trust source does not decide; its grant is added by #35.
    let t = Directives::of(&Action::TrustSource(crate::model::TrustSourceDirective {
        mode: TrustMode::Direct,
        scope_paths: vec!["C:\\A".to_owned()],
        tag_output: false,
    }));
    assert_eq!(t, Directives::default());
    assert_eq!(Directives::of(&Action::Allow {}), Directives::default());
}
