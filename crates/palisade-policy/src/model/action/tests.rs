use super::*;
use palisade_core::ScriptKind;

const ID: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70";

fn read(json: serde_json::Value) -> Result<Action, String> {
    serde_json::from_value(json).map_err(|e| e.to_string())
}

fn id() -> Uuid7 {
    ID.parse().unwrap()
}

#[test]
fn every_action_reads_and_writes_its_documented_form() {
    let cases = [
        (serde_json::json!({"type": "allow"}), Action::Allow {}),
        (serde_json::json!({"type": "deny"}), Action::deny()),
        (
            serde_json::json!({"type": "deny", "kill_running": true, "allow_request": true, "request_template": ID}),
            Action::Deny(DenyOptions {
                kill_running: true,
                allow_request: true,
                request_template: Some(RequestTemplateRef(id())),
            }),
        ),
        (serde_json::json!({"type": "audit"}), Action::Audit {}),
        (
            serde_json::json!({"type": "allow_contained", "profile_id": ID}),
            Action::AllowContained(ContainmentDirective {
                profile_id: ContainmentProfileRef(id()),
            }),
        ),
        (
            serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "if_required"}),
            Action::AllowElevated(ElevationDirective {
                token_profile: TokenProfileRef(id()),
                condition: ElevationCondition::IfRequired,
                reason_prompt: None,
                auth: ElevationAuth::None,
            }),
        ),
        (
            serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "always", "reason_prompt": "Why?", "auth": "mfa"}),
            Action::AllowElevated(ElevationDirective {
                token_profile: TokenProfileRef(id()),
                condition: ElevationCondition::Always,
                reason_prompt: Some("Why?".to_owned()),
                auth: ElevationAuth::Mfa,
            }),
        ),
        (
            serde_json::json!({"type": "trust_source", "mode": "chained", "scope_paths": ["C:\\Apps\\"], "tag_output": true}),
            Action::TrustSource(TrustSourceDirective {
                mode: TrustMode::Chained,
                scope_paths: vec!["C:\\Apps\\".to_owned()],
                tag_output: true,
            }),
        ),
        (serde_json::json!({"type": "ignore"}), Action::Ignore {}),
        (serde_json::json!({"type": "defer"}), Action::Defer {}),
    ];
    for (json, action) in cases {
        assert_eq!(read(json.clone()).unwrap(), action, "{json}");
        // Writing gives the same JSON back: defaults are left out.
        assert_eq!(serde_json::to_value(&action).unwrap(), json);
    }
}

#[test]
fn keys_may_come_before_type() {
    let action = read(serde_json::json!({"profile_id": ID, "type": "allow_contained"})).unwrap();
    assert_eq!(action.kind(), ActionKind::AllowContained);
}

#[test]
fn an_option_of_another_action_is_rejected() {
    // After `type`: reported at the key, naming the action's options.
    let e = read(serde_json::json!({"type": "allow", "kill_running": true})).unwrap_err();
    assert!(
        e.contains("unknown field `kill_running`: action `allow` takes no options"),
        "{e}"
    );
    let e = read(serde_json::json!({"type": "deny", "profile_id": ID})).unwrap_err();
    assert!(
        e.contains("unknown field `profile_id` for action `deny`, expected one of `kill_running`, `allow_request`, `request_template`"),
        "{e}"
    );
    // Before `type`: found once `type` is known.
    let e = read(serde_json::json!({"mode": "direct", "type": "deny"})).unwrap_err();
    assert!(e.contains("unknown field `mode` for action `deny`"), "{e}");
    // A key no action has.
    let e = read(serde_json::json!({"type": "deny", "kil_running": true})).unwrap_err();
    assert!(e.contains("unknown field `kil_running`"), "{e}");
}

#[test]
fn required_options_are_required() {
    for (json, field) in [
        (serde_json::json!({"type": "allow_contained"}), "profile_id"),
        (
            serde_json::json!({"type": "allow_elevated", "condition": "always"}),
            "token_profile",
        ),
        (
            serde_json::json!({"type": "allow_elevated", "token_profile": ID}),
            "condition",
        ),
        (
            serde_json::json!({"type": "trust_source", "scope_paths": ["C:\\A"]}),
            "mode",
        ),
        (
            serde_json::json!({"type": "trust_source", "mode": "direct"}),
            "scope_paths",
        ),
    ] {
        let e = read(json.clone()).unwrap_err();
        assert!(
            e.contains(&format!("missing field `{field}`")),
            "{json}: {e}"
        );
    }
}

#[test]
fn repeated_and_mistyped_options_are_rejected() {
    let e = serde_json::from_str::<Action>(
        r#"{"type":"deny","kill_running":true,"kill_running":false}"#,
    )
    .unwrap_err();
    assert!(
        e.to_string().contains("duplicate field `kill_running`"),
        "{e}"
    );
    for json in [
        serde_json::json!({"type": "deny", "kill_running": "yes"}),
        serde_json::json!({"type": "deny", "kill_running": 1}),
        serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "sometimes"}),
        serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "always", "auth": "password"}),
        serde_json::json!({"type": "trust_source", "mode": "transitive", "scope_paths": ["C:\\A"]}),
        serde_json::json!({"type": "trust_source", "mode": "direct", "scope_paths": "C:\\A"}),
        serde_json::json!({"type": "allow_contained", "profile_id": "01936B2E-8C4A-7B3D-9F21-0A1B2C3D4E70"}),
        serde_json::json!({"type": "allow_contained", "profile_id": "00000000-0000-4000-8000-000000000000"}),
        serde_json::json!({"type": "deny", "request_template": 7}),
    ] {
        assert!(read(json.clone()).is_err(), "{json}");
    }
}

#[test]
fn null_unsets_an_optional_option_as_the_schema_allows() {
    let action = read(serde_json::json!({"type": "deny", "request_template": null})).unwrap();
    assert_eq!(action, Action::deny());
    let action = read(serde_json::json!({
        "type": "allow_elevated", "token_profile": ID, "condition": "always", "reason_prompt": null
    }))
    .unwrap();
    assert!(matches!(action, Action::AllowElevated(e) if e.reason_prompt.is_none()));
    // Options with a default, and required ones, are not nullable.
    for json in [
        serde_json::json!({"type": "deny", "kill_running": null}),
        serde_json::json!({"type": "allow_contained", "profile_id": null}),
        serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "always", "auth": null}),
    ] {
        assert!(read(json.clone()).is_err(), "{json}");
    }
}

#[test]
fn the_tag_is_a_name_not_an_index() {
    for json in [
        serde_json::json!({"type": 1}),
        serde_json::json!({"type": "Deny"}),
        serde_json::json!({"type": "allow-contained"}),
        serde_json::json!(["deny"]),
        serde_json::json!("deny"),
        serde_json::json!({}),
    ] {
        assert!(read(json.clone()).is_err(), "{json}");
    }
}

#[test]
fn option_keys_match_what_is_written() {
    // `option_keys` drives the reader; it must list exactly the keys each
    // action's serialised form can have.
    for action in [
        Action::Allow {},
        Action::Deny(DenyOptions {
            kill_running: true,
            allow_request: true,
            request_template: Some(RequestTemplateRef(id())),
        }),
        Action::Audit {},
        Action::AllowContained(ContainmentDirective {
            profile_id: ContainmentProfileRef(id()),
        }),
        Action::AllowElevated(ElevationDirective {
            token_profile: TokenProfileRef(id()),
            condition: ElevationCondition::Always,
            reason_prompt: Some("Why?".to_owned()),
            auth: ElevationAuth::Reauth,
        }),
        Action::TrustSource(TrustSourceDirective {
            mode: TrustMode::Direct,
            scope_paths: vec!["C:\\A".to_owned()],
            tag_output: true,
        }),
        Action::Ignore {},
        Action::Defer {},
    ] {
        let value = serde_json::to_value(&action).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| *k != "type")
            .collect();
        let mut expected = action.kind().option_keys().to_vec();
        keys.sort_unstable();
        expected.sort_unstable();
        assert_eq!(keys, expected, "{action:?}");
        assert_eq!(value["type"], action.kind().as_str());
    }
}

#[test]
fn kinds_are_named_as_in_documents() {
    for kind in ActionKind::ALL {
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::Value::from(kind.as_str())
        );
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn terminal_and_permitting_actions() {
    use ActionKind as A;
    let terminal: Vec<_> = A::ALL.into_iter().filter(|k| k.is_terminal()).collect();
    assert_eq!(
        terminal,
        [
            A::Allow,
            A::Deny,
            A::AllowContained,
            A::AllowElevated,
            A::Ignore
        ]
    );
    let permits: Vec<_> = A::ALL.into_iter().filter(|k| k.permits()).collect();
    assert_eq!(permits, [A::Allow, A::AllowContained, A::AllowElevated]);
    let identity: Vec<_> = A::ALL.into_iter().filter(|k| k.needs_identity()).collect();
    assert_eq!(
        identity,
        [
            A::Allow,
            A::AllowContained,
            A::AllowElevated,
            A::TrustSource,
            A::Ignore
        ]
    );
}

/// The validity matrix, written out in full so that any change to it is a
/// deliberate change to this table.
#[test]
fn validity_matrix_by_object_type() {
    use ActionKind as A;
    use ObjectType as T;
    let script = T::Script(ScriptKind::Powershell);
    // Columns: executable, library, driver, script, installer,
    // compiled_html, html_application, control_panel_applet, packaged_app,
    // command, com_object.
    let columns = [
        T::Executable,
        T::Library,
        T::Driver,
        script,
        T::Installer,
        T::CompiledHtml,
        T::HtmlApplication,
        T::ControlPanelApplet,
        T::PackagedApp,
        T::Command,
        T::ComObject,
    ];
    let table: [(A, [u8; 11]); 8] = [
        (A::Allow, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        (A::Deny, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        (A::Audit, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        (A::AllowContained, [1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]),
        (A::AllowElevated, [1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0]),
        (A::TrustSource, [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
        (A::Ignore, [0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1]),
        (A::Defer, [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
    ];
    for (kind, row) in table {
        for (t, want) in columns.iter().zip(row) {
            assert_eq!(kind.valid_for_object_type(*t), want == 1, "{kind} / {t}");
        }
    }
    // Every script kind is treated alike.
    for kind in ScriptKind::ALL {
        for action in A::ALL {
            assert_eq!(
                action.valid_for_object_type(T::Script(kind)),
                action.valid_for_object_type(script),
                "{action} / {kind:?}"
            );
        }
    }
    let kill: Vec<bool> = columns
        .iter()
        .map(|t| A::kill_running_valid_for(*t))
        .collect();
    assert_eq!(
        kill,
        [
            true, false, false, true, true, true, true, true, true, true, true
        ]
    );
}

#[test]
fn validity_matrix_by_rule_set_kind() {
    use ActionKind as A;
    use RuleSetKind as K;
    // Columns: allowlist, blocklist, baseline, trust, elevation,
    // containment, mixed.
    let columns = [
        K::Allowlist,
        K::Blocklist,
        K::Baseline,
        K::Trust,
        K::Elevation,
        K::Containment,
        K::Mixed,
    ];
    let table: [(A, [u8; 7]); 8] = [
        (A::Allow, [1, 0, 1, 0, 0, 0, 1]),
        (A::Deny, [0, 1, 0, 0, 0, 0, 1]),
        (A::Audit, [1, 1, 1, 1, 1, 1, 1]),
        (A::AllowContained, [1, 0, 0, 0, 0, 1, 1]),
        (A::AllowElevated, [0, 0, 0, 0, 1, 0, 1]),
        (A::TrustSource, [0, 0, 0, 1, 0, 0, 1]),
        (A::Ignore, [0, 0, 0, 0, 0, 0, 1]),
        (A::Defer, [1, 1, 1, 1, 1, 1, 1]),
    ];
    for (kind, row) in table {
        for (k, want) in columns.iter().zip(row) {
            assert_eq!(kind.valid_in_rule_set(*k), want == 1, "{kind} / {k:?}");
        }
    }
}

#[test]
fn generated_documents_cover_every_action() {
    // The property tests run over `arbitrary::document`; check that it
    // reaches every action, so the validity matrix and round trips are
    // exercised for each.
    use proptest::strategy::{Strategy, ValueTree};
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let mut seen = std::collections::BTreeSet::new();
    let mut effects = false;
    for _ in 0..2000 {
        let doc = crate::model::arbitrary::document()
            .new_tree(&mut runner)
            .unwrap()
            .current();
        for rule in doc.rule_sets.iter().flat_map(|s| &s.rules) {
            seen.insert(rule.action.kind());
            effects |= !rule.effects.is_empty();
        }
        if seen.len() == ActionKind::ALL.len() && effects {
            return;
        }
    }
    panic!("only generated {seen:?}, effects: {effects}");
}
