//! Validation of actions and effect flags (#34).

use super::{help_url_problem, notification_text_problem, scope_path_key, scope_path_problem};
use crate::model::{PolicyDocument, RuleSetKind};
use crate::validate::{ErrorCode, Severity, ValidationError};

const RULE: &str = "/rule_sets/0/rules/0";

/// A document with one rule set of `kind` holding one rule. `rule` is
/// merged over a rule that matches one SHA-256.
fn doc(kind: &str, mandatory: bool, rule: &serde_json::Value) -> PolicyDocument {
    let mut full = serde_json::json!({
        "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
        "name": "Rule",
        "match": {"criterion": {
            "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]
        }}
    });
    for (k, v) in rule.as_object().unwrap() {
        full[k] = v.clone();
    }
    let json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Actions",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"]
        },
        "rule_sets": [{
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
            "name": "Set",
            "kind": kind,
            "mandatory": mandatory,
            "rules": [full]
        }]
    });
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

/// The findings for one rule in a `mixed` set.
fn findings(rule: &serde_json::Value) -> Vec<(ErrorCode, String)> {
    findings_in("mixed", false, rule)
}

fn findings_in(kind: &str, mandatory: bool, rule: &serde_json::Value) -> Vec<(ErrorCode, String)> {
    let all: Vec<ValidationError> = match doc(kind, mandatory, rule).validate() {
        Ok(v) => v.warnings().to_vec(),
        Err(e) => e,
    };
    all.into_iter()
        .map(|e| (e.code, e.path.replacen(RULE, "", 1)))
        .collect()
}

fn one(code: ErrorCode, path: &str) -> Vec<(ErrorCode, String)> {
    vec![(code, path.to_owned())]
}

const ID: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70";

fn elevated() -> serde_json::Value {
    serde_json::json!({"type": "allow_elevated", "token_profile": ID, "condition": "always"})
}

fn trust(paths: &[&str]) -> serde_json::Value {
    serde_json::json!({"type": "trust_source", "mode": "direct", "scope_paths": paths})
}

#[test]
fn every_action_is_valid_in_a_mixed_set_for_a_type_it_supports() {
    for (action, types) in [
        (serde_json::json!({"type": "allow"}), serde_json::json!([])),
        (serde_json::json!({"type": "deny"}), serde_json::json!([])),
        (serde_json::json!({"type": "audit"}), serde_json::json!([])),
        (
            serde_json::json!({"type": "allow_contained", "profile_id": ID}),
            serde_json::json!(["executable"]),
        ),
        (
            elevated(),
            serde_json::json!(["executable", "script.batch"]),
        ),
        (trust(&["C:\\Apps\\"]), serde_json::json!(["installer"])),
        (serde_json::json!({"type": "defer"}), serde_json::json!([])),
    ] {
        let f = findings(&serde_json::json!({"action": action, "object_types": types}));
        assert!(f.is_empty(), "{action}: {f:?}");
    }
}

#[test]
fn rule_set_kind_must_fit_the_action() {
    let f = findings_in(
        "allowlist",
        false,
        &serde_json::json!({"action": {"type": "deny"}}),
    );
    assert_eq!(f, one(ErrorCode::ActionNotValidInRuleSet, "/action/type"));
    let f = findings_in(
        "blocklist",
        false,
        &serde_json::json!({"action": {"type": "allow"}}),
    );
    assert_eq!(f, one(ErrorCode::ActionNotValidInRuleSet, "/action/type"));
    let f = findings_in(
        "trust",
        false,
        &serde_json::json!({"action": elevated(), "object_types": ["executable"]}),
    );
    assert_eq!(f, one(ErrorCode::ActionNotValidInRuleSet, "/action/type"));
    // Audit and defer fit everywhere.
    for kind in [
        "allowlist",
        "blocklist",
        "baseline",
        "trust",
        "elevation",
        "containment",
    ] {
        for action in ["audit", "defer"] {
            let f = findings_in(
                kind,
                false,
                &serde_json::json!({"action": {"type": action}}),
            );
            assert!(f.is_empty(), "{kind} {action}: {f:?}");
        }
    }
}

#[test]
fn a_mandatory_set_reports_a_non_deny_once() {
    // The mandatory check already says it must deny; the kind check does
    // not repeat it.
    let f = findings_in(
        "blocklist",
        true,
        &serde_json::json!({"action": {"type": "allow"}}),
    );
    assert_eq!(f, one(ErrorCode::MandatoryRuleNotDeny, "/action"));
}

#[test]
fn object_types_must_fit_the_action() {
    let f = findings(&serde_json::json!({
        "action": elevated(), "object_types": ["executable", "library", "driver"]
    }));
    assert_eq!(
        f,
        vec![
            (
                ErrorCode::ActionNotValidForObjectType,
                "/object_types/1".to_owned()
            ),
            (
                ErrorCode::ActionNotValidForObjectType,
                "/object_types/2".to_owned()
            ),
        ]
    );
    let f = findings(&serde_json::json!({
        "action": {"type": "allow_contained", "profile_id": ID}, "object_types": ["driver"]
    }));
    assert_eq!(
        f,
        one(ErrorCode::ActionNotValidForObjectType, "/object_types/0")
    );
    let f = findings(&serde_json::json!({
        "action": trust(&["C:\\A"]), "object_types": ["script.powershell"]
    }));
    assert_eq!(
        f,
        one(ErrorCode::ActionNotValidForObjectType, "/object_types/0")
    );
}

#[test]
fn an_empty_type_list_means_every_type() {
    // So a restricted action must list its types.
    for action in [
        elevated(),
        trust(&["C:\\A"]),
        serde_json::json!({"type": "allow_contained", "profile_id": ID}),
    ] {
        let f = findings(&serde_json::json!({"action": action}));
        assert_eq!(
            f,
            one(ErrorCode::ActionNotValidForObjectType, "/object_types"),
            "{action}"
        );
    }
}

#[test]
fn kill_running_is_not_for_drivers_or_libraries() {
    let kill = serde_json::json!({"type": "deny", "kill_running": true});
    let f =
        findings(&serde_json::json!({"action": kill, "object_types": ["executable", "library"]}));
    assert_eq!(
        f,
        one(
            ErrorCode::ActionNotValidForObjectType,
            "/action/kill_running"
        )
    );
    let f = findings(&serde_json::json!({"action": kill}));
    assert_eq!(
        f,
        one(
            ErrorCode::ActionNotValidForObjectType,
            "/action/kill_running"
        )
    );
    let f = findings(
        &serde_json::json!({"action": kill, "object_types": ["executable", "script.cmd"]}),
    );
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn request_options_are_consistent() {
    let f = findings(&serde_json::json!({
        "action": {"type": "deny", "request_template": ID}
    }));
    assert_eq!(
        f,
        one(ErrorCode::InvalidActionOption, "/action/request_template")
    );
    let f = findings(&serde_json::json!({
        "action": {"type": "deny", "allow_request": true}, "effects": {"notify": "none"}
    }));
    assert_eq!(
        f,
        one(ErrorCode::InvalidActionOption, "/action/allow_request")
    );
    let f = findings_in(
        "blocklist",
        true,
        &serde_json::json!({"action": {"type": "deny", "allow_request": true}}),
    );
    assert_eq!(
        f,
        one(ErrorCode::InvalidActionOption, "/action/allow_request")
    );
    let f = findings(&serde_json::json!({
        "action": {"type": "deny", "allow_request": true, "request_template": ID}
    }));
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn reason_prompts_are_bounded_and_printable() {
    // One line: tabs and line breaks are rejected, unlike notification text.
    for bad in [
        "",
        " padded",
        "a\u{7}b",
        "two\nlines",
        "tab\there",
        "cr\rhere",
        "\u{202e}abc",
        &"x".repeat(257),
    ] {
        let mut action = elevated();
        action["reason_prompt"] = bad.into();
        let f = findings(&serde_json::json!({"action": action, "object_types": ["executable"]}));
        assert_eq!(
            f,
            one(ErrorCode::InvalidActionOption, "/action/reason_prompt"),
            "{bad:?}"
        );
    }
    let mut action = elevated();
    action["reason_prompt"] = "x".repeat(256).into();
    let f = findings(&serde_json::json!({"action": action, "object_types": ["executable"]}));
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn scope_paths_are_checked() {
    let f = findings(&serde_json::json!({"action": trust(&[]), "object_types": ["installer"]}));
    assert_eq!(
        f,
        one(ErrorCode::InvalidActionOption, "/action/scope_paths")
    );
    let many: Vec<String> = (0..33).map(|i| format!("C:\\P{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let f = findings(&serde_json::json!({"action": trust(&many), "object_types": ["installer"]}));
    assert_eq!(
        f,
        one(ErrorCode::InvalidActionOption, "/action/scope_paths")
    );
    let f = findings(&serde_json::json!({
        "action": trust(&["C:\\Apps", "relative\\path", "c:\\APPS\\"]), "object_types": ["installer"]
    }));
    assert_eq!(
        f,
        vec![
            (
                ErrorCode::InvalidActionOption,
                "/action/scope_paths/1".to_owned()
            ),
            (
                ErrorCode::InvalidActionOption,
                "/action/scope_paths/2".to_owned()
            ),
        ]
    );
}

#[test]
fn scope_path_forms() {
    for ok in [
        "C:\\",
        "C:\\Program Files\\Vendor",
        "d:\\apps\\",
        "\\\\server\\share",
        "\\\\server\\share\\apps\\",
        "%PROGRAMFILES%",
        "%PROGRAMFILES%\\Tools",
        "%ProgramFiles%\\Tools\\",
        "%windir%",
        "%TMP%\\Installers",
    ] {
        assert_eq!(scope_path_problem(ok), None, "{ok}");
    }
    for bad in [
        "",
        "C:",
        "C:relative",
        "relative\\path",
        "\\rooted",
        "C:/Apps",
        "C:\\Apps\\*",
        "C:\\Apps\\?",
        "C:\\Apps\\..\\Windows",
        "C:\\Apps\\.\\x",
        "C:\\Apps\\\\x",
        "\\\\?\\C:\\Apps",
        "\\\\.\\C:\\Apps",
        "\\\\server",
        "\\\\server\\",
        "\\\\\\share",
        "%%\\x",
        "%UNCLOSED\\x",
        "%BAD NAME%\\x",
        "%TEMP%x",
        "%PROGRAMFILES(X86)%\\Tools",
        "%TYPO%\\Apps",
        "%()%",
        "%123%",
        "C:\\Apps\\%TEMP%",
        "C:\\100%\\x",
        "%PROGRAMFILES%\\%WINDIR%",
        "C:\\a<b",
        "C:\\a>b",
        "C:\\a\"b",
        "C:\\a|b",
        "C:\\Apps\u{0}",
        "C:\\Apps.",
        "C:\\Apps \\x",
        "C:\\Apps\\file.txt:stream",
        "\\\\server\\share.\\x",
        "C:\\\u{202e}exe.txt",
    ] {
        assert!(scope_path_problem(bad).is_some(), "{bad:?}");
    }
    assert!(scope_path_problem(&format!("C:\\{}", "a".repeat(1021))).is_none());
    assert!(scope_path_problem(&format!("C:\\{}", "a".repeat(1022))).is_some());
}

#[test]
fn ignore_always_warns_and_never_covers_executables_or_drivers() {
    let f = findings(&serde_json::json!({
        "action": {"type": "ignore"}, "object_types": ["library", "script.python"]
    }));
    assert_eq!(f, one(ErrorCode::ExclusionNeedsPermission, "/action"));
    assert_eq!(
        ErrorCode::ExclusionNeedsPermission.severity(),
        Severity::Warning
    );
    // Valid with the warning.
    assert!(
        doc(
            "mixed",
            false,
            &serde_json::json!({
                "action": {"type": "ignore"}, "object_types": ["library"]
            })
        )
        .validate()
        .is_ok()
    );
    let f = findings(&serde_json::json!({
        "action": {"type": "ignore"}, "object_types": ["executable"]
    }));
    assert_eq!(
        f,
        vec![
            (
                ErrorCode::ActionNotValidForObjectType,
                "/object_types/0".to_owned()
            ),
            (ErrorCode::ExclusionNeedsPermission, "/action".to_owned()),
        ]
    );
    // Every type includes executables.
    let f = findings(&serde_json::json!({"action": {"type": "ignore"}}));
    assert_eq!(
        f[0],
        (
            ErrorCode::ActionNotValidForObjectType,
            "/object_types".to_owned()
        )
    );
    // Only in a mixed set.
    let f = findings_in(
        "allowlist",
        false,
        &serde_json::json!({"action": {"type": "ignore"}, "object_types": ["library"]}),
    );
    assert_eq!(
        f[0],
        (
            ErrorCode::ActionNotValidInRuleSet,
            "/action/type".to_owned()
        )
    );
}

#[test]
fn rules_that_run_trust_or_exclude_need_an_identity() {
    let negation = serde_json::json!({"not": {"criterion": {
        "field": "path.extension", "operator": "equals", "values": ["exe"]
    }}});
    let sha1 = serde_json::json!({"criterion": {
        "field": "hash.sha1", "operator": "equals", "values": ["a".repeat(40)]
    }});
    for (action, types) in [
        (
            serde_json::json!({"type": "allow_contained", "profile_id": ID}),
            "executable",
        ),
        (elevated(), "executable"),
        (trust(&["C:\\A"]), "installer"),
        (serde_json::json!({"type": "ignore"}), "library"),
    ] {
        let rule = |m: &serde_json::Value| serde_json::json!({"action": action, "object_types": [types], "match": m});
        let f = findings(&rule(&negation));
        assert!(
            f.contains(&(ErrorCode::NoIdentityAnchor, "/match".to_owned())),
            "{action}: {f:?}"
        );
        let f = findings(&rule(&sha1));
        assert!(
            f.contains(&(ErrorCode::WeakHashOnlyAllow, "/match".to_owned())),
            "{action}: {f:?}"
        );
    }
    // Deny, audit and defer may match on a weak hash, and a negation alone
    // only gets the general negation check (#32), not the anchor rule.
    for action in ["deny", "audit", "defer"] {
        let f = findings(&serde_json::json!({"action": {"type": action}, "match": sha1}));
        assert!(f.is_empty(), "{action}: {f:?}");
        let f = findings(&serde_json::json!({"action": {"type": action}, "match": negation}));
        assert_eq!(f, one(ErrorCode::NegationOnly, "/match"), "{action}");
    }
}

#[test]
fn deny_audit_elevation_and_trust_need_an_event_per_decision() {
    for (action, types) in [
        (serde_json::json!({"type": "deny"}), serde_json::json!([])),
        (serde_json::json!({"type": "audit"}), serde_json::json!([])),
        (elevated(), serde_json::json!(["executable"])),
        (trust(&["C:\\Apps"]), serde_json::json!(["installer"])),
    ] {
        for log in ["never", "summary"] {
            let f = findings(&serde_json::json!({
                "action": action, "object_types": types, "effects": {"log": log}
            }));
            assert_eq!(
                f,
                one(ErrorCode::LogLevelNotAllowed, "/effects/log"),
                "{action} {log}"
            );
        }
        for log in ["always", "sampled"] {
            let f = findings(&serde_json::json!({
                "action": action, "object_types": types, "effects": {"log": log}
            }));
            assert!(f.is_empty(), "{action} {log}: {f:?}");
        }
    }
    // Allow may log nothing.
    let f =
        findings(&serde_json::json!({"action": {"type": "allow"}, "effects": {"log": "never"}}));
    assert!(f.is_empty(), "{f:?}");
}

#[test]
fn notifications_are_consistent() {
    let rule = |effects: serde_json::Value| {
        findings(&serde_json::json!({"action": {"type": "deny"}, "effects": effects}))
    };
    assert_eq!(
        rule(serde_json::json!({"notify": "custom"})),
        one(ErrorCode::InvalidNotification, "/effects/notify")
    );
    assert_eq!(
        rule(serde_json::json!({"notification_text": "Blocked"})),
        one(ErrorCode::InvalidNotification, "/effects/notification_text")
    );
    assert_eq!(
        rule(serde_json::json!({"notify": "custom", "notification_text": "Hi {name}"})),
        one(ErrorCode::InvalidNotification, "/effects/notification_text")
    );
    assert_eq!(
        rule(serde_json::json!({"notify": "none", "help_url": "https://help.example"})),
        one(ErrorCode::InvalidNotification, "/effects/help_url")
    );
    assert_eq!(
        rule(serde_json::json!({"help_url": "http://help.example"})),
        one(ErrorCode::InvalidNotification, "/effects/help_url")
    );
    assert!(rule(serde_json::json!({
        "notify": "custom",
        "notification_text": "{file} ({hash}) by {publisher} was blocked for {user} by {rule}. {{literal}}",
        "help_url": "https://help.example/a?b=c#d"
    }))
    .is_empty());
    // An allow shows nothing by default, so a help URL needs `notify`.
    let f = findings(&serde_json::json!({
        "action": {"type": "allow"}, "effects": {"help_url": "https://help.example"}
    }));
    assert_eq!(f, one(ErrorCode::InvalidNotification, "/effects/help_url"));
}

#[test]
fn notification_text_forms() {
    for ok in [
        "Blocked.",
        "{file}",
        "{{}}",
        "Line one\nLine two\tTabbed",
        "{{file}} is literal",
        &"x".repeat(2048),
    ] {
        assert_eq!(notification_text_problem(ok), None, "{ok:?}");
    }
    for bad in [
        "",
        "   ",
        "{",
        "}",
        "{file",
        "{ file }",
        "{FILE}",
        "{unknown}",
        "{{file}",
        "{fi{le}",
        "a\u{7}b",
        "\u{202e}",
        &"x".repeat(2049),
    ] {
        assert!(notification_text_problem(bad).is_some(), "{bad:?}");
    }
}

#[test]
fn scope_paths_compare_as_the_engine_compares_paths() {
    for (a, b) in [
        ("C:\\Apps", "C:\\Apps\\"),
        ("C:\\Apps", "c:\\APPS"),
        ("%PROGRAMFILES%", "%programfiles%\\"),
        // Values are read in NFC, as a bundle stores them.
        ("C:\\Caf\u{e9}", "C:\\Cafe\u{301}"),
        // The upcase table folds these (#399).
        ("C:\\\u{e9}", "C:\\\u{c9}"),
        ("C:\\\u{1f80}", "C:\\\u{1f88}"),
        // `TMP` is another name for `TEMP`.
        ("%TMP%\\Installers", "%temp%\\installers\\"),
    ] {
        assert_eq!(scope_path_key(a), scope_path_key(b), "{a} / {b}");
    }
    for (a, b) in [
        ("C:\\", "C:"),
        ("C:\\Apps", "C:\\Apps2"),
        // Sharp s has no single-character upper case, so it is kept.
        ("C:\\\u{df}", "C:\\\u{1e9e}"),
        // NTFS keeps the dotless i and the long s apart from ASCII (#399).
        ("C:\\a\u{131}", "C:\\aI"),
        ("C:\\\u{17f}etup", "C:\\SETUP"),
    ] {
        assert_ne!(scope_path_key(a), scope_path_key(b), "{a} / {b}");
    }
    // A drive root keeps its `\`.
    assert_eq!(scope_path_key("C:\\"), "C:\\");
}

#[test]
fn help_url_forms() {
    for ok in [
        "https://h",
        "https://help.example:8443/a/b?c=d#e",
        "https://xn--bcher-kva.example/",
        "https://help.example./",
        "https://[2001:db8::1]/",
        "https://[2001:db8::1]:443/x",
        "https://[::1]/",
        "https://[::ffff:192.0.2.1]/",
        "https://h:1",
        "https://h:65535",
    ] {
        assert_eq!(help_url_problem(ok), None, "{ok}");
    }
    for bad in [
        "http://help.example",
        "https://",
        "https:///path",
        "https://:443/",
        "https://user@help.example/",
        "https://user:pw@help.example/",
        "https://help.example/a b",
        "https://h\u{e9}lp.example/",
        "javascript:alert(1)",
        "HTTPS://help.example",
        "https://\\",
        "https://\\evil.example",
        "https://a.example\\b",
        "https://\"",
        "https://<script>",
        "https://h/a{b}",
        "https://h/a|b",
        "https://h/a^b",
        "https://h/a`b",
        "https://[]/",
        "https://[evil.example]/",
        "https://[:]/",
        "https://[:::]/",
        "https://[...:]/",
        "https://[1:2]/",
        "https://[12345::1]/",
        "https://[::ffff:999.999.999.999]/",
        "https://[2001:db8::1/",
        "https://[2001:db8::1]x/",
        "https://host:notaport/",
        "https://host:/",
        "https://host:0/",
        "https://host:65536/",
        "https://host:1:2/",
        "https://-host/",
        "https://host-/",
        "https://a..b/",
        "https://under_score/",
    ] {
        assert!(help_url_problem(bad).is_some(), "{bad}");
    }
    assert!(help_url_problem(&format!("https://h/{}", "a".repeat(2038))).is_none());
    assert!(help_url_problem(&format!("https://h/{}", "a".repeat(2039))).is_some());
}

#[test]
fn effect_tags_and_window_are_checked() {
    let rule = |effects: serde_json::Value| {
        findings(&serde_json::json!({"action": {"type": "deny"}, "effects": effects}))
    };
    assert_eq!(
        rule(serde_json::json!({"tags": ["lolbin", "lolbin"]})),
        one(ErrorCode::InvalidTag, "/effects/tags/1")
    );
    assert_eq!(
        rule(serde_json::json!({"tags": [" padded"]})),
        one(ErrorCode::InvalidTag, "/effects/tags/0")
    );
    let many: Vec<String> = (0..65).map(|i| format!("t{i}")).collect();
    assert_eq!(
        rule(serde_json::json!({"tags": many})),
        one(ErrorCode::InvalidTag, "/effects/tags")
    );
    assert_eq!(
        rule(serde_json::json!({"suppress_duplicates_secs": 604_801})),
        one(
            ErrorCode::InvalidEffect,
            "/effects/suppress_duplicates_secs"
        )
    );
    assert!(rule(serde_json::json!({
        "suppress_duplicates_secs": 0, "tags": ["mitre:T1218.005"], "severity": "critical", "upload": "local_only"
    }))
    .is_empty());
}

#[test]
fn ignore_and_defer_have_no_effects() {
    let f = findings(&serde_json::json!({
        "action": {"type": "defer"}, "effects": {"severity": "high"}
    }));
    assert_eq!(f, one(ErrorCode::EffectsNotApplicable, "/effects"));
    let f = findings(&serde_json::json!({
        "action": {"type": "ignore"}, "object_types": ["library"], "effects": {"tags": ["x"]}
    }));
    assert!(
        f.contains(&(ErrorCode::EffectsNotApplicable, "/effects".to_owned())),
        "{f:?}"
    );
}

#[test]
fn every_rule_set_kind_accepts_an_action_of_its_own() {
    // A sanity check on the matrix: every kind accepts some action besides
    // `audit` and `defer`, which fit everywhere.
    use crate::model::ActionKind;
    for kind in [
        RuleSetKind::Allowlist,
        RuleSetKind::Blocklist,
        RuleSetKind::Baseline,
        RuleSetKind::Trust,
        RuleSetKind::Elevation,
        RuleSetKind::Containment,
        RuleSetKind::Mixed,
    ] {
        assert!(
            ActionKind::ALL
                .into_iter()
                .filter(|a| !matches!(a, ActionKind::Audit | ActionKind::Defer))
                .any(|a| a.valid_in_rule_set(kind)),
            "{kind:?}"
        );
    }
}
