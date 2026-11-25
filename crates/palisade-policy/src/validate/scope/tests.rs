//! Validation of scopes (#38).

use crate::model::PolicyDocument;
use crate::validate::{ErrorCode, ValidationError};

const SET: &str = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60";

fn rule(action: serde_json::Value, scope: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
        "name": "Rule",
        "match": {"criterion": {"field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]}},
        "action": action,
        "scope": scope,
    })
}

fn doc(rules: Vec<serde_json::Value>, policy_extra: serde_json::Value) -> PolicyDocument {
    let mut json = serde_json::json!({
        "schema_version": "1.0.0",
        "policy": {
            "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
            "name": "Scopes",
            "revision": 1,
            "mode": "enforce",
            "rule_sets": [SET]
        },
        "rule_sets": [{"id": SET, "name": "Set", "kind": "mixed", "rules": rules}]
    });
    for (k, v) in policy_extra.as_object().unwrap() {
        json["policy"][k] = v.clone();
    }
    PolicyDocument::from_json(&json.to_string()).unwrap()
}

fn codes(doc: PolicyDocument) -> Vec<(ErrorCode, String)> {
    match doc.validate() {
        Ok(v) => v
            .warnings()
            .iter()
            .map(|e: &ValidationError| (e.code, e.path.clone()))
            .collect(),
        Err(e) => e.into_iter().map(|e| (e.code, e.path)).collect(),
    }
}

fn pattern(list: &str, negate: bool) -> serde_json::Value {
    serde_json::json!({
        "principals": {list: [{"user_pattern": "*\\svc_*"}]},
        "negate": negate,
    })
}

#[test]
fn user_patterns_never_widen_a_permit_or_narrow_a_deny() {
    let at = |list: &str| format!("/rule_sets/0/rules/0/scope/principals/{list}/0");
    let bad = |list: &str| vec![(ErrorCode::UserPatternNotAllowed, at(list))];
    let actions = [
        ("allow", serde_json::json!({"type": "allow"})),
        ("deny", serde_json::json!({"type": "deny"})),
        ("audit", serde_json::json!({"type": "audit"})),
    ];
    // (action, list, negate, rejected?)
    let cases = [
        ("allow", "include", false, true),
        ("allow", "exclude", false, false),
        ("allow", "include", true, false),
        ("allow", "exclude", true, true),
        ("deny", "include", false, false),
        ("deny", "exclude", false, true),
        ("deny", "include", true, true),
        ("deny", "exclude", true, false),
        ("audit", "include", false, false),
        ("audit", "exclude", true, false),
    ];
    for (name, list, negate, rejected) in cases {
        let action = actions.iter().find(|a| a.0 == name).unwrap().1.clone();
        let found = codes(doc(
            vec![rule(action, pattern(list, negate))],
            serde_json::json!({}),
        ));
        let expected = if rejected { bad(list) } else { vec![] };
        assert_eq!(found, expected, "{name} {list} negate={negate}");
    }
}

#[test]
fn assignment_and_policy_scopes_check_every_rule_they_cover() {
    let allow = rule(serde_json::json!({"type": "allow"}), serde_json::json!({}));
    let found = codes(doc(
        vec![allow.clone()],
        serde_json::json!({
            "scope": pattern("include", false),
            "rule_set_scopes": [{"rule_set": SET, "scopes": [pattern("include", false)]}]
        }),
    ));
    assert_eq!(
        found,
        vec![
            (
                ErrorCode::UserPatternNotAllowed,
                "/policy/scope/principals/include/0".to_owned()
            ),
            (
                ErrorCode::UserPatternNotAllowed,
                "/policy/rule_set_scopes/0/scopes/0/principals/include/0".to_owned()
            ),
        ]
    );
    // Over an empty set, the scope is read as covering allows: a name
    // pattern cannot include principals, but the per-session options are
    // valid, as they will be once allows are added.
    let found = codes(doc(
        vec![],
        serde_json::json!({"scope": pattern("include", false)}),
    ));
    assert_eq!(
        found,
        vec![(
            ErrorCode::UserPatternNotAllowed,
            "/policy/scope/principals/include/0".to_owned()
        )]
    );
    let found = codes(doc(
        vec![],
        serde_json::json!({"scope": {"max_instances_per_session": 2}}),
    ));
    assert!(found.is_empty(), "{found:?}");
    // Disabled rules count: a policy scope over a disabled allow still may
    // not include a name pattern, and may still limit instances.
    let mut disabled = allow.clone();
    disabled["enabled"] = false.into();
    let found = codes(doc(
        vec![disabled.clone()],
        serde_json::json!({"scope": pattern("include", false)}),
    ));
    assert_eq!(found.len(), 1, "{found:?}");
    let found = codes(doc(
        vec![disabled],
        serde_json::json!({"rule_set_scopes": [{"rule_set": SET, "scopes": [{"max_instances_per_session": 2}]}]}),
    ));
    assert!(found.is_empty(), "{found:?}");
    // Two assignments of one set, and an empty `scopes`.
    let found = codes(doc(
        vec![allow],
        serde_json::json!({"rule_set_scopes": [
            {"rule_set": SET, "scopes": [{}]},
            {"rule_set": SET, "scopes": []}
        ]}),
    ));
    assert_eq!(
        found,
        vec![
            (
                ErrorCode::DuplicateRuleSetRef,
                "/policy/rule_set_scopes/1/rule_set".to_owned()
            ),
            (
                ErrorCode::InvalidScope,
                "/policy/rule_set_scopes/1/scopes".to_owned()
            ),
        ]
    );
}

#[test]
fn lists_over_the_limit_need_a_library_set() {
    let entries: Vec<serde_json::Value> = (0..1001)
        .map(|i| serde_json::json!({"tag": format!("t{i}")}))
        .collect();
    let scope = serde_json::json!({"devices": {"exclude": entries}});
    let found = codes(doc(
        vec![rule(serde_json::json!({"type": "deny"}), scope)],
        serde_json::json!({}),
    ));
    assert_eq!(
        found,
        vec![(
            ErrorCode::InvalidScope,
            "/rule_sets/0/rules/0/scope/devices/exclude".to_owned()
        )]
    );
    let entries: Vec<serde_json::Value> = (0..1000)
        .map(|i| serde_json::json!({"tag": format!("t{i}")}))
        .collect();
    let scope = serde_json::json!({"devices": {"exclude": entries}});
    assert!(
        codes(doc(
            vec![rule(serde_json::json!({"type": "deny"}), scope)],
            serde_json::json!({})
        ))
        .is_empty()
    );
}

#[test]
fn values_are_checked_per_kind() {
    let scope = serde_json::json!({
        "principals": {"include": [
            {"sid": "S-1-5-x"},
            {"cloud_group": {"tenant_id": "nope", "object_id": "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e"}},
            {"local_group": " Users"},
            {"directory_group": {"sid": "S-1-5-21-1-2-3-1105", "name": "Finance"}}
        ]},
        "devices": {"include": [
            {"ou": {"dn": "Finance"}},
            {"ou": {"dn": "OU=Fin\u{202e}ance,DC=corp,DC=example"}},
            {"ou": {"dn": " OU=Finance,DC=corp"}},
            {"hostname_pattern": ""},
            {"directory_computer_group": "S-1-5-21-1-2-3-4001"}
        ]},
        "network": {"include": [
            {"range": "10.0.0.9-10.0.0.1"},
            {"gateway_mac": "00-11-22"},
            {"dns_suffix": "corp..example"},
            {"cidr": "2001:db8::/32"}
        ]},
        "sessions": {"types": ["rdp", "rdp"], "client": {"ip": ["10.0.0.0/33"], "hostname": ["THIN-*"]}}
    });
    let found: Vec<String> = codes(doc(
        vec![rule(serde_json::json!({"type": "deny"}), scope)],
        serde_json::json!({}),
    ))
    .into_iter()
    .map(|(c, p)| {
        format!(
            "{} {}",
            c.as_str(),
            p.trim_start_matches("/rule_sets/0/rules/0/scope/")
        )
    })
    .collect();
    assert_eq!(
        found,
        [
            "invalid_scope principals/include/0",
            "invalid_scope principals/include/1",
            "invalid_scope principals/include/2",
            "invalid_scope devices/include/0",
            "invalid_scope devices/include/1",
            "invalid_scope devices/include/2",
            "invalid_scope devices/include/3",
            "invalid_scope network/include/0",
            "invalid_scope network/include/1",
            "invalid_scope network/include/2",
            "invalid_scope sessions/types/1",
            "invalid_scope sessions/client/ip/0",
        ]
    );
}

#[test]
fn schedules_and_options_are_checked() {
    let scope = serde_json::json!({
        "schedule": {
            "windows": [
                {"days": [], "start": "09:00", "end": "17:00"},
                {"days": ["mon"], "start": "24:00", "duration_mins": 60},
                {"days": ["mon"], "start": "09:00"},
                {"days": ["mon"], "start": "09:00", "duration_mins": 10081}
            ],
            "dates": [{"from": "2026-02-01", "to": "2026-01-01"}],
            "grace_secs": 60
        },
        "schedule_set": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e72"}
    });
    let found: Vec<String> = codes(doc(
        vec![rule(serde_json::json!({"type": "allow"}), scope)],
        serde_json::json!({}),
    ))
    .into_iter()
    .map(|(c, p)| {
        format!(
            "{} {}",
            c.as_str(),
            p.trim_start_matches("/rule_sets/0/rules/0/scope/")
        )
    })
    .collect();
    assert_eq!(
        found,
        [
            "invalid_scope schedule_set",
            "invalid_schedule schedule/windows/0/days",
            "invalid_schedule schedule/windows/1/start",
            "invalid_schedule schedule/windows/2",
            "invalid_schedule schedule/windows/3",
            "invalid_schedule schedule/dates/0/to",
            "invalid_schedule schedule/grace_secs",
        ]
    );
}

#[test]
fn window_close_needs_a_schedule_that_ends_the_match() {
    for extra in [
        serde_json::json!({"negate": true}),
        serde_json::json!({"combine": "any", "principals": {"include": [{"sid": "S-1-5-32-544"}]}}),
    ] {
        let mut scope = serde_json::json!({"schedule": {
            "windows": [{"days": ["mon"], "start": "09:00", "end": "17:00"}],
            "on_window_close": "warn"
        }});
        for (k, v) in extra.as_object().unwrap() {
            scope[k] = v.clone();
        }
        let found = codes(doc(
            vec![rule(serde_json::json!({"type": "allow"}), scope)],
            serde_json::json!({}),
        ));
        assert_eq!(
            found,
            vec![(
                ErrorCode::InvalidSchedule,
                "/rule_sets/0/rules/0/scope/schedule/on_window_close".to_owned()
            )],
            "{extra}"
        );
    }
}

#[test]
fn directory_group_names_follow_the_schema() {
    let named = |name: String| {
        serde_json::json!({"principals": {"include": [{"directory_group": {
            "sid": "S-1-5-21-1-2-3-1105", "name": name
        }}]}})
    };
    let ok = codes(doc(
        vec![rule(
            serde_json::json!({"type": "deny"}),
            named("é".repeat(128)),
        )],
        serde_json::json!({}),
    ));
    assert!(ok.is_empty(), "{ok:?}");
    for bad in ["x".repeat(129), "Fin\u{202e}ance".to_owned()] {
        let found = codes(doc(
            vec![rule(serde_json::json!({"type": "deny"}), named(bad))],
            serde_json::json!({}),
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, ErrorCode::InvalidScope);
    }
}

#[test]
fn location_profiles_are_checked() {
    let found = codes(doc(
        vec![rule(
            serde_json::json!({"type": "deny"}),
            serde_json::json!({"network": {"include": [{"location_profile": "CORP"}]}}),
        )],
        serde_json::json!({"location_profiles": [
            {"name": "corp", "all": [{"server_reachable": true}]},
            {"name": "Corp", "all": [{"location_profile": "corp"}]},
            {"name": "bad name", "all": []}
        ]}),
    ));
    assert_eq!(
        found,
        vec![
            (
                ErrorCode::DuplicateId,
                "/policy/location_profiles/1/name".to_owned()
            ),
            (
                ErrorCode::InvalidScope,
                "/policy/location_profiles/1/all/0".to_owned()
            ),
            (
                ErrorCode::InvalidScope,
                "/policy/location_profiles/2/name".to_owned()
            ),
            (
                ErrorCode::InvalidScope,
                "/policy/location_profiles/2/all".to_owned()
            ),
        ]
    );
}

#[test]
fn per_session_options_only_on_allows_and_negate_needs_a_dimension() {
    let found = codes(doc(
        vec![rule(
            serde_json::json!({"type": "trust_source", "mode": "direct", "scope_paths": ["C:\\Apps"]}),
            serde_json::json!({"max_instances_per_session": 3, "negate": true}),
        )],
        serde_json::json!({}),
    ));
    assert!(found.contains(&(
        ErrorCode::InvalidScope,
        "/rule_sets/0/rules/0/scope/max_instances_per_session".to_owned()
    )));
    assert!(found.contains(&(
        ErrorCode::InvalidScope,
        "/rule_sets/0/rules/0/scope/negate".to_owned()
    )));
}

#[test]
fn the_group_cache_age_is_in_range() {
    for (secs, ok) in [(3599, false), (3600, true), (86_400, true), (86_401, false)] {
        let found = codes(doc(
            vec![],
            serde_json::json!({"settings": {"group_cache_max_age_secs": secs}}),
        ));
        assert_eq!(found.is_empty(), ok, "{secs}: {found:?}");
    }
}

#[test]
fn pins_and_set_refs_read_strictly() {
    let with_pin = |pin: serde_json::Value| {
        let json = serde_json::json!({"principal_set": {"id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e70", "pin": pin}});
        serde_json::from_value::<crate::scope::PrincipalRef>(json)
    };
    assert!(with_pin("latest".into()).is_ok());
    assert!(with_pin(3.into()).is_ok());
    for bad in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!("v3"),
        serde_json::json!(1.5),
    ] {
        assert!(with_pin(bad.clone()).is_err(), "{bad}");
    }
    let r = with_pin(7.into()).unwrap();
    assert_eq!(
        serde_json::to_value(&r).unwrap()["principal_set"]["pin"],
        serde_json::json!(7)
    );
}
