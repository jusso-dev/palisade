//! Validation of where a policy sets its modes (#36).

use super::{ErrorCode, Validator, serde_name};
use crate::mode::strictness;
use crate::model::mode::limits::{DISCONNECTED_AFTER_MAX, DISCONNECTED_AFTER_MIN};
use crate::model::{Action, EnforcementOverride, Mode, PolicyDocument, RuleSetKind};

impl Validator {
    pub(super) fn modes(&mut self, doc: &PolicyDocument) {
        let policy = &doc.policy;
        let o = &policy.mode_options;
        if policy.mode == Mode::Disabled {
            self.push(
                ErrorCode::ModeNotAllowed,
                "/policy/mode",
                "a policy cannot be `disabled`: only a device can, with a reason and an expiry",
            );
        }
        for (t, mode) in &o.mode_by_type {
            if *mode == Mode::Disabled {
                self.push(
                    ErrorCode::ModeNotAllowed,
                    &format!("/policy/mode_options/mode_by_type/{t}"),
                    "an object type cannot be `disabled`; set its control level to `off` instead",
                );
            }
        }
        if let Some(offline) = o.mode_disconnected {
            // The same mode, or a stricter one: an equally strict other
            // mode (`learning` for `audit`) would never apply.
            if offline == Mode::Disabled
                || (offline != policy.mode && strictness(offline) <= strictness(policy.mode))
            {
                self.push(
                    ErrorCode::ModeDisconnectedWeaker,
                    "/policy/mode_options/mode_disconnected",
                    format!(
                        "`{}` is not stricter than the policy's mode `{}`; a disconnected device must be as strict or stricter",
                        serde_name(&offline),
                        serde_name(&policy.mode)
                    ),
                );
            }
        }
        if let Some(secs) = o.disconnected_after_secs {
            let poll = policy.settings.poll_interval_secs;
            let min = DISCONNECTED_AFTER_MIN.max(poll);
            if !(min..=DISCONNECTED_AFTER_MAX).contains(&secs) {
                self.push(
                    ErrorCode::SettingOutOfRange,
                    "/policy/mode_options/disconnected_after_secs",
                    format!(
                        "{secs} is outside {min}..={DISCONNECTED_AFTER_MAX}; it must be at least the check-in interval"
                    ),
                );
            }
        }
        for (i, set) in doc.rule_sets.iter().enumerate() {
            for (j, rule) in set.rules.iter().enumerate() {
                if rule.enforcement_override != EnforcementOverride::Inherit
                    && !matches!(rule.action, Action::Deny(_))
                {
                    self.push(
                        ErrorCode::EnforcementOverrideNotDeny,
                        &format!("/rule_sets/{i}/rules/{j}/enforcement_override"),
                        "only a deny rule blocks, so only a deny rule can be enforced or relaxed",
                    );
                }
            }
            let Some(mode) = set.mode_override else {
                continue;
            };
            let path = format!("/rule_sets/{i}/mode_override");
            if set.kind != RuleSetKind::Blocklist || set.mandatory {
                self.push(
                    ErrorCode::ModeOverrideNotAllowed,
                    &path,
                    "only a blocklist that is not mandatory can set its own mode; a mandatory blocklist blocks in every mode (ADR 0004)",
                );
            } else if mode == Mode::Disabled {
                self.push(
                    ErrorCode::ModeNotAllowed,
                    &path,
                    "a rule set cannot be `disabled`; leave it out of the policy instead",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{Mode, ObjectType, PolicyDocument, RuleSetKind};
    use crate::validate::ErrorCode;

    fn doc(mode: Mode) -> PolicyDocument {
        let json = serde_json::json!({
            "schema_version": "1.0.0",
            "policy": {
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e5f",
                "name": "Modes",
                "revision": 1,
                "mode": mode,
                "rule_sets": ["01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"],
            },
            "rule_sets": [{
                "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60",
                "name": "Blocklist",
                "kind": "blocklist",
            }],
        });
        PolicyDocument::from_json(&json.to_string()).unwrap()
    }

    fn codes(doc: PolicyDocument) -> Vec<(ErrorCode, String)> {
        match doc.validate() {
            Ok(_) => Vec::new(),
            Err(e) => e.into_iter().map(|f| (f.code, f.path)).collect(),
        }
    }

    #[test]
    fn mode_disconnected_is_the_same_or_stricter() {
        const ENABLED: [Mode; 4] = [Mode::Monitor, Mode::Audit, Mode::Learning, Mode::Enforce];
        for mode in ENABLED {
            for offline in [
                Mode::Disabled,
                Mode::Monitor,
                Mode::Audit,
                Mode::Learning,
                Mode::Enforce,
            ] {
                let mut d = doc(mode);
                d.policy.mode_options.mode_disconnected = Some(offline);
                let ok = offline == mode
                    || crate::mode::strictness(offline) > crate::mode::strictness(mode);
                let expected = if ok {
                    Vec::new()
                } else {
                    vec![(
                        ErrorCode::ModeDisconnectedWeaker,
                        "/policy/mode_options/mode_disconnected".to_owned(),
                    )]
                };
                assert_eq!(codes(d), expected, "{mode:?} offline {offline:?}");
            }
        }
    }

    #[test]
    fn disconnected_after_is_at_least_the_check_in_interval() {
        for (secs, poll, ok) in [
            (60, 60, true),
            (59, 60, false),
            (899, 900, false),
            (900, 900, true),
            (2_592_000, 900, true),
            (2_592_001, 900, false),
        ] {
            let mut d = doc(Mode::Enforce);
            d.policy.settings.poll_interval_secs = poll;
            d.policy.mode_options.disconnected_after_secs = Some(secs);
            assert_eq!(codes(d).is_empty(), ok, "{secs} with {poll}");
        }
    }

    #[test]
    fn only_an_ordinary_blocklist_may_set_its_mode() {
        let mut d = doc(Mode::Enforce);
        d.rule_sets[0].mode_override = Some(Mode::Audit);
        assert!(codes(d.clone()).is_empty());
        d.rule_sets[0].mandatory = true;
        assert_eq!(
            codes(d.clone()),
            [(
                ErrorCode::ModeOverrideNotAllowed,
                "/rule_sets/0/mode_override".to_owned()
            )]
        );
        d.rule_sets[0].mandatory = false;
        d.rule_sets[0].kind = RuleSetKind::Allowlist;
        assert_eq!(codes(d).len(), 1);
    }

    #[test]
    fn enforcement_override_is_only_for_denies() {
        let rule = |action: serde_json::Value, enforcement: &str| {
            let mut d = doc(Mode::Audit);
            d.rule_sets[0].kind = RuleSetKind::Mixed;
            d.rule_sets[0].rules = vec![
                serde_json::from_value(serde_json::json!({
                    "id": "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61",
                    "name": "Rule",
                    "match": {"criterion": {
                        "field": "hash.sha256", "operator": "equals", "values": ["a".repeat(64)]
                    }},
                    "action": action,
                    "enforcement_override": enforcement,
                }))
                .unwrap(),
            ];
            codes(d)
        };
        let finding = [(
            ErrorCode::EnforcementOverrideNotDeny,
            "/rule_sets/0/rules/0/enforcement_override".to_owned(),
        )];
        for enforcement in ["always_enforce", "never_enforce"] {
            assert!(rule(serde_json::json!({"type": "deny"}), enforcement).is_empty());
            for action in ["allow", "audit"] {
                assert_eq!(
                    rule(serde_json::json!({"type": action}), enforcement),
                    finding,
                    "{action} {enforcement}"
                );
            }
        }
        assert!(rule(serde_json::json!({"type": "allow"}), "inherit").is_empty());
    }

    #[test]
    fn a_disabled_offline_mode_is_reported_even_with_a_disabled_policy() {
        let mut d = doc(Mode::Disabled);
        d.policy.mode_options.mode_disconnected = Some(Mode::Disabled);
        assert_eq!(codes(d).len(), 2);
    }

    #[test]
    fn disabled_is_only_for_a_device() {
        assert_eq!(
            codes(doc(Mode::Disabled)),
            [(ErrorCode::ModeNotAllowed, "/policy/mode".to_owned())]
        );
        let mut d = doc(Mode::Enforce);
        d.policy
            .mode_options
            .mode_by_type
            .insert(ObjectType::Library, Mode::Disabled);
        assert_eq!(
            codes(d),
            [(
                ErrorCode::ModeNotAllowed,
                "/policy/mode_options/mode_by_type/library".to_owned()
            )]
        );
    }
}
