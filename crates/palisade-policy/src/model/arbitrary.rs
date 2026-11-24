//! `proptest` strategies for the model.
//!
//! [`document`] produces documents that pass validation: every reference
//! resolves, IDs are unique, and every value fits its field. Tests that want
//! invalid input mutate one of these.

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

use super::{
    Action, AdvancedValue, ControlLevel, Criterion, EnforcementOverride, Field, Match, Metadata,
    Mode, ObjectType, Os, Policy, PolicyDocument, PolicySettings, PrecedenceModel, Rule, RuleSet,
    RuleSetKind, ScriptKind, TimeZoneBasis,
};
use super::{FieldClass, Operator, PolicyId, RuleId, RuleSetId};
use crate::schema::CURRENT;
use palisade_core::Uuid7;

/// Any valid UUIDv7.
pub fn uuid7() -> impl Strategy<Value = Uuid7> {
    any::<[u8; 16]>().prop_map(|mut b| {
        b[6] = (b[6] & 0x0f) | 0x70;
        b[8] = (b[8] & 0x3f) | 0x80;
        match Uuid7::from_bytes(b) {
            Some(id) => id,
            None => unreachable!("version and variant bits were just set"),
        }
    })
}

/// A valid name: printable, trimmed, 1 to 40 characters, including non-ASCII.
pub fn name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9\u{e9}\u{4e2d}\u{1F6E1}][A-Za-z0-9 _./\u{e9}\u{4e2d}-]{0,38}[A-Za-z0-9]?"
        .prop_filter("trimmed", |s| s.trim() == s)
}

fn text() -> impl Strategy<Value = Option<String>> {
    proptest::option::of("[ -~\n\t\u{e9}]{0,80}")
}

fn metadata() -> impl Strategy<Value = Metadata> {
    (
        text(),
        proptest::option::of("[A-Z]{2,5}-[0-9]{1,6}"),
        proptest::collection::btree_set("[a-z][a-z0-9:._-]{0,20}", 0..4),
        text(),
    )
        .prop_map(|(justification, ticket_ref, tags, comment)| Metadata {
            justification,
            ticket_ref,
            tags: tags.into_iter().collect(),
            comment,
        })
}

/// SIDs in every accepted spelling: either case of `S`, a decimal
/// authority with leading zeros or a 48-bit hex one of 2^32 or more, and
/// sub-authorities of up to 10 digits with leading zeros.
const SID: &str = "[sS]-1-(0{0,2}5|0[xX]0001[0-9a-fA-F]{8})(-0{0,2}[1-3]?[0-9]{1,9}){1,5}";

fn value_for(class: FieldClass, operator: Operator) -> BoxedStrategy<String> {
    match (class, operator) {
        (FieldClass::Hash { hex_len }, _) => vec(
            proptest::sample::select(b"0123456789abcdef".to_vec()),
            hex_len,
        )
        .prop_map(|b| b.into_iter().map(char::from).collect())
        .boxed(),
        (FieldClass::Version, _) => "[0-9]{1,4}(\\.[0-9]{1,4}){0,3}".boxed(),
        (FieldClass::Sid, _) => SID.boxed(),
        (FieldClass::PrincipalSet, _) => prop_oneof![
            SID,
            "[0-9a-fA-F]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ]
        .boxed(),
        (FieldClass::TagSet, _) => "[a-z][a-z0-9:._-]{0,20}".boxed(),
        (FieldClass::SessionType, _) => proptest::sample::select(
            crate::context::SessionType::ALL
                .iter()
                .map(|t| t.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
        .boxed(),
        // Never used: yes-or-no operators take no values.
        (FieldClass::Bool, _) => Just(String::new()).boxed(),
        (FieldClass::PrincipalName, _) => "[A-Z]{1,8}\\\\[a-z0-9.]{1,12}".boxed(),
        // Simple patterns that are always valid regular expressions.
        (_, Operator::Regex | Operator::NotRegex) => {
            "[A-Za-z0-9]{1,10}(\\.\\*|\\+)?[A-Za-z0-9]{0,10}".boxed()
        }
        (FieldClass::Path, Operator::Wildcard | Operator::NotWildcard) => {
            "[A-Za-z]:\\\\[A-Za-z0-9 _\\\\*?.-]{1,40}".boxed()
        }
        // Only these operators expand path variables.
        (FieldClass::Path, Operator::Equals | Operator::NotEquals | Operator::StartsWith) => {
            prop_oneof![
                "[A-Za-z]:\\\\[A-Za-z0-9 _\\\\.-]{1,40}",
                "%(PROGRAMFILES|WINDIR|TEMP)%(\\\\[A-Za-z0-9 _-]{1,20}){0,3}",
            ]
            .boxed()
        }
        (FieldClass::Path, _) => "[A-Za-z]:\\\\[A-Za-z0-9 _\\\\.-]{1,40}".boxed(),
        (FieldClass::FileName, _) => "[A-Za-z0-9 _-]{1,30}(\\.[a-z]{1,4})?".boxed(),
        (FieldClass::Text, _) => "[A-Za-z0-9 ,.\u{e9}-]{1,40}".boxed(),
    }
}

/// A criterion whose operator and values are valid for its field.
pub fn criterion() -> impl Strategy<Value = Criterion> {
    proptest::sample::select(Field::ALL.to_vec()).prop_flat_map(|field| {
        let class = field.class();
        let operators: Vec<Operator> = Operator::ALL
            .iter()
            .copied()
            .filter(|op| op.applies_to(class))
            .collect();
        let case = if class.has_case() {
            proptest::option::of(any::<bool>()).boxed()
        } else {
            Just(None).boxed()
        };
        (proptest::sample::select(operators), case).prop_flat_map(move |(operator, case)| {
            let (min, max) = operator.value_count();
            vec(value_for(class, operator), min..=max.min(4)).prop_map(move |mut values| {
                if operator == Operator::VersionBetween {
                    values.sort_by_key(|v| crate::ops::Version::parse_strict(v));
                }
                Criterion {
                    field,
                    operator,
                    values,
                    case_sensitive: case,
                }
            })
        })
    })
}

/// A match tree within the depth and size limits.
///
/// The root is always `all` with a positive SHA-256 criterion first, so every
/// generated rule satisfies the identity-anchor and weak-hash checks whatever
/// its action.
pub fn tree() -> impl Strategy<Value = Match> {
    let leaf = criterion().prop_map(Match::Criterion);
    let inner = leaf.prop_recursive(3, 12, 3, |inner| {
        prop_oneof![
            vec(inner.clone(), 1..3).prop_map(Match::All),
            vec(inner.clone(), 1..3).prop_map(Match::Any),
            inner.prop_map(|m| Match::Not(Box::new(m))),
        ]
    });
    (
        value_for(FieldClass::Hash { hex_len: 64 }, Operator::Equals),
        vec(inner, 0..3),
    )
        .prop_map(|(hash, rest)| {
            let mut children = vec![Match::Criterion(Criterion {
                field: Field::HashSha256,
                operator: Operator::Equals,
                values: vec![hash],
                case_sensitive: None,
            })];
            children.extend(rest);
            Match::All(children)
        })
}

fn rule(kind: RuleSetKind, mandatory: bool) -> impl Strategy<Value = Rule> {
    // An action valid in the rule set, object types valid for it, and
    // effects valid for it (#34).
    let action = if mandatory {
        deny_options(false).prop_map(Action::Deny).boxed()
    } else {
        let valid: Vec<_> = super::ActionKind::ALL
            .into_iter()
            .filter(|a| a.valid_in_rule_set(kind))
            .collect();
        proptest::sample::select(valid)
            .prop_flat_map(action_strategy::action_of)
            .boxed()
    };
    let action_and_types = action.prop_flat_map(|action| {
        let k = action.kind();
        let kill = matches!(&action, Action::Deny(o) if o.kill_running);
        let valid: Vec<ObjectType> = ObjectType::ALL
            .into_iter()
            .filter(|t| k.valid_for_object_type(*t))
            .filter(|t| !kill || super::ActionKind::kill_running_valid_for(*t))
            .collect();
        // An empty list means every type, so it is only valid when every
        // type is.
        let min = usize::from(valid.len() < ObjectType::ALL.len());
        let effects = action_strategy::effects(&action);
        (
            Just(action),
            proptest::collection::btree_set(proptest::sample::select(valid), min..4),
            effects,
        )
    });
    (
        (
            uuid7(),
            proptest::option::of("R-[0-9]{6,12}"),
            name(),
            text(),
        ),
        (any::<bool>(), tree(), action_and_types),
        (
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<i32>()),
            if mandatory {
                // Mandatory rules always block (ADR 0004).
                prop_oneof![
                    Just(EnforcementOverride::Inherit),
                    Just(EnforcementOverride::AlwaysEnforce)
                ]
                .boxed()
            } else {
                prop_oneof![
                    Just(EnforcementOverride::Inherit),
                    Just(EnforcementOverride::AlwaysEnforce),
                    Just(EnforcementOverride::NeverEnforce)
                ]
                .boxed()
            },
            metadata(),
        ),
    )
        .prop_map(
            |(
                (id, display_id, name, description),
                (enabled, match_, (action, types, effects)),
                (order, priority, enforcement_override, metadata),
            )| Rule {
                id: RuleId(id),
                display_id,
                name,
                description,
                enabled,
                object_types: types.into_iter().collect(),
                match_,
                action,
                effects,
                order,
                priority,
                enforcement_override,
                metadata,
            },
        )
}

fn rule_set() -> impl Strategy<Value = RuleSet> {
    let kind = proptest::sample::select(vec![
        RuleSetKind::Allowlist,
        RuleSetKind::Blocklist,
        RuleSetKind::Baseline,
        RuleSetKind::Trust,
        RuleSetKind::Elevation,
        RuleSetKind::Containment,
        RuleSetKind::Mixed,
    ]);
    (kind, any::<bool>()).prop_flat_map(|(kind, mandatory_bit)| {
        let mandatory = mandatory_bit && kind == RuleSetKind::Blocklist;
        (
            (
                uuid7(),
                name(),
                text(),
                proptest::option::of("[0-9]{1,2}\\.[0-9]{1,2}"),
            ),
            (any::<bool>(), any::<bool>()),
            vec(rule(kind, mandatory), 0..4),
            metadata(),
        )
            .prop_map(
                move |((id, name, description, version), (read_only, hidden), rules, metadata)| {
                    RuleSet {
                        id: RuleSetId(id),
                        name,
                        description,
                        version,
                        kind,
                        mandatory,
                        os: Os::Windows,
                        read_only,
                        hidden,
                        rules,
                        metadata,
                    }
                },
            )
    })
}

fn control() -> impl Strategy<Value = ControlLevel> {
    prop_oneof![
        Just(ControlLevel::Off),
        Just(ControlLevel::Audit),
        Just(ControlLevel::Enforce)
    ]
}

fn settings() -> impl Strategy<Value = PolicySettings> {
    (
        (
            control(),
            btree_map(
                proptest::sample::select(ScriptKind::ALL.to_vec()),
                control(),
                0..3,
            ),
            control(),
            control(),
            any::<bool>(),
        ),
        (
            60u32..=604_800,
            0u32..=86_400,
            vec(0u32..=10_080, 0..=5),
            prop_oneof![Just(TimeZoneBasis::DeviceLocal), Just(TimeZoneBasis::Utc)],
            1u8..=16,
        ),
        btree_map(
            "[a-z][a-z0-9_.-]{0,20}",
            prop_oneof![
                any::<bool>().prop_map(AdvancedValue::Bool),
                any::<i64>().prop_map(AdvancedValue::Int),
                "[ -~]{0,20}".prop_map(AdvancedValue::Text),
            ],
            0..3,
        ),
    )
        .prop_map(
            |(
                (script_control, script_control_by_kind, dll_control, driver_control, capture),
                (poll, ttl, overrides, tz, depth),
                advanced,
            )| PolicySettings {
                script_control,
                script_control_by_kind,
                dll_control,
                driver_control,
                capture_command_line: capture,
                poll_interval_secs: poll,
                decision_cache_ttl_secs: ttl,
                override_durations: overrides,
                time_zone_basis: tz,
                max_ancestor_depth: depth,
                // Unknown keys are only valid with the opt-in.
                allow_unknown_advanced: !advanced.is_empty(),
                advanced,
            },
        )
}

/// A document that passes [`PolicyDocument::validate`].
pub fn document() -> impl Strategy<Value = PolicyDocument> {
    let mode = proptest::sample::select(vec![
        Mode::Disabled,
        Mode::Monitor,
        Mode::Audit,
        Mode::Learning,
        Mode::Enforce,
    ]);
    let model = proptest::sample::select(vec![
        PrecedenceModel::DenyWins,
        PrecedenceModel::Specificity,
        PrecedenceModel::FirstMatch,
        PrecedenceModel::Priority,
    ]);
    (
        (uuid7(), name(), text(), any::<u64>(), model, mode),
        settings(),
        vec(rule_set(), 0..4),
        metadata(),
    )
        .prop_map(
            |(
                (id, name, description, revision, precedence_model, mode),
                settings,
                sets,
                metadata,
            )| {
                let rule_sets = sets.iter().map(|s| s.id).collect();
                PolicyDocument {
                    schema_version: CURRENT,
                    policy: Policy {
                        id: PolicyId(id),
                        name,
                        description,
                        revision,
                        precedence_model,
                        mode,
                        settings,
                        rule_sets,
                        metadata,
                    },
                    rule_sets: sets,
                }
            },
        )
        // Random IDs collide with negligible probability; drop those cases
        // so every generated document is valid.
        .prop_filter("unique IDs", |doc| {
            let mut ids = std::collections::BTreeSet::new();
            doc.rule_sets.iter().all(|s| ids.insert(s.id.0))
                && doc
                    .rule_sets
                    .iter()
                    .flat_map(|s| &s.rules)
                    .all(|r| ids.insert(r.id.0))
        })
}

fn deny_options(allow_request: bool) -> impl Strategy<Value = super::DenyOptions> {
    (
        any::<bool>(),
        if allow_request {
            any::<bool>().boxed()
        } else {
            Just(false).boxed()
        },
        proptest::option::of(uuid7()),
    )
        .prop_map(
            |(kill_running, allow_request, template)| super::DenyOptions {
                kill_running,
                allow_request,
                request_template: template
                    .filter(|_| allow_request)
                    .map(super::RequestTemplateRef),
            },
        )
}

/// Strategies for actions and effect flags (#34).
pub mod action_strategy {
    use proptest::prelude::*;

    use super::super::{
        Action, ActionKind, ContainmentDirective, ContainmentProfileRef, Effects, ElevationAuth,
        ElevationCondition, ElevationDirective, EventSeverity, LogLevel, Notify, TokenProfileRef,
        TrustMode, TrustSourceDirective, Upload,
    };
    use super::{deny_options, uuid7};

    /// An action of this kind, with valid options.
    pub fn action_of(kind: ActionKind) -> BoxedStrategy<Action> {
        match kind {
            ActionKind::Allow => Just(Action::Allow {}).boxed(),
            ActionKind::Deny => deny_options(true).prop_map(Action::Deny).boxed(),
            ActionKind::Audit => Just(Action::Audit {}).boxed(),
            ActionKind::AllowContained => uuid7()
                .prop_map(|id| {
                    Action::AllowContained(ContainmentDirective {
                        profile_id: ContainmentProfileRef(id),
                    })
                })
                .boxed(),
            ActionKind::AllowElevated => (
                uuid7(),
                prop_oneof![
                    Just(ElevationCondition::Always),
                    Just(ElevationCondition::IfRequired)
                ],
                proptest::option::of("[A-Za-z0-9][A-Za-z0-9 ?.,\u{e9}-]{0,40}[A-Za-z0-9?]"),
                prop_oneof![
                    Just(ElevationAuth::None),
                    Just(ElevationAuth::Reauth),
                    Just(ElevationAuth::Mfa)
                ],
            )
                .prop_map(|(id, condition, reason_prompt, auth)| {
                    Action::AllowElevated(ElevationDirective {
                        token_profile: TokenProfileRef(id),
                        condition,
                        reason_prompt,
                        auth,
                    })
                })
                .boxed(),
            ActionKind::TrustSource => (
                prop_oneof![Just(TrustMode::Direct), Just(TrustMode::Chained)],
                proptest::collection::btree_set(scope_path(), 1..4),
                any::<bool>(),
            )
                .prop_map(|(mode, paths, tag_output)| {
                    Action::TrustSource(TrustSourceDirective {
                        mode,
                        // Unique without case, as validation requires.
                        scope_paths: dedup_ci(paths.into_iter().collect()),
                        tag_output,
                    })
                })
                .boxed(),
            ActionKind::Ignore => Just(Action::Ignore {}).boxed(),
            ActionKind::Defer => Just(Action::Defer {}).boxed(),
        }
    }

    fn dedup_ci(paths: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        paths
            .into_iter()
            .filter(|p| seen.insert(crate::validate::scope_path_key(p)))
            .collect()
    }

    /// A valid trust-source scope path.
    pub fn scope_path() -> impl Strategy<Value = String> {
        prop_oneof![
            "[A-Za-z]:\\\\([A-Za-z0-9_-]([A-Za-z0-9 _-]{0,10}[A-Za-z0-9_-])?\\\\){0,3}([A-Za-z0-9_-]([A-Za-z0-9 _-]{0,10}[A-Za-z0-9_-])?)?",
            "\\\\\\\\[a-z0-9-]{1,10}\\\\[A-Za-z0-9$_-]{1,10}(\\\\[A-Za-z0-9_-]([A-Za-z0-9 _-]{0,10}[A-Za-z0-9_-])?){0,2}",
            "%(PROGRAMFILES|WINDIR|LOCALAPPDATA)%(\\\\[A-Za-z0-9_-]([A-Za-z0-9 _-]{0,10}[A-Za-z0-9_-])?){0,3}",
        ]
    }

    /// Effect flags valid for an action. A deny that allows requests needs
    /// a notification; any other may hide it.
    pub fn effects(action: &Action) -> BoxedStrategy<Effects> {
        let kind = action.kind();
        let needs_notification = matches!(action, Action::Deny(o) if o.allow_request);
        if matches!(kind, ActionKind::Ignore | ActionKind::Defer) {
            return Just(Effects::default()).boxed();
        }
        let log = proptest::sample::select(
            [
                LogLevel::Always,
                LogLevel::Summary,
                LogLevel::Sampled,
                LogLevel::Never,
            ]
            .into_iter()
            .filter(|l| l.allowed_for(kind))
            .collect::<Vec<_>>(),
        );
        let notify = if needs_notification {
            prop_oneof![Just(Notify::Default), Just(Notify::Custom)].boxed()
        } else {
            prop_oneof![
                Just(Notify::None),
                Just(Notify::Default),
                Just(Notify::Custom)
            ]
            .boxed()
        };
        (
            (
                proptest::option::of(log),
                proptest::option::of(prop_oneof![
                    Just(Upload::Immediate),
                    Just(Upload::Batched),
                    Just(Upload::LocalOnly)
                ]),
                proptest::option::of(notify),
                "[A-Za-z0-9\u{e9}][A-Za-z0-9 .,!\u{e9}]{0,29}( \\{(file|publisher|rule|user|hash)\\})?( \\{\\{x\\}\\})?",
            ),
            (
                proptest::option::of("https://[a-z]{1,10}\\.example(/[a-z0-9_-]{0,10}){0,2}"),
                proptest::option::of(prop_oneof![
                    Just(EventSeverity::Info),
                    Just(EventSeverity::Low),
                    Just(EventSeverity::Medium),
                    Just(EventSeverity::High),
                    Just(EventSeverity::Critical)
                ]),
                proptest::collection::btree_set("[a-z][a-z0-9:._-]{0,20}", 0..3),
                proptest::option::of(0u32..=604_800),
            ),
        )
            .prop_map(
                move |((log, upload, notify, text), (help_url, severity, tags, suppress))| {
                    let mut e = Effects {
                        log,
                        upload,
                        notify,
                        notification_text: None,
                        help_url,
                        severity,
                        tags: tags.into_iter().collect(),
                        suppress_duplicates_secs: suppress,
                    };
                    let effective = e.notify_for(kind);
                    if effective == Notify::Custom {
                        e.notification_text = Some(text);
                    }
                    if effective == Notify::None {
                        e.help_url = None;
                    }
                    e
                },
            )
            .boxed()
    }
}
