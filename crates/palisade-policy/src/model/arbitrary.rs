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

fn object_type() -> impl Strategy<Value = ObjectType> {
    proptest::sample::select(ObjectType::ALL.to_vec())
}

fn value_for(class: FieldClass) -> BoxedStrategy<String> {
    match class {
        FieldClass::Hash { hex_len } => vec(
            proptest::sample::select(b"0123456789abcdef".to_vec()),
            hex_len,
        )
        .prop_map(|b| b.into_iter().map(char::from).collect())
        .boxed(),
        FieldClass::Version => "[0-9]{1,4}(\\.[0-9]{1,4}){0,3}".boxed(),
        FieldClass::Path => "[A-Za-z]:\\\\[A-Za-z0-9 _\\\\*?.-]{1,40}".boxed(),
        FieldClass::Text => "[A-Za-z0-9 ,.\u{e9}-]{1,40}".boxed(),
    }
}

/// A criterion whose operator and values are valid for its field.
pub fn criterion() -> impl Strategy<Value = Criterion> {
    proptest::sample::select(Field::ALL.to_vec()).prop_flat_map(|field| {
        let class = field.class();
        let operators: Vec<Operator> = OPERATORS
            .iter()
            .copied()
            .filter(|op| op.applies_to(class))
            .collect();
        let case = if matches!(class, FieldClass::Path | FieldClass::Text) {
            proptest::option::of(any::<bool>()).boxed()
        } else {
            Just(None).boxed()
        };
        (proptest::sample::select(operators), case).prop_flat_map(move |(operator, case)| {
            let max = if operator.is_single_valued() { 1 } else { 4 };
            vec(value_for(class), 1..=max).prop_map(move |values| Criterion {
                field,
                operator,
                values,
                case_sensitive: case,
            })
        })
    })
}

const OPERATORS: [Operator; 13] = [
    Operator::Equals,
    Operator::NotEquals,
    Operator::StartsWith,
    Operator::EndsWith,
    Operator::Contains,
    Operator::NotContains,
    Operator::Wildcard,
    Operator::NotWildcard,
    Operator::VersionEq,
    Operator::VersionGt,
    Operator::VersionGe,
    Operator::VersionLt,
    Operator::VersionLe,
];

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
        value_for(FieldClass::Hash { hex_len: 64 }),
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

fn rule(mandatory: bool) -> impl Strategy<Value = Rule> {
    let action = if mandatory {
        Just(Action::Deny {}).boxed()
    } else {
        prop_oneof![
            Just(Action::Allow {}),
            Just(Action::Deny {}),
            Just(Action::Audit {})
        ]
        .boxed()
    };
    (
        (
            uuid7(),
            proptest::option::of("R-[0-9]{6,12}"),
            name(),
            text(),
        ),
        (
            any::<bool>(),
            proptest::collection::btree_set(object_type(), 0..4),
            tree(),
            action,
        ),
        (
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<i32>()),
            prop_oneof![
                Just(EnforcementOverride::Inherit),
                Just(EnforcementOverride::AlwaysEnforce),
                Just(EnforcementOverride::NeverEnforce)
            ],
            metadata(),
        ),
    )
        .prop_map(
            |(
                (id, display_id, name, description),
                (enabled, types, match_, action),
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
            vec(rule(mandatory), 0..4),
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
            "[a-z][a-z0-9_.]{0,20}",
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
