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
        .prop_flat_map(|(justification, ticket_ref, tags, comment)| {
            (
                proptest::option::of("[a-z]{1,12}"),
                proptest::option::of(timestamp()),
                proptest::option::of(date()),
                proptest::option::of(proptest::sample::select(vec![
                    super::RiskRating::Low,
                    super::RiskRating::Medium,
                    super::RiskRating::High,
                ])),
                proptest::option::of(proptest::sample::select(vec![
                    super::RuleSource::Manual,
                    super::RuleSource::Learned,
                    super::RuleSource::Api,
                ])),
            )
                .prop_map(
                    move |(owner, created_at, review_by, risk_rating, source)| Metadata {
                        justification: justification.clone(),
                        ticket_ref: ticket_ref.clone(),
                        tags: tags.iter().cloned().collect(),
                        comment: comment.clone(),
                        owner,
                        created_at,
                        review_by,
                        risk_rating,
                        source,
                        ..Metadata::default()
                    },
                )
        })
}

/// An instant in years 1970 to 2100.
fn timestamp() -> impl Strategy<Value = super::Timestamp> {
    (0i64..4_102_444_800).prop_map(super::Timestamp)
}

/// A date in years 1970 to 2100.
fn date() -> impl Strategy<Value = super::Date> {
    (0i64..47_482).prop_map(super::Date)
}

/// An activity window and expiry behaviour that pass validation.
fn window() -> impl Strategy<
    Value = (
        Option<super::Timestamp>,
        Option<super::Timestamp>,
        super::OnExpire,
    ),
> {
    (
        proptest::option::of(0i64..2_000_000_000),
        proptest::option::of(1i64..1_000_000_000),
        proptest::sample::select(vec![
            super::OnExpire::Deactivate,
            super::OnExpire::ConvertToAudit,
            super::OnExpire::DeleteAfterDays(30),
        ]),
    )
        .prop_map(|(start, len, on)| {
            let activates = start.map(super::Timestamp);
            let expires = len.map(|l| super::Timestamp(start.unwrap_or(0) + l));
            let on = if expires.is_some() {
                on
            } else {
                super::OnExpire::Deactivate
            };
            (activates, expires, on)
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
        (FieldClass::Digest, _) => {
            prop_oneof!["[0-9a-f]{40}", "[0-9a-f]{64}", "[0-9A-F]{96}"].boxed()
        }
        (FieldClass::Guid, _) => (
            any::<bool>(),
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
            .prop_map(|(braced, g)| if braced { format!("{{{g}}}") } else { g })
            .boxed(),
        (FieldClass::OidSet, _) => "[0-2](\\.[0-9]{1,5}){1,6}".boxed(),
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
        // Never used either: `exists` takes no values (#329).
        (FieldClass::Presence, _) => Just(String::new()).boxed(),
        (FieldClass::ProbeValue, op) if op.is_ordered() => {
            (0u64..100_000).prop_map(|n| n.to_string()).boxed()
        }
        (FieldClass::PrincipalName, _) => "[A-Z]{1,8}\\\\[a-z0-9.]{1,12}".boxed(),
        (FieldClass::Number, _) => (0u64..100_000).prop_map(|n| n.to_string()).boxed(),
        (FieldClass::IntegrityLevel, _) => proptest::sample::select(
            crate::context::IntegrityLevel::ALL
                .iter()
                .map(|l| l.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
        .boxed(),
        (FieldClass::Date, _) => (1u16..=9999, 1u8..=12, 1u8..=28)
            .prop_map(|(y, m, d)| format!("{y:04}-{m:02}-{d:02}"))
            .boxed(),
        (FieldClass::DistinguishedName, _) => "(OU=[A-Za-z]{1,8},){1,3}DC=[a-z]{1,8}".boxed(),
        (FieldClass::Ip | FieldClass::IpSet, Operator::IpInCidr) => prop_oneof![
            any::<[u8; 2]>().prop_map(|b| format!("10.{}.{}.0/24", b[0], b[1])),
            Just("2001:db8::/32".to_owned()),
        ]
        .boxed(),
        (FieldClass::Ip | FieldClass::IpSet, Operator::IpBetween) => {
            (any::<u8>(), 0u8..100, 100u8..=255)
                .prop_map(|(c, a, b)| format!("192.168.{c}.{a}-{b}"))
                .boxed()
        }
        (FieldClass::Ip | FieldClass::IpSet, Operator::IpWildcard) => {
            (any::<u8>()).prop_map(|a| format!("10.{a}.*.*")).boxed()
        }
        (FieldClass::Ip | FieldClass::IpSet, _) => any::<[u8; 4]>()
            .prop_map(|b| std::net::Ipv4Addr::from(b).to_string())
            .boxed(),
        (FieldClass::MacSet, _) => any::<[u8; 6]>()
            .prop_map(|b| {
                b.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            })
            .boxed(),
        (FieldClass::NameSet, _) => "[a-z][a-z0-9.-]{0,20}".boxed(),
        (FieldClass::Weekday, _) => proptest::sample::select(
            crate::context::Weekday::ALL
                .iter()
                .map(|d| d.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
        .boxed(),
        (FieldClass::TimeOfDay, _) => (0u16..24, 0u16..60)
            .prop_map(|(h, m)| format!("{h:02}:{m:02}"))
            .boxed(),
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
        (FieldClass::Text | FieldClass::ProbeValue, _) => "[A-Za-z0-9 ,.\u{e9}-]{1,40}".boxed(),
    }
}

/// A criterion whose operator and values are valid for its field.
pub fn criterion() -> impl Strategy<Value = Criterion> {
    proptest::sample::select(Field::ALL.to_vec()).prop_flat_map(|field| {
        let class = field.class();
        let operators: Vec<Operator> = Operator::ALL
            .iter()
            .copied()
            .filter(|op| op.applies_to_field(field))
            .collect();
        let case = if class.has_case() {
            proptest::option::of(any::<bool>()).boxed()
        } else {
            Just(None).boxed()
        };
        (proptest::sample::select(operators), case).prop_flat_map(move |(operator, case)| {
            let (min, max) = operator.value_count();
            vec(value_for(class, operator), min..=max.min(4)).prop_map(move |mut values| {
                match operator {
                    Operator::VersionBetween => {
                        values.sort_by_key(|v| crate::ops::Version::parse_strict(v));
                    }
                    // Numbers and dates sort as their text when padded;
                    // numbers are compared as numbers.
                    Operator::Between
                        if matches!(class, FieldClass::Number | FieldClass::ProbeValue) =>
                    {
                        values.sort_by_key(|v| v.parse::<u64>().unwrap_or(0));
                    }
                    Operator::Between if class == FieldClass::IntegrityLevel => {
                        values.sort_by_key(|v| crate::context::IntegrityLevel::from_name(v));
                    }
                    Operator::Between | Operator::DateBetween => values.sort(),
                    // A window may wrap midnight, but cannot be empty.
                    Operator::TimeBetween if values[0] == values[1] => {
                        values[1] = if values[0] == "00:00" {
                            "00:01"
                        } else {
                            "00:00"
                        }
                        .to_owned();
                    }
                    _ => {}
                }
                // A probed field needs a target (#329), here in the
                // machine hive or a fixed path; `user_controlled_context`
                // is tested on its own.
                let target = match field {
                    Field::EnvVar => Some("PALISADE_TEST".to_owned()),
                    Field::RegKey | Field::RegValue => Some("HKLM\\Software\\Example".to_owned()),
                    Field::FsFile | Field::FsFolder => Some("C:\\Example\\flag".to_owned()),
                    _ => None,
                };
                Criterion {
                    case_sensitive: case,
                    target,
                    // A cold criterion needs a cadence (#329).
                    evaluate: (field.cost_class() == crate::model::CostClass::Cold)
                        .then_some(crate::model::Cadence::OncePerSession),
                    ..Criterion::new(field, operator, values)
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
            let mut children = vec![Match::Criterion(Criterion::new(
                Field::HashSha256,
                Operator::Equals,
                vec![hash],
            ))];
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
            proptest::option::of(0u32..=1_000_000),
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
            move |(
                (id, display_id, name, description),
                (enabled, match_, (action, types, effects)),
                (order, priority, enforcement_override, metadata),
            )| Rule {
                id: RuleId(id),
                display_id,
                name,
                description,
                enabled,
                activates_at: None,
                expires_at: None,
                on_expire: super::OnExpire::Deactivate,
                object_types: types.into_iter().collect(),
                match_,
                catch_all: false,
                attribute: false,
                effects,
                order,
                priority,
                // Only a deny may override its enforcement (#36).
                enforcement_override: if matches!(action, Action::Deny(_)) {
                    enforcement_override
                } else {
                    EnforcementOverride::Inherit
                },
                scope: None,
                action,
                metadata: metadata.into(),
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
            // Only a blocklist that is not mandatory may set its mode.
            if kind == RuleSetKind::Blocklist && !mandatory {
                proptest::option::of(enabled_mode()).boxed()
            } else {
                Just(None).boxed()
            },
        )
            .prop_map(
                move |(
                    (id, name, description, version),
                    (read_only, hidden),
                    rules,
                    metadata,
                    mode_override,
                )| {
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
                        mode_override,
                        allow_child_suppress: None,
                        category_path: None,
                        band: 0,
                        rules,
                        metadata,
                    }
                },
            )
    })
}

/// Any mode but `disabled`, which only a device can be in.
pub fn enabled_mode() -> impl Strategy<Value = Mode> {
    proptest::sample::select(vec![
        Mode::Monitor,
        Mode::Audit,
        Mode::Learning,
        Mode::Enforce,
    ])
}

/// Mode options that are valid with a base mode of `mode`.
pub fn mode_options(mode: Mode) -> impl Strategy<Value = super::ModeOptions> {
    let stricter: Vec<Mode> = [Mode::Monitor, Mode::Audit, Mode::Learning, Mode::Enforce]
        .into_iter()
        .filter(|m| *m == mode || crate::mode::strictness(*m) > crate::mode::strictness(mode))
        .collect();
    (
        btree_map(
            proptest::sample::select(ObjectType::ALL.to_vec()),
            enabled_mode(),
            0..4,
        ),
        proptest::option::of(proptest::sample::select(stricter)),
        // At least the longest check-in interval the generator uses.
        proptest::option::of(604_800u32..=2_592_000),
    )
        .prop_map(
            |(mode_by_type, mode_disconnected, disconnected_after_secs)| super::ModeOptions {
                mode_by_type,
                mode_disconnected,
                disconnected_after_secs,
            },
        )
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
            prop_oneof![
                Just(TimeZoneBasis::DeviceLocal),
                Just(TimeZoneBasis::Utc),
                Just(TimeZoneBasis::UserLocal)
            ],
            3_600u32..=86_400,
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
                (poll, ttl, overrides, tz, cache_age, depth),
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
                group_cache_max_age_secs: cache_age,
                max_ancestor_depth: depth,
                // Generated trees use the fixed maximums; tighter limits
                // are tested on their own.
                max_criteria_per_rule: super::settings::ranges::CRITERIA_PER_RULE_MAX,
                max_tree_depth: super::settings::ranges::TREE_DEPTH_MAX,
                max_values_per_criterion: super::settings::ranges::VALUES_PER_CRITERION_MAX,
                condition_budget_ms: super::settings::ranges::CONDITION_BUDGET_DEFAULT,
                // Unknown keys are only valid with the opt-in.
                allow_unknown_advanced: !advanced.is_empty(),
                advanced,
            },
        )
}

/// A scope that is valid on a rule of any action: no `user_pattern`, no
/// per-session options, and a location profile only by the one name every
/// generated policy defines.
pub fn scope() -> impl Strategy<Value = crate::scope::Scope> {
    use crate::context::SessionType;
    use crate::scope::{
        ClientFilter, CloudObject, Combine, DateRange, DeviceRef, DirectoryGroup, NetworkRef,
        OuRef, Pin, PrincipalRef, RefList, Schedule, Scope, ScopeSubject, SessionFilter, SetRef,
        TimeOfDay, Weekday, WellKnown, Window,
    };
    let set = (uuid7(), proptest::option::of(1u32..1000))
        .prop_map(|(id, v)| SetRef {
            id: crate::library::LibraryId(id),
            pin: v.map_or(Pin::Latest, Pin::Version),
        })
        .boxed();
    let guid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    let cloud = (guid, guid)
        .prop_map(|(tenant_id, object_id)| CloudObject {
            tenant_id,
            object_id,
        })
        .boxed();
    let principal = prop_oneof![
        "S-1-5-21-[1-9][0-9]{0,8}-[1-9][0-9]{0,8}-[1-9][0-9]{0,8}-[1-9][0-9]{0,5}"
            .prop_map(PrincipalRef::Sid),
        proptest::sample::select(WellKnown::ALL.to_vec()).prop_map(PrincipalRef::WellKnown),
        "[A-Za-z][A-Za-z ]{0,20}[a-z]".prop_map(PrincipalRef::LocalGroup),
        (
            "S-1-5-21-1-2-3-[1-9][0-9]{0,4}",
            proptest::option::of("[A-Za-z]{1,20}")
        )
            .prop_map(|(sid, name)| PrincipalRef::DirectoryGroup(DirectoryGroup { sid, name })),
        cloud.clone().prop_map(PrincipalRef::CloudGroup),
        set.clone().prop_map(PrincipalRef::PrincipalSet),
    ];
    let device = prop_oneof![
        uuid7().prop_map(DeviceRef::DeviceId),
        "[A-Z]{2,5}-[*?0-9]{1,4}".prop_map(DeviceRef::HostnamePattern),
        set.clone().prop_map(DeviceRef::DeviceSet),
        "S-1-5-21-1-2-3-[1-9][0-9]{0,4}".prop_map(DeviceRef::DirectoryComputerGroup),
        cloud.prop_map(DeviceRef::CloudDeviceGroup),
        ("OU=[A-Za-z]{1,10},DC=[a-z]{1,8},DC=org", any::<bool>()).prop_map(
            |(dn, include_sub_ous)| DeviceRef::Ou(OuRef {
                dn,
                include_sub_ous
            })
        ),
        "[a-z]{1,8}=[a-z0-9]{1,8}".prop_map(DeviceRef::Tag),
    ];
    let network = prop_oneof![
        (0u8..=255, 0u8..=255).prop_map(|(a, b)| NetworkRef::Cidr(format!("10.{a}.{b}.0/24"))),
        (0u8..=255, 1u8..=100)
            .prop_map(|(a, n)| NetworkRef::Range(format!("10.0.{a}.1-10.0.{a}.{n}"))),
        "[a-z]{1,8}\\.example\\.org".prop_map(NetworkRef::DnsSuffix),
        any::<[u8; 6]>().prop_map(|m| NetworkRef::GatewayMac(
            m.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("-")
        )),
        any::<bool>().prop_map(NetworkRef::ServerReachable),
        Just(NetworkRef::LocationProfile("corporate".to_owned())),
        set.clone().prop_map(NetworkRef::NetworkSet),
    ];
    fn list<T: core::fmt::Debug + Clone>(
        s: impl Strategy<Value = T> + Clone,
    ) -> impl Strategy<Value = Option<RefList<T>>> {
        proptest::option::of(
            (vec(s.clone(), 0..3), vec(s, 0..3))
                .prop_map(|(include, exclude)| RefList { include, exclude }),
        )
    }
    let time = (0u16..1440).prop_map(|m| {
        TimeOfDay::from_minutes(m)
            .unwrap_or(TimeOfDay::from_minutes(0).unwrap_or_else(|| unreachable!()))
    });
    let window = (
        proptest::sample::subsequence(
            vec![
                Weekday::Mon,
                Weekday::Tue,
                Weekday::Wed,
                Weekday::Thu,
                Weekday::Fri,
                Weekday::Sat,
                Weekday::Sun,
            ],
            1..=7,
        ),
        time.clone(),
        prop_oneof![
            time.prop_map(|t| (Some(t), None)),
            (1u32..=10_080).prop_map(|d| (None, Some(d))),
        ],
    )
        .prop_map(|(days, start, (end, duration_mins))| Window {
            days,
            start,
            end,
            duration_mins,
        });
    let date = (2000i16..2100, 1i8..=12, 1i8..=28)
        .prop_filter_map("a date", |(y, m, d)| {
            jiff::civil::Date::new(y, m, d).ok().map(crate::scope::Date)
        })
        .boxed();
    let range = (date.clone(), proptest::option::of(0i32..400)).prop_map(|(from, len)| DateRange {
        from,
        to: len.map(|n| {
            crate::scope::Date(
                from.0
                    .checked_add(jiff::Span::new().days(n))
                    .unwrap_or(from.0),
            )
        }),
    });
    let schedule = (
        proptest::option::of(prop_oneof![
            Just(TimeZoneBasis::DeviceLocal),
            Just(TimeZoneBasis::Utc),
            Just(TimeZoneBasis::UserLocal)
        ]),
        vec(window, 0..3),
        vec(range.clone(), 0..2),
        vec(range, 0..2),
    )
        .prop_map(|(timezone_basis, windows, dates, except_dates)| Schedule {
            timezone_basis,
            windows,
            dates,
            except_dates,
            ..Schedule::default()
        });
    let sessions = proptest::option::of(
        (
            proptest::sample::subsequence(SessionType::ALL.to_vec(), 0..=3),
            proptest::option::of(
                (
                    vec("THIN-[0-9*]{1,3}", 0..2),
                    vec(Just("10.50.0.0/16".to_owned()), 0..2),
                    vec(set.clone(), 0..2),
                )
                    .prop_map(|(hostname, ip, device_sets)| ClientFilter {
                        hostname,
                        ip,
                        device_sets,
                    }),
            ),
        )
            .prop_map(|(types, client)| SessionFilter { types, client }),
    );
    (
        list(principal),
        list(device),
        list(network),
        sessions,
        prop_oneof![
            Just((None, None)),
            schedule.prop_map(|s| (Some(s), None)),
            set.prop_map(|s| (None, Some(s))),
        ],
        any::<bool>(),
        proptest::sample::select(vec![
            ScopeSubject::ProcessUser,
            ScopeSubject::SessionUser,
            ScopeSubject::ParentProcessUser,
        ]),
        any::<bool>(),
    )
        .prop_map(
            |(
                principals,
                devices,
                network,
                sessions,
                (schedule, schedule_set),
                any,
                subject,
                negate,
            )| {
                let mut s = Scope {
                    principals,
                    devices,
                    network,
                    sessions,
                    schedule,
                    schedule_set,
                    combine: if any { Combine::Any } else { Combine::All },
                    negate: false,
                    subject,
                    max_instances_per_session: 0,
                };
                // A negated scope needs a dimension.
                s.negate = negate && s.has_dimension();
                s
            },
        )
}

/// An unknown-application policy that passes validation (#39): any levels,
/// except `restrict` and `prompt` only where the object type allows them,
/// with a containment profile, and no preset.
pub fn unknown_policy() -> impl Strategy<Value = super::UnknownPolicy> {
    use super::unknown::{Level, LocationClass, OriginClass};
    let level = || proptest::sample::select(Level::ALL.to_vec());
    (
        level(),
        proptest::collection::btree_map(
            proptest::sample::select(LocationClass::ALL.to_vec()),
            level(),
            0..4,
        ),
        proptest::collection::btree_map(
            proptest::sample::select(OriginClass::ALL.to_vec()),
            level(),
            0..3,
        ),
        proptest::collection::btree_map(
            proptest::sample::select(ObjectType::ALL.to_vec()),
            level(),
            0..3,
        ),
        proptest::sample::select(vec![
            Level::Block,
            Level::Detect,
            Level::Restrict,
            Level::Allow,
        ]),
        any::<bool>(),
        uuid7(),
    )
        .prop_map(
            |(default, by_location, by_origin, mut by_type, fallback, allow_request, profile)| {
                by_type.retain(|t, l| {
                    (*l != Level::Restrict || crate::unknown::restrict_valid_for(*t))
                        && (*l != Level::Prompt || crate::unknown::prompt_valid_for(*t))
                });
                let mut p = super::UnknownPolicy {
                    default,
                    by_location,
                    by_origin,
                    by_type,
                    restrict_profile: Some(super::ContainmentProfileRef(profile)),
                    allow_request,
                    ..super::UnknownPolicy::default()
                };
                p.prompt.fallback = fallback;
                p
            },
        )
}

/// A document that passes [`PolicyDocument::validate`], with scopes on
/// some rules, on the policy and on a rule set assignment (#38). The
/// properties of [`document`] that assume every rule is a candidate do not
/// hold here; the ones about the document's form do.
pub fn scoped_document() -> impl Strategy<Value = PolicyDocument> {
    (
        document(),
        proptest::option::of(scope()),
        vec(scope(), 1..3),
        any::<bool>(),
        vec(proptest::option::of(scope()), 0..8),
    )
        .prop_map(|(mut doc, scope, set_scopes, assign, rule_scopes)| {
            let p = &mut doc.policy;
            p.scope = scope;
            p.location_profiles = vec![crate::scope::LocationProfile {
                name: "corporate".to_owned(),
                all: vec![
                    crate::scope::NetworkRef::DnsSuffix("corp.example.org".to_owned()),
                    crate::scope::NetworkRef::ServerReachable(true),
                ],
            }];
            if let (Some(first), true) = (p.rule_sets.first(), assign) {
                p.rule_set_scopes = vec![crate::scope::RuleSetScope {
                    rule_set: *first,
                    scopes: set_scopes,
                }];
            }
            let rules = doc.rule_sets.iter_mut().flat_map(|s| s.rules.iter_mut());
            for (rule, scope) in rules.zip(rule_scopes) {
                rule.scope = scope.map(Box::new);
            }
            doc
        })
}

/// [`scoped_document`], with random activity windows, expiry behaviour and
/// governance metadata on its rules (#40). The evaluation proptests use
/// [`document`], whose rules are always active, so their oracles need no
/// clock.
pub fn document_with_lifecycle() -> impl Strategy<Value = PolicyDocument> {
    (scoped_document(), vec(window(), 0..16)).prop_map(|(mut doc, windows)| {
        let rules = doc.rule_sets.iter_mut().flat_map(|s| {
            let mandatory = s.mandatory;
            s.rules.iter_mut().map(move |r| (mandatory, r))
        });
        for ((mandatory, rule), (activates_at, expires_at, on_expire)) in rules.zip(windows) {
            rule.activates_at = activates_at;
            rule.expires_at = expires_at;
            rule.on_expire = if mandatory && on_expire == super::OnExpire::ConvertToAudit {
                super::OnExpire::Deactivate
            } else {
                on_expire
            };
        }
        doc
    })
}

/// A document that passes [`PolicyDocument::validate`].
///
/// Boxed: the document's strategy is deep, and tests compose it further;
/// unboxed, the composed value overflows a test thread's stack in debug
/// builds.
pub fn document() -> BoxedStrategy<PolicyDocument> {
    let model = proptest::sample::select(vec![
        PrecedenceModel::DenyWins,
        PrecedenceModel::AllowWins,
        PrecedenceModel::Specificity,
        PrecedenceModel::FirstMatch,
        PrecedenceModel::Priority,
    ]);
    // A policy cannot be `disabled` (#36).
    let mode_and_options = enabled_mode().prop_flat_map(|m| (Just(m), mode_options(m)));
    (
        (
            uuid7(),
            name(),
            text(),
            any::<u64>(),
            model,
            mode_and_options,
        ),
        (settings(), precedence_options(), unknown_policy()),
        vec(rule_set(), 0..4),
        metadata(),
    )
        .prop_map(
            |(
                (id, name, description, revision, precedence_model, (mode, mode_options)),
                (settings, precedence_options, unknown),
                mut sets,
                metadata,
            )| {
                fit_to_model(precedence_model, &mut sets);
                let rule_sets = sets.iter().map(|s| s.id).collect();
                PolicyDocument {
                    schema_version: CURRENT,
                    policy: Policy {
                        id: PolicyId(id),
                        name,
                        description,
                        revision,
                        precedence_model,
                        precedence_options,
                        mode,
                        mode_options,
                        settings,
                        unknown,
                        // Governance mode off, so random metadata need not
                        // satisfy it; the settings themselves vary.
                        governance: super::GovernanceSettings {
                            require_justification: Some(false),
                            stale_after_days: 30 + u16::try_from(revision % 300).unwrap_or(0),
                            ..super::GovernanceSettings::default()
                        },
                        rule_sets,
                        scope: None,
                        rule_set_scopes: Vec::new(),
                        location_profiles: Vec::new(),
                        confirm_permit_all: None,
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
        .boxed()
}

/// Any precedence options. Options the model does not use only warn.
pub fn precedence_options() -> impl Strategy<Value = super::PrecedenceOptions> {
    use super::{AllowTiebreak, PriorityDirection, TierTiebreak};
    (
        prop_oneof![
            Just(AllowTiebreak::MostRestrictive),
            Just(AllowTiebreak::MostPermissive)
        ],
        any::<bool>(),
        any::<bool>(),
        prop_oneof![Just(TierTiebreak::Deny), Just(TierTiebreak::Allow)],
        prop_oneof![
            Just(PriorityDirection::LowerWins),
            Just(PriorityDirection::HigherWins)
        ],
    )
        .prop_map(
            |(
                allow_tiebreak,
                granularity_tiebreak,
                curated_first,
                same_tier_tiebreak,
                direction,
            )| {
                super::PrecedenceOptions {
                    allow_tiebreak,
                    granularity_tiebreak,
                    curated_first,
                    same_tier_tiebreak,
                    priority_direction: direction,
                }
            },
        )
}

/// Gives every rule the model decides an `order` or a `priority`, and
/// moves custom orders into the custom range, as validation requires,
/// keeping the generated value where it is valid.
pub fn fit_to_model(model: super::PrecedenceModel, sets: &mut [RuleSet]) {
    use crate::validate::order_ranges::CUSTOM;
    for set in sets.iter_mut().filter(|s| !s.mandatory) {
        let curated = set.read_only;
        for rule in &mut set.rules {
            let decides = crate::precedence::Verdict::of(&rule.action).is_some();
            match model {
                // Every custom rule with an order uses the custom range;
                // every rule that decides has one.
                PrecedenceModel::FirstMatch if decides || rule.order.is_some() => {
                    let order = rule.order.unwrap_or(*CUSTOM.start());
                    rule.order = Some(if curated || CUSTOM.contains(&order) {
                        order
                    } else {
                        CUSTOM.start() + order % (CUSTOM.end() - CUSTOM.start() + 1)
                    });
                }
                PrecedenceModel::FirstMatch => {}
                _ if !decides => {}
                PrecedenceModel::Priority => {
                    rule.priority = Some(rule.priority.unwrap_or_default());
                }
                PrecedenceModel::DenyWins
                | PrecedenceModel::AllowWins
                | PrecedenceModel::Specificity => {}
            }
        }
    }
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
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(kill_running, allow_request, template, unknown, unparseable)| {
                let unknown_as = |b| {
                    if b {
                        super::UnknownAs::Match
                    } else {
                        super::UnknownAs::NoMatch
                    }
                };
                super::DenyOptions {
                    kill_running,
                    allow_request,
                    request_template: template
                        .filter(|_| allow_request)
                        .map(super::RequestTemplateRef),
                    unknown_as: unknown_as(unknown),
                    on_unparseable: unknown_as(unparseable),
                }
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
