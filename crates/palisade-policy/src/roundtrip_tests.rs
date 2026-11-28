//! Lossless JSON and YAML round trips of library and hierarchy objects
//! (#30, #330). Policy documents have their own 10,000-case tests in
//! `tests.rs` and `dsl/tests.rs`.
//!
//! The strategies here build any value of each type that serde can write;
//! they are not checked against validation, because what is tested is the
//! serialised form, not the semantics.

use std::collections::BTreeMap;

use proptest::collection::vec;
use proptest::prelude::*;

use crate::dsl::{self, Limits};
use crate::hierarchy::{
    Assignment, Builtin, HierarchyDocument, LevelOrder, ModeMerge, Node, NodeId, NodeKind,
    PlacementConditions, PlacementRule, PolicyEntry, PrecedenceSetting, TenantOptions,
};
use crate::library::{
    ApplicationSource, Derivation, Library, LibraryContent, LibraryId, LibraryRef, Pin, Realm,
};
use crate::model::arbitrary::{self, name, uuid7};
use crate::model::{Field, Mode, Operator, PolicyId, PrecedenceModel, RuleId};
use crate::schema::CURRENT;

fn cases(default: u32) -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default);
    ProptestConfig::with_cases(cases)
}

fn short_text() -> impl Strategy<Value = String> {
    "[ -~\u{e9}\u{4e2d}]{1,40}"
}

fn opt_text() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(short_text())
}

fn node_id() -> impl Strategy<Value = NodeId> {
    uuid7().prop_map(NodeId)
}

fn library_ref() -> impl Strategy<Value = LibraryRef> {
    (
        uuid7(),
        prop_oneof![Just(Pin::Latest), (1u32..).prop_map(Pin::Version)],
    )
        .prop_map(|(id, pin)| LibraryRef {
            id: LibraryId(id),
            pin,
        })
}

fn realm() -> impl Strategy<Value = Realm> {
    prop_oneof![Just(Realm::Global), node_id().prop_map(Realm::Tenant)]
}

fn strings() -> impl Strategy<Value = Vec<String>> {
    vec(short_text(), 0..4)
}

fn content() -> impl Strategy<Value = LibraryContent> {
    let field = proptest::sample::select(vec![
        Field::HashSha256,
        Field::PathFull,
        Field::PathDirectory,
        Field::SignerPublisher,
    ]);
    let source = proptest::sample::select(vec![
        ApplicationSource::Manual,
        ApplicationSource::Learned,
        ApplicationSource::Catalogue,
        ApplicationSource::Imported,
        ApplicationSource::Api,
        ApplicationSource::Recommendation,
    ]);
    // A rule set from a generated document, so every rule shape is covered.
    let rule_set =
        arbitrary::document().prop_filter_map("has a rule set", |d| d.rule_sets.into_iter().next());
    prop_oneof![
        rule_set.prop_map(|rule_set| LibraryContent::RuleSet { rule_set }),
        (
            (opt_text(), opt_text(), opt_text(), opt_text()),
            source,
            vec(arbitrary::tree(), 0..3),
        )
            .prop_map(
                |((vendor, product, min_version, max_version), source, matches)| {
                    LibraryContent::ApplicationDefinition {
                        vendor,
                        product,
                        min_version,
                        max_version,
                        source,
                        matches,
                    }
                }
            ),
        arbitrary::tree().prop_map(|tree| LibraryContent::MatchFragment { tree }),
        (field.clone(), strings())
            .prop_map(|(field, hashes)| LibraryContent::HashSet { field, hashes }),
        strings().prop_map(|publishers| LibraryContent::PublisherSet { publishers }),
        (
            field,
            proptest::sample::select(vec![Operator::Equals, Operator::StartsWith]),
            strings()
        )
            .prop_map(|(field, operator, paths)| LibraryContent::PathSet {
                field,
                operator,
                paths
            }),
        strings().prop_map(|principals| LibraryContent::PrincipalSet { principals }),
        strings().prop_map(|devices| LibraryContent::DeviceSet { devices }),
        strings().prop_map(|entries| LibraryContent::NetworkSet { entries }),
        strings().prop_map(|entries| LibraryContent::ScheduleSet { entries }),
        short_text().prop_map(|text| LibraryContent::MessageTemplate { text }),
    ]
}

fn library() -> impl Strategy<Value = Library> {
    (
        (uuid7(), 1u32.., name(), opt_text(), realm(), any::<bool>()),
        (
            opt_text(),
            proptest::option::of((uuid7(), 1u32..)),
            content(),
            arbitrary::document_with_lifecycle(),
        ),
    )
        .prop_map(
            |((id, version, name, description, realm, read_only), (owner, from, content, doc))| {
                Library {
                    id: LibraryId(id),
                    version,
                    name,
                    description,
                    realm,
                    read_only,
                    owner,
                    derived_from: from.map(|(id, version)| Derivation {
                        id: LibraryId(id),
                        version,
                    }),
                    content,
                    // Governance metadata from a generated policy.
                    metadata: doc.policy.metadata,
                }
            },
        )
}

fn setting_value() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        short_text().prop_map(serde_json::Value::from),
    ]
}

fn node() -> impl Strategy<Value = Node> {
    let kind = proptest::sample::select(vec![
        NodeKind::Global,
        NodeKind::Tenant,
        NodeKind::Group,
        NodeKind::Device,
        NodeKind::DynamicGroup,
        NodeKind::Template,
    ]);
    let builtin = proptest::sample::select(vec![
        Builtin::Unassigned,
        Builtin::Unmanaged,
        Builtin::Staging,
    ]);
    let model = proptest::sample::select(vec![
        PrecedenceModel::DenyWins,
        PrecedenceModel::AllowWins,
        PrecedenceModel::Specificity,
        PrecedenceModel::FirstMatch,
        PrecedenceModel::Priority,
    ]);
    let tenant_options = (
        proptest::option::of(proptest::sample::select(vec![
            LevelOrder::TopDown,
            LevelOrder::BottomUp,
            LevelOrder::Flat,
        ])),
        proptest::option::of(proptest::sample::select(vec![
            ModeMerge::Closest,
            ModeMerge::Strictest,
        ])),
        proptest::option::of(any::<bool>()),
        proptest::option::of(any::<bool>()),
    )
        .prop_map(|(level_order, mode_merge, group, user)| TenantOptions {
            level_order,
            mode_merge,
            allow_group_precedence: group,
            place_on_user_change: user,
        });
    (
        (
            node_id(),
            name(),
            kind,
            proptest::option::of(node_id()),
            proptest::option::of(builtin),
            proptest::option::of(node_id()),
            vec((uuid7(), any::<u32>()), 0..3),
            vec(library_ref(), 0..3),
        ),
        (
            vec("[A-Za-z]{1,10}(/[A-Za-z]{1,10})?", 0..3),
            vec(uuid7(), 0..3),
            proptest::collection::btree_map("[a-z][a-z0-9_.]{0,15}", setting_value(), 0..4),
            vec("[a-z][a-z0-9_.]{0,15}", 0..3),
            proptest::option::of(arbitrary::enabled_mode()),
            any::<bool>(),
        ),
        (
            proptest::option::of((model, arbitrary::precedence_options())),
            proptest::option::of(tenant_options),
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<bool>()),
        ),
    )
        .prop_map(
            |(
                (id, name, kind, parent, builtin, template, assignments, rule_sets),
                (categories, suppress, settings, locked_settings, mode, lock_mode),
                (precedence, tenant_options, rank, allow_auto_assignment),
            )| Node {
                id,
                name,
                kind,
                parent,
                builtin,
                template,
                assignments: assignments
                    .into_iter()
                    .map(|(p, slot_order)| Assignment {
                        policy: PolicyId(p),
                        slot_order,
                    })
                    .collect(),
                rule_sets,
                categories,
                suppress_inherited: suppress.into_iter().map(RuleId).collect(),
                settings: settings.into_iter().collect::<BTreeMap<_, _>>(),
                locked_settings,
                mode: mode.filter(|m| *m != Mode::Disabled),
                lock_mode,
                precedence: precedence.map(|(model, options)| PrecedenceSetting { model, options }),
                tenant_options,
                rank,
                allow_auto_assignment,
            },
        )
}

fn placement() -> impl Strategy<Value = PlacementRule> {
    (
        uuid7(),
        node_id(),
        any::<u32>(),
        node_id(),
        (
            strings(),
            strings(),
            strings(),
            strings(),
            strings(),
            strings(),
        ),
    )
        .prop_map(
            |(id, tenant, order, target, (ou, groups, hostname, networks, tags, os))| {
                PlacementRule {
                    id,
                    tenant,
                    order,
                    target,
                    conditions: PlacementConditions {
                        directory_ou: ou,
                        directory_groups: groups,
                        hostname,
                        networks,
                        tags,
                        os,
                    },
                }
            },
        )
}

fn hierarchy() -> impl Strategy<Value = HierarchyDocument> {
    (
        any::<u64>(),
        vec(node(), 0..4),
        vec(
            (realm(), arbitrary::document())
                .prop_map(|(realm, document)| PolicyEntry { realm, document }),
            0..2,
        ),
        vec(library(), 0..3),
        vec(placement(), 0..3),
    )
        .prop_map(
            |(revision, nodes, policies, libraries, placement)| HierarchyDocument {
                schema_version: CURRENT,
                revision,
                nodes,
                policies,
                libraries,
                placement,
            },
        )
}

/// Reads YAML (or JSON) with the strict reader of [`crate::dsl`], with
/// room for what was just written.
fn from_yaml<T: serde::de::DeserializeOwned>(text: &str) -> T {
    let room = Limits {
        max_bytes: text.len().max(Limits::DEFAULT.max_bytes),
        max_lookahead: text.len().max(Limits::DEFAULT.max_lookahead),
        ..Limits::DEFAULT
    };
    serde_json::from_value(dsl::to_json_value(text, &room).unwrap()).unwrap()
}

proptest! {
    // The acceptance criterion in #330: the 10,000-case JSON and YAML round
    // trips cover library and hierarchy objects too.
    #![proptest_config(cases(10_000))]

    #[test]
    fn libraries_round_trip_through_json_and_yaml(lib in library()) {
        let json = serde_json::to_string_pretty(&lib).unwrap();
        let back: Library = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&back, &lib);
        prop_assert_eq!(serde_json::to_string_pretty(&back).unwrap(), json.clone());
        // The strict reader reads the JSON text the same way.
        prop_assert_eq!(&from_yaml::<Library>(&json), &lib);
        let yaml = dsl::emit::to_string(&lib, "").unwrap();
        let back: Library = from_yaml(&yaml);
        prop_assert_eq!(&back, &lib);
        prop_assert_eq!(dsl::emit::to_string(&back, "").unwrap(), yaml);
    }
}

proptest! {
    // Each case holds several policies and libraries, so fewer cases cover
    // as many objects as the library test does.
    #![proptest_config(cases(1_000))]

    #[test]
    fn hierarchies_round_trip_through_json_and_yaml(h in hierarchy()) {
        let json = serde_json::to_string_pretty(&h).unwrap();
        let back = HierarchyDocument::from_json(&json).unwrap();
        prop_assert_eq!(&back, &h);
        prop_assert_eq!(serde_json::to_string_pretty(&back).unwrap(), json);
        let yaml = dsl::emit::to_string(&h, "").unwrap();
        let back: HierarchyDocument = from_yaml(&yaml);
        prop_assert_eq!(&back, &h);
        prop_assert_eq!(dsl::emit::to_string(&back, "").unwrap(), yaml);
    }
}
