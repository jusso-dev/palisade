//! Tests of libraries: references, pins, expansion, cycles, limits and
//! ownership (#37).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::*;
use crate::hierarchy::tests::id;

fn lib_id(n: u32) -> LibraryId {
    LibraryId(id(n).parse().unwrap())
}

fn tenant(n: u32) -> NodeId {
    NodeId(id(n).parse().unwrap())
}

fn library(n: u32, version: u32, realm: Value, content: Value) -> Library {
    serde_json::from_value(json!({
        "id": id(n),
        "version": version,
        "name": format!("Lib {n}"),
        "realm": realm,
        "content": content,
    }))
    .unwrap()
}

fn fragment(n: u32, version: u32, tree: Value) -> Library {
    library(
        n,
        version,
        json!("global"),
        json!({"kind": "match_fragment", "tree": tree}),
    )
}

fn hash(c: char) -> Value {
    json!({"criterion": {"field": "hash.sha256", "operator": "equals", "values": [std::iter::repeat_n(c, 64).collect::<String>()]}})
}

fn tree(v: Value) -> Match {
    serde_json::from_value(v).unwrap()
}

fn r(n: u32) -> Value {
    json!({"ref": {"id": id(n)}})
}

fn codes(e: &[LibraryError]) -> Vec<(LibraryCode, String)> {
    e.iter().map(|e| (e.code, e.path.clone())).collect()
}

#[test]
fn pins_read_and_write_as_latest_or_a_number() {
    let latest: LibraryRef = serde_json::from_value(json!({"id": id(1)})).unwrap();
    assert_eq!(latest.pin, Pin::Latest);
    assert_eq!(serde_json::to_value(latest).unwrap(), json!({"id": id(1)}));
    let three: LibraryRef = serde_json::from_value(json!({"id": id(1), "pin": 3})).unwrap();
    assert_eq!(three.pin, Pin::Version(3));
    assert_eq!(
        serde_json::to_value(three).unwrap(),
        json!({"id": id(1), "pin": 3})
    );
    for bad in [
        json!(0),
        json!(-1),
        json!("newest"),
        json!(4_294_967_296u64),
    ] {
        assert!(serde_json::from_value::<LibraryRef>(json!({"id": id(1), "pin": bad})).is_err());
    }
}

#[test]
fn latest_resolves_to_the_highest_version_and_a_pin_stays() {
    let c = Catalogue::new(vec![fragment(1, 2, hash('b')), fragment(1, 1, hash('a'))]).unwrap();
    let get = |pin| {
        c.resolve(&LibraryRef { id: lib_id(1), pin }, Visibility::Global)
            .unwrap()
            .version
    };
    assert_eq!(get(Pin::Latest), 2);
    assert_eq!(get(Pin::Version(1)), 1);
    let missing = c
        .resolve(
            &LibraryRef {
                id: lib_id(1),
                pin: Pin::Version(3),
            },
            Visibility::Global,
        )
        .unwrap_err();
    assert_eq!(missing.code, LibraryCode::UnknownLibrary);
    let unknown = c
        .resolve(
            &LibraryRef {
                id: lib_id(2),
                pin: Pin::Latest,
            },
            Visibility::Global,
        )
        .unwrap_err();
    assert_eq!(unknown.code, LibraryCode::UnknownLibrary);
}

#[test]
fn expansion_inlines_fragments_and_applications_and_records_versions() {
    let app = library(
        3,
        1,
        json!("global"),
        json!({"kind": "application_definition", "source": "catalogue", "vendor": "Example", "matches": [hash('c'), r(1)]}),
    );
    let c = Catalogue::new(vec![
        fragment(1, 1, hash('a')),
        fragment(2, 1, json!({"not": r(1)})),
        app,
    ])
    .unwrap();
    let mut used = BTreeSet::new();
    let out = c
        .expand(
            &tree(json!({"all": [r(2), r(3)]})),
            Visibility::Global,
            &mut used,
        )
        .unwrap();
    assert_eq!(
        out,
        tree(json!({"all": [{"not": hash('a')}, {"any": [hash('c'), hash('a')]}]}))
    );
    assert_eq!(
        used,
        BTreeSet::from([(lib_id(1), 1), (lib_id(2), 1), (lib_id(3), 1)])
    );
}

#[test]
fn sets_become_criteria_of_at_most_25_values() {
    let hashes: Vec<String> = (0..30).map(|i| format!("{i:064x}")).collect();
    let mut upper = hashes.clone();
    upper[0] = format!("0X{}", hashes[0].to_uppercase());
    let set = library(
        1,
        1,
        json!("global"),
        json!({"kind": "hash_set", "field": "hash.sha256", "hashes": upper}),
    );
    let c = Catalogue::new(vec![set.clone()]).unwrap();
    let out = c
        .expand(&tree(r(1)), Visibility::Global, &mut BTreeSet::new())
        .unwrap();
    let Match::Any(ref children) = out else {
        panic!("{out:?}")
    };
    assert_eq!(children.len(), 2);
    let Match::Criterion(first) = &children[0] else {
        panic!()
    };
    assert_eq!(first.values.len(), 25);
    assert_eq!(first.values[0], hashes[0], "canonical lowercase form");
    // The index finds entries in any spelling.
    let index = set.hash_index().unwrap();
    assert_eq!(index.len(), 30);
    assert!(index.contains(&hashes[5].to_uppercase()));
    assert!(!index.contains(&format!("{:064x}", 99)));
}

#[test]
fn a_set_too_large_for_one_rule_is_rejected_when_inlined() {
    let hashes: Vec<String> = (0..801).map(|i| format!("{i:064x}")).collect();
    let c = Catalogue::new(vec![library(
        1,
        1,
        json!("global"),
        json!({"kind": "hash_set", "field": "hash.sha256", "hashes": hashes}),
    )])
    .unwrap();
    let e = c
        .expand(&tree(r(1)), Visibility::Global, &mut BTreeSet::new())
        .unwrap_err();
    assert_eq!(
        (e.code, e.path.as_str()),
        (LibraryCode::SetTooLarge, "/ref")
    );
}

#[test]
fn many_references_to_a_large_set_cost_little() {
    // A 100,000-entry publisher set (mostly duplicates, 900 distinct),
    // reached through a doubling chain of fragments from many rules: each
    // reference costs O(1) after the catalogue makes the entries canonical
    // once, whatever the size of the set.
    let publishers: Vec<String> = (0..100_000)
        .map(|i| format!("Publisher {}", i % 900))
        .collect();
    let mut libs = vec![library(
        1,
        1,
        json!("global"),
        json!({"kind": "publisher_set", "publishers": publishers}),
    )];
    for n in 2..=8 {
        libs.push(fragment(n, 1, json!({"any": [r(n - 1), r(n - 1)]})));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "times the operation to check its performance bound"
    )]
    let start = std::time::Instant::now();
    let c = Catalogue::new(libs).unwrap();
    for _ in 0..1_000 {
        let e = c
            .expand(&tree(r(8)), Visibility::Global, &mut BTreeSet::new())
            .unwrap_err();
        assert_eq!(e.code, LibraryCode::SetTooLarge);
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        start.elapsed()
    );
}

#[test]
fn cycles_are_rejected_with_the_cycle_path_once() {
    let libs = vec![
        fragment(1, 1, json!({"all": [r(2), hash('a')]})),
        fragment(2, 1, json!({"any": [r(3), hash('a')]})),
        fragment(3, 1, json!({"not": r(1)})),
        // Not on the cycle, but leads into it.
        fragment(4, 1, r(2)),
        // A self-reference.
        fragment(5, 1, json!({"all": [r(5), hash('a')]})),
    ];
    let e = Catalogue::new(libs).unwrap_err();
    let cycles: Vec<&str> = e
        .iter()
        .filter(|e| e.code == LibraryCode::LibraryCycle)
        .map(|e| e.message.as_str())
        .collect();
    assert_eq!(
        cycles,
        [
            "references form a cycle: `Lib 1` v1 -> `Lib 2` v1 -> `Lib 3` v1 -> `Lib 1` v1",
            "references form a cycle: `Lib 5` v1 -> `Lib 5` v1",
        ]
    );
}

#[test]
fn a_pinned_older_version_is_a_different_node_of_the_graph() {
    // v2 of 1 refers to 2, which refers to v1 of 1: no cycle.
    let libs = vec![
        fragment(1, 1, hash('a')),
        fragment(1, 2, json!({"all": [{"ref": {"id": id(2)}}, hash('b')]})),
        fragment(2, 1, json!({"ref": {"id": id(1), "pin": 1}})),
    ];
    let c = Catalogue::new(libs).unwrap();
    let out = c
        .expand(&tree(r(1)), Visibility::Global, &mut BTreeSet::new())
        .unwrap();
    assert_eq!(out, tree(json!({"all": [hash('a'), hash('b')]})));
}

#[test]
fn chains_deeper_than_the_limit_are_rejected() {
    let mut libs: Vec<Library> = (1..=9).map(|n| fragment(n, 1, r(n + 1))).collect();
    libs.push(fragment(10, 1, hash('a')));
    let e = Catalogue::new(libs).unwrap_err();
    assert_eq!(
        codes(&e),
        [(LibraryCode::RefTooDeep, "/libraries/0".to_owned())]
    );
}

#[test]
fn exponential_expansion_is_bounded() {
    // Each fragment uses the next twice: 2^8 leaves, more than the node
    // budget allows once the tree is doubled again at the top.
    let mut libs: Vec<Library> = (1..=7)
        .map(|n| fragment(n, 1, json!({"any": [r(n + 1), r(n + 1)]})))
        .collect();
    libs.push(fragment(8, 1, json!({"all": [hash('a'), hash('b')]})));
    let c = Catalogue::new(libs).unwrap();
    let e = c
        .expand(
            &tree(json!({"any": [r(1), r(1), r(1), r(1)]})),
            Visibility::Global,
            &mut BTreeSet::new(),
        )
        .unwrap_err();
    assert_eq!(e.code, LibraryCode::RefTooDeep);
}

#[test]
fn references_must_be_visible_and_of_a_tree_kind() {
    let libs = vec![
        library(
            1,
            1,
            json!({"tenant": id(50)}),
            json!({"kind": "match_fragment", "tree": hash('a')}),
        ),
        // A global library cannot use a tenant's.
        fragment(2, 1, r(1)),
        library(
            3,
            1,
            json!("global"),
            json!({"kind": "principal_set", "principals": ["S-1-5-32-544"]}),
        ),
        fragment(4, 1, r(3)),
        fragment(5, 1, r(99)),
    ];
    let e = Catalogue::new(libs).unwrap_err();
    assert_eq!(
        codes(&e),
        [
            (
                LibraryCode::NotVisible,
                "/libraries/1/content/tree/ref".to_owned()
            ),
            (
                LibraryCode::RefKindNotAllowed,
                "/libraries/3/content/tree/ref".to_owned()
            ),
            (
                LibraryCode::UnknownLibrary,
                "/libraries/4/content/tree/ref".to_owned()
            ),
        ]
    );
    // The tenant can use its own, another tenant cannot.
    let c = Catalogue::new(vec![library(
        1,
        1,
        json!({"tenant": id(50)}),
        json!({"kind": "match_fragment", "tree": hash('a')}),
    )])
    .unwrap();
    assert!(
        c.expand(
            &tree(r(1)),
            Visibility::Tenant(tenant(50)),
            &mut BTreeSet::new()
        )
        .is_ok()
    );
    let e = c
        .expand(
            &tree(r(1)),
            Visibility::Tenant(tenant(51)),
            &mut BTreeSet::new(),
        )
        .unwrap_err();
    assert_eq!(e.code, LibraryCode::NotVisible);
}

#[test]
fn content_is_checked() {
    let libs = vec![
        library(
            1,
            0,
            json!("global"),
            json!({"kind": "message_template", "text": "Blocked."}),
        ),
        library(
            2,
            1,
            json!("global"),
            json!({"kind": "hash_set", "field": "hash.sha256", "hashes": ["xyz"]}),
        ),
        library(
            3,
            1,
            json!("global"),
            json!({"kind": "hash_set", "field": "path.full", "hashes": ["a"]}),
        ),
        library(
            4,
            1,
            json!("global"),
            json!({"kind": "publisher_set", "publishers": []}),
        ),
        library(
            5,
            1,
            json!("global"),
            json!({"kind": "path_set", "field": "path.full", "operator": "regex", "paths": ["x"]}),
        ),
        library(
            6,
            1,
            json!("global"),
            json!({"kind": "principal_set", "principals": ["Administrators"]}),
        ),
        library(
            7,
            1,
            json!("global"),
            json!({"kind": "application_definition", "source": "manual", "matches": []}),
        ),
        library(
            8,
            1,
            json!("global"),
            json!({"kind": "rule_set", "rule_set": {"id": id(9), "name": "x", "kind": "blocklist"}}),
        ),
        library(
            10,
            1,
            json!("global"),
            json!({"kind": "message_template", "text": "a"}),
        ),
        library(
            10,
            1,
            json!("global"),
            json!({"kind": "message_template", "text": "b"}),
        ),
        library(
            10,
            2,
            json!("global"),
            json!({"kind": "device_set", "devices": ["d1"]}),
        ),
    ];
    let e = Catalogue::new(libs).unwrap_err();
    assert_eq!(
        codes(&e),
        [
            (
                LibraryCode::InvalidVersion,
                "/libraries/0/version".to_owned()
            ),
            (
                LibraryCode::InvalidEntry,
                "/libraries/1/content/hashes/0".to_owned()
            ),
            (
                LibraryCode::InvalidEntry,
                "/libraries/2/content/field".to_owned()
            ),
            (
                LibraryCode::InvalidEntry,
                "/libraries/3/content/publishers".to_owned()
            ),
            (LibraryCode::InvalidEntry, "/libraries/4/content".to_owned()),
            (
                LibraryCode::InvalidEntry,
                "/libraries/5/content/principals/0".to_owned()
            ),
            (
                LibraryCode::InvalidTree,
                "/libraries/6/content/matches".to_owned()
            ),
            (
                LibraryCode::IdMismatch,
                "/libraries/7/content/rule_set/id".to_owned()
            ),
            (
                LibraryCode::InvalidVersion,
                "/libraries/9/version".to_owned()
            ),
            (LibraryCode::KindChanged, "/libraries/10/content".to_owned()),
        ]
    );
}

#[test]
fn principal_sets_are_canonical() {
    let lib = library(
        1,
        1,
        json!("global"),
        json!({"kind": "principal_set", "principals": ["s-1-5-32-544", "S-1-5-32-544", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"]}),
    );
    assert_eq!(
        lib.content.canonical_entries(),
        ["0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", "S-1-5-32-544"]
    );
}

#[test]
fn categories_include_subcategories() {
    let rs = |n: u32, cat: &str| {
        library(
            n,
            1,
            json!("global"),
            json!({"kind": "rule_set", "rule_set": {"id": id(n), "name": "x", "kind": "blocklist", "category_path": cat}}),
        )
    };
    let c = Catalogue::new(vec![
        rs(1, "Tools"),
        rs(2, "Tools/Build"),
        rs(3, "Toolsmith"),
    ])
    .unwrap();
    let ids = |cat| -> Vec<LibraryId> {
        c.in_category(cat, Visibility::Global)
            .iter()
            .map(|l| l.id)
            .collect()
    };
    assert_eq!(ids("Tools"), [lib_id(1), lib_id(2)]);
    assert_eq!(ids("Tools/Build"), [lib_id(2)]);
}

#[test]
fn owners_metadata_and_texts_are_checked() {
    let mut a = library(
        1,
        1,
        json!("global"),
        json!({"kind": "message_template", "text": "Blocked \u{202e}here"}),
    );
    a.owner = Some(String::new());
    a.description = Some("bad\u{0}".to_owned());
    a.derived_from = Some(Derivation {
        id: lib_id(9),
        version: 0,
    });
    a.metadata.tags = vec![" spaced".to_owned()];
    let mut b = library(
        2,
        1,
        json!("global"),
        json!({"kind": "rule_set", "rule_set": {"id": id(2), "name": "x", "kind": "blocklist", "read_only": true}}),
    );
    b.read_only = false;
    let e = Catalogue::new(vec![a, b]).unwrap_err();
    assert_eq!(
        codes(&e),
        [
            (
                LibraryCode::InvalidText,
                "/libraries/0/description".to_owned()
            ),
            (LibraryCode::InvalidOwner, "/libraries/0/owner".to_owned()),
            (
                LibraryCode::InvalidVersion,
                "/libraries/0/derived_from/version".to_owned()
            ),
            (
                LibraryCode::InvalidText,
                "/libraries/0/metadata/tags/0".to_owned()
            ),
            (
                LibraryCode::InvalidText,
                "/libraries/0/content/text".to_owned()
            ),
            (
                LibraryCode::ReadOnlyMismatch,
                "/libraries/1/content/rule_set/read_only".to_owned()
            ),
        ]
    );
}

#[test]
fn an_empty_or_malformed_principal_never_owns_and_sids_compare_canonically() {
    let mut lib = library(
        1,
        1,
        json!({"tenant": id(50)}),
        json!({"kind": "message_template", "text": "x"}),
    );
    let actor = |p: &str| Actor {
        principal: p.to_owned(),
        tenant: Some(tenant(50)),
        tenant_admin: false,
        installation_admin: false,
    };
    lib.owner = Some(String::new());
    assert!(!lib.can_edit(&actor("")));
    lib.owner = Some("S-1-5-21-1-2-3-1001".to_owned());
    assert!(lib.can_edit(&actor("s-1-5-21-1-2-3-001001")));
    assert!(!lib.can_edit(&actor("not a sid")));
}

#[test]
fn ownership_decides_who_edits_and_who_uses() {
    let mut lib = library(
        1,
        1,
        json!({"tenant": id(50)}),
        json!({"kind": "message_template", "text": "x"}),
    );
    lib.owner = Some("S-1-5-21-1-2-3-1001".to_owned());
    let actor = |p: &str, t: Option<u32>, ta: bool, ia: bool| Actor {
        principal: p.to_owned(),
        tenant: t.map(tenant),
        tenant_admin: ta,
        installation_admin: ia,
    };
    assert!(lib.can_edit(&actor("S-1-5-21-1-2-3-1001", Some(50), false, false)));
    assert!(lib.can_edit(&actor("someone", Some(50), true, false)));
    assert!(!lib.can_edit(&actor("someone", Some(50), false, false)));
    assert!(!lib.can_edit(&actor("S-1-5-21-1-2-3-1001", Some(51), true, false)));
    assert!(lib.can_use(&actor("someone", Some(50), false, false)));
    assert!(!lib.can_use(&actor("someone", Some(51), false, false)));
    lib.read_only = true;
    assert!(!lib.can_edit(&actor("someone", Some(50), true, false)));
    let global = library(
        2,
        1,
        json!("global"),
        json!({"kind": "message_template", "text": "x"}),
    );
    assert!(global.can_use(&actor("someone", Some(51), false, false)));
    assert!(!global.can_edit(&actor("someone", Some(51), true, false)));
    assert!(global.can_edit(&actor("someone", None, false, true)));
}

#[test]
fn duplicating_makes_an_editable_copy_that_records_its_source() {
    let rs = library(
        1,
        4,
        json!("global"),
        json!({"kind": "rule_set", "rule_set": {"id": id(1), "name": "Curated", "kind": "blocklist", "read_only": true, "rules": [
            {"id": id(10), "name": "r", "match": hash('a'), "action": {"type": "deny"}}
        ]}}),
    );
    let mut next = 100;
    let copy = rs.duplicate(lib_id(2), tenant(50), "owner".to_owned(), || {
        next += 1;
        RuleId(id(next).parse().unwrap())
    });
    assert_eq!(copy.version, 1);
    assert_eq!(
        copy.derived_from,
        Some(Derivation {
            id: lib_id(1),
            version: 4
        })
    );
    assert_eq!(copy.realm, Realm::Tenant(tenant(50)));
    assert!(!copy.read_only);
    let LibraryContent::RuleSet { rule_set } = &copy.content else {
        panic!()
    };
    assert_eq!(rule_set.id.0, lib_id(2).0);
    assert!(!rule_set.read_only);
    assert_eq!(rule_set.rules[0].id, RuleId(id(101).parse().unwrap()));
}

#[test]
fn an_unresolved_ref_is_rejected_by_policy_validation_and_compilation() {
    let doc = crate::model::PolicyDocument::from_json(
        &json!({
            "schema_version": "1.0.0",
            "policy": {"id": id(1), "name": "P", "revision": 1, "mode": "enforce", "rule_sets": [id(2)]},
            "rule_sets": [{"id": id(2), "name": "S", "kind": "allowlist", "rules": [
                {"id": id(3), "name": "R", "match": {"all": [hash('a'), r(9)]}, "action": {"type": "allow"}}
            ]}],
        })
        .to_string(),
    )
    .unwrap();
    let e = doc.validate().unwrap_err();
    assert!(
        e.iter()
            .any(|f| f.code == crate::validate::ErrorCode::UnresolvedRef
                && f.path == "/rule_sets/0/rules/0/match/all/1/ref"),
        "{e:#?}"
    );
    let err = crate::condition::CompiledMatch::compile(&tree(json!({"all": [hash('a'), r(9)]})))
        .unwrap_err();
    assert_eq!(
        err,
        [crate::condition::TreeError::UnresolvedRef {
            pointer: "/all/1/ref".to_owned()
        }]
    );
}
