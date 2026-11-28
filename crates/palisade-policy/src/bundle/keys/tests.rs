use std::collections::BTreeSet;
use std::path::Path;

use super::*;

const GOLDEN: &str = "tests/golden/bundle-keys.txt";

fn registry_text() -> String {
    let mut out = String::from(
        "# Every bundle key ever published (#43): `id name since`. A line is\n\
         # never changed or removed; new keys are appended. Regenerate with\n\
         # PALISADE_BLESS=1 cargo test -p palisade-policy bundle::keys\n",
    );
    for k in KEYS {
        out.push_str(&format!("{} {} {}\n", k.id, k.name, k.since));
    }
    out
}

#[test]
fn ids_and_names_are_unique() {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for k in KEYS {
        assert!(ids.insert(k.id), "ID {} is used twice", k.id);
        assert!(names.insert(k.name), "`{}` is registered twice", k.name);
        assert!(k.since >= 1, "`{}` has no format version", k.name);
    }
}

#[test]
fn critical_ids_count_up_from_zero_and_ignorable_ids_down_from_minus_one() {
    let critical: Vec<i64> = KEYS.iter().filter(|k| k.critical()).map(|k| k.id).collect();
    let ignorable: Vec<i64> = KEYS
        .iter()
        .filter(|k| !k.critical())
        .map(|k| k.id)
        .collect();
    assert!(
        critical
            .iter()
            .copied()
            .eq(0..i64::try_from(critical.len()).unwrap()),
        "critical IDs must be 0, 1, 2, ..."
    );
    assert!(
        ignorable
            .iter()
            .copied()
            .eq((1..=i64::try_from(ignorable.len()).unwrap()).map(|n| -n)),
        "ignorable IDs must be -1, -2, ..."
    );
}

#[test]
fn lookups_agree_with_the_table() {
    for k in KEYS {
        assert_eq!(id(k.name), Some(k.id));
        assert_eq!(name(k.id), Some(k.name));
    }
    assert_eq!(id("no_such_field"), None);
    assert_eq!(name(i64::MAX), None);
}

/// Only fields that never change a decision may be ignorable.
#[test]
fn ignorable_keys_are_only_text_and_display_fields() {
    let ignorable: Vec<&str> = KEYS
        .iter()
        .filter(|k| !k.critical())
        .map(|k| k.name)
        .collect();
    assert_eq!(
        ignorable,
        [
            "description",
            "hidden",
            "category_path",
            "version",
            "allow_child_suppress"
        ]
    );
}

/// A published ID never changes meaning: every line of the golden file is
/// still in the table, unchanged. New keys are added to the file by
/// blessing it.
#[test]
fn published_keys_never_change() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    let generated = registry_text();
    if std::env::var_os("PALISADE_BLESS").is_some() {
        if let Ok(old) = std::fs::read_to_string(&path) {
            let old = old.replace("\r\n", "\n");
            for line in old.lines().filter(|l| !l.starts_with('#')) {
                assert!(
                    generated.lines().any(|g| g == line),
                    "published key `{line}` was changed or removed"
                );
            }
        }
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    for line in committed.lines().filter(|l| !l.starts_with('#')) {
        assert!(
            generated.lines().any(|g| g == line),
            "published key `{line}` was changed or removed: IDs are never reused"
        );
    }
    assert_eq!(
        committed, generated,
        "{GOLDEN} is stale. Regenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-policy bundle::keys"
    );
}

#[test]
fn every_key_is_from_format_version_one_or_two() {
    // `k` is format 1's constructor and `k2` format 2's (#368). Within the
    // table a key's format never goes down.
    assert!(KEYS.iter().all(|key| matches!(key.since, 1 | 2)));
    assert!(
        KEYS.iter()
            .filter(|key| key.critical())
            .map(|key| key.since)
            .is_sorted()
    );
    assert!(
        KEYS.iter()
            .all(|key| key.since <= crate::bundle::format::FORMAT_VERSION)
    );
    assert_eq!(k2(1, "x").since, 2);
    assert_eq!(
        k(7, "x"),
        Key {
            id: 7,
            name: "x",
            since: 1
        }
    );
    assert!(k(0, "x").critical());
    assert!(!k(-1, "x").critical());
}
