//! insta snapshots of validation and reader error output (#30, #330).
//!
//! The `.expected` files next to the fixtures pin each finding's code and
//! JSON Pointer. These snapshots pin the rest of what a user sees: the
//! severity and the message, in the order they are reported, for a fixed
//! set of fixtures that between them cover every kind of finding:
//!
//! - `validation`: the findings of fixtures in `tests/fixtures/invalid/`
//!   that each hold several, one per line, as `Display` writes them.
//! - `loading`: what the strict reader says about fixtures in
//!   `tests/fixtures/malformed/`.
//! - `migration`: what the migrating and lenient readers say about the
//!   fixtures in `tests/fixtures/migrate/rejected/` and about documents
//!   they refuse or read in part.
//!
//! A fixture added to those directories is checked by its `.expected` file;
//! it only needs to be listed here if its messages are worth pinning.
//! Review changes with `cargo insta review`, or write them with
//! `INSTA_UPDATE=always` and read the diff (docs/testing.md).

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use palisade_policy::model::PolicyDocument;
use palisade_policy::{lenient, migrate};

fn settings() -> insta::Settings {
    let mut s = insta::Settings::clone_current();
    s.set_prepend_module_to_snapshot(false);
    s.set_omit_expression(true);
    s.set_snapshot_path("snapshots/validation");
    s
}

fn fixture(dir: &str, name: &str) -> (PathBuf, String) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(dir)
        .join(format!("{name}.json"));
    let text = fs::read_to_string(&path).unwrap();
    (path, text)
}

/// Cuts serde's list of the names it expected (`, expected one of ...`),
/// which grows whenever a field or criterion is added, and would make
/// these snapshots change with unrelated work. The rest, including the
/// position, is kept.
fn stable(message: &str) -> String {
    let Some(start) = message.find(", expected one of ") else {
        return message.to_owned();
    };
    let rest = &message[start..];
    let end = rest.find(" at line ").unwrap_or(rest.len());
    format!("{}{}", &message[..start], &rest[end..])
}

/// One section per fixture: its name, then one line per finding.
fn report(dir: &str, names: &[&str], read: impl Fn(&str) -> Vec<String>) -> String {
    let mut out = String::new();
    for name in names {
        let (_, text) = fixture(dir, name);
        writeln!(out, "== {name}").unwrap();
        for line in read(&text) {
            writeln!(out, "{}", stable(&line)).unwrap();
        }
    }
    out
}

#[test]
fn validation_findings() {
    let out = report(
        "invalid",
        &[
            "multiple-errors",
            "criterion-options",
            "scope-errors",
            "unknown-policy",
            "lifecycle-governance",
            "mode-settings",
            "action-not-valid",
        ],
        |text| match PolicyDocument::from_json(text).unwrap().validate() {
            Ok(_) => vec!["valid".to_owned()],
            Err(errors) => errors.iter().map(ToString::to_string).collect(),
        },
    );
    settings().bind(|| insta::assert_snapshot!("validation", out));
}

#[test]
fn loading_errors() {
    let out = report(
        "malformed",
        &[
            "bad-schema-version",
            "unknown-field",
            "unknown-action",
            "action-unknown-option",
            "two-keys-in-node",
            "integer-enum",
            "uuid-v4",
            "uppercase-id",
        ],
        |text| match PolicyDocument::from_json(text) {
            Ok(_) => vec!["loads".to_owned()],
            Err(e) => vec![e.to_string()],
        },
    );
    settings().bind(|| insta::assert_snapshot!("loading", out));
}

#[test]
fn migration_and_lenient_errors() {
    let both = |text: &str| {
        let m = match migrate::read_json(text) {
            Ok(r) => format!("migrate: reads, from {}", r.from),
            Err(e) => format!("migrate: {e}"),
        };
        let l = match lenient::read_json(text) {
            Ok(r) => {
                let mut s = format!("lenient: reads, from {}", r.from);
                for i in r.ignored {
                    write!(s, "\n  ignored {} ({:?}): {}", i.pointer, i.kind, i.reason).unwrap();
                }
                s
            }
            Err(e) => format!("lenient: {e}"),
        };
        vec![m, l]
    };
    let mut out = report(
        "migrate/rejected",
        &[
            "duplicate-key",
            "flags-and-effects",
            "newer-major",
            "no-version",
            "unknown-criterion-field",
            "v1-version-in-policy",
        ],
        both,
    );
    // A newer minor with an unknown governance field and an unreadable
    // audit rule, which the lenient reader sets aside.
    let (_, text) = fixture("valid", "actions-and-effects");
    let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    doc["schema_version"] = "1.4.0".into();
    doc["policy"]["metadata"] = serde_json::json!({"cost_centre": "42"});
    doc["rule_sets"][1]["rules"][1]["match"] = serde_json::json!({
        "criterion": {"field": "future.field", "operator": "equals", "values": ["x"]}
    });
    out.push_str("== newer minor, set aside\n");
    for line in both(&doc.to_string()) {
        writeln!(out, "{}", stable(&line)).unwrap();
    }
    settings().bind(|| insta::assert_snapshot!("migration", out));
}
