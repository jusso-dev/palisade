//! Migrations between major versions of the policy schema (#330), against
//! the fixtures in `tests/fixtures/migrate/`.
//!
//! - `v{N}/` holds documents written for major `N`. For each one, the step
//!   from `N` gives the document of the same name in `v{N+1}/`, and
//!   `migrate` gives the one in the current major's directory.
//! - Every document in the current major's directory is unchanged by
//!   `migrate`, loads with the strict reader, passes the committed JSON
//!   Schema and validates.
//! - Every document in `rejected/` is refused by `read_json`. When it has an
//!   `.expected` file, the error's text is that file's first line.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use palisade_policy::migrate::{self, STEPS};
use palisade_policy::model::PolicyDocument;
use palisade_policy::schema::{self, CURRENT};
use serde_json::Value;

fn dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/migrate")
        .join(name)
}

fn files(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no fixtures in {}", dir.display());
    paths
}

fn value(path: &Path) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_step_has_fixtures_and_gives_the_next_version() {
    for step in STEPS {
        let next = dir(&format!("v{}", step.from + 1));
        for path in files(&dir(&format!("v{}", step.from))) {
            let Value::Object(old) = value(&path) else {
                panic!("{} is not an object", path.display());
            };
            let migrated = (step.apply)(old).unwrap();
            let expected = value(&next.join(path.file_name().unwrap()));
            assert_eq!(Value::Object(migrated), expected, "{}", path.display());
        }
    }
}

#[test]
fn every_old_fixture_migrates_to_a_current_document_that_validates() {
    let current = dir(&format!("v{}", CURRENT.major));
    for step in STEPS {
        for path in files(&dir(&format!("v{}", step.from))) {
            let text = fs::read_to_string(&path).unwrap();
            let read = migrate::read_json(&text).unwrap();
            assert!(read.was_migrated(), "{}", path.display());
            assert_eq!(read.from.major, step.from, "{}", path.display());
            let expected = fs::read_to_string(current.join(path.file_name().unwrap())).unwrap();
            assert_eq!(
                read.document,
                PolicyDocument::from_json(&expected).unwrap(),
                "{}",
                path.display()
            );
            // Idempotent: the migrated document migrates to itself.
            let migrated = migrate::migrate(value(&path)).unwrap();
            assert_eq!(migrate::migrate(migrated.clone()).unwrap(), migrated);
        }
    }
}

#[test]
fn current_fixtures_are_unchanged_and_valid() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/policy/v1.json"),
    )
    .unwrap();
    let mut schemas = boon::Schemas::new();
    let mut compiler = boon::Compiler::new();
    compiler.enable_format_assertions();
    compiler
        .add_resource(schema::SCHEMA_ID, serde_json::from_str(&text).unwrap())
        .unwrap();
    let index = compiler.compile(schema::SCHEMA_ID, &mut schemas).unwrap();
    for path in files(&dir(&format!("v{}", CURRENT.major))) {
        let v = value(&path);
        assert_eq!(
            migrate::migrate(v.clone()).unwrap(),
            v,
            "{}",
            path.display()
        );
        if let Err(e) = schemas.validate(&v, index) {
            panic!("{}: {e:#}", path.display());
        }
        let doc = PolicyDocument::from_json(&fs::read_to_string(&path).unwrap()).unwrap();
        if let Err(errors) = doc.validate() {
            panic!("{}: {errors:#?}", path.display());
        }
    }
}

#[test]
fn rejected_fixtures_are_refused() {
    for path in files(&dir("rejected")) {
        let text = fs::read_to_string(&path).unwrap();
        let Err(e) = migrate::read_json(&text) else {
            panic!("{} was accepted", path.display());
        };
        if let Ok(expected) = fs::read_to_string(path.with_extension("expected")) {
            assert_eq!(
                e.to_string(),
                expected.lines().next().unwrap(),
                "{}",
                path.display()
            );
        }
    }
}
