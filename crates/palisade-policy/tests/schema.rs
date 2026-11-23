//! The committed JSON Schema, and the fixture policies checked against it.
//!
//! - `committed_schema_is_current` fails if `schemas/policy/v1.json` differs
//!   from the schema generated from the Rust types. Regenerate it with
//!   `PALISADE_BLESS=1 cargo test -p palisade-policy --test schema`.
//! - Every fixture in `tests/fixtures/valid/` passes the schema, loads, and
//!   validates.
//! - Every fixture in `tests/fixtures/invalid/` passes the schema and loads,
//!   but validation reports exactly the findings in its `.expected` file
//!   (one `code path` per line).
//! - Every fixture in `tests/fixtures/malformed/` is rejected by the schema,
//!   with an error at each JSON Pointer in its `.expected` file, and is also
//!   rejected by loading or by validation.

// `clippy.toml` allows unwrap inside `#[test]` functions only; the helpers
// here are test code too.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use palisade_policy::model::PolicyDocument;
use palisade_policy::schema;

const SCHEMA_PATH: &str = "../../schemas/policy/v1.json";

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn committed_schema_is_current() {
    let path = manifest_dir().join(SCHEMA_PATH);
    let generated = schema::generate_pretty().unwrap();
    if std::env::var_os("PALISADE_BLESS").is_some() {
        fs::write(&path, &generated).unwrap();
        return;
    }
    // Git may check the file out with CRLF line endings on Windows.
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "{} is stale. Regenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-policy --test schema",
        path.display()
    );
}

#[test]
fn schema_declares_its_draft_id_and_version() {
    let value = schema::generate();
    assert_eq!(
        value["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(value["$id"], schema::SCHEMA_ID);
    assert_eq!(value["x-schema-version"], schema::CURRENT.to_string());
    assert!(schema::SCHEMA_ID.ends_with(&format!("/v{}.json", schema::CURRENT.major)));
}

/// The schema compiled by an independent JSON Schema 2020-12 validator.
struct CompiledSchema {
    schemas: boon::Schemas,
    index: boon::SchemaIndex,
}

impl CompiledSchema {
    fn new() -> Self {
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler.enable_format_assertions();
        compiler
            .add_resource(schema::SCHEMA_ID, schema::generate())
            .unwrap();
        let index = compiler.compile(schema::SCHEMA_ID, &mut schemas).unwrap();
        Self { schemas, index }
    }

    /// The instance locations of every leaf error, or empty if valid.
    fn errors(&self, instance: &serde_json::Value) -> Vec<String> {
        match self.schemas.validate(instance, self.index) {
            Ok(()) => Vec::new(),
            Err(e) => {
                let mut out = Vec::new();
                let mut stack = vec![&e];
                while let Some(err) = stack.pop() {
                    out.push(err.instance_location.to_string());
                    stack.extend(&err.causes);
                }
                out
            }
        }
    }
}

fn fixtures(dir: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(manifest_dir().join("tests/fixtures").join(dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no fixtures in {dir}");
    paths
}

fn load(path: &Path) -> (String, serde_json::Value) {
    let text = fs::read_to_string(path).unwrap();
    let value = serde_json::from_str(&text).unwrap();
    (text, value)
}

fn expected(path: &Path) -> Vec<String> {
    fs::read_to_string(path.with_extension("expected"))
        .unwrap_or_else(|_| panic!("{} has no .expected file", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn valid_fixtures_pass_schema_and_validation() {
    let schema = CompiledSchema::new();
    for path in fixtures("valid") {
        let (text, value) = load(&path);
        let errors = schema.errors(&value);
        assert!(
            errors.is_empty(),
            "{}: schema errors {errors:?}",
            path.display()
        );
        let doc = PolicyDocument::from_json(&text).unwrap();
        // Lossless: writing and reading again gives the same document.
        let again = PolicyDocument::from_json(&doc.to_json_pretty().unwrap()).unwrap();
        assert_eq!(again, doc, "{} does not round-trip", path.display());
        if let Err(errors) = doc.validate() {
            panic!("{}: {errors:#?}", path.display());
        }
    }
}

#[test]
fn invalid_fixtures_report_expected_codes_and_paths() {
    let schema = CompiledSchema::new();
    for path in fixtures("invalid") {
        let (text, value) = load(&path);
        let errors = schema.errors(&value);
        assert!(
            errors.is_empty(),
            "{}: schema errors {errors:?}",
            path.display()
        );
        let doc = PolicyDocument::from_json(&text).unwrap();
        let found: Vec<String> = match doc.validate() {
            Ok(_) => panic!("{} validated", path.display()),
            Err(errors) => errors
                .iter()
                .map(|e| format!("{} {}", e.code, e.path))
                .collect(),
        };
        assert_eq!(found, expected(&path), "{}", path.display());
    }
}

#[test]
fn malformed_fixtures_are_rejected_by_schema_and_loader() {
    let schema = CompiledSchema::new();
    for path in fixtures("malformed") {
        let (text, value) = load(&path);
        let errors = schema.errors(&value);
        for location in expected(&path) {
            assert!(
                errors.contains(&location),
                "{}: no schema error at {location:?}; got {errors:?}",
                path.display()
            );
        }
        let rejected = PolicyDocument::from_json(&text).map_or(true, |doc| doc.validate().is_err());
        assert!(rejected, "{} was accepted", path.display());
    }
}
