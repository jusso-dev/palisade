//! The YAML policy language against the committed JSON Schema, the example
//! policies and the fixtures (#190).
//!
//! - Every example in `docs/examples/policies/` has the editor schema
//!   header, passes the JSON Schema, loads, validates, and is unchanged by a
//!   write and read.
//! - Every JSON fixture written as YAML reads back as the same document, so
//!   the YAML and JSON forms are interchangeable; the schema result is the
//!   same for both.
//! - Every file in `tests/fixtures/yaml/invalid/` loads, but validation
//!   reports exactly the findings in its `.expected` file
//!   (`code pointer line:column` per line).
//! - Every file in `tests/fixtures/yaml/rejected/` fails to load with the
//!   error in its `.expected` file (`code line:column [pointer]`).

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use palisade_policy::dsl::{self, Limits, SCHEMA_HEADER};
use palisade_policy::model::PolicyDocument;
use palisade_policy::schema;

fn manifest_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

struct CompiledSchema {
    schemas: boon::Schemas,
    index: boon::SchemaIndex,
}

impl CompiledSchema {
    /// The committed schema file, which is what editors use.
    fn committed() -> Self {
        let text = fs::read_to_string(manifest_dir().join("../../schemas/policy/v1.json")).unwrap();
        let mut schemas = boon::Schemas::new();
        let mut compiler = boon::Compiler::new();
        compiler.enable_format_assertions();
        compiler
            .add_resource(schema::SCHEMA_ID, serde_json::from_str(&text).unwrap())
            .unwrap();
        let index = compiler.compile(schema::SCHEMA_ID, &mut schemas).unwrap();
        Self { schemas, index }
    }

    fn is_valid(&self, instance: &serde_json::Value) -> Result<(), String> {
        self.schemas
            .validate(instance, self.index)
            .map_err(|e| format!("{e:#}"))
    }
}

fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == extension))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "no .{extension} files in {}",
        dir.display()
    );
    paths
}

fn expected(path: &Path) -> Vec<String> {
    fs::read_to_string(path.with_extension("expected"))
        .unwrap_or_else(|_| panic!("{} has no .expected file", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// Git may check text out with CRLF line endings on Windows.
fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap().replace("\r\n", "\n")
}

#[test]
fn examples_have_the_header_pass_the_schema_and_validate() {
    let schema = CompiledSchema::committed();
    let dir = manifest_dir().join("../../docs/examples/policies");
    for path in files(&dir, "yaml") {
        let text = read(&path);
        assert!(
            text.starts_with(SCHEMA_HEADER),
            "{} must start with the editor schema header",
            path.display()
        );
        let value = dsl::to_json_value(&text, &Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if let Err(e) = schema.is_valid(&value) {
            panic!("{}: schema errors {e}", path.display());
        }
        let loaded = dsl::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let doc = loaded.document.clone();
        if let Err(errors) = loaded.validate() {
            panic!("{}: {errors:#?}", path.display());
        }
        let again = PolicyDocument::from_yaml(&dsl::to_string(&doc).unwrap()).unwrap();
        assert_eq!(again, doc, "{} does not round-trip", path.display());
    }
}

#[test]
fn yaml_example_equals_its_json_fixture() {
    let yaml = read(&manifest_dir().join("../../docs/examples/policies/workstation-baseline.yaml"));
    let json = read(&manifest_dir().join("tests/fixtures/valid/workstation-baseline.json"));
    assert_eq!(
        PolicyDocument::from_yaml(&yaml).unwrap(),
        PolicyDocument::from_json(&json).unwrap()
    );
}

#[test]
fn json_fixtures_mean_the_same_as_yaml() {
    let schema = CompiledSchema::committed();
    for dir in ["valid", "invalid", "malformed"] {
        for path in files(&manifest_dir().join("tests/fixtures").join(dir), "json") {
            let text = read(&path);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            // The JSON text read as YAML gives the same JSON value.
            let as_yaml = dsl::to_json_value(&text, &Limits::DEFAULT)
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(as_yaml, value, "{}", path.display());
            // Loading agrees with the JSON reader.
            let json_doc = PolicyDocument::from_json(&text);
            let yaml_doc = PolicyDocument::from_yaml(&text);
            assert_eq!(
                json_doc.is_ok(),
                yaml_doc.is_ok(),
                "{}: {:?} / {:?}",
                path.display(),
                json_doc.err(),
                yaml_doc.err()
            );
            let Ok(doc) = json_doc else { continue };
            assert_eq!(yaml_doc.unwrap(), doc);
            // Written as YAML, the document reads back the same and the
            // schema gives the same answer.
            let written = dsl::to_string(&doc).unwrap();
            assert_eq!(PolicyDocument::from_yaml(&written).unwrap(), doc);
            let written_value = dsl::to_json_value(&written, &Limits::DEFAULT).unwrap();
            assert_eq!(
                schema.is_valid(&written_value).is_ok(),
                schema.is_valid(&value).is_ok(),
                "{}",
                path.display()
            );
        }
    }
}

#[test]
fn invalid_yaml_fixtures_report_codes_paths_and_locations() {
    for path in files(&manifest_dir().join("tests/fixtures/yaml/invalid"), "yaml") {
        let loaded =
            dsl::from_str(&read(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let found: Vec<String> = match loaded.validate() {
            Ok(_) => panic!("{} validated", path.display()),
            Err(errors) => errors
                .iter()
                .map(|l| {
                    format!(
                        "{} {} {}:{}",
                        l.error.code, l.error.path, l.location.line, l.location.column
                    )
                })
                .collect(),
        };
        assert_eq!(found, expected(&path), "{}", path.display());
    }
}

#[test]
fn rejected_yaml_fixtures_fail_to_load_at_the_expected_place() {
    for path in files(&manifest_dir().join("tests/fixtures/yaml/rejected"), "yaml") {
        let e = match dsl::from_str(&read(&path)) {
            Ok(_) => panic!("{} loaded", path.display()),
            Err(e) => e,
        };
        let location = e.location().unwrap();
        let mut found = format!("{} {}:{}", e.kind(), location.line, location.column);
        if let Some(pointer) = e.pointer() {
            found.push(' ');
            found.push_str(pointer);
        }
        assert_eq!(vec![found], expected(&path), "{}: {e}", path.display());
    }
}

#[test]
fn schema_header_names_the_committed_schema() {
    let url = SCHEMA_HEADER
        .trim_end()
        .strip_prefix("# yaml-language-server: $schema=")
        .unwrap();
    assert!(
        url.ends_with(&format!("/schemas/policy/v{}.json", schema::CURRENT.major)),
        "{url}"
    );
    assert!(
        manifest_dir()
            .join("../../schemas/policy/v1.json")
            .is_file()
    );
}
