//! Generates `registry_gen.rs` and `events/REGISTRY.md` from
//! `events/registry.yaml`, and checks that the committed copies are current.
//!
//! Regenerate both after editing the registry:
//!
//! ```sh
//! PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry
//! ```

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use super::{Category, Description, FieldSet, SchemaVersion};

const REGISTRY: &str = include_str!("../../events/registry.yaml");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDoc {
    schema_version: SchemaVersion,
    types: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(rename = "type")]
    name: String,
    category: Category,
    severity: u8,
    required: Vec<FieldSet>,
    summarisable: bool,
    description: Description,
}

/// Reads and checks the registry. Panics with a message on any problem,
/// because this only runs in tests.
fn load() -> RegistryDoc {
    let value =
        palisade_policy::dsl::to_json_value(REGISTRY, &palisade_policy::dsl::Limits::DEFAULT)
            .unwrap_or_else(|e| panic!("events/registry.yaml: {e}"));
    let doc: RegistryDoc =
        serde_json::from_value(value).unwrap_or_else(|e| panic!("events/registry.yaml: {e}"));
    assert_eq!(
        doc.schema_version.major,
        super::CURRENT.major,
        "registry major version"
    );
    let mut names = BTreeSet::new();
    for entry in &doc.types {
        assert!(
            valid_name(&entry.name),
            "`{}` is not a dotted lowercase name",
            entry.name
        );
        assert!(
            names.insert(entry.name.as_str()),
            "`{}` is registered twice",
            entry.name
        );
        assert!(entry.severity <= 10, "`{}`: severity above 10", entry.name);
        let sets: BTreeSet<_> = entry.required.iter().collect();
        assert_eq!(
            sets.len(),
            entry.required.len(),
            "`{}`: a field set is listed twice",
            entry.name
        );
    }
    assert!(!doc.types.is_empty(), "the registry is empty");
    doc
}

/// `<area>.<what>`: two or more dot-separated words of lowercase letters,
/// digits and `_`, each starting with a letter.
fn valid_name(name: &str) -> bool {
    let words: Vec<&str> = name.split('.').collect();
    words.len() >= 2
        && words.iter().all(|w| {
            let mut bytes = w.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_lowercase())
                && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

/// `agent.clock_unsynced` becomes `AgentClockUnsynced`.
fn variant(name: &str) -> String {
    name.split(['.', '_'])
        .map(|w| {
            let mut chars = w.chars();
            chars.next().map_or_else(String::new, |c| {
                c.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect()
}

fn json_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        other => panic!("not a string enum: {other:?}"),
    }
}

/// `packaged_app` becomes `PackagedApp`.
fn rust_name(snake: &str) -> String {
    variant(snake)
}

fn rust_string(text: &str) -> String {
    format!("{text:?}")
}

fn generate_rust(doc: &RegistryDoc) -> String {
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(
        w,
        "// @generated from `events/registry.yaml` by `src/events/registry.rs`."
    );
    let _ = writeln!(w, "// Do not edit by hand. Regenerate with:");
    let _ = writeln!(
        w,
        "//   PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry"
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "use super::{{Category, FieldSet, Severity}};");
    let _ = writeln!(w);
    let _ = writeln!(w, "/// A registered event type. See `events/REGISTRY.md`.");
    let _ = writeln!(
        w,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]"
    );
    let _ = writeln!(w, "pub enum EventType {{");
    for e in &doc.types {
        let _ = writeln!(w, "    /// `{}`: {}", e.name, e.description);
        let _ = writeln!(w, "    {},", variant(&e.name));
    }
    let _ = writeln!(w, "}}");
    let _ = writeln!(w);
    let _ = writeln!(w, "impl EventType {{");
    let _ = writeln!(w, "    /// Every registered type, in registry order.");
    let _ = writeln!(w, "    pub const ALL: [Self; {}] = [", doc.types.len());
    for e in &doc.types {
        let _ = writeln!(w, "        Self::{},", variant(&e.name));
    }
    let _ = writeln!(w, "    ];");
    let mut method = |name: &str, doc_line: &str, ret: &str, body: &dyn Fn(&Entry) -> String| {
        let _ = writeln!(w);
        let _ = writeln!(w, "    /// {doc_line}");
        let _ = writeln!(w, "    #[must_use]");
        let _ = writeln!(w, "    pub const fn {name}(self) -> {ret} {{");
        let _ = writeln!(w, "        match self {{");
        for e in &doc.types {
            let _ = writeln!(w, "            Self::{} => {},", variant(&e.name), body(e));
        }
        let _ = writeln!(w, "        }}");
        let _ = writeln!(w, "    }}");
    };
    method("as_str", "The dotted name.", "&'static str", &|e| {
        rust_string(&e.name)
    });
    method(
        "category",
        "The category every event of this type has.",
        "Category",
        &|e| format!("Category::{}", rust_name(&json_name(&e.category))),
    );
    method(
        "default_severity",
        "The severity used when the producer has no better one.",
        "Severity",
        &|e| format!("Severity::clamped({})", e.severity),
    );
    method(
        "required",
        "The field sets every event of this type carries.",
        "&'static [FieldSet]",
        &|e| {
            let sets: Vec<String> = e
                .required
                .iter()
                .map(|s| format!("FieldSet::{}", rust_name(&json_name(s))))
                .collect();
            format!("&[{}]", sets.join(", "))
        },
    );
    method(
        "summarisable",
        "Whether allowed events of this type may be summarised (#197).",
        "bool",
        &|e| e.summarisable.to_string(),
    );
    method(
        "description",
        "One sentence about the type.",
        "&'static str",
        &|e| rust_string(e.description.as_str()),
    );
    let _ = writeln!(w, "}}");
    out
}

fn generate_markdown(doc: &RegistryDoc) -> String {
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "# Event types");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "<!-- @generated from `registry.yaml`. Do not edit by hand. Regenerate with `PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry`. -->"
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "Registry schema version {}.", doc.schema_version);
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "| Type | Category | Default severity | Required field sets | Summarisable | Description |"
    );
    let _ = writeln!(w, "|---|---|---|---|---|---|");
    for e in &doc.types {
        let required: Vec<String> = e
            .required
            .iter()
            .map(|s| format!("`{}`", s.as_str()))
            .collect();
        let required = if required.is_empty() {
            "none".to_owned()
        } else {
            required.join(", ")
        };
        let _ = writeln!(
            w,
            "| `{}` | `{}` | {} | {} | {} | {} |",
            e.name,
            json_name(&e.category),
            e.severity,
            required,
            if e.summarisable { "yes" } else { "no" },
            e.description
        );
    }
    out
}

fn check_or_bless(relative: &str, generated: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    if std::env::var_os("PALISADE_BLESS").is_some() {
        fs::write(&path, generated).unwrap();
        return;
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == generated,
        "{} is stale. Regenerate it with:\n  PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry",
        path.display()
    );
}

#[test]
fn registry_generated_files_are_current() {
    let doc = load();
    check_or_bless("src/events/registry_gen.rs", &generate_rust(&doc));
    check_or_bless("events/REGISTRY.md", &generate_markdown(&doc));
}

#[test]
fn registry_matches_generated_enum() {
    let doc = load();
    assert_eq!(doc.types.len(), super::EventType::ALL.len());
    for (entry, ty) in doc.types.iter().zip(super::EventType::ALL) {
        assert_eq!(entry.name, ty.as_str());
        assert_eq!(entry.category, ty.category());
        assert_eq!(entry.severity, ty.default_severity().get());
        assert_eq!(entry.required, ty.required());
        assert_eq!(entry.summarisable, ty.summarisable());
    }
}

#[test]
fn registry_has_the_execution_control_minimum() {
    for name in [
        "exec.decision",
        "library.decision",
        "driver.decision",
        "script.decision",
        "installer.decision",
        "packaged_app.decision",
        "com.decision",
        "policy.applied",
        "policy.failed",
        "policy.activated",
        "agent.health",
        "agent.started",
        "agent.stopped",
        "agent.tamper",
        "agent.throttled",
        "agent.dropped",
        "agent.clock_unsynced",
    ] {
        assert!(
            name.parse::<super::EventType>().is_ok(),
            "`{name}` is not registered"
        );
    }
}

#[test]
fn names_are_checked() {
    assert!(valid_name("exec.decision"));
    assert!(valid_name("agent.clock_unsynced"));
    assert!(valid_name("integrity.fim.changed"));
    for bad in [
        "exec",
        "Exec.decision",
        "exec..decision",
        ".exec",
        "exec.decision.",
        "exec.1x",
        "exec-x.y",
    ] {
        assert!(!valid_name(bad), "{bad}");
    }
    assert_eq!(variant("agent.clock_unsynced"), "AgentClockUnsynced");
    assert_eq!(variant("packaged_app.decision"), "PackagedAppDecision");
}
