//! `cargo xtask check-manifests`: every member crate inherits its shared
//! package fields, lints and dependency versions from the workspace root.
//!
//! This keeps `[workspace.dependencies]` the single source of every version,
//! and stops a crate from quietly opting out of the workspace lints.

use toml::{Table, Value};

/// `[package]` fields that must be `{ workspace = true }`.
const INHERITED_FIELDS: &[&str] = &[
    "version",
    "edition",
    "rust-version",
    "license",
    "repository",
    "authors",
    "publish",
];

/// Includes the deprecated underscore spellings, which Cargo still accepts.
const DEPENDENCY_TABLES: &[&str] = &[
    "dependencies",
    "dev-dependencies",
    "dev_dependencies",
    "build-dependencies",
    "build_dependencies",
];

/// Keys a dependency entry may set next to `workspace = true`.
const ALLOWED_DEPENDENCY_KEYS: &[&str] = &["workspace", "features", "optional"];

/// Checks one member `Cargo.toml`. `path` is only used in messages.
pub fn check_member(path: &str, source: &str) -> Result<Vec<String>, String> {
    let manifest: Table = source
        .parse()
        .map_err(|e| format!("{path}: invalid TOML: {e}"))?;
    let mut violations = Vec::new();

    let package = manifest.get("package").and_then(Value::as_table);
    for field in INHERITED_FIELDS {
        if !package.and_then(|p| p.get(*field)).is_some_and(inherits) {
            violations.push(format!(
                "{path}: package.{field} must be `{{ workspace = true }}`"
            ));
        }
    }

    if !manifest.get("lints").is_some_and(inherits) {
        violations.push(format!(
            "{path}: [lints] must be exactly `workspace = true`"
        ));
    }

    let mut tables: Vec<(String, &Table)> = Vec::new();
    for name in DEPENDENCY_TABLES {
        if let Some(table) = manifest.get(*name).and_then(Value::as_table) {
            tables.push(((*name).to_owned(), table));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, spec) in targets {
            for name in DEPENDENCY_TABLES {
                if let Some(table) = spec.get(*name).and_then(Value::as_table) {
                    tables.push((format!("target.{target}.{name}"), table));
                }
            }
        }
    }
    for (table_name, table) in tables {
        for (dep, spec) in table {
            if !is_workspace_dependency(spec) {
                violations.push(format!(
                    "{path}: {table_name}.{dep} must use `{{ workspace = true }}` (only `features` and `optional` may be added); declare the version in the root [workspace.dependencies]"
                ));
            }
        }
    }
    Ok(violations)
}

/// `true` for `{ workspace = true }` with no other keys.
fn inherits(value: &Value) -> bool {
    value
        .as_table()
        .is_some_and(|t| t.len() == 1 && t.get("workspace").and_then(Value::as_bool) == Some(true))
}

fn is_workspace_dependency(spec: &Value) -> bool {
    let Some(table) = spec.as_table() else {
        // A bare version string such as `serde = "1"`.
        return false;
    };
    table.get("workspace").and_then(Value::as_bool) == Some(true)
        && table
            .keys()
            .all(|k| ALLOWED_DEPENDENCY_KEYS.contains(&k.as_str()))
}

#[cfg(test)]
mod tests {
    use super::check_member;

    const PACKAGE: &str = r#"
[package]
name = "example"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
publish.workspace = true

[lints]
workspace = true
"#;

    fn check(extra: &str) -> Vec<String> {
        check_member("x/Cargo.toml", &format!("{PACKAGE}{extra}")).unwrap()
    }

    #[test]
    fn fully_inherited_manifest_passes() {
        let v = check(
            r#"
[dependencies]
serde_json.workspace = true
palisade-core = { workspace = true, features = ["std"], optional = true }

[target.'cfg(windows)'.dependencies]
toml = { workspace = true }
"#,
        );
        assert_eq!(v, Vec::<String>::new());
    }

    #[test]
    fn bare_version_fails() {
        let v = check("[dependencies]\nserde = \"1\"\n");
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("dependencies.serde must use"), "{v:?}");
    }

    #[test]
    fn version_next_to_workspace_fails() {
        let v = check("[dev-dependencies]\nserde = { workspace = true, version = \"1\" }\n");
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("dev-dependencies.serde"), "{v:?}");
    }

    #[test]
    fn path_and_git_dependencies_fail() {
        let v = check(
            "[build-dependencies]\na = { path = \"../a\" }\nb = { git = \"https://example.invalid/b\" }\n",
        );
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn underscore_table_spellings_are_checked() {
        let v = check(
            "[dev_dependencies]\na = \"1\"\n[target.'cfg(unix)'.build_dependencies]\nb = \"1\"\n",
        );
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn target_specific_dependencies_are_checked() {
        let v = check("[target.'cfg(windows)'.dependencies]\nwindows-sys = \"0.61\"\n");
        assert_eq!(v.len(), 1);
        assert!(
            v[0].contains("target.cfg(windows).dependencies.windows-sys"),
            "{v:?}"
        );
    }

    #[test]
    fn own_package_fields_and_lints_fail() {
        let source = PACKAGE
            .replace("edition.workspace = true", "edition = \"2021\"")
            .replace(
                "[lints]\nworkspace = true",
                "[lints.rust]\nunsafe_code = \"allow\"",
            );
        let v = check_member("x/Cargo.toml", &source).unwrap();
        assert_eq!(
            v,
            [
                "x/Cargo.toml: package.edition must be `{ workspace = true }`",
                "x/Cargo.toml: [lints] must be exactly `workspace = true`",
            ]
        );
    }

    #[test]
    fn missing_package_fields_fail() {
        let v = check_member("x/Cargo.toml", "[package]\nname = \"x\"\n").unwrap();
        assert_eq!(v.len(), 8, "{v:?}");
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(check_member("x/Cargo.toml", "[package").is_err());
    }
}
