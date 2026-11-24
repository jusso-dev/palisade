//! `cargo xtask check-manifests`: every member crate inherits its shared
//! package fields, lints and dependency versions from the workspace root.
//!
//! This keeps `[workspace.dependencies]` the single source of every version,
//! and stops a crate from quietly opting out of the workspace lints.
//!
//! It also checks the feature flag conventions in `docs/workspace.md`: the
//! `test-util` feature is never on by default and never enabled through a
//! normal or build dependency, so it cannot reach a release build. And it
//! checks every crate README ([`check_readme`]): the required sections are
//! present, and every feature the crate has is documented.

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

/// The test-only feature, which must never reach a release build.
const TEST_UTIL: &str = "test-util";

/// Dependency tables whose features reach release builds.
const RELEASE_DEPENDENCY_TABLES: &[&str] =
    &["dependencies", "build-dependencies", "build_dependencies"];

/// Sections every crate README must have, besides the purpose in its opening
/// paragraph.
pub const README_SECTIONS: &[&str] = &[
    "## Allowed dependencies",
    "## Platform support",
    "## Feature flags",
    "## Stability",
];

/// `test-util` is not on by default, and no normal or build dependency turns
/// it on. Dev-dependencies may.
pub fn check_test_util(path: &str, source: &str) -> Result<Vec<String>, String> {
    let manifest: Table = source
        .parse()
        .map_err(|e| format!("{path}: invalid TOML: {e}"))?;
    let mut v = Vec::new();
    let features = manifest.get("features").and_then(Value::as_table);
    if features
        .and_then(|f| f.get("default"))
        .is_some_and(turns_on_test_util)
    {
        v.push(format!(
            "{path}: the default features must not include `{TEST_UTIL}`"
        ));
    }
    let mut tables: Vec<(String, &Table)> = Vec::new();
    for name in RELEASE_DEPENDENCY_TABLES {
        if let Some(table) = manifest.get(*name).and_then(Value::as_table) {
            tables.push(((*name).to_owned(), table));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for (target, spec) in targets {
            for name in RELEASE_DEPENDENCY_TABLES {
                if let Some(table) = spec.get(*name).and_then(Value::as_table) {
                    tables.push((format!("target.{target}.{name}"), table));
                }
            }
        }
    }
    for (table_name, table) in tables {
        for (dep, spec) in table {
            if spec.get("features").is_some_and(enables_test_util) {
                v.push(format!(
                    "{path}: {table_name}.{dep} enables `{TEST_UTIL}`; only dev-dependencies may"
                ));
            }
        }
    }
    // Only `test-util` itself may turn on `test-util`: this crate's own
    // (`"test-util"`, which also covers `default` reaching it through another
    // feature) or a dependency's (`dep/test-util` or `dep?/test-util`).
    for (feature, enables) in features.into_iter().flatten() {
        if feature == TEST_UTIL || feature == "default" {
            continue;
        }
        if turns_on_test_util(enables) {
            v.push(format!(
                "{path}: feature `{feature}` enables `{TEST_UTIL}`; only `{TEST_UTIL}` itself may"
            ));
        }
    }
    Ok(v)
}

/// No entry in the root `[workspace.dependencies]` enables `test-util`:
/// members inherit those features in every dependency table, including
/// `[dependencies]`.
pub fn check_workspace_test_util(path: &str, source: &str) -> Result<Vec<String>, String> {
    let manifest: Table = source
        .parse()
        .map_err(|e| format!("{path}: invalid TOML: {e}"))?;
    let deps = manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(Value::as_table);
    Ok(deps
        .into_iter()
        .flatten()
        .filter(|(_, spec)| spec.get("features").is_some_and(enables_test_util))
        .map(|(dep, _)| {
            format!(
                "{path}: workspace.dependencies.{dep} enables `{TEST_UTIL}`; enable it in a member's [dev-dependencies] instead"
            )
        })
        .collect())
}

/// A feature list that turns on this crate's `test-util` or a dependency's
/// (`dep/test-util`, `dep?/test-util`).
fn turns_on_test_util(features: &Value) -> bool {
    features.as_array().into_iter().flatten().any(|e| {
        e.as_str().is_some_and(|e| {
            e == TEST_UTIL || e.split_once('/').is_some_and(|(_, f)| f == TEST_UTIL)
        })
    })
}

fn enables_test_util(features: &Value) -> bool {
    features
        .as_array()
        .into_iter()
        .flatten()
        .any(|f| f.as_str() == Some(TEST_UTIL))
}

/// Every feature a crate exposes: the keys of `[features]` except `default`,
/// plus optional dependencies that no feature refers to as `dep:<name>`
/// (Cargo turns those into features of the same name).
pub fn feature_names(path: &str, source: &str) -> Result<Vec<String>, String> {
    let manifest: Table = source
        .parse()
        .map_err(|e| format!("{path}: invalid TOML: {e}"))?;
    let features = manifest.get("features").and_then(Value::as_table);
    let mut names: Vec<String> = features
        .into_iter()
        .flatten()
        .map(|(k, _)| k.clone())
        .filter(|k| k != "default")
        .collect();
    let explicit_deps: Vec<&str> = features
        .into_iter()
        .flatten()
        .flat_map(|(_, enables)| enables.as_array().into_iter().flatten())
        .filter_map(|e| e.as_str()?.strip_prefix("dep:"))
        .collect();
    let mut tables: Vec<&Table> = DEPENDENCY_TABLES
        .iter()
        .filter_map(|name| manifest.get(*name).and_then(Value::as_table))
        .collect();
    if let Some(targets) = manifest.get("target").and_then(Value::as_table) {
        for spec in targets.values() {
            tables.extend(
                DEPENDENCY_TABLES
                    .iter()
                    .filter_map(|name| spec.get(*name).and_then(Value::as_table)),
            );
        }
    }
    for table in tables {
        for (dep, spec) in table {
            let optional = spec.get("optional").and_then(Value::as_bool) == Some(true);
            if optional && !explicit_deps.contains(&dep.as_str()) && !names.contains(dep) {
                names.push(dep.clone());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Checks a crate README: every section in [`README_SECTIONS`] is present,
/// and every feature in `features` is named in backticks in the
/// `## Feature flags` section.
pub fn check_readme(path: &str, readme: &str, features: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    for section in README_SECTIONS {
        if !readme.lines().any(|l| l.trim_end() == *section) {
            v.push(format!("{path}: missing section `{section}`"));
        }
    }
    let feature_section: String = readme
        .lines()
        .skip_while(|l| l.trim_end() != "## Feature flags")
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n");
    for feature in features {
        if !feature_section.contains(&format!("`{feature}`")) {
            v.push(format!(
                "{path}: feature `{feature}` is not documented under `## Feature flags`"
            ));
        }
    }
    v
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
    use super::{
        check_member, check_readme, check_test_util, check_workspace_test_util, feature_names,
    };

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
    fn test_util_must_not_reach_release_builds() {
        let ok = format!(
            "{PACKAGE}[features]\ndefault = [\"std\"]\nstd = []\ntest-util = [\"palisade-core/test-util\"]\n[dev-dependencies]\npalisade-core = {{ workspace = true, features = [\"test-util\"] }}\n"
        );
        assert_eq!(check_test_util("x", &ok).unwrap(), Vec::<String>::new());

        let bad = format!(
            "{PACKAGE}[features]\ndefault = [\"test-util\"]\ntest-util = []\nextra = [\"palisade-core?/test-util\"]\n[dependencies]\npalisade-core = {{ workspace = true, features = [\"test-util\"] }}\n[target.'cfg(windows)'.build-dependencies]\nhelper = {{ workspace = true, features = [\"test-util\"] }}\n"
        );
        let v = check_test_util("x", &bad).unwrap();
        assert_eq!(v.len(), 4, "{v:?}");
        assert!(v[0].contains("default features"), "{v:?}");
        assert!(v[1].contains("dependencies.palisade-core enables"), "{v:?}");
        assert!(
            v[2].contains("target.cfg(windows).build-dependencies.helper"),
            "{v:?}"
        );
        assert!(v[3].contains("feature `extra`"), "{v:?}");
    }

    #[test]
    fn test_util_cannot_be_reached_through_another_feature() {
        // `default` reaches `test-util` through `full`; `full` is reported.
        let source = format!(
            "{PACKAGE}[features]\ndefault = [\"full\"]\nfull = [\"std\", \"test-util\"]\nstd = []\ntest-util = []\n"
        );
        let v = check_test_util("x", &source).unwrap();
        assert_eq!(
            v,
            ["x: feature `full` enables `test-util`; only `test-util` itself may"]
        );
    }

    #[test]
    fn default_must_not_enable_a_dependency_test_util() {
        for default in ["palisade-core/test-util", "palisade-core?/test-util"] {
            let source = format!("{PACKAGE}[features]\ndefault = [\"{default}\"]\n");
            let v = check_test_util("x", &source).unwrap();
            assert_eq!(v.len(), 1, "{default}: {v:?}");
            assert!(v[0].contains("default features"), "{v:?}");
        }
    }

    #[test]
    fn workspace_dependencies_must_not_enable_test_util() {
        let source = "[workspace.dependencies]\nok = { version = \"1\", features = [\"std\"] }\nbad = { path = \"crates/bad\", features = [\"test-util\"] }\nplain = \"1\"\n";
        let v = check_workspace_test_util("Cargo.toml", source).unwrap();
        assert_eq!(v.len(), 1);
        assert!(
            v[0].starts_with("Cargo.toml: workspace.dependencies.bad enables"),
            "{v:?}"
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
        let root = std::fs::read_to_string(root).unwrap();
        assert_eq!(
            check_workspace_test_util("Cargo.toml", &root).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn feature_names_include_implicit_optional_dependencies() {
        let source = format!(
            "{PACKAGE}[features]\ndefault = [\"std\"]\nstd = []\nserde = [\"dep:serde\"]\n[dependencies]\nserde = {{ workspace = true, optional = true }}\nlog = {{ workspace = true, optional = true }}\nsha2 = {{ workspace = true }}\n"
        );
        assert_eq!(
            feature_names("x", &source).unwrap(),
            ["log", "serde", "std"]
        );
    }

    const README: &str = "# x\n\nPurpose.\n\n## Allowed dependencies\n\nNone.\n\n## Platform support\n\nAll.\n\n## Feature flags\n\n- `std` (default): std.\n\n## Stability\n\nUnstable.\n";

    #[test]
    fn complete_readme_passes() {
        assert_eq!(
            check_readme("x/README.md", README, &["std".to_owned()]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn undocumented_feature_and_missing_section_fail() {
        let readme = README.replace("## Platform support", "## Platforms");
        // `serde` appears in the file, but not in the feature section.
        let readme = format!("{readme}\n## Notes\n\n`serde` is planned.\n");
        let v = check_readme(
            "x/README.md",
            &readme,
            &["std".to_owned(), "serde".to_owned()],
        );
        assert_eq!(
            v,
            [
                "x/README.md: missing section `## Platform support`",
                "x/README.md: feature `serde` is not documented under `## Feature flags`",
            ]
        );
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(check_member("x/Cargo.toml", "[package").is_err());
    }
}
