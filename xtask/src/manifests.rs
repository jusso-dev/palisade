//! `cargo xtask check-manifests`: every member crate inherits its shared
//! package fields, lints and dependency versions from the workspace root.
//!
//! This keeps `[workspace.dependencies]` the single source of every version,
//! and stops a crate from quietly opting out of the workspace lints.
//!
//! It also checks the feature flag conventions in `docs/workspace.md`: the
//! `test-util` feature is never on by default and never enabled through a
//! normal or build dependency, so no ordinary build turns it on. It does not
//! see build commands: `--features test-util` or `--all-features` still can.
//! And it checks every crate README ([`check_readme`]): it has no HTML
//! comments, it opens with a purpose paragraph, the required sections are
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
    // `test-util/<feature>` also turns on this crate's own `test-util`
    // feature, if it has one, explicit or implicit.
    let has_own = features.is_some_and(|f| f.contains_key(TEST_UTIL))
        || implicit_features(&manifest).iter().any(|f| f == TEST_UTIL);
    let turns_on_test_util = |enables: &Value| turns_on_test_util(enables, has_own);
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
    // feature, or `test-util/<feature>` when this crate has a `test-util`
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
/// (`dep/test-util`, `dep?/test-util`). `has_own` is `true` when this crate
/// has a `test-util` feature, declared in `[features]` or implicit from an
/// optional dependency named `test-util`: then `test-util/<feature>` turns
/// it on too, because for a non-weak `dep/feature` Cargo enables the
/// dependency and this crate's feature of the same name. (`test-util?/...`
/// does neither.)
fn turns_on_test_util(features: &Value, has_own: bool) -> bool {
    features.as_array().into_iter().flatten().any(|e| {
        e.as_str().is_some_and(|e| {
            e == TEST_UTIL
                || e.split_once('/')
                    .is_some_and(|(dep, f)| f == TEST_UTIL || (has_own && dep == TEST_UTIL))
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
    let mut names: Vec<String> = manifest
        .get("features")
        .and_then(Value::as_table)
        .into_iter()
        .flatten()
        .map(|(k, _)| k.clone())
        .filter(|k| k != "default")
        .collect();
    for name in implicit_features(&manifest) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Optional dependencies that no feature refers to as `dep:<name>`, which
/// Cargo turns into features of the same name.
fn implicit_features(manifest: &Table) -> Vec<String> {
    let features = manifest.get("features").and_then(Value::as_table);
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
    let mut names: Vec<String> = Vec::new();
    for table in tables {
        for (dep, spec) in table {
            let optional = spec.get("optional").and_then(Value::as_bool) == Some(true);
            if optional && !explicit_deps.contains(&dep.as_str()) && !names.contains(dep) {
                names.push(dep.clone());
            }
        }
    }
    names
}

/// Checks a crate README: it has no HTML comment, it states the crate's
/// purpose in a paragraph before its first `## ` section, every section in
/// [`README_SECTIONS`] is present, and every feature in `features` is named
/// in backticks in the `## Feature flags` section.
///
/// The rendered page hides a comment, so a section, paragraph or feature
/// name inside one must not count. Where a comment starts and ends depends on
/// the whole Markdown block structure (a `<!--` in a code span or fence is
/// text, one in a list item or quote can span lines), which these line-based
/// checks do not model. So any `<!--` is rejected, and the other checks
/// read the text as written. A README that must show the characters can
/// write them as `&lt;!--`.
pub fn check_readme(path: &str, readme: &str, features: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(line) = readme.lines().position(|l| l.contains("<!--")) {
        v.push(format!(
            "{path}:{}: HTML comments are not allowed in a crate README; check-manifests cannot tell what they hide",
            line + 1
        ));
    }
    if !has_purpose_paragraph(readme) {
        v.push(format!(
            "{path}: missing the purpose paragraph before the first `## ` section"
        ));
    }
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

/// Some text, other than headings and HTML comments, before the first `## `
/// line. ([`check_readme`] rejects any comment anyway; ignoring them here
/// keeps this message about the paragraph.)
fn has_purpose_paragraph(readme: &str) -> bool {
    let intro: Vec<&str> = readme
        .lines()
        .take_while(|l| !l.starts_with("## "))
        .collect();
    let mut intro = intro.join("\n");
    while let Some(start) = intro.find("<!--") {
        let end = intro[start..]
            .find("-->")
            .map_or(intro.len(), |e| start + e + 3);
        intro.replace_range(start..end, "");
    }
    intro
        .lines()
        .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
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
    fn default_must_not_forward_to_an_own_test_util_feature() {
        // An optional dependency named `test-util`, with no `dep:test-util`,
        // is this crate's implicit `test-util` feature; `test-util/std`
        // enables it. It enables an explicit `test-util` feature too.
        let dep = "[dependencies]\ntest-util = { workspace = true, optional = true }\n";
        for features in [
            "default = [\"test-util/std\"]",
            "extra = [\"test-util/std\"]",
            "default = [\"test-util/std\"]\ntest-util = [\"dep:test-util\"]",
            "extra = [\"test-util/std\"]\ntest-util = []\nhelpers = [\"dep:test-util\"]",
        ] {
            let source = format!("{PACKAGE}[features]\n{features}\n{dep}");
            let v = check_test_util("x", &source).unwrap();
            assert_eq!(v.len(), 1, "{features}: {v:?}");
        }
        // `?` does not enable the dependency, and with `dep:test-util` and no
        // `test-util` feature, `test-util/std` only enables the dependency's
        // `std`.
        for features in [
            "default = [\"test-util?/std\"]",
            "default = [\"test-util/std\"]\nhelpers = [\"dep:test-util\"]",
        ] {
            let source = format!("{PACKAGE}[features]\n{features}\n{dep}");
            assert_eq!(
                check_test_util("x", &source).unwrap(),
                Vec::<String>::new(),
                "{features}"
            );
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
    fn readme_without_a_purpose_paragraph_fails() {
        // A crate with no features still needs its purpose stated.
        let only_headings = README.replace("Purpose.\n\n", "### Overview\n\n");
        assert_eq!(
            check_readme("x/README.md", &only_headings, &[]),
            ["x/README.md: missing the purpose paragraph before the first `## ` section"]
        );
        // A comment is not a purpose paragraph (and is reported itself).
        let only_comment = README.replace("Purpose.\n\n", "<!-- TODO -->\n### Overview\n\n");
        assert_eq!(
            check_readme("x/README.md", &only_comment, &[]),
            [
                "x/README.md:3: HTML comments are not allowed in a crate README; check-manifests cannot tell what they hide",
                "x/README.md: missing the purpose paragraph before the first `## ` section",
            ]
        );
        assert_eq!(
            check_readme("x/README.md", README, &[]),
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
    fn html_comments_are_rejected() {
        let std = ["std".to_owned()];
        let comment = |l: usize| {
            format!(
                "x/README.md:{l}: HTML comments are not allowed in a crate README; check-manifests cannot tell what they hide"
            )
        };
        // A section that exists only inside a comment.
        let hidden = README.replace("## Stability", "<!--\n## Stability\n-->");
        assert_eq!(check_readme("x/README.md", &hidden, &std), [comment(17)]);
        // A feature named only inside a comment.
        let feature = README.replace("- `std` (default): std.", "<!-- Document `std` here -->");
        assert_eq!(check_readme("x/README.md", &feature, &std), [comment(15)]);
        // A commented-out heading before the purpose paragraph.
        let draft = README.replace("Purpose.", "<!--\n## Draft\n-->\n\nPurpose.");
        assert_eq!(check_readme("x/README.md", &draft, &std)[0], comment(3));
        // Every place a comment can hide: in a list item, a quote, a code
        // span, mid-line, empty, unterminated.
        for text in [
            "- `std` (default): std. <!--\n  `serde`\n-->",
            "> <!--\n> `serde`\n> -->",
            "- `std` (default): std. `<!--`",
            "- `std` <!-->",
            "<!-- ## Stability",
        ] {
            let readme = README.replace("- `std` (default): std.", text);
            let v = check_readme("x/README.md", &readme, &std);
            assert!(v.contains(&comment(15)), "{text}: {v:?}");
        }
        // The escaped form is plain text.
        let escaped = README.replace("Unstable.", "Unstable. Write `&lt;!--` to show it.");
        assert_eq!(
            check_readme("x/README.md", &escaped, &std),
            Vec::<String>::new()
        );
    }

    #[test]
    fn invalid_toml_is_an_error() {
        assert!(check_member("x/Cargo.toml", "[package").is_err());
    }
}
