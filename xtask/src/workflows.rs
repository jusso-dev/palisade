//! `cargo xtask check-workflows`: the CI runner and action policy.
//!
//! Palisade CI runs on GitHub-hosted runners only. This check works from
//! allowlists rather than a list of forbidden services, so anything not
//! explicitly approved fails, including self-hosted runners, third-party or
//! cloud-managed build runners, and actions that hand the build to an
//! external service. For every workflow under `.github/workflows` it checks:
//!
//! - every job's `runs-on` is a label in [`ALLOWED_RUNNERS`]. The only
//!   expression allowed is `${{ matrix.<key> }}`, and then every value of that
//!   matrix key must itself be an allowed label. Arrays, runner groups and
//!   labels taken from inputs or variables fail.
//! - every step `uses:` names a repository in [`ALLOWED_ACTIONS`], pinned to
//!   a full 40-character commit SHA. Container actions fail.
//! - no job calls a reusable workflow (`jobs.<id>.uses`), local or remote.
//!   None are needed yet; allowing them safely means proving the called file
//!   is one this check also reads, which can wait until one is needed.
//! - there is a top-level `permissions:` block that grants nothing beyond
//!   `read` (`read-all`, `{}`, or a mapping whose values are `read` or
//!   `none`), so every job starts from least privilege. Jobs that need more
//!   ask for it themselves.
//! - `pull_request_target` is never used.
//! - `actions/checkout` sets `persist-credentials: false`.

use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader, yaml::Hash};

/// GitHub-hosted runner labels that jobs may use.
pub const ALLOWED_RUNNERS: &[&str] = &[
    "ubuntu-latest",
    "ubuntu-24.04",
    "windows-latest",
    "windows-2025",
    "windows-11-arm",
    "macos-latest",
    "macos-15",
];

/// `owner/repo` of every action that workflows may use. Adding one is a
/// reviewed change to this file.
pub const ALLOWED_ACTIONS: &[&str] = &[
    "actions/checkout",
    "Swatinem/rust-cache",
    "taiki-e/install-action",
];

/// Checks every `*.yml` and `*.yaml` file directly inside `dir`.
pub fn check_dir(dir: &Path) -> Result<Vec<String>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let is_yaml = path
            .extension()
            .is_some_and(|ext| ext == "yml" || ext == "yaml");
        if is_yaml {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(format!("no workflow files found in {}", dir.display()));
    }
    paths.sort();
    let mut violations = Vec::new();
    for path in paths {
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        violations.extend(check_workflow(&name, &source));
    }
    Ok(violations)
}

/// Checks the source of one workflow file. `name` is only used in messages.
pub fn check_workflow(name: &str, source: &str) -> Vec<String> {
    let docs = match YamlLoader::load_from_str(source) {
        Ok(docs) => docs,
        Err(e) => return vec![format!("{name}: invalid YAML: {e}")],
    };
    let [Yaml::Hash(workflow)] = docs.as_slice() else {
        return vec![format!("{name}: expected a single YAML mapping")];
    };
    let mut v = Vec::new();

    match get(workflow, "permissions") {
        None => v.push(format!(
            "{name}: missing top-level `permissions:` (use `contents: read`)"
        )),
        Some(permissions) if !is_read_only(permissions) => v.push(format!(
            "{name}: top-level `permissions:` must be read-only (`read-all`, or scopes set to `read` or `none`); grant writes per job"
        )),
        Some(_) => {}
    }

    if uses_pull_request_target(get(workflow, "on")) {
        v.push(format!(
            "{name}: the `pull_request_target` trigger is not allowed"
        ));
    }

    let Some(Yaml::Hash(jobs)) = get(workflow, "jobs") else {
        v.push(format!("{name}: missing `jobs:` mapping"));
        return v;
    };
    for (job_id, job) in jobs {
        let job_id = job_id.as_str().unwrap_or("?");
        let Yaml::Hash(job) = job else {
            v.push(format!("{name}: job `{job_id}` is not a mapping"));
            continue;
        };
        check_job(&format!("{name}: job `{job_id}`"), job, &mut v);
    }
    v
}

fn check_job(at: &str, job: &Hash, v: &mut Vec<String>) {
    match (get(job, "runs-on"), get(job, "uses")) {
        (Some(runs_on), None) => check_runs_on(at, runs_on, job, v),
        (None, Some(_)) => v.push(format!(
            "{at}: calling a reusable workflow (`jobs.<id>.uses`) is not allowed"
        )),
        _ => v.push(format!("{at}: needs exactly one of `runs-on` or `uses`")),
    }

    let Some(steps) = get(job, "steps") else {
        return;
    };
    let Yaml::Array(steps) = steps else {
        v.push(format!("{at}: `steps` is not a list"));
        return;
    };
    for (index, step) in steps.iter().enumerate() {
        let Some(uses) = step.as_hash().and_then(|s| get(s, "uses")) else {
            continue;
        };
        let at = format!("{at} step {}", index + 1);
        match uses.as_str() {
            Some(uses) => check_action(&at, uses, step, v),
            None => v.push(format!("{at}: `uses` is not a string")),
        }
    }
}

fn check_runs_on(at: &str, runs_on: &Yaml, job: &Hash, v: &mut Vec<String>) {
    let Some(label) = runs_on.as_str() else {
        v.push(format!(
            "{at}: `runs-on` must be a single GitHub-hosted runner label, not a list or runner group"
        ));
        return;
    };
    if let Some(key) = matrix_key(label) {
        for value in matrix_values(job, key) {
            match value {
                Some(label) if is_allowed_runner(label) => {}
                Some(label) => v.push(format!(
                    "{at}: matrix.{key} value `{label}` is not an allowed runner"
                )),
                None => v.push(format!(
                    "{at}: matrix.{key} must be a literal list of allowed runner labels"
                )),
            }
        }
    } else if !is_allowed_runner(label) {
        v.push(format!(
            "{at}: runner `{label}` is not allowed; use one of: {}",
            ALLOWED_RUNNERS.join(", ")
        ));
    }
}

fn is_allowed_runner(label: &str) -> bool {
    ALLOWED_RUNNERS.contains(&label)
}

/// `Some("os")` for exactly `${{ matrix.os }}` (spaces optional).
fn matrix_key(label: &str) -> Option<&str> {
    let inner = label.strip_prefix("${{")?.strip_suffix("}}")?.trim();
    let key = inner.strip_prefix("matrix.")?;
    let valid = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    valid.then_some(key)
}

/// Every value `matrix.<key>` can take. `None` marks a value that is not a
/// plain string, such as an expression that builds the matrix at run time.
/// A key that is missing from the matrix yields a single `None`.
fn matrix_values<'a>(job: &'a Hash, key: &str) -> Vec<Option<&'a str>> {
    let matrix = job
        .get(&key_of("strategy"))
        .and_then(|s| s.as_hash())
        .and_then(|s| get(s, "matrix"));
    let Some(Yaml::Hash(matrix)) = matrix else {
        return vec![None];
    };
    // GitHub resolves `matrix.<key>` case-insensitively, so `OS` and `os`
    // are the same key here.
    let same_key = |k: &Yaml| k.as_str().is_some_and(|k| k.eq_ignore_ascii_case(key));
    let mut values = Vec::new();
    for (_, items) in matrix.iter().filter(|(k, _)| same_key(k)) {
        match items {
            Yaml::Array(items) => values.extend(items.iter().map(Yaml::as_str)),
            _ => values.push(None),
        }
    }
    match get(matrix, "include") {
        Some(Yaml::Array(entries)) => {
            for entry in entries {
                let Some(entry) = entry.as_hash() else {
                    // An expression or other non-mapping entry: fail closed.
                    values.push(None);
                    continue;
                };
                for (_, value) in entry.iter().filter(|(k, _)| same_key(k)) {
                    values.push(value.as_str());
                }
            }
        }
        Some(_) => values.push(None),
        None => {}
    }
    if values.is_empty() {
        values.push(None);
    }
    values
}

fn check_action(at: &str, uses: &str, step: &Yaml, v: &mut Vec<String>) {
    let Some((action, reference)) = uses.split_once('@') else {
        v.push(format!(
            "{at}: `{uses}` must be `owner/repo@<full commit SHA>`"
        ));
        return;
    };
    // `owner/repo/path` actions belong to `owner/repo`.
    let repo: String = action.splitn(3, '/').take(2).collect::<Vec<_>>().join("/");
    if !ALLOWED_ACTIONS
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&repo))
    {
        v.push(format!(
            "{at}: action `{action}` is not allowed; allowed: {}",
            ALLOWED_ACTIONS.join(", ")
        ));
    }
    let pinned = reference.len() == 40
        && reference
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !pinned {
        v.push(format!(
            "{at}: `{uses}` must be pinned to a full 40-character commit SHA"
        ));
    }
    if repo.eq_ignore_ascii_case("actions/checkout") {
        let persist = step
            .as_hash()
            .and_then(|s| get(s, "with"))
            .and_then(|w| w.as_hash())
            .and_then(|w| get(w, "persist-credentials"));
        if !matches!(persist, Some(Yaml::Boolean(false))) {
            v.push(format!(
                "{at}: actions/checkout must set `persist-credentials: false`"
            ));
        }
    }
}

/// `true` for top-level permissions that grant no write scope.
fn is_read_only(permissions: &Yaml) -> bool {
    match permissions {
        Yaml::String(s) => s == "read-all",
        Yaml::Hash(scopes) => scopes
            .values()
            .all(|level| matches!(level.as_str(), Some("read" | "none"))),
        _ => false,
    }
}

fn uses_pull_request_target(on: Option<&Yaml>) -> bool {
    const TRIGGER: &str = "pull_request_target";
    match on {
        Some(Yaml::String(s)) => s == TRIGGER,
        Some(Yaml::Array(items)) => items.iter().any(|i| i.as_str() == Some(TRIGGER)),
        Some(Yaml::Hash(map)) => map.contains_key(&key_of(TRIGGER)),
        _ => false,
    }
}

fn key_of(key: &str) -> Yaml {
    Yaml::String(key.to_owned())
}

fn get<'a>(map: &'a Hash, key: &str) -> Option<&'a Yaml> {
    map.get(&key_of(key))
}

#[cfg(test)]
mod tests {
    use super::check_workflow;

    const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

    /// A workflow that follows every rule, with `{jobs}` spliced in.
    fn workflow(jobs: &str) -> String {
        format!(
            "name: t\non:\n  pull_request:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n{jobs}"
        )
    }

    fn job(runs_on: &str) -> String {
        format!("  build:\n    runs-on: {runs_on}\n    steps:\n      - run: cargo test\n")
    }

    fn check(source: &str) -> Vec<String> {
        check_workflow("t.yml", source)
    }

    #[test]
    fn compliant_workflow_passes() {
        let jobs = format!(
            "  build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
        include:
          - os: macos-latest
    runs-on: ${{{{ matrix.os }}}}
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
        with:
          persist-credentials: false
      - uses: Swatinem/rust-cache@{SHA}
      - run: cargo test
"
        );
        assert_eq!(check(&workflow(&jobs)), Vec::<String>::new());
    }

    #[test]
    fn this_repository_workflows_pass() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows");
        assert_eq!(super::check_dir(&dir).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn self_hosted_runner_fails() {
        let v = check(&workflow(&job("self-hosted")));
        assert_eq!(v.len(), 1);
        assert!(
            v[0].contains("runner `self-hosted` is not allowed"),
            "{v:?}"
        );
    }

    #[test]
    fn third_party_runner_label_fails() {
        let v = check(&workflow(&job("cloud-build-linux-large")));
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn runner_label_list_and_group_fail() {
        assert_eq!(check(&workflow(&job("[self-hosted, linux]"))).len(), 1);
        assert_eq!(check(&workflow(&job("{ group: builders }"))).len(), 1);
        // Even a list holding only an allowed label is rejected: lists select
        // runners by label intersection, which is how self-hosted pools work.
        assert_eq!(check(&workflow(&job("[ubuntu-latest]"))).len(), 1);
    }

    #[test]
    fn runner_from_inputs_or_variables_fails() {
        for expr in [
            "${{ inputs.runner }}",
            "${{ vars.RUNNER }}",
            "${{ github.event.inputs.os }}",
        ] {
            let v = check(&workflow(&job(&format!("\"{expr}\""))));
            assert_eq!(v.len(), 1, "{expr}: {v:?}");
        }
    }

    #[test]
    fn matrix_runner_values_are_checked() {
        let jobs = "  build:
    strategy:
      matrix:
        os: [ubuntu-latest, self-hosted]
        include:
          - os: my-runner
    runs-on: ${{ matrix.os }}
    steps: []
";
        let v = check(&workflow(jobs));
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn matrix_keys_match_case_insensitively() {
        let jobs = "  build:
    strategy:
      matrix:
        os: [ubuntu-latest]
        include:
          - OS: self-hosted
    runs-on: ${{ matrix.os }}
    steps: []
";
        let v = check(&workflow(jobs));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("self-hosted"), "{v:?}");
        let mixed = "  build:
    strategy:
      matrix:
        Os: [my-runner]
    runs-on: ${{ matrix.oS }}
    steps: []
";
        assert_eq!(check(&workflow(mixed)).len(), 1);
    }

    #[test]
    fn non_mapping_include_entry_fails() {
        let jobs = "  build:
    strategy:
      matrix:
        os: [ubuntu-latest]
        include:
          - ${{ fromJSON(vars.EXTRA) }}
    runs-on: ${{ matrix.os }}
    steps: []
";
        assert_eq!(check(&workflow(jobs)).len(), 1);
    }

    #[test]
    fn computed_or_missing_matrix_fails() {
        let computed = "  build:
    strategy:
      matrix: ${{ fromJSON(inputs.matrix) }}
    runs-on: ${{ matrix.os }}
    steps: []
";
        assert_eq!(check(&workflow(computed)).len(), 1);
        let computed_key = "  build:
    strategy:
      matrix:
        os: ${{ fromJSON(vars.OSES) }}
    runs-on: ${{ matrix.os }}
    steps: []
";
        assert_eq!(check(&workflow(computed_key)).len(), 1);
        assert_eq!(check(&workflow(&job("${{ matrix.os }}"))).len(), 1);
    }

    #[test]
    fn job_needs_runs_on_and_no_reusable_workflow() {
        assert_eq!(check(&workflow("  a:\n    steps: []\n")).len(), 1);
        for target in [
            "./.github/workflows/other.yml",
            "./.github/workflows/../evil.yml",
            "./.github/workflows/sub/evil.yml",
            "someone/repo/.github/workflows/x.yml@main",
        ] {
            let v = check(&workflow(&format!("  a:\n    uses: {target}\n")));
            assert_eq!(v.len(), 1, "{target}: {v:?}");
        }
    }

    #[test]
    fn unpinned_or_unknown_actions_fail() {
        let steps = |uses: &str| {
            workflow(&format!(
                "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {uses}\n"
            ))
        };
        assert_eq!(check(&steps("Swatinem/rust-cache@v2")).len(), 1);
        assert_eq!(
            check(&steps(&format!("Swatinem/rust-cache@{}", &SHA[..12]))).len(),
            1
        );
        assert_eq!(
            check(&steps(&format!("someone/build-service@{SHA}"))).len(),
            1
        );
        // Container actions and local actions have no `@<sha>` and fail.
        assert_eq!(check(&steps("docker://alpine:3")).len(), 1);
        assert_eq!(check(&steps("./.github/actions/local")).len(), 1);
        assert_eq!(
            check(&steps(&format!("docker://alpine@sha256:{SHA}"))).len(),
            2
        );
        // Sub-path actions are matched on their repository.
        assert_eq!(
            check(&steps(&format!("taiki-e/install-action/sub@{SHA}"))).len(),
            0
        );
    }

    #[test]
    fn checkout_must_not_persist_credentials() {
        let jobs = format!(
            "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{SHA}\n"
        );
        let v = check(&workflow(&jobs));
        assert_eq!(v.len(), 1);
        assert!(v[0].contains("persist-credentials"), "{v:?}");
    }

    #[test]
    fn missing_or_broad_permissions_fail() {
        let source = workflow(&job("ubuntu-latest"));
        let missing = source.replace("permissions:\n  contents: read\n", "");
        assert_eq!(check(&missing).len(), 1);
        let base = "permissions:\n  contents: read\n";
        for broad in [
            "permissions: write-all\n",
            "permissions:\n  contents: write\n",
            "permissions:\n  contents: read\n  id-token: write\n",
            "permissions:\n  contents:\n",
            "permissions: [read]\n",
        ] {
            let v = check(&source.replace(base, broad));
            assert_eq!(v.len(), 1, "{broad}: {v:?}");
        }
        for narrow in [
            "permissions: read-all\n",
            "permissions: {}\n",
            "permissions:\n  contents: none\n",
        ] {
            let v = check(&source.replace(base, narrow));
            assert_eq!(v, Vec::<String>::new(), "{narrow}");
        }
    }

    #[test]
    fn pull_request_target_fails_in_every_form() {
        let source = workflow(&job("ubuntu-latest"));
        let on_block = "on:\n  pull_request:\n  push:\n    branches: [main]\n";
        for on in [
            "on: pull_request_target\n",
            "on: [push, pull_request_target]\n",
            "on:\n  pull_request_target:\n",
        ] {
            let v = check(&source.replace(on_block, on));
            assert_eq!(v.len(), 1, "{on}: {v:?}");
        }
    }

    #[test]
    fn yaml_anchors_are_resolved() {
        let jobs = "  a:\n    runs-on: &runner self-hosted\n    steps: []\n  b:\n    runs-on: *runner\n    steps: []\n";
        assert_eq!(check(&workflow(jobs)).len(), 2);
    }

    #[test]
    fn invalid_yaml_fails() {
        assert_eq!(check("jobs: [").len(), 1);
        assert_eq!(check("- a\n- b\n").len(), 1);
    }
}
