//! Palisade repository automation. Run `cargo xtask help` for the command list.
//!
//! Each command checks one repository rule and exits non-zero on a violation,
//! so CI can run them as plain steps. The rules themselves live in the module
//! for each command, next to their unit tests.

#![forbid(unsafe_code)]

mod ci;
mod deps;
mod junit;
mod manifests;
mod unsafe_code;
mod workflows;

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const HELP: &str = "\
Usage: cargo xtask <command>

Commands:
  ci [--fast]      Run the checks from .github/workflows/ci.yml locally (--fast skips docs,
                   feature-powerset and msrv)
  check-deps       Enforce the allowed dependency directions between crates
  check-manifests  Enforce workspace inheritance of package fields, lints and dependency versions,
                   and that every crate README documents its features
  check-unsafe     Enforce the unsafe-code allowlist (unsafe-allowlist.txt, ADR 0011)
  check-workflows  Enforce the CI runner and action policy for .github/workflows,
                   and that nothing under .github names a cloud-managed build service
  test-summary <label> <junit.xml>
                   Summarise a nextest JUnit report for the GitHub job page
  help             Show this message
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, label, path] = args.as_slice() {
        if command == "test-summary" {
            return test_summary(label, Path::new(path));
        }
    }
    match args.as_slice() {
        [command] if command == "ci" => return run_ci(false),
        [command, fast] if command == "ci" && fast == "--fast" => return run_ci(true),
        _ => {}
    }
    let command = match args.as_slice() {
        [command] => command.as_str(),
        _ => "",
    };
    let result = match command {
        "check-deps" => run_check("check-deps", check_deps),
        "check-manifests" => run_check("check-manifests", check_manifests),
        "check-unsafe" => run_check("check-unsafe", check_unsafe),
        "check-workflows" => run_check("check-workflows", check_workflows),
        "help" | "--help" | "-h" => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprint!("{HELP}");
            return ExitCode::FAILURE;
        }
    };
    if result {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `cargo xtask ci`: the CI checks, run locally from the workspace root.
fn run_ci(fast: bool) -> ExitCode {
    let root = workspace_root();
    let rust_version = read(&root.join("Cargo.toml"))
        .and_then(|s| {
            s.parse::<toml::Table>()
                .map_err(|e| format!("Cargo.toml: invalid TOML: {e}"))
        })
        .and_then(|m| {
            m.get("workspace")
                .and_then(|w| w.get("package"))
                .and_then(|p| p.get("rust-version"))
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "Cargo.toml: no workspace.package.rust-version".to_owned())
        });
    match rust_version.and_then(|v| ci::run(&root, fast, &v)) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("ci: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Prints the Markdown summary of a nextest JUnit report to
/// `$GITHUB_STEP_SUMMARY` (or stdout outside GitHub Actions), and one error
/// annotation per failed test. The test step itself reports failure, so this
/// exits non-zero only when the report cannot be read or parsed. A missing
/// report (the tests did not build) is a warning, not an error.
fn test_summary(label: &str, path: &Path) -> ExitCode {
    if !path.exists() {
        println!(
            "::warning title=No test report::{} was not written; see the test step's log",
            path.display()
        );
        return ExitCode::SUCCESS;
    }
    let report = match read(path).and_then(|xml| junit::parse(&xml)) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("test-summary: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let markdown = junit::markdown(label, &report);
    match std::env::var_os("GITHUB_STEP_SUMMARY") {
        Some(summary) => {
            use std::io::Write as _;
            let written = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&summary)
                .and_then(|mut f| f.write_all(markdown.as_bytes()));
            if let Err(error) = written {
                eprintln!("test-summary: error: cannot write the step summary: {error}");
                return ExitCode::FAILURE;
            }
        }
        None => print!("{markdown}"),
    }
    for annotation in junit::annotations(&report) {
        println!("{annotation}");
    }
    ExitCode::SUCCESS
}

/// Runs one check and prints its outcome. Returns `true` when it passed.
fn run_check(name: &str, check: fn(&Path) -> Result<Vec<String>, String>) -> bool {
    match check(&workspace_root()) {
        Ok(violations) if violations.is_empty() => {
            println!("{name}: ok");
            true
        }
        Ok(violations) => {
            for violation in &violations {
                eprintln!("{name}: {violation}");
            }
            eprintln!("{name}: {} violation(s)", violations.len());
            false
        }
        Err(error) => {
            eprintln!("{name}: error: {error}");
            false
        }
    }
}

fn check_deps(root: &Path) -> Result<Vec<String>, String> {
    // `--all-features` and no `--filter-platform`, so optional and
    // Windows-only dependencies are part of the checked graph too.
    let metadata = cargo_metadata(root, &["--all-features"])?;
    deps::check(&metadata)
}

fn check_manifests(root: &Path) -> Result<Vec<String>, String> {
    let metadata = cargo_metadata(root, &["--no-deps"])?;
    let mut violations =
        manifests::check_workspace_test_util("Cargo.toml", &read(&root.join("Cargo.toml"))?)?;
    for path in deps::member_manifest_paths(&metadata)? {
        let path = PathBuf::from(path);
        let shown = path.display().to_string();
        let source = read(&path)?;
        violations.extend(manifests::check_member(&shown, &source)?);
        violations.extend(manifests::check_test_util(&shown, &source)?);
        let readme = path.with_file_name("README.md");
        if readme.exists() {
            violations.extend(manifests::check_readme(
                &readme.display().to_string(),
                &read(&readme)?,
                &manifests::feature_names(&shown, &source)?,
            ));
        } else {
            violations.push(format!("{}: missing", readme.display()));
        }
    }
    Ok(violations)
}

fn check_unsafe(root: &Path) -> Result<Vec<String>, String> {
    let (paths, mut violations) = unsafe_code::repository_files(root)?;
    let mut files = Vec::new();
    for path in &paths {
        if unsafe_code::is_rust_path(path) {
            files.push((path.clone(), read(&root.join(path))?));
        }
    }
    let allowlist = unsafe_code::parse_allowlist(&read(&root.join("unsafe-allowlist.txt"))?);
    violations.extend(unsafe_code::check_files(&files, &allowlist));

    // Library and binary roots of the crates with no allowlisted module.
    let metadata = cargo_metadata(root, &["--no-deps"])?;
    for (name, kind, src_path) in deps::member_targets(&metadata)? {
        if !unsafe_code::FORBID_AT_ROOT.contains(&name.as_str()) {
            continue;
        }
        let forbids = unsafe_code::forbids_unsafe_code(&read(Path::new(&src_path))?)
            .map_err(|e| format!("{src_path}: cannot tokenise: {e}"))?;
        if !forbids {
            violations.push(format!(
                "{src_path}: the {kind} root of {name} must start with #![forbid(unsafe_code)] (ADR 0011)"
            ));
        }
    }

    violations.extend(unsafe_code::check_workspace_lint(&read(
        &root.join("Cargo.toml"),
    )?)?);
    // Cargo reads `.cargo/config.toml` and `.cargo/config` from the build
    // directory and every parent, so check them wherever they are.
    for path in &paths {
        if unsafe_code::is_cargo_config_path(path) {
            violations.extend(unsafe_code::check_cargo_config(
                path,
                &read(&root.join(path))?,
            ));
        }
    }
    Ok(violations)
}

fn check_workflows(root: &Path) -> Result<Vec<String>, String> {
    let github = root.join(".github");
    let mut violations = workflows::check_dir(&github.join("workflows"))?;
    violations.extend(workflows::check_terms(&github)?);
    Ok(violations)
}

/// The repository root: this crate lives in `<root>/xtask`.
fn workspace_root() -> PathBuf {
    let xtask_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask_dir.parent().unwrap_or(xtask_dir).to_path_buf()
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn cargo_metadata(root: &Path, extra_args: &[&str]) -> Result<serde_json::Value, String> {
    // `cargo run` sets CARGO to the cargo binary that launched us.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
        .args(extra_args)
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("cannot parse cargo metadata output: {e}"))
}
