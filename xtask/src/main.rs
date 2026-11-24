//! Palisade repository automation. Run `cargo xtask help` for the command list.
//!
//! Each command checks one repository rule and exits non-zero on a violation,
//! so CI can run them as plain steps. The rules themselves live in the module
//! for each command, next to their unit tests.

#![forbid(unsafe_code)]

mod deps;
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
  check-deps       Enforce the allowed dependency directions between crates
  check-manifests  Enforce workspace inheritance of package fields, lints and dependency versions,
                   and that every crate README documents its features
  check-unsafe     Enforce the unsafe-code allowlist (unsafe-allowlist.txt, ADR 0011)
  check-workflows  Enforce the CI runner and action policy for .github/workflows
  help             Show this message
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
    let mut violations = Vec::new();
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
    let mut violations = Vec::new();
    let mut files = Vec::new();
    for path in unsafe_code::rust_files(root)? {
        let source = read(&root.join(&path))?;
        files.push((path, source));
    }
    let allowlist = unsafe_code::parse_allowlist(&read(&root.join("unsafe-allowlist.txt"))?);
    violations.extend(unsafe_code::check_files(&files, &allowlist));

    // Library and binary roots of the crates with no allowlisted module.
    let metadata = cargo_metadata(root, &["--no-deps"])?;
    for (name, kind, src_path) in deps::member_targets(&metadata)? {
        if !unsafe_code::FORBID_AT_ROOT.contains(&name.as_str()) {
            continue;
        }
        if !unsafe_code::forbids_unsafe_code(&read(Path::new(&src_path))?) {
            violations.push(format!(
                "{src_path}: the {kind} root of {name} must have #![forbid(unsafe_code)] (ADR 0011)"
            ));
        }
    }

    violations.extend(unsafe_code::check_workspace_lint(&read(
        &root.join("Cargo.toml"),
    )?)?);
    let config = root.join(".cargo").join("config.toml");
    if config.exists() {
        violations.extend(unsafe_code::check_cargo_config(
            ".cargo/config.toml",
            &read(&config)?,
        ));
    }
    Ok(violations)
}

fn check_workflows(root: &Path) -> Result<Vec<String>, String> {
    workflows::check_dir(&root.join(".github").join("workflows"))
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
