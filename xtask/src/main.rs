//! Palisade repository automation. Run `cargo xtask help` for the command list.
//!
//! Each command checks one repository rule and exits non-zero on a violation,
//! so CI can run them as plain steps. The rules themselves live in the module
//! for each command, next to their unit tests.

mod deps;
mod manifests;
mod workflows;

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const HELP: &str = "\
Usage: cargo xtask <command>

Commands:
  check-deps       Enforce the allowed dependency directions between crates
  check-manifests  Enforce workspace inheritance of package fields, lints and dependency versions
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
        violations.extend(manifests::check_member(
            &path.display().to_string(),
            &read(&path)?,
        )?);
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
