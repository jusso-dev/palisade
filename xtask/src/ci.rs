//! `cargo xtask ci [--fast]`: runs the checks from `.github/workflows/ci.yml`
//! locally, with the same commands.
//!
//! [`STEPS`] lists every command. A unit test compares it with the `cargo`
//! commands in `ci.yml` and fails if one has a command the other lacks, so
//! the two cannot drift. Jobs that differ only by runner (the OS matrix) run
//! once, on the local machine.

use std::process::Command;

/// One local step: a CI command and the external tool it needs, if any.
#[derive(Debug)]
pub struct Step {
    /// The CI job this step comes from.
    pub job: &'static str,
    /// The command, exactly as `ci.yml` runs it.
    pub command: &'static str,
    /// Extra environment, as set on the CI job.
    pub env: &'static [(&'static str, &'static str)],
    /// The tool needed beyond the pinned toolchain, with how to install it.
    pub tool: Option<Tool>,
    /// Skipped by `--fast`.
    pub slow: bool,
}

/// An external tool: the command that proves it is installed, and the
/// install command for the version CI uses.
#[derive(Debug, Clone, Copy)]
pub struct Tool {
    pub check: &'static [&'static str],
    pub install: &'static str,
}

const NEXTEST: Tool = Tool {
    check: &["cargo", "nextest", "--version"],
    install: "cargo install --locked cargo-nextest@0.9.152",
};
const DENY: Tool = Tool {
    check: &["cargo", "deny", "--version"],
    install: "cargo install --locked cargo-deny@0.22.0",
};
const AUDIT: Tool = Tool {
    check: &["cargo", "audit", "--version"],
    install: "cargo install --locked cargo-audit@0.23.0",
};
const VET: Tool = Tool {
    check: &["cargo", "vet", "--version"],
    install: "cargo install --locked cargo-vet@0.10.3",
};
const HACK: Tool = Tool {
    check: &["cargo", "hack", "--version"],
    install: "cargo install --locked cargo-hack@0.6.46",
};
const ACTIONLINT: Tool = Tool {
    check: &["actionlint", "-version"],
    install: "see https://github.com/rhysd/actionlint/releases (CI uses 1.7.12)",
};
const ZIZMOR: Tool = Tool {
    check: &["zizmor", "--version"],
    install: "cargo install --locked zizmor@1.33.1",
};

const fn step(job: &'static str, command: &'static str) -> Step {
    Step {
        job,
        command,
        env: &[],
        tool: None,
        slow: false,
    }
}

/// Every local step, in CI job order. The MSRV check is added by [`run`],
/// because its toolchain comes from `Cargo.toml`.
pub const STEPS: &[Step] = &[
    step("fmt", "cargo fmt --all --check"),
    step(
        "clippy",
        "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
    ),
    step(
        "clippy",
        "cargo clippy -p palisade-core -p palisade-driver --no-default-features --all-targets --locked -- -D warnings",
    ),
    step(
        "clippy",
        "cargo clippy -p palisade-core --no-default-features --features schema --all-targets --locked -- -D warnings",
    ),
    Step {
        tool: Some(NEXTEST),
        ..step(
            "test",
            "cargo nextest run --workspace --all-features --locked --profile ci",
        )
    },
    step(
        "test",
        "cargo test --workspace --all-features --locked --doc",
    ),
    Step {
        env: &[("RUSTDOCFLAGS", "-D warnings")],
        slow: true,
        ..step(
            "docs",
            "cargo doc --workspace --no-deps --all-features --locked",
        )
    },
    step("deps", "cargo xtask check-deps"),
    step("deps", "cargo xtask check-manifests"),
    step("deps", "cargo xtask check-unsafe"),
    Step {
        tool: Some(DENY),
        ..step("deps", "cargo deny --locked check")
    },
    Step {
        tool: Some(AUDIT),
        ..step("deps", "cargo audit")
    },
    Step {
        tool: Some(VET),
        ..step("supply-chain", "cargo vet --locked")
    },
    step("supply-chain", "cargo xtask check-supply-chain"),
    Step {
        tool: Some(HACK),
        slow: true,
        ..step(
            "feature-powerset",
            "cargo hack check --each-feature --all-targets --locked -p palisade-core -p palisade-fileid -p palisade-policy -p palisade-proto -p palisade-server -p palisade-cli -p palisade-console",
        )
    },
    step("runner-guard", "cargo xtask check-workflows"),
    Step {
        tool: Some(ACTIONLINT),
        ..step("workflow-lint", "actionlint -color")
    },
    Step {
        tool: Some(ZIZMOR),
        ..step("workflow-lint", "zizmor --offline .github/workflows")
    },
];

/// The MSRV toolchain name for `rust-version` (`1.85` becomes `1.85.0`, as
/// the `msrv` CI job installs it).
pub fn msrv_toolchain(rust_version: &str) -> String {
    if rust_version.split('.').count() == 2 {
        format!("{rust_version}.0")
    } else {
        rust_version.to_owned()
    }
}

/// The MSRV step's command line for a toolchain such as `1.85.0`.
pub fn msrv_command(toolchain: &str) -> String {
    format!("cargo +{toolchain} check --workspace --all-targets --all-features --locked")
}

/// A step ready to run: its command line is built at run time for MSRV.
struct Planned {
    job: &'static str,
    command: String,
    env: &'static [(&'static str, &'static str)],
    /// The command that proves the needed tool is installed, and how to
    /// install it.
    needs: Option<(Vec<String>, String)>,
}

/// Runs the selected steps from `root`. Every step runs even after one
/// fails, as in CI. Returns `true` if all passed.
pub fn run(root: &std::path::Path, fast: bool, rust_version: &str) -> Result<bool, String> {
    let toolchain = msrv_toolchain(rust_version);
    let mut selected: Vec<Planned> = STEPS
        .iter()
        .filter(|s| !(fast && s.slow))
        .map(|s| Planned {
            job: s.job,
            command: s.command.to_owned(),
            env: s.env,
            needs: s.tool.map(|t| {
                (
                    t.check.iter().map(|w| (*w).to_owned()).collect(),
                    t.install.to_owned(),
                )
            }),
        })
        .collect();
    if !fast {
        selected.push(Planned {
            job: "msrv",
            command: msrv_command(&toolchain),
            env: &[],
            needs: Some((
                vec![
                    "cargo".to_owned(),
                    format!("+{toolchain}"),
                    "--version".to_owned(),
                ],
                format!("rustup toolchain install {toolchain} --profile minimal"),
            )),
        });
    }

    // Find every missing tool first, so one run lists them all.
    let mut missing = Vec::new();
    for step in &selected {
        let Some((check, install)) = &step.needs else {
            continue;
        };
        if !succeeds(check) {
            missing.push(format!("  {}\n    needs: {install}", step.command));
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "missing tools; install them, or run `cargo xtask ci --fast` to skip the slow steps:\n{}",
            missing.join("\n")
        ));
    }

    let mut failed = Vec::new();
    for step in &selected {
        let Planned {
            job, command, env, ..
        } = step;
        println!("ci: [{job}] {command}");
        let mut words = command.split(' ');
        let program = words.next().unwrap_or_default();
        let status = Command::new(program)
            .args(words)
            .envs(env.iter().copied())
            .current_dir(root)
            .status()
            .map_err(|e| format!("cannot run `{command}`: {e}"))?;
        if !status.success() {
            failed.push(format!("[{job}] {command}"));
        }
    }
    if failed.is_empty() {
        println!("ci: all {} steps passed", selected.len());
        Ok(true)
    } else {
        for step in &failed {
            eprintln!("ci: FAILED {step}");
        }
        eprintln!("ci: {} of {} steps failed", failed.len(), selected.len());
        Ok(false)
    }
}

fn succeeds(command: &[String]) -> bool {
    let Some((program, args)) = command.split_first() else {
        return false;
    };
    Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use yaml_rust2::{Yaml, YamlLoader};

    /// Every `run:` command of `ci.yml`, with folded lines joined, as
    /// `(job, command)`.
    fn ci_yml_commands() -> Vec<(String, String)> {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let source = std::fs::read_to_string(path).unwrap();
        let docs = YamlLoader::load_from_str(&source).unwrap();
        let mut commands = Vec::new();
        for (job, spec) in docs[0]["jobs"].as_hash().unwrap() {
            let job = job.as_str().unwrap().to_owned();
            let Yaml::Array(steps) = &spec["steps"] else {
                continue;
            };
            for step in steps {
                if let Some(run) = step["run"].as_str() {
                    let command = run.split_whitespace().collect::<Vec<_>>().join(" ");
                    commands.push((job.clone(), command));
                }
            }
        }
        commands
    }

    /// CI commands that are not checks, or that only make sense on a runner.
    fn is_runner_only(command: &str) -> bool {
        command.starts_with("rustup ")
            || command.starts_with("grep ")
            || command.starts_with("cargo xtask test-summary ")
            || command.starts_with("cargo xtask deps-report ")
            || command.starts_with("archive=")
            || command.starts_with("echo ")
            || command.starts_with("exit ")
    }

    #[test]
    fn steps_match_ci_yml_exactly() {
        let mut ci: Vec<String> = ci_yml_commands()
            .into_iter()
            .map(|(job, command)| {
                // The MSRV job reads its toolchain from an env variable.
                let command = command.replace("cargo \"+$MSRV\" check", "cargo +$MSRV check");
                // actionlint runs from where the job downloaded it.
                let command = command.replace("\"$RUNNER_TEMP/actionlint\"", "actionlint");
                format!("[{job}] {command}")
            })
            .filter(|c| !is_runner_only(c.split_once("] ").unwrap().1))
            .collect();
        let mut local: Vec<String> = STEPS
            .iter()
            .map(|s| format!("[{}] {}", s.job, s.command))
            .chain([format!("[msrv] {}", msrv_command("$MSRV"))])
            .collect();
        ci.sort();
        ci.dedup();
        local.sort();
        assert_eq!(
            local, ci,
            "xtask/src/ci.rs STEPS and .github/workflows/ci.yml must run the same commands"
        );
    }

    #[test]
    fn steps_set_the_same_env_as_their_ci_job() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let docs_env = &docs[0]["jobs"]["docs"]["env"]["RUSTDOCFLAGS"];
        let step = STEPS.iter().find(|s| s.job == "docs").unwrap();
        assert_eq!(step.env, [("RUSTDOCFLAGS", docs_env.as_str().unwrap())]);
    }

    #[test]
    fn install_hints_use_the_ci_tool_versions() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let source = std::fs::read_to_string(path).unwrap();
        for tool in [NEXTEST, DENY, AUDIT, VET, HACK, ZIZMOR] {
            let pinned = tool.install.rsplit(' ').next().unwrap();
            assert!(source.contains(pinned), "ci.yml does not install {pinned}");
        }
        assert!(source.contains("ACTIONLINT_VERSION: \"1.7.12\""));
    }

    #[test]
    fn msrv_toolchain_matches_the_ci_job() {
        assert_eq!(msrv_toolchain("1.85"), "1.85.0");
        assert_eq!(msrv_toolchain("1.85.1"), "1.85.1");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
        let manifest: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
        let rust_version = manifest["workspace"]["package"]["rust-version"]
            .as_str()
            .unwrap();
        let ci = ci_yml_commands();
        let ci_source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml"),
        )
        .unwrap();
        assert!(ci.iter().any(|(job, _)| job == "msrv"));
        assert!(ci_source.contains(&format!("MSRV: \"{}\"", msrv_toolchain(rust_version))));
    }

    #[test]
    fn fast_skips_only_slow_steps() {
        let slow: Vec<&str> = STEPS.iter().filter(|s| s.slow).map(|s| s.job).collect();
        assert_eq!(slow, ["docs", "feature-powerset"]);
    }
}
