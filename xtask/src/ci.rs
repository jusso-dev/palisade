//! `cargo xtask ci [--fast]`: runs the checks from `.github/workflows/ci.yml`
//! locally, with the same commands.
//!
//! [`STEPS`] lists every command. A unit test compares it with the `cargo`
//! commands in `ci.yml` and fails if one has a command the other lacks, so
//! the two cannot drift. Jobs that differ only by runner (the OS matrix) run
//! once, on the local machine, and the sharded `fuzz` job runs unsharded:
//! every target, once.

use std::process::Command;

use crate::tools::{self, Probe, ProcessProbe, Status};

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
    /// An environment variable the step needs from the developer's
    /// environment. Without it the step is skipped with a note, as the
    /// tests it runs would skip themselves.
    pub needs_env: Option<&'static str>,
    /// The only OS family the step runs on, as `std::env::consts::FAMILY`
    /// or `OS` names it (`windows`, `linux`). Elsewhere it is skipped with
    /// a note, as CI runs it only on that runner.
    pub only_on: Option<&'static str>,
}

/// Where the `postgres` job's tests find a disposable Postgres superuser
/// connection.
pub const POSTGRES_URL: &str = "PALISADE_TEST_DATABASE_ADMIN_URL";

/// An external tool: the command that proves it is installed, the version
/// CI uses (when its version command prints one to compare), and the
/// install command for that version.
#[derive(Debug, Clone, Copy)]
pub struct Tool {
    pub check: &'static [&'static str],
    pub version: Option<&'static str>,
    pub install: &'static str,
}

const NEXTEST: Tool = Tool {
    check: &["cargo", "nextest", "--version"],
    version: Some("0.9.152"),
    install: "cargo install --locked cargo-nextest@0.9.152",
};
const DENY: Tool = Tool {
    check: &["cargo", "deny", "--version"],
    version: Some("0.22.0"),
    install: "cargo install --locked cargo-deny@0.22.0",
};
const AUDIT: Tool = Tool {
    check: &["cargo", "audit", "--version"],
    version: Some("0.23.0"),
    install: "cargo install --locked cargo-audit@0.23.0",
};
const VET: Tool = Tool {
    check: &["cargo", "vet", "--version"],
    version: Some("0.10.3"),
    install: "cargo install --locked cargo-vet@0.10.3",
};
const HACK: Tool = Tool {
    check: &["cargo", "hack", "--version"],
    version: Some("0.6.46"),
    install: "cargo install --locked cargo-hack@0.6.46",
};
const LLVM_COV: Tool = Tool {
    check: &["cargo", "llvm-cov", "--version"],
    version: Some("0.9.2"),
    install: "cargo install --locked cargo-llvm-cov@0.9.2",
};
const INSTA: Tool = Tool {
    check: &["cargo", "insta", "--version"],
    version: Some("1.49.0"),
    install: "cargo install --locked cargo-insta@1.49.0",
};
const FUZZ: Tool = Tool {
    check: &["cargo", "+nightly-2026-11-20", "fuzz", "--version"],
    version: Some("0.13.2"),
    install: "rustup toolchain install nightly-2026-11-20 --profile minimal && cargo install --locked cargo-fuzz@0.13.2",
};
const ACTIONLINT: Tool = Tool {
    check: &["actionlint", "-version"],
    version: Some("1.7.12"),
    install: "see https://github.com/rhysd/actionlint/releases (CI uses 1.7.12)",
};
/// `docs build` checks for each of its tools itself (`crate::docs::TOOLS`)
/// and names every one that is missing; this only gates the step.
const MDBOOK: Tool = Tool {
    check: &["mdbook", "--version"],
    version: Some("0.5.2"),
    install: "mdbook 0.5.2, mdbook-mermaid-ssr 0.3.0 and lychee 0.24.2; see docs/ci.md#documentation-site",
};
const TYPOS: Tool = Tool {
    check: &["typos", "--version"],
    version: Some("1.52.2"),
    install: "cargo install --locked typos-cli@1.52.2",
};
const ZIZMOR: Tool = Tool {
    check: &["zizmor", "--version"],
    version: Some("1.33.1"),
    install: "cargo install --locked zizmor@1.33.1",
};

const fn step(job: &'static str, command: &'static str) -> Step {
    Step {
        job,
        command,
        env: &[],
        tool: None,
        slow: false,
        needs_env: None,
        only_on: None,
    }
}

/// `true` when a step limited to `os` runs on this machine.
fn runs_here(os: Option<&str>) -> bool {
    os.is_none_or(|os| os == std::env::consts::FAMILY || os == std::env::consts::OS)
}

const PODMAN: Tool = Tool {
    check: &["podman", "--version"],
    version: None,
    install: "install podman (CI uses the one on the ubuntu-latest image)",
};
const DOTNET: Tool = Tool {
    check: &["dotnet", "--list-runtimes"],
    version: None,
    install: "install the .NET runtime (CI uses the one on the hosted Windows images); WiX itself is fetched and checked by `cargo xtask dist`",
};

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
        tool: Some(LLVM_COV),
        slow: true,
        ..step(
            "coverage",
            "cargo llvm-cov nextest --workspace --all-features --locked --profile ci --json --summary-only --output-path target/llvm-cov-summary.json",
        )
    },
    step("snapshots", "cargo fetch --locked"),
    Step {
        tool: Some(INSTA),
        env: &[("CARGO_NET_OFFLINE", "true")],
        ..step(
            "snapshots",
            "cargo insta test --check --unreferenced reject --all-features -p palisade-policy -p palisade-proto -p xtask",
        )
    },
    step("fixtures", "cargo xtask check-testdata"),
    step("fixtures", "cargo xtask golden"),
    step("fuzz-locks", "cargo xtask check-fuzz-locks"),
    Step {
        tool: Some(FUZZ),
        slow: true,
        ..step("fuzz", "cargo xtask fuzz")
    },
    step(
        "bench",
        "cargo test --workspace --all-features --locked --bench criterion_eval --bench hash_and_parse --bench simulate --bench policy_eval",
    ),
    Step {
        tool: Some(NEXTEST),
        needs_env: Some(POSTGRES_URL),
        ..step(
            "postgres",
            "cargo nextest run -p palisade-server --test postgres --locked --profile ci",
        )
    },
    Step {
        env: &[("RUSTDOCFLAGS", "-D warnings")],
        slow: true,
        ..step(
            "docs",
            "cargo doc --workspace --no-deps --all-features --locked",
        )
    },
    step("docs-book", "cargo xtask docs check"),
    Step {
        tool: Some(MDBOOK),
        slow: true,
        ..step("docs-book", "cargo xtask docs build")
    },
    Step {
        tool: Some(TYPOS),
        ..step("spelling", "typos")
    },
    step("banned-terms", "cargo xtask check-banned-terms"),
    step("deps", "cargo xtask check-deps"),
    step("deps", "cargo xtask check-manifests"),
    step("deps", "cargo xtask check-unsafe"),
    Step {
        tool: Some(DENY),
        ..step("deps", "cargo deny --locked check")
    },
    Step {
        tool: Some(DENY),
        ..step(
            "deps",
            "cargo deny --locked --manifest-path crates/palisade-fileid/fuzz/Cargo.toml --config deny.toml check",
        )
    },
    Step {
        tool: Some(DENY),
        ..step(
            "deps",
            "cargo deny --locked --manifest-path crates/palisade-proto/fuzz/Cargo.toml --config deny.toml check",
        )
    },
    Step {
        tool: Some(DENY),
        ..step(
            "deps",
            "cargo deny --locked --manifest-path crates/palisade-policy/fuzz/Cargo.toml --config deny.toml check",
        )
    },
    Step {
        tool: Some(AUDIT),
        ..step("deps", "cargo xtask audit")
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
            "cargo hack check --each-feature --all-targets --locked -p palisade-core -p palisade-fileid -p palisade-policy -p palisade-proto -p palisade-server -p palisade-cli -p palisade-console -p palisade-agent",
        )
    },
    step("runner-guard", "cargo xtask check-workflows"),
    step("runner-guard", "cargo xtask adr lint"),
    Step {
        // `bash` on Windows is often missing, or a shim for a Linux subsystem.
        only_on: Some("unix"),
        ..step("runner-guard", "bash .github/scripts/main-snapshot.test.sh")
    },
    step("doc-checks", "cargo xtask threat-coverage"),
    // `package` installs a service and writes to HKLM, so its smoke test
    // stays on the CI runner; locally only the packages are built.
    Step {
        tool: Some(DOTNET),
        slow: true,
        only_on: Some("windows"),
        ..step(
            "package",
            "cargo xtask dist --msi --sign none --out target/dist/current",
        )
    },
    Step {
        tool: Some(DOTNET),
        slow: true,
        only_on: Some("windows"),
        ..step(
            "package",
            "cargo xtask dist --msi --bump-patch --out target/dist/next",
        )
    },
    // `sign-test` trusts a throwaway root machine-wide, so locally only the
    // test-CA build runs; verification and the pfx test stay on the runner.
    Step {
        tool: Some(DOTNET),
        slow: true,
        only_on: Some("windows"),
        ..step(
            "sign-test",
            "cargo xtask dist --msi --sign test-ca --out target/dist/signed",
        )
    },
    Step {
        slow: true,
        only_on: Some("linux"),
        ..step("server-image", "cargo xtask dist --out target/dist/server")
    },
    Step {
        tool: Some(PODMAN),
        slow: true,
        only_on: Some("linux"),
        ..step(
            "server-image",
            "podman build --file packaging/server/Containerfile --tag palisade-server:ci target/dist/server",
        )
    },
    Step {
        tool: Some(PODMAN),
        slow: true,
        only_on: Some("linux"),
        ..step("server-image", "podman run --rm palisade-server:ci version")
    },
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
    /// The needed tool: the command that proves it is installed, the
    /// version CI uses, and how to install it.
    needs: Option<Needs>,
}

/// A tool a step needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Needs {
    check: Vec<String>,
    version: Option<String>,
    install: String,
}

/// Runs the selected steps from `root`. Every step runs even after one
/// fails, as in CI. Returns `true` if all passed.
pub fn run(root: &std::path::Path, fast: bool, rust_version: &str) -> Result<bool, String> {
    let toolchain = msrv_toolchain(rust_version);
    for s in STEPS {
        if let Some(os) = s.only_on.filter(|os| !runs_here(Some(os))) {
            if !(fast && s.slow) {
                println!("ci: [{}] skipped: runs on {os} only: {}", s.job, s.command);
            }
        }
        if let Some(var) = s.needs_env {
            if std::env::var_os(var).is_none() {
                println!(
                    "ci: [{}] skipped: set {var} to a disposable Postgres superuser URL to run it",
                    s.job
                );
            }
        }
    }
    let mut selected: Vec<Planned> = STEPS
        .iter()
        .filter(|s| !(fast && s.slow))
        .filter(|s| s.needs_env.is_none_or(|v| std::env::var_os(v).is_some()))
        .filter(|s| runs_here(s.only_on))
        .map(|s| Planned {
            job: s.job,
            command: s.command.to_owned(),
            env: s.env,
            needs: s.tool.map(|t| Needs {
                check: t.check.iter().map(|w| (*w).to_owned()).collect(),
                version: t.version.map(str::to_owned),
                install: t.install.to_owned(),
            }),
        })
        .collect();
    if !fast {
        selected.push(Planned {
            job: "msrv",
            command: msrv_command(&toolchain),
            env: &[],
            needs: Some(Needs {
                check: vec![
                    "cargo".to_owned(),
                    format!("+{toolchain}"),
                    "--version".to_owned(),
                ],
                version: None,
                install: format!("rustup toolchain install {toolchain} --profile minimal"),
            }),
        });
    }

    // Find every missing tool first, so one run lists them all.
    let (missing, other_versions) = tool_problems(&selected, &mut ProcessProbe);
    for warning in &other_versions {
        println!("ci: warning: {warning}");
    }
    if !missing.is_empty() {
        return Err(missing_tools_message(&missing));
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

/// The tools `selected` needs that are missing (an error: `ci` stops
/// before running anything), and those at another version than CI's (a
/// warning: the steps still run, but may not match CI). Each tool is
/// checked once, however many steps need it.
fn tool_problems(selected: &[Planned], probe: &mut dyn Probe) -> (Vec<String>, Vec<String>) {
    let mut checked: Vec<&Vec<String>> = Vec::new();
    let (mut missing, mut other_versions) = (Vec::new(), Vec::new());
    for step in selected {
        let Some(needs) = &step.needs else {
            continue;
        };
        match tools::check(probe, &needs.check, needs.version.as_deref()) {
            Status::Missing => {
                missing.push(format!("  {}\n    needs: {}", step.command, needs.install));
            }
            status @ Status::WrongVersion { .. } if !checked.contains(&&needs.check) => {
                let name = needs.check.join(" ");
                if let Some(line) =
                    tools::problem(&name, needs.version.as_deref(), &needs.install, &status)
                {
                    other_versions.push(line);
                }
            }
            _ => {}
        }
        checked.push(&needs.check);
    }
    (missing, other_versions)
}

fn missing_tools_message(missing: &[String]) -> String {
    format!(
        "missing tools; install them, or run `cargo xtask ci --fast` to skip the slow steps:\n{}",
        missing.join("\n")
    )
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
            || command.starts_with("cargo xtask coverage-summary ")
            // Compares with the PR's base commit; locally:
            // `cargo xtask coverage-gate --base origin/main`.
            || command.starts_with("cargo xtask coverage-gate ")
            || command.starts_with("archive=")
            || command.starts_with("echo ")
            || command.starts_with("exit ")
            // The package smoke test installs a service; CI runners only.
            || command.starts_with("./packaging/wix/smoke-test.ps1 ")
            // The main-only snapshot publishing jobs.
            || command.starts_with(".github/scripts/main-snapshot.sh ")
            || command == "cargo xtask dist --msi --sign none --out target/dist/snapshot"
            // Trusts a throwaway root machine-wide: CI runners only.
            || command.starts_with("./packaging/sign/")
            || command == "cargo xtask release verify target/dist/signed --allow-untimestamped"
    }

    /// The argument the sharded `fuzz` job adds to `cargo xtask fuzz`.
    const FUZZ_SHARD_ARG: &str = " --shard \"$SHARD\"";

    /// The shard argument is removed only from the `fuzz` job's command,
    /// and that job's `SHARD` is exactly the matrix shard out of the
    /// matrix's length, so no shard is skipped or run twice.
    #[test]
    fn fuzz_job_shards_cover_every_target() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let job = &docs[0]["jobs"]["fuzz"];
        let shards = job["strategy"]["matrix"]["shard"].as_vec().unwrap().len();
        let Yaml::Array(steps) = &job["steps"] else {
            panic!("no fuzz job");
        };
        let fuzz_step = steps
            .iter()
            .find(|s| {
                s["run"]
                    .as_str()
                    .is_some_and(|r| r.contains(FUZZ_SHARD_ARG))
            })
            .expect("the fuzz job runs `cargo xtask fuzz --shard \"$SHARD\"`");
        assert_eq!(
            fuzz_step["run"].as_str(),
            Some(format!("cargo xtask fuzz{FUZZ_SHARD_ARG}").as_str())
        );
        assert_eq!(
            fuzz_step["env"]["SHARD"].as_str(),
            Some(format!("${{{{ matrix.shard }}}}/{shards}").as_str())
        );
        assert_eq!(job["strategy"]["fail-fast"].as_bool(), Some(false));
        let others: Vec<(String, String)> = ci_yml_commands()
            .into_iter()
            .filter(|(job, c)| job != "fuzz" && c.contains(FUZZ_SHARD_ARG))
            .collect();
        assert!(others.is_empty(), "{others:?}");
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
                // CI splits the fuzz targets across a matrix of shards
                // (`SHARD` is `${{ matrix.shard }}/N`); locally one run
                // covers every shard.
                let command = if job == "fuzz" {
                    command.replace(FUZZ_SHARD_ARG, "")
                } else {
                    command
                };
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

    /// cargo-insta has no `--locked`: the `snapshots` job fetches the
    /// locked dependencies first and runs it offline, here and in CI.
    #[test]
    fn snapshot_step_runs_offline_after_a_locked_fetch() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let Yaml::Array(steps) = &docs[0]["jobs"]["snapshots"]["steps"] else {
            panic!("no snapshots job");
        };
        let runs: Vec<&Yaml> = steps
            .iter()
            .filter(|s| s["run"].as_str().is_some())
            .collect();
        let insta = runs
            .iter()
            .position(|s| s["run"].as_str().unwrap().contains("cargo insta test"))
            .unwrap();
        let fetch = runs
            .iter()
            .position(|s| s["run"].as_str() == Some("cargo fetch --locked"))
            .unwrap();
        assert!(fetch < insta, "cargo fetch --locked must come first");
        assert_eq!(
            runs[insta]["env"]["CARGO_NET_OFFLINE"].as_str(),
            Some("true")
        );
        let local: Vec<&Step> = STEPS.iter().filter(|s| s.job == "snapshots").collect();
        assert_eq!(local[0].command, "cargo fetch --locked");
        assert!(local[1].command.starts_with("cargo insta test "));
        assert_eq!(local[1].env, [("CARGO_NET_OFFLINE", "true")]);
    }

    #[test]
    fn install_hints_use_the_ci_tool_versions() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let source = std::fs::read_to_string(path).unwrap();
        for tool in [
            NEXTEST, DENY, AUDIT, VET, HACK, LLVM_COV, INSTA, FUZZ, ZIZMOR,
        ] {
            let pinned = tool.install.rsplit(' ').next().unwrap();
            assert!(source.contains(pinned), "ci.yml does not install {pinned}");
        }
        let nightly = format!("+{}", crate::fuzz::TOOLCHAIN);
        assert_eq!(FUZZ.check[1], nightly);
        assert!(FUZZ.install.ends_with(crate::fuzz::CARGO_FUZZ));
        assert!(source.contains("ACTIONLINT_VERSION: \"1.7.12\""));
        assert!(source.contains("typos@1.52.2") && TYPOS.install.ends_with("typos-cli@1.52.2"));
        // The docs tools: `docs build` checks for them, and ci.yml installs
        // the same versions.
        for tool in crate::docs::TOOLS {
            let pinned = format!("{}@{}", tool.name, tool.version);
            let in_ci = source.contains(&pinned)
                || source.contains(&format!(
                    "{}_VERSION: \"{}\"",
                    tool.name.to_uppercase(),
                    tool.version
                ));
            assert!(
                in_ci,
                "ci.yml does not install {} {}",
                tool.name, tool.version
            );
            assert!(tool.install.contains(tool.version), "{}", tool.name);
        }
    }

    #[test]
    fn every_pinned_tool_version_matches_its_install_hint() {
        for tool in [
            NEXTEST, DENY, AUDIT, VET, HACK, LLVM_COV, INSTA, FUZZ, ACTIONLINT, MDBOOK, TYPOS,
            ZIZMOR, PODMAN, DOTNET,
        ] {
            match tool.version {
                Some(v) => assert!(tool.install.contains(v), "{:?}", tool.check),
                // Only tools CI takes from the runner image have no pin.
                None => assert!(
                    tool.install.contains("CI uses the one on"),
                    "{:?}",
                    tool.check
                ),
            }
        }
    }

    fn planned(command: &str, tool: Tool) -> Planned {
        Planned {
            job: "test",
            command: command.to_owned(),
            env: &[],
            needs: Some(Needs {
                check: tool.check.iter().map(|w| (*w).to_owned()).collect(),
                version: tool.version.map(str::to_owned),
                install: tool.install.to_owned(),
            }),
        }
    }

    #[test]
    fn missing_tools_stop_ci_and_other_versions_warn() {
        use crate::tools::tests::FakeProbe;
        let selected = [
            planned("cargo nextest run", NEXTEST),
            planned("cargo deny check", DENY),
            planned("cargo deny check bans", DENY),
            planned("typos", TYPOS),
            Planned {
                job: "fmt",
                command: "cargo fmt --all --check".to_owned(),
                env: &[],
                needs: None,
            },
        ];
        // Everything present at CI's versions.
        let mut probe = FakeProbe::with(&[
            (
                "cargo nextest --version",
                Some("cargo-nextest 0.9.152 (x 2026-11-13)\n"),
            ),
            ("cargo deny --version", Some("cargo-deny 0.22.0\n")),
            ("typos --version", Some("typos-cli 1.52.2\n")),
        ]);
        assert_eq!(tool_problems(&selected, &mut probe), (vec![], vec![]));
        // A step with no tool runs nothing.
        assert!(!probe.asked.iter().any(|c| c.contains("fmt")));

        // Missing: listed per step, with the install command; another
        // version: one warning per tool.
        let mut probe = FakeProbe::with(&[
            (
                "cargo nextest --version",
                Some("cargo-nextest 0.9.100 (x 2026-01-01)\n"),
            ),
            ("typos --version", Some("typos-cli 1.52.2\n")),
        ]);
        let (missing, other) = tool_problems(&selected, &mut probe);
        assert_eq!(
            missing,
            [
                "  cargo deny check\n    needs: cargo install --locked cargo-deny@0.22.0",
                "  cargo deny check bans\n    needs: cargo install --locked cargo-deny@0.22.0",
            ]
        );
        assert_eq!(
            other,
            [
                "cargo nextest --version 0.9.152 is needed, found `cargo-nextest 0.9.100 (x 2026-01-01)`: cargo install --locked cargo-nextest@0.9.152"
            ]
        );
        assert_eq!(
            missing_tools_message(&missing),
            "missing tools; install them, or run `cargo xtask ci --fast` to skip the slow steps:\n  cargo deny check\n    needs: cargo install --locked cargo-deny@0.22.0\n  cargo deny check bans\n    needs: cargo install --locked cargo-deny@0.22.0"
        );
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
    fn postgres_step_reads_the_ci_job_env() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let job = &docs[0]["jobs"]["postgres"];
        assert!(job["env"][POSTGRES_URL].as_str().is_some());
        let image = job["services"]["postgres"]["image"].as_str().unwrap();
        assert!(
            image.starts_with("postgres@sha256:") && image.len() == 16 + 64,
            "{image}"
        );
        let needs = docs[0]["jobs"]["ci-ok"]["needs"].as_vec().unwrap();
        assert!(needs.iter().any(|n| n.as_str() == Some("postgres")));
        let step = STEPS.iter().find(|s| s.job == "postgres").unwrap();
        assert_eq!(step.needs_env, Some(POSTGRES_URL));
    }

    #[test]
    fn fast_skips_only_slow_steps() {
        let slow: Vec<&str> = STEPS.iter().filter(|s| s.slow).map(|s| s.job).collect();
        assert_eq!(
            slow,
            [
                "coverage",
                "fuzz",
                "docs",
                "docs-book",
                "feature-powerset",
                "package",
                "package",
                "sign-test",
                "server-image",
                "server-image",
                "server-image"
            ]
        );
    }

    /// Steps limited to one OS are the ones whose CI job runs only there.
    #[test]
    fn os_limited_steps_match_their_runners() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        for s in STEPS {
            let job = &docs[0]["jobs"][s.job];
            let mut runners: Vec<String> = match job["runs-on"].as_str() {
                Some(r) if r.starts_with("${{") => job["strategy"]["matrix"]["include"]
                    .as_vec()
                    .into_iter()
                    .flatten()
                    .map(|e| e["os"].as_str().unwrap().to_owned())
                    .chain(
                        job["strategy"]["matrix"]["os"]
                            .as_vec()
                            .into_iter()
                            .flatten()
                            .map(|o| o.as_str().unwrap().to_owned()),
                    )
                    .collect(),
                Some(r) => vec![r.to_owned()],
                None => panic!("{}: no runs-on", s.job),
            };
            runners.dedup();
            let all_windows = runners.iter().all(|r| r.starts_with("windows"));
            match s.only_on {
                Some("windows") => assert!(all_windows, "{}: {runners:?}", s.command),
                Some("linux") => assert!(
                    runners.iter().all(|r| r.starts_with("ubuntu")),
                    "{}: {runners:?}",
                    s.command
                ),
                Some("unix") => assert!(
                    runners
                        .iter()
                        .all(|r| r.starts_with("ubuntu") || r.starts_with("macos")),
                    "{}: {runners:?}",
                    s.command
                ),
                Some(other) => panic!("unknown OS {other}"),
                None => assert!(!all_windows, "{} runs only on Windows in CI", s.command),
            }
        }
        assert!(runs_here(None));
    }

    /// `ci-ok` waits for every other job except the main-only snapshot
    /// jobs, which run after it.
    #[test]
    fn ci_ok_needs_every_other_job() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml");
        let docs = YamlLoader::load_from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let jobs = docs[0]["jobs"].as_hash().unwrap();
        let mut needs: Vec<&str> = docs[0]["jobs"]["ci-ok"]["needs"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap())
            .collect();
        needs.sort_unstable();
        let mut others: Vec<&str> = jobs
            .keys()
            .map(|k| k.as_str().unwrap())
            // The post-merge release snapshot jobs run after `ci-ok`; the
            // `snapshots` test job is an ordinary check, so match exactly.
            .filter(|k| {
                *k != "ci-ok" && !["snapshot-prepare", "snapshot", "snapshot-finish"].contains(k)
            })
            .collect();
        others.sort_unstable();
        assert_eq!(needs, others);
        for snapshot in ["snapshot-prepare", "snapshot", "snapshot-finish"] {
            let job = &docs[0]["jobs"][snapshot];
            assert_eq!(
                job["if"].as_str(),
                Some("github.event_name == 'push' && github.ref == 'refs/heads/main'"),
                "{snapshot}"
            );
            assert_eq!(job["permissions"]["contents"].as_str(), Some("write"));
        }
        // No other job can write.
        for (name, job) in jobs {
            let name = name.as_str().unwrap();
            if !name.starts_with("snapshot") {
                assert!(job["permissions"].is_badvalue(), "{name} sets permissions");
            }
        }
    }

    /// The `bench` job names every bench target, so a new one cannot be
    /// left out of CI.
    #[test]
    fn bench_step_names_every_bench_target() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut found = Vec::new();
        for entry in std::fs::read_dir(root.join("crates")).unwrap() {
            let benches = entry.unwrap().path().join("benches");
            let Ok(files) = std::fs::read_dir(&benches) else {
                continue;
            };
            for file in files {
                let path = file.unwrap().path();
                if path.extension().is_some_and(|e| e == "rs") {
                    found.push(path.file_stem().unwrap().to_string_lossy().into_owned());
                }
            }
        }
        found.sort();
        let step = STEPS.iter().find(|s| s.job == "bench").unwrap();
        let mut named: Vec<String> = step
            .command
            .split(" --bench ")
            .skip(1)
            .map(|n| n.split(' ').next().unwrap().to_owned())
            .collect();
        named.sort();
        assert!(!found.is_empty());
        assert_eq!(
            named, found,
            "the bench step must name every crates/*/benches/*.rs"
        );
    }
}
