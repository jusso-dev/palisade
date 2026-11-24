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
const LLVM_COV: Tool = Tool {
    check: &["cargo", "llvm-cov", "--version"],
    install: "cargo install --locked cargo-llvm-cov@0.9.2",
};
const FUZZ: Tool = Tool {
    check: &["cargo", "+nightly-2026-11-20", "fuzz", "--version"],
    install: "rustup toolchain install nightly-2026-11-20 --profile minimal && cargo install --locked cargo-fuzz@0.13.2",
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
    install: "install podman (CI uses the one on the ubuntu-latest image)",
};
const DOTNET: Tool = Tool {
    check: &["dotnet", "--list-runtimes"],
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
    step("fuzz-locks", "cargo xtask check-fuzz-locks"),
    Step {
        tool: Some(FUZZ),
        slow: true,
        ..step("fuzz", "cargo xtask fuzz")
    },
    step(
        "bench",
        "cargo test --workspace --all-features --locked --bench criterion_eval --bench hash_and_parse --bench simulate",
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
            "cargo hack check --each-feature --all-targets --locked -p palisade-core -p palisade-fileid -p palisade-policy -p palisade-proto -p palisade-server -p palisade-cli -p palisade-console",
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
    /// The command that proves the needed tool is installed, and how to
    /// install it.
    needs: Option<(Vec<String>, String)>,
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
        for tool in [NEXTEST, DENY, AUDIT, VET, HACK, LLVM_COV, FUZZ, ZIZMOR] {
            let pinned = tool.install.rsplit(' ').next().unwrap();
            assert!(source.contains(pinned), "ci.yml does not install {pinned}");
        }
        let nightly = format!("+{}", crate::fuzz::TOOLCHAIN);
        assert_eq!(FUZZ.check[1], nightly);
        assert!(FUZZ.install.ends_with(crate::fuzz::CARGO_FUZZ));
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
                "feature-powerset",
                "package",
                "package",
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
            .filter(|k| *k != "ci-ok" && !k.starts_with("snapshot"))
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
