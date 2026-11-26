//! Palisade repository automation. Run `cargo xtask help` for the command list.
//!
//! Each command checks one repository rule and exits non-zero on a violation,
//! so CI can run them as plain steps. The rules themselves live in the module
//! for each command, next to their unit tests.

#![forbid(unsafe_code)]

mod adr;
mod bench_compare;
mod ci;
mod coverage;
mod coverage_gate;
mod deps;
mod dist;
mod fuzz;
mod fuzz_locks;
mod junit;
mod manifests;
mod release;
mod report;
mod supply_chain;
mod testdata;
mod threat_coverage;
mod unsafe_code;
mod workflows;

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

const HELP: &str = "\
Usage: cargo xtask <command>

Commands:
  adr new \"<title>\"
                   Copy docs/adr/0000-template.md to the next ADR number, as `proposed`
  adr index        Regenerate the ADR index table in docs/adr/README.md
  adr lint         Check every ADR's file name, number, status, date and sections (Security
                   impact included), supersession links, and that the index is current
  audit            Run cargo-audit over the root and fuzz lockfiles, ignoring exactly the
                   advisories deny.toml ignores
  ci [--fast]      Run the checks from .github/workflows/ci.yml locally (--fast skips coverage,
                   fuzz, docs, feature-powerset, msrv, package, sign-test and server-image)
  bench-compare --base <commit>
                   Run every criterion bench at <commit> and at the working tree, and fail if a
                   median is more than 10% slower outside the noise (bench.yml)
  check-deps       Enforce the allowed dependency directions between crates
  check-fuzz-locks Check that every crates/*/fuzz/Cargo.lock is current (cargo metadata --locked)
  check-testdata   Fail if any file in the repository that starts like an executable (MZ) is not
                   allowlisted in testdata/manifest.txt
  check-manifests  Enforce workspace inheritance of package fields, lints and dependency versions,
                   and that every crate README documents its features
  check-supply-chain
                   Enforce the duplicate-version budget, deny.toml ignore expiry and reasons,
                   the cargo-vet criteria and exemption notes, and no audit.toml
  check-unsafe     Enforce the unsafe-code allowlist (unsafe-allowlist.txt, ADR 0011)
  dist [--target <triple>] [--msi] [--sign <signer>] [--out <dir>] [--bump-patch]
       [--compare-sizes <sizes.json>] [--from <dir>] [--no-timestamp]
                   Release-build the Windows binaries (with --msi, the installer package) or the
                   Linux server, with symbols and size reports, as CI does (docs/packaging.md)
  dist driver      Explain how the optional kernel driver is packaged (local-only, #8)
  sign --signer <none|test-ca|pfx|cloud-hsm> [--verify] [--no-timestamp] <file>...
                   Authenticode-sign and verify files (docs/releasing.md#code-signing)
  release <prepare|check-tag|notes|checksums|verify-checksums|provenance|verify> ...
                   The release pipeline's steps (docs/releasing.md)
  deps-report [--base <commit>]
                   Print the dependency report: duplicates, third-party crates per crate,
                   third-party unsafe counts and code that runs at build time; with --base,
                   only when Cargo.lock changed, adding cargo tree -d and unsafe changes
  sbom             Reserved for the SBOM (#226); prints where it will be written and fails
  check-workflows  Enforce the CI runner and action policy for .github/workflows,
                   and that nothing under .github names a cloud-managed build service
  threat-coverage  Check the threat model's tables, and that every test, fuzz target and CI
                   check it cites exists (docs/security/threat-model.md)
  test-summary <label> <junit.xml>
                   Summarise a nextest JUnit report for the GitHub job page
  coverage-summary <label> <coverage.json>
                   Summarise a cargo-llvm-cov JSON summary for the GitHub job page
  coverage-gate --base <commit>
                   Fail if palisade-policy line coverage is lower than at <commit>; needs
                   cargo-llvm-cov and cargo-nextest
  fixtures         Build the generated test fixture corpus into target/fixtures/
  golden [--update]
                   Check the corpus's hashes against testdata/golden/fixtures.txt, or rewrite it
  fuzz [--seconds N] [--target NAME]
                   Build every cargo-fuzz target, seed it from the test fixtures and run it for
                   N seconds (default 60), or only NAME; needs the pinned nightly and cargo-fuzz
  help             Show this message
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let [command, label, path] = args.as_slice() {
        if command == "test-summary" {
            return test_summary(label, Path::new(path));
        }
        if command == "coverage-summary" {
            return coverage_summary(label, Path::new(path));
        }
    }
    if let [command, rest @ ..] = args.as_slice() {
        if command == "fuzz" {
            return run_fuzz(rest);
        }
        if command == "adr" {
            return run_adr(rest);
        }
        if command == "dist" {
            return run_dist(rest);
        }
        if command == "sign" {
            return run_sign(rest);
        }
        if command == "release" {
            return run_release(rest);
        }
    }
    match args.as_slice() {
        [command, flag, base] if command == "deps-report" && flag == "--base" => {
            return deps_report(Some(base));
        }
        [command, flag, base] if command == "coverage-gate" && flag == "--base" => {
            return coverage_gate(base);
        }
        [command, flag, base] if command == "bench-compare" && flag == "--base" => {
            return bench_compare(base);
        }
        [command, flag] if command == "golden" && flag == "--update" => return golden(true),
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
        "check-fuzz-locks" => run_check("check-fuzz-locks", check_fuzz_locks),
        "check-testdata" => run_check("check-testdata", check_testdata),
        "fixtures" => return fixtures().map_or_else(fail("fixtures"), |_| ExitCode::SUCCESS),
        "golden" => return golden(false),
        "audit" => return run_audit(),
        "check-supply-chain" => run_check("check-supply-chain", check_supply_chain),
        "check-unsafe" => run_check("check-unsafe", check_unsafe),
        "deps-report" => return deps_report(None),
        "sbom" => {
            eprintln!(
                "sbom: not implemented yet. CycloneDX output is reserved at {SBOM_DIR}/<crate>.cdx.json; \
                 generating and attesting it is #226; the release pipeline's provenance job runs it once RELEASE_PROVENANCE is on (docs/releasing.md#provenance)."
            );
            return ExitCode::FAILURE;
        }
        "check-workflows" => run_check("check-workflows", check_workflows),
        "threat-coverage" => run_check("threat-coverage", check_threat_coverage),
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
    if let Err(error) = write_step_summary(&junit::markdown(label, &report)) {
        eprintln!("test-summary: error: {error}");
        return ExitCode::FAILURE;
    }
    for annotation in junit::annotations(&report) {
        println!("{annotation}");
    }
    ExitCode::SUCCESS
}

/// Prints the per-crate table of a `cargo llvm-cov --json --summary-only`
/// report to the job summary, and a warning for each crate below its
/// coverage target. Coverage is not a gate: this fails only when the report
/// cannot be read.
fn coverage_summary(label: &str, path: &Path) -> ExitCode {
    let root = workspace_root();
    let report = read(path).and_then(|json| coverage::parse(&json, &root.to_string_lossy()));
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            eprintln!("coverage-summary: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = write_step_summary(&coverage::markdown(label, &report)) {
        eprintln!("coverage-summary: error: {error}");
        return ExitCode::FAILURE;
    }
    for annotation in coverage::annotations(label, &report) {
        println!("{annotation}");
    }
    ExitCode::SUCCESS
}

/// `cargo xtask coverage-gate --base <commit>`: see `src/coverage_gate.rs`.
fn coverage_gate(base: &str) -> ExitCode {
    let root = workspace_root();
    let work = root.join("target").join("coverage-gate");
    let result = (|| -> Result<(String, Option<String>), String> {
        println!(
            "coverage-gate: measuring {} at the working tree",
            coverage_gate::CRATE
        );
        let head = coverage_gate::measure(&root, &work.join("head"))?;
        println!(
            "coverage-gate: measuring {} at {base}",
            coverage_gate::CRATE
        );
        let base_lines = report::base_metadata(&root, base, |dir| {
            coverage_gate::measure(dir, &work.join("base"))
        })?;
        Ok(coverage_gate::report(base, base_lines, head))
    })();
    match result {
        Ok((markdown, error)) => {
            if let Err(e) = write_step_summary(&markdown) {
                eprintln!("coverage-gate: error: {e}");
                return ExitCode::FAILURE;
            }
            match error {
                None => ExitCode::SUCCESS,
                Some(annotation) => {
                    println!("{annotation}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(error) => {
            eprintln!("coverage-gate: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo xtask bench-compare --base <commit>`: see `src/bench_compare.rs`.
fn bench_compare(base: &str) -> ExitCode {
    let root = workspace_root();
    let work = bench_compare::work_dir(&root);
    let result = (|| -> Result<(String, Vec<String>), String> {
        // Alternate base and head runs while the base worktree exists.
        let (base_results, head) = report::base_metadata(&root, base, |dir| {
            let (mut base_best, mut head_best) = Default::default();
            for round in 1..=bench_compare::ROUNDS {
                println!("bench-compare: round {round}: benchmarking {base}");
                let results =
                    bench_compare::run_benches(dir, &work.join("base"), &work.join("target-base"))?;
                bench_compare::best_of(&mut base_best, results);
                println!("bench-compare: round {round}: benchmarking the working tree");
                let results = bench_compare::run_benches(
                    &root,
                    &work.join("head"),
                    &work.join("target-head"),
                )?;
                bench_compare::best_of(&mut head_best, results);
            }
            Ok((base_best, head_best))
        })?;
        if head.is_empty() {
            return Err("no benchmark results; is there a crates/*/benches/*.rs?".to_owned());
        }
        let rows = bench_compare::compare(&base_results, &head);
        Ok(bench_compare::markdown(base, &rows))
    })();
    match result {
        Ok((markdown, errors)) => {
            if let Err(e) = write_step_summary(&markdown) {
                eprintln!("bench-compare: error: {e}");
                return ExitCode::FAILURE;
            }
            for error in &errors {
                println!("{error}");
            }
            if errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("bench-compare: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo xtask fuzz`: runs every fuzz target, then writes the results to
/// the job summary. Fails if any target failed.
fn run_fuzz(args: &[String]) -> ExitCode {
    let args = match fuzz::parse_args(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("fuzz: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let outcomes = match fuzz::run(&workspace_root(), &args) {
        Ok(outcomes) => outcomes,
        Err(error) => {
            println!(
                "::error title=Fuzzing could not run::{}",
                fuzz::escape_data(&error)
            );
            eprintln!("fuzz: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let summary = write_step_summary(&fuzz::markdown(args.seconds, &outcomes));
    for annotation in fuzz::annotations(&outcomes) {
        println!("{annotation}");
    }
    if let Err(error) = summary {
        eprintln!("fuzz: error: {error}");
        return ExitCode::FAILURE;
    }
    let failed = outcomes.iter().filter(|o| o.failure.is_some()).count();
    if failed == 0 {
        println!("fuzz: all {} targets passed", outcomes.len());
        ExitCode::SUCCESS
    } else {
        eprintln!("fuzz: {failed} of {} targets failed", outcomes.len());
        ExitCode::FAILURE
    }
}

/// `cargo xtask sign`: see `src/release/sign.rs`.
fn run_sign(args: &[String]) -> ExitCode {
    use release::sign;
    let result = (|| -> Result<usize, String> {
        let args = sign::parse_args(args)?;
        let root = workspace_root();
        let mut config = sign::Config::from_process(args.kind, &root);
        if args.no_timestamp {
            config.timestamp = sign::Timestamp::Skip;
        }
        let mut runner = sign::ProcessRunner::new(&config);
        if args.verify_only {
            for file in &args.files {
                sign::verify_file(&root, config.timestamp, &mut runner, file)?;
            }
            return Ok(args.files.len());
        }
        let mut signer = sign::signer(&config, &mut runner)?;
        sign::sign_all(signer.as_mut(), &args.files, true)
    })();
    match result {
        Ok(count) => {
            println!("sign: {count} file(s) done");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("::error title=sign::{}", fuzz::escape_data(&error));
            eprintln!("sign: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo xtask release`: see `src/release/mod.rs`.
fn run_release(args: &[String]) -> ExitCode {
    let root = workspace_root();
    let result: Result<(), String> = match args {
        [cmd, version] if cmd == "prepare" => {
            let date = std::env::var("RELEASE_DATE").unwrap_or_default();
            if release::is_calendar_date(&date) {
                release::prepare(&root, version, &date).map(|section| print!("{section}"))
            } else {
                Err("set RELEASE_DATE to a real date, YYYY-MM-DD (the date the release is cut)".to_owned())
            }
        }
        [cmd, tag] if cmd == "check-tag" => release::check_tag(&root, tag).map(|v| {
            println!("check-tag: {tag} is version {v}{}", if release::is_prerelease(&v) { " (pre-release)" } else { "" });
        }),
        [cmd, version] if cmd == "notes" => read(&root.join("CHANGELOG.md"))
            .and_then(|c| release::changelog::excerpt(&c, version))
            .map(|notes| print!("{notes}")),
        [cmd, dir] if cmd == "checksums" => {
            let dir = Path::new(dir);
            release::checksums::for_dir(dir).and_then(|sums| {
                std::fs::write(dir.join("SHA256SUMS"), &sums).map_err(|e| format!("cannot write SHA256SUMS: {e}"))?;
                print!("{sums}");
                Ok(())
            })
        }
        [cmd, dir] if cmd == "verify-checksums" => {
            let dir = Path::new(dir);
            (|| {
                let sums = read(&dir.join("SHA256SUMS"))?;
                // Every listed name and every file present are read; a name
                // that is not a plain file name in `dir`, or a file that
                // cannot be read, is an error rather than skipped.
                let mut names: Vec<String> = Vec::new();
                for line in sums.lines() {
                    if let Some((_, name)) = line.split_once("  ") {
                        release::checksums::check_name(name)?;
                        names.push(name.to_owned());
                    }
                }
                for entry in std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))? {
                    let entry = entry.map_err(|e| e.to_string())?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let kind = entry.file_type().map_err(|e| format!("{name}: {e}"))?;
                    if kind.is_file() && name != "SHA256SUMS" && name != "SHA256SUMS.sig" && !names.contains(&name) {
                        names.push(name);
                    }
                }
                let mut files = Vec::new();
                for name in names {
                    let path = dir.join(&name);
                    let meta = std::fs::symlink_metadata(&path);
                    match meta {
                        Ok(m) if m.file_type().is_symlink() => return Err(format!("{name}: is a link")),
                        Ok(_) => {
                            let data = std::fs::read(&path).map_err(|e| format!("cannot read {name}: {e}"))?;
                            files.push((name, data));
                        }
                        // Missing: checksums::verify reports it as listed but missing.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(format!("cannot read {name}: {e}")),
                    }
                }
                let problems = release::checksums::verify(&sums, &files);
                if problems.is_empty() { Ok(()) } else { Err(problems.join("\n")) }
            })()
        }
        [cmd] if cmd == "provenance" => {
            let enabled = std::env::var("RELEASE_PROVENANCE").is_ok_and(|v| v == "on");
            release::provenance(&root, enabled)
        }
        [cmd, dir, rest @ ..] if cmd == "verify" && rest.len() <= 1 => {
            let timestamp = match rest.first() {
                None => Ok(release::sign::Timestamp::Required),
                Some(flag) if flag == "--allow-untimestamped" => Ok(release::sign::Timestamp::IfConfigured),
                Some(other) => Err(format!("unexpected argument `{other}`")),
            };
            timestamp.and_then(|t| {
                let work = dist::target_dir(&root)?.join("release-verify");
                release::verify_dir(&root, Path::new(dir), &work, t).map(|n| println!("verify: {n} file(s) signed and valid"))
            })
        }
        _ => Err("usage: cargo xtask release prepare <version> | check-tag <tag> | notes <version> | checksums <dir> | verify-checksums <dir> | provenance | verify <dir> [--allow-untimestamped]".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            println!("::error title=release::{}", fuzz::escape_data(&error));
            eprintln!("release: error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo xtask dist`: see `src/dist/mod.rs`.
fn run_dist(args: &[String]) -> ExitCode {
    let request = match dist::parse_args(args) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("dist: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    match request {
        dist::Request::Driver => {
            eprintln!("{}", dist::DRIVER_NOTE);
            ExitCode::FAILURE
        }
        dist::Request::Build(args) => match dist::run(&workspace_root(), &args) {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                println!("::error title=dist::{}", fuzz::escape_data(&error));
                eprintln!("dist: error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

/// Appends Markdown to `$GITHUB_STEP_SUMMARY`, or prints it outside GitHub
/// Actions.
fn write_step_summary(markdown: &str) -> Result<(), String> {
    match std::env::var_os("GITHUB_STEP_SUMMARY") {
        Some(summary) => {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&summary)
                .and_then(|mut f| f.write_all(markdown.as_bytes()))
                .map_err(|e| format!("cannot write the step summary: {e}"))
        }
        None => {
            print!("{markdown}");
            Ok(())
        }
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

fn check_fuzz_locks(root: &Path) -> Result<Vec<String>, String> {
    let manifests = fuzz_locks::fuzz_manifests(root)?;
    for manifest in &manifests {
        println!("check-fuzz-locks: {manifest}");
    }
    fuzz_locks::check(&manifests, |m| fuzz_locks::cargo_metadata_locked(root, m))
}

fn check_testdata(root: &Path) -> Result<Vec<String>, String> {
    let (files, mut violations) = unsafe_code::repository_files(root)?;
    let allowed = testdata::parse_manifest(&read(&root.join(testdata::MANIFEST))?)?;
    violations.extend(testdata::check_files(root, &files, &allowed)?);
    Ok(violations)
}

/// An `ExitCode::FAILURE` that prints `error` for `command`.
fn fail(command: &'static str) -> impl FnOnce(String) -> ExitCode {
    move |error| {
        eprintln!("{command}: error: {error}");
        ExitCode::FAILURE
    }
}

/// `cargo xtask fixtures`: builds the corpus into `target/fixtures/` and
/// returns its manifest.
fn fixtures() -> Result<testdata::Hashes, String> {
    let root = workspace_root();
    let out = root.join(testdata::OUT_DIR);
    if out.exists() {
        std::fs::remove_dir_all(&out)
            .map_err(|e| format!("cannot clear {}: {e}", out.display()))?;
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // Release: the RSA-3072 test keys take seconds there and minutes in a
    // debug build.
    let status = Command::new(cargo)
        .args([
            "test",
            "--release",
            "--locked",
            "-p",
            "palisade-fileid",
            "--test",
            "fixture_corpus",
            "--",
            "--ignored",
            "--exact",
            "write_fixture_corpus",
        ])
        .env("PALISADE_FIXTURE_DIR", &out)
        .current_dir(&root)
        .status()
        .map_err(|e| format!("cannot run cargo test: {e}"))?;
    if !status.success() {
        return Err("building the corpus failed".to_owned());
    }
    let manifest = out.join("MANIFEST");
    let hashes = testdata::parse_hashes(&read(&manifest)?, &manifest.display().to_string())?;
    if hashes.is_empty() {
        return Err("the corpus is empty".to_owned());
    }
    println!("fixtures: {} fixtures in {}", hashes.len(), out.display());
    Ok(hashes)
}

/// `cargo xtask golden [--update]`.
fn golden(update: bool) -> ExitCode {
    let root = workspace_root();
    let built = match fixtures() {
        Ok(h) => h,
        Err(e) => return fail("golden")(e),
    };
    let path = root.join(testdata::GOLDEN);
    if update {
        return match std::fs::write(&path, testdata::render_golden(&built)) {
            Ok(()) => {
                println!("golden: wrote {}", testdata::GOLDEN);
                ExitCode::SUCCESS
            }
            Err(e) => fail("golden")(format!("cannot write {}: {e}", path.display())),
        };
    }
    let golden = match read(&path).and_then(|t| testdata::parse_hashes(&t, testdata::GOLDEN)) {
        Ok(g) => g,
        Err(e) => return fail("golden")(e),
    };
    let diffs = testdata::compare(&golden, &built);
    if diffs.is_empty() {
        println!(
            "golden: all {} fixtures match {}",
            built.len(),
            testdata::GOLDEN
        );
        ExitCode::SUCCESS
    } else {
        for d in &diffs {
            eprintln!("golden: {d}");
        }
        eprintln!(
            "golden: {} difference(s). If the change is intended, run `cargo xtask golden --update` and review the diff.",
            diffs.len()
        );
        ExitCode::FAILURE
    }
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

/// Where `cargo xtask sbom` will write CycloneDX files (#226).
const SBOM_DIR: &str = "target/dist/sbom";

fn check_supply_chain(root: &Path) -> Result<Vec<String>, String> {
    let metadata = cargo_metadata(root, &["--all-features"])?;
    let mut violations = supply_chain::check_duplicates(
        &supply_chain::duplicates(&metadata)?,
        supply_chain::DUPLICATE_BUDGET,
    );
    violations.extend(supply_chain::check_deny_toml(
        &read(&root.join("deny.toml"))?,
        &supply_chain::today_utc()?,
    )?);
    violations.extend(supply_chain::check_vet_config(
        &read(&root.join("supply-chain").join("config.toml"))?,
        &supply_chain::member_names(&metadata)?,
    )?);
    let (paths, _) = unsafe_code::repository_files(root)?;
    violations.extend(supply_chain::check_no_audit_toml(&paths));
    Ok(violations)
}

/// `cargo xtask audit`: cargo-audit with exactly the advisory ignores from
/// `deny.toml`, so the two tools agree, over the root `Cargo.lock` and the
/// lockfile of every fuzz workspace in [`fuzz::PROJECTS`]. The ignores are checked first (ID,
/// reason, an expiry date that has not passed, no scope), so an expired or
/// incomplete ignore fails here too, including in the daily audit. Exits
/// non-zero if any cargo-audit run fails.
fn run_audit() -> ExitCode {
    let root = workspace_root();
    let checked = read(&root.join("deny.toml")).and_then(|source| {
        let violations = supply_chain::check_deny_toml(&source, &supply_chain::today_utc()?)?;
        if violations.is_empty() {
            supply_chain::ignored_advisories(&source)
        } else {
            Err(violations.join("\n"))
        }
    });
    let ignores = match checked {
        Ok(ignores) => ignores,
        Err(error) => {
            eprintln!("audit: error: {error}");
            return ExitCode::FAILURE;
        }
    };
    // The root lockfile, then each fuzz workspace's own lockfile.
    let mut lockfiles = vec![None];
    lockfiles.extend(
        fuzz::PROJECTS
            .iter()
            .map(|p| Some(format!("{}/Cargo.lock", p.dir))),
    );
    println!(
        "audit: cargo audit, ignoring {} advisories from deny.toml",
        ignores.len()
    );
    let mut passed = true;
    let mut fetched = false;
    for lockfile in &lockfiles {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut command = Command::new(cargo);
        command.arg("audit").current_dir(&root);
        if let Some(lockfile) = lockfile {
            println!("audit: {lockfile}");
            command.args(["--file", lockfile]);
        }
        // The advisory database is fetched once, by the first run.
        if fetched {
            command.arg("--no-fetch");
        }
        for id in &ignores {
            command.args(["--ignore", id]);
        }
        match command.status() {
            Ok(status) => passed &= status.success(),
            Err(error) => {
                eprintln!("audit: error: cannot run cargo audit: {error}");
                return ExitCode::FAILURE;
            }
        }
        fetched = true;
    }
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `cargo xtask deps-report [--base <commit>]`: see `src/report.rs`.
fn deps_report(base: Option<&str>) -> ExitCode {
    let root = workspace_root();
    let result = (|| -> Result<(String, Vec<String>), String> {
        let (base_lock, tree) = match base {
            Some(base) => {
                let lock = report::git_show(&root, base, "Cargo.lock")?;
                if lock == read(&root.join("Cargo.lock"))? {
                    return Ok((
                        "## Dependency report\n\n`Cargo.lock` is unchanged from the base branch.\n"
                            .to_owned(),
                        Vec::new(),
                    ));
                }
                (Some(lock), Some(report::cargo_tree_duplicates(&root)?))
            }
            None => (None, None),
        };
        let metadata = cargo_metadata(&root, &["--all-features"])?;
        // The base commit's packages: `cargo metadata --locked` in a worktree
        // of it makes Cargo download and unpack exactly its locked crates.io
        // packages (checksum-verified, no build scripts run), so their
        // `unsafe` can be counted. The worktree is removed afterwards.
        let mut registries = supply_chain::registry_dirs(&metadata);
        let mut base_warnings = Vec::new();
        if let (Some(base), Some(_)) = (base, &base_lock) {
            match report::base_metadata(&root, base, |dir| cargo_metadata(dir, &["--all-features"]))
            {
                Ok(base_metadata) => {
                    registries.extend(supply_chain::registry_dirs(&base_metadata));
                }
                Err(error) => base_warnings.push(format!(
                    "::warning title=Base dependencies not unpacked::{}",
                    error.replace(['\n', '\r', '%'], " ")
                )),
            }
            registries.sort();
            registries.dedup();
        }
        let base_count = |name: &str, version: &str| {
            registries.iter().find_map(|dir| {
                let crate_dir = dir.join(format!("{name}-{version}"));
                // An incomplete scan is not a known baseline: a skipped file
                // would make the base count too low and raise a false jump.
                crate_dir
                    .is_dir()
                    .then(|| supply_chain::count_dir(&crate_dir, &unsafe_code::count_unsafe))
                    .and_then(|(count, unreadable)| (unreadable == 0).then_some(count))
            })
        };
        let (markdown, mut warnings) =
            report::render(&metadata, base_lock.as_deref(), tree.as_deref(), base_count)?;
        warnings.extend(base_warnings);
        Ok((markdown, warnings))
    })();
    match result {
        Ok((markdown, warnings)) => {
            // Into the job summary on GitHub Actions, like test-summary;
            // workflow commands go to stdout, where the runner reads them.
            if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
                use std::io::Write as _;
                let written = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&summary)
                    .and_then(|mut f| f.write_all(markdown.as_bytes()));
                if let Err(error) = written {
                    eprintln!("deps-report: error: cannot write the step summary: {error}");
                    return ExitCode::FAILURE;
                }
            } else {
                print!("{markdown}");
            }
            for warning in warnings {
                println!("{warning}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("deps-report: error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn check_workflows(root: &Path) -> Result<Vec<String>, String> {
    let github = root.join(".github");
    let mut violations = workflows::check_dir(&github.join("workflows"))?;
    violations.extend(workflows::check_terms(&github)?);
    Ok(violations)
}

/// `cargo xtask threat-coverage`: see [`threat_coverage`].
fn check_threat_coverage(root: &Path) -> Result<Vec<String>, String> {
    let doc = read(&root.join(threat_coverage::DOCUMENT))?;
    let (paths, mut violations) = unsafe_code::repository_files(root)?;

    // Test function names per crate. A file belongs to the member whose
    // directory is the longest prefix of its path.
    let metadata = cargo_metadata(root, &["--no-deps"])?;
    let mut crates: Vec<(String, String)> = Vec::new();
    for manifest in deps::member_manifest_paths(&metadata)? {
        let dir = Path::new(&manifest)
            .parent()
            .and_then(|d| d.strip_prefix(root).ok())
            .ok_or_else(|| format!("{manifest}: not under the repository root"))?;
        let source = read(Path::new(&manifest))?;
        let name = source
            .parse::<toml::Table>()
            .map_err(|e| format!("{manifest}: invalid TOML: {e}"))?
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{manifest}: no package name"))?
            .to_owned();
        let mut prefix = dir.to_string_lossy().replace('\\', "/");
        if !prefix.is_empty() {
            prefix.push('/');
        }
        crates.push((prefix, name));
    }
    crates.sort_by_key(|(prefix, _)| std::cmp::Reverse(prefix.len()));
    let mut facts = threat_coverage::Facts::default();
    for (_, name) in &crates {
        facts.tests.entry(name.clone()).or_default();
    }
    let (ids, components) = threat_coverage::defined_ids(&doc);
    // Fuzz projects are separate workspaces, not part of the crate's tests.
    let fuzz_dirs: Vec<String> = fuzz::PROJECTS
        .iter()
        .map(|p| format!("{}/", p.dir))
        .collect();
    for path in &paths {
        let is_rust = unsafe_code::is_rust_path(path);
        let is_markdown = path.to_ascii_lowercase().ends_with(".md");
        if !(is_rust || is_markdown) || path == threat_coverage::DOCUMENT {
            continue;
        }
        let text = read(&root.join(path))?;
        violations.extend(threat_coverage::check_references(
            path,
            &text,
            &ids,
            &components,
        ));
        let in_fuzz = fuzz_dirs.iter().any(|d| path.starts_with(d.as_str()));
        if is_rust && !in_fuzz {
            if let Some((_, name)) = crates
                .iter()
                .find(|(prefix, _)| path.starts_with(prefix.as_str()))
            {
                let tests = threat_coverage::test_functions(&text)
                    .ok_or_else(|| format!("{path}: cannot tokenise"))?;
                facts.tests.entry(name.clone()).or_default().extend(tests);
            }
        }
    }
    facts.fuzz_targets = fuzz::PROJECTS
        .iter()
        .flat_map(|p| p.targets.iter().map(|t| t.name.to_owned()))
        .collect();
    for path in &paths {
        if path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml"))
        {
            facts
                .ci_commands
                .extend(workflows::run_commands(&read(&root.join(path))?));
        }
    }
    violations.extend(threat_coverage::check(&doc, &facts));
    Ok(violations)
}

/// `cargo xtask adr new|index|lint`.
fn run_adr(args: &[String]) -> ExitCode {
    let root = workspace_root();
    let readme_path = root.join(adr::DIR).join("README.md");
    match args {
        [lint] if lint == "lint" => {
            let result = adr::read_dir(&root.join(adr::DIR))
                .and_then(|files| Ok(adr::lint(&files, &read(&readme_path)?)));
            match result {
                Ok(v) if v.is_empty() => {
                    println!("adr lint: ok");
                    ExitCode::SUCCESS
                }
                Ok(v) => {
                    for violation in &v {
                        eprintln!("adr lint: {violation}");
                    }
                    eprintln!("adr lint: {} violation(s)", v.len());
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("adr lint: error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [index] if index == "index" => {
            let result = adr::read_dir(&root.join(adr::DIR)).and_then(|files| {
                let adrs = adr::index_entries(&files)?;
                let readme = read(&readme_path)?;
                let updated = adr::replace_index(&readme, &adrs)?;
                if updated != readme {
                    std::fs::write(&readme_path, updated)
                        .map_err(|e| format!("cannot write {}: {e}", readme_path.display()))?;
                    println!("adr index: updated {}/README.md", adr::DIR);
                } else {
                    println!("adr index: {}/README.md is current", adr::DIR);
                }
                Ok(())
            });
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("adr index: error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        [new, title] if new == "new" => {
            let result = adr::read_dir(&root.join(adr::DIR)).and_then(|files| {
                let template = files
                    .iter()
                    .find(|(n, _)| n == adr::TEMPLATE)
                    .map(|(_, t)| t.clone())
                    .ok_or_else(|| format!("{}/{} is missing", adr::DIR, adr::TEMPLATE))?;
                let names: Vec<String> = files.into_iter().map(|(n, _)| n).collect();
                let (name, text) =
                    adr::new_adr(&names, &template, title, &supply_chain::today_utc()?)?;
                let path = root.join(adr::DIR).join(&name);
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes()))
                    .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
                Ok(name)
            });
            match result {
                Ok(name) => {
                    println!(
                        "adr new: created {}/{name}; fill it in, then run `cargo xtask adr index`",
                        adr::DIR
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("adr new: error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("usage: cargo xtask adr new \"<title>\" | adr index | adr lint");
            ExitCode::FAILURE
        }
    }
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
