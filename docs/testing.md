# Testing

How Palisade is tested, which tests run where, and the conventions new tests follow.
[CONTRIBUTING.md](../CONTRIBUTING.md#testing-expectations) says what a change must come with, and
[ci.md](ci.md) lists every CI job.

## Kinds of test

| Kind | Where | Runs |
|---|---|---|
| Unit tests | `#[cfg(test)] mod tests` next to the code, or a `tests.rs` sibling module | Every `cargo test` / `cargo nextest run`, on every CI test runner |
| Integration tests | `crates/<crate>/tests/*.rs`, using only the crate's public API | Same |
| Property tests | `proptest`, in either of the above | Same |
| Golden-file tests | Expected output committed next to the test, regenerated on request | Same |
| Doctests | Examples in `///` comments | `cargo test --doc`, because nextest does not run them |
| Fuzz targets | `crates/<crate>/fuzz/`, cargo-fuzz (libFuzzer) | 60 s per target on every PR; 30 min per target weekly |
| Benchmarks | `crates/<crate>/benches/*.rs`, criterion | Built and run once in test mode on every PR; measured locally |
| Coverage | Unit, integration, property and golden-file tests, instrumented (not doctests, fuzzing or benchmarks) | Every PR, on Linux and Windows x64 |

## Running tests

```sh
cargo nextest run --workspace --all-features --locked   # the `default` profile
cargo nextest run --workspace --all-features --locked --profile ci
cargo test --workspace --all-features --locked --doc
cargo test --workspace --all-features --locked           # also works, without the JUnit report
```

`.config/nextest.toml` has two profiles:

- `default`: for local runs. No retries, and a test is reported as slow after 60 s.
- `ci`: the same, plus `fail-fast = false`, so one run reports every failure, and a JUnit report
  at `target/nextest/ci/junit.xml`. `cargo xtask test-summary` turns that report into the job
  summary ([ci.md](ci.md#test-reports)).

Neither profile retries. A test that passes only on a retry is flaky, and a flaky test in a
security product hides real failures, so it is fixed rather than retried. Do not add `retries` to
a profile or a per-test override.

The `postgres` test group holds `palisade-server`'s database tests (`tests/postgres.rs`). Each
test creates its own database and roles, so they run in parallel, at most four at a time so the
server's connection limit never fails a test. Outside the `postgres` CI job they skip themselves,
because `PALISADE_TEST_DATABASE_ADMIN_URL` is not set. A new test binary that needs Postgres joins
the group by adding its `binary(...)` to the filter in `.config/nextest.toml`.

The slowest tests are the 10,000-case property tests in `palisade-policy`, which take tens of
seconds in a debug build. Set `PROPTEST_CASES` to run fewer cases locally.

## Conventions

### Names

A test name says what is expected, as a sentence in snake case: what holds, or what happens in
which case. For example `hostile_descriptors_are_errors`, `every_truncation_of_a_rich_image` and
`huge_counts_do_not_overflow`. A reader of a failure should know what broke from the name alone.
Do not prefix names with `test_`.

### Determinism

- **No sleeps.** A test that waits for something uses a channel, a barrier or a mock clock. A
  `Clock` trait for code that reads the time arrives with the platform abstraction (#29). Until
  then, pass times in as values.
- **No network.** Unit and integration tests do not open sockets to anything outside the test,
  resolve names or download anything. Tests that need a real service, such as Postgres for the
  server (#126, #127), are marked and run only where that service is provided.
- **No dependence on the machine.** Tests do not read the user's home directory, environment or
  locale, or the system clock's time zone. Temporary files go in a fresh directory under
  `std::env::temp_dir()` or the target directory, and are removed afterwards.
- Randomness comes only from proptest, which reports a seed for every failure.

### Platforms

- Code and tests that only work on Windows are gated with `#[cfg(windows)]`, so the workspace
  builds and tests on every platform. CI runs the tests on Linux, macOS, Windows x64 and
  Windows ARM64.
- Tests that need administrator rights or a test VM are `#[ignore]`d, with a reason, and run in
  the VM harness (#26).
- Ignored tests that write files on request, such as the fuzz seed writers below, say so in
  their `#[ignore = "..."]` reason.

### Fixtures

- Fixtures are synthetic and built at test time where possible. `palisade-fileid` builds its PE
  images byte by byte (`crates/palisade-fileid/tests/common`), so no binaries are committed.
- Small committed fixtures (policy documents, PKCS#7 signatures) live in the crate's
  `tests/fixtures/`, each set with a note, or a script, that says how it was made.
- Never commit malware, antivirus test strings or third-party signed binaries
  ([responsible-use.md](responsible-use.md)). The one exception is the content tagger's
  built-in rule for the standard anti-malware test file (#44): its rule and test fixture
  hold the string as hex only, assembled in memory at test time and never written to disk,
  and `source_files_do_not_carry_the_test_string` (`crates/palisade-fileid/tests/tags.rs`)
  fails if the string appears verbatim in the crate's sources.
  `cargo xtask check-testdata` (the `fixtures` CI job) fails if any file in the repository starts
  like an executable (`MZ`) and its SHA-256 is not in `testdata/manifest.txt` with a reason.
  Generated fixtures are never committed, so that list is normally empty, and a dropped-in PE,
  anywhere, fails the check.

### The fixture corpus

`palisade-fileid` builds a whole corpus from Rust at test time, on any OS, in
`crates/palisade-fileid/tests/corpus/`:

| Kind | Fixtures |
|---|---|
| PE | PE32+ x64 and ARM64, PE32 x86, each as an `.exe` and a `.dll`, with a version resource (original file name, product, company, file version) |
| Test PKI | A root CA, an intermediate and RSA-3072 leaves; an ECDSA P-256 leaf; expired, revoked-in-CRL, wrong-EKU (TLS server only) and self-signed leaves; a CRL |
| Signed PE | Embedded Authenticode, dual signed (nested), tampered after signing, a truncated certificate table, a page-hash-bearing signature, and one per bad leaf above |
| Catalog | A signed catalog (`.cat`) and the unsigned PE it lists by SHA-256 Authenticode digest (catalog-signed) |
| Malformed | Zero length, `MZ` only, truncated headers, overlapping sections, `NumberOfSections` 0xffff, a recursive resource directory, `SizeOfImage` near 4 GiB |
| Script | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf`, `.hta`, each only printing `PALISADE-FIXTURE` |

- **Signing is pure Rust** (`tests/corpus/sign.rs`): PKCS#7 SignedData over
  `SpcIndirectDataContent` (or a catalog's trust list), as code signers write it, so no OS
  signing tools are needed.
- **Deterministic.** The RSA test keys come from an RNG seeded by the key's name, and the
  signing time is fixed, so every run on every OS makes the same bytes. The one exception is the
  ECDSA fixture, whose signature is random by nature.
- **Checked by the crate itself.** `tests/fixture_corpus.rs` parses every fixture and asserts
  the property it was built to have: machine, format and version info; signatures that verify
  and chain to the test root (and the nested one); the tampered fixture a digest mismatch; the
  wrong-EKU leaf refused because code signing is not permitted, the self-signed one because it
  reaches no anchor; the CRL listing the revoked leaf; the page hash table matching; malformed
  inputs never panicking. This runs in the `test` job on every OS.
- **On disk:** `cargo xtask fixtures` writes the corpus and a `MANIFEST` to `target/fixtures/`.
- **Golden hashes:** `cargo xtask golden` rebuilds the corpus and compares every fixture's
  SHA-256 with `testdata/golden/fixtures.txt`; `cargo xtask golden --update` rewrites it. A
  changed hash is a changed fixture, reviewed in the PR. Provenance:
  `testdata/golden/README.md`.
- **Fuzz seeds:** `write_corpus_fuzz_seeds` adds the corpus to the seed corpora of the PE,
  PKCS#7 and X.509 fuzz targets.

Not in the corpus: MSI/MSP/MST fixtures, which arrive with installer identity (#53; its
compound-file builder is on `main` since #279), and CHM and CPL fixtures, which arrive with compiled HTML
and control panel item enforcement (#98, M2).
- **Builders.** Policy tests in other crates build their inputs with `palisade-policy`'s
  `test-util` feature (`palisade_policy::test_util`) rather than hand-written JSON:

  ```toml
  [dev-dependencies]
  palisade-policy = { workspace = true, features = ["test-util"] }
  ```

  ```rust,ignore
  let policy = PolicyBuilder::new()
      .rule_set(RuleSetBuilder::allowlist(1).rule(RuleBuilder::allow(1, hash('a'))))
      .validate();
  let decision = subject(&facts().sha256('a')).decide(&policy);
  ```

### Unwrap in tests

`clippy.toml` allows `unwrap` and `expect` inside `#[test]` functions. Helpers outside them need
`#![allow(clippy::unwrap_used)]` at the top of the test file, with a comment that says why.

## Property tests

Property tests use [`proptest`](https://docs.rs/proptest). Use them for invariants that must hold
for every input: parsers never panic and respect their limits, serialisation round-trips, and
matching agrees with a simpler reference.

- Failing cases are saved and replayed first on every run, so a fixed bug stays fixed: for unit
  tests in `proptest-regressions/` next to the crate's sources, and for integration tests in
  `tests/<name>.proptest-regressions`. Commit those files.
- Check that a property can fail: plant a bug (an off-by-one at a bound, say), run it, and
  revert. `tests/version_properties.rs` in `palisade-policy` says which bugs it was checked
  against.
- Prefer mutating valid inputs (flip, truncate, overwrite) over purely random bytes: they reach
  much deeper into a parser.
- The default case count is 256. Expensive properties set a smaller count with
  `ProptestConfig::with_cases`; important cheap ones set a larger one.

## Golden-file tests

A golden-file test compares generated output with a committed file. The convention is the one
`palisade-policy`'s JSON Schema test uses (`crates/palisade-policy/tests/schema.rs`):

- The test fails with a message that says how to regenerate the file.
- Setting `PALISADE_BLESS=1` makes the test rewrite the file instead of failing:
  `PALISADE_BLESS=1 cargo test -p palisade-policy --test schema`.
- A change to a golden file is reviewed in the PR like code. The diff shows what changed in the
  output.

## Snapshot tests

Structured output that people and other systems rely on is checked with
[`insta`](https://insta.rs) snapshots: the test serialises the value, and `insta` compares it with
a reviewed `.snap` file next to the test.

| Crate | Test | What is snapshotted |
|---|---|---|
| `palisade-policy` | `tests/decision_snapshots.rs` | Whole-pipeline decisions (outcome, deciding rule, overridden rules, annotations, directives, effects, reason code), for policies built with `test_util` |
| `palisade-proto` | `tests/event_snapshots.rs` | Event JSON: the canonical bytes, and a readable pretty-printed copy |

Conventions:

- **One directory per test file**, set with `Settings::set_snapshot_path` (for example
  `tests/snapshots/pipeline/`), and **named snapshots** (`assert_json_snapshot!("name", value)`), so
  file names say what they hold and do not depend on test function names.
- **Deterministic input.** Fixed IDs (the `test_util` builders make them), fixed times, fixed trace
  IDs. Never snapshot a random or time-dependent value; redact it or set it.
- **`.gitattributes` with `* -text`** in each snapshot directory, so Windows checkouts keep LF and
  the byte comparison holds on every runner.
- **Review like code.** A snapshot diff in a PR is a change to output. After a deliberate change:

  ```sh
  cargo insta test -p palisade-policy --all-features   # writes .snap.new files for changes
  cargo insta review                                   # accept or reject each one
  ```

  `INSTA_UPDATE=always cargo test ...` writes them directly; read the diff before committing.
- **CI** (the `snapshots` job) runs `cargo insta test --check --unreferenced reject`, offline
  after `cargo fetch --locked`: it fails if any snapshot differs, is missing, or is no longer
  referenced by a test. The normal `test` job
  also fails on a differing snapshot, because `insta` does not write files when `CI` is set.

The older golden-file convention above (`PALISADE_BLESS=1`) stays for committed artefacts that are
not snapshots of a test value: the JSON Schemas and the event registry. Snapshots of the compiled
OS-native policy XML and of CLI output arrive with that code (#84, #15), using the same
conventions. `xtask` snapshots its own `--help` output (`xtask/src/snapshots/`, #29); after a
change to the command list, run `cargo insta test -p xtask` and review.

## Fuzzing

Every parser of untrusted input has a coverage-guided fuzz target. The targets live in a
separate cargo-fuzz workspace per crate (`crates/<crate>/fuzz/`), so normal builds never compile
them, and only they need a nightly toolchain. There are three projects:

- `crates/palisade-fileid/fuzz`, with fourteen targets: `pe_parse`, `version_info_parse`,
  `authenticode_ranges`, `authenticode_pkcs7`, `fsctx_parse`, `x509_chain`, `timestamp_crl`,
  `fuzz_ctl`, `fuzz_classify`, `fuzz_msi_tables`, `legacy_parse`, `fuzz_tags`, `script_sig` and
  `fuzz_appx_manifest`. The project builds `palisade-fileid` with its `content-rules` feature,
  for `fuzz_tags`.
- `crates/palisade-proto/fuzz`, with one target: `trust_set_decode`.
- `crates/palisade-policy/fuzz`, with four targets: `fuzz_policy_json` (the strict JSON reader,
  validation and the evaluator build), `fuzz_policy_yaml` (the YAML reader),
  `fuzz_wildcard_regex_compile` (compiling and matching wildcards, regular expressions and text
  values) and `fuzz_bundle_decode` (the policy bundle's header-only and strict decoders, #43).

Target names are unique across projects, so `--target` names one without its project. Each fuzz
workspace has its own committed `Cargo.lock`. Dependabot keeps it up to date, cargo-deny checks it against the root `deny.toml` on every PR and daily, and
`cargo xtask audit` runs cargo-audit over it. cargo-vet covers only the root workspace, so a
fuzz-only dependency is reviewed in its PR instead
([dependencies.md](dependencies.md)). The fuzz crates are never shipped.

One command builds every target of every project, seeds its corpus from the synthetic test fixtures, and runs it:

```sh
rustup toolchain install nightly-2026-11-20 --profile minimal
cargo install --locked cargo-fuzz@0.13.2
cargo xtask fuzz                         # 60 s per target, every target, as a PR runs them
cargo xtask fuzz --shard 2/6             # only the targets of one of CI's 6 shards
cargo xtask fuzz --seconds 1800 --target pe_parse
```

The nightly is pinned by date in `xtask/src/fuzz.rs`, so a new nightly cannot break CI. The
lockfile is checked with `cargo fetch --locked` on that nightly, and the build and runs are then
offline, so they cannot download anything or re-resolve the lockfile. The
corpus and any findings go to `target/fuzz-smoke/<target>/`. Each target runs with a 10 s limit
per input and a 2 GiB memory limit, so hangs and runaway allocation count as findings too.

- **On every PR**, the `fuzz` job in `ci.yml` runs every target for 60 s, split across 6 parallel
  shards: shard `I` runs `cargo xtask fuzz --shard I/6`, the targets whose position in
  `PROJECTS` (counted from 0 across all projects) is `I` modulo 6, and builds only the projects
  those targets are in. Together the shards run every target exactly once, and `cargo xtask ci`
  runs them all in one go.
- **Every week**, `fuzz.yml` runs each target for 30 minutes, as one job per target. If any
  fails, it opens an `area:security` issue, or comments on the open one.

A finding fails the job. The job summary lists each target's result and, for each failing input
up to 64 KiB, the input itself as base64 with the command that reproduces it. That stands in for
an artefact upload, which would need an action outside the allowlist ([ci.md](ci.md)). To fix a
finding:

1. Reproduce it locally with the command from the job summary.
2. Fix the parser.
3. Add the input as a regression test in the crate's normal tests, so it runs on every platform
   on every PR, not only under the fuzzer.

`xtask/src/fuzz.rs` lists every fuzz project and target. Its tests fail if a target is missing
from the list, from a project's `Cargo.toml` or from `fuzz.yml`'s matrix, if two projects use the
same target name, if a `crates/*/fuzz` project is not listed, or if a project has no committed
lockfile. To add a target:

1. Add the target to `fuzz_targets/` and as a `[[bin]]` in the project's `Cargo.toml`.
2. Add it to `PROJECTS` in `xtask/src/fuzz.rs`, with its dictionary and the ignored tests that
   write its seed inputs (they read the output directory from `PALISADE_FUZZ_SEED_DIR`).
3. Add it to the matrix in `.github/workflows/fuzz.yml`.

A test also fails if the PR `fuzz` job's shards would have more than 5 targets each. Then add
shards: extend the `shard` list in the job's matrix in `.github/workflows/ci.yml`, and change the
`/6` in its `SHARD` to the new count, so no shard nears its 30-minute limit.

For a new crate's fuzz project, also add it to `PROJECTS` with the package whose tests write its
seeds, commit its `Cargo.lock` (and keep `Cargo.lock` out of its `.gitignore`), add it to
`.github/dependabot.yml`, and add its cargo-deny step to the `deps` job in `ci.yml`, to
`audit.yml` and to `xtask/src/ci.rs`. The tests in `xtask/src/fuzz.rs` fail
until all of these are in place. A seed writer that writes nothing fails the run, because libtest
passes when `--exact` matches no test.

## Coverage

The `coverage` job in `ci.yml` runs the nextest suite under
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov), on ubuntu-latest and windows-latest.
`cargo xtask coverage-summary` then writes a table to the job summary page: line, function and
region coverage for each crate, and the total. The instrumentation needs `llvm-tools-preview`,
which `rust-toolchain.toml` installs.

Coverage is reported, not enforced, with one exception. The initial targets are 80% line
coverage for `palisade-policy` and `palisade-fileid` (#25). A crate below its target gets a
warning annotation on the run, and the job still passes.

The exception: **`palisade-policy` line coverage must not decrease.** On every pull request the
`coverage-gate` job measures the crate's own tests at the base commit and at the PR, in the same
job, and fails if the share of covered lines went down. New code needs tests in the same PR; new
code at the same ratio passes. `PROPTEST_RNG_SEED` is fixed for both runs, so property tests
generate the same cases and the number is reproducible. To check before pushing:

```sh
cargo xtask coverage-gate --base origin/main
```

The full line-by-line report is not uploaded as an artefact, because that needs an action
outside the CI allowlist ([ci.md](ci.md#runner-and-action-policy)); generate it locally with
`cargo llvm-cov report --html` (below). For the same reason the table goes to the job summary,
not a PR comment, which would also need a write token on pull requests.

To see the report locally:

```sh
cargo install --locked cargo-llvm-cov@0.9.2
cargo llvm-cov nextest --workspace --all-features --locked --profile ci \
  --json --summary-only --output-path target/llvm-cov-summary.json
cargo xtask coverage-summary local target/llvm-cov-summary.json
cargo llvm-cov report --html --open      # line-by-line, from the same run
```

## Benchmarks

Benchmarks use [criterion](https://docs.rs/criterion), in `crates/<crate>/benches/`:

| Crate | Bench | What it measures |
|---|---|---|
| `palisade-policy` | `criterion_eval` | One compiled criterion against an object's facts: hash, 25-value text, path wildcard, regex and version range |
| `palisade-policy` | `policy_eval` | Whole-policy evaluation on the #42 reference policy (10k rules, a 100k hash set), under `deny_wins`, `first_match` and `specificity`; a decision-cache hit; loading the reference and 1M-hash policies |
| `palisade-fileid` | `hash_and_parse` | Flat hashing of 1 MiB with each algorithm set, streamed hashing, PE parsing (full and metadata-only) and the Authenticode hash |

Run them locally, on a quiet machine:

```sh
cargo bench -p palisade-policy --bench criterion_eval
cargo bench -p palisade-policy --bench policy_eval
cargo bench -p palisade-fileid --bench hash_and_parse
cargo bench -p palisade-policy --bench criterion_eval -- --save-baseline before   # then, after a change:
cargo bench -p palisade-policy --bench criterion_eval -- --baseline before
```

The `bench` job in CI builds every bench and runs each benchmark once in test mode
(`cargo test --bench <name>`). That catches benches that no longer build or that panic, but it
measures nothing. Shared hosted runners vary too much from run to run for their timings to be
compared. A test in `xtask/src/ci.rs` fails if a `benches/*.rs` file is missing from the job.

criterion 0.7 was chosen because later releases needed a newer Rust than the MSRV of the time
(1.85), and the `msrv` job builds every target, including benches. The MSRV is now 1.94
([workspace.md](workspace.md#toolchain-and-msrv)); moving to a newer criterion is a separate
change. Its plotting and parallel features are off.

### Regression gate

`.github/workflows/bench.yml` runs `cargo xtask bench-compare --base <commit>` weekly (`main`
against `main` a week earlier) and on demand for any branch. It measures every bench at the base
commit and at the head, in one job on one runner, twice each, alternating (base, head, base,
head), keeps each side's faster median, and compares them. A benchmark **regresses** when its
median is more than 10% slower **and** the 95% confidence intervals of the two medians do not
overlap. The table is in the job summary.

How it copes with noise on shared hosted runners, which vary by tens of percent between runs and
machines:

- **Same job, back to back.** A stored baseline from another run would not be comparable, so the
  base is measured again every time.
- **Iteration counts.** criterion runs many iterations per sample and 100 samples per benchmark,
  which gives the confidence intervals.
- **Alternating rounds, best of two.** Noise on a shared machine almost only ever slows a run
  down, and alternating means a slow patch hits both sides alike.
- **Two conditions.** Over the threshold *and* outside the noise.

Small changes still show up as noise, so treat a regression as a prompt to measure locally, where
a quiet machine gives sharper numbers:

```sh
cargo xtask bench-compare --base origin/main    # the same comparison, locally
```

The gate was checked by slowing one benchmark (`hash_1mib/sha256`) by 20% on purpose. The
comparison measured it at +19.7%, reported it as regressed and failed, and reported the other
eleven benchmarks within ±5% as unchanged.

The policy performance budget (#42) is in `crates/palisade-policy/perf-budget.toml`, and
`crates/palisade-policy/tests/budget.rs` checks it. CI runs that test in its smoke mode: it checks
the memory budget, which is counted by a counting allocator and so is the same on every runner, and
reports the timings without comparing them. On reference hardware,
`PALISADE_BUDGET=enforce cargo test --release -p palisade-policy --test budget -- --nocapture`
fails on any breach.

Bundle-loading benchmarks arrive with the code they measure (#43). The gate covers the policy
benchmarks (`policy_eval`, over whole policies and the decision cache) as it does every
`crates/*/benches/*.rs`. The 100 MB and 1 GB file hashing runs stay local and on demand.
