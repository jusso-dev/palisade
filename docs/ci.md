# Continuous integration

CI is defined in `.github/workflows/`. It runs on **GitHub-hosted runners
only**. Self-hosted runners, third-party runner services and cloud-managed
build or pipeline services are permanently prohibited: self-hosted runners on
a public repository can be taken over by pull requests from forks, and paid
build services have caused surprise bills. The `runner-guard` job enforces
this on every PR (see below). If a job cannot run on a hosted runner, it
becomes a documented local-only step; it is never moved to another runner
type.

## Workflows

### `ci.yml` (every pull request and every push to `main`)

| Job | Runners | What it runs |
|---|---|---|
| `fmt` | ubuntu-latest | `cargo fmt --all --check` |
| `clippy` | ubuntu-latest, windows-latest | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, then the same for `palisade-core` and `palisade-driver` with `--no-default-features` (the `no_std` build), and for `palisade-core` with `--no-default-features --features schema` (`no_std` with serde and JSON Schema support) |
| `test` | ubuntu-latest, macos-latest, windows-latest (x64), windows-11-arm (ARM64, native) | `cargo nextest run --workspace --all-features --locked --profile ci`, then the doctests with `cargo test --doc`, then `cargo xtask test-summary` (see [Test reports](#test-reports)) |
| `coverage` | ubuntu-latest, windows-latest | `cargo llvm-cov nextest --workspace --all-features --locked --profile ci --json --summary-only`, then `cargo xtask coverage-summary` (see [Coverage, fuzzing and benchmarks](#coverage-fuzzing-and-benchmarks)) |
| `coverage-gate` | ubuntu-latest | On PRs, `cargo xtask coverage-gate --base <base>`: `palisade-policy` line coverage at the PR's base commit and at the PR, measured in the same job; fails if it decreased (see [Coverage, fuzzing and benchmarks](#coverage-fuzzing-and-benchmarks)) |
| `fuzz-locks` | ubuntu-latest | `cargo xtask check-fuzz-locks`: `cargo metadata --locked` on every `crates/*/fuzz/Cargo.toml`, so a stale fuzz lockfile fails in seconds |
| `fuzz` | ubuntu-latest | After `fuzz-locks`, `cargo xtask fuzz`: every cargo-fuzz target, seeded from the test fixtures, for 60 s each, on the pinned nightly |
| `bench` | ubuntu-latest | `cargo test --bench <name>` for every criterion bench: builds them and runs each benchmark once, without timing |
| `postgres` | ubuntu-latest | `cargo nextest run -p palisade-server --test postgres --locked --profile ci` against a Postgres 17 service container (official image, pinned by digest), with `PALISADE_TEST_DATABASE_ADMIN_URL` set. Elsewhere those tests skip themselves. `cargo xtask ci` runs this step only when that variable is set locally |
| `msrv` | ubuntu-latest | `cargo +1.94.0 check --workspace --all-targets --all-features --locked`, after checking that the version matches `rust-version` in `Cargo.toml` |
| `docs` | ubuntu-latest | `cargo doc --workspace --no-deps --all-features --locked` with `RUSTDOCFLAGS=-D warnings` |
| `deps` | ubuntu-latest | `cargo xtask check-deps`, `cargo xtask check-manifests`, `cargo xtask check-unsafe`, `cargo deny --locked check` for the root workspace and for each fuzz workspace (with the root `deny.toml`), `cargo xtask audit` (cargo-audit over the root and every fuzz lockfile, with the ignores from `deny.toml`) |
| `supply-chain` | ubuntu-latest | `cargo vet --locked`, `cargo xtask check-supply-chain`, and on PRs `cargo xtask deps-report --base <base>` to the job summary ([dependencies.md](dependencies.md)) |
| `feature-powerset` | ubuntu-latest | `cargo hack check --each-feature --all-targets --locked` on the portable crates (`core`, `fileid`, `policy`, `proto`, `server`, `cli`, `console`) |
| `runner-guard` | ubuntu-latest | `cargo xtask check-workflows` ([Runner and action policy](#runner-and-action-policy)), `cargo xtask adr lint` (ADR format and index, [docs/adr/PROCESS.md](adr/PROCESS.md#index-and-tooling)), and the tests of the snapshot script (`bash .github/scripts/main-snapshot.test.sh`) |
| `doc-checks` | ubuntu-latest | `cargo xtask threat-coverage`: the threat model's tables are complete and consistent, and every test, fuzz target and CI check it cites exists ([threat model](security/threat-model.md#keeping-it-current)) |
| `workflow-lint` | ubuntu-latest | `actionlint` (checksum-verified release) and `zizmor --offline` |
| `package` | windows-latest (x64), windows-11-arm (ARM64, native) | `cargo xtask dist --msi --sign none`, then the same with `--bump-patch`, then `packaging/wix/smoke-test.ps1`: install, upgrade, downgrade, repair and removal of the package on the runner ([packaging.md](packaging.md#tests-in-ci)) |
| `sign-test` | windows-latest | Code signing end to end with throwaway certificates made on the runner and deleted: `cargo xtask dist --msi --sign test-ca`, `cargo xtask release verify` of every signature including inside the packages, then `packaging/sign/ci-test.ps1` (the `pfx` signer with a canary password that must not appear in the output, and a signed package of unsigned executables that verification must reject). No secrets ([releasing.md](releasing.md#dry-run-on-pull-requests)) |
| `server-image` | ubuntu-latest | `cargo xtask dist` (the Linux server binary), `podman build` of `packaging/server/Containerfile`, and `palisade-server version` in the image |
| `ci-ok` | ubuntu-latest | Passes only if every job above succeeded |
| `snapshot-prepare`, `snapshot`, `snapshot-finish` | ubuntu-latest; windows-latest and windows-11-arm | Pushes to `main` only, after `ci-ok`: the [`main-snapshot`](#main-snapshot) pre-release |

**Branch protection requires `ci-ok`** (and the `PR title` check below). It
depends on every other job and fails if any of them failed, was cancelled or
was skipped, so new jobs are covered without changing the branch rules. The
ruleset is in [repo-settings.md](repo-settings.md#branch-protection-for-main).
Requiring the one aggregate check, instead of each job by name, is how the
required set in #21 (fmt, both clippy runs, the tests, msrv, deps, docs and
runner-guard), and the coverage, fuzz and bench jobs from #25, is enforced:
a matrix job's check names change whenever the matrix does, and the
aggregate cannot be left out of date.

The `test` matrix runs the whole workspace on every runner. On Linux and the
other desktop OS that means the portable crates, plus the Windows-only crates
as stubs; Windows x64 and Windows ARM64 run everything natively. The issue's
`test-portable`, `test-windows-x64` and `test-windows-arm64` are the four
entries of this one matrix.

#### Test reports

nextest writes a JUnit report (`.config/nextest.toml`, profile `ci`) to
`target/nextest/ci/junit.xml`. The `Test summary` step runs even when the
tests fail, and `cargo xtask test-summary` turns the report into a table on
the job's summary page and one error annotation per failed test. Failure
names are escaped, so a test name cannot inject a workflow command. If the
tests did not build, there is no report, and the step only warns.

#### Coverage, fuzzing and benchmarks

Details and local commands are in [testing.md](testing.md).

- `coverage` runs the same nextest suite instrumented by cargo-llvm-cov, and
  `cargo xtask coverage-summary` writes line, function and region coverage
  per crate to the job summary. It is reported, not enforced: a crate below
  its target (80% lines for `palisade-policy` and `palisade-fileid`) gets a
  warning annotation and the job still passes.
- `coverage-gate` is the one coverage rule that is enforced (#25):
  `palisade-policy` line coverage must not decrease. On a pull request,
  `cargo xtask coverage-gate` runs `cargo llvm-cov nextest -p palisade-policy`
  at the PR's base commit (in a temporary git worktree) and at the PR, with
  `PROPTEST_RNG_SEED` fixed so property tests cover the same cases each time,
  and fails if the share of covered lines went down. Adding code at the same
  coverage ratio passes. Both numbers are in the job summary. Nothing is
  stored between runs: a baseline from `main` would need an artefact or a
  cache write from a pull request, and measuring the base again in the same
  job needs neither.
- `fuzz-locks` runs `cargo metadata --locked` on each fuzz workspace (found
  on disk, so a new one is checked before it is listed anywhere). A pull
  request that changes a dependency of a crate a fuzz workspace builds, even
  indirectly, must re-lock that workspace; this job says so in seconds, with
  the minimal re-lock command (`cargo metadata --manifest-path <dir>/Cargo.toml`,
  which upgrades nothing). The `fuzz` job waits for it.
- `fuzz` runs `cargo xtask fuzz`. It builds every target of every project
  listed in `xtask/src/fuzz.rs`, each from its fuzz workspace's committed
  `Cargo.lock`, seeds
  each corpus from the crate's synthetic fixtures, and runs each target for
  60 s. A crash, hang, leak or out-of-memory input fails the job, and the job
  summary shows each failing input up to 64 KiB as base64, with the command
  that reproduces it. The nightly toolchain is pinned by date. cargo-fuzz has
  no prebuilt binary in the install action, so it is built from crates.io
  with `cargo install --locked` (`fallback: cargo-install`, which passes no
  token).
- `bench` builds every criterion bench and runs each benchmark once in test
  mode, so a bench that no longer builds or panics fails. Timings are not
  measured on shared runners. A unit test fails if a `benches/*.rs` file is
  not named in the job.

#### `main-snapshot`

Every push to `main` whose CI passed replaces the files of one rolling pre-release, tagged
`main-snapshot`, with that commit's unsigned packages (`<commit>.Palisade-<version>-x64.msi` and
`-arm64.msi`, where `<commit>` is the first 12 characters of the commit) and their `.msi.sha256`
checksums (#22). The release is marked as a pre-release, never as the latest release, and its
notes say the builds are unsigned, untested snapshots and not for production use, and name the
commit and the run. Every file name starts with its commit, so an upload never replaces another
commit's file: the previous set stays published until the new one is complete, and is then
removed, so there is only ever one set.

Only the three snapshot jobs have a write scope (`contents: write`, to edit the release and
move the tag), and they run only on `push` to `main`, never on pull requests, so fork code
never runs with it. `snapshot-prepare` creates the release on first use and marks it as being
updated, `snapshot` builds and uploads each architecture's package on its own runner, and
`snapshot-finish` checks that `main` still points at the commit (a re-run of an older run's
job keeps that run's commit, and must not publish over a newer snapshot) and that all four
files are there, then points the tag at the commit, removes older files and writes the notes.
`snapshot-prepare` stops on any release lookup failure other than "not found", so an API error
never creates a release or moves the tag. The commands are in `.github/scripts/main-snapshot.sh`, which uses
the preinstalled `gh` CLI; its tests (`main-snapshot.test.sh`, a fake `gh`) run in
`runner-guard`. Pushes to `main` queue rather than cancel each other (`concurrency`), so two
snapshots never interleave.

The `snapshot` job builds the packages again instead of reusing the `package` job's: passing
files between jobs needs an artefact action, and only three actions are allowed (see below).
The packages are built from the same commit with the same command. Pull requests build and test
the packages in `package` and publish nothing.

### `release.yml` (pushed `v*` tags; pull requests that change release tooling)

The release pipeline: `check-tag`, `build` (x64 and ARM64, natively), `server`, `sign` (the
approval-gated `release-signing` environment), `verify`, `provenance` and `publish`. Files move
between jobs through a draft release, using the preinstalled `gh`, because no artefact action is
allowed; the draft is published only after `verify` passes. Pull requests that change
`release.yml`, `xtask/src/dist/`, `xtask/src/release/` or `packaging/` run only `dry-run`: the
same build, signing with a throwaway test CA, packaging and verification, with no secrets, no
write access and no upload. Details: [releasing.md](releasing.md).

### `fuzz.yml` (weekly on Sunday at 04:41 UTC, and on demand)

| Job | Runners | What it runs |
|---|---|---|
| `fuzz` | ubuntu-latest | `cargo xtask fuzz --seconds 1800 --target <name>`, one job per target of every fuzz project (target names are unique, so the name selects the project) |
| `report` | ubuntu-latest | On failure, opens an issue titled "Scheduled fuzzing found a failure" with the `area:security` label, or comments on the open one |

Longer runs find what the 60 s PR run cannot. A unit test in
`xtask/src/fuzz.rs` keeps the matrix in step with the target list. Only
`report` has `issues: write`, and it runs no repository code. The failing
input is in the failed job's summary.

### `bench.yml` (weekly on Monday at 05:23 UTC, and on demand)

| Job | Runners | What it runs |
|---|---|---|
| `compare` | ubuntu-latest | `cargo xtask bench-compare --base <commit>`: every criterion bench at the base commit and at the head, in the same job, twice each, alternating, keeping each side's faster median; fails if any median is more than 10% slower with non-overlapping 95% confidence intervals |

The weekly run compares `main` with `main` a week earlier. Run it on demand
from the Actions tab for any branch, with `base` (default `main`) to compare
against. It is not part of PR CI: two full benchmark runs take longer than a
PR check should, and the result is only meaningful when both runs share a
runner, which is why the base is measured again each time instead of being
stored. The comparison table is in the job summary. See
[testing.md](testing.md#benchmarks).

### `pr-title.yml` (pull requests, including title edits)

| Job | Runners | What it runs |
|---|---|---|
| `PR title` | ubuntu-latest | `bash .github/scripts/check-pr-title.test.sh`, then `.github/scripts/check-pr-title.sh` on the pull request title |

Pull requests are squash-merged with the PR title as the commit message, so
the title must be a Conventional Commit ([CONTRIBUTING.md](../CONTRIBUTING.md#conventional-commits)).
This is a separate workflow because it reruns when the title is edited,
which should not rerun the whole build. The title reaches the script through
an environment variable, never by expression interpolation into the shell.
It is also a required check.

### `dco.yml` (pull requests)

| Job | Runners | What it runs |
|---|---|---|
| `DCO` | ubuntu-latest | `bash .github/scripts/check-dco.test.sh`, then `.github/scripts/check-dco.sh` on the pull request's base and head commits |

Fails if a commit in the pull request has no `Signed-off-by:` trailer from its
author ([CONTRIBUTING.md](../CONTRIBUTING.md#sign-off)). It is not a required
check yet ([repo-settings.md](repo-settings.md#dco-check)). The commit SHAs
reach the script through environment variables. It reruns when a pull
request's base branch changes (`edited`).

Dependabot authors its commits at a noreply address but signs them off as
`dependabot[bot] <support@github.com>`. When GitHub reports that Dependabot
opened the pull request, the workflow passes `--dependabot`, and the script
accepts that sign-off for commits authored at the bot's noreply address only.
The pull request author comes from GitHub, not from the commits, so a commit
that copies the bot's address gains nothing.

Pull requests opened by the repository owner pass with a notice and are not
checked ([CONTRIBUTING.md](../CONTRIBUTING.md#sign-off)). The workflow reads
GitHub's `author_association` for the pull request, which commits cannot
change. The checker's own tests still run on those pull requests.

### `labels.yml` (label and milestone changes, and on demand)

| Job | Runners | What it runs |
|---|---|---|
| `validate` | ubuntu-latest | `bash .github/scripts/sync-labels.test.sh`, then `.github/scripts/sync-labels.sh --validate` |
| `sync` | ubuntu-latest | `.github/scripts/sync-labels.sh --apply` on a push to `main`; `--check` (a dry run) on a manual run unless `apply` is ticked |

Runs on pull requests and pushes to `main` that change `.github/labels.yml`,
`.github/milestones.yml`, the issue templates, `dependabot.yml`, the sync
script or the workflow. `sync` never runs on a pull request, and is the only
job here with a write scope (`issues: write`, plus `contents: read` for the
checkout). Details:
[repo-settings.md](repo-settings.md#labels-and-milestones).

### `audit.yml` (daily at 03:17 UTC, and on demand)

Runs `cargo deny check advisories` and `cargo xtask audit` (cargo-audit with the same ignores) against `main`, for the root workspace and every fuzz workspace's lockfile. Both
also run on every PR (the `deps` job). A new advisory can affect `main`
without any change here, which is why this is also scheduled. On failure, a second job opens an issue titled "Scheduled advisory
audit is failing" with the `area:security` label, or comments on the open
one. That job, the `report` job in `fuzz.yml` and the `sync` job in `labels.yml`
are the only places with `issues: write`.

### Dependabot (`.github/dependabot.yml`)

Weekly updates for Cargo dependencies (the workspace, and each fuzz
workspace's own lockfile) and for the pinned action SHAs, with minor and
patch bumps grouped into one PR per manifest. Security updates are
opened as soon as an advisory is published. Dependabot PRs run the full CI
like any other PR, including `DCO`, cargo-deny, cargo-audit and cargo-vet, so
a bump of the root workspace merges only once the new version is audited or
exempted with a note ([dependencies.md](dependencies.md#cargo-vet)).
cargo-deny and cargo-audit also check each fuzz workspace's lockfile; cargo-vet
covers only the root workspace, so a fuzz-only bump is reviewed in its PR.
The fuzz crates are never shipped ([testing.md](testing.md#fuzzing)). They are labelled
`area:security` (Cargo) or `area:infra` (actions), because the label sync
deletes Dependabot's default labels.

## Runner and action policy

`cargo xtask check-workflows` (the `runner-guard` job) checks every workflow
file against allowlists in `xtask/src/workflows.rs`:

- `runs-on` must be one of `ubuntu-latest`, `ubuntu-24.04`, `windows-latest`,
  `windows-2025`, `windows-11-arm`, `macos-latest`, `macos-15`. The only
  expression allowed is `${{ matrix.<key> }}`, and every value of that key
  must be an allowed label. Matrix keys are matched case-insensitively, as
  GitHub does, and a matrix or `include:` entry built from an expression
  fails. Label lists, runner groups, and labels read from inputs or variables
  fail.
- Every action is on the allowlist (`actions/checkout`, `Swatinem/rust-cache`,
  `taiki-e/install-action`) and pinned to a full 40-character commit SHA, with
  the version in a trailing comment. Container actions fail.
- No job calls a reusable workflow (`jobs.<id>.uses`), local or remote. None
  are needed yet.
- The workflow has a top-level `permissions:` block that is read-only:
  `read-all`, `{}`, or scopes set only to `read` or `none`. Jobs that need
  more ask for it themselves.
- `pull_request_target` is never used, so fork PRs never run with secrets or
  a write token.
- `actions/checkout` sets `persist-credentials: false`.
- `Swatinem/rust-cache` sets `save-if` exactly once (in any letter case, as
  the runner matches input names), to `false` or to the main-branch
  expression, so only `main` writes the cache (threat model T-ci-06).
- No file under `.github/` (workflows, scripts, issue templates, anything)
  names a cloud-managed build or pipeline service, in any letter case,
  anywhere in its text or its file name. The names are kept out of this
  repository ([NAMING.md](NAMING.md)), so the check stores only their SHA-256
  digests and compares the digest of every substring of the same length.

Because the check allowlists runners and actions rather than blocklisting
services, an unapproved build service fails by default. Adding a runner label
or an action is a reviewed change to `xtask/src/workflows.rs`.

Other hardening:

- Rust caches are written only from `main` (`save-if`, checked above), so PR
  builds, including forks, cannot poison them.
- Superseded PR runs are cancelled; pushes to `main` always finish.
- Every job has a `timeout-minutes` (30, or 60 for the test and coverage
  matrices and the weekly fuzz jobs).
- CI sets `CARGO_TERM_COLOR=always`, `CARGO_INCREMENTAL=0` and
  `RUST_BACKTRACE=1`.
- Every Cargo command uses `--locked`, so CI builds exactly `Cargo.lock`.

The workspace rules the `deps` and `feature-powerset` jobs enforce are described in
[workspace.md](workspace.md).

## Running the checks locally

The toolchain is pinned in `rust-toolchain.toml`, so rustup picks it up
automatically. One command runs every check in `ci.yml`, with the same
command lines:

```sh
cargo xtask ci          # everything, including coverage, fuzz, docs, feature-powerset and msrv
cargo xtask ci --fast   # skips those slow steps, and the package, signing and server-image builds
```

It runs every step even after one fails, and lists the failed ones at the
end. Before it starts, it checks that the extra tools are installed
(cargo-nextest, cargo-deny, cargo-audit, cargo-vet, cargo-hack, actionlint, zizmor and,
without `--fast`, cargo-llvm-cov, the fuzzing nightly with cargo-fuzz, and the
MSRV toolchain), and prints the install command for
each one that is missing, at the version CI uses. Jobs that differ only by
runner run once, on your machine. Steps whose job runs only on one OS run
only there: on Windows, `ci` builds both packages (the `package` job, without
its smoke test, which installs a service); on Linux, it builds the server
binary and image (the `server-image` job, with podman). Elsewhere they are
skipped with a note, and `--fast` skips them. A unit test in `xtask/src/ci.rs`
compares its steps with `ci.yml`, so the two cannot drift.

The same checks, one by one:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy -p palisade-core -p palisade-driver --no-default-features --all-targets --locked -- -D warnings
cargo clippy -p palisade-core --no-default-features --features schema --all-targets --locked -- -D warnings
cargo nextest run --workspace --all-features --locked --profile ci   # needs cargo-nextest 0.9
PALISADE_TEST_DATABASE_ADMIN_URL=postgres://postgres:<pw>@127.0.0.1:5432/postgres \
  cargo nextest run -p palisade-server --test postgres --locked --profile ci  # needs a disposable Postgres 16+
cargo test --workspace --all-features --locked --doc
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo xtask check-deps
cargo xtask check-manifests
cargo xtask check-unsafe
cargo xtask check-workflows
cargo xtask adr lint
cargo xtask threat-coverage
cargo deny --locked check          # needs cargo-deny 0.22
cargo deny --locked --manifest-path crates/palisade-fileid/fuzz/Cargo.toml --config deny.toml check
cargo deny --locked --manifest-path crates/palisade-proto/fuzz/Cargo.toml --config deny.toml check
cargo xtask audit                  # cargo-audit 0.23, with deny.toml's ignores
cargo vet --locked                 # needs cargo-vet 0.10
cargo xtask check-supply-chain
cargo xtask deps-report            # add --base origin/main to compare
cargo llvm-cov nextest --workspace --all-features --locked --profile ci \
  --json --summary-only --output-path target/llvm-cov-summary.json   # needs cargo-llvm-cov 0.9
cargo xtask fuzz                   # needs nightly-2026-11-20 and cargo-fuzz 0.13
cargo test --workspace --all-features --locked --bench criterion_eval --bench hash_and_parse
cargo hack check --each-feature --all-targets --locked \
  -p palisade-core -p palisade-fileid -p palisade-policy \
  -p palisade-proto -p palisade-server -p palisade-cli \
  -p palisade-console                                    # needs cargo-hack 0.6
actionlint -color && zizmor --offline .github/workflows
cargo +1.94.0 check --workspace --all-targets --all-features --locked
bash .github/scripts/check-pr-title.test.sh
bash .github/scripts/check-pr-title.sh "docs: example title"
bash .github/scripts/check-dco.test.sh
bash .github/scripts/check-dco.sh origin/main HEAD
bash .github/scripts/sync-labels.test.sh   # needs jq and yq v4
bash .github/scripts/sync-labels.sh --validate
bash .github/scripts/main-snapshot.test.sh
cargo xtask dist --msi --sign none --out target/dist/current   # Windows, needs the .NET runtime
cargo xtask dist --out target/dist/server                      # Linux x64
podman build --file packaging/server/Containerfile --tag palisade-server:ci target/dist/server
```

To check Windows-only code from Linux or another desktop OS:

```sh
rustup target add x86_64-pc-windows-gnu
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
```

`cargo test --workspace --all-features --locked` still works and runs the
same tests, without the JUnit report.

## Not run in CI yet

Each of these arrives with the work it depends on, and runs on GitHub-hosted
runners like everything else:

- Uploading reports as artefacts (the JUnit XML, the lcov coverage report,
  fuzz crash inputs, the dependency report) and posting summaries as PR
  comments. Artefacts need an action outside the allowlist, and comments need
  a write token on pull requests, so both stay with #25. Every one of these
  is in the job summary instead: test results, the coverage table, fuzz
  findings as base64, and the dependency report.
- The absolute performance budget of policy evaluation, with the benchmarks
  it is measured on (#42).
- A Postgres service container for server tests, with the first server tests
  (#126, #127).
- The mdBook build and link check, with the documentation site (#27).
- The `vm-smoke` subset of the Windows VM harness (#26).
