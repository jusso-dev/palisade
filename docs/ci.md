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
| `test` | ubuntu-latest, windows-latest, macos-latest | `cargo test --workspace --all-features --locked` |
| `msrv` | ubuntu-latest | `cargo +1.85.0 check --workspace --all-targets --all-features --locked`, after checking that the version matches `rust-version` in `Cargo.toml` |
| `docs` | ubuntu-latest | `cargo doc --workspace --no-deps --all-features --locked` with `RUSTDOCFLAGS=-D warnings` |
| `deps` | ubuntu-latest | `cargo xtask check-deps`, `cargo xtask check-manifests`, `cargo deny --locked check` |
| `runner-guard` | ubuntu-latest | `cargo xtask check-workflows` |
| `workflow-lint` | ubuntu-latest | `actionlint` (checksum-verified release) and `zizmor --offline` |
| `ci-ok` | ubuntu-latest | Passes only if every job above succeeded |

**Branch protection requires `ci-ok`** (and the `PR title` check below). It
depends on every other job and fails if any of them failed, was cancelled or
was skipped, so new jobs are covered without changing the branch rules. The
ruleset is in [repo-settings.md](repo-settings.md#branch-protection-for-main).

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
reach the script through environment variables.

### `labels.yml` (label and milestone changes, and on demand)

| Job | Runners | What it runs |
|---|---|---|
| `validate` | ubuntu-latest | `bash .github/scripts/sync-labels.test.sh`, then `.github/scripts/sync-labels.sh --validate` |
| `sync` | ubuntu-latest | `.github/scripts/sync-labels.sh --apply` on a push to `main`; `--check` (a dry run) on a manual run unless `apply` is ticked |

Runs on pull requests and pushes to `main` that change `.github/labels.yml`,
`.github/milestones.yml`, the issue templates, `dependabot.yml`, the sync
script or the workflow. `sync` never runs on a pull request, and is the only
job here with a write scope (`issues: write`). Details:
[repo-settings.md](repo-settings.md#labels-and-milestones).

### `audit.yml` (daily at 03:17 UTC, and on demand)

Runs `cargo deny check advisories` and `cargo audit` against `main`. A new
advisory can affect `main` without any change here, which is why this is
scheduled. On failure, a second job opens an issue titled "Scheduled advisory
audit is failing" with the `area:security` label, or comments on the open
one. That job is the only place with `issues: write`.

### Dependabot (`.github/dependabot.yml`)

Weekly updates for Cargo dependencies and for the pinned action SHAs, with
minor and patch bumps grouped into one PR per ecosystem. Dependabot PRs run
the full CI like any other PR.

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

Because the check allowlists runners and actions rather than blocklisting
services, an unapproved build service fails by default. Adding a runner label
or an action is a reviewed change to `xtask/src/workflows.rs`.

Other hardening:

- Rust caches are written only from `main` (`save-if`), so PR builds,
  including forks, cannot poison them.
- Superseded PR runs are cancelled; pushes to `main` always finish.
- Every job has a `timeout-minutes` (30, or 60 for the test matrix).
- CI sets `CARGO_TERM_COLOR=always`, `CARGO_INCREMENTAL=0` and
  `RUST_BACKTRACE=1`.
- Every Cargo command uses `--locked`, so CI builds exactly `Cargo.lock`.

## Running the checks locally

The toolchain is pinned in `rust-toolchain.toml`, so rustup picks it up
automatically.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy -p palisade-core -p palisade-driver --no-default-features --all-targets --locked -- -D warnings
cargo clippy -p palisade-core --no-default-features --features schema --all-targets --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo xtask check-deps
cargo xtask check-manifests
cargo xtask check-workflows
cargo deny --locked check          # needs cargo-deny 0.22
bash .github/scripts/check-pr-title.test.sh
bash .github/scripts/check-pr-title.sh "docs: example title"
bash .github/scripts/check-dco.test.sh
bash .github/scripts/check-dco.sh origin/main HEAD
bash .github/scripts/sync-labels.test.sh   # needs jq and yq v4
bash .github/scripts/sync-labels.sh --validate
```

To check Windows-only code from Linux or another desktop OS:

```sh
rustup target add x86_64-pc-windows-gnu
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
```

A single `cargo xtask ci` command that runs all of these is planned in #29.
