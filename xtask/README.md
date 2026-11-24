# xtask

Repository automation for Palisade, run as `cargo xtask <command>` (the alias
is in `.cargo/config.toml`). It is a normal workspace crate, so it builds with
the pinned toolchain and needs no other tools.

| Command | What it does |
|---|---|
| `ci [--fast]` | Runs every check in `.github/workflows/ci.yml` locally, with the same commands. `--fast` skips docs, feature-powerset and msrv. A unit test keeps its step list identical to `ci.yml`. Steps: `src/ci.rs`. |
| `check-deps` | The allowed dependency directions between workspace crates, and crates banned from the `palisade-policy` and `palisade-agent` dependency trees. Rules: `src/deps.rs`. |
| `check-manifests` | Every member crate inherits version, edition, MSRV, licence, repository, authors, `publish` and lints from the workspace, and takes every dependency from `[workspace.dependencies]`. `test-util` never reaches a release build. Every crate README opens with a purpose paragraph, has the required sections and documents every feature. Rules: `src/manifests.rs`. |
| `check-unsafe` | Only files listed in `unsafe-allowlist.txt`, in the locations ADR 0011 allows, may relax the `unsafe_code` lint. Crates without an allowlisted module keep `#![forbid(unsafe_code)]` at their roots. Rules: `src/unsafe_code.rs`. |
| `check-workflows` | GitHub-hosted runners only, allowlisted and SHA-pinned actions, least-privilege permissions, and no cloud-managed build service named anywhere under `.github/`. Rules: `src/workflows.rs`; see `docs/ci.md`. |
| `test-summary <label> <junit.xml>` | Turns a nextest JUnit report into the CI job summary and one annotation per failed test. Code: `src/junit.rs`. |

Each command prints one line per violation and exits non-zero if there are
any. Each rule set has unit tests with passing and failing fixtures:
`cargo test -p xtask`. The workspace rules themselves are described in
[`docs/workspace.md`](../docs/workspace.md).

More commands (`dist`, `fixtures` and others) are planned in #29.

## Allowed dependencies

No workspace crates: no product crate may depend on `xtask`, and `xtask`
reads the workspace through `cargo metadata` instead of linking it. Third-party:
`serde_json`, `toml` and `yaml-rust2`, to read `cargo metadata` output,
manifests and workflow files; `proc-macro2`, to tokenise Rust source; and
`sha2`, for the service-name digests in `check-workflows`.

## Platform support

All platforms. It runs on every CI runner and every contributor machine.

## Feature flags

None.

## Stability

Internal tool, not published. Commands and messages may change.
