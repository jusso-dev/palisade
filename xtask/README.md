# xtask

Repository automation for Palisade, run as `cargo xtask <command>` (the alias
is in `.cargo/config.toml`). It is a normal workspace crate, so it builds with
the pinned toolchain and needs no other tools.

| Command | What it enforces |
|---|---|
| `check-deps` | The allowed dependency directions between workspace crates, and crates banned from the `palisade-policy` and `palisade-agent` dependency trees. Rules: `src/deps.rs`. |
| `check-manifests` | Every member crate inherits version, edition, MSRV, licence, repository, authors, `publish` and lints from the workspace, and takes every dependency from `[workspace.dependencies]`. `test-util` is never on by default and only dev-dependencies may enable it (an explicit `--features test-util` on the command line still can). Every crate README opens with a purpose paragraph, has the required sections and documents every feature, outside HTML comments. Rules: `src/manifests.rs`. |
| `check-unsafe` | Only files listed in `unsafe-allowlist.txt`, in the locations ADR 0011 allows, may relax the `unsafe_code` lint. Crates without an allowlisted module keep `#![forbid(unsafe_code)]` at their roots. Rules: `src/unsafe_code.rs`. |
| `check-workflows` | GitHub-hosted runners only, allowlisted and SHA-pinned actions, least-privilege permissions. Rules: `src/workflows.rs`; see `docs/ci.md`. |

Each command prints one line per violation and exits non-zero if there are
any. Each rule set has unit tests with passing and failing fixtures:
`cargo test -p xtask`. The workspace rules themselves are described in
[`docs/workspace.md`](../docs/workspace.md).

More commands (`ci`, `dist`, `fixtures` and others) are planned in #29.

## Allowed dependencies

No workspace crates: no product crate may depend on `xtask`, and `xtask`
reads the workspace through `cargo metadata` instead of linking it. Third-party:
`serde_json`, `toml` and `yaml-rust2`, to read `cargo metadata` output,
manifests and workflow files, and `proc-macro2`, to tokenise Rust source.

## Platform support

All platforms. It runs on every CI runner and every contributor machine.

## Feature flags

None.

## Stability

Internal tool, not published. Commands and messages may change.
