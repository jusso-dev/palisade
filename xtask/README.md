# xtask

Repository automation for Palisade, run as `cargo xtask <command>` (the alias
is in `.cargo/config.toml`). It is a normal workspace crate, so it builds with
the pinned toolchain and needs no other tools.

| Command | What it enforces |
|---|---|
| `check-deps` | The allowed dependency directions between workspace crates, and crates banned from the `palisade-policy` and `palisade-agent` dependency trees. Rules: `src/deps.rs`. |
| `check-manifests` | Every member crate inherits version, edition, MSRV, licence, repository, authors, `publish` and lints from the workspace, and takes every dependency from `[workspace.dependencies]`. Rules: `src/manifests.rs`. |
| `check-workflows` | GitHub-hosted runners only, allowlisted and SHA-pinned actions, least-privilege permissions. Rules: `src/workflows.rs`; see `docs/ci.md`. |

Each command prints one line per violation and exits non-zero if there are
any. Each rule set has unit tests with passing and failing fixtures:
`cargo test -p xtask`.

More commands (`ci`, `check-unsafe`, `dist`, `fixtures` and others) are
planned in #29.
