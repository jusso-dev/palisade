# xtask

Repository automation for Palisade, run as `cargo xtask <command>` (the alias
is in `.cargo/config.toml`). It is a normal workspace crate, so it builds with
the pinned toolchain and needs no other tools.

| Command | What it does |
|---|---|
| `ci [--fast]` | Runs every check in `.github/workflows/ci.yml` locally, with the same commands. `--fast` skips coverage, fuzz, docs, feature-powerset, msrv and the package and server-image builds. A unit test keeps its step list identical to `ci.yml`. Steps: `src/ci.rs`. |
| `check-deps` | The allowed dependency directions between workspace crates, and crates banned from the `palisade-policy` and `palisade-agent` dependency trees. Rules: `src/deps.rs`. |
| `check-manifests` | Every member crate inherits version, edition, MSRV, licence, repository, authors, `publish` and lints from the workspace, and takes every dependency from `[workspace.dependencies]`. `test-util` is never on by default and only dev-dependencies may enable it (an explicit `--features test-util` on the command line still can). Every crate README has no HTML comments, opens with a purpose paragraph, has the required sections and documents every feature. Rules: `src/manifests.rs`. |
| `adr new "<title>"`, `adr index`, `adr lint` | The ADR tooling from `docs/adr/PROCESS.md`: scaffold the next ADR from the template, regenerate the index in `docs/adr/README.md`, and check every ADR's file name, number, title, Status, Date and Deciders lines, sections (present, in order, not empty), supersession links and the index. Rules: `src/adr.rs`. |
| `audit` | Runs cargo-audit with exactly the advisory ignores from `deny.toml`. |
| `check-supply-chain` | At most 10 duplicated crates, `deny.toml` ignores with an ID, a reason and an unexpired date, reasons on skips and licence exceptions, the cargo-vet criteria and exemption notes, and no `audit.toml`. Rules: `src/supply_chain.rs`; see `docs/dependencies.md`. |
| `check-unsafe` | Only files listed in `unsafe-allowlist.txt`, in the locations ADR 0011 allows, may relax the `unsafe_code` lint. Crates without an allowlisted module keep `#![forbid(unsafe_code)]` at their roots. Rules: `src/unsafe_code.rs`. |
| `check-workflows` | GitHub-hosted runners only, allowlisted and SHA-pinned actions, least-privilege permissions, and no cloud-managed build service named anywhere under `.github/`. Rules: `src/workflows.rs`; see `docs/ci.md`. |
| `threat-coverage` | The threat model (`docs/security/threat-model.md`): STRIDE rows well formed, every component considers all six categories, one mitigation row per threat in order with the same issues, every `implemented` or `verified` threat cites a check on `main`, every cited test function, fuzz target and workflow command exists, the status summary matches, and no file names an undefined threat ID. Rules: `src/threat_coverage.rs`. |
| `dist [--target <triple>] [--msi] [--sign none] [--out <dir>] [--bump-patch] [--compare-sizes <file>]` | Release-builds the Windows executables (static CRT, version resource, manifest, `/Brepro`), checks them, writes the symbols archive and size report, and with `--msi` builds and validates the installer package with the pinned WiX; on Linux, the server binary. `dist driver` explains the local-only driver package (#8). Code: `src/dist/`; see `docs/packaging.md`. |
| `deps-report [--base <commit>]` | The dependency report on the CI job summary: duplicates, `cargo tree -d`, third-party crates per crate, third-party `unsafe` counts and their change, build scripts and proc-macros. Code: `src/report.rs`. |
| `sbom` | Reserved for #226; prints where the CycloneDX files will go (`target/dist/sbom/`) and fails. |
| `test-summary <label> <junit.xml>` | Turns a nextest JUnit report into the CI job summary and one annotation per failed test. Code: `src/junit.rs`. |
| `coverage-summary <label> <coverage.json>` | Turns a `cargo llvm-cov --json --summary-only` report into a per-crate coverage table on the job summary, with a warning for each crate below its target. Code: `src/coverage.rs`. |
| `fuzz [--seconds N] [--target NAME]` | Builds every cargo-fuzz target, seeds its corpus from the test fixtures, runs it for `N` seconds (default 60) and writes the results, with a base64 reproducer for each finding, to the job summary. Needs the pinned nightly and cargo-fuzz. Its tests keep the target list in step with each fuzz `Cargo.toml` and `fuzz.yml`. Code: `src/fuzz.rs`; see `docs/testing.md`. |

Each command prints one line per violation and exits non-zero if there are
any. Each rule set has unit tests with passing and failing fixtures:
`cargo test -p xtask`. The workspace rules themselves are described in
[`docs/workspace.md`](../docs/workspace.md).

More commands (`fixtures` and others) are planned in #29; `sign` comes with the release pipeline (#24), and `sbom` is filled in by #226.

## Allowed dependencies

No workspace crates: no product crate may depend on `xtask`, and `xtask`
reads the workspace through `cargo metadata` instead of linking it. Third-party:
`serde_json`, `toml` and `yaml-rust2`, to read `cargo metadata` output,
manifests and workflow files; `proc-macro2`, to tokenise Rust source; and
`sha2`, for the service-name digests in `check-workflows` and the WiX package checksum in
`dist`.

## Platform support

All platforms. It runs on every CI runner and every contributor machine. `dist` builds Windows targets only on Windows and the server only on Linux x64, each with the platform's own linker.

## Feature flags

None.

## Stability

Internal tool, not published. Commands and messages may change.
