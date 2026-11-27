# xtask

Repository automation for Palisade, run as `cargo xtask <command>` (the alias
is in `.cargo/config.toml`). It is a normal workspace crate, so it builds with
the pinned toolchain and needs no other tools.

| Command | What it does |
|---|---|
| `ci [--fast]` | Runs every check in `.github/workflows/ci.yml` locally, with the same commands. `--fast` skips coverage, fuzz, docs, the book build, feature-powerset, msrv and the package, signing and server-image builds. A unit test keeps its step list identical to `ci.yml`. Steps: `src/ci.rs`. |
| `check-banned-terms [--digest <term>]` | No commercial vendor or product name in any file or path, matched as whole words in any letter case ([`docs/NAMING.md`](../docs/NAMING.md)). The list, `docs/banned-terms.txt`, holds SHA-256 digests only; `--digest` prints the line for a new term. Rules: `src/banned_terms.rs`. |
| `docs generate`, `docs check`, `docs build`, `docs serve`, `docs assemble` | The documentation site (#27): generates the reference pages, checks that they are current and that every page is in the book and accessible, builds the book with mdBook and checks its links, serves it locally with `mdbook serve`, and assembles the GitHub Pages tree. Code: `src/docs/`; see [`docs/ci.md`](../docs/ci.md#documentation-site). |
| `check-deps` | The allowed dependency directions between workspace crates, and crates banned from the `palisade-policy` and `palisade-agent` dependency trees. Rules: `src/deps.rs`. |
| `check-manifests` | Every member crate inherits version, edition, MSRV, licence, repository, authors, `publish` and lints from the workspace, and takes every dependency from `[workspace.dependencies]`. `test-util` is never on by default and only dev-dependencies may enable it (an explicit `--features test-util` on the command line still can). Every crate README has no HTML comments, opens with a purpose paragraph, has the required sections and documents every feature. Rules: `src/manifests.rs`. |
| `adr new "<title>"`, `adr index`, `adr lint` | The ADR tooling from `docs/adr/PROCESS.md`: scaffold the next ADR from the template, regenerate the index in `docs/adr/README.md`, and check every ADR's file name, number, title, Status, Date and Deciders lines, sections (present, in order, not empty), supersession links and the index. Rules: `src/adr.rs`. |
| `audit` | Runs cargo-audit with exactly the advisory ignores from `deny.toml`. |
| `check-supply-chain` | At most 10 duplicated crates, `deny.toml` ignores with an ID, a reason and an unexpired date, reasons on skips and licence exceptions, the cargo-vet criteria and exemption notes, and no `audit.toml`. Rules: `src/supply_chain.rs`; see `docs/dependencies.md`. |
| `check-unsafe` | Only files listed in `unsafe-allowlist.txt`, in the locations ADR 0011 allows, may relax the `unsafe_code` lint. Crates without an allowlisted module keep `#![forbid(unsafe_code)]` at their roots. Rules: `src/unsafe_code.rs`. |
| `check-workflows` | GitHub-hosted runners only, allowlisted and SHA-pinned actions, least-privilege permissions, and no cloud-managed build service named anywhere under `.github/`. Rules: `src/workflows.rs`; see `docs/ci.md`. |
| `threat-coverage` | The threat model (`docs/security/threat-model.md`): STRIDE rows well formed, every component considers all six categories, one mitigation row per threat in order with the same issues, every `implemented` or `verified` threat cites a check on `main`, every cited test function, fuzz target and workflow command exists, the status summary matches, and no file names an undefined threat ID. Rules: `src/threat_coverage.rs`. |
| `dist [--target <triple>] [--msi] [--sign <signer>] [--out <dir>] [--bump-patch] [--compare-sizes <file>] [--from <dir>] [--no-timestamp]` | Release-builds the Windows executables (static CRT, version resource, manifest, `/Brepro`), checks them, writes the symbols archive and size report, and with `--msi` builds and validates the installer package with the pinned WiX; on Linux, the server binary. `dist driver` explains the local-only driver package (#8). Code: `src/dist/`; see `docs/packaging.md`. |
| `sign --signer <none\|test-ca\|pfx\|cloud-hsm> [--verify] [--no-timestamp] <file>...` | Authenticode-signs PE files and packages with a SHA-256 digest and an RFC 3161 timestamp, then verifies them; secrets come from the environment and are scrubbed from output. Code: `src/release/sign.rs`; see `docs/releasing.md#code-signing`. |
| `release <prepare\|check-tag\|notes\|checksums\|verify-checksums\|verify\|provenance> ...` | The release pipeline's steps: version bump and changelog, tag checks, release notes, `SHA256SUMS`, signature verification inside packages, and the provenance hook. Code: `src/release/`; see `docs/releasing.md`. |
| `deps-report [--base <commit>]` | The dependency report on the CI job summary: duplicates, `cargo tree -d`, third-party crates per crate, third-party `unsafe` counts and their change, build scripts and proc-macros. Code: `src/report.rs`. |
| `sbom` | Reserved for #226; prints where the CycloneDX files will go (`target/dist/sbom/`) and fails. |
| `test-summary <label> <junit.xml>` | Turns a nextest JUnit report into the CI job summary and one annotation per failed test. Code: `src/junit.rs`. |
| `coverage-summary <label> <coverage.json>` | Turns a `cargo llvm-cov --json --summary-only` report into a per-crate coverage table on the job summary, with a warning for each crate below its target. Code: `src/coverage.rs`. |
| `fixtures` | Builds `palisade-fileid`'s generated fixture corpus into `target/fixtures/`, with a `MANIFEST` of hashes (release build: the RSA-3072 test keys are slow in debug). Code: `src/testdata.rs`, `crates/palisade-fileid/tests/corpus/`. |
| `golden [--update]` | Rebuilds the corpus and compares every fixture's SHA-256 with `testdata/golden/fixtures.txt`, or rewrites it. Code: `src/testdata.rs`. |
| `check-testdata` | Fails if any file in the repository starts like an executable (`MZ`) and is not allowlisted, by SHA-256 with a reason, in `testdata/manifest.txt`. Code: `src/testdata.rs`. |
| `check-fuzz-locks` | Runs `cargo metadata --locked` on every `crates/*/fuzz/Cargo.toml` and fails, with the minimal re-lock command, if a fuzz workspace's committed lockfile is out of date. Code: `src/fuzz_locks.rs`. |
| `coverage-gate --base <commit>` | Measures `palisade-policy` line coverage at `<commit>` (in a temporary worktree) and at the working tree, and fails if it decreased. Needs cargo-llvm-cov and cargo-nextest. Code: `src/coverage_gate.rs`. |
| `bench-compare --base <commit>` | Runs every criterion bench at `<commit>` and at the working tree (twice each, alternating, keeping the faster), writes a comparison table to the job summary, and fails if a median is more than 10% slower with non-overlapping confidence intervals. Code: `src/bench_compare.rs`. |
| `fuzz [--seconds N] [--target NAME \| --shard I/N]` | Builds every cargo-fuzz target, seeds its corpus from the test fixtures, runs it for `N` seconds (default 60) and writes the results, with a base64 reproducer for each finding, to the job summary. Needs the pinned nightly and cargo-fuzz. Its tests keep the target list in step with each fuzz `Cargo.toml` and `fuzz.yml`. Code: `src/fuzz.rs`; see `docs/testing.md`. |

Each command prints one line per violation and exits non-zero if there are
any. Each rule set has unit tests with passing and failing fixtures:
`cargo test -p xtask`.

The command line is declared once with clap (`src/cli.rs`): `cargo xtask
help` (or `--help`) lists every command, and `cargo xtask <command> --help`,
`-h` or `cargo xtask help <command>` prints its usage and options. A wrong
command line exits with status 2 and clap's message. Values with rules of
their own (a target triple, a signer, a shard, the fuzz time) are still
checked by the command's module. Tests in `src/help.rs` snapshot the help of
every command and sub-command (`src/snapshots/`, checked by the
`snapshots` CI job), fail if any command or argument has no help text, and
parse every command line the workflows and scripts use.

Commands that need an external tool check for it first through
`src/tools.rs`, which reads the version from the tool's version command:
a missing tool stops the command with the install line for CI's version,
and another version is a warning. `ci` and `docs build` check every tool
their steps run; `coverage-gate` checks git, cargo-llvm-cov and
cargo-nextest; `bench-compare` git; `dist --msi` the .NET runtime that runs
WiX; and `sign` (and `dist --sign`) PowerShell 7 for the signing script,
except for the `none` dry run. Each fails with every missing tool named
before it builds or runs anything. Tests run the checks against a fake
probe for each case: present, missing and at another version. The workspace rules themselves are described in
[`docs/workspace.md`](../docs/workspace.md).

More commands are planned in #29; `sbom` is filled in by #226.

## Allowed dependencies

No workspace crates: no product crate may depend on `xtask`, and `xtask`
reads the workspace through `cargo metadata` instead of linking it. Third-party:
`clap`, for the command line (the workspace's version, as `pal` and the
server use); `serde_json`, `toml` and `yaml-rust2`, to read `cargo metadata` output,
manifests, workflow files and JSON Schemas; `proc-macro2`, to tokenise Rust
source; and `sha2`, for the term digests in `check-workflows` and
`check-banned-terms`, and the WiX package checksum in `dist`.

## Platform support

All platforms. It runs on every CI runner and every contributor machine. `dist` builds Windows targets only on Windows and the server only on Linux x64, each with the platform's own linker.

## Feature flags

None.

## Stability

Internal tool, not published. Commands and messages may change.
