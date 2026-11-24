# Workspace rules

How the Cargo workspace is laid out, and the rules every crate follows. The decisions behind them
are in [ADR 0003](adr/0003-crate-boundaries-and-dependency-direction.md) (crate layout),
[ADR 0011](adr/0011-msrv-and-unsafe-code-policy.md) (MSRV and unsafe code) and
[ADR 0012](adr/0012-fail-open-vs-fail-closed-defaults.md) (panic strategy). Each rule says which
check enforces it. All the checks run in CI ([ci.md](ci.md)).

## Crates

The members are the ten crates under `crates/` plus `xtask`. `palisade-driver` is left out of
`default-members`, so a plain `cargo build` at the root does not build it. `--workspace` still
includes it. Every crate has a README with its purpose, allowed dependencies, platform support,
feature flags and stability level. `cargo xtask check-manifests` fails if the purpose paragraph
(text before the first `## ` section) or one of those sections is missing.

## Shared settings

`[workspace.package]` sets the version, edition (`2024`), MSRV (`rust-version`), licence
(`Apache-2.0 OR MIT`), repository, authors and `publish = false`. Every crate inherits all of them
and the workspace `[lints]`, and takes every dependency from `[workspace.dependencies]` with
`{ workspace = true }`. Enforced by `cargo xtask check-manifests`.

## Dependency directions

`core` ← `fileid` ← `policy` ← `proto` ← {`agent`, `server`, `cli`, `tray`}. `console` may use only
`proto`, and `driver` only `core` without `std`. `policy` never reaches `tokio`, `reqwest`,
`windows` or `windows-sys`, and `agent` never reaches a server or database stack. Enforced by
`cargo xtask check-deps`.

## Unsafe code

The workspace sets `unsafe_code = "forbid"`, so any `unsafe` fails to compile. When the first FFI
module lands, ADR 0011 lowers the workspace level to `deny`, and only these locations may then
relax the lint:

- `palisade_agent::ffi` and its submodules (`crates/palisade-agent/src/ffi.rs` or `ffi/`)
- `palisade_tray::ffi` and its submodules
- `palisade_fileid::win` and its submodules
- the whole `palisade-driver` crate

Every file that relaxes the lint (`allow`, `expect` or `warn` naming `unsafe_code` in the same
attribute, as an inner or outer attribute, including inside `cfg_attr` and macro bodies) must be
listed in
[`unsafe-allowlist.txt`](../unsafe-allowlist.txt), which needs code owner review.
`cargo xtask check-unsafe` fails if:

- a file relaxes the lint and is not listed;
- a listed file no longer relaxes it, does not exist, is listed twice, or is outside the
  locations above;
- the library or binary root of `palisade-core`, `-policy`, `-proto`, `-server`, `-console`,
  `-cli` or `xtask` does not start with `#![forbid(unsafe_code)]` (a `forbid` inside a nested
  module or function does not count, and neither does a tool path such as
  `forbid(clippy::unsafe_code)`);
- the workspace level is anything but `forbid` or `deny`, or the lint is set twice under both
  spellings (`unsafe_code` and `unsafe-code`);
- a Cargo config file in the repository (`.cargo/config.toml`, or the legacy `.cargo/config`, in
  any letter case) sets anything but `[alias]`, or an alias passes `--config`, a response file
  (`@file`), rustflags, `--cap-lints`, any `-Z` unstable option, or a lint option (`-A`,
  `--allow` and the rest, also grouped after other short flags as in `-gA`) whose operand names the
  lint. Other arguments may mention it, such as a `unsafe_code::tests` filter. Rustflags, compiler and wrapper
  overrides and `[env]` can all switch lints off, so a repository config may not set them;
- a file is a symbolic link, in the working tree or as recorded in the git index (which catches a
  link that `core.symlinks=false` checked out as a regular file), a listed file cannot be
  inspected (only a tracked file deleted from the working tree is skipped), or a Rust file (`.rs`
  in any letter case) cannot be tokenised. That includes a first line starting with `#!` that is not an inner attribute: rustc
  strips such a shebang line and the tokeniser does not, so the check fails rather than guess.

The files scanned are the ones git tracks or would track (ignored build output is skipped), and
each is tokenised with `proc-macro2`, the tokeniser procedural macros use, so comments and
literals are never mistaken for attributes. What text scanning cannot see is left to review: an
attribute a macro builds from its parameters (`#[$a($b)]`), a module loaded through `#[path]` or
`include!` from a file that is untracked or not named `.rs`, and code a build script generates. The workspace `forbid` still
applies to all of these. Every `unsafe` block also needs a `// SAFETY:` comment
(`clippy::undocumented_unsafe_blocks = "deny"`).

## Feature flags

- **Additive only.** Turning a feature on adds code or output. It never changes how a policy
  decides, so a build with more features makes the same decisions.
- **Documented.** Every feature, including optional dependencies that act as features, is listed in
  the `## Feature flags` section of the crate README. Enforced by `cargo xtask check-manifests`.
- **Each feature builds on its own.** CI runs `cargo hack check --each-feature --all-targets` on the
  portable crates, `core`, `fileid`, `policy`, `proto`, `server`, `cli` and `console` (the
  `feature-powerset` job).
- **`test-util` never reaches a release build.** It may hold fixtures and mocks. It is never in
  `default`, no other feature of the crate turns it on (so `default` cannot reach it indirectly),
  and only `[dev-dependencies]` may enable it on another crate. No `[workspace.dependencies]`
  entry may enable it, because members inherit those features in every table. Enforced by
  `cargo xtask check-manifests`.

The planned flag names, each added with the code that needs it:

| Flag | Meaning | Lands with |
|---|---|---|
| `std` | Standard library support. Off for `no_std` users such as the driver. | `palisade-core` (now) |
| `serde` | `Serialize`/`Deserialize` for public types. | `palisade-core` (now) |
| `schema` | JSON Schema descriptions (`schemars`). #19 calls this flag `schemars`; it landed in `palisade-core` as `schema` (#30), and `palisade-policy` depends on that name. | `palisade-core` (now) |
| `test-util` | Fixtures and mocks for other crates' tests. | #25, #29 |
| `etw` | Event Tracing for Windows collection in the agent. | #59 |
| `minifilter` | Agent support for the optional kernel driver. | #110 |
| `os-native-compiler` | Compiling policies with the operating system's own tooling, on a Windows build host. | #84 |
| `os-trust` | OS signature and catalog checks in `palisade-fileid` (ADR 0003). | #3 |

## Profiles

- `[profile.dev]` keeps overflow checks.
- `[profile.release]`: `lto = "thin"`, `codegen-units = 1`, `debug = "line-tables-only"` with
  `split-debuginfo = "packed"` (PDB files on Windows, which the release pipeline publishes as
  symbols in #22), and `strip = "none"`.
- `panic = "unwind"` in release. #19 suggested `abort` for agent binaries, subject to an ADR.
  [ADR 0012](adr/0012-fail-open-vs-fail-closed-defaults.md) decided `unwind`: the agent catches a
  parser panic on one crafted file and treats that file as unknown, instead of crashing the whole
  service. Cargo applies `panic` to a whole profile, so every release binary unwinds. The `no_std`
  driver is built separately and sets its own strategy (#8).
- `palisade-policy`, `palisade-fileid` and `palisade-proto` keep overflow checks in release builds
  too: decision logic, and the parsers of untrusted input.

## Toolchain and MSRV

`rust-toolchain.toml` pins one stable release with `rustfmt`, `clippy` and `llvm-tools-preview`,
and the Windows x64, Windows ARM64 and Linux x64 targets. `rust-version` in `[workspace.package]`
is the MSRV, never newer than stable minus 2. Every bump is recorded in the changelog, or in an ADR
if it drops a platform (ADR 0011). The `msrv` CI job checks the workspace on exactly that version.
