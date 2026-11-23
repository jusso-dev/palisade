# 0011. MSRV and unsafe code policy

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade parses untrusted files (#3), runs as a privileged Windows service (#4) and may load a
kernel driver (#8). Memory-safety bugs in those places are the worst kind of bug it can have.
Rust prevents them only outside `unsafe` code, so where `unsafe` is allowed is a security
decision. Windows APIs and the driver still need FFI, so `unsafe` cannot be banned outright.

The build also needs a known compiler. Contributors, CI (#21) and release builds (#24) must agree
on the toolchain, and the minimum supported Rust version (MSRV) must be stated and tested.
Issue #19 sets the rules. This ADR records them and fixes one detail #19 leaves implicit: how
"forbidden by default" and "allowed in named modules" fit together in Rust's lint system.

## Decision drivers

1. Keep `unsafe` code small, named, reviewed and impossible to add by accident.
2. Make the compiler and Clippy enforce the rules, not reviewers alone.
3. Reproducible builds: one pinned toolchain for CI and releases.
4. Do not leave contributors behind: a stated MSRV that CI checks.

## Considered options

Unsafe code:

1. **No unsafe rules.** Unacceptable for this project.
2. **`forbid(unsafe_code)` across the whole workspace.** The strongest setting, but `forbid` cannot
   be relaxed by a later `allow`. The compiler rejects `#![allow(unsafe_code)]` inside a crate
   compiled with `forbid` (error E0453, checked with the current stable compiler). The FFI modules
   could not exist.
3. **`deny` across the workspace, `forbid` at the root of every crate that has no allowlisted
   module, `allow` only in allowlisted modules, and an allowlist file checked by xtask.** The
   same strength in effect, and it compiles.

MSRV:

1. **Latest stable only.** Simplest, but every stable release forces an upgrade on contributors.
2. **A pinned toolchain for builds, plus a declared MSRV no newer than stable minus 2, tested in
   CI.** Reproducible builds and a predictable window.

## Decision

**Toolchain and MSRV**

- `rust-toolchain.toml` pins one stable release, with `rustfmt`, `clippy` and
  `llvm-tools-preview`, and the targets listed in #19. CI and releases use it.
- `rust-version` (the MSRV) is declared once in `[workspace.package]` and inherited by every
  crate. A CI job builds the workspace on the MSRV toolchain (#21).
- The MSRV is never newer than the current stable release minus 2. Every MSRV bump is recorded in
  the changelog, or in an ADR if it drops support for a platform.
- `edition = "2024"`, inherited from `[workspace.package]`.

**Unsafe code**, option 3:

- `[workspace.lints]` sets `rust.unsafe_code = "deny"`. While no allowlisted module exists yet,
  the workspace may set `forbid` instead, as #19 describes. The PR that adds the first allowlisted
  module lowers it to `deny`, since `forbid` would reject that module.
- Every crate that contains no allowlisted module adds `#![forbid(unsafe_code)]` at its crate root.
  That covers `palisade-core`, `palisade-policy`, `palisade-proto`, `palisade-server`,
  `palisade-console`, `palisade-cli` and `xtask`.
- Only these modules may say `#![allow(unsafe_code)]`:
  - `palisade_agent::ffi` and its submodules,
  - `palisade_tray::ffi` and its submodules,
  - `palisade_fileid::win` and its submodules (only if the OS trust APIs are needed;
    [ADR 0003](0003-crate-boundaries-and-dependency-direction.md)),
  - `palisade-driver`, as a whole crate.
- Every `unsafe` block has a `// SAFETY:` comment. Clippy's `undocumented_unsafe_blocks` lint is
  set to `deny`.
- `unsafe-allowlist.txt` lists the files that allow unsafe code. An xtask check lists the actual
  files and fails CI if they differ from the allowlist. The check matches every way of relaxing
  the lint: `allow(unsafe_code)` and `expect(unsafe_code)`, as inner (`#![...]`) or outer
  (`#[...]`) attributes, including inside `cfg_attr`. Changing the allowlist needs CODEOWNERS
  review (#28).

**Related lints** (from #19, in `[workspace.lints]`): `clippy.all = "deny"`,
`rust.unused_must_use = "deny"`, `rust.missing_docs = "warn"` for library crates,
`clippy.unwrap_used = "deny"` outside tests (with `allow-unwrap-in-tests = true` in
`clippy.toml`, because workspace lints also apply to test code), `clippy.expect_used = "warn"`, and
`clippy.indexing_slicing = "warn"` in the parser crates.

## Consequences

### Positive

- `unsafe` can only appear in four named places. Anywhere else, the compiler rejects it.
- Reviewers know exactly where to look, and the allowlist diff makes a new unsafe file visible.
- Builds are reproducible, and the MSRV is tested, not assumed.

### Negative

- The workspace-level lint is `deny`, not `forbid`. A crate that drops its root `forbid` could
  then allow unsafe locally. The allowlist check catches that, because it lists every file that
  allows unsafe code, whatever crate it is in.
- The toolchain pin and the MSRV need regular bumps, which are small but recurring PRs.
- `palisade-fileid` cannot `forbid` at its root because of the `win` module. Its pure-Rust parser
  modules each carry `#![forbid(unsafe_code)]` instead.

## Security impact

This ADR is the main control against memory-safety bugs in Palisade. File parsers handle
attacker-supplied input and, outside the `win` module, cannot contain `unsafe` code at all, so a
crafted file can at worst cause a panic or an error, not memory corruption. The privileged
service's FFI is confined to `ffi` modules, where every block has a written safety argument. The
kernel driver is the one crate where unsafe is pervasive, which is why it is optional, built
separately, and limited to depending on `palisade-core` (ADR 0003). Denying `unwrap` in non-test
code also removes a common source of attacker-triggered panics.

## Links

- Issues #20, #19 (workspace rules), #21 (MSRV CI job), #24 (release builds), #28 (CODEOWNERS).
- [ADR 0003](0003-crate-boundaries-and-dependency-direction.md) (crate layout).
