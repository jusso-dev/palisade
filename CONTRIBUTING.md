# Contributing to Palisade

Thanks for your interest. Palisade is an educational, personal-development project with one
maintainer. It is not a replacement for commercial application control products. Contributions
are welcome, and are reviewed on a best-effort basis (see [SUPPORT.md](SUPPORT.md)).

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md) and the
[responsible-use statement](docs/responsible-use.md).

**Security vulnerabilities, including bypasses, are never reported in issues or pull requests.**
Use [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a small fix, comment on the issue first, or open one, so the work is
  not duplicated and the design is agreed before you write code.
- Decisions that affect several crates, the security model, or what is blocked or allowed need an
  ADR (see [Architecture decisions](#architecture-decisions)).

## How issues are organised

- **Epics** are issues labelled `epic` ([#1](https://github.com/jusso-dev/palisade/issues/1) to [#18](https://github.com/jusso-dev/palisade/issues/18)). Each covers one area of the project.
- Every other issue names its parent epic at the top (`**Parent epic:** #N`), and often the issues
  it depends on (`**Depends on:** #N`).
- Every issue belongs to one [milestone](https://github.com/jusso-dev/palisade/milestones),
  from `M0 Foundations` to `M6 Compliance & Advanced`. Milestones are delivered roughly in order.
- `area:*` labels say which part of the project an issue touches, and `priority:p0` to
  `priority:p2` give its priority within the milestone.
- `good first issue` and `help wanted` mark issues that suit new contributors.

A pull request says which issue it relates to: `Closes #N` if it completes the issue, or
`Part of #N` if it delivers part of it. Say what is left and which issue it belongs to.

## Development setup

You need [rustup](https://rustup.rs) and Git. The toolchain is pinned in
`rust-toolchain.toml`, so the first `cargo` command in the repository installs the right version,
components and targets.

- **Windows**: rustup's installer offers to install the Windows C++ build tools that the
  `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` targets need. Accept that.
- **Linux and other desktop OS**: no extra system packages are needed today. Windows-only crates
  build as stubs, so the whole workspace builds and tests anywhere.
- **cargo-deny** (for the dependency check): `cargo install cargo-deny --version 0.22.0 --locked`.

To check Windows-only code from Linux or another desktop OS:

```sh
rustup target add x86_64-pc-windows-gnu
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
```

A fuller setup guide, a dev container and opt-in Git hooks are planned in [#29](https://github.com/jusso-dev/palisade/issues/29).

## Before you push

Run the same checks CI runs. [docs/ci.md](docs/ci.md) explains each one.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy -p palisade-core -p palisade-driver --no-default-features --all-targets --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo xtask check-deps
cargo xtask check-manifests
cargo xtask check-workflows
cargo deny --locked check
```

A single `cargo xtask ci` command that runs all of these is planned in [#29](https://github.com/jusso-dev/palisade/issues/29). Until it lands, run
the list above.

## Coding standards

The lints live in `[workspace.lints]` in the root `Cargo.toml`, and every crate inherits them
(`cargo xtask check-manifests` enforces that). CI runs clippy with `-D warnings`, so **every
warning fails CI**, including the lints set to `warn`.

### Errors and panics

- No `unwrap()` or `expect()` in non-test code. `clippy::unwrap_used` is denied, and
  `clippy::expect_used` warns, which fails CI. Tests may use both (`clippy.toml`).
- Return errors with enough context to act on. Do not panic on bad input: Palisade parses untrusted
  files, policy and network messages.
- `todo!()`, `unimplemented!()` and `dbg!()` are denied.
- Silent numeric truncation is flagged (`cast_possible_truncation` and related lints). Use checked
  conversions.
- Public items need doc comments (`missing_docs`).

### Unsafe code

- Today `unsafe_code` is `forbid` for the whole workspace, so no crate may contain `unsafe`.
- When unsafe code is allowed is decided in
  [ADR 0011](docs/adr/0011-msrv-and-unsafe-code-policy.md). In short: `unsafe` only in a few named
  FFI modules and the driver, every file that allows it listed in `unsafe-allowlist.txt`, which
  needs maintainer review, and an automated check that the allowlist matches the code ([#23](https://github.com/jusso-dev/palisade/issues/23)).
- Every `unsafe` block needs a `// SAFETY:` comment that explains why it is sound. Clippy's
  `undocumented_unsafe_blocks` lint is already denied.

### Naming

Docs, code, comments, commit messages and PR text must not name commercial products, vendors or
their trademarked feature names. Use the neutral terms in [docs/NAMING.md](docs/NAMING.md).
Operating system components and open standards are fine to name.

### Licence headers

Source files do **not** carry licence headers. The licence is declared once, as the SPDX
expression `Apache-2.0 OR MIT`, in `[workspace.package]`, and every crate inherits it
(`cargo xtask check-manifests` enforces that). Files copied from elsewhere keep their original
notices.

## Testing expectations

- Every change that affects behaviour comes with tests. Bug fixes include a test that fails
  without the fix.
- New rule types or condition types need **property tests** (for example: a rule never matches a
  file it should not) and **snapshot tests** of their compiled or serialised form.
- Every parser of untrusted input needs a **fuzz target**. The fuzzing setup arrives with [#29](https://github.com/jusso-dev/palisade/issues/29)
  (`fuzz`) and the parser crates; until then, say in your PR that a fuzz target is still owed.
- Test files must be benign ([responsible use](docs/responsible-use.md)). Never commit real
  malware.
- Code that only runs on Windows is gated with `#[cfg(windows)]`, so the workspace still builds
  and tests on other platforms.

## Dependencies

Every third-party dependency becomes part of the code a privileged Windows service trusts, so new
ones are added with care.

- Add the version once, in `[workspace.dependencies]` in the root `Cargo.toml`, and use
  `{ workspace = true }` in the crate. `cargo xtask check-manifests` enforces this.
- Justify every new dependency in the PR description: why it is needed, what it pulls in, and its
  licence and maintenance status.
- `cargo deny --locked check` must pass: allowed licences only, crates.io only, no known
  advisories (`deny.toml`).
- The allowed dependency directions between workspace crates are enforced by
  `cargo xtask check-deps`.

The full admission policy is tracked in [#23](https://github.com/jusso-dev/palisade/issues/23).

## Architecture decisions

Significant decisions are recorded as Architecture Decision Records (ADRs) in
[`docs/adr/`](docs/adr/README.md). [PROCESS.md](docs/adr/PROCESS.md) says when a change needs an
ADR, and how to write, number, accept and supersede one, starting from the
[template](docs/adr/0000-template.md). If you are not sure whether your change needs one, ask in
the issue. If a PR contradicts an accepted ADR, it must link a new ADR that supersedes it.
Tooling to scaffold, index and lint ADRs is planned in
[#29](https://github.com/jusso-dev/palisade/issues/29).

## Commits and pull requests

### Conventional Commits

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org):

```
<type>(<optional scope>): <summary>
```

- **Types**: `feat`, `fix`, `security`, `docs`, `ci`, `build`, `refactor`, `test`, `chore`, and
  `revert` for reverting an earlier change.
- **Scope**: a crate name without the `palisade-` prefix (`core`, `fileid`, `policy`, `agent`,
  `server`, `cli` and so on) or an area (`adr`, `deps`, `xtask`). Lowercase letters, digits and
  `-`, `.` or `_`.
- Add `!` before the colon for a breaking change, for example `feat(policy)!: …`.
- Examples: `feat(policy): add publisher rule condition`, `fix(agent): handle renamed files`,
  `docs: explain rule precedence`.

Pull requests are squash-merged, and the **PR title becomes the commit message on `main`**, which
the release changelog ([#24](https://github.com/jusso-dev/palisade/issues/24)) is generated from. The `PR title` check
(`.github/workflows/pr-title.yml`) fails a pull request whose title does not follow this format.
Edit the title to fix it; the check reruns.

### Sign-off and licensing of contributions

There is no Contributor Licence Agreement. Contributions are accepted under the project licence,
inbound = outbound ([ADR 0010](docs/adr/0010-licence.md)): unless you explicitly state otherwise,
any contribution you intentionally submit for inclusion in Palisade, as defined in the Apache-2.0
licence, is dual-licensed as `Apache-2.0 OR MIT`, without any additional terms or conditions.

Whether commits must also carry a Developer Certificate of Origin sign-off (`Signed-off-by:`,
added by `git commit -s`) is an open decision. ADR 0010 leaves it to a separate ADR, to be written
under [#28](https://github.com/jusso-dev/palisade/issues/28) and enforced by a CI check if it requires sign-off. Until then,
sign-off is welcome but not required.

### Pull request size

- One concern per pull request. Refactoring, formatting and behaviour changes go in separate PRs.
- Aim for under about 400 changed lines, not counting generated files, lockfiles and test fixtures.
  Split larger work into a series of PRs that each build, pass CI and make sense on their own.
- Fill in the pull request template. It is the reviewer's checklist.

### Review

- The `ci-ok` check and the `PR title` check must pass. The `main` branch ruleset makes both
  required ([docs/repo-settings.md](docs/repo-settings.md)).
- Changes to CI, supply-chain policy, unsafe code, the driver and signing need the maintainer's
  review ([`.github/CODEOWNERS`](.github/CODEOWNERS)).
- Workflow changes must pass `cargo xtask check-workflows`: GitHub-hosted runners only, allowlisted
  actions pinned to a full commit SHA, and read-only default permissions. Self-hosted runners and
  cloud-managed build services are never allowed ([docs/ci.md](docs/ci.md)).
