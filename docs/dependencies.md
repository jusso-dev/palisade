# Dependencies and supply chain

Third-party crates make up most of the code that Palisade's privileged Windows service trusts. A
compromised or careless dependency can do anything the service can do. This page says how a
dependency gets in, and what checks it on every pull request. CI runs all of them
([ci.md](ci.md)), and `cargo xtask ci` runs them locally.

## Admitting a new dependency

Every new top-level dependency is justified in the pull request description. Say why it is
needed, and cover each of these:

| Criterion | What to check |
|---|---|
| Need | Is it worth it? A small piece of code may be better written in the crate that needs it. |
| Maintenance | Recent releases, open issues and pull requests, more than one maintainer, a security policy. |
| Use | Downloads and reverse dependencies. Widely used crates are reviewed more, by more people. |
| `unsafe` | How much it has, and whether it is documented. `cargo xtask deps-report` counts it. |
| Footprint | How many crates it pulls in, on every platform. `cargo tree -p <crate> --target all -e normal`. |
| Licence | One of the licences allowed in `deny.toml`. |
| Build-time code | Build scripts and proc-macros run on the build machine. They must not use the network; prefer crates with none. |
| Features | Use `default-features = false` and turn on only the features needed, so less code is compiled. |

Add the version once, in `[workspace.dependencies]` in the root `Cargo.toml`, and use
`{ workspace = true }` in the crate (`cargo xtask check-manifests`). The allowed directions between
workspace crates are in [workspace.md](workspace.md#dependency-directions).

Keep the agent's tree small. The agent runs as a privileged service and should pull in much
less than the server. The dependency report lists each crate's tree size separately. In the
agent, prefer `windows-sys` to `windows`: it is bindings only, so it compiles faster and ships
less.

## What runs on every pull request

| Check | Tool | Enforces |
|---|---|---|
| Lockfile | Cargo | `Cargo.lock` is committed, and every Cargo command uses `--locked`. |
| Licences | `cargo deny check licenses` | Only the licences in `deny.toml` (Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0, MPL-2.0). GPL, AGPL and LGPL fail unless an exception with a reason is added. `confidence-threshold = 0.9`. |
| Sources | `cargo deny check sources` | crates.io only. Git dependencies and other registries fail. |
| Bans | `cargo deny check bans` | No wildcard versions. `openssl` and `openssl-sys` are denied (use rustls). Duplicate versions warn. |
| Advisories | `cargo deny check advisories`, `cargo xtask audit` (cargo-audit with the same ignores) | No known vulnerability, unsound or yanked crate. Unmaintained crates fail when a workspace crate depends on them directly. |
| Audits | `cargo vet --locked` | Every crate is audited, covered by an imported audit, or exempted with a note (below). |
| Repository rules | `cargo xtask check-supply-chain` | At most 10 crates in more than one version. Every advisory ignore has an ID, a reason and an `expiry` date that has not passed, and no `audit.toml` exists. Every skip has a `reason`, and every licence exception a `# reason:` comment. The cargo-vet criteria for each workspace crate, no `[policy]` entry that lowers what dependencies need, and a note on every exemption. |
| Report | `cargo xtask deps-report` | On a PR that changes `Cargo.lock`, the job summary shows duplicates, `cargo tree -d`, third-party crates per workspace crate, every third-party crate's `unsafe` count with the change against the base branch, and the build scripts and proc-macros. A new crate with more than 100 `unsafe` keywords, or a version that adds more than 100 compared with the version it replaces, raises a warning on the run. The old counts come from the base commit: the report checks it out in a temporary git worktree and runs `cargo metadata --locked` there, which downloads and unpacks its locked crates.io packages (checksum-verified; nothing is built). If that fails, the change is shown without a warning rather than raising a false one. |

Advisories are also scanned daily (`audit.yml`), because a new advisory can affect `main`
without any change here. A failure opens or updates an issue labelled `area:security`.

To see the checks fail, add a GPL-licensed crate, a `git = "..."` dependency, or a crate from
another registry: `cargo deny check` rejects each one.

## Ignoring an advisory

Only when the vulnerable code cannot be reached, and only for a limited time. Add a table to
`[advisories] ignore` in `deny.toml`:

```toml
ignore = [
    { id = "RUSTSEC-2026-0001", reason = "only the parser is used, not the affected writer", expiry = "2027-01-31" },
]
```

`expiry` is cargo-deny's own key: it fails the advisory check once the date has passed. `cargo
xtask check-supply-chain` also fails then, and requires the ID, the reason and the date on every
entry. Review the advisory again, and renew the date with a new reason or remove the ignore.

`deny.toml` is the only place an advisory is ignored. CI runs cargo-audit as `cargo xtask audit`,
which passes the same IDs as `--ignore`, so both tools agree. A cargo-audit `audit.toml` anywhere
in the repository fails `check-supply-chain`, because it would bypass these rules.

An ignore has exactly these three keys. cargo-deny also accepts `allow`, which limits an ignore to
some dependents, but cargo-audit cannot scope an ignore, so `allow` is rejected to keep the two
tools in step. `cargo xtask audit` runs these checks before cargo-audit, so an expired or incomplete
ignore also fails the daily audit.

A licence exception works the same way, except that cargo-deny has no `reason` key for it: write a
`# reason: ...` comment on the line directly above each entry in `[licenses] exceptions`, in the
inline-array or the `[[licenses.exceptions]]` form. Each entry needs its own comment.

## cargo-vet

`supply-chain/` holds the cargo-vet files:

- `config.toml`: the criteria and exemptions. Product crates, which are shipped, require
  `safe-to-deploy` for their whole tree. `xtask` and dev-dependencies require `safe-to-run`.
- `audits.toml`: audits done for this project.
- `imports.lock`: the audits imported from trusted public audit sets, pinned.

Audits are imported from two public sets run by non-profit open-source organisations. When
cargo-vet was adopted, 6 crates were covered by imported audits, and the other 93 were recorded as
exemptions with the note "Baseline when cargo-vet was adopted". The 17 crates that the Authenticode
verifier (#247) brought in while cargo-vet was in review (`ring` and its build and platform
dependencies) are exempted the same way, with a note that names #247. The exemptions are the
backlog.
Each one is removed when the crate is audited, or when an imported audit covers it
(`cargo vet prune` removes exemptions that are no longer needed).

A new crate, or a version bump, fails `cargo vet` until one of these is done:

1. **An imported audit covers it.** Run `cargo vet` to see.
2. **You audit it.** Run `cargo vet diff <crate> <old> <new>` (or `cargo vet inspect` for a new
   crate), read the code against the criteria, then run `cargo vet certify`.
3. **It is exempted.** Only with a reason. Run `cargo vet add-exemption <crate> <version>`, then
   add a `notes` field to the entry in `config.toml` saying why it was not audited.
   `check-supply-chain` fails on an exemption without notes.

`cargo vet suggest` lists the cheapest audits to do next.

## Code that runs at build time

Build scripts (`build.rs`) and proc-macros run on the developer's or CI machine during the build,
with that machine's permissions. `cargo xtask deps-report` lists every one. Review the list when a
pull request adds one. The aim for the agent's tree is that no build script touches the network.

## Not done yet

- SBOM and provenance. `cargo xtask sbom` is reserved: it will write CycloneDX files to
  `target/dist/sbom/<crate>.cdx.json`. Generating them, attesting provenance, and deciding on
  `cargo-auditable` are in #226. The release pipeline that publishes them is #24.
- Dependabot for npm (the console) and for the server's container image. These are added when
  those files exist: #136 and #126.
