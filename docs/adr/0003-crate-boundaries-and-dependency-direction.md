# 0003. Crate boundaries and dependency direction

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade has a portable decision engine, a privileged Windows endpoint, a management server and
tooling. If they mix, a privileged service ends up linking a web framework, Windows-only code
leaks into logic that should be testable anywhere, and the trusted computing base grows. Issue
#19 defines the workspace layout. This ADR records it as a decision, together with the rule
for which crate may depend on which, and settles the open question #19 left for this ADR:
whether `palisade-fileid` should be split.

## Decision drivers

- The evaluation core (`palisade-policy`) stays small, deterministic and portable, so it can be
  unit-tested and fuzzed on any OS.
- All Windows FFI lives in a few named places.
- The agent never links server-side stacks.
- The kernel driver can share types without pulling in `std`.
- Rules can be checked mechanically from `cargo metadata`.

## Considered options

1. **One large crate with feature flags.** Simple to start, but features leak, and the
   dependency rules cannot be checked.
2. **Many fine-grained crates.** Strong isolation, but heavy to maintain for one maintainer.
3. **The ten #19 crates plus `xtask`, in strict layers.** Matches the component boundaries
   (core types, file identity, policy, wire protocol, and one crate per binary).

For `palisade-fileid`:

- **Split** into `palisade-fileid` (pure) and `palisade-fileid-win` (OS trust APIs). This gives a
  clean crate boundary, but an eleventh crate and a more complex graph.
- **Keep one crate** with a `#[cfg(windows)]` `win` module. Fewer crates. The cfg gate keeps
  Windows dependencies out of other builds.

## Decision

Option 3. The workspace has exactly these members:

| Crate | Role |
|---|---|
| `palisade-core` | Shared types (IDs, hashes, timestamps, errors, `Decision`, `Mode`). No I/O. `no_std` with `alloc`, and `std` behind a feature. |
| `palisade-fileid` | PE parsing, hashing, signatures, certificate chains, version metadata (#3). |
| `palisade-policy` | Policy model, conditions, precedence, evaluation, decision trace (#2). Pure and deterministic. |
| `palisade-proto` | Agent-server wire types, event schema, schema versioning. |
| `palisade-agent` | Windows service: ETW and code integrity collection, policy cache, enforcement glue (#4). |
| `palisade-tray` | Per-session user notifier and request UI. |
| `palisade-server` | Management server (#10). |
| `palisade-console` | Web console frontend and asset embedding. |
| `palisade-cli` | The `pal` binary (#15). |
| `palisade-driver` | Optional kernel minifilter (#8). Built separately and excluded from `default-members`. |
| `xtask` | Build and automation commands (#29). |

**Dependency direction.** In `A ← B`, `B` may depend on `A`:

- `core` ← `fileid` ← `policy` ← `proto` ← {`agent`, `server`, `cli`, `tray`}
- A crate may depend on any crate to its left, never on one to its right. The four crates in
  braces are siblings and never depend on each other (in particular, `agent` never depends on
  `server`). They talk over IPC or the network using `proto` types.
- `console` may depend only on `proto` (generated types).
- `driver` may depend only on `core`, built `no_std`.
- `agent` never depends on `server`, `axum`, `sqlx` or any HTTP server stack.
- `policy` never depends on `tokio`, `reqwest`, `windows` or `windows-sys`.
- No product crate depends on `xtask`.

These rules are enforced by `cargo xtask check-deps` (#19) for edges inside the workspace, and by
cargo-deny bans (#23) for third-party crates.

**`palisade-fileid` stays one crate.** The OS trust API backend (signature verification and
catalog lookups) lives in a `#[cfg(windows)]` module, `palisade_fileid::win`. The pure-Rust
parser is the default and is what Linux builds use. This keeps the crate list as #19 defines it,
and matches the unsafe allowlist in [ADR 0011](0011-msrv-and-unsafe-code-policy.md). A split is
reconsidered, through a superseding ADR, if the `win` module's dependencies start reaching
non-Windows builds or the module grows its own release cadence.

## Consequences

### Positive

- `palisade-policy` and its dependencies build and test on Linux and other desktop OS, and can
  be fuzzed there.
- The privileged agent's dependency tree has no web server stack, which keeps it smaller.
- Violations fail CI mechanically. They are not left to reviewer memory.

### Negative

- Sharing code between sibling binaries means moving it down a layer (usually into `proto` or
  `core`). Sometimes that feels heavier than a direct dependency.
- `palisade-fileid` carries Windows-only code behind a cfg gate, so Windows-only bugs in that
  module are only caught by the Windows CI job.

## Security impact

The layering keeps the trusted computing base small. The code that decides "may this run"
(`policy`, `fileid`, `core`) has no network or OS-specific dependencies, so it can be audited and
fuzzed in isolation. Banning server stacks from the agent removes a whole class of remotely
reachable code from the privileged endpoint service. The `no_std` `core` lets the kernel driver
share decision types without duplicating them, which avoids drift between user mode and kernel
mode decision encodings.

## Links

- Issues #19 (workspace), #20, #23 (cargo-deny bans), #29 (xtask).
- Unsafe allowlist: [ADR 0011](0011-msrv-and-unsafe-code-policy.md).
