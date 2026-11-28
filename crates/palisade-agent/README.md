# palisade-agent

The Windows endpoint agent: a Windows service that collects execution events, caches policy locally and drives enforcement.

**Status:** service host only. The process, component model, supervisor, lifecycle states and configuration loading are in place ([#56](https://github.com/jusso-dev/palisade/issues/56)). The only subsystem so far is `config`. Policy cache (#61), server comms (#62), ETW (#59), the installer (#57) and tamper protection (#220) come later. Parent epic: [#4](https://github.com/jusso-dev/palisade/issues/4).

## Running

```sh
palisade-agent --console [--config <path>]   # foreground, any OS, stop with Ctrl-C
palisade-agent --service [--config <path>]   # Windows only, started by the service control manager
palisade-agent --simulate [--scenario <path>] # development builds only: the fake agent, see below
```

Without `--config`, the agent reads `%ProgramData%\Palisade\agent.toml` on Windows if it exists, and uses built-in defaults otherwise. If the file exists but is invalid, the agent does not start. The OS-native policy keeps enforcing while it is down ([ADR 0012](../../docs/adr/0012-fail-open-vs-fail-closed-defaults.md)).

## Configuration

Strict TOML. Unknown keys, wrong types and out-of-range values are errors. The file is limited to 64 KiB.

```toml
fail_mode = "fail_open"               # or "fail_closed"; see below
safe_mode_behaviour = "audit_only"    # "enforce_cached" | "audit_only" | "disabled"

[runtime]
worker_threads = 4                    # 1..=64; default min(4, cores)
max_blocking_threads = 8              # 1..=256; file I/O and hashing pool

[log]
level = "info"                        # "error" | "warn" | "info" | "debug" | "trace"
```

`fail_mode` defaults to `fail_open` for M1. That is a security trade-off: while the agent's decision engine is unavailable, agent-side decisions allow, and the kernel-enforced OS-native policy stays the baseline ([ADR 0002](../../docs/adr/0002-enforcement-strategy.md)). Enforcement components (#113) consume the setting.

The policy-delivered and local-override layers come with the policy cache (#61).

## Design

- `subsystem`: the `Subsystem` trait (`name`, `criticality`, `dependencies`, `run`, `health`, `start_timeout`, `stop_timeout`). A run calls `set_ready` once initialised, works until `stopped()` resolves, and returns by the given deadline.
- `supervisor`: starts subsystems in dependency order, which must be acyclic. A subsystem's dependents wait until it is ready. A run that fails is restarted with exponential backoff from 1 s to 5 min. Failure means an error, an early exit, a panic or a start timeout. A panic is contained in that subsystem's task. Three panics within 10 minutes mark the subsystem `Failed`. Shutdown runs in reverse order within a budget, and subsystems that miss their deadline are aborted.
- `lifecycle`: the agent states (`Starting`, `Running`, `Degraded`, `SafeMode`, `Updating`, `Stopping`, `Stopped`, `FailSafe`) and the legal transitions between them. A permanently failed critical subsystem forces `FailSafe`, and only stopping leaves it.
- `host`: the tokio runtime (ADR 0009), logging to standard error, the panic hook and the console run loop.
- `service` (Windows): the service control manager integration. It handles `STOP` (20 s budget) and `PRESHUTDOWN`/`SHUTDOWN` (10 s budget).

## Platform layer

The agent reads the OS only through the `palisade_core::platform` traits (#29), so its logic can be
tested on any OS against the mocks in `palisade_core::test_util`. `palisade_agent::platform` holds
the real implementations:

| Trait | Implementation | Status |
|---|---|---|
| `Clock` | `SystemClock` | Done. The one place that reads the wall clock (`clippy.toml` bans `SystemTime::now` elsewhere) |
| `FileSystem` | `StdFileSystem`; `windows::WindowsFileSystem` | Reads, size and times on every OS, opened so other processes can keep writing and deleting. On Windows, `WindowsFileSystem` adds the file ID, volume serial and USN (from the open handle), the owner SID, the security descriptor and the alternate data streams, through `palisade_fileid::win`; `StdFileSystem` reports those `Unsupported` |
| `Environment` | `StdEnvironment` | Variables, architecture and interface addresses everywhere; host name, domain and OS version from the OS on Windows. On Windows, the connection type is that of the interfaces the OS routes internet-bound IPv4 and IPv6 traffic through (`GetBestRoute2`, then `GetIfEntry2` by LUID), read on each call: wired, wireless or cellular only for an up, connected hardware interface that is not a tunnel and whose type and physical medium agree; VPN only for a virtual tunnel interface (it means some tunnel, not a trusted network, which is #38's question); offline only when neither family has a route; and `Unknown` otherwise and on other OSes |
| `Registry` | `windows::WindowsRegistry` | Done, on Windows |
| `IdentityProvider` | `windows::WindowsIdentity` | On Windows: a process's token (user, groups with deny-only flags, session ID and kind, integrity level, elevation type and state), account names, local group members by SID, and the directory group cache (filled by the directory sync, #38) |
| `ProcessInfo` | `windows::WindowsProcesses` | On Windows: process records keyed by process ID and creation time, with parent ID, image path and command line, read through one handle |
| `SignatureVerifier` | `FileidSignatures` | Every OS: embedded Authenticode signatures, chains, timestamps, expiry and revocation, and catalog lookups, all judged by `palisade_fileid`, against the trust, validity and revocation settings and the catalog store policy supplies |

The Windows identity and process backends fail closed
([ADR 0018](../../docs/adr/0018-fail-open-vs-fail-closed-defaults-revised.md)). A token is read
in full or not at all: if the OS refuses its user, groups, integrity level or elevation type, the
query fails instead of returning a token with a part guessed, so a failed elevation query never
reads as "not elevated". Only the session kind falls back: session 0 is always `Services`, whatever the protocol query says, and a non-zero session whose protocol cannot be read is `Unknown`, never `Console`. A
group that is in a token but not enabled is reported as deny-only, like a group UAC filtered,
since the OS does not use it to grant access. A process that has exited is `NotFound`, even
while a handle keeps its object alive, and a process key whose creation time does not match the
process now using its ID is `NotFound` too, so a reused process ID is never read as the process
it replaced. A local group's members are listed only if the SID names a local group whose name
resolves back to the same SID: the bare name the OS enumerates by must itself be a local group with that SID, so a local group that only shares a domain group's name is never listed in its place. An account name lookup that fails for any reason other than "no such account" is an error, not `None`.

The signature and file-system backends fail closed too. A file that cannot be read, or is larger
than the size limit (256 MiB by default), is an error, never "unsigned"; so is a file that
starts like a PE image but does not parse, or whose certificate table cannot be read
(`MalformedSignature`). A file whose hash is revoked (its flat or Authenticode SHA-256 or SHA-1)
is `RevokedByHash` on the embedded and the catalog path alike. A signature or catalog match that
relies on SHA-1 is `WeakHashAlgorithm` (ADR 0008). With no catalog store, or an incomplete one (a
load error or limit, an unreadable catalog, a truncated index), a catalog miss is an error, not
"no catalog signature", and a catalog whose expiry and revocation were never judged is not `Ok`.
Embedded signatures are judged on every call against the current settings and clock; a
catalog's own signature is judged when the store is built, so the store is rebuilt to re-judge
it, while the file's own revocation is checked on every call. The OS trust-verification API is
never consulted: it is a diagnostic cross-check (`palisade_fileid::win::trust`) and must not
decide. Owners and security descriptors are reported only on volumes where they can be relied on
(a local NTFS or ReFS physical disk), and `None` elsewhere, which writability checks read as
possibly writable; a descriptor is checked by `palisade_fileid`'s parser before it is returned; a
named stream has no file ID, volume serial or USN of its own; and a stream list the OS cut short
is `TooLarge`, never a complete list.

Each implementation passes the same contract checks as the mocks
(`palisade_core::test_util::contract`), in `tests/platform.rs`, on every CI runner. The Windows
registry, environment, identity, process and file-system tests run on the Windows runners,
against the test process itself, its token and files it creates. `tests/signatures.rs` runs the
signature backend on every OS against `palisade_fileid`'s fixtures, including the shared
`contract::signatures` check that `MockSignatures` also passes.

## The fake agent

`palisade-agent --simulate`, in a build with the `test-util` feature, replays a scripted scenario
on the mock platform and writes the agent's events to standard output, one canonical JSON event
per line. It runs on any OS, so server and console work needs no Windows machine
([docs/dev/unix.md](../../docs/dev/unix.md#the-fake-agent)).

```sh
cargo run -p palisade-agent --features test-util -- --simulate [--scenario <path>]
```

It emits `agent.started`, one `exec.decision` per step, then `agent.stopped`. The events are built
only through the platform traits: process, parent and grandparent (from the process-ID-reuse-safe
ancestry), user and session, image hash and signer, and the host. Every event passes
`Event::validate`, is numbered (`seq`) and linked to the previous one (`prev_hash`; a plain
SHA-256 placeholder until the keyed chain in #220 and #202), and the same scenario always gives the
same events. Decisions are scripted, not evaluated (evaluation comes with the policy cache, #61).
Sending the events to a server needs the agent endpoints and enrolment (#62, #126, #223).

A scenario is strict TOML (unknown keys are errors, at most 1 MiB and 10,000 steps). The built-in
one is [`scenarios/default.toml`](scenarios/default.toml).

```toml
start = "2026-01-05T09:00:00.000000Z"   # the simulated wall clock at start
mode = "audit"                          # audit | monitor | learning | enforce

[device]
hostname = "SIM-0001"
domain = "example.test"                 # optional
os_version = "10.0.26100.2314"          # major.minor.build.revision
architecture = "x64"                    # x64 | arm64 | x86
tenant_id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e61"   # UUIDv7
host_id = "01936b2e-8c4a-7b3d-9f21-0a1b2c3d4e60"     # UUIDv7

[[user]]                                # every SID a process runs as
sid = "S-1-5-21-1111111111-2222222222-3333333333-1001"
name = "alice"
domain = "EXAMPLE"                      # optional
session = "console"                     # console | remote_desktop | services
elevated = false                        # optional; elevated users hold Administrators

[[running]]                             # processes running before the first step
pid = 5120
parent = 744                            # optional
image = 'C:\Windows\explorer.exe'
user = "S-1-5-21-1111111111-2222222222-3333333333-1001"

[[step]]                                # one process start each
after_ms = 1500                         # time since the previous step, at most a day
exited = []                             # process IDs that exit first (to reuse an ID)
pid = 6200
parent = 5120
image = 'C:\Windows\System32\cmd.exe'
command_line = "cmd.exe /c ver"         # optional
user = "S-1-5-21-1111111111-2222222222-3333333333-1001"
outcome = "allowed"                     # allowed | blocked | audited
signer = "Example OS Publisher"         # optional: the image's signature publisher
```

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. Must never depend on `palisade-server` or any HTTP server or database stack. The rules are enforced by `cargo xtask check-deps`.

Workspace: `palisade-fileid`, for SIDs, signature verification and catalog lookups, and on Windows with its `os-trust` feature, for account names and the file-system context (ADR 0003: the agent is the crate that enables it).

Third-party: `tokio` (the only async runtime, ADR 0009), `tracing` and `tracing-subscriber` (logging), `serde` and `toml` (configuration), `if-addrs` (interface addresses, as in the server), and, on Windows only, `windows-service` (the safe service control manager API), `windows-registry` (safe registry reads), `windows-version` (the running OS version) and `windows-sys` (the process, token, session and local-group calls in `ffi`). With `test-util` only: `palisade-proto` (the event schema) and `sha2` (the simulator's placeholder chain).

## Unsafe code

Only in `ffi` (Windows only), the one file listed in [`unsafe-allowlist.txt`](../../unsafe-allowlist.txt) ([ADR 0011](../../docs/adr/0011-msrv-and-unsafe-code-policy.md)). It wraps the process, token, session, account and local-group calls once, each `unsafe` block with a `// SAFETY:` comment, owns every buffer it hands to the OS, closes every handle on drop, and returns raw bytes for variable-length records. The portable `platform::nt` decodes those records without `unsafe` code, checking every pointer inside a record against the record's bounds, and its tests run on every OS.

The library root cannot say `#![forbid(unsafe_code)]`, because `forbid` cannot be relaxed by `ffi`, so it keeps the workspace's `deny`, and every other module, and the binary root, forbids unsafe code itself. The service entry point is written by hand, not with the wrapper crate's macro, which expands to `unsafe`. The registry and OS version are read through safe wrapper crates.

## Platform support

The service host is platform-independent and builds and tests on Linux, other desktop OS and Windows. `--console` and `--simulate` work everywhere. `--service` and the registry, identity, process and file-system context backends are Windows only; elsewhere `--service` exits with an error.

## Feature flags

- `test-util`: the fake agent (`--simulate`) and the `simulate` module, built on `palisade-core`'s platform mocks. For development builds only, never a release build ([docs/workspace.md](../../docs/workspace.md#feature-flags)). Without it, `--simulate` exits with a message saying how to build it.

## Stability

Unstable and not published. Anything may change.
