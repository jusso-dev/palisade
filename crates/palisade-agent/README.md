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
| `FileSystem` | `StdFileSystem` | Reads, size and times on every OS, opened so other processes can keep writing and deleting. Owner SID, security descriptor, streams, file ID and USN report `Unsupported` until they are read through `palisade_fileid::win` (#54) for the file inventory (#60) |
| `Environment` | `StdEnvironment` | Variables, architecture and interface addresses everywhere; host name, domain and OS version from the OS on Windows. The connection type is `Unknown` until network location (#38) defines it |
| `Registry` | `windows::WindowsRegistry` | Done, on Windows |
| `IdentityProvider`, `ProcessInfo`, `SignatureVerifier` | | With the process tracker (#59), which reads tokens and resolves each image's identity |

Each implementation passes the same contract checks as the mocks
(`palisade_core::test_util::contract`), in `tests/platform.rs`, on every CI runner. The Windows
registry and environment tests run on the Windows runners.

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

Third-party: `tokio` (the only async runtime, ADR 0009), `tracing` and `tracing-subscriber` (logging), `serde` and `toml` (configuration), `if-addrs` (interface addresses, as in the server), and, on Windows only, `windows-service` (the safe service control manager API), `windows-registry` (safe registry reads) and `windows-version` (the running OS version). With `test-util` only: `palisade-proto` (the event schema) and `sha2` (the simulator's placeholder chain).

## Unsafe code

None. The crate root is `#![forbid(unsafe_code)]`. The service entry point is written by hand, not with the wrapper crate's macro, which expands to `unsafe`. The registry and OS version are read through safe wrapper crates. FFI that needs `unsafe` will go in `palisade_agent::ffi` ([ADR 0011](../../docs/adr/0011-msrv-and-unsafe-code-policy.md)).

## Platform support

The service host is platform-independent and builds and tests on Linux, other desktop OS and Windows. `--console` and `--simulate` work everywhere. `--service` and the registry backend are Windows only; elsewhere `--service` exits with an error.

## Feature flags

- `test-util`: the fake agent (`--simulate`) and the `simulate` module, built on `palisade-core`'s platform mocks. For development builds only, never a release build ([docs/workspace.md](../../docs/workspace.md#feature-flags)). Without it, `--simulate` exits with a message saying how to build it.

## Stability

Unstable and not published. Anything may change.
