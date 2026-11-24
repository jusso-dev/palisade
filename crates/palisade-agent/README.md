# palisade-agent

The Windows endpoint agent: a Windows service that collects execution events, caches policy locally and drives enforcement.

**Status:** service host only. The process, component model, supervisor, lifecycle states and configuration loading are in place ([#56](https://github.com/jusso-dev/palisade/issues/56)). The only subsystem so far is `config`. Policy cache (#61), server comms (#62), ETW (#59), the installer (#57) and tamper protection (#220) come later. Parent epic: [#4](https://github.com/jusso-dev/palisade/issues/4).

## Running

```sh
palisade-agent --console [--config <path>]   # foreground, any OS, stop with Ctrl-C
palisade-agent --service [--config <path>]   # Windows only, started by the service control manager
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

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. Must never depend on `palisade-server` or any HTTP server or database stack. The rules are enforced by `cargo xtask check-deps`.

Third-party: `tokio` (the only async runtime, ADR 0009), `tracing` and `tracing-subscriber` (logging), `serde` and `toml` (configuration), and, on Windows only, `windows-service` (the safe service control manager API).

## Unsafe code

None. The crate root is `#![forbid(unsafe_code)]`. The service entry point is written by hand, not with the wrapper crate's macro, which expands to `unsafe`. FFI that needs `unsafe` will go in `palisade_agent::ffi` ([ADR 0011](../../docs/adr/0011-msrv-and-unsafe-code-policy.md)).

## Platform support

The service host is platform-independent and builds and tests on Linux, macOS and Windows. `--console` works everywhere. `--service` is Windows only; elsewhere it exits with an error.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
