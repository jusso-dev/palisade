# 0009. Async runtime and concurrency model

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

The agent, server and CLI all do network I/O, timers and concurrent tasks. The policy engine
(#2) sits on the process-creation and image-load path, with a p99 budget under 200 µs for a
cached-identity request (#61) and deterministic output (#2). Mixing async runtimes in one binary
causes subtle bugs, and an enforcement decision that waits on the network turns a slow server
into a hung machine.

Issue #20 requires that the agent's enforcement hot path never awaits the network. Issue #61's
"lazy approval lookup" asks the server for a decision with a 2 s timeout when the local result is
deny or indeterminate. Read literally, that would hold a verdict for up to 2 s. This ADR settles
how the two fit together.

## Decision drivers

1. Enforcement latency and determinism: decisions must be fast, bounded and reproducible.
2. A decision must never depend on network availability.
3. One runtime ecosystem, compatible with the chosen protocol and server stacks
   ([ADR 0005](0005-agent-server-protocol.md), [ADR 0006](0006-server-database.md)).
4. Testability: the engine runs in plain unit and property tests and in fuzzers without a
   runtime.

## Considered options

1. **tokio everywhere, including the policy engine** (an async `evaluate`). Uniform, but it
   forces a runtime into fuzzers and the driver-facing path, and invites awaiting I/O inside a
   decision.
2. **tokio for I/O-bound binaries, a synchronous policy engine.** The engine is a pure function
   over its inputs. Callers decide how to schedule it.
3. **A smaller or different runtime, or plain threads for the agent.** Fewer dependencies, but
   tonic, axum and sqlx all assume tokio. Running two runtimes, or bridging between them, costs
   more than it saves.

## Decision

Option 2.

- **`tokio`** (multi-threaded runtime) is the only async runtime in `palisade-agent`,
  `palisade-server` and `palisade-cli`. No other runtime is added to those crates.
- **`palisade-policy` is synchronous and deterministic.** It does no I/O and reads no clock and
  no randomness itself. Time and other context arrive as inputs (the `Clock` abstraction in
  #29). It does not depend on `tokio` ([ADR 0003](0003-crate-boundaries-and-dependency-direction.md)).
  `palisade-core` and `palisade-fileid` are synchronous too.
- **The enforcement hot path never awaits the network.** In the agent, decision requests (from
  the driver, from ETW handling, from script hosts) run synchronously against the in-memory
  evaluator on dedicated threads, or through `spawn_blocking` where they start in async code.
  Policy swaps are lock-free reads (`ArcSwap`, #61).
- **Server lookups are asynchronous follow-ups, never part of the verdict.** When #61's "lazy
  approval lookup" applies (the 2 s timeout bounds the background request, not the verdict), the agent returns the local verdict immediately and sends the lookup
  in the background. If the server has an approval, it lands in the local cache and the *next*
  attempt is allowed. A verdict is never delayed waiting for the server.
- Heavy file identity work (hashing a large file) runs on a bounded blocking pool and is
  cancellable. The CPU and I/O budgets are in #65.

## Consequences

### Positive

- The engine can be property-tested, benchmarked and fuzzed with no runtime.
- Server outages and slow links cannot stall process creation.
- One runtime keeps the dependency tree and the mental model small.

### Negative

- A user whose file is approved on the server sees one block before the approval reaches the
  device. The tray message must say "approved, run it again" (#11).
- Callers must remember to move evaluation off async worker threads. The agent wraps this in a
  single entry point, so the rule is applied in one place.

## Security impact

Keeping decisions off the network removes a denial-of-service lever: an attacker who blocks or
slows the server cannot hang endpoints or force a timeout path. It also removes a bypass lever:
no verdict depends on a reply an attacker might be able to delay, spoof or race. A synchronous,
I/O-free engine with injected time is deterministic, so a decision can be replayed exactly from
its inputs for audit (#41), and fuzzing covers the code that makes decisions.

## Links

- Issues #20, #29 (`Clock` and platform traits), #41 (decision trace), #42 (performance budget),
  #56 (service host), #61 (policy cache and lazy lookup), #65 (budgets). Epics #2, #4.
