# 0012. Fail-open versus fail-closed defaults

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Every enforcement component can fail. When one does, Palisade either **fails open** (allows,
keeping the machine usable) or **fails closed** (blocks, keeping the control effective). A
control that an attacker can switch off by crashing a process or corrupting a file is not a
control (ISM-0846). A control that bricks machines when a cache file is damaged will be removed
by the people it protects. The child issues make choices for individual cases (#56, #61, #113,
#220, #225), and two of them pull in different directions:

- #61 says that if both cached policies are corrupt, the agent runs built-in safe defaults in
  audit mode.
- #225 says the agent loads a built-in emergency policy that blocks everything except OS-signed
  binaries and Palisade itself, and must not fail open.

#19 also defers the release profile's `panic` strategy for the agent to this ADR, and #56 wants
to restart a panicked subsystem without restarting the whole service.

This ADR sets one rule for these cases. It relies on [ADR 0002](0002-enforcement-strategy.md):
the OS-native policy is enforced by the kernel and does not depend on the Palisade agent
process.

## Decision drivers

1. Nothing an unprivileged attacker can cause (a crash, a corrupt file, a clock change) may widen
   what is allowed.
2. A recoverable failure must not make the machine unbootable or unmanageable.
3. Failure is visible: every degraded state raises an event and shows in health.
4. Behaviour must be predictable and testable on the VM harness (#26, #230).

## Considered options

1. **Fail open everywhere.** Maximum availability, but any crash is a bypass.
2. **Fail closed everywhere,** including the driver layer and first install. Maximum security,
   but a driver fault or a bad first deploy blocks everything, including recovery tools.
3. **Fail closed for anything that holds or once held policy, fail open only where another
   enforcing layer still covers the gap, and say which case is which.** This is the option
   detailed below.

## Decision

Option 3. Case by case:

| Failure | Behaviour | Why |
|---|---|---|
| **Agent process crash or hang** | The OS-native policy keeps enforcing, because the kernel holds it. The SCM restarts the service after 5 s, and the watchdog repairs it (#56, #220). | Stopping the agent removes reporting, not enforcement. |
| **Panic in an agent subsystem** | The agent is built with `panic = "unwind"`. Each subsystem task is wrapped with `catch_unwind` and restarted (#56). After 3 panics in 10 minutes the subsystem is marked `Failed` and an alert is raised. If a panic happens while parsing a particular file, that file's identity is recorded as unparseable, and any decision the agent itself makes treats it as an unknown file (implicit deny in enforce mode, #39). | With `abort`, one crafted file that triggers a parser panic would crash the whole agent on every scan, blinding it in a loop. Unwinding confines the damage to one subsystem, and treating the file as unknown keeps the decision closed. Aborts that unwinding cannot catch (stack overflow, out of memory) fall back to the row above. |
| **Policy cache: current bundle corrupt or fails verification** | Load the previous bundle (N-1) if it verifies (#61, #225). | Last-known-good keeps the last approved policy. |
| **Policy cache: current and previous both fail, after a policy was ever accepted** | Load the built-in **emergency policy** from #225 in enforce mode: allow OS-signed binaries and Palisade itself, block the rest. Raise a critical event. | Corruption after enrolment is a possible attack, so it must not relax anything. |
| **No policy yet (first install, before the first bundle)** | Run the built-in safe defaults from #61: audit mode, with the mandatory blocklists (#87) enforced if the agent ships them. Report `PolicyMissing`. | Nothing has been approved yet, so there is nothing to protect by locking down. Blocking everything at install time would make deployment fail. |
| **Policy stale or past `expires_at`** | Keep enforcing the current policy. Report `PolicyStale`. Never relax automatically (#61, #225). | Staleness is not evidence that the policy is wrong. |
| **Driver absent, disconnected, timed out or version-mismatched** | Follow `driver_failure_mode` (#113). Default `fail_safe` (pass-through with audit) for early rollout rings; `fail_secure` recommended once stable. The native layer keeps enforcing either way. | The driver only adds restrictions on top of the native policy (ADR 0002), so failing it open loses the extra rules but keeps the baseline. |
| **Clock skew or rollback** | Expiry (exceptions, override codes, maintenance windows, tokens) is checked against *trusted time*: never earlier than the latest trusted time the agent has recorded (from a server reply, or persisted before a reboot) plus the monotonic time elapsed since. Skew over 5 minutes, or a backward jump over 60 s, raises `tamper.clock.skew` (#220). | Rolling the clock back cannot revive an expired grant. Rolling it forward only expires grants early, which is the closed direction. |

How the agent decides "a policy was ever accepted": if the anti-rollback record (#225) shows a
version above zero, or any cache file exists, the agent treats the device as having had a policy.
Deleting the record alone does not unlock the first-install path. The mismatch between record
copies raises `tamper.policy.rollback_suspected` (#225).

## Consequences

### Positive

- One rule covers every case: if Palisade has ever enforced a policy, failures keep it enforced or
  make it stricter.
- The `#61` and `#225` behaviours are reconciled. Each applies to a different, testable state.
- A crafted file cannot use a parser panic to stop the agent reporting.

### Negative

- `panic = "unwind"` makes binaries slightly larger than `abort`, and code must be unwind-safe at
  subsystem boundaries. Because Cargo applies `panic` to a whole profile, the release profile uses
  `unwind` for every binary. The no_std driver crate is built separately (#8)
  and sets its own panic strategy.
- The driver's default `fail_safe` leaves driver-only rules unenforced while the driver is down.
  The endpoint reports those rules as "not enforced" (#113), so it is not counted as effective for
  them.
- A device whose caches are both corrupted after enrolment becomes very restrictive until it gets a
  new bundle. Users will notice, which is intended.

## Security impact

This ADR decides whether crashing, corrupting or confusing Palisade is a bypass. With these
defaults it is not: the kernel-enforced native layer survives agent failure, cache corruption
leads to a stricter policy, a stale policy keeps enforcing, and clock manipulation can only
shorten grants. The two deliberate fail-open points are the first-install audit window (bounded:
built-in mandatory blocklists still enforce, and it ends at the first bundle) and the driver's default
`fail_safe` (bounded: the native layer still enforces, and it is configurable to `fail_secure`).
Both are listed in the threat model as accepted risks (#219) and are exercised by the bypass
regression suite (#230).

## Links

- Issues #20, #19 (release profile), #39, #56, #61, #87, #113, #219, #220, #222, #225, #226, #230.
- [ADR 0002](0002-enforcement-strategy.md) (enforcement layers).
