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
| **Panic while parsing one file** | The agent is built with `panic = "unwind"`. Each file parse runs inside its own `catch_unwind` boundary. A panic there marks that file's identity as unparseable, raises a `fileid.parse_panic` event (rate-limited, with the file's hash if one was computed), and the subsystem carries on with the next file. Any decision the agent itself makes treats an unparseable file as an unknown file (implicit deny in enforce mode, #39). Per-file panics do **not** count towards the subsystem circuit breaker below. | With `abort`, one crafted file that triggers a parser panic would crash the whole agent on every scan, blinding it in a loop. Counting per-file panics towards the breaker would let a standard user disable a subsystem by dropping three crafted files. Treating the file as unknown keeps the decision closed. |
| **Panic in a subsystem outside a per-file boundary** | The subsystem task is wrapped with `catch_unwind` and restarted (#56). After 3 such panics in 10 minutes the subsystem is marked `Failed` and a critical health alert is raised. If the failed subsystem is the one that answers driver verdict requests, the driver sees the agent as disconnected, and the driver row below applies. Aborts that unwinding cannot catch (stack overflow, out of memory) fall back to the first row (agent process crash). | A real bug, not a crafted input, is the likely cause, so it is surfaced loudly. The native layer keeps enforcing whatever the subsystem state. |
| **New bundle (`pending`) fails verification or activation** | Keep `active`. Report `PolicyRejected(reason)` (#61). | Nothing was rolled back: the device stays on the policy it already had. |
| **Active bundle (N) corrupt or fails verification at load** | Load `previous` (N-1) if it verifies, as #225 specifies. This is a **bounded, one-step exception to anti-rollback**: the anti-rollback record keeps N, so only bundles at N or above are accepted from the server. The agent raises a critical `policy.lkg_loaded` tamper event at once (not only when both bundles fail) and starts a rapid check-in to fetch a fresh bundle. | Availability: disk corruption must not lock a machine down when a verified, previously approved policy exists. N-1 may be weaker than N (for example, if N added a deny), so this is recorded as an accepted risk below. |
| **Active and previous bundles both fail, after a policy was ever accepted** | Load the built-in **emergency policy** from #225 in enforce mode: allow OS-signed binaries and Palisade itself, block the rest. Raise a critical event. | Corruption after enrolment is a possible attack, so it must not relax anything. |
| **No policy yet (first install, before the first bundle)** | Run the built-in safe defaults from #61: audit mode, with the mandatory blocklists (#87) enforced if the agent ships them. Report `PolicyMissing`. | Nothing has been approved yet, so there is nothing to protect by locking down. Blocking everything at install time would make deployment fail. |
| **Policy stale or past `expires_at`** | Keep enforcing the current policy. Report `PolicyStale`. Never relax automatically (#61, #225). | Staleness is not evidence that the policy is wrong. |
| **Driver absent, disconnected, timed out or version-mismatched** | Follow `driver_failure_mode` (#113). Default `fail_safe` (pass-through with audit) for early rollout rings; `fail_secure` recommended once stable. The native layer keeps enforcing either way. | The driver only adds restrictions on top of the native policy (ADR 0002), so failing it open loses the extra rules but keeps the baseline. |
| **Clock skew, rollback or forward jump** | Time-bounded grants (exceptions, override codes, maintenance windows, tokens) are checked against the wall clock and Palisade's own time sources, using the rules in "Time rules" below. | While the agent runs, no clock change can revive an expired grant or start one early. The remaining gap (a clock set while the agent is not running) is bounded and listed as an accepted risk. |

**Time rules.** Two clocks are involved. The *wall clock* can be changed by an administrator or
a spoofed time source. The *monotonic clock* only counts forwards while the agent process runs.
Some platforms also count it through sleep. From these the agent derives three values:

- **Anchored time.** Set from the server time in an authenticated check-in reply (mTLS with
  server pinning, [ADR 0005](0005-agent-server-protocol.md)), then advanced by the monotonic
  clock. It is valid until the agent process stops or the machine resumes from a sleep the
  monotonic clock did not count. The wall clock never moves it.
- **Session time.** At the start of each *session* the agent records the wall clock and the
  monotonic clock. Session time is that wall-clock value plus the monotonic time elapsed since.
  A session starts when the agent process starts, and on resume from an uncounted sleep. Session
  time is never persisted.
- **The floor.** A lower bound on real time, held in protected storage (#220). When the agent
  loads it, at session start, it advances it by the monotonic time elapsed since the load (never
  by the boot uptime, so a service restart within one boot is not double-counted). While
  anchored, the floor is raised to anchored time if that is higher. The agent writes it back
  every minute and at shutdown, in every state, so offline running time is kept across reboots.
  Writes only ever raise the stored value. The wall clock never moves it. The floor does not
  count time spent powered off, which is why it is only a lower bound.

The agent is **anchored** while anchored time is valid, and **floor-only** otherwise. Let `T` be
anchored time when anchored, and `max(floor, session time)` when floor-only. The agent also keeps
an **expired-grant list** in protected storage: the ID of every grant it has seen expire. The
agent checks every held grant for expiry at least every minute, alongside the floor write, so
expiries are recorded promptly. An entry, and likewise an entry in the redeemed-code list (rule
3), can be pruned once the grant's end is at or before the floor, because rule 1 then covers it.
For a grant with start `s` and end `e`:

1. **Expiry.** A grant is expired when `max(wall_clock, T) >= e`, when `e <= floor`, or when its
   ID is in the expired-grant list. Once the agent has seen a grant expire it cannot come back:
   within a session `T` keeps counting whatever the wall clock does, and the list and the floor survive reboots and
   the switch from floor-only to anchored (when `T` may drop to the real time).
2. **Start of a pre-scheduled grant** (a maintenance window or exception in the cached bundle
   with a future start). It starts when `s <= min(wall_clock, T)`. Because `T` does not follow
   the wall clock within a session, moving the wall clock forward while the agent runs cannot
   start a grant early. After an offline reboot, session time starts from the current wall
   clock, so scheduled windows still open on time rather than being skipped. The start condition
   is re-checked continuously, not once: if a later check-in shows that `s` has not really been
   reached, the grant closes again until it has.
3. **Offline override codes** (#222). A code is accepted only when its own validity window
   contains the wall clock, its end is after `T`, and its ID has not been redeemed before (the
   redeemed list is in protected storage). The override session it opens is timed on the
   monotonic clock. Codes are authenticated by a secret (#222), so no clock change can forge one.
4. **Skew and drift.** The agent compares the wall clock with `T` continuously, as a cumulative
   difference rather than step by step, so many small adjustments add up:
   - when anchored, a difference over 5 minutes in either direction;
   - when floor-only, the wall clock more than 60 s behind `T`, or more than 5 minutes ahead of
     session time;
   - at session start, a wall clock more than 60 s behind the floor.

   Each raises `tamper.clock.skew`. Until the next authenticated check-in, pre-scheduled grants
   that had not started stay closed, and grants already running keep their expiry.

**Accepted risk.** Only one gap remains. Someone who can set the clock while the agent is not
running (with the machine powered off, before the service starts, or during an uncounted sleep)
starts the next session from a false wall clock. They need physical access or administrator
rights. Until that device's next authenticated check-in, they can:

- start a pre-scheduled window early; and
- use a grant, or redeem an unused override code, whose end had not been reached when the agent
  last ran. A grant then lasts at most its remaining running time (`e` minus the floor), because
  `T` starts at or above the floor and keeps rising while the agent runs.

They cannot revive a grant the agent has seen expire, use anything whose end is at or before the
floor, or forge or replay an override code. The next authenticated check-in compares the wall
clock with server time, raises `tamper.clock.skew`, and closes any window that opened early.

**"A policy was ever accepted".** The device is treated as having had a policy if the
anti-rollback record (#225) shows a version above zero, or an `active` or `previous` cache file
exists. An unverified `pending` file does not count, so an interrupted first download leaves the
device on the first-install path. Deleting the record alone does not unlock the first-install
path. The mismatch between record copies raises `tamper.policy.rollback_suspected` (#225).

## Consequences

### Positive

- One rule covers almost every case: if Palisade has ever enforced a policy, failures keep it
  enforced or make it stricter. The bounded exceptions are listed in Security impact.
- The `#61` and `#225` behaviours are reconciled. Each applies to a different, testable state.
- A crafted file cannot use a parser panic to stop the agent reporting or to trip a subsystem
  circuit breaker.

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
- The time rules need protected storage for the floor, the expired-grant list and the
  redeemed-code list. They are subtle, so #220 must implement them as one pure function of
  (wall clock, monotonic clock, stored state) with a property-test table covering anchored,
  floor-only, service restart, uncounted sleep, offline reboot, rollback, forward jump and slow
  drift.

## Security impact

This ADR decides whether crashing, corrupting or confusing Palisade is a bypass. With these
defaults it is not: the kernel-enforced native layer survives agent failure, losing both cached
bundles leads to the stricter emergency policy, a stale policy keeps enforcing, crafted files
cannot disable a subsystem, a grant the agent has seen expire never comes back, and a clock change
while the agent runs cannot start a grant early or extend one. There are four deliberate, bounded weak points:

1. the first-install audit window (built-in mandatory blocklists still enforce, and it ends at the
   first verified bundle);
2. the one-step N-1 fallback when `active` is corrupt (it raises a critical tamper event at once,
   it never goes further back than N-1, and the agent re-fetches N or later straight away). Only
   SYSTEM can write the cache directory (#220), so an attacker who can trigger this already has
   stronger options; and
3. the driver's default `fail_safe` (the native layer still enforces, and it is configurable to
   `fail_secure`); and
4. a clock set while the agent is not running can, until the next check-in, start a pre-scheduled
   window early or stretch a grant that had not yet expired by its remaining running time (it
   needs physical access or administrator rights, and it is detected at the next check-in).

All four are listed in the threat model as accepted risks (#219) and are exercised by the bypass
regression suite (#230).

## Links

- Issues #20, #19 (release profile), #39, #56, #61, #87, #113, #219, #220, #222, #225, #226, #230.
- [ADR 0002](0002-enforcement-strategy.md) (enforcement layers),
  [ADR 0005](0005-agent-server-protocol.md) (authenticated server time),
  [ADR 0007](0007-agent-local-store.md) (cache files).
