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
| **Clock skew, rollback or forward jump** | Time-bounded grants (exceptions, override codes, maintenance windows, tokens) are checked against the wall clock and Palisade's own time sources, using the rules in "Time rules" below. | Rolling the clock back can never revive an expired grant. Rolling it forward while the agent runs can never start a grant early. The remaining gap (a clock changed while the machine is off) is bounded and listed as an accepted risk. |

**Time rules.** The agent keeps two time sources besides the wall clock:

- **Anchored time**: the server time from an authenticated check-in reply (mTLS with server
  pinning, [ADR 0005](0005-agent-server-protocol.md)) received *in the current boot session*,
  plus the time elapsed since on a monotonic clock that keeps counting through sleep and
  hibernate. The wall clock never moves it. If the platform cannot guarantee that the monotonic
  clock counted through a resume, the resume is treated like a reboot.
- **The time floor**: a value persisted to protected storage (#220), plus the monotonic time
  elapsed since this boot. While anchored, the agent writes the current anchored time to it
  periodically and at shutdown. The floor only ever increases. It is a lower bound on real time,
  because it does not count time spent powered off. The wall clock never moves it.

The agent is **anchored** when it has anchored time for this boot session, and **floor-only**
otherwise (after a reboot, before the first check-in). The rules for a grant with start `s`
and end `e`:

1. **Expiry.** A grant is expired once `max(wall_clock, T) >= e`, where `T` is anchored time
   when anchored and the floor when floor-only. A grant whose end is at or before the floor is
   expired for good, whatever the wall clock says. Rolling the clock back cannot revive it.
2. **Start of a pre-scheduled grant** (a maintenance window or exception in the cached bundle
   with a future start). When anchored: `s <= min(wall_clock, anchored_time)`. When floor-only:
   `s <= wall_clock`, provided the wall clock is at or after the floor and has not jumped this
   session (see 4). A floor-only device therefore runs scheduled windows on time after an
   offline reboot, rather than skipping them.
3. **Offline override codes** (#222). A code is accepted only if its own validity window
   contains the wall clock, its end is after the floor, and its ID has not been redeemed before
   (anti-replay, recorded in protected storage). The override session it opens is timed on the
   monotonic clock, not the wall clock. A forward clock change cannot forge a code, because
   codes are authenticated by a secret (#222). It can only make a valid code fail early.
4. **Skew and jumps.**
   - Anchored: `|wall_clock - anchored_time| > 5 min` raises `tamper.clock.skew`.
   - Floor-only: `wall_clock < floor - 60 s` raises `tamper.clock.skew`. A wall clock ahead of
     the floor is normal (the machine was off), so it raises nothing.
   - In any state, a wall-clock jump relative to the monotonic clock while the agent runs, of more
     than 60 s backwards or more than 5 minutes forwards, raises `tamper.clock.skew`.
     Until the next authenticated check-in, pre-scheduled grants that had not started are kept
     closed, and grants already running keep their expiry.

**Accepted risk.** Someone who can set the firmware clock while the machine is off, or change
the time before the agent starts (both need physical access or administrator rights), can make a
floor-only device start a pre-scheduled window early. They cannot extend an expired grant or
forge an override code. The change is detected at the next authenticated check-in, when the wall
clock is compared with server time.

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
- The time rules need protected storage for the persisted floor and the redeemed-code list, and a
  monotonic clock that counts through sleep. They are more rules to test, so #220 needs a
  property-test table covering anchored, floor-only, rollback and forward-jump cases.

## Security impact

This ADR decides whether crashing, corrupting or confusing Palisade is a bypass. With these
defaults it is not: the kernel-enforced native layer survives agent failure, losing both cached
bundles leads to the stricter emergency policy, a stale policy keeps enforcing, crafted files
cannot disable a subsystem, a clock rollback cannot revive an expired grant, and a clock change
while the agent runs cannot start one early. There are four deliberate, bounded weak points:

1. the first-install audit window (built-in mandatory blocklists still enforce, and it ends at the
   first verified bundle);
2. the one-step N-1 fallback when `active` is corrupt (it raises a critical tamper event at once,
   it never goes further back than N-1, and the agent re-fetches N or later straight away). Only
   SYSTEM can write the cache directory (#220), so an attacker who can trigger this already has
   stronger options; and
3. the driver's default `fail_safe` (the native layer still enforces, and it is configurable to
   `fail_secure`); and
4. a clock changed while the machine is off can start a pre-scheduled window early on a device
   that has not yet checked in (it needs physical access or administrator rights, and it is
   detected at the next check-in).

All four are listed in the threat model as accepted risks (#219) and are exercised by the bypass
regression suite (#230).

## Links

- Issues #20, #19 (release profile), #39, #56, #61, #87, #113, #219, #220, #222, #225, #226, #230.
- [ADR 0002](0002-enforcement-strategy.md) (enforcement layers),
  [ADR 0005](0005-agent-server-protocol.md) (authenticated server time),
  [ADR 0007](0007-agent-local-store.md) (cache files).
