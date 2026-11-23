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
| **Clock skew, rollback or forward jump** | Time-bounded grants (exceptions, override codes, maintenance windows, tokens) follow the rules in "Time rules" below. | By default only offline override codes and tokens consult the wall clock, so changing it cannot start, extend or revive a scheduled grant. The remaining gaps are listed as accepted risks. |

**Time rules.** The *wall clock* can be changed by an administrator or a spoofed time source, so
by default only one decision uses it: redeeming an offline override code on an offline-started
agent (rule 3). The *monotonic clock* only counts forwards while the agent
runs. From these the agent keeps two values:

- **Anchored time**: the server time from an authenticated check-in reply (mTLS with server
  pinning, [ADR 0005](0005-agent-server-protocol.md)), advanced by the monotonic clock. It is
  valid until the agent process stops or the machine resumes from a sleep that the monotonic
  clock did not count. The agent is **anchored** while it holds a valid anchored time, and
  **offline-started** otherwise (after a restart or such a resume, before its next check-in).
- **The floor**: a lower bound on real time in protected storage (#220). On load it is advanced
  only by the monotonic time elapsed since the load, never by boot uptime, so a service restart
  within one boot is not counted twice. While anchored it is raised to anchored time. It is
  written every minute and at shutdown, in every state, and a write never lowers it. It does
  not count time spent powered off, so it lags real time after a shutdown.

For a scheduled grant with start `s` and end `e` (an exception or maintenance window from the
policy bundle):

1. **Anchored.** The grant is active when `s <= anchored time < e` and `e > floor`. The wall
   clock plays no part, so changing it cannot start, extend, end or revive a grant.
2. **Offline-started, default.** Grants from the policy bundle do not start or continue. A
   grant that was active when the agent stopped stays closed until the next check-in. This is
   the closed direction: scheduled work waits for the device to check in. For offline
   maintenance, an administrator uses an override code (rule 3) instead.
3. **Offline override codes and unlock tokens** (#222). A code or token is accepted only if it is authenticated by its
   secret, its ID is not in the redeemed-code list, its end is after the floor, and its validity
   window contains anchored time (when anchored) or the wall clock (when offline-started). The
   override session it opens is timed on the monotonic clock, not by `s` and `e`. Its remaining duration is kept in
   protected storage and only ever decreases, so restarts and reboots cannot lengthen it. Entries
   in the redeemed-code list are kept until the code's end is at or before the floor; after that,
   the floor check alone rejects the code.
4. **Opt-in offline scheduling.** A group may set `offline_scheduled_grants = allow`. Then, while
   offline-started, rule 1 applies with *session time* in place of anchored time. An *offline
   session* starts each time the agent becomes offline-started: at agent start, and on resume
   from an uncounted sleep. Session time is the wall clock recorded when the offline session
   started, plus the monotonic time since, so wall-clock changes during the session do not move
   it. Session time is discarded when the agent becomes anchored. The console marks groups using
   this option.
5. **Skew.** `tamper.clock.skew` is raised, depending on the state:
   - while anchored: when the wall clock differs from anchored time by more than 5 minutes;
   - when an offline session starts: when the wall clock is more than 60 s behind the floor;
   - during an offline session: when the wall clock drifts from session time by more than 60 s
     backwards or 5 minutes forwards, measured cumulatively, so small steps add up.

   The alert sets a skew latch in protected storage. Only an authenticated check-in clears it,
   and the offline-session checks stop once the agent is anchored, so a corrected clock does not
   re-set the latch. While the latch is set, rule 4 is off and rule 2 applies.

#220 implements these rules as one pure function of (wall clock, monotonic clock, stored state),
with a property-test table covering anchored, offline-started, service restart, uncounted sleep,
offline reboot, rollback, forward jump and slow drift.

**Accepted risk.** With the default rules, the wall clock only matters for offline override
codes on an offline-started agent. Someone who can change the clock (administrator rights, or a
spoofed time source) can redeem a genuine, unredeemed code outside its intended window: later,
by setting the clock back, or earlier, by setting it forward. Each code still works only once,
only while its end is after the floor, and only for its own monotonic-timed duration. They
cannot forge a code or reuse a redeemed one. The same applies to unlock tokens.

With `offline_scheduled_grants = allow`, someone who sets the clock while the agent is not running (with physical access, administrator rights, or a spoofed time source at boot) can,
until the next check-in, start a scheduled grant early or use a grant whose end the floor has not
reached. An authenticated check-in ends this: from then on rule 1 uses server time, and a clock
that is still wrong raises `tamper.clock.skew`. Check-in cannot always *detect* that it happened.
If the clock is put back right before the device reconnects, a grant used inside the time the
device was powered off looks the same as a legitimate offline run. The uploaded events still show
the grant was used offline, which is why the console marks groups with this option.

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
- By default, scheduled maintenance windows and exceptions do not run on a device that has
  restarted and cannot check in. Offline maintenance needs an override code.
- The time rules need protected storage for the floor, the redeemed-code list, the override
  session budget and the skew latch.

## Security impact

This ADR decides whether crashing, corrupting or confusing Palisade is a bypass. With these
defaults it is not: the kernel-enforced native layer survives agent failure, losing both cached
bundles leads to the stricter emergency policy, a stale policy keeps enforcing, crafted files
cannot disable a subsystem, and by default a clock change cannot start, extend or revive a scheduled grant.
There are four deliberate, bounded weak points:

1. the first-install audit window (built-in mandatory blocklists still enforce, and it ends at the
   first verified bundle);
2. the one-step N-1 fallback when `active` is corrupt (it raises a critical tamper event at once,
   it never goes further back than N-1, and the agent re-fetches N or later straight away). Only
   SYSTEM can write the cache directory (#220), so an attacker who can trigger this already has
   stronger options;
3. the driver's default `fail_safe` (the native layer still enforces, and it is configurable to
   `fail_secure`); and
4. the clock risks in "Accepted risk" above: using an unredeemed override code or token outside its window,
   and, only for groups that opt in to offline scheduling, starting or stretching scheduled
   grants until the next check-in.

All four are listed in the threat model as accepted risks (#219) and are exercised by the bypass
regression suite (#230).

## Links

- Issues #20, #19 (release profile), #39, #56, #61, #87, #113, #219, #220, #222, #225, #226, #230.
- [ADR 0002](0002-enforcement-strategy.md) (enforcement layers),
  [ADR 0005](0005-agent-server-protocol.md) (authenticated server time),
  [ADR 0007](0007-agent-local-store.md) (cache files).
