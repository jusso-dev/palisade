# 0018. Fail-open versus fail-closed defaults, revised

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

This ADR supersedes [ADR 0012](0012-fail-open-vs-fail-closed-defaults.md). It keeps that
decision and its failure table, and closes three gaps found in review:

- **Emergency policy and the native policy.** ADR 0012 loads a built-in emergency policy that
  allows OS-signed binaries, but did not say what happens to the OS-native code integrity policy
  already installed on the device. If loading the emergency policy replaced or relaxed the native
  policy, a native deny (including a deny on an OS-signed binary) could be lost.
- **Sleep and reboot during an override session.** ADR 0012 kept an override session's remaining
  duration across restarts and reboots. Time that the agent does not count (powered off, or a
  sleep the monotonic clock did not count) was not deducted, so a session with ten minutes left
  could resume ten minutes of access after a day.
- **Crash order of the redeemed-code list.** ADR 0012 dropped a redeemed code's ID once the
  *live* floor passed the code's end. The floor is only written every minute. A crash before that
  write restores an older floor that no longer covers the code, while the ID is already gone.
  With the clock set back on an offline-started agent, the same code could then be redeemed
  again. The same gap exists if the agent crashes after opening a session but before the ID is
  written.

A later review found two more gaps, also closed here: the one-step N-1 fallback could reach
further back than one step after a corrupt `active` was replaced (fixed in
[ADR 0007](0007-agent-local-store.md), and referenced in the table below), and in `native_only`
mode nothing enforced the emergency policy.

The rest of the context is unchanged.

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
| **Active bundle (N) corrupt or fails verification at load** | Load `previous` (N-1) if it verifies and the anti-rollback record names it as the bundle N directly replaced ([ADR 0007](0007-agent-local-store.md)), as #225 specifies. Otherwise the next row applies. This is a **bounded, one-step exception to anti-rollback**: the anti-rollback record keeps N, so only bundles at N or above are accepted from the server. The agent raises a critical `policy.lkg_loaded` tamper event at once (not only when both bundles fail) and starts a rapid check-in to fetch a fresh bundle. | Availability: disk corruption must not lock a machine down when a verified, previously approved policy exists. N-1 may be weaker than N (for example, if N added a deny), so this is recorded as an accepted risk below. |
| **Active and previous bundles both fail, after a policy was ever accepted** (including when the anti-rollback floor rejects every bundle on disk, [ADR 0007](0007-agent-local-store.md)) | Load the built-in **emergency policy** from #225 in enforce mode: allow OS-signed binaries and Palisade itself, block the rest. Raise a critical event. The emergency policy is an extra restriction in Palisade's own layer. It never removes, replaces or relaxes the installed OS-native policies: see "Emergency policy and the native layer" below. | Corruption after enrolment is a possible attack, so it must not relax anything. |
| **No policy yet (first install, before the first bundle)** | Run the built-in safe defaults from #61: audit mode, with the mandatory blocklists (#87) enforced if the agent ships them. Report `PolicyMissing`. | Nothing has been approved yet, so there is nothing to protect by locking down. Blocking everything at install time would make deployment fail. |
| **Policy stale or past `expires_at`** | Keep enforcing the current policy. Report `PolicyStale`. Never relax automatically (#61, #225). | Staleness is not evidence that the policy is wrong. |
| **Driver absent, disconnected, timed out or version-mismatched** | Follow `driver_failure_mode` (#113). Default `fail_safe` (pass-through with audit) for early rollout rings; `fail_secure` recommended once stable. The native layer keeps enforcing either way. | The driver only adds restrictions on top of the native policy (ADR 0002), so failing it open loses the extra rules but keeps the baseline. |
| **Clock skew, rollback or forward jump** | Time-bounded grants (exceptions, override codes, maintenance windows, tokens) follow the rules in "Time rules" below. | By default only offline override codes and tokens consult the wall clock, so changing it cannot start, extend or revive a scheduled grant. The remaining gaps are listed as accepted risks. |

**Emergency policy and the native layer.** The installed OS-native code integrity policies are
enforced by the kernel and do not depend on the agent's bundle cache
([ADR 0002](0002-enforcement-strategy.md)). Loading the emergency policy:

- leaves every installed native base and supplemental policy in place and active. While in
  emergency mode the agent makes no change to native policy files at all: it does not remove,
  replace, refresh, downgrade or stage any of them. A native deny, including a deny on an
  OS-signed binary, therefore stays enforced. A native policy that was already staged from an
  earlier verified bundle (for example, one waiting for a reboot) is left as it is;
- does not compile the emergency policy to a native policy. Native deployment and activation
  stay governed by the activation contract in #6, which only deploys policies compiled from a
  verified bundle;
- applies the emergency policy only to the decisions Palisade itself makes (the driver layer when
  present, and the agent's own evaluation and reporting). A file must pass both layers, so the
  effective result is the native policy *and* the emergency policy. The emergency policy's
  "allow OS-signed binaries" can never override a native deny.

**Who enforces the emergency policy.** It depends on the `enforcement_strategy`
([ADR 0002](0002-enforcement-strategy.md)):

- `layered` or `driver_only`: the Palisade driver enforces it before execution. If the driver is
  absent or failing, the driver row of the table applies (`driver_failure_mode`).
- `native_only` (the M2 default): there is no Palisade pre-execution enforcer, so the emergency
  policy is **not enforced**. Enforcement stays at the installed native policy, which was compiled
  from the last verified bundle the device activated, so it is no weaker than a policy that was
  already approved. Rules that only the agent or driver could enforce were already reported as
  "not enforced" in this mode, and stay so. The agent applies the emergency policy to its own
  audit evaluation, so events show what it *would* block. It reports the degraded state as
  `PolicyEmergencyUnenforced` in health, with a critical `policy.emergency_loaded` event that
  says the emergency policy has no enforcer. The console shows the device as degraded until a
  verified bundle arrives.

A native emergency policy for `native_only` devices (a separate, pre-built base policy that
allows only OS-signed binaries and Palisade, and intersects with the installed one) is not part
of this decision. It would need signing inputs and possibly a reboot, so it is left to #225 and
#6.

The emergency policy itself is defined in #225. When the agent next receives a verified bundle,
it leaves emergency mode and normal activation (#61, #6) resumes.

**Time rules.** The *wall clock* can be changed by an administrator or a spoofed time source, so
by default only one decision uses it: redeeming an offline override code on an offline-started
agent (rule 3). The *monotonic clock* only counts forwards while the agent
runs. From these the agent keeps two values:

- **Anchored time**: the server time from an authenticated check-in reply (mTLS with server
  pinning, [ADR 0015](0015-agent-server-protocol-fallback-triggers.md)), advanced by the monotonic clock. It is
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
   window contains anchored time (when anchored) or the wall clock (when offline-started).
   - **Redeem before use.** The ID is written durably to the redeemed-code list, together with
     the open-session marker below, before the session takes effect. A crash after redemption
     therefore leaves the code redeemed, never reusable, and the session is still reported as
     ended at the next start.
   - **Session timing.** The session is timed on the monotonic clock, not by `s` and `e`, and it
     lasts at most the code's duration. It **ends** at the first event after which the agent can
     no longer count elapsed time itself: the agent process stopping (service stop, crash or
     restart), a reboot, or a resume from a sleep the monotonic clock did not count (the same
     events that end anchored time). A session is never resumed after such an event. The agent
     marks the session open in protected storage (written with the redeemed ID, before the session
     takes effect), and if it finds an open session at start it
     records it as ended and raises an event, so the end is reported even after a crash. Time
     the agent cannot count is therefore never credited to a session, and the access period can
     only be shorter than the code's duration, never longer. Work that needs a restart or reboot
     uses a new code after it.
   - **Pruning.** An entry in the redeemed-code list is kept until the code's end is at or before
     the floor *as stored* in protected storage. The ID is removed only after a floor write that
     covers the code's end has completed. After a crash the stored floor still covers the code,
     so the floor check alone rejects it, whatever the clock shows.
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
offline reboot, rollback, forward jump and slow drift. The table also covers an override session
across a service restart, a crash, a reboot and an uncounted sleep, and a crash at each write point:
between redeeming a code and opening its session, and between a floor write and pruning an ID.

**Accepted risk.** With the default rules, the wall clock only matters for offline override
codes on an offline-started agent. Someone who can change the clock (administrator rights, or a
spoofed time source) can redeem a genuine, unredeemed code outside its intended window: later,
by setting the clock back, or earlier, by setting it forward. Each code still works only once,
only while its end is after the floor, and only for its own monotonic-timed duration, which ends
at the next agent restart, reboot or uncounted sleep. They cannot forge a code or reuse a redeemed one: the ID is
recorded before the session opens, and it is only dropped once the stored floor alone rejects the
code. The same applies to unlock tokens.

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
- The time rules need protected storage for the floor, the redeemed-code list, the open-session
  marker and the skew latch. Writes to them are ordered: the
  redeemed ID before the session opens, and the stored floor before an ID is pruned.
- An override session ends when the agent restarts, the machine reboots, or it resumes from a
  sleep the agent could not count. Offline work that needs a restart or reboot needs a second
  code.
- While in emergency mode, no native policy change reaches the device, including one that would
  have added a deny. The device keeps its last installed native policy until a verified bundle
  arrives.
- On `native_only` devices the emergency policy has no pre-execution enforcer. Losing both
  caches leaves the device on its last installed native policy, reported as degraded, not on
  the stricter emergency policy.

## Security impact

This ADR decides whether crashing, corrupting or confusing Palisade is a bypass. With these
defaults it is not: the kernel-enforced native layer survives agent failure, losing both cached
bundles leads to the stricter emergency policy where a Palisade driver can enforce it (it only
adds restrictions on top of the installed native policy, never replacing it) and to the
unchanged, last-approved native policy on `native_only` devices, a stale policy keeps enforcing, crafted files
cannot disable a subsystem, and by default a clock change cannot start, extend or revive a scheduled grant.
There are five deliberate, bounded weak points:

1. the first-install audit window (built-in mandatory blocklists still enforce, and it ends at the
   first verified bundle);
2. the one-step N-1 fallback when `active` is corrupt (it raises a critical tamper event at once,
   it never goes further back than N-1, and the agent re-fetches N or later straight away). Only
   SYSTEM can write the cache directory (#220), so an attacker who can trigger this already has
   stronger options;
3. the driver's default `fail_safe` (the native layer still enforces, and it is configurable to
   `fail_secure`);
4. on `native_only` devices, no enforcement of the emergency policy when both caches fail (the
   last installed native policy, compiled from a verified bundle, keeps enforcing, and the device
   is reported as degraded); and
5. the clock risks in "Accepted risk" above: using an unredeemed override code or token outside its window
   (each code still opens one session, which ends at the next agent restart, reboot or uncounted
   sleep),
   and, only for groups that opt in to offline scheduling, starting or stretching scheduled
   grants until the next check-in.

All five are listed in the threat model as accepted risks (#219) and are exercised by the bypass
regression suite (#230).

## Links

- Supersedes: 0012
- Issues #20, #6 (native policy deployment and activation), #19 (release profile), #39, #56,
  #61, #87, #113, #219, #220, #222, #225 (emergency policy, anti-rollback), #226, #230.
- [ADR 0002](0002-enforcement-strategy.md) (enforcement layers),
  [ADR 0015](0015-agent-server-protocol-fallback-triggers.md) (authenticated server time),
  [ADR 0007](0007-agent-local-store.md) (cache files and anti-rollback ordering).
