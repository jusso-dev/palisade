# 0007. Agent local store

- Status: proposed
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

The agent keeps three kinds of local state:

1. **The policy cache**: the current signed policy bundle, the previous one (last-known-good)
   and the anti-rollback record (#61, #225). The bundle bytes and their canonical encoding are
   defined by #43, and signing and encryption at rest by #225.
2. **The event queue**: events buffered while offline, then replayed in order, with a size cap
   and back-pressure (#63). Thirty days offline must survive restarts (#4).
3. **The hash cache**: file identity keyed by file ID and change stamp, so a cached lookup takes
   under 50 µs (#3, #46).

All three must survive power loss, resist tampering by non-SYSTEM users (#220), and support
encryption at rest. Issue #20 lists the candidates: a signed, memory-mappable, versioned policy
cache file, plus SQLite (through `rusqlite`) or an embedded pure-Rust key-value store (`redb` or
`sled`) for the queue and the hash cache.

## Decision drivers

1. Crash safety: no torn writes, and no lost acknowledged events after power loss.
2. Tamper evidence: changes made outside the agent are detected (#220, #225).
3. Encryption at rest for the policy cache, and optionally for the event queue.
4. Throughput and latency within the agent's resource budget (#65).
5. Dependency footprint and auditability: C code, `unsafe`, maintenance status.
6. Builds for x64 and ARM64 Windows with the GitHub-hosted toolchain.

## Considered options

Policy cache:

1. **Signed file, memory-mapped in place.** Zero-copy loading. But a mapping reflects later
   changes to the file. If anything with write access changes it after verification, the agent
   evaluates bytes it never verified (a time-of-check to time-of-use gap). It also does not fit
   AES-GCM encryption at rest (#225), which needs a decrypted copy anyway.
2. **Signed file, read whole into private memory, then verified, then parsed.** One copy per
   activation (bundles are capped at 64 MiB by #225). What is evaluated is exactly what was
   verified.
3. **Policy rows in the embedded database.** One store for everything, but a signature over a
   database is awkward, and atomic swap of a whole policy becomes a transaction design problem.

Event queue and hash cache:

1. **SQLite through `rusqlite` (bundled).** Decades of crash-safety testing, WAL mode, and an
   easy query surface for diagnostics. Brings a large C library into the privileged service, and
   encryption needs an extension or application-level encryption.
2. **`redb`.** Pure Rust, ACID with copy-on-write B-trees, a small API. Younger, and its
   power-loss behaviour on Windows has not been verified for this project.
3. **`sled`.** Pure Rust, but it has stayed in beta for years with an unstable on-disk format.
   Rejected.

## Decision

**Policy cache: option 2, decided.** The policy cache is a set of files (`active`, `previous`,
`pending`) under the agent's SYSTEM-only store directory. Each holds one signed envelope from
#225. The agent reads a file whole into private memory, verifies its signature before parsing
anything beyond the envelope, and only then decodes it. Memory mapping is not used.

The anti-rollback record (#225) is kept separately from the cache files, but it is ordered
against them. Its **floor** is the highest bundle version the agent has made `active`. The rule is
that the floor never exceeds the version of the bundle in `active`, so a crash can never leave
every bundle on disk below the floor. Activation follows #61, in this order:

1. Write `pending`, flush, and verify it. Its version must be at or above the floor. If `active`
   is *loadable* (its signature verifies and its version is at or above the floor, the same test
   as at startup), the version must also be above `active`'s version. Otherwise reject it and keep
   what is loaded (`PolicyRejected`). So while the agent runs `previous` (N-1) or the emergency
   policy because `active` (N) failed, a re-fetched copy of N is accepted, as
   [ADR 0018](0018-fail-open-vs-fail-closed-defaults-revised.md) requires.
2. If `active` is loadable, copy it to `previous` (written to a temporary file, flushed, then
   renamed). If `active` is missing, fails verification or is below the floor, leave `previous`
   untouched, so a verified last-known-good bundle is never overwritten by a bad or stale one.
3. Atomically rename `pending` over `active`, with write-through, so the rename is durable
   before the next step.
4. Only then raise the floor to the new version, in every copy of the record (#225).

A power loss before step 3 leaves the old `active` in place with the old floor. A power loss
between steps 3 and 4 leaves the new bundle in `active` with a floor below it. At every point a
verified `active` exists that the floor accepts, so a power loss mid-swap never leaves the agent
without its current policy.

At startup the agent:

- deletes any leftover `pending`. It was never activated, and the agent fetches it again;
- reads the floor as the highest value among the record's intact copies;
- loads `active` if it verifies and its version is at or above the floor, then raises the floor
  to that version if it is lower (completing an interrupted step 4). If the record's copies are
  all intact and differ only because step 4 raised some of them and not others, and the highest
  copy equals the verified `active` version, the agent raises the rest to match and does not
  raise `tamper.policy.rollback_suspected`. Any other mismatch, and any missing or corrupt copy
  once a bundle has been activated, raises it (#225) and is not treated as an interrupted step 4;
- otherwise follows the failure rows of [ADR 0018](0018-fail-open-vs-fail-closed-defaults-revised.md):
  `previous` may load below the floor only under its bounded one-step N-1 exception;
- if no bundle on disk can load, even with that exception (for example, both files were
  replaced with older, validly signed bundles), treats that as both bundles failing: it loads the built-in emergency
  policy, raises `tamper.policy.rollback_suspected`, and starts a rapid check-in. It never
  lowers the floor to make an old bundle load.

**Event queue and hash cache: proposed, leaning to `redb`, pending a spike.** The lean is `redb`,
because it keeps C code out of the privileged service and keeps the dependency tree pure Rust.
It becomes `accepted` (or is replaced by SQLite through a revised proposal) once a spike on the
Windows VM harness (#26) shows:

- **Crash safety:** at least 1,000 forced power-offs or process kills during sustained writes,
  with no corruption and no loss of committed records;
- **Throughput:** the #63 event rate and the #46 hash cache lookup target within the #65 CPU and
  memory budgets, on x64 and ARM64;
- **Size and maintenance:** added binary size, `unsafe` count, licence and maintenance status,
  checked against the #23 dependency admission policy;
- **Encryption:** a working design for encrypting records with a DPAPI-wrapped data key (#225),
  with the measured overhead.

The same spike runs against SQLite as the control. Either store keeps only data that can be
rebuilt or that is already integrity-protected: the hash cache can be recomputed, and queued
events carry their own hash chain (#220).

## Consequences

### Positive

- Policy loading has no time-of-check to time-of-use gap, and works the same with or without
  encryption at rest.
- The store decision is made on measured crash behaviour, not on reputation.

### Negative

- Reading the whole bundle costs a copy and up to 64 MiB of peak memory during activation,
  which #65 must budget for.
- #60, #63 and #46 start against a storage trait until this ADR is accepted, so the backend can
  be swapped.

## Security impact

Verify-then-parse on a private copy means a bundle that changes on disk after verification can
never reach the evaluator. That closes a policy substitution route for anyone who can write to
the cache directory. Raising the anti-rollback floor only after the rename means a power loss
cannot leave the agent with no bundle it may load, and a floor that rejects every bundle on disk
leads to the stricter emergency policy, never to a lowered floor. The store directory is SYSTEM-only (#220), and the policy cache is
authenticated by signature, not by file permissions alone. The event queue and the hash cache
are not trusted inputs to a decision without verification: a tampered hash cache entry must not
turn a deny into an allow. Binding entries to file ID and change stamp only detects that the
*file* changed; it does not protect the cache *store*. So each hash cache record is also
authenticated with an agent-held key (HMAC-SHA-256 over volume ID, file ID, change stamp and
hashes, [ADR 0017](0017-cryptographic-algorithms-and-nonces.md)), and a record that fails is discarded and
the file re-hashed (#46). The spike measures the cost of that MAC. The choice of store also changes how much C code runs in the
privileged service, which is why it is part of the spike criteria.

## Links

- Issues #20, #43 (bundle encoding), #46 (hash cache), #60, #61 (policy cache), #63 (event
  pipeline), #65 (budgets), #220 (tamper), #225 (signing and encryption), #26 (VM harness),
  #23 (dependency policy). Epics #4, #18.
- [ADR 0018](0018-fail-open-vs-fail-closed-defaults-revised.md) (failure behaviour when bundles
  fail to load).
