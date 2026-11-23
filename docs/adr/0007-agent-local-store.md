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
anything beyond the envelope, and only then decodes it. Memory mapping is not used. Activation
follows #61: write `pending`, flush, verify, then atomic rename to `active`. The anti-rollback
record is kept separately, as #225 describes.

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
the cache directory. The store directory is SYSTEM-only (#220), and the policy cache is
authenticated by signature, not by file permissions alone. The event queue and the hash cache
are not trusted inputs to a decision without verification: a tampered hash cache entry must not
turn a deny into an allow, so cache entries are bound to file ID and change stamp and are
invalidated on doubt (#46). The choice of store also changes how much C code runs in the
privileged service, which is why it is part of the spike criteria.

## Links

- Issues #20, #43 (bundle encoding), #46 (hash cache), #60, #61 (policy cache), #63 (event
  pipeline), #65 (budgets), #220 (tamper), #225 (signing and encryption), #26 (VM harness),
  #23 (dependency policy). Epics #4, #18.
