# palisade-core

Shared types for every Palisade crate. It does no I/O, so the kernel driver can reuse it.

- `Uuid7`: a UUID version 7 in canonical lowercase form, and the typed IDs built on it (`PolicyId`, `RuleSetId`, `RuleId`).
- `SchemaVersion`: a strict `MAJOR.MINOR.PATCH` version, with the "same major, any minor" reader rule.
- `Mode`: the enforcement mode (#36).
- `ObjectType` and `ScriptKind`: the classes of object a decision is about (ISM-1657, ISM-1658).
- `VerificationError`: the signature verification-error taxonomy (#50). Codes 0 to 28 are the OS code integrity `VerificationError` values with the same meanings, so Palisade and OS events correlate; codes from 1000 are Palisade-specific. One table, shared by `palisade-fileid` (#50) and the OS event decoder (#58), and never renumbered.
- `path`: lexical normalisation of Windows paths (#32). Prefixes such as `\\?\` and `\??\`, device paths (through a `VolumeMap`), mixed and repeated separators, `.` and `..`, and stream-type suffixes are folded into one canonical form, so the agent's facts and the policy's values compare equal. Normalisation is idempotent.

- `platform`: the platform abstraction (#29). Traits for everything the agent reads from the OS: `Clock` (wall and monotonic time), `FileSystem` (reads, metadata with file ID, volume serial and USN, owner SID, security descriptor, alternate data streams), `SignatureVerifier` (embedded and catalog signatures), `IdentityProvider` (tokens, groups, sessions, integrity, elevation, the directory group cache), `ProcessInfo` (process records keyed by ID and creation time, so a reused process ID is never mistaken for the old process; `ancestry` walks parents safely), `Environment` (host, domain, OS version, architecture, addresses, connection type, variables; `expand_env_vars` expands `%NAME%`), `Registry` and `EventSink`. `Platform` bundles them for generic code; every trait but `FileSystem` is also object safe. The traits do no I/O themselves; the agent implements them.
- `test_util` (feature `test-util`): an in-memory mock of each platform trait, `MockPlatform` bundling them, and `contract`, the checks that the mocks and the agent's real implementations both pass.

Hashes, timestamps, error types and `Decision` are still to come (#2, #3, #34).

**Status:** early. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Allowed dependencies

No workspace crates. This is the bottom of the dependency graph, and the rules are enforced by `cargo xtask check-deps`. The only third-party dependencies are optional: `serde` and `schemars`, both built without `std`.

## Platform support

All platforms. `no_std` (with `alloc`) when the `std` feature is off, with or without `serde` and `schema`.

## Feature flags

- `std` (default): standard library support. Turn it off for `no_std` users such as `palisade-driver`.
- `serde`: `Serialize` and `Deserialize` for every type. Text forms are the canonical ones above; enums are `snake_case` strings.
- `schema`: `schemars::JsonSchema` for every type, used by `palisade-policy` to generate the policy JSON Schema. Implies `serde`.
- `test-util`: the `test_util` module (platform mocks and contract checks). For tests and the agent's simulator only; only `[dev-dependencies]` and other crates' `test-util` features may turn it on, never a release build. Works without `std`.

## Stability

Unstable and not published. Anything may change.
