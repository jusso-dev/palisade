# palisade-core

Shared types for every Palisade crate. It does no I/O, so the kernel driver can reuse it.

- `Uuid7`: a UUID version 7 in canonical lowercase form, and the typed IDs built on it (`PolicyId`, `RuleSetId`, `RuleId`).
- `SchemaVersion`: a strict `MAJOR.MINOR.PATCH` version, with the "same major, any minor" reader rule.
- `Mode`: the enforcement mode (#36).
- `ObjectType` and `ScriptKind`: the classes of object a decision is about (ISM-1657, ISM-1658).
- `VerificationError`: the signature verification-error taxonomy (#50). Codes 0 to 28 are the OS code integrity `VerificationError` values with the same meanings, so Palisade and OS events correlate; codes from 1000 are Palisade-specific. One table, shared by `palisade-fileid` (#50) and the OS event decoder (#58), and never renumbered.
- `path`: lexical normalisation of Windows paths (#32). Prefixes such as `\\?\` and `\??\`, device paths (through a `VolumeMap`), mixed and repeated separators, `.` and `..`, and stream-type suffixes are folded into one canonical form, so the agent's facts and the policy's values compare equal. Normalisation is idempotent.

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

## Stability

Unstable and not published. Anything may change.
