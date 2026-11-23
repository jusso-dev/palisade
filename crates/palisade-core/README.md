# palisade-core

Shared types for every Palisade crate: identifiers, hashes, timestamps, error types and the `Decision` and `Mode` enums. It does no I/O, so the kernel driver can reuse it.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Allowed dependencies

None. This is the bottom of the dependency graph. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. `no_std` when the `std` feature is off.

## Feature flags

- `std` (default): standard library support. Turn it off for `no_std` users such as `palisade-driver`.

## Stability

Unstable and not published. Anything may change.
