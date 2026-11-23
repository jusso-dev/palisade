# palisade-driver

An optional Windows kernel minifilter for enforcement gaps the OS-native policy formats cannot cover.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#8](https://github.com/jusso-dev/palisade/issues/8) and [#110](https://github.com/jusso-dev/palisade/issues/110).

## Allowed dependencies

`palisade-core` only, without its `std` feature. No third-party crates. The rules are enforced by `cargo xtask check-deps`.

## Platform support

Placeholder `no_std` library on every platform. The real driver needs the Windows Driver Kit and is built separately, so it is left out of the workspace `default-members`.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
