# palisade-agent

The Windows endpoint agent: a Windows service that collects execution events, caches policy locally and drives enforcement.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#4](https://github.com/jusso-dev/palisade/issues/4).

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. Must never depend on `palisade-server` or any HTTP server or database stack. The rules are enforced by `cargo xtask check-deps`.

## Platform support

Windows only. On other platforms the crate builds as a stub so `cargo check --workspace` works everywhere, and the `palisade-agent` binary exits with an error.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
