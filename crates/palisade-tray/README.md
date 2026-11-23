# palisade-tray

The per-session user notifier and request UI that runs in each Windows user session.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#146](https://github.com/jusso-dev/palisade/issues/146).

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. The rules are enforced by `cargo xtask check-deps`.

## Platform support

Windows only. On other platforms the crate builds as a stub, and the `palisade-tray` binary exits with an error.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
