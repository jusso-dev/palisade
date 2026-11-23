# palisade-policy

The policy model, conditions, precedence and evaluation, with a decision trace. Evaluation is pure and deterministic: no network or filesystem access.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#2](https://github.com/jusso-dev/palisade/issues/2).

## Allowed dependencies

`palisade-core`, `palisade-fileid`. Must never depend on an async runtime, an HTTP client or Windows API bindings. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
