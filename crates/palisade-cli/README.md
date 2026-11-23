# palisade-cli

The `pal` command-line tool for policy-as-code and administration.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#15](https://github.com/jusso-dev/palisade/issues/15).

## Allowed dependencies

`palisade-core`, `palisade-fileid`, `palisade-policy`, `palisade-proto`. The rules are enforced by `cargo xtask check-deps`.

## Platform support

All platforms. Commands that talk to a local agent will be Windows only.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
