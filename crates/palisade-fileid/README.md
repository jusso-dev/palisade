# palisade-fileid

File identity: PE parsing, hashing (SHA-256, Authenticode, page and flat hashes), signature and certificate chain extraction, and version-info metadata.

**Status:** skeleton. The crate compiles but has no functionality yet. Work is tracked in [#3](https://github.com/jusso-dev/palisade/issues/3).

## Allowed dependencies

`palisade-core`. The rules are enforced by `cargo xtask check-deps`.

## Platform support

Portable parsing and hashing on all platforms. OS trust APIs, if needed, will live in a `#[cfg(windows)]` module.

## Feature flags

None yet.

## Stability

Unstable and not published. Anything may change.
