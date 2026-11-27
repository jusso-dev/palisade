# Exceptions and offline overrides

> **Planned.** Trust sources and overrides are designed in epic
> [#9](https://github.com/jusso-dev/palisade/issues/9). The policy engine already defines how an
> override session changes a decision; issuing one is not built yet.

A default-deny policy needs principled ways to say yes without weakening it:

- **Trust sources** ([#114](https://github.com/jusso-dev/palisade/issues/114)): trust a file by how
  it arrived, for example written by a trusted installer or updater. The `trust_source` action
  grants this, `direct` or `chained` through child processes.
- **Owner-based trust** ([#117](https://github.com/jusso-dev/palisade/issues/117)): trust files
  owned by a trusted principal.
- **Offline override codes** ([#120](https://github.com/jusso-dev/palisade/issues/120)): a
  time-boxed, device-bound, audited code for when the server cannot be reached.
- **Challenge/response** and **install windows** ([#121](https://github.com/jusso-dev/palisade/issues/121),
  [#123](https://github.com/jusso-dev/palisade/issues/123)).

One invariant holds throughout: **the mandatory blocklist always wins**
([#125](https://github.com/jusso-dev/palisade/issues/125)). An override session lowers the mode of
ordinary rules to `audit`; it never lets through what a mandatory deny blocks.

The Essential Eight requires that users cannot disable or bypass application control (ISM-0846).
Every override is therefore logged, bounded in time and scope, and reported as `allowed_override`.
