# 0010. Licence

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade is a public, educational Rust project. The repository already contains `LICENSE-MIT`
and `LICENSE-APACHE`. The licence decides who can reuse the code and on what terms, which
third-party code can be pulled in, and whether kernel sample code can be reused in the driver
(#8). Licence work in #28 (DCO, file headers, third-party notices) and #23 (the dependency
licence allowlist) depends on this decision.

## Decision drivers

1. Maximum reuse for learners and other projects, which is the point of an educational project.
2. Compatibility with the Rust ecosystem, where most crates are MIT or Apache-2.0.
3. An explicit patent grant for contributors and users.
4. No obligations that a learner reusing a small part would trip over.

## Considered options

1. **MIT only.** Simple and permissive, but no explicit patent grant.
2. **Apache-2.0 only.** Patent grant and contributor terms, but incompatible with GPLv2-only
   projects that might want to reuse the code.
3. **Apache-2.0 OR MIT (dual).** The Rust ecosystem convention. Users pick either, so they get
   the patent grant when they want it and GPLv2 compatibility when they need it.
4. **A copyleft licence (GPL or MPL).** Keeps derivatives open, but limits reuse, and mixing it
   with permissive crates complicates the release licence notices.

## Decision

Option 3. **Palisade is licensed under `Apache-2.0 OR MIT`.**

- Every crate declares `license = "Apache-2.0 OR MIT"`, inherited from `[workspace.package]` (#19).
- Contributions are accepted under the same dual licence (inbound = outbound). Whether that is
  confirmed by DCO sign-off is decided in a separate ADR under #28.
- **Dependencies** must be compatible with distributing a binary under either licence. Strong
  copyleft (GPL, AGPL) and LGPL crates are not admitted into shipped binaries. File-level weak
  copyleft (such as MPL-2.0) needs a case-by-case review under #23. The exact allowlist is
  enforced by cargo-deny (#23).
- **`palisade-driver` is assessed separately.** It is under the same dual licence by default.
  If kernel sample code is ever reused, its licence is checked before the code is merged:
  permissive sample code is kept with its notice; code under any other terms is not copied.
  The result is recorded in the driver crate README, and in a superseding ADR if the driver
  licence has to differ.

## Consequences

### Positive

- Anyone can reuse any part of Palisade with minimal obligations.
- Matches most of the dependency tree, so licence review is mostly mechanical.

### Negative

- Derivatives can be closed source. That is accepted for an educational project.
- Release artefacts must ship third-party notices (#28), and the dependency allowlist must be
  kept current (#23).

## Security impact

The licence has no direct effect on runtime security. It affects supply-chain security
indirectly: restricting dependencies to an explicit, mechanically enforced licence allowlist
(#23) means every new dependency gets reviewed when it is added, which is also when its
provenance and maintenance status are checked. Keeping kernel sample code under a review gate
stops unreviewed code from entering the most privileged component.

## Links

- Issues #20, #19 (workspace metadata), #23 (cargo-deny licences), #28 (DCO, headers, notices).
  Epic #8 (driver).
