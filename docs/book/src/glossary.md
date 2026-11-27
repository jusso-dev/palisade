# Glossary

**Allowlist.** A rule set of things that may run. Under default-deny, everything not on it is
blocked.

**Application control.** Allowing only approved code to run. ASD's definition covers executables,
libraries, scripts, installers, compiled HTML, HTML applications, control panel applets and
drivers.

**Authenticode.** The code-signing format for Windows files. Palisade parses the signature, the
certificate chain and the image hash itself ([`palisade-fileid`](../../../crates/palisade-fileid/README.md)).

**Audit mode.** Decisions are evaluated and logged but not enforced. See [Modes](concepts/modes.md).

**Blocklist.** A rule set of things that may not run. A **mandatory** blocklist is decided before
every other rule and is never overridden.

**Catalog.** A signed file that lists the hashes of other files, so unsigned files can be trusted
through it.

**Condition tree.** A rule's match: `all`, `any` and `not` over criteria.
See [Rules and conditions](concepts/rules-and-conditions.md).

**Criterion.** One test of one fact: `field operator values`.

**Decision.** The engine's answer for one object: the outcome, the deciding rule, the rules it
overrode, and why. See [Decision trace](concepts/decision-trace.md).

**Effective policy.** The single policy a device evaluates, after the group hierarchy is merged.

**Essential Eight.** ASD's eight baseline mitigation strategies, with Maturity Levels One to Three.
See [Compliance](compliance/README.md).

**Identity criterion.** A criterion about the file itself: hash, signer, path or metadata. See
[Identities](concepts/identities.md).

**Implicit deny.** The decision when no rule decides: blocked, or reported in non-enforcing modes.

**ISM.** ASD's Information Security Manual.

**Learning mode.** Audit mode that also marks objects only the implicit deny would block as
candidates for new rules.

**Mode.** `disabled`, `monitor`, `audit`, `learning` or `enforce`. See [Modes](concepts/modes.md).

**OS-native policy.** The operating system's own code integrity and rule-collection policy
formats, which Palisade compiles to ([ADR 0002](../../adr/0002-enforcement-strategy.md)).

**Override session.** A time-boxed, audited relaxation of ordinary rules on one device. See
[Exceptions and offline overrides](concepts/exceptions-and-overrides.md).

**Precedence model.** How the matching rules are combined into one decision. See
[Precedence models](concepts/precedence.md).

**Rule set.** A named, reusable, ordered collection of rules, referenced by policies.

**Trust source.** A process whose output is trusted, such as an installer or updater.
