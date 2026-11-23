# 0004. Default rule precedence model

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

A file often matches more than one rule: a publisher allow and a path deny, or a hash allow
inside a blocked folder. The precedence model decides which rule wins. Products in this space
use incompatible models, and a policy written for one model can mean the opposite under another:

- **Deny-wins.** Explicit deny beats explicit allow, and anything unmatched is implicitly
  denied. This is how the OS-native formats work.
- **Allow-wins.** Any matching allow beats any deny. Some products also let a more specific
  item beat a less specific one within a rule.
- **Specificity ladder.** A fixed ranking such as hash, then signer with file and version, then
  publisher, then path, with deny and allow alternating at each level.
- **First-match ordered.** Rules are numbered, the first match decides, and a catch-all sits at
  the bottom, as in a firewall.

Every model in practice also needs blocklists (recommended block rules, the vulnerable driver
blocklist) that override every kind of trust, including temporary overrides. Issue #35
specifies the full evaluation pipeline. This ADR fixes the default and the safety rules every
model must keep.

## Decision drivers

1. Safety by default: a mistaken allow must not defeat a deliberate deny.
2. Compatibility with the OS-native compile target (#6), so a policy means the same thing in
   both enforcement layers ([ADR 0002](0002-enforcement-strategy.md)).
3. Predictability: the result must not depend on rule order unless the model says it does.
4. Migration: people bring policies written for other models.
5. Essential Eight: recommended blocklists must override allow rules (ISM-1544, ISM-1659).

## Considered options

1. **Deny-wins** (explicit deny > explicit allow > implicit deny). Order-independent and safe
   by default, and it compiles directly to the OS-native formats. A broad deny can hide a
   narrow allow. Exceptions have to be written as exceptions on the deny rule.
2. **Allow-wins.** Convenient for permissive environments, but one over-broad allow defeats
   every deny. That is unsafe as a default, and it does not map to the native formats.
3. **Specificity ladder.** Intuitive ("the more exact rule wins"), but the tier of a
   multi-condition rule needs a definition, and native compilation needs extra work.
4. **First-match ordered.** Very explicit, but order-dependent. Inserting one rule can change
   decisions far away, and it does not compile cleanly to the unordered native formats.

## Decision

1. **Deny-wins is the default** `precedence_model` for every new policy.
2. **The other models are selectable per policy**: `allow_wins`, `specificity`, `first_match`
   and `priority`, as specified in #35. Selecting `allow_wins` produces a validation warning
   that it is not recommended for Essential Eight.
3. **Fixed safety tiers apply under every model.** The model only decides among ordinary rules.
   It never touches:
   - the **mandatory-deny tier** (recommended block rules, the vulnerable driver blocklist and
     tenant "never run" lists), which is evaluated first and blocks regardless of any allow,
     trust source, exception, offline override, override session, elevation or exclusion. Only
     a rule-specific, scoped, expiring `mandatory_exception` (#35) can override it; and
   - the implicit deny for unmatched files in enforce mode (#39).

## Consequences

### Positive

- The default matches the OS-native formats, so the native compiler (#6) does not need to
  reorder or rewrite rules for default policies.
- Decisions under the default do not depend on rule order, which property tests can check (#2).
- Blocklists cannot be bypassed through override codes or self-service, which removes a whole
  class of support-desk social engineering.

### Negative

- Five models means five code paths to test, and the decision trace must name the model used.
- Policies using a non-default model may not compile one-to-one to native formats. The compile
  report has to flag rules whose meaning changes (#81).
- People used to allow-wins need to rewrite "allow this file in a denied folder" as an
  exception on the deny.

## Security impact

Deny-wins fails towards blocking. A mistaken or malicious broad allow rule cannot undo a
specific deny, which limits the damage from a compromised policy author or a typo. The
non-overridable mandatory-deny tier means known bypass binaries and vulnerable drivers stay
blocked even during an override session, which is when an attacker with a stolen override code
would try to use them. Allowing other models per policy reintroduces risk, so validation warns,
and the policy's model is recorded in every decision trace (#41) for audit.

## Links

- Issues #20, #35 (precedence pipeline), #39 (unknown applications), #41 (decision trace),
  #81 (compile report). Epic #2.
