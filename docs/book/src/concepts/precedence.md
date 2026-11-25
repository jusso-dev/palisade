# Precedence models

A file often matches several rules: a publisher allow and a path deny, say. The **precedence
model** decides which wins. Specified in [#35](https://github.com/jusso-dev/palisade/issues/35) and
[ADR 0004](../../../adr/0004-default-rule-precedence-model.md).

Evaluation runs in fixed stages, whatever the model:

1. **Mandatory deny.** A matching rule of a `mandatory` blocklist blocks, in every mode and every
   override session. Nothing overrides it.
2. **Exclusion.** A matching `ignore` rule makes the object `ignored`.
3. **Policy.** The policy's `precedence_model` chooses among the matching allows and denies.
4. **Unknown.** If nothing decided, the implicit deny ([Unknown applications](unknown-applications.md)).

| Model | Decides |
|---|---|
| `deny_wins` (default) | any matching deny; otherwise an allow |
| `allow_wins` | any matching allow; otherwise a deny (not recommended for Essential Eight) |
| `specificity` | the rule with the most specific identity (hash beats publisher beats path) |
| `first_match` | the lowest `order` |
| `priority` | the winning numeric `priority` |

Decisions are deterministic: every tie ends on the unique rule ID, so shuffling rule sets or
rules never changes a decision. The decision names the deciding rule **and every rule it
overrode**.

An example under `first_match`, validated in CI:

```yaml
{{#include ../../../examples/policies/first-match.yaml}}
```
