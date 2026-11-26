# Rules and conditions

A **rule** is a match tree plus an action. Specified in
[#33](https://github.com/jusso-dev/palisade/issues/33) (condition trees),
[#32](https://github.com/jusso-dev/palisade/issues/32) (operators) and
[#34](https://github.com/jusso-dev/palisade/issues/34) (actions).

The tree combines criteria with `all`, `any` and `not`. Each criterion is `field operator values`:
`signer.publisher equals ["Example Software Ltd"]`. Context criteria test the user, device and
session (`user.is_admin`, `device.tags`, `session.type`) rather than the file, so a rule can say
"this publisher, but only for members of this group".

Evaluation uses three-valued logic. A criterion on a fact that was not collected is **unknown**,
and unknown never makes an allow match: an allow rule fails closed. A deny rule chooses, with
`unknown_as`, whether unknown blocks.

Rules live in **rule sets** (allowlist, blocklist, baseline, trust, elevation, containment or
mixed). A policy references rule sets by ID, so one rule set can be shared by many policies.

The actions are `allow`, `deny`, `audit` (an annotation, never a decision), `allow_contained`,
`allow_elevated`, `trust_source`, `ignore` (a performance exclusion) and `defer`. Each rule can set
**effects**: logging, upload, notification, severity and tags.

A complete example with every action, validated in CI:

```yaml
{{#include ../../../examples/policies/actions-and-effects.yaml}}
```

A **scope** narrows who, where and when a rule applies: users and groups, devices, network
location, session type and time windows. Specified in
[#38](https://github.com/jusso-dev/palisade/issues/38). A scope never identifies the object, which
is the match tree's job, and never widens a rule: a rule applies only when the policy's scope, its
rule set's assignment scope and its own scope all match. An example, validated in CI:

```yaml
{{#include ../../../examples/policies/scoped-rules.yaml}}
```

See also: [`Rule`](../reference/generated/policy/rule.md),
[`Match`](../reference/generated/policy/match.md),
[`Criterion`](../reference/generated/policy/criterion.md) and
[`Action`](../reference/generated/policy/action.md) in the policy reference.
