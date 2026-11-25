# Modes

The **mode** decides whether a decision takes effect. Specified in
[#36](https://github.com/jusso-dev/palisade/issues/36).

| Mode | Effect |
|---|---|
| `disabled` | The engine is not consulted. Only a whole device can be disabled. |
| `monitor` | Evaluate fully, allow everything, report what would have been blocked. |
| `audit` | As `monitor`, with a full event for every decision. |
| `learning` | As `audit`, and every object only the implicit deny would block becomes a learning candidate. |
| `enforce` | Blocked means blocked. |

A safe rollout moves from `audit` to `enforce` in steps: per object type (`mode_by_type`, for
example scripts still in audit while executables are enforced), per rule set (`mode_override` on a
new blocklist), and per rule (`enforcement_override`). A device that has been offline too long can
switch to a stricter `mode_disconnected`. Leaving `enforce` is time-boxed, needs a reason, and
reverts automatically, even if the clock is set back.

A **mandatory deny blocks in every mode**. Only a disabled device skips it.

A staged rollout, validated in CI:

```yaml
{{#include ../../../examples/policies/staged-rollout.yaml}}
```

The audit-to-enforce walkthrough is in [Getting started](../getting-started/first-policy.md).
