# Unknown applications

When no rule decides, the **unknown-application policy** does. Specified in
[#39](https://github.com/jusso-dev/palisade/issues/39).

Today the engine applies the **implicit deny**: anything not explicitly allowed is blocked (in
`enforce` mode) or reported (in `audit`, `monitor` and `learning`). The decision's reason code is
`implicit_deny_unknown`, so reports can tell "blocked by a rule" from "never allowed".

Planned refinements in #39: per-location and per-origin variants (user-writable folders,
files downloaded from the internet, removable or network media), graded `detect`, `restrict` and
`block` levels, prompt-based handling, and built-in safe defaults so a default-deny policy does not
stop Windows itself from working.

The smallest policy shows the implicit deny on its own, validated in CI:

```yaml
{{#include ../../../examples/policies/minimal.yaml}}
```
