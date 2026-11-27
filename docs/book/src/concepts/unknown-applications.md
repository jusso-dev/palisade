# Unknown applications

When no rule decides, the **unknown-application policy** (`policy.unknown`) does. Specified in
[#39](https://github.com/jusso-dev/palisade/issues/39). It never overrides an explicit allow or
deny.

By default it applies the **implicit deny**: anything not explicitly allowed is blocked (in
`enforce` mode) or reported (in `audit`, `monitor` and `learning`). The decision's reason code is
`implicit_deny_unknown`, so reports can tell "blocked by a rule" from "never allowed".

The smallest policy shows the implicit deny on its own, validated in CI:

```yaml
{{#include ../../../examples/policies/minimal.yaml}}
```

## Levels and overrides

A policy can choose a level other than `block` for unknown objects: `restrict` (run in a
containment profile), `prompt` (ask the user), `detect` (allow and report) or `allow`. It can set
that level per object type, per location class (`user_profile`, `temp`, `program_files`,
`removable`, `network` and others) and per origin (`internet`, `email_attachment`,
`removable_copy` and others). The most restrictive matching entry wins, and `default` applies when
none matches. The Essential Eight presets `e8_ml1` to `e8_ml3` set a documented starting point, and
validation warns when a policy is weaker than its preset.

```yaml
{{#include ../../../examples/policies/unknown-applications.yaml}}
```

## Missing facts never make an object look safer

The endpoint agent supplies the facts stage 6 decides on: the path variables, the volume a file is
on, and where the file came from. If one is missing, the engine does not guess. A location class or
origin that the missing fact could make true is treated as possible, and its level applies too. A
missing fact can therefore make a decision stricter, never looser. The decision lists the missing
facts, and the explanation names them.

If the agent sends no origin facts at all, every origin is possible. Under the default
`preexisting_policy: baseline_only`, that blocks every unknown object in `enforce` mode.

The full rules, including scopes, inheritance and the built-in `system_baseline`, are in the
policy crate's README.
