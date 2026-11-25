# Your first policy

Policies are YAML (or JSON) documents checked against the
[policy schema](../reference/generated/policy/index.md). The first line names the schema, so an
editor with the YAML language server completes field names and flags mistakes.

## Write it

Start from the smallest valid policy. It has no rule sets, so the implicit deny reports every
file, and `mode: audit` means nothing is blocked:

```yaml
{{#include ../../../examples/policies/minimal.yaml}}
```

Then add an allowlist rule set with hash, publisher and path rules, as in the
[workstation baseline](../concepts/identities.md).

## Validate it

The policy engine's tests check every example in `docs/examples/policies/` against the committed
schema, load it, and run full validation, which reports every finding with a code, a JSON Pointer
and a line and column:

```sh
cargo test -p palisade-policy --test yaml
```

To check your own file the same way, add it to `docs/examples/policies/` and run that test. A
`pal policy validate` command arrives with the CLI ([#189](https://github.com/jusso-dev/palisade/issues/189)).

## From audit to enforce

1. **Audit.** Deploy in `audit` mode. Every decision is logged, and what enforce mode would block
   is reported as `allowed_audit` with `would_have_been: blocked`.
2. **Review.** Turn the would-block reports into rules, or confirm they should stay blocked.
   Learning mode marks objects that only the implicit deny would block as candidates
   ([#5](https://github.com/jusso-dev/palisade/issues/5)).
3. **Enforce by type.** Enforce executables first with `mode_by_type`, while scripts stay in audit.
   Try new blocklists with `mode_override: audit`.
4. **Enforce.** Switch the policy to `enforce`. Leaving `enforce` later is time-boxed and reverts on
   its own ([Modes](../concepts/modes.md)).

The staged-rollout example on the [Modes](../concepts/modes.md) page shows steps 3 and 4 in one
document.
