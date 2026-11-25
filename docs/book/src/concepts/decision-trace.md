# Decision trace

Every decision must be explainable. Specified in
[#41](https://github.com/jusso-dev/palisade/issues/41).

Today every `Decision` already carries:

- the **outcome** (`allowed`, `blocked`, `allowed_audit`, `allowed_override`, `ignored`) and the
  enforce-mode outcome (`would_have_been`);
- the **deciding rule** and **every rule it overrode**;
- `audit` annotations, trust-source grants and the effective **mode**;
- a **reason code** (for example `mandatory_deny` or `implicit_deny_unknown`) and a trace ID.

Planned in #41: a structured trace of which stages ran, which rules **nearly** matched and why,
and which facts were used or missing; an explain API for the console, CLI and tray; and a policy
simulator that replays recorded events against a candidate policy and reports what would change.

Decisions become events in the canonical event schema; see the
[event reference](../reference/generated/events/index.md).
