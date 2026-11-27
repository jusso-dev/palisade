# Decision trace

Every decision must be explainable. Specified in
[#41](https://github.com/jusso-dev/palisade/issues/41); the engine side is built (`trace` in
[`palisade-policy`](../../../../crates/palisade-policy/README.md#trace-explain-and-simulate)).

Every `Decision` carries:

- the **outcome** (`allowed`, `blocked`, `allowed_audit`, `allowed_override`, `ignored`) and the
  enforce-mode outcome (`would_have_been`);
- the **deciding rule** and **every rule it overrode**;
- `audit` annotations, trust-source grants and the effective **mode**;
- a **reason code** (for example `mandatory_deny` or `implicit_deny_unknown`) and a trace ID.

A **trace** records how that decision was reached, at a level the agent chooses (minimal for an
object that runs, standard for a block or would-block, full while diagnosing):

- how the mode was resolved, and which pipeline stages decided, passed or were skipped;
- every rule that matched and its role, and each of the deciding rule's criteria with its result;
- every fact that was missing or untrusted, and what that did;
- the rules that **nearly** matched, with the criteria that failed;
- for a block, a **draft allow rule** from the strongest identity available, which the engine
  never applies itself.

Every list in a trace is bounded, and user, device and session values are withheld by default
(an HMAC digest can stand in for them).

**Explain** turns a trace into text for the CLI, the console and the tray: a summary, a reason a
person can act on, "why not allowed?" and "what would allow this?".

**Simulate** replays recorded facts against the current policy and a candidate (a draft, a set of
rule changes, or a mode change such as `audit` to `enforce`) and reports what would change. The
same machinery runs **policy-as-code tests** and the **readiness report** for moving to enforce;
see the [simulation examples](../../../examples/simulation/README.md).

Decisions become events in the canonical event schema; see the
[event reference](../reference/generated/events/index.md).
