# Event types

<!-- @generated from `registry.yaml`. Do not edit by hand. Regenerate with `PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry`. -->

Registry schema version 1.0.0.

| Type | Category | Default severity | Required field sets | Summarisable | Description |
|---|---|---|---|---|---|
| `exec.decision` | `execution` | 3 | `file` | yes | An executable was allowed, blocked or audited. |
| `library.decision` | `library` | 3 | `file` | yes | A library load into a process was allowed, blocked or audited. |
| `driver.decision` | `driver` | 5 | `file` | yes | A kernel driver load was allowed, blocked or audited. |
| `script.decision` | `script` | 3 | `script` | yes | A script was allowed, blocked or audited. |
| `installer.decision` | `installer` | 3 | `file` | yes | An installer package was allowed, blocked or audited. |
| `packaged_app.decision` | `packaged_app` | 3 | `file` | yes | A packaged app's installation or activation was allowed, blocked or audited. |
| `com.decision` | `execution` | 3 | `native` | yes | A COM class activation was allowed, blocked or audited. |
| `exec.origin_check` | `execution` | 1 | `file`, `native` | yes | The OS checked a file's managed-installer or reputation origin claims. Diagnostic only, not the final decision. |
| `policy.applied` | `policy` | 2 | none | no | A policy was applied, or was already current. |
| `policy.failed` | `policy` | 7 | none | no | A policy could not be applied or activated. |
| `policy.activated` | `policy` | 2 | none | no | A policy became active in the enforcement engine. |
| `agent.started` | `agent` | 2 | none | no | The agent started. |
| `agent.stopped` | `agent` | 4 | none | no | The agent stopped. |
| `agent.health` | `agent` | 1 | `agent` | no | A periodic report of the agent's health and counters. |
| `agent.tamper` | `agent` | 9 | none | no | An attempt to tamper with the agent, its configuration or its data was detected. |
| `agent.throttled` | `agent` | 5 | `agent` | no | The agent throttled events because of their rate. |
| `agent.dropped` | `agent` | 7 | `agent` | no | The agent dropped events, and reports how many. |
| `agent.clock_unsynced` | `agent` | 5 | none | no | The agent's wall clock is not synchronised, so event times may be wrong. |
