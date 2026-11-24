# Event types

<!-- @generated from `registry.yaml`. Do not edit by hand. Regenerate with `PALISADE_BLESS=1 cargo test -p palisade-proto --lib registry`. -->

Registry schema version 1.1.0.

| Type | Category | Default severity | Required field sets | Summarisable | Since | Description |
|---|---|---|---|---|---|---|
| `exec.decision` | `execution` | 3 | `file` | yes | 1.0.0 | An executable was allowed, blocked or audited. |
| `library.decision` | `library` | 3 | `file` | yes | 1.0.0 | A library load into a process was allowed, blocked or audited. |
| `driver.decision` | `driver` | 5 | `file` | yes | 1.0.0 | A kernel driver load was allowed, blocked or audited. |
| `script.decision` | `script` | 3 | `script` | yes | 1.0.0 | A script was allowed, blocked or audited. |
| `installer.decision` | `installer` | 3 | `file` | yes | 1.0.0 | An installer package was allowed, blocked or audited. |
| `packaged_app.decision` | `packaged_app` | 3 | `file` | yes | 1.0.0 | A packaged app's installation or activation was allowed, blocked or audited. |
| `com.decision` | `execution` | 3 | `native` | yes | 1.0.0 | A COM class activation was allowed, blocked or audited. |
| `exec.origin_check` | `execution` | 1 | `file`, `native` | yes | 1.0.0 | The OS checked a file's managed-installer or reputation origin claims. Diagnostic only, not the final decision. |
| `policy.applied` | `policy` | 2 | none | no | 1.0.0 | A policy was applied, or was already current. |
| `policy.failed` | `policy` | 7 | none | no | 1.0.0 | A policy could not be applied or activated. |
| `policy.activated` | `policy` | 2 | none | no | 1.0.0 | A policy became active in the enforcement engine. |
| `agent.started` | `agent` | 2 | none | no | 1.0.0 | The agent started. |
| `agent.stopped` | `agent` | 4 | none | no | 1.0.0 | The agent stopped. |
| `agent.health` | `agent` | 1 | `agent` | no | 1.0.0 | A periodic report of the agent's health and counters. |
| `agent.tamper` | `agent` | 9 | none | no | 1.0.0 | An attempt to tamper with the agent, its configuration or its data was detected. |
| `agent.throttled` | `agent` | 5 | `agent` | no | 1.0.0 | The agent throttled events because of their rate. |
| `agent.dropped` | `agent` | 7 | `agent` | no | 1.0.0 | The agent dropped events, and reports how many. |
| `agent.clock_unsynced` | `agent` | 5 | none | no | 1.0.0 | The agent's wall clock is not synchronised, so event times may be wrong. |
| `process.created` | `execution` | 2 | `process` | no | 1.1.0 | The OS reported a new process, with its command line where collected (ISM-1889). |
| `script.block_logged` | `script` | 2 | `script` | no | 1.1.0 | The script interpreter logged the text of a script block it ran (ISM-1623). |
| `script.language_audit` | `script` | 4 | `restriction` | no | 1.1.0 | The script interpreter reported a restriction it would apply in constrained language mode. |
| `containment.decision` | `containment` | 4 | `process` | yes | 1.1.0 | A contained application's access to a file, registry key, process or the network was allowed, blocked or audited. |
| `device.attached` | `device` | 2 | `device` | no | 1.1.0 | A peripheral device was connected. |
| `device.detached` | `device` | 1 | `device` | no | 1.1.0 | A peripheral device was disconnected. |
| `storage.decision` | `device` | 4 | `device` | yes | 1.1.0 | Access to a removable or external storage device was allowed, blocked, made read-only or audited. |
| `network.app.decision` | `network` | 3 | `network` | yes | 1.1.0 | An application's network connection was allowed, blocked or audited. |
| `network.host.decision` | `network` | 3 | `network` | yes | 1.1.0 | A connection to or from the device was allowed, blocked or audited by host network control. |
| `web.decision` | `web` | 3 | `network` | yes | 1.1.0 | Access to a web address was allowed, blocked or audited. |
| `elevation.requested` | `elevation` | 4 | `elevation` | no | 1.1.0 | A user asked to run something with elevated rights. |
| `elevation.decision` | `elevation` | 5 | `elevation` | no | 1.1.0 | Elevated rights were granted, refused or cancelled. |
| `elevation.ended` | `elevation` | 3 | `elevation` | no | 1.1.0 | An elevation grant ended or expired. |
| `approval.requested` | `approval` | 3 | `approval` | no | 1.1.0 | A user asked for an approval. |
| `approval.decided` | `approval` | 4 | `approval` | no | 1.1.0 | An approval request was approved, denied, expired or cancelled. |
| `exception.created` | `exception` | 5 | `admin` | no | 1.1.0 | A policy exception was created. |
| `exception.changed` | `exception` | 5 | `admin` | no | 1.1.0 | A policy exception was changed. |
| `exception.removed` | `exception` | 4 | `admin` | no | 1.1.0 | A policy exception was removed. |
| `exception.expired` | `exception` | 3 | none | no | 1.1.0 | A policy exception reached its end date. |
| `otp.session.started` | `exception` | 7 | `approval` | no | 1.1.0 | An offline override code started a session in which the policy is relaxed. |
| `otp.session.ended` | `exception` | 4 | `approval` | no | 1.1.0 | An offline override session ended. |
| `admin.action` | `admin_audit` | 4 | `admin` | no | 1.1.0 | An administrator, API client or job changed something on the server. |
| `admin.login` | `admin_audit` | 2 | `admin` | no | 1.1.0 | A person or client signed in to the server. |
| `admin.login_failed` | `admin_audit` | 5 | `admin` | no | 1.1.0 | A sign-in to the server failed. |
| `identity.logon` | `identity` | 2 | `user` | no | 1.1.0 | An account logged on to the device. |
| `identity.logon_failed` | `identity` | 5 | `user` | no | 1.1.0 | A logon to the device failed. |
| `identity.local_group.changed` | `identity` | 6 | `identity` | no | 1.1.0 | A member was added to or removed from a security group (ISM-1650). |
| `identity.group.changed` | `identity` | 6 | `identity` | no | 1.1.0 | A member was added to or removed from a directory global or universal security group (ISM-1650). |
| `detection.log_cleared` | `detection` | 9 | none | no | 1.1.0 | An event log was cleared. |
| `detection.audit_policy_changed` | `detection` | 7 | `audit_policy` | no | 1.1.0 | The OS audit policy was changed. |
| `integrity.fim.changed` | `integrity` | 5 | `file`, `fim` | no | 1.1.0 | A monitored file was created, changed, renamed or deleted. |
| `compliance.probe.result` | `compliance` | 3 | `probe` | no | 1.1.0 | A compliance probe reported its result. |
