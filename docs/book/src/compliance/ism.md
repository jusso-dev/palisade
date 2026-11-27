# ISM controls

> **Evidence, not certification.** See [Compliance](README.md).

Every ISM control that Palisade's code, tests or design documents cite, with where each is
addressed. Wording is summarised; the ISM itself is authoritative.

| ISM | Topic | Where it is addressed |
|---|---|---|
| ISM-0585 | Each event records the date and time, user or process, file name, description and host. | The canonical event schema ([event reference](../reference/generated/events/index.md)); `Event::ism_0585_gaps` and the mapping loader check every decision event. |
| ISM-0843, ISM-1490, ISM-1656 | Application control on workstations and servers. | [Essential Eight](essential-eight.md). |
| ISM-0846 | Users cannot disable or bypass application control. | [Threat model](../../../security/threat-model.md); ADR [0012](../../../adr/0012-fail-open-vs-fail-closed-defaults.md) and [0013](../../../adr/0013-protected-process-light-feasibility.md). |
| ISM-0955 | Hash, publisher or path rules. | [Identities](../concepts/identities.md). |
| ISM-0988 | An accurate time source. | Events record whether the agent's clock is synchronised (`clock_synced`, `agent.clock_unsynced`); [threat model](../../../security/threat-model.md). |
| ISM-1175 | Privileged accounts are blocked from the internet, email and web. | [Threat model](../../../security/threat-model.md) (the console and server administrators). |
| ISM-1392, ISM-1746 | Path rules only where approved users control writes and permissions. | `palisade-fileid`'s ACL writability facts; [Identities](../concepts/identities.md). |
| ISM-1471 | Publisher and product names in publisher rules. | `palisade-fileid` signer attributes. |
| ISM-1544, ISM-1659 | The OS vendor's recommended application and driver blocklists. | The mandatory blocklist tier, [ADR 0004](../../../adr/0004-default-rule-precedence-model.md); ingestion [#87](https://github.com/jusso-dev/palisade/issues/87). |
| ISM-1582 | Rulesets validated at least annually. | [#40](https://github.com/jusso-dev/palisade/issues/40). |
| ISM-1623 | PowerShell module, script block and transcription logs centrally logged. | The `script.block_logged` event type and its OS event mapping. |
| ISM-1650 | Privileged account and security group changes centrally logged. | The `identity.group.changed` and `identity.local_group.changed` event types. |
| ISM-1657, ISM-1658 | The object types application control restricts, including drivers. | `ObjectType` in `palisade-core`; per-type modes and protection status in `palisade-policy`. |
| ISM-1660 | Allowed and blocked events centrally logged. | Logging defaults per action in `palisade-policy`; [#202](https://github.com/jusso-dev/palisade/issues/202). |
| ISM-1815 | Event logs protected from unauthorised modification and deletion. | Hash-chained events (`seq`, `prev_hash`); [threat model](../../../security/threat-model.md). |
| ISM-1870, ISM-1871 | Which locations application control covers. | [Essential Eight](essential-eight.md). |
| ISM-1889 | Command-line process creation events centrally logged. | The `process.created` event type and its OS event mapping. |
| ISM-1984, ISM-1985 | Event logs encrypted in transit and protected from unauthorised access. | [Threat model](../../../security/threat-model.md); [ADR 0005](../../../adr/0005-agent-server-protocol.md). |
| ISM-1988 | Event logs retained and searchable for at least 12 months. | [Threat model](../../../security/threat-model.md); [#202](https://github.com/jusso-dev/palisade/issues/202). |
