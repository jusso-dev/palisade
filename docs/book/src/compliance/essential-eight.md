# Essential Eight: application control

> **Evidence, not certification.** See [Compliance](README.md). "Status" says what exists in the
> repository today; it is not an assessment of any deployment.

Status values: **in place** (implemented and tested), **partial** (some of it is implemented),
**planned** (designed in the issue named, not built).

## Maturity Level One

| ISM | Requirement | Palisade | Status |
|---|---|---|---|
| ISM-0843 | Application control is implemented on workstations. | The endpoint agent ([#4](https://github.com/jusso-dev/palisade/issues/4)) and OS-native policy compilation ([#6](https://github.com/jusso-dev/palisade/issues/6)). | planned |
| ISM-1870 | Applied to user profiles and temporary folders used by operating systems, web browsers and email clients. | Path facts with ACL safety; allow rules only trust paths users cannot write. Default-deny covers these folders; [unknown-application](../concepts/unknown-applications.md) variants for user-writable locations in [#39](https://github.com/jusso-dev/palisade/issues/39). | partial |
| ISM-1657 | Restricts executables, libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set. | Every one is an object type in the policy model (`ObjectType`), with its own mode (`mode_by_type`) and protection status. Enforcement needs the agent. | partial |

## Maturity Level Two

All of ML1, and:

| ISM | Requirement | Palisade | Status |
|---|---|---|---|
| ISM-1490 | Application control is implemented on internet-facing servers. | Server editions are a platform target ([#68](https://github.com/jusso-dev/palisade/issues/68)); `device.is_server` is a context criterion today. | planned |
| ISM-1871 | Applied to all locations other than user profiles and temporary folders. | The same engine and default-deny apply everywhere; nothing is excluded by location unless an `ignore` rule says so, which needs a permission. | partial |
| ISM-1544 | The OS vendor's recommended application blocklist is implemented. | A `mandatory` blocklist tier that nothing overrides ([ADR 0004](../../../adr/0004-default-rule-precedence-model.md)); ingesting the published list is [#87](https://github.com/jusso-dev/palisade/issues/87). | partial |
| ISM-1582 | Application control rulesets are validated at least annually. | Governance metadata and review-by dates, static analysis of rules ([#40](https://github.com/jusso-dev/palisade/issues/40)). | planned |
| ISM-1660 | Allowed and blocked application control events are centrally logged. | Deny, audit, elevation and trust-source rules must log every decision; the canonical event schema checks the ISM-0585 fields. Central storage is [#202](https://github.com/jusso-dev/palisade/issues/202). | partial |

## Maturity Level Three

All of ML2, and:

| ISM | Requirement | Palisade | Status |
|---|---|---|---|
| ISM-1656 | Application control is implemented on non-internet-facing servers. | As ISM-1490. | planned |
| ISM-1658 | Restricts the execution of drivers to an organisation-approved set. | `driver` is an object type with its own mode; driver load control is [#105](https://github.com/jusso-dev/palisade/issues/105). | partial |
| ISM-1659 | The OS vendor's vulnerable driver blocklist is implemented. | The mandatory blocklist tier; ingestion is [#87](https://github.com/jusso-dev/palisade/issues/87). | partial |

## How rules are written

These ISM controls are not tagged Essential Eight, but assessors use them to judge whether
application control is effective. The [ISM page](ism.md) lists them all.

| ISM | Requirement | Palisade |
|---|---|---|
| ISM-0955 | Implemented using cryptographic hash rules, publisher certificate rules or path rules. | All three are identity criteria; [Identities](../concepts/identities.md). |
| ISM-1471 | Publisher rules use publisher names and product names. | `palisade-fileid` records the publisher and product pair; validation warns on weak identities. |
| ISM-1392 | Path rules: only approved users can modify approved files and write to approved folders. | Allow rules on paths only match where the path and its ancestors are not user-writable. |
| ISM-1746 | Path rules: only approved users can change permissions on approved files and folders. | The same ACL check covers permission changes. |
| ISM-0846 | Users cannot disable or bypass application control. | Agent self-protection in [#18](https://github.com/jusso-dev/palisade/issues/18) and the [threat model](../../../security/threat-model.md); overrides are time-boxed and logged. |
