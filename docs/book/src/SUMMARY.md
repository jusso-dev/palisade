# Summary

[Introduction](introduction.md)

# User guide

- [Concepts](concepts/README.md)
    - [Identities](concepts/identities.md)
    - [Rules and conditions](concepts/rules-and-conditions.md)
    - [Precedence models](concepts/precedence.md)
    - [Modes](concepts/modes.md)
    - [Groups and inheritance](concepts/groups-and-inheritance.md)
    - [Unknown applications](concepts/unknown-applications.md)
    - [Exceptions and offline overrides](concepts/exceptions-and-overrides.md)
    - [Decision trace](concepts/decision-trace.md)
- [Getting started](getting-started/README.md)
    - [Lab install](getting-started/lab-install.md)
    - [Your first policy](getting-started/first-policy.md)

# Reference

<!-- generated:start -->
- [Policy reference](reference/generated/policy/index.md)
    - [Action](reference/generated/policy/action.md)
    - [Criterion](reference/generated/policy/criterion.md)
    - [Effects](reference/generated/policy/effects.md)
    - [LibraryRef](reference/generated/policy/library-ref.md)
    - [Match](reference/generated/policy/match.md)
    - [Metadata](reference/generated/policy/metadata.md)
    - [ModeOptions](reference/generated/policy/mode-options.md)
    - [PolicySettings](reference/generated/policy/policy-settings.md)
    - [Policy](reference/generated/policy/policy.md)
    - [PrecedenceOptions](reference/generated/policy/precedence-options.md)
    - [RuleSet](reference/generated/policy/rule-set.md)
    - [Rule](reference/generated/policy/rule.md)
    - [Value types](reference/generated/policy/types.md)
- [Event reference](reference/generated/events/index.md)
    - [Account](reference/generated/events/account.md)
    - [Admin](reference/generated/events/admin.md)
    - [AgentInfo](reference/generated/events/agent-info.md)
    - [Approval](reference/generated/events/approval.md)
    - [AuditPolicy](reference/generated/events/audit-policy.md)
    - [CacheStats](reference/generated/events/cache-stats.md)
    - [ChangeRule](reference/generated/events/change-rule.md)
    - [Change](reference/generated/events/change.md)
    - [Device](reference/generated/events/device.md)
    - [Elevation](reference/generated/events/elevation.md)
    - [File](reference/generated/events/file.md)
    - [Fim](reference/generated/events/fim.md)
    - [Hashes](reference/generated/events/hashes.md)
    - [Host](reference/generated/events/host.md)
    - [Identity](reference/generated/events/identity.md)
    - [Native](reference/generated/events/native.md)
    - [Network](reference/generated/events/network.md)
    - [Origin](reference/generated/events/origin.md)
    - [ParentProcess](reference/generated/events/parent-process.md)
    - [PolicyRef](reference/generated/events/policy-ref.md)
    - [Principal](reference/generated/events/principal.md)
    - [Probe](reference/generated/events/probe.md)
    - [ProcessSummary](reference/generated/events/process-summary.md)
    - [Process](reference/generated/events/process.md)
    - [RegistryData](reference/generated/events/registry-data.md)
    - [Registry](reference/generated/events/registry.md)
    - [Restriction](reference/generated/events/restriction.md)
    - [Script](reference/generated/events/script.md)
    - [Signer](reference/generated/events/signer.md)
    - [Source](reference/generated/events/source.md)
    - [Value types](reference/generated/events/types.md)
    - [User](reference/generated/events/user.md)
    - [VersionInfo](reference/generated/events/version-info.md)
<!-- generated:end -->
- [CLI reference](reference/generated/cli.md)
- [API reference](reference/api.md)
- [Vendor-neutral naming](../../NAMING.md)

# Architecture

- [Project overview](../../../README.md)
- [Crate map](reference/generated/crates.md)
    - [palisade-core](../../../crates/palisade-core/README.md)
    - [palisade-fileid](../../../crates/palisade-fileid/README.md)
    - [palisade-policy](../../../crates/palisade-policy/README.md)
    - [palisade-proto](../../../crates/palisade-proto/README.md)
    - [palisade-agent](../../../crates/palisade-agent/README.md)
    - [palisade-server](../../../crates/palisade-server/README.md)
    - [palisade-cli](../../../crates/palisade-cli/README.md)
    - [palisade-tray](../../../crates/palisade-tray/README.md)
    - [palisade-console](../../../crates/palisade-console/README.md)
    - [palisade-driver](../../../crates/palisade-driver/README.md)
    - [xtask](../../../xtask/README.md)
- [Workspace rules](../../workspace.md)
- [Architecture decision records](../../adr/README.md)
    - [ADR process](../../adr/PROCESS.md)
<!-- adr:start -->
    - [0001. Record architecture decisions](../../adr/0001-record-architecture-decisions.md)
    - [0002. Enforcement strategy: OS-native policy first, optional own driver](../../adr/0002-enforcement-strategy.md)
    - [0003. Crate boundaries and dependency direction](../../adr/0003-crate-boundaries-and-dependency-direction.md)
    - [0004. Default rule precedence model](../../adr/0004-default-rule-precedence-model.md)
    - [0005. Agent-server protocol](../../adr/0005-agent-server-protocol.md)
    - [0006. Server database and tenant isolation](../../adr/0006-server-database.md)
    - [0007. Agent local store](../../adr/0007-agent-local-store.md)
    - [0008. Cryptographic algorithms and libraries](../../adr/0008-cryptographic-algorithms.md)
    - [0009. Async runtime and concurrency model](../../adr/0009-async-runtime-and-concurrency.md)
    - [0010. Licence](../../adr/0010-licence.md)
    - [0011. MSRV and unsafe code policy](../../adr/0011-msrv-and-unsafe-code-policy.md)
    - [0012. Fail-open versus fail-closed defaults](../../adr/0012-fail-open-vs-fail-closed-defaults.md)
    - [0013. Protected process light feasibility](../../adr/0013-protected-process-light-feasibility.md)
    - [0014. Educational scope statement](../../adr/0014-educational-scope-statement.md)
<!-- adr:end -->

# Security

- [Security](security/README.md)
    - [Threat model](../../security/threat-model.md)
    - [Hardening guide](security/hardening.md)
    - [Reporting a vulnerability](../../../SECURITY.md)
    - [Responsible use](../../responsible-use.md)

# Compliance

- [Compliance](compliance/README.md)
    - [Essential Eight](compliance/essential-eight.md)
    - [ISM controls](compliance/ism.md)

# Contributing

- [Contributing](../../../CONTRIBUTING.md)
    - [Testing](../../testing.md)
    - [Continuous integration](../../ci.md)
    - [Dependencies](../../dependencies.md)
    - [Repository settings](../../repo-settings.md)
    - [Code of conduct](../../../CODE_OF_CONDUCT.md)
    - [Support](../../../SUPPORT.md)

---

[Glossary](glossary.md)
