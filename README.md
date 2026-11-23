# Palisade

**Open-source application allowlisting and application control for Windows, written in Rust.**

> Status: **pre-alpha / design phase**. Nothing here is production ready yet. The roadmap lives in [GitHub Issues](https://github.com/jusso-dev/palisade/issues) and [Milestones](https://github.com/jusso-dev/palisade/milestones).

Palisade aims to match the features of commercial application control platforms (Airlock Digital, ThreatLocker, Microsoft App Control for Business (WDAC), AppLocker, Ivanti Application Control, Trellix Application Control, Carbon Black App Control, BeyondTrust/CyberArk EPM, ManageEngine, Heimdal) in a single open-source product:

- **Allowlisting and denylisting** using hash, publisher/certificate, path, file attributes, parent process, trusted installer/updater and ownership rules
- **Native enforcement** by compiling Palisade policy to **App Control for Business (WDAC)** and **AppLocker** XML, with an optional Palisade enforcement driver for gaps those formats can't cover
- **Script control**: PowerShell (Constrained Language Mode, signed scripts), JS/VBS/HTA/MSI/batch/Python and interpreter arguments
- **DLL, driver and packaged-app control**, including Microsoft's recommended block rules
- **Learning/audit mode**, file inventory, baselines and policy recommendations
- **Offline override codes** (OTP), temporary bypass and maintenance/install windows
- **Self-service requests and approvals** (console, email, Teams/Slack, mobile)
- **Just-in-time elevation** without giving users local admin
- **Trusted developer workstations** with scoped, audited exemptions
- **Ringfencing**: limit what allowed apps can touch (files, registry, network, child processes)
- **Central management**: groups, policy inheritance, RBAC, multi-tenancy
- **REST API**, `pal` CLI, **policy-as-code** with GitOps and CI/CD gates
- **Audit logging and SIEM** (syslog/CEF, Splunk HEC, Microsoft Sentinel, Elastic, OTLP)
- **Australian Essential Eight** (ML1 to ML3) and ISM evidence reporting

## Architecture (planned)

```
          ┌───────────────── pal CLI / GitOps / CI ─────────────────┐
          │                                                         ▼
┌──────────────────┐    REST/gRPC (mTLS)     ┌────────────────────────────────┐
│ palisade-console │ ◀────────────────────▶  │ palisade-server (axum+Postgres) │──▶ SIEM / ITSM / IdP
└──────────────────┘                         └────────────────────────────────┘
                                                        ▲  policy, approvals, OTP
                                                        │  events, inventory
                                         ┌──────────────┴──────────────┐
                                         │ palisade-agent (Windows svc)│
                                         │  ├─ ETW / CodeIntegrity     │
                                         │  ├─ App Control / AppLocker │
                                         │  ├─ palisade-driver (opt.)  │
                                         │  └─ palisade-tray (UX)      │
                                         └─────────────────────────────┘
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Palisade is an independent project. It is not affiliated with or endorsed by any vendor named above. Vendor names are used only to describe feature parity.
