# Palisade

**An educational application allowlisting and application control project for Windows, written in Rust.**

> **About this project:** Palisade is a personal learning project that I've worked on for my own professional development, to understand how application control works end to end. It is **not** a replacement for enterprise products or enterprise support, and it should not be relied on to protect production environments. Use it to learn, experiment and explore.

> Status: **pre-alpha / design phase**. The roadmap lives in [GitHub Issues](https://github.com/jusso-dev/palisade/issues) and [Milestones](https://github.com/jusso-dev/palisade/milestones).

## What it explores

- **Allowlisting and denylisting** using hash, publisher/certificate, path, file attributes, parent process, trusted installer/updater and ownership rules
- **Native enforcement** by compiling Palisade policy to Windows' built-in application control policy formats, with an optional enforcement driver for gaps those formats can't cover
- **Script control**: PowerShell (Constrained Language Mode, signed scripts), JS/VBS/HTA/MSI/batch/Python and interpreter arguments
- **DLL, driver and packaged-app control**, including recommended block rules
- **Learning/audit mode**, file inventory, baselines and policy recommendations
- **Offline override codes** (OTP), temporary bypass and maintenance/install windows
- **Self-service requests and approvals**
- **Just-in-time elevation** without giving users local admin
- **Trusted developer workstations** with scoped, audited exemptions
- **Application containment**: limit what allowed apps can touch (files, registry, network, child processes)
- **Central management**: groups, policy inheritance, RBAC, multi-tenancy
- **REST API**, `pal` CLI, **policy-as-code** with GitOps and CI/CD gates
- **Audit logging and SIEM** export (syslog/CEF, HTTP event collectors, OTLP)
- **Australian Essential Eight** (ML1 to ML3) application control concepts and evidence reporting

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
                                         │  ├─ native policy compiler  │
                                         │  ├─ palisade-driver (opt.)  │
                                         │  └─ palisade-tray (UX)      │
                                         └─────────────────────────────┘
```

## Repository layout

The Cargo workspace holds one crate per component under `crates/`, plus `xtask` for repository checks. Each crate's README gives its purpose, allowed dependencies and platform support. Windows-only crates build as stubs on other platforms, so the whole workspace checks and tests anywhere.

```sh
cargo test --workspace     # toolchain is pinned in rust-toolchain.toml
cargo xtask help           # repository checks
```

CI and how to run every check locally: [docs/ci.md](docs/ci.md).

## Disclaimer

This software is provided as-is for educational purposes, without warranty of any kind. It is not a supported product, comes with no support commitment, and is not intended to replace commercial or enterprise security solutions.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
