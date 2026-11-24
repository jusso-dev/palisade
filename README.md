# Palisade

[![CI](https://github.com/jusso-dev/palisade/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jusso-dev/palisade/actions/workflows/ci.yml)
[![Licence: Apache-2.0 OR MIT](https://img.shields.io/badge/licence-Apache--2.0%20OR%20MIT-blue.svg)](#license)

**An educational application allowlisting and application control project for Windows, written in Rust.**

Palisade explores how application control works end to end on Windows: deciding which programs, scripts and libraries may run, enforcing that with the operating system's own policy engines and an optional driver, explaining each decision, and managing policy centrally. It is written in Rust and built in public as a learning project.

> **About this project:** Palisade is a personal learning project that I've worked on for my own professional development, to understand how application control works end to end. It is **not** a replacement for enterprise products or enterprise support, and it should not be relied on to protect production environments. Use it to learn, experiment and explore.

> Status: **pre-alpha / design phase**. The roadmap lives in [GitHub Issues](https://github.com/jusso-dev/palisade/issues) and [Milestones](https://github.com/jusso-dev/palisade/milestones).

> **Palisade is an educational, personal-development project. It is not a replacement for commercial application control products and comes with no support or warranty. Do not rely on it to protect production systems.**

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

## Status by milestone

Nothing is usable yet. Each milestone is tracked on GitHub, and the epics in it list the work.

| Milestone | Scope | Status |
|---|---|---|
| [M0 Foundations](https://github.com/jusso-dev/palisade/milestone/1) | Workspace, CI, core policy model, threat model | In progress: workspace, CI and dependency policy done |
| [M1 Audit & Inventory](https://github.com/jusso-dev/palisade/milestone/2) | Agent in audit mode, file inventory, event collection, learning mode | Not started |
| [M2 Enforcement](https://github.com/jusso-dev/palisade/milestone/3) | Native Windows policy compilation and deployment, script and DLL control, offline override | Not started |
| [M3 Central Management](https://github.com/jusso-dev/palisade/milestone/4) | Server, API, console, groups, approvals workflow, RBAC | Not started |
| [M4 Elevation & Self-Service](https://github.com/jusso-dev/palisade/milestone/5) | Just-in-time elevation, user requests, trusted developer workflows | Not started |
| [M5 Integrations & Policy-as-Code](https://github.com/jusso-dev/palisade/milestone/6) | SIEM, ITSM, identity, CLI, GitOps, CI/CD | Not started |
| [M6 Compliance & Advanced](https://github.com/jusso-dev/palisade/milestone/7) | Essential Eight reporting, application containment, driver, change control | Not started |

## Building

The Cargo workspace holds one crate per component under `crates/`, plus `xtask` for repository checks. Each crate's README gives its purpose, allowed dependencies and platform support. Windows-only crates build as stubs on other platforms, so the whole workspace builds and tests anywhere.

You need [rustup](https://rustup.rs) and Git. The toolchain is pinned in `rust-toolchain.toml`, and rustup installs it on the first `cargo` command.

**Windows** (x64 or ARM64): install the C++ build tools when the rustup installer offers them, then:

```sh
cargo build --workspace --exclude palisade-driver
cargo test --workspace --exclude palisade-driver
```

The kernel driver needs the Windows Driver Kit and is built separately ([#22](https://github.com/jusso-dev/palisade/issues/22)). For now it is a placeholder that builds anywhere, so `--workspace` without the exclusion also works.

**Linux and other desktop OS**:

```sh
cargo build            # the default members: every crate except the driver
cargo test --workspace
cargo xtask help       # repository checks
```

To type-check the Windows-only code from Linux or another desktop OS:

```sh
rustup target add x86_64-pc-windows-gnu
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
```

Every check CI runs, and how to run it locally: [docs/ci.md](docs/ci.md). Before opening a pull request, read [CONTRIBUTING.md](CONTRIBUTING.md).

A quick start that installs Palisade on a disposable Windows virtual machine arrives with the VM test harness ([#26](https://github.com/jusso-dev/palisade/issues/26)).

## Documentation and project policies

- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, coding standards, tests and pull requests
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately
- [docs/security/threat-model.md](docs/security/threat-model.md): STRIDE threat model, attack trees and residual risks
- [SUPPORT.md](SUPPORT.md): where to ask questions, and what support to expect
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): Contributor Covenant 2.1
- [docs/responsible-use.md](docs/responsible-use.md): Palisade is defensive; what contributions are not accepted
- [docs/ci.md](docs/ci.md): CI jobs and the runner policy
- [docs/workspace.md](docs/workspace.md): crate layout, dependency, unsafe-code and feature-flag rules
- [docs/dependencies.md](docs/dependencies.md): admitting dependencies, cargo-deny, cargo-audit, cargo-vet and the dependency report
- [docs/repo-settings.md](docs/repo-settings.md): the repository settings the project relies on
- [docs/NAMING.md](docs/NAMING.md): vendor-neutral terminology
- [docs/adr/](docs/adr/README.md): architecture decision records, and the process for proposing one

## Disclaimer

This software is provided as-is for educational purposes, without warranty of any kind. It is not a supported product, comes with no support commitment, and is not intended to replace commercial or enterprise security solutions.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
