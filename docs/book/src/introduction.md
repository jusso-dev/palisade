# Introduction

Palisade is an open-source, educational project for learning how **application control** works on
Windows: deciding, before any code runs, whether it may run at all. It is written in Rust and built
in public, design decisions and threat model included.

## What application control is

Most endpoint security asks "is this file bad?". Application control asks a different question:
"is this file one we approved?". An **allowlist** names the software an organisation approves, by
cryptographic hash, by publisher certificate, or by a path that only administrators can write.
Everything else is blocked by default: unknown executables, libraries, scripts, installers,
drivers and the other object types the operating system can run. A **blocklist** removes
dangerous exceptions from what an allowlist would otherwise allow, such as signed tools that are
known to bypass the control.

Done well, application control stops most commodity malware and much hands-on-keyboard intrusion,
because the attacker's tools are simply not on the list. Done badly, it either blocks the business
or is quietly bypassed. Most of this book is about the details that decide which: how files are
identified, how rules are combined, how changes are rolled out safely, and how a decision is
explained afterwards.

## Goals

- Model the rule designs used across the application-control industry in one engine: hash,
  publisher, path and metadata rules, multi-condition rules, several precedence models, modes,
  group inheritance and unknown-application handling ([Concepts](concepts/README.md)).
- Enforce through the operating system's own policy formats first, with an optional driver only
  for the gaps those formats leave ([ADR 0002](../../adr/0002-enforcement-strategy.md)).
- Explain every decision: which rule decided, which rules it overrode, and which facts were used.
- Map the controls to the Australian Essential Eight and ISM as **evidence**
  ([Compliance](compliance/essential-eight.md)).
- Practise careful engineering in the open: ADRs, a STRIDE threat model, fuzzing, supply-chain
  checks, and CI on GitHub-hosted runners only.

## Non-goals

- Replacing commercial application control products, or their support.
- Production readiness. There is no service-level agreement, no supported-version promise and
  no security-fix timeline ([ADR 0014](../../adr/0014-educational-scope-statement.md)).
- Offensive tooling, real malware samples or bypass weaponisation
  ([Responsible use](../../responsible-use.md)).

## Scope and status

Palisade is in milestone M0 (foundations). The policy model and evaluation engine, file identity
(PE parsing, hashes, Authenticode, catalogs), the canonical event schema, the server skeleton and
the repository tooling exist. The endpoint agent, OS-native policy compilation, the console and
the REST API are still to come. The [README](../../../README.md) has the milestone table. Pages
in this book say plainly when they describe a design that is not built yet.

## How this book is made

The book is built from the repository's own Markdown: `docs/`, the root policy files and every
crate README. The reference pages are generated from the JSON Schemas and the command-line
definitions the code uses, so they cannot drift. `cargo xtask docs check` fails CI when a
generated page is stale. To build it locally, see
[Continuous integration: documentation site](../../ci.md#documentation-site).
