# Hardening guide

Palisade is educational software and **must not protect production systems**. This page is about
running a lab without making that lab, or the network it sits on, less safe. Product hardening
(self-protection of the agent, signed policy, server and console hardening to ASVS L2) is designed
in the [threat model](../../../security/threat-model.md) and epic
[#18](https://github.com/jusso-dev/palisade/issues/18); each item there says whether it exists yet.

## The lab

- Run the agent only on **disposable virtual machines you own**, never on a workstation you rely
  on. Snapshot before every test and revert after.
- Keep lab VMs on an isolated virtual network. The server binds its admin, agent and metrics
  listeners separately; bind each to the lab interface only
  ([server README: listeners](../../../../crates/palisade-server/README.md#listeners-and-binding)).
- Use test certificates made for the lab. Never reuse a real code-signing or TLS key.

## The server

- Run `palisade-server check-config` before `serve`. It checks the TLS chain, key, agent CA, file
  permissions on secret files, and that every public URL matches a certificate name, and reports
  every problem at once.
- Keep secrets in files readable only by the server's account; the server refuses group- or
  world-readable secret files.
- Give the server two database logins: a migration login that owns the schema, and a runtime
  login that does not. Row-level security isolates tenants
  ([server README: database](../../../../crates/palisade-server/README.md#database)).

## Policies

- Start in `audit`; enforce by object type; keep a mandatory blocklist for known-dangerous tools
  ([Modes](../concepts/modes.md)).
- Prefer hash and publisher rules. Use path rules only for locations users cannot write
  (ISM-1392), and let validation's weak-identity warnings guide you
  ([Identities](../concepts/identities.md)).
- Time-box every override; it reverts on its own.

## The supply chain

Every dependency is reviewed, audited or exempted with a reason
([Dependencies](../../../dependencies.md)), and CI runs on GitHub-hosted runners only, with
SHA-pinned actions from an allowlist ([CI](../../../ci.md#runner-and-action-policy)).
