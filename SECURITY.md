# Security policy

Palisade is an educational, personal-development project maintained by one person on a
best-effort basis. It is not a replacement for commercial application control products, and it
should not be relied on to protect production systems. Security reports are still welcome and
are taken seriously. This page explains how to send one privately and what response to expect.

## Supported versions

Palisade has no releases yet. Once it does, only the **latest minor release** receives security
fixes. Older releases are not patched, so you must upgrade to get a fix. Until the first release,
fixes land on `main` only.

| Version | Security fixes |
|---|---|
| Latest minor release | Yes |
| Any older release | No |
| `main` (before the first release) | Yes |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it through GitHub private vulnerability reporting:

1. Open the [Security tab](https://github.com/jusso-dev/palisade/security) of this repository.
2. Select **Report a vulnerability**, or go straight to the
   [private reporting form](https://github.com/jusso-dev/palisade/security/advisories/new).
3. Describe the issue, the affected commit or version, and the steps to reproduce it.

Only you and the maintainer can see the report. It becomes a draft security advisory, so the
discussion, any fix and the final advisory all happen in one private place.

GitHub private vulnerability reporting is the only private channel. The project does not offer
an email address or an encryption key for reports. If you cannot use the form, start a
[discussion](https://github.com/jusso-dev/palisade/discussions/categories/q-a) that asks the
maintainer for a private channel and contains **no details** of the vulnerability.

A useful report includes:

- the Palisade commit or version, the Windows build and the architecture (x64 or ARM64);
- the policy or configuration needed to reproduce it, with secrets and enrolment tokens removed;
- what you expected to happen and what happened instead;
- the impact as you understand it.

Use benign test files only. Do not attach real malware.

## What to expect

These are **best-effort targets, not commitments**. Palisade has one maintainer and no service
level agreement.

| Step | Target |
|---|---|
| Acknowledge your report | within 7 days |
| Triage it (confirmed or not, severity, next steps) | within 14 days |
| Public disclosure | 90 days after the report, by default |

If a target is missed, the maintainer will say so in the report thread, and the advisory will say
so too.

## Coordinated disclosure

The default disclosure window is **90 days** from the report. Within that window the maintainer
aims to release a fix and publish an advisory. The window can change by agreement:

- shorter, if a fix ships early or the issue is already being exploited;
- longer, if a fix needs more time and you agree to wait.

Please do not disclose the issue publicly before the advisory is published or the window ends.

Advisories are published as GitHub Security Advisories in this repository. A CVE is requested
through GitHub when the issue affects released code. You are credited in the advisory unless you
ask not to be.

## Scope

In scope:

- **Agent bypasses**: running code that policy should block, for example through a rule-matching
  flaw, path or file-identity confusion, a race between the check and the execution, or a
  script-host or interpreter gap.
- **Tamper**: stopping, unloading or reconfiguring the agent or the optional driver, or editing
  its policy, its local store or its logs, without the rights the threat model requires.
- **Privilege escalation** through any Palisade component, including the elevation features.
- **Server and API authentication and authorisation**: getting access without credentials,
  crossing tenants, escalating roles, forging or replaying enrolment, or misusing override codes.
- **Supply chain**: the build, the CI workflows, release signing, dependency handling and the
  update path.
- Memory-safety bugs, panics and resource exhaustion in parsers of untrusted input (files, policy,
  network messages).

Out of scope:

- Findings that need administrator-equivalent access on the endpoint, or any other access that the
  threat model already defines as a trust boundary Palisade does not defend. The threat model is
  tracked in [#18](https://github.com/jusso-dev/palisade/issues/18); until it is published, ask in your report and the maintainer will decide case by
  case.
- Bugs in the operating system, in third-party dependencies (report those upstream; tell us if
  Palisade is affected) or in GitHub itself.
- Missing hardening with no demonstrated impact, scanner output without a working proof of
  concept, and social engineering of the maintainer.
- Denial of service that needs high traffic volumes against a deployment you do not own.

## Safe harbour

If you research and report in good faith under this policy, the maintainer will not pursue or
support any legal action against you, and will treat your work as authorised. Good faith means
that you:

- test only on systems and data you own or are explicitly allowed to test;
- do not access, change or delete other people's data, and stop as soon as you reach it;
- do not degrade services for other users;
- use benign test files, never real malware;
- give the maintainer a reasonable chance to fix the issue before you disclose it.

This statement covers the maintainer only. It cannot give permission on behalf of anyone else,
including GitHub or the owners of any system you test against. If you are unsure whether
something is covered, ask in your report first.

See also [docs/responsible-use.md](docs/responsible-use.md).
