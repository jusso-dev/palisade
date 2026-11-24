# 0019. Contributor sign-off: DCO, no CLA

- Status: accepted
- Date: 2026-11-24
- Deciders: Palisade maintainer

## Context

[ADR 0010](0010-licence.md) licenses Palisade as `Apache-2.0 OR MIT` and accepts contributions
under the same terms (inbound = outbound). It leaves open whether contributors must also confirm,
on each commit, that they have the right to submit their change, and points to #28 for that
decision. This ADR makes it.

Palisade is security software that runs as a privileged Windows service. Its history should
show, for every change, who submitted it and on what terms, so that a disputed or tainted
contribution can be traced and removed. It has one maintainer, no legal entity and no budget,
so whatever is chosen must cost nothing to run and must not put off a first-time contributor.

Two common mechanisms exist. A **Contributor Licence Agreement** (CLA) is a separate legal
agreement, signed once per contributor, that grants the project rights to the contribution,
sometimes including the right to relicense it. The **Developer Certificate of Origin** (DCO,
version 1.1, <https://developercertificate.org>) is a short statement that a contributor
certifies per commit by adding a `Signed-off-by: Name <email>` trailer, usually with
`git commit -s`.

## Decision drivers

1. A clear, per-change record of who submitted what, under the project licence.
2. Nothing that stops a first-time contributor: no account on another service, no legal review.
3. No infrastructure, secrets or services for one maintainer to run. CI may use only the
   allowlisted, SHA-pinned actions ([docs/ci.md](../ci.md)).
4. No extra rights for the maintainer beyond the project licence, so contributors give up nothing
   by contributing.
5. Checkable by a machine on every pull request.

## Considered options

1. **Inbound = outbound only (the current state).** The Apache-2.0 contribution clause already
   says contributions are licensed under the project licence. Costs nothing, but leaves no
   explicit, per-commit statement that the contributor had the right to submit the change, and
   nothing to check. Weak on driver 1 and 5.
2. **A CLA.** Gives the strongest legal record and can allow relicensing. But it needs a signing
   service, a stored record of signatures, a legal text the maintainer cannot have reviewed, and
   a hosted bot or third-party action that is not on the allowlist. Contributors must sign before
   their first pull request, and a relicensing right asks them to trust the maintainer with more
   than the licence grants. Fails drivers 2, 3 and 4.
3. **DCO sign-off, checked by a script in the repository.** Each commit carries
   `Signed-off-by:`. A short shell script (`.github/scripts/check-dco.sh`), run by a workflow
   that uses only `actions/checkout`, checks every commit in a pull request. No service, no
   secret, no extra rights. The DCO certifies the contributor's right to submit, which is what
   driver 1 asks for; it does not allow relicensing, which driver 4 rules out anyway.
4. **DCO sign-off, checked by a hosted app or a third-party action.** Same record as option 3, but
   adds an external integration or an action outside the allowlist, and with it a supply-chain
   dependency with access to pull requests. Fails driver 3 for no gain over option 3.

## Decision

Option 3. **Every commit in a pull request carries a DCO 1.1 sign-off. There is no CLA.**

- A sign-off is a `Signed-off-by: Name <email>` trailer in the commit message, with a non-empty
  name and an email that matches the commit's author email, ignoring case. `git commit -s` adds
  one.
- A `DCO` check, added in #244 as the workflow `.github/workflows/dco.yml` and the script
  `.github/scripts/check-dco.sh` with its tests, runs on every pull request. It fails if any
  non-merge commit lacks a matching sign-off. The script lives in the repository and changes
  only through review ([CODEOWNERS](../../.github/CODEOWNERS)).
- Merge commits are skipped. They are not free of content: a merge that resolves a conflict, or
  that is edited before it is committed, can add changes found in neither parent. They are
  skipped because the hosting platform's "update branch" button creates them, usually without
  a sign-off, and failing those would punish contributors for keeping a branch current. Changes
  made inside a merge commit are therefore not covered by the check (see Negative and Security
  impact). Contributors who must change code while resolving a conflict should rebase instead.
- Once this ADR is accepted, `DCO` becomes a required status check on `main`. Changing the
  ruleset is a repository setting, tracked with the other required checks in #21. The steps are
  in [docs/repo-settings.md](../repo-settings.md) (from #244). Until then the check reports but
  does not block.
- Pull requests are squash-merged, and the squashed commit on `main` is not itself checked. The
  record is the pull request's own commits, which GitHub keeps with the closed pull request.
- Dependabot signs off its own commits, but with a different email from the one it authors them
  with. The check accepts that sign-off only when GitHub reports Dependabot as the pull request's
  author, and only for commits authored at the bot's address. The pull request author comes from
  GitHub, not from the commit, so copying the bot's address into a commit gains nothing. No other
  exemptions exist.
- The licence terms do not change: contributions remain inbound = outbound under
  `Apache-2.0 OR MIT` ([ADR 0010](0010-licence.md)).

A later PR can be checked against this decision: no CLA text, signing service or CLA bot is
added, and the DCO check stays a script in the repository run with allowlisted actions only.

## Consequences

### Positive

- Every non-merge commit on a pull request has a signed statement from its author that they may
  submit it.
- Nothing to sign up for or sign in advance; `git commit -s` is enough.
- No service, secret or third-party action to run or trust. The checker is under 100 lines
  of shell, with tests.
- Contributors keep every right the project licence gives them; nobody can relicense their work.

### Negative

- First-time contributors will forget to sign off and must amend or rebase their commits. The
  check prints the exact commands, and CONTRIBUTING.md explains them.
- A sign-off is a statement, not proof of identity. The check confirms that a trailer matches the
  author email; it cannot confirm the person is who they say they are.
- Without a CLA, the project cannot relicense contributions. Any future change of licence would
  need every contributor's consent, or the removal of their code.
- The record for squash-merged changes lives in the pull request, not in `main`'s history. If
  the hosting platform lost pull request history, the per-commit sign-offs would go with it.
- The maintainer's own pull requests must be signed off too, which is one more habit to keep.
- The Dependabot rule depends on the bot's current author and sign-off addresses. If they change,
  its pull requests fail `DCO` until the script is updated.
- Changes introduced inside a merge commit, by conflict resolution or by editing the merge, carry
  no sign-off and are not checked. Squash merging puts them on `main` like any other change. The
  pull request's diff, which reviewers read, still shows them.

## Security impact

The DCO is a provenance control for the source, not a runtime control. A sign-off ties each
change to a named contributor who has certified their right to submit it, which helps trace and
remove a tainted or disputed contribution that arrives through a pull request: the
source-hosting boundary TB-12 in the [threat model](../security/threat-model.md). It does not
stop malicious code: a hostile contributor can sign off just as easily as an honest one, and it
does nothing about a compromised third-party crate, build tool or action (actor AC-09), which
the dependency policy covers. Review, CODEOWNERS and the required checks remain the controls
against malicious changes.

The check has two known gaps, both closed by review rather than by the check:

- Content added inside a merge commit is not checked (see Decision).
- The workflow runs the script from the pull request's own branch, so a pull request can edit
  `dco.yml` or `check-dco.sh` to make its own check pass. Every change under `.github/` needs the
  maintainer's review (CODEOWNERS), and the reviewer reads that diff before merging.

Choosing a script in the repository over a hosted app or third-party action adds no new code
with access to pull requests, and the workflow needs only `contents: read`. The workflow uses the
`pull_request` trigger, not `pull_request_target`, so fork pull requests run it without secrets
or a write token. Every value taken from the event (the commit SHAs and the pull request
author's login) reaches the script through environment variables, never through expression
interpolation into the shell.

## Links

- Issue #28 (contributor docs, governance and licensing), which this ADR completes.
- PR #244: adds the `DCO` workflow and script, and the sign-off section of
  [CONTRIBUTING.md](../../CONTRIBUTING.md), the `DCO` section of [docs/ci.md](../ci.md) and the
  steps in [docs/repo-settings.md](../repo-settings.md) for making the check required.
- Issue #21: required status checks on `main`, which `DCO` joins once this ADR is accepted.
- [ADR 0010](0010-licence.md): the licence, which left this decision to #28.
- Developer Certificate of Origin 1.1: <https://developercertificate.org>.
