# 0001. Record architecture decisions

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Application control has several design forks where the options exclude each other and are
expensive to reverse: how enforcement happens, how conflicting rules resolve, what is trusted,
and what happens when a component fails. Palisade is also a learning project, so the reasons
behind each choice matter as much as the choice itself. Without a written record, later
contributors (including the maintainer, months later) reopen settled questions, or change a
security default without seeing why it was set.

Issue #20 asks for a lightweight decision record process under `docs/adr/` and an initial set
of decisions that the other epics depend on.

## Decision drivers

- Decisions and their trade-offs must be findable next to the code, in version control.
- Low ceremony: one maintainer has to be able to run the process.
- A changed decision must leave the old reasoning readable, not overwrite it.
- Security consequences must be stated for every decision, because Palisade is security software.

## Considered options

1. **No formal record.** Decisions live in issue threads and commit messages. No overhead, but
   the reasoning is scattered, issue threads mix proposals with outcomes, and nothing marks a
   decision as settled.
2. **A single living design document.** One place to read, but edits overwrite history, a
   reader cannot tell when a decision was made, and the document grows past what anyone reads.
3. **Markdown ADRs in the repository, one decision per file, in a MADR-style format.** Small,
   reviewable in PRs, immutable once accepted, superseded rather than edited. Costs a short
   document per decision.

## Decision

Option 3. Palisade keeps ADRs in `docs/adr/`, using the template in
[`0000-template.md`](0000-template.md) and the rules in [`PROCESS.md`](PROCESS.md). In summary:

- Files are `NNNN-kebab-title.md`, with 4-digit, monotonic numbers that are never reused.
- Status is one of `proposed`, `accepted`, `superseded by NNNN`, `deprecated`, `rejected`.
- ADR PRs are labelled `area:infra`. Acceptance needs one maintainer approval and at least
  3 days open, unless the maintainer marks the PR urgent.
- An accepted ADR is immutable except for its Status, Date and Links lines. A change of
  direction is a new ADR that supersedes the old one. A PR that contradicts an accepted ADR
  must link the superseding ADR.
- Every ADR has a non-empty Security impact section.

**Bootstrap.** A process cannot govern its own adoption. The ADRs marked `accepted` in the PR
that introduces this directory are accepted when that PR merges, which needs maintainer approval
like any other PR. The 3-day rule applies to every later ADR PR. ADRs in that first PR that
still need evidence are marked `proposed`.

## Consequences

### Positive

- Each fork has one place that records what was chosen, what was rejected and why.
- Reviewers can reject a PR by pointing at an accepted ADR, instead of arguing again.
- The superseded chain shows how the design changed over time, which helps learners.

### Negative

- Each significant decision costs a short document and, for acceptance, a 3-day wait.
- Until the `cargo xtask adr` tooling lands (#29, #21), the index and the format checks are
  manual, and reviewers have to check them.

## Security impact

ADRs make security defaults (enforcement mode, failure behaviour, crypto, trust rules) explicit
and reviewable. A PR that silently weakens a default can be rejected against a named ADR. The
immutability rule stops an accepted security decision from being edited to mean something else
without a visible superseding record. The required Security impact section means no
architectural change can merge without its security effect being stated.

## Links

- Issue #20 (this process), epic #1.
- Tooling: `cargo xtask adr new|index|lint` in #29, CI enforcement in #21, ADR table in the
  docs site in #27, PR template checklist in #28.
