# ADR process

Palisade records significant design decisions as Architecture Decision Records (ADRs) in this
directory. An ADR is a short document that captures one decision: its context, the options that
were considered, the choice made and its consequences. ADRs stop settled questions from being
reopened by accident, and they explain to a learner *why* Palisade works the way it does.

[ADR 0001](0001-record-architecture-decisions.md) adopts this process.

## When to write an ADR

Write one when a change:

- picks between design forks that are expensive to reverse (protocols, storage, crypto,
  enforcement mechanisms, crate boundaries, default security behaviour);
- changes a default that affects whether something is blocked or allowed;
- adds a dependency on a new privileged component (driver, service, signing key); or
- contradicts an accepted ADR. That requires a new, superseding ADR (see below).

Routine choices inside one crate do not need an ADR. Put those in code comments or the crate
README.

## Format

- Location: `docs/adr/`.
- File name: `NNNN-kebab-title.md`, for example `0002-enforcement-strategy.md`.
- `NNNN` is a 4-digit number. `0000` is reserved for the template.
- Start from [`0000-template.md`](0000-template.md). The sections and their order are fixed:
  Title, Status, Date, Deciders, Context, Decision drivers, Considered options, Decision,
  Consequences (Positive and Negative), Security impact, Links.
- The first line is `# NNNN. Title`. The next three lines are a list, so that tooling can parse
  them:

  ```markdown
  - Status: accepted
  - Date: 2026-11-23
  - Deciders: Palisade maintainer
  ```

- **Status** is exactly one of `proposed`, `accepted`, `superseded by NNNN`, `deprecated` or
  `rejected`.
- **Date** is the date of the most recent status change.
- **Security impact** must say something real. If a decision truly has no security effect, the
  section explains why.
- Keep an ADR to one or two pages. Put long research in `docs/design/` and link to it.
- Never name commercial products or vendors. Describe approaches generically
  ([naming guide](../NAMING.md)).

## Numbering

- Numbers increase monotonically. The next ADR takes the highest existing number plus one,
  counting every file in the directory, including rejected and superseded ADRs.
- Numbers are never reused. A rejected ADR stays in the repository with status `rejected`, so
  its number and reasoning are not lost.
- If two open PRs pick the same number, the PR that merges second renumbers its ADR before it
  merges. That is allowed because the ADR is not yet accepted.

## Lifecycle

```
proposed ──▶ accepted ──▶ superseded by NNNN
    │            └───────▶ deprecated
    └──▶ rejected
```

1. **Propose.** Open a PR that adds the ADR with status `proposed` (or `accepted`, if the PR
   is meant to accept it on merge). Label the PR `area:infra`.
2. **Discuss.** While an ADR is `proposed`, its content may change freely in follow-up PRs.
3. **Accept.** An ADR becomes `accepted` when a PR that sets that status is merged. The PR
   needs:
   - approval from at least one maintainer, and
   - at least 3 days open since the PR was created, unless the maintainer marks it urgent.
     To mark it urgent, the maintainer adds a line `ADR-Urgent: <reason>` to the PR
     description, and the reason is copied into the ADR's Links section.
4. **Reject.** A proposal that is declined is merged with status `rejected`, with a sentence in
   Decision explaining why, so the reasoning is kept.

### Accepted ADRs are immutable

Once accepted, an ADR's text does not change. The only edits allowed are:

- the Status line and the Date line (to `superseded by NNNN` or `deprecated`), and
- the Links section (to add links to later ADRs, issues or docs).

Typos may be fixed if the meaning does not change.

### Changing direction

To change an accepted decision:

1. Write a new ADR that explains what changed, links the old one under "Supersedes", and is
   accepted through the normal process.
2. In the same PR, set the old ADR's status to `superseded by NNNN` and add a link back.

A PR that contradicts an accepted ADR must link the superseding ADR (an existing one, or one
proposed in the same PR). Reviewers reject PRs that contradict an accepted ADR without one.
`deprecated` is for decisions that no longer apply because the thing they governed was
removed, with nothing to replace them.

## Index and tooling

[`README.md`](README.md) holds the index of all ADRs. The index is maintained by hand for now.
Planned tooling (tracked in #29, with CI wiring in #21) will replace the manual steps:

- `cargo xtask adr new "<title>"` copies the template with the next number;
- `cargo xtask adr index` regenerates the table between the `adr-index` markers in `README.md`,
  and CI fails if it is stale;
- `cargo xtask adr lint` rejects an ADR with a bad file name or number, a missing or invalid
  Status line, or a missing or empty Security impact section.

Until that tooling lands, the PR author updates the index by hand and reviewers check the format
against this document.

## Review checklist for ADR PRs

- [ ] The file name and number follow the numbering rules.
- [ ] All template sections are present, in order, and none is empty.
- [ ] Every considered option has its trade-offs against the decision drivers.
- [ ] The Decision can be checked against later PRs.
- [ ] A `proposed` ADR says what evidence would decide it.
- [ ] Security impact is specific.
- [ ] No commercial product or vendor names.
- [ ] The index in `README.md` is updated.
- [ ] Any superseded ADR has its status and links updated in the same PR.
