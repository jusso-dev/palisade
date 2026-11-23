# 0014. Educational scope statement

- Status: accepted
- Date: 2026-11-23
- Deciders: Palisade maintainer

## Context

Palisade is a personal learning project, built in public to understand application control end
to end. The README says it is not a replacement for enterprise products or enterprise support,
and should not be relied on to protect production environments. Because Palisade is security
software, people will still ask whether it is production ready, file vulnerability reports, and
may deploy it anyway. Unclear promises are worse than plain limits: someone who assumes a
security fix will ship within days may leave an exposure in place. This ADR says precisely what
"educational" and "not for production" mean, so that the README (#28), SECURITY.md (#28),
SUPPORT.md (#28) and the docs site (#27) say the same thing.

## Decision drivers

1. Honesty about what one maintainer can sustain.
2. Users must be able to make a safe decision about whether to run it.
3. Security reports still need a clear, private path and a stated response, because the code is
   public and people may use it.
4. Engineering practice stays high: the project exists to learn how to do this well.

## Considered options

1. **Say nothing beyond the licence's no-warranty clause.** Legally enough, but it leaves
   expectations about fixes and support undefined.
2. **Offer production-style commitments** (an SLA, supported versions, security-fix timelines).
   Not sustainable for one maintainer, and it would mislead users.
3. **An explicit educational-scope statement with best-effort targets.** Clear limits, a defined
   security reporting path, and response targets stated as best effort.

## Decision

Option 3. Palisade's scope is defined as follows.

**What "educational" means**

- Palisade is built to learn and to teach. Design choices are documented so others can learn from
  them (ADRs, the threat model, design docs).
- The engineering bar is still high: signed releases, a threat model, tests, fuzzing and
  supply-chain checks. "Educational" lowers the support commitment, not the engineering quality.

**What "not for production" means**

- **No support commitment.** Help is community best-effort, through GitHub Discussions for
  questions and Issues for bugs. There is no commercial support, now or planned.
- **No SLA.** No guaranteed response, fix or release times for anything, including security.
- **Security fixes are best effort.** Reports go through GitHub private vulnerability reporting.
  The targets are acknowledgement within 7 days and triage within 14 days, stated as best effort.
  Coordinated disclosure defaults to 90 days. Fixes land on the latest minor release only; older
  releases are not patched. SECURITY.md (#28) holds the full policy.
- **No certification or compliance claim.** Essential Eight and ISM mappings are learning aids and
  evidence examples, not an assessment outcome. Palisade claims no certified status (#18).
- **No warranty**, as stated in both licences ([ADR 0010](0010-licence.md)).
- Anyone who runs Palisade on machines they care about does so at their own risk, and should test
  on disposable VMs first (#26).

**Where it is stated**

- README (already present), SECURITY.md and SUPPORT.md (#28), and the docs site landing page
  (#27). They use the same wording, and the docs site wording is the source (#27, #28).

## Consequences

### Positive

- Users know the limits before they deploy anything.
- Security reporters know where to report and what response to expect.
- The maintainer is not held to commitments one person cannot keep.

### Negative

- Some potential users will skip the project because it offers no support.
- Best-effort security targets can still be missed. When that happens, the advisory should say so
  plainly.

## Security impact

Clear scope reduces the risk of Palisade being relied on as someone's only application control in
production without them knowing the fix cadence is best effort. A defined private reporting path
keeps vulnerability details out of public issues until a fix or advisory is ready. "Latest minor
only" means users must upgrade to receive fixes, and SECURITY.md has to state that plainly.

## Links

- Issues #20, #18, #26, #27, #28. README "About this project" and "Disclaimer".
