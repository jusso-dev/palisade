<!--
The PR title becomes the commit message on `main` (squash merge), so it must
follow Conventional Commits, for example `feat(policy): add publisher rule
condition`. See CONTRIBUTING.md.

Security fixes for undisclosed vulnerabilities are coordinated privately
first (SECURITY.md). Do not describe an undisclosed vulnerability here.
-->

## Summary

<!-- What this changes and why. -->

Closes #<!-- issue number, or use "Part of #N" and say what is left below -->

## Deferred

<!-- Anything not done here, and the existing issue it belongs to. Write "None" if nothing. -->

## How to test

<!-- Commands or steps a reviewer can run. -->

## Checklist

- [ ] Tests added or updated, and the checks in [CONTRIBUTING.md](https://github.com/jusso-dev/palisade/blob/main/CONTRIBUTING.md#before-you-push) pass locally.
- [ ] Docs updated, or no docs change is needed.
- [ ] ADR linked, if this is an architectural change, or not applicable.
- [ ] No new `unsafe` code, or the unsafe allowlist is updated and every block has a `// SAFETY:` comment.
- [ ] New dependencies, if any, are justified in the summary above.
- [ ] No secrets, tokens, keys or real malware samples.
- [ ] No commercial product or vendor names ([naming guide](https://github.com/jusso-dev/palisade/blob/main/docs/NAMING.md)).
- [ ] The title is a Conventional Commit that would read well in the changelog.
- [ ] Every commit is signed off (`git commit -s`), or the pull request is opened by the repository owner, as described in [CONTRIBUTING.md](https://github.com/jusso-dev/palisade/blob/main/CONTRIBUTING.md#sign-off).
