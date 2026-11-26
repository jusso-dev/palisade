# Repository settings

Some of Palisade's security depends on GitHub repository settings, not on files in the
repository. This page lists every setting the project relies on, why it matters, and how to apply
it. Only a repository administrator can change these, so they are documented here and reviewed
like code. When a setting changes, update this page in the same change.

The `gh api` commands below use the GitHub REST API. Run them as a repository administrator. The
same settings are also available under **Settings** in the web UI.

## Summary

| Setting | Required value | Why |
|---|---|---|
| Private vulnerability reporting | On | The only private channel in [SECURITY.md](../SECURITY.md) |
| Secret scanning | On | Catches leaked credentials in commits |
| Push protection | On | Blocks pushes that contain a detected secret |
| Dependabot alerts | On | Warns about vulnerable dependencies between scheduled audits |
| Dependabot security updates | On | Opens fix PRs for those alerts ([docs/ci.md](ci.md#dependabot-githubdependabotyml)) |
| Allowed actions | Selected: the allowlist in `xtask/src/workflows.rs` only, pinned to a full SHA | A second layer behind `cargo xtask check-workflows` |
| Default `GITHUB_TOKEN` permissions | Read | Least privilege; jobs ask for more themselves |
| Actions can approve pull requests | Off | A workflow must never approve its own change |
| Fork pull request workflows | Need approval for first-time contributors | Stops drive-by workflow runs from new accounts |
| `main` ruleset | Pull requests only, required checks, linear history, no force pushes or deletion | See [Branch protection](#branch-protection-for-main) |
| Merge methods | Squash only, commit title from the PR title | The PR title is the changelog entry ([CONTRIBUTING.md](../CONTRIBUTING.md#conventional-commits)) |
| Discussions | On, with a Q&A category | The support channel in [SUPPORT.md](../SUPPORT.md) |
| Labels and milestones | Exactly the lists in `.github/labels.yml` and `.github/milestones.yml` | Synced by `labels.yml`; see [Labels and milestones](#labels-and-milestones) |
| `DCO` check | Runs on every pull request; not yet required | See [DCO check](#dco-check) |
| GitHub Pages | Deploy from the `gh-pages` branch, root folder | Serves the documentation site; see [GitHub Pages](#github-pages) |

## Code security

```sh
# Private vulnerability reporting.
gh api -X PUT repos/jusso-dev/palisade/private-vulnerability-reporting

# Dependabot alerts, then Dependabot security updates (alerts must be on first).
gh api -X PUT repos/jusso-dev/palisade/vulnerability-alerts
gh api -X PUT repos/jusso-dev/palisade/automated-security-fixes

# Secret scanning and push protection.
gh api -X PATCH repos/jusso-dev/palisade --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF
```

To check them:

```sh
gh api repos/jusso-dev/palisade/private-vulnerability-reporting   # {"enabled":true}
gh api repos/jusso-dev/palisade/vulnerability-alerts               # HTTP 204 when on, 404 when off
gh api repos/jusso-dev/palisade -q .security_and_analysis
```

After enabling private vulnerability reporting, file a test report from a second account through
the [private reporting form](https://github.com/jusso-dev/palisade/security/advisories/new), check
that it arrives as a draft advisory, then close it.

## GitHub Actions

CI policy is enforced in two places: `cargo xtask check-workflows` checks the workflow files on
every pull request ([docs/ci.md](ci.md#runner-and-action-policy)), and these settings stop GitHub
from running anything outside the same allowlist, even if a workflow file got past the check.

```sh
# Only selected actions, and only when pinned to a full commit SHA.
gh api -X PUT repos/jusso-dev/palisade/actions/permissions \
  -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true

# The allowlist. Keep it identical to ALLOWED_ACTIONS in xtask/src/workflows.rs.
gh api -X PUT repos/jusso-dev/palisade/actions/permissions/selected-actions --input - <<'EOF'
{
  "github_owned_allowed": false,
  "verified_allowed": false,
  "patterns_allowed": [
    "actions/checkout@*",
    "Swatinem/rust-cache@*",
    "taiki-e/install-action@*"
  ]
}
EOF

# Read-only GITHUB_TOKEN by default, and workflows may not approve pull requests.
gh api -X PUT repos/jusso-dev/palisade/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false

# Fork pull requests from first-time contributors wait for approval before workflows run.
gh api -X PUT repos/jusso-dev/palisade/actions/permissions/fork-pr-contributor-approval \
  -f approval_policy=first_time_contributors
```

To check them:

```sh
gh api repos/jusso-dev/palisade/actions/permissions                   # allowed_actions "selected", sha_pinning_required true
gh api repos/jusso-dev/palisade/actions/permissions/selected-actions
gh api repos/jusso-dev/palisade/actions/permissions/workflow          # "read", false
gh api repos/jusso-dev/palisade/actions/permissions/fork-pr-contributor-approval
```

When an action is added to `ALLOWED_ACTIONS`, add it to `patterns_allowed` too, or its workflow
will not run.

Dependabot's own update jobs run as GitHub-managed workflows that bypass these Actions policies, so
the allowlist does not stop Dependabot from opening pull requests.

Runners are not a setting: every job runs on a GitHub-hosted runner, and the runner-guard check
rejects anything else. Self-hosted runners must never be registered for this repository, and
cloud-managed build services are never used ([docs/ci.md](ci.md)).

## GitHub Pages

The documentation site is published by `.github/workflows/pages.yml`, which pushes the built site to
the `gh-pages` branch ([docs/ci.md](ci.md#publishing)). The Pages deployment actions are not on
the action allowlist, so Pages serves that branch directly. This is a one-time setting, made after
the first run of `pages.yml` has created the branch:

```sh
# Serve the gh-pages branch, root folder.
gh api -X POST repos/jusso-dev/palisade/pages \
  -f build_type=legacy -f 'source[branch]=gh-pages' -f 'source[path]=/'
```

Or in the web UI: **Settings → Pages → Build and deployment → Source: Deploy from a branch**,
branch `gh-pages`, folder `/ (root)`. Then check it:

```sh
gh api repos/jusso-dev/palisade/pages    # "build_type": "legacy", source gh-pages and /
```

The site is then at <https://jusso-dev.github.io/palisade/>, which redirects to `latest/`. The
first deployment needs this setting before Pages serves anything: after making it, rerun
`pages.yml` once (**Actions → Pages → Run workflow** on `main`).

A push made with a workflow's `GITHUB_TOKEN` does not start a Pages build, so `pages.yml`'s push
alone would update `gh-pages` but not the site. After each push it therefore requests the build
itself (`POST repos/jusso-dev/palisade/pages/builds`), with the same token and only the job's
`pages: write` permission, even when the site is unchanged, so rerunning `pages.yml` also
retries a build request that failed. No personal token or deployment action is needed. A push to
`gh-pages` made by hand, by someone with admin rights, still starts a build as usual.

Serving a branch still runs GitHub's own `pages-build-deployment` workflow. If the Actions
allowlist above stops that workflow, its run shows a startup failure naming the blocked action,
and the site is not updated. The fix widens the allowlist, so it is a maintainer decision: add the
action it names to `patterns_allowed`, or allow actions created by GitHub, and record the change
on this page. `pages.yml` itself needs neither.

## Branch protection for `main`

`main` is protected by a repository ruleset named `main`. It:

- requires a pull request for every change, so nothing is pushed to `main` directly;
- allows squash merges only;
- requires two status checks to pass on the latest commit:
  - `ci-ok`, which passes only when every job in `ci.yml` passed ([docs/ci.md](ci.md));
  - `PR title`, the Conventional Commits check on the pull request title (`pr-title.yml`);
- requires review threads to be resolved before merging;
- requires linear history, and blocks force pushes and deletion of `main`.

Both checks are pinned to the GitHub Actions app (`integration_id` 15368), so a status with the
same name posted by anything else does not count.

**Required approvals are 0 while Palisade has one maintainer.** GitHub does not let a pull
request author approve their own pull request, so requiring an approval would block every change
the maintainer makes. Pull requests from anyone else are still reviewed, because only the
maintainer can merge, and [CODEOWNERS](../.github/CODEOWNERS) requests the maintainer's review on
every pull request. When a second maintainer joins, set `required_approving_review_count` to 1 and
`require_code_owner_review` to true.

Signed commits are recommended but not required.

```sh
gh api -X POST repos/jusso-dev/palisade/rulesets --input - <<'EOF'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "required_linear_history" },
    {
      "type": "pull_request",
      "parameters": {
        "allowed_merge_methods": ["squash"],
        "required_approving_review_count": 0,
        "require_code_owner_review": false,
        "dismiss_stale_reviews_on_push": true,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "ci-ok", "integration_id": 15368 },
          { "context": "PR title", "integration_id": 15368 }
        ]
      }
    }
  ]
}
EOF
```

`strict_required_status_checks_policy` is `false`, so a pull request does not have to be updated
with the latest `main` before it merges. That keeps a single maintainer's queue moving. The cost
is that a branch can merge without rerunning checks that changed on `main` since it was last
tested. `main` runs the full CI again after every merge, so a failure shows up there at once.

To check the ruleset, and to change it later, list it with `gh api repos/jusso-dev/palisade/rulesets`, then update
it with `gh api -X PUT repos/jusso-dev/palisade/rulesets/<id> --input <file>`.

## Merging and general settings

```sh
gh api -X PATCH repos/jusso-dev/palisade --input - <<'EOF'
{
  "allow_squash_merge": true,
  "allow_merge_commit": false,
  "allow_rebase_merge": false,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY",
  "delete_branch_on_merge": true,
  "has_issues": true,
  "has_discussions": true
}
EOF
```

To check them:

```sh
gh api repos/jusso-dev/palisade \
  -q '{allow_squash_merge, allow_merge_commit, allow_rebase_merge, squash_merge_commit_title, delete_branch_on_merge, has_discussions}'
```

`squash_merge_commit_title` must be `PR_TITLE`. The default uses the commit title instead when a
pull request has a single commit, which would bypass the PR title check.

## Labels and milestones

The label set and the milestone titles live in two files, so they are reviewed like code:

- [`.github/labels.yml`](../.github/labels.yml): every label, with its colour and description;
- [`.github/milestones.yml`](../.github/milestones.yml): the seven milestones, `M0 Foundations` to
  `M6 Compliance & Advanced`, with their exact titles and descriptions.

The `Label sync` workflow (`.github/workflows/labels.yml`) runs
[`.github/scripts/sync-labels.sh`](../.github/scripts/sync-labels.sh):

- On a pull request that touches either file, the issue templates, `dependabot.yml` or the script,
  it runs the script's tests and validates the files. Validation also fails if an issue template
  or Dependabot applies a label that is not listed, because the sync would delete it.
- On a push to `main` it applies the files. Missing labels are created, colours and descriptions
  are updated, and **labels that are not listed are deleted**, which removes them from every
  issue. Missing milestones are created and their descriptions updated. An open milestone that is
  not listed is reported and the run fails, but it is never deleted or closed; close it by hand,
  or add it to the file. Closed milestones that are not listed are ignored.
- Run it by hand from the Actions tab for a dry run that prints every change and writes nothing.
  Tick `apply` to make the changes. Changes are only ever applied from `main`; a manual run on any
  other branch is always a dry run.

Only the sync job has a write scope, `issues: write`, which covers labels and milestones, plus
`contents: read` for the checkout. It never runs on a pull request.

To dry-run locally, with the GitHub CLI signed in to an account that can read the repository:

```sh
bash .github/scripts/sync-labels.sh --validate
bash .github/scripts/sync-labels.sh --check --repo jusso-dev/palisade   # exit 1 means drift; nothing is written
bash .github/scripts/sync-labels.test.sh
```

Review the `DELETE` lines before the first apply. The first sync removes the default labels that
GitHub creates with a repository (`bug`, `documentation`, `duplicate`, `enhancement`, `invalid`,
`question`, `wontfix`) and `accessibility`, none of which is in the list. The issue templates
apply `needs-triage` instead, and Dependabot applies `area:security` or `area:infra`.

## DCO check

The `DCO` workflow (`.github/workflows/dco.yml`) runs
[`.github/scripts/check-dco.sh`](../.github/scripts/check-dco.sh) on every pull request. It fails
if any non-merge commit lacks a `Signed-off-by:` trailer whose email matches the commit author
([CONTRIBUTING.md](../CONTRIBUTING.md#sign-off)). It needs no token scope beyond `contents: read`.
Dependabot's pull requests pass it with the bot's own sign-off ([docs/ci.md](ci.md#dcoyml-pull-requests)).
Pull requests opened by the repository owner pass without sign-off
([CONTRIBUTING.md](../CONTRIBUTING.md#sign-off)). The exemption follows GitHub's `author_association`, which
is `OWNER` only on a repository owned by a personal account. Transferring the repository to another
personal account moves the exemption to that account. Transferring it to an organisation ends it, because
organisation owners and members are reported as `MEMBER`, so the check then applies to everyone (it fails
closed).

The check is **informational**: the `main` ruleset does not require it yet. Requiring sign-off is
decided by an ADR under [#28](https://github.com/jusso-dev/palisade/issues/28). Once that ADR is
accepted, add the check to the ruleset's required status checks:

```json
{ "context": "DCO", "integration_id": 15368 }
```

in the `required_status_checks` list of the ruleset in
[Branch protection](#branch-protection-for-main), then update the ruleset with
`gh api -X PUT repos/jusso-dev/palisade/rulesets/<id> --input <file>`, and update the summary
table above.
