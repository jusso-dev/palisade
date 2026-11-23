#!/usr/bin/env bash
# Checks that a pull request title follows Conventional Commits, as described
# in CONTRIBUTING.md. Squash merges use the PR title as the commit message on
# `main`, and the release changelog is generated from those messages.
#
# Usage: check-pr-title.sh "<title>"
# Exit 0 if the title is valid, 1 if not, 2 on a usage error.
set -euo pipefail
# Byte-wise matching: under other locales `[a-z]` can match uppercase letters.
export LC_ALL=C

if [ "$#" -ne 1 ]; then
  echo "usage: $0 \"<pull request title>\"" >&2
  exit 2
fi
title=$1

types='feat|fix|security|docs|ci|build|refactor|test|chore|revert'
# <type>(<optional scope>)<optional !>: <summary>. The summary must not start
# with a space and must not contain control characters (newline, CR, tab), so
# the squash commit subject is always a single clean line.
pattern="^(${types})(\([a-z0-9][a-z0-9._-]*\))?!?: [^[:space:][:cntrl:]][^[:cntrl:]]*$"

if [[ "$title" =~ $pattern ]]; then
  echo "PR title OK: $title"
  exit 0
fi

cat >&2 <<EOF
PR title does not follow Conventional Commits: $title

Expected: <type>(<optional scope>): <summary>
  type:  ${types//|/, }
  scope: a crate or area in lowercase, for example policy, agent, adr, deps
  add ! before the colon for a breaking change
Examples:
  feat(policy): add publisher rule condition
  fix(agent): handle renamed files
  docs: explain rule precedence

Edit the pull request title to fix this; the check reruns. See CONTRIBUTING.md.
EOF
exit 1
