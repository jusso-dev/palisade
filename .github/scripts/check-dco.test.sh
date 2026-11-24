#!/usr/bin/env bash
# Tests for check-dco.sh. Run: bash .github/scripts/check-dco.test.sh
# Builds throwaway repositories under a temporary directory; needs only git.
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/check-dco.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0

# A fresh repository with one unsigned base commit, tagged `base`.
new_repo() {
  repo="$work/$1"
  git init -q "$repo"
  git -C "$repo" config user.name "Ada Lovelace"
  git -C "$repo" config user.email "ada@example.org"
  git -C "$repo" config commit.gpgsign false
  git -C "$repo" commit -q --allow-empty -m "base"
  git -C "$repo" tag base
}

# commit <message> [extra git args]: an empty commit in $repo.
commit() {
  local message=$1
  shift
  git -C "$repo" commit -q --allow-empty -m "$message" "$@"
}

# expect <exit code> <description> [args]: runs the checker in $repo on
# base..HEAD, or on the given arguments.
expect() {
  local want=$1 what=$2 got
  shift 2
  [ "$#" -gt 0 ] || set -- base HEAD
  (cd "$repo" && bash "$script" "$@") >/dev/null 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: $what: expected exit $want, got $got"
    failures=$((failures + 1))
  fi
}

new_repo signed
commit "feat: one" -s
commit "fix: two" -s
expect 0 "every commit signed off"

new_repo empty-range
expect 0 "no commits in the range"

new_repo unsigned
commit "feat: one" -s
commit "fix: two"
expect 1 "one commit without a sign-off"

new_repo other-person
commit "feat: one" -m "Signed-off-by: Someone Else <someone@example.org>"
expect 1 "sign-off by someone other than the author"

new_repo case
commit "feat: one" -m "Signed-off-by: Ada Lovelace <ADA@Example.ORG>"
expect 0 "email compared without case"

new_repo second-trailer
commit "feat: one" -m "Signed-off-by: Someone Else <someone@example.org>
Signed-off-by: Ada Lovelace <ada@example.org>"
expect 0 "author's sign-off among several"

new_repo body-only
commit "feat: one" -m "As discussed, Signed-off-by: Ada Lovelace <ada@example.org> is needed.

More text after it."
expect 1 "sign-off text in the body, not a trailer"

new_repo co-author
commit "feat: one" -m "Co-authored-by: Ada Lovelace <ada@example.org>"
expect 1 "a co-author trailer is not a sign-off"

new_repo malformed
commit "feat: one" -m "Signed-off-by: Ada Lovelace ada@example.org"
expect 1 "sign-off without an email in angle brackets"

new_repo merge
git -C "$repo" checkout -q -b topic
commit "feat: on topic" -s
git -C "$repo" checkout -q -
commit "fix: on main" -s
git -C "$repo" merge -q --no-ff --no-edit topic
expect 0 "merge commits are skipped"

new_repo nameless
commit "feat: one" -m "Signed-off-by: <ada@example.org>"
expect 1 "sign-off without a name"

# Dependabot authors at a noreply address and signs off as support@github.com.
bot_commit() {
  git -C "$repo" -c user.name='dependabot[bot]' \
    -c user.email='49699333+dependabot[bot]@users.noreply.github.com' \
    commit -q --allow-empty -m "chore(deps): bump a crate" \
    -m "Signed-off-by: ${1:-dependabot[bot] <support@github.com>}"
}
new_repo bot-flag
bot_commit
expect 0 "Dependabot commit with --dependabot" --dependabot base HEAD
expect 1 "Dependabot commit without --dependabot" base HEAD

new_repo bot-wrong-signoff
bot_commit "Someone Else <someone@example.org>"
expect 1 "Dependabot commit signed off by someone else" --dependabot base HEAD

new_repo bot-flag-human
commit "feat: one" -m "Signed-off-by: dependabot[bot] <support@github.com>"
expect 1 "--dependabot does not let a human use the bot sign-off" --dependabot base HEAD
commit "fix: two" -s
expect 1 "--dependabot still checks every commit" --dependabot base HEAD

new_repo usage
expect 2 "no arguments" base
expect 2 "unknown ref" base no-such-ref
expect 2 "flag only" --dependabot base

if [ "$failures" -ne 0 ]; then
  echo "$failures check-dco test(s) failed"
  exit 1
fi
echo "check-dco tests passed"
