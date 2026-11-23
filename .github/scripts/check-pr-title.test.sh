#!/usr/bin/env bash
# Tests for check-pr-title.sh. Run: bash .github/scripts/check-pr-title.test.sh
set -uo pipefail

script="$(dirname "$0")/check-pr-title.sh"
failures=0

expect() {
  local want=$1 title=$2 got
  bash "$script" "$title" >/dev/null 2>&1
  got=$?
  if [ "$got" -ne "$want" ]; then
    echo "FAIL: expected exit $want, got $got for title: [$title]"
    failures=$((failures + 1))
  fi
}

# Valid titles.
expect 0 'feat(policy): add publisher rule condition'
expect 0 'fix(agent): handle renamed files'
expect 0 'security: reject oversized policy bundles'
expect 0 'docs: explain rule precedence'
expect 0 'ci: pin actionlint'
expect 0 'build: bump the toolchain'
expect 0 'refactor(core): split rule types'
expect 0 'test(fileid): add PE header fuzz corpus'
expect 0 'chore(deps): bump serde_json from 1.0.1 to 1.0.2'
expect 0 'revert: feat(policy): add publisher rule condition'
expect 0 'feat(policy)!: change the default precedence'
expect 0 'feat!: drop the legacy policy format'
expect 0 'fix(palisade-agent): handle renamed files'
expect 0 'docs(adr.index): fix a link'
expect 0 'chore(ci_cache): tidy'

# Invalid titles.
expect 1 ''
expect 1 'Add publisher rule condition'
expect 1 'feature(policy): add publisher rule condition'
expect 1 'Feat(policy): add publisher rule condition'
expect 1 'feat(Policy): add publisher rule condition'
expect 1 'feat(): empty scope'
expect 1 'feat(-policy): scope starts with a separator'
expect 1 'feat(policy) : space before the colon'
expect 1 'feat(policy):no space after the colon'
expect 1 'feat(policy):  two spaces after the colon'
expect 1 'feat(policy): '
expect 1 'feat(policy)'
expect 1 'feat policy: missing parentheses'
expect 1 'feat(policy)!!: two bangs'
expect 1 'Revert "feat(policy): add publisher rule condition"'
expect 1 ' feat(policy): leading space'

# Usage errors.
bash "$script" >/dev/null 2>&1
[ $? -eq 2 ] || { echo "FAIL: expected exit 2 with no arguments"; failures=$((failures + 1)); }
bash "$script" a b >/dev/null 2>&1
[ $? -eq 2 ] || { echo "FAIL: expected exit 2 with two arguments"; failures=$((failures + 1)); }

if [ "$failures" -ne 0 ]; then
  echo "$failures check-pr-title test(s) failed"
  exit 1
fi
echo "All check-pr-title tests passed."
