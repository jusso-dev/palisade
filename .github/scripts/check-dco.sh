#!/usr/bin/env bash
# Checks that every commit in a range carries a Developer Certificate of Origin
# sign-off from its author: a `Signed-off-by: Name <email>` trailer whose
# email matches the commit's author email (ignoring case). `git commit -s`
# adds one. Merge commits are skipped. See CONTRIBUTING.md#sign-off.
#
# Usage: check-dco.sh <base> <head>
#   Checks the commits reachable from <head> but not from <base>, run inside
#   the repository.
# Exit 0 if every commit is signed off (or there are none), 1 if any is not,
# 2 on a usage or git error.
set -euo pipefail
export LC_ALL=C

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <base> <head>" >&2
  exit 2
fi
base=$1
head=$2

for ref in "$base" "$head"; do
  git rev-parse --verify --quiet "$ref^{commit}" >/dev/null || {
    echo "check-dco: not a commit: $ref" >&2
    exit 2
  }
done

commits=$(git rev-list --no-merges --reverse "$base..$head") || {
  echo "check-dco: git rev-list failed" >&2
  exit 2
}

lower() { tr '[:upper:]' '[:lower:]'; }

checked=0
missing=0
for commit in $commits; do
  checked=$((checked + 1))
  author_email=$(git show -s --format='%ae' "$commit" | lower)
  subject=$(git show -s --format='%s' "$commit")
  # One sign-off value per line, for example `Ada Lovelace <ada@example.org>`.
  signoffs=$(git show -s --format='%(trailers:key=Signed-off-by,valueonly,separator=%x0A)' "$commit")
  signed=0
  while IFS= read -r line; do
    [[ "$line" =~ \<([^<>]+)\>[[:space:]]*$ ]] || continue
    if [ "$(printf '%s' "${BASH_REMATCH[1]}" | lower)" = "$author_email" ]; then
      signed=1
      break
    fi
  done <<<"$signoffs"
  if [ "$signed" -eq 0 ]; then
    missing=$((missing + 1))
    echo "missing sign-off: ${commit:0:12} $subject (author <$author_email>)" >&2
  fi
done

if [ "$missing" -gt 0 ]; then
  cat >&2 <<EOF

$missing of $checked commits have no Signed-off-by trailer matching the commit author's email.
Signing off certifies the Developer Certificate of Origin (https://developercertificate.org).
To fix: sign off new commits with \`git commit -s\`. To sign off existing ones:
  git rebase --signoff <base branch>
  git push --force-with-lease
See CONTRIBUTING.md#sign-off.
EOF
  exit 1
fi
echo "DCO OK: $checked commits signed off"
