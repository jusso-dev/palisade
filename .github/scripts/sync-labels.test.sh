#!/usr/bin/env bash
# Tests for sync-labels.sh. Run: bash .github/scripts/sync-labels.test.sh
# Needs jq and yq v4. The GitHub API is replaced by a fake `gh` on PATH that
# serves fixture JSON and records every write, so nothing touches the network.
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/sync-labels.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# The fake gh: GET requests print $FAKE_DIR/labels.json or milestones.json;
# writes append their arguments to $FAKE_DIR/writes and print nothing.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
[ "$1" = api ] || exit 9
shift
if [ "$1" = --paginate ]; then
  case $2 in
    */labels\?*) cat "$FAKE_DIR/labels.json" ;;
    */milestones\?*) cat "$FAKE_DIR/milestones.json" ;;
    *) exit 9 ;;
  esac
  exit 0
fi
printf '%s\n' "$*" >>"$FAKE_DIR/writes"
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" FAKE_DIR="$work/fake"
unset GITHUB_REPOSITORY

# Fixture configuration: two labels, two milestones, one template.
cfg="$work/cfg"
mkdir -p "$cfg/templates" "$FAKE_DIR"
cat >"$cfg/labels.yml" <<'EOF'
- name: area:core
  color: "0e8a16"
  description: Policy model
- name: needs-triage
  color: "ededed"
  description: Not yet triaged
EOF
cat >"$cfg/milestones.yml" <<'EOF'
- title: M0 Foundations
  description: Workspace and CI
- title: M1 Audit & Inventory
  description: Audit mode
EOF
printf 'name: Bug\nlabels: [needs-triage]\nbody: []\n' >"$cfg/templates/bug.yml"
printf 'blank_issues_enabled: false\n' >"$cfg/templates/config.yml"
printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n    labels: ["area:core"]\n' >"$cfg/dependabot.yml"

# run <mode> [extra args]: runs the script on the fixtures. Sets $code, $out.
run() {
  local mode=$1
  shift
  : >"$FAKE_DIR/writes"
  out=$(bash "$script" "--$mode" --labels "$cfg/labels.yml" --milestones "$cfg/milestones.yml" \
    --templates "$cfg/templates" --dependabot "$cfg/dependabot.yml" "$@" 2>&1)
  code=$?
}
expect_code() { [ "$code" -eq "$1" ] || fail "$2: expected exit $1, got $code. Output: $out"; }
expect_out() { grep -qF -- "$1" <<<"$out" || fail "$2: output lacks [$1]. Output: $out"; }
expect_writes() {
  local got
  got=$(wc -l <"$FAKE_DIR/writes" | tr -d ' ')
  [ "$got" -eq "$1" ] || fail "$2: expected $1 API writes, got $got: $(cat "$FAKE_DIR/writes")"
}

# GitHub state that matches the fixtures exactly.
in_sync_labels='[{"name":"area:core","color":"0E8A16","description":"Policy model"},
  {"name":"needs-triage","color":"ededed","description":"Not yet triaged"}]'
in_sync_milestones='[{"number":1,"title":"M0 Foundations","description":"Workspace and CI","state":"open"},
  {"number":2,"title":"M1 Audit & Inventory","description":"Audit mode","state":"open"}]'
set_github() { printf '%s' "$1" >"$FAKE_DIR/labels.json"; printf '%s' "$2" >"$FAKE_DIR/milestones.json"; }

# --- --validate ----------------------------------------------------------

run validate
expect_code 0 "valid fixtures"

# The repository's own files must validate.
out=$(bash "$script" --validate 2>&1)
code=$?
expect_code 0 "the repository's labels, milestones, templates and dependabot.yml"

cp "$cfg/labels.yml" "$work/good-labels.yml"
bad_label() {
  printf '%s\n' "$1" >"$cfg/labels.yml"
  run validate
  expect_code 2 "$2"
  expect_out "$3" "$2"
  cp "$work/good-labels.yml" "$cfg/labels.yml"
}
bad_label '- name: x
  color: 123456
  description: d' "unquoted colour that YAML reads as a number" "6 lowercase hex digits"
bad_label '- name: x
  color: "0E8A16"
  description: d' "uppercase colour" "6 lowercase hex digits"
bad_label '- name: x
  color: "#0e8a16"
  description: d' "colour with a hash" "6 lowercase hex digits"
bad_label '- name: ""
  color: "0e8a16"
  description: d' "empty name" "non-empty string"
bad_label '- name: x
  color: "0e8a16"' "missing description" "must be a string"
bad_label "- name: x
  color: \"0e8a16\"
  description: $(printf 'a%.0s' $(seq 101))" "description over 100 characters" "longer than 100"
bad_label '- name: x
  color: "0e8a16"
  description: d
  colour: "ffffff"' "unknown key" "unknown key"
bad_label '- name: Blocked
  color: "0e8a16"
  description: d
- name: blocked
  color: "0e8a16"
  description: d' "duplicate names ignoring case" "more than once"
bad_label 'name: x' "not a list" "must be a list"
bad_label "- name: x
  color: \"0e8a16\"
  description: d
---
- name: y
  color: \"0e8a16\"
  description: d" "more than one YAML document" "exactly one YAML document"
bad_label "- name: $(printf 'n%.0s' $(seq 51))
  color: \"0e8a16\"
  description: d" "name over 50 characters" "longer than 50"
bad_label '- name: x
  color: "0e8a16"
  description: "line one\nline two"' "control character in a description" "control characters"

printf -- '- title: M0\n  description: a\n- title: M0\n  description: b\n' >"$work/dup-milestones.yml"
out=$(bash "$script" --validate --labels "$cfg/labels.yml" --milestones "$work/dup-milestones.yml" \
  --templates "$cfg/templates" --dependabot "$cfg/dependabot.yml" 2>&1)
code=$?
expect_code 2 "duplicate milestone titles"
expect_out "listed more than once" "duplicate milestone titles"

printf 'name: Feature\nlabels: [enhancement]\nbody: []\n' >"$cfg/templates/feature.yml"
run validate
expect_code 2 "template applies an unlisted label"
expect_out "feature.yml: applies label \`enhancement\`" "template applies an unlisted label"
set_github "$in_sync_labels" "$in_sync_milestones"
run apply --repo o/r
expect_code 2 "--apply refuses while a template uses an unlisted label"
expect_writes 0 "--apply refuses while a template uses an unlisted label"
rm "$cfg/templates/feature.yml"

printf 'name: Feature\nlabels: [enhancement]\nbody: []\n' >"$cfg/templates/feature.yaml"
run validate
expect_code 2 "a .yaml template is checked too"
expect_out "feature.yaml: applies label" "a .yaml template is checked too"
rm "$cfg/templates/feature.yaml"

printf 'name: Feature\nlabels: "needs-triage, enhancement"\nbody: []\n' >"$cfg/templates/feature.yml"
run validate
expect_code 2 "comma-separated string of labels"
expect_out "applies label \`enhancement\`" "comma-separated string of labels"
printf 'name: Feature\nlabels: "needs-triage"\nbody: []\n' >"$cfg/templates/feature.yml"
run validate
expect_code 0 "a single listed label as a string"
rm "$cfg/templates/feature.yml"

printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n' >"$cfg/dependabot.yml"
run validate
expect_code 2 "dependabot falls back to its default label"
expect_out "applies label \`dependencies\`" "dependabot falls back to its default label"
printf 'version: 2\nupdates:\n  - package-ecosystem: cargo\n    labels: ["area:core"]\n' >"$cfg/dependabot.yml"

# --- --check and --apply -------------------------------------------------

run check
expect_code 2 "--check without a repository"
expect_out "--repo" "--check without a repository"

for bad in 'bad repo' 'o/..' 'o/.' '../r' 'o.x/r' 'o/r/x'; do
  run check --repo "$bad"
  expect_code 2 "malformed --repo $bad"
done

set_github "$in_sync_labels" "$in_sync_milestones"
run check --repo o/r
expect_code 0 "in sync (colour case ignored)"
expect_out "match the files" "in sync"
expect_writes 0 "in sync"

# Closed milestones, listed or not, never cause a change or a failure.
set_github "$in_sync_labels" '[{"number":1,"title":"M0 Foundations","description":"Workspace and CI","state":"closed"},
  {"number":2,"title":"M1 Audit & Inventory","description":"Audit mode","state":"open"},
  {"number":7,"title":"Retired","description":"","state":"closed"}]'
run apply --repo o/r
expect_code 0 "closed listed and closed unlisted milestones"
expect_writes 0 "closed listed milestone is not recreated; closed unlisted one is ignored"

set_github '[{"name":"Area:Core","color":"0e8a16","description":"old"},
  {"name":"wontfix","color":"ffffff","description":""}]' \
  '[{"number":1,"title":"M0 Foundations","description":"old","state":"open"},
    {"number":9,"title":"Old milestone","description":"","state":"open"}]'
run check --repo o/r
expect_code 1 "drift reported by --check"
expect_out "update label: Area:Core -> area:core" "case-only rename and description change"
expect_out "create label: needs-triage" "missing label"
expect_out "DELETE label: wontfix" "unlisted label"
expect_out "update milestone: M0 Foundations" "milestone description"
expect_out "create milestone: M1 Audit & Inventory" "missing milestone"
expect_out "unlisted milestone: Old milestone" "unlisted milestone"
expect_writes 0 "--check makes no API writes"

run apply --repo o/r
expect_code 1 "--apply with an unlisted milestone left over"
expect_writes 5 "--apply makes one write per label or milestone change"
writes=$(cat "$FAKE_DIR/writes")
grep -qF -- "-X PATCH repos/o/r/labels/Area%3ACore" <<<"$writes" || fail "label URL is percent-encoded: $writes"
grep -qF -- "-X DELETE repos/o/r/labels/wontfix" <<<"$writes" || fail "unlisted label deleted: $writes"
grep -qF -- "-X POST repos/o/r/milestones" <<<"$writes" || fail "missing milestone created: $writes"
grep -qF -- "-X PATCH repos/o/r/milestones/1" <<<"$writes" || fail "milestone updated by number: $writes"
if grep -qF -- "milestones/9" <<<"$writes"; then fail "unlisted milestone must never be changed: $writes"; fi

set_github '[{"name":"area:core","color":"0e8a16","description":"Policy model"},
  {"name":"needs-triage","color":"ededed","description":"Not yet triaged"},
  {"name":"good first issue","color":"ededed","description":"x"}]' "$in_sync_milestones"
printf -- '- name: good first issue\n  color: "7057ff"\n  description: x\n' >>"$cfg/labels.yml"
run apply --repo o/r
expect_code 0 "--apply with nothing left over"
grep -qF -- "repos/o/r/labels/good%20first%20issue" "$FAKE_DIR/writes" \
  || fail "space in a label name is percent-encoded: $(cat "$FAKE_DIR/writes")"
cp "$work/good-labels.yml" "$cfg/labels.yml"

# A failing API call stops the run with exit 2.
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
run check --repo o/r
expect_code 2 "API error"

if [ "$failures" -ne 0 ]; then
  echo "$failures sync-labels test(s) failed"
  exit 1
fi
echo "sync-labels tests passed"
