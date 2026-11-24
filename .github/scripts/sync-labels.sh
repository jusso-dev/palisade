#!/usr/bin/env bash
# Makes the repository's labels and milestones match .github/labels.yml and
# .github/milestones.yml. See docs/repo-settings.md#labels-and-milestones.
#
# Usage:
#   sync-labels.sh --validate                  check the two files, and that the
#                                              issue templates and Dependabot use
#                                              listed labels only; no network
#   sync-labels.sh --check --repo OWNER/NAME   dry run: print every change that
#                                              --apply would make
#   sync-labels.sh --apply --repo OWNER/NAME   make those changes
# Options: --labels FILE, --milestones FILE, --templates DIR and
# --dependabot FILE replace the default paths (used by the tests).
# --repo defaults to $GITHUB_REPOSITORY.
#
# Labels: missing ones are created, colours and descriptions are updated, and
# labels that are not listed are DELETED (GitHub removes them from every issue).
# Milestones: matched by title, open or closed. Missing ones are created and
# descriptions are updated. An open milestone that is not listed is reported and
# fails the run; nothing is ever deleted or closed. Closed unlisted milestones
# (finished, retired work) are ignored.
#
# Exit codes: 0 in sync (or --validate passed, or --apply finished with nothing
# left over), 1 drift found (--check) or unlisted milestones remain (--apply),
# 2 usage, configuration or API error.
# Needs bash, jq and yq v4 (mikefarah); --check and --apply also need an
# authenticated gh CLI. GitHub-hosted Ubuntu runners have all four.
set -euo pipefail
export LC_ALL=C

here=$(cd "$(dirname "$0")" && pwd)
labels_file="$here/../labels.yml"
milestones_file="$here/../milestones.yml"
templates_dir="$here/../ISSUE_TEMPLATE"
dependabot_file="$here/../dependabot.yml"
mode=""
repo=${GITHUB_REPOSITORY:-}

die() { echo "sync-labels: $*" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
  case $1 in
    --validate|--check|--apply)
      [ -z "$mode" ] || die "give only one of --validate, --check, --apply"
      mode=${1#--} ;;
    --repo) [ "$#" -ge 2 ] || die "--repo needs a value"; repo=$2; shift ;;
    --labels) [ "$#" -ge 2 ] || die "--labels needs a value"; labels_file=$2; shift ;;
    --milestones) [ "$#" -ge 2 ] || die "--milestones needs a value"; milestones_file=$2; shift ;;
    --templates) [ "$#" -ge 2 ] || die "--templates needs a value"; templates_dir=$2; shift ;;
    --dependabot) [ "$#" -ge 2 ] || die "--dependabot needs a value"; dependabot_file=$2; shift ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done
[ -n "$mode" ] || die "give one of --validate, --check, --apply (see --help)"
for tool in jq yq; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

# Reads a single-document YAML file as compact JSON.
yaml_json() {
  local docs
  [ -f "$1" ] || die "no such file: $1"
  docs=$(yq ea '[.] | length' "$1") || die "cannot parse $1"
  [ "$docs" = 1 ] || die "$1 must hold exactly one YAML document"
  yq -o=json -I=0 '.' "$1" || die "cannot parse $1"
}

want_labels=$(yaml_json "$labels_file")
want_milestones=$(yaml_json "$milestones_file")

# Validation. Each jq program prints one line per problem.
problems=$(jq -r '
  if type != "array" then "labels file: must be a list" else
    (to_entries[] | .key as $i | .value |
      if type != "object" then "label \($i + 1): must be a mapping" else
        (keys - ["name", "color", "description"] | .[] | "label \($i + 1): unknown key `\(.)`"),
        (if (.name | type) != "string" or .name == "" then "label \($i + 1): `name` must be a non-empty string"
          elif (.name | length) > 50 then "label \($i + 1): `name` is longer than 50 characters"
          else empty end),
        (if (.color | type) != "string" or (.color | test("^[0-9a-f]{6}$") | not)
          then "label \($i + 1): `color` must be a quoted string of 6 lowercase hex digits" else empty end),
        (if (.description | type) != "string" then "label \($i + 1): `description` must be a string"
          elif (.description | length) > 100 then "label \($i + 1): `description` is longer than 100 characters"
          else empty end),
        (if [.name, .description] | map(strings | test("[[:cntrl:]]")) | any
          then "label \($i + 1): `name` and `description` must not contain control characters" else empty end)
      end),
    (map(select(type == "object" and (.name | type) == "string") | .name | ascii_downcase)
      | group_by(.) | map(select(length > 1) | .[0]) | .[] | "label `\(.)` is listed more than once")
  end' <<<"$want_labels")
problems+=$'\n'$(jq -r '
  if type != "array" then "milestones file: must be a list" else
    (to_entries[] | .key as $i | .value |
      if type != "object" then "milestone \($i + 1): must be a mapping" else
        (keys - ["title", "description"] | .[] | "milestone \($i + 1): unknown key `\(.)`"),
        (if (.title | type) != "string" or .title == "" then "milestone \($i + 1): `title` must be a non-empty string" else empty end),
        (if (.description | type) != "string" then "milestone \($i + 1): `description` must be a string" else empty end),
        (if [.title, .description] | map(strings | test("[[:cntrl:]]")) | any
          then "milestone \($i + 1): `title` and `description` must not contain control characters" else empty end)
      end),
    (map(select(type == "object") | .title) | group_by(.) | map(select(length > 1) | .[0]) | .[]
      | "milestone `\(.)` is listed more than once")
  end' <<<"$want_milestones")

# Issue templates and Dependabot may only apply labels that are listed, or
# the sync would delete the label they rely on.
# This runs in every mode, so a local --apply cannot delete a label that a
# template still uses.
# Prints a problem for each label in $2 (a JSON list, or a comma-separated
# string as issue forms allow) that is not listed.
unlisted() {
  jq -r --arg where "$1" --argjson want "$want_labels" '
    ([$want | arrays | .[] | objects | .name]) as $names
    | (if type == "string" then split(",") | map(gsub("^ +| +$"; ""))
       elif type == "array" then . else ["<not a list>"] end)
    | .[] | select(type != "string" or (. as $l | $names | index($l) | not))
    | "\($where): applies label `\(.)`, which is not in the labels file"' <<<"$2"
}
if [ -d "$templates_dir" ]; then
  for template in "$templates_dir"/*.yml "$templates_dir"/*.yaml; do
    [ -f "$template" ] || continue
    case $(basename "$template") in config.yml|config.yaml) continue ;; esac
    used=$(yq -o=json -I=0 '.labels // []' "$template") || die "cannot parse $template"
    problems+=$'\n'$(unlisted "$(basename "$template")" "$used")
  done
fi
if [ -f "$dependabot_file" ]; then
  used=$(yq -o=json -I=0 '[.updates[] | .labels // ["dependencies"] | .[]] | unique' "$dependabot_file") \
    || die "cannot parse $dependabot_file"
  problems+=$'\n'$(unlisted "$(basename "$dependabot_file")" "$used")
fi

problems=$(sed '/^$/d' <<<"$problems")
if [ -n "$problems" ]; then
  echo "$problems" >&2
  exit 2
fi
if [ "$mode" = validate ]; then
  echo "labels and milestones files are valid"
  exit 0
fi

[ -n "$repo" ] || die "--repo OWNER/NAME is required (or set GITHUB_REPOSITORY)"
# Owner: letters, digits and hyphens. Name: also `.` and `_`, but not `.` or `..`.
if ! [[ "$repo" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$ ]] || [[ "${repo#*/}" =~ ^\.+$ ]]; then
  die "bad --repo: $repo"
fi
command -v gh >/dev/null || die "gh is required"

# Fetches every page of a list endpoint as one JSON array.
fetch() {
  local out
  out=$(gh api --paginate "repos/$repo/$1") || die "GET repos/$repo/$1 failed"
  jq -c -s 'add // []' <<<"$out" || die "unexpected response from repos/$repo/$1"
}

have_labels=$(fetch "labels?per_page=100")
have_milestones=$(fetch "milestones?state=all&per_page=100")

# The plan: one compact JSON object per change. GitHub label names are
# case-insensitive, so labels are matched ignoring case and a case change is an
# update. Colours are compared in lowercase.
plan=$(jq -c -n --argjson want "$want_labels" --argjson have "$have_labels" '
  ($have | map({key: (.name | ascii_downcase), value: .}) | from_entries) as $h
  | ($want | map(.name | ascii_downcase)) as $listed
  | ($want[] | . as $w | $h[.name | ascii_downcase] as $cur
      | if $cur == null then {op: "create-label"} + $w
        elif $cur.name != $w.name or ($cur.color | ascii_downcase) != $w.color
             or ($cur.description // "") != $w.description
          then {op: "update-label", current: $cur.name} + $w
        else empty end),
    ($have[] | select((.name | ascii_downcase) as $n | $listed | index($n) | not)
      | {op: "delete-label", name})')
plan+=$'\n'$(jq -c -n --argjson want "$want_milestones" --argjson have "$have_milestones" '
  ($have | map({key: .title, value: .}) | from_entries) as $h
  | ($want[] | . as $w | $h[.title] as $cur
      | if $cur == null then {op: "create-milestone"} + $w
        elif ($cur.description // "") != $w.description
          then {op: "update-milestone", number: $cur.number} + $w
        else empty end),
    ($have[] | select(.state != "closed" and (.title as $t | $want | map(.title) | index($t) | not))
      | {op: "unlisted-milestone", title, number})')
plan=$(sed '/^$/d' <<<"$plan")

if [ -z "$plan" ]; then
  echo "labels and milestones in $repo match the files"
  exit 0
fi

label_path() { printf 'repos/%s/labels/%s' "$repo" "$(jq -rn --arg n "$1" '$n | @uri')"; }

# Makes one API call in --apply mode; in --check mode it does nothing.
call() {
  if [ "$mode" = apply ]; then
    gh api "$@" --silent || die "API call failed: gh api $*"
  fi
}

leftover=0
while IFS= read -r change; do
  field() { jq -r --arg k "$1" '.[$k]' <<<"$change"; }
  case $(field op) in
    create-label)
      echo "create label: $(field name) (#$(field color), \"$(field description)\")"
      call -X POST "repos/$repo/labels" \
        -f name="$(field name)" -f color="$(field color)" -f description="$(field description)" ;;
    update-label)
      echo "update label: $(field current) -> $(field name) (#$(field color), \"$(field description)\")"
      call -X PATCH "$(label_path "$(field current)")" \
        -f new_name="$(field name)" -f color="$(field color)" -f description="$(field description)" ;;
    delete-label)
      echo "DELETE label: $(field name) (not in the labels file; removed from every issue)"
      call -X DELETE "$(label_path "$(field name)")" ;;
    create-milestone)
      echo "create milestone: $(field title) (\"$(field description)\")"
      call -X POST "repos/$repo/milestones" -f title="$(field title)" -f description="$(field description)" ;;
    update-milestone)
      echo "update milestone: $(field title) (\"$(field description)\")"
      call -X PATCH "repos/$repo/milestones/$(field number)" -f description="$(field description)" ;;
    unlisted-milestone)
      echo "unlisted milestone: $(field title) (#$(field number)); add it to the milestones file or close it by hand" >&2
      leftover=1 ;;
    *) die "internal error: unknown change: $change" ;;
  esac
done <<<"$plan"

if [ "$mode" = check ]; then
  echo "drift found: run with --apply to make these changes" >&2
  exit 1
fi
exit "$leftover"
