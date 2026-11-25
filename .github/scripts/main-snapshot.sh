#!/usr/bin/env bash
# Maintains the rolling `main-snapshot` pre-release: the unsigned Windows
# packages of the latest main commit whose CI passed (#22). Run by the
# snapshot jobs in ci.yml, on pushes to main only. See docs/ci.md#main-snapshot.
#
# Usage:
#   main-snapshot.sh prepare                 create the release if needed and
#                                            mark it as being updated
#   main-snapshot.sh upload <arch> <file>... upload files as <commit>.<name>
#   main-snapshot.sh finish                  if main still points at this commit
#                                            and its set is complete: move the
#                                            tag, drop older sets, write notes
#
# `finish` reads the version from Cargo.toml in the current directory (or
# $SNAPSHOT_MANIFEST). Reads GITHUB_REPOSITORY, GITHUB_SHA, GITHUB_SERVER_URL and GITHUB_RUN_ID, as
# set on Actions runners, and needs gh authenticated with contents: write.
# Exit codes: 0 done, 2 usage or API error.
set -euo pipefail
export LC_ALL=C

tag=main-snapshot
manifest=${SNAPSHOT_MANIFEST:-Cargo.toml}
die() { echo "main-snapshot: $*" >&2; exit 2; }

repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
sha=${GITHUB_SHA:?GITHUB_SHA is not set}
server=${GITHUB_SERVER_URL:-https://github.com}
run_url="$server/$repo/actions/runs/${GITHUB_RUN_ID:-0}"
case $sha in
  *[!0-9a-f]*|'') die "GITHUB_SHA is not a commit hash" ;;
esac
[ "${#sha}" -eq 40 ] || die "GITHUB_SHA is not a full commit hash"

warning="Unsigned, untested snapshot builds of the main branch. They are not releases and are not for production use: they change with every push, carry no signature, and are replaced without notice. Palisade is an educational, personal-development project."

notes_updating() {
  printf '%s\n\nBeing updated to %s by %s.\n' "$warning" "$sha" "$run_url"
}

notes_done() {
  printf '%s\n\nCommit: %s\nBuilt by: %s\n\nEach file name starts with the first 12 characters of the commit. Each `.msi` has a `.msi.sha256` file with its SHA-256 checksum.\n' \
    "$warning" "$sha" "$run_url"
}

# 0 if the release exists, 1 if GitHub says it does not, and the script
# stops on any other failure, so an API error never looks like "absent".
release_exists() {
  local out
  if out=$(gh api "repos/$repo/releases/tags/$tag" 2>&1 >/dev/null); then
    return 0
  fi
  case $out in
    *"HTTP 404"*|*"Not Found"*) return 1 ;;
    *) die "cannot look up the $tag release: $out" ;;
  esac
}

# Every file is published under this commit's prefix, so no upload ever
# replaces another commit's file, and the previous set stays published
# until this one is complete.
stage="${sha:0:12}."

# The commit main points at now; a re-run of an older run must not
# publish over a newer one.
main_head() {
  gh api "repos/$repo/git/ref/heads/main" --jq .object.sha
}

# Points the tag at $sha, creating it if needed. A lightweight tag, moved
# by the API; tags pushed with the workflow token start no workflows.
move_tag() {
  if gh api "repos/$repo/git/ref/tags/$tag" >/dev/null 2>&1; then
    gh api -X PATCH "repos/$repo/git/refs/tags/$tag" -f sha="$sha" -F force=true >/dev/null
  else
    gh api -X POST "repos/$repo/git/refs" -f ref="refs/tags/$tag" -f sha="$sha" >/dev/null
  fi
}

case ${1:-} in
  prepare)
    [ "$#" -eq 1 ] || die "prepare takes no arguments"
    if release_exists; then
      gh release edit "$tag" --repo "$repo" --prerelease --latest=false \
        --notes "$(notes_updating)" >/dev/null
    else
      move_tag
      gh release create "$tag" --repo "$repo" --verify-tag --prerelease --latest=false \
        --title "main snapshot (unsigned, not for production)" \
        --notes "$(notes_updating)" >/dev/null
    fi
    echo "main-snapshot: prepared for $sha"
    ;;
  upload)
    [ "$#" -ge 3 ] || die "upload needs an architecture and at least one file"
    arch=$2
    shift 2
    case $arch in x64|arm64) ;; *) die "unknown architecture: $arch" ;; esac
    for file in "$@"; do
      [ -f "$file" ] || die "no such file: $file"
      case ${file##*/} in
        Palisade-*-"$arch".msi|Palisade-*-"$arch".msi.sha256) ;;
        *) die "not a $arch package or checksum: $file" ;;
      esac
    done
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    staged=()
    for file in "$@"; do
      cp "$file" "$dir/$stage${file##*/}"
      staged+=("$dir/$stage${file##*/}")
    done
    gh release upload "$tag" --repo "$repo" --clobber -- "${staged[@]}"
    echo "main-snapshot: uploaded $# file(s) for $arch"
    ;;
  finish)
    [ "$#" -eq 1 ] || die "finish takes no arguments"
    # This commit's version, from the workspace manifest the packages were
    # built from.
    current=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1)
    case $current in
      ''|*[!0-9A-Za-z.+-]*) die "cannot read workspace.package.version from $manifest" ;;
    esac
    # A re-run of an older run's job keeps that run's commit; it must not
    # publish over a newer snapshot.
    [ "$(main_head)" = "$sha" ] || die "main has moved on from $sha; a newer run publishes the snapshot"
    names=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')
    # This commit's whole set must be there before anything changes: a
    # failed upload leaves the tag and the previous set alone.
    keep=()
    for want in x64.msi x64.msi.sha256 arm64.msi arm64.msi.sha256; do
      printf '%s\n' "$names" | grep -Fqx "${stage}Palisade-$current-$want" \
        || die "Palisade-$current-$want was not uploaded for $sha"
      keep+=("${stage}Palisade-$current-$want")
    done
    move_tag
    printf '%s\n' "$names" | while IFS= read -r name; do
      [ -n "$name" ] || continue
      case " ${keep[*]} " in *" $name "*) continue ;; esac
      gh release delete-asset "$tag" "$name" --repo "$repo" --yes >/dev/null
      echo "main-snapshot: removed $name"
    done
    gh release edit "$tag" --repo "$repo" --prerelease --latest=false \
      --notes "$(notes_done)" >/dev/null
    echo "main-snapshot: $tag is $current at $sha"
    ;;
  -h|--help) sed -n '2,17p' "$0" ;;
  *) die "usage: main-snapshot.sh prepare | upload <arch> <file>... | finish" ;;
esac
