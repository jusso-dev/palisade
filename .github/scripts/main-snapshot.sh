#!/usr/bin/env bash
# Maintains the rolling `main-snapshot` pre-release: the unsigned Windows
# packages of the latest main commit whose CI passed (#22). Run by the
# snapshot jobs in ci.yml, on pushes to main only. See docs/ci.md#main-snapshot.
#
# Usage:
#   main-snapshot.sh prepare                 create the release if needed and
#                                            mark it as being updated
#   main-snapshot.sh upload <arch> <file>... upload files, replacing any with
#                                            the same name
#   main-snapshot.sh finish                  point the tag at this commit, drop
#                                            files from older versions, and
#                                            write the notes
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
  printf '%s\n\nCommit: %s\nBuilt by: %s\n\nEach `.msi` has a `.msi.sha256` file with its SHA-256 checksum.\n' \
    "$warning" "$sha" "$run_url"
}

release_exists() {
  gh release view "$tag" --repo "$repo" --json tagName >/dev/null 2>&1
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
    gh release upload "$tag" --repo "$repo" --clobber -- "$@"
    echo "main-snapshot: uploaded $# file(s) for $arch"
    ;;
  finish)
    [ "$#" -eq 1 ] || die "finish takes no arguments"
    # This commit's version, from the workspace manifest the packages were
    # built from. Files of any other version are from an older snapshot.
    current=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version = "\([^"]*\)"$/\1/p' "$manifest" | head -n 1)
    case $current in
      ''|*[!0-9A-Za-z.+-]*) die "cannot read workspace.package.version from $manifest" ;;
    esac
    names=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[].name')
    # Every file must be there before anything changes: a failed upload
    # leaves the tag and the previous files alone.
    for want in x64.msi x64.msi.sha256 arm64.msi arm64.msi.sha256; do
      printf '%s\n' "$names" | grep -Fqx "Palisade-$current-$want" \
        || die "Palisade-$current-$want was not uploaded"
    done
    move_tag
    printf '%s\n' "$names" | while IFS= read -r name; do
      case $name in
        ''|"Palisade-$current-x64.msi"|"Palisade-$current-x64.msi.sha256"|"Palisade-$current-arm64.msi"|"Palisade-$current-arm64.msi.sha256") ;;
        *) gh release delete-asset "$tag" "$name" --repo "$repo" --yes >/dev/null
           echo "main-snapshot: removed $name" ;;
      esac
    done
    gh release edit "$tag" --repo "$repo" --prerelease --latest=false \
      --notes "$(notes_done)" >/dev/null
    echo "main-snapshot: $tag is $current at $sha"
    ;;
  -h|--help) sed -n '2,17p' "$0" ;;
  *) die "usage: main-snapshot.sh prepare | upload <arch> <file>... | finish" ;;
esac
