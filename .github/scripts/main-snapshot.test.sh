#!/usr/bin/env bash
# Tests for main-snapshot.sh. Run: bash .github/scripts/main-snapshot.test.sh
# The GitHub CLI is replaced by a fake `gh` on PATH that keeps the release in
# files and records every call, so nothing touches the network.
set -uo pipefail

script="$(cd "$(dirname "$0")" && pwd)/main-snapshot.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# The fake gh. State: $FAKE/release (exists), $FAKE/tag (the tagged
# commit), $FAKE/assets (one name per line), $FAKE/notes; every call is
# appended to $FAKE/calls.
mkdir -p "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE/calls"
arg() { # value after flag $1 among the remaining arguments
  local want=$1; shift
  while [ "$#" -gt 0 ]; do [ "$1" = "$want" ] && { printf '%s' "$2"; return; }; shift; done
}
case "$1 $2" in
  "release view")
    [ -f "$FAKE/release" ] || exit 1
    case $* in *assets*) cat "$FAKE/assets" 2>/dev/null ;; *) echo '{"tagName":"main-snapshot"}' ;; esac ;;
  "release create")
    [ -f "$FAKE/tag" ] || { echo "tag missing" >&2; exit 1; }
    touch "$FAKE/release"; arg --notes "$@" >"$FAKE/notes" ;;
  "release edit")
    arg --notes "$@" >"$FAKE/notes" ;;
  "release upload")
    shift 3
    for a in "$@"; do
      case $a in --) continue ;; *.msi|*.msi.sha256|*.txt) n=${a##*/}
        grep -Fqx "$n" "$FAKE/assets" 2>/dev/null || echo "$n" >>"$FAKE/assets" ;;
      esac
    done ;;
  "release delete-asset")
    grep -Fvx "$4" "$FAKE/assets" >"$FAKE/assets.new"; mv "$FAKE/assets.new" "$FAKE/assets" ;;
  "api repos/o/r/git/ref/tags/main-snapshot")
    [ -f "$FAKE/tag" ] ;;
  "api -X")
    case $* in *PATCH*|*POST*) for a in "$@"; do case $a in sha=*) echo "${a#sha=}" >"$FAKE/tag" ;; esac; done ;; esac ;;
  *) echo "unexpected gh call: $*" >&2; exit 9 ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH" FAKE="$work/fake"
export GITHUB_REPOSITORY=o/r GITHUB_RUN_ID=7 GITHUB_SERVER_URL=https://example.test
sha1=1111111111111111111111111111111111111111
sha2=2222222222222222222222222222222222222222
mkdir -p "$FAKE" "$work/out"
for f in Palisade-0.1.0-x64.msi Palisade-0.1.0-x64.msi.sha256 Palisade-0.1.0-arm64.msi Palisade-0.1.0-arm64.msi.sha256 \
         Palisade-0.2.0-x64.msi Palisade-0.2.0-x64.msi.sha256 Palisade-0.2.0-arm64.msi Palisade-0.2.0-arm64.msi.sha256 other.txt; do
  echo "$f" >"$work/out/$f"
done
printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.1.0"\nedition = "2024"\n\n[profile.x]\nversion = "9.9.9"\n' >"$work/Cargo.toml"
export SNAPSHOT_MANIFEST="$work/Cargo.toml"
run() { "$script" "$@" >"$work/stdout" 2>"$work/stderr"; }

# First snapshot: the release and the tag are created.
GITHUB_SHA=$sha1 run prepare || fail "prepare: $(cat "$work/stderr")"
[ -f "$FAKE/release" ] || fail "prepare creates the release"
grep -q -- '--prerelease --latest=false' "$FAKE/calls" || fail "the release is a pre-release, never latest"
grep -q "Being updated to $sha1" "$FAKE/notes" || fail "prepare notes name the commit"
grep -q "not for production" "$FAKE/notes" || fail "notes warn the builds are not for production"
GITHUB_SHA=$sha1 run upload x64 "$work/out/Palisade-0.1.0-x64.msi" "$work/out/Palisade-0.1.0-x64.msi.sha256" || fail "upload x64"
GITHUB_SHA=$sha1 run upload arm64 "$work/out/Palisade-0.1.0-arm64.msi" "$work/out/Palisade-0.1.0-arm64.msi.sha256" || fail "upload arm64"
grep -q -- '--clobber' "$FAKE/calls" || fail "uploads replace files of the same name"
GITHUB_SHA=$sha1 run finish || fail "finish: $(cat "$work/stderr")"
[ "$(cat "$FAKE/tag")" = "$sha1" ] || fail "finish points the tag at the commit"
grep -q "Commit: $sha1" "$FAKE/notes" || fail "finish notes name the commit"
grep -q "Unsigned, untested" "$FAKE/notes" || fail "finish notes say unsigned and untested"
[ "$(wc -l <"$FAKE/assets" | tr -d ' ')" = 4 ] || fail "four files after the first snapshot"

# A new version: old files go, one release remains.
: >"$FAKE/calls"
sed -i.bak 's/^version = "0.1.0"$/version = "0.2.0"/' "$work/Cargo.toml"
GITHUB_SHA=$sha2 run prepare || fail "second prepare"
grep -q 'release create' "$FAKE/calls" && fail "the release is reused, not recreated"
GITHUB_SHA=$sha2 run upload x64 "$work/out/Palisade-0.2.0-x64.msi" "$work/out/Palisade-0.2.0-x64.msi.sha256" || fail "second upload x64"
GITHUB_SHA=$sha2 run upload arm64 "$work/out/Palisade-0.2.0-arm64.msi" "$work/out/Palisade-0.2.0-arm64.msi.sha256" || fail "second upload arm64"
GITHUB_SHA=$sha2 run finish || fail "second finish: $(cat "$work/stderr")"
[ "$(cat "$FAKE/tag")" = "$sha2" ] || fail "the tag moves to the new commit"
[ "$(sort "$FAKE/assets" | tr '\n' ' ')" = "Palisade-0.2.0-arm64.msi Palisade-0.2.0-arm64.msi.sha256 Palisade-0.2.0-x64.msi Palisade-0.2.0-x64.msi.sha256 " ] \
  || fail "only the new version's files remain: $(tr '\n' ' ' <"$FAKE/assets")"

# A missing architecture fails finish, before the tag moves or files go.
grep -Fvx Palisade-0.2.0-arm64.msi "$FAKE/assets" >"$FAKE/a" && mv "$FAKE/a" "$FAKE/assets"
sha3=3333333333333333333333333333333333333333
before=$(sort "$FAKE/assets")
GITHUB_SHA=$sha3 run finish && fail "finish fails when a package is missing"
grep -q "arm64.msi was not uploaded" "$work/stderr" || fail "the error names the missing package"
[ "$(cat "$FAKE/tag")" = "$sha2" ] || fail "a failed finish leaves the tag where it was"
[ "$(sort "$FAKE/assets")" = "$before" ] || fail "a failed finish removes no files"

# Refused input.
GITHUB_SHA=$sha2 run upload x64 "$work/out/other.txt" && fail "only packages and checksums are uploaded"
GITHUB_SHA=$sha2 run upload x64 "$work/out/Palisade-0.2.0-arm64.msi" && fail "files must match the architecture"
GITHUB_SHA=$sha2 run upload x86 "$work/out/Palisade-0.2.0-x64.msi" && fail "unknown architectures are refused"
GITHUB_SHA=$sha2 run upload x64 "$work/out/missing.msi" && fail "missing files are refused"
GITHUB_SHA=nothex run prepare && fail "a bad commit is refused"
GITHUB_SHA=abc run prepare && fail "a short commit is refused"
GITHUB_SHA=$sha2 run bogus && fail "unknown commands are refused"
[ "$?" -ne 0 ] || true
GITHUB_SHA=$sha2 "$script" bogus >/dev/null 2>&1
[ "$?" -eq 2 ] || fail "usage errors exit 2"

if [ "$failures" -gt 0 ]; then
  echo "$failures failure(s)"
  exit 1
fi
echo "main-snapshot.sh: all tests passed"
