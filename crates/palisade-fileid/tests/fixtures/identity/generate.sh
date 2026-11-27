#!/bin/sh
# Checks the generated files of the file identity corpus (#55) with tools
# independent of palisade-fileid, and prints their digests for
# manifest.yaml.
#
# Nothing signed is committed (docs/testing.md#fixtures). The corpus files
# are built at test time: `fixtures/identity/signed.rs` signs the synthetic
# images with the fixture corpus's pure-Rust signer, whose RSA keys come
# from a deterministic RNG, so every run makes the same bytes. This script
# makes sure those bytes are what they claim to be, without trusting this
# crate:
#
# 1. `tests/identity_corpus.rs` writes every synthetic and generated file
#    (`write_corpus_files`) to a temporary directory.
# 2. osslsigncode verifies the good signatures against the corpus CA, and
#    must refuse the tampered, revoked (with the corpus CRL) and rogue ones.
# 3. The digests are computed by tools independent of palisade-fileid:
#    shasum for the flat hashes, osslsigncode `extract-data` for the
#    Authenticode SHA-256, openssl for the signer thumbprints.
#
# manifest.yaml holds the printed digests; `corpus_matches_the_manifest`
# fails if a file stops matching them, so a change to the signer or the
# builder that changes a byte shows up there, and this script is rerun to
# check the new bytes independently before the manifest is updated.
#
# Needs: openssl (3.x or later), osslsigncode (2.7 or later), shasum,
# cargo. Run from anywhere:
#   sh crates/palisade-fileid/tests/fixtures/identity/generate.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_CORPUS_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test identity_corpus -- \
  --ignored --exact write_corpus_files --quiet
test -s unsigned/plain.bin && test -s signed-tool.exe

openssl x509 -inform DER -in ca.der -out ca.crt
openssl crl -inform DER -in ca-2025-2027.crl -out ca.crl

# Signatures the corpus says are good: osslsigncode must verify them.
# The OS signer names a CRL distribution point that is never fetched: the
# corpus CRL is given instead.
for f in signed-tool signed-tool-v2 signed-powershell sha1-signed-tool; do
  osslsigncode verify -CAfile ca.crt -CRLfile ca.crl -in "$f.exe" >/dev/null
done
# And refuse these: changed after signing, revoked, and self-signed.
refuse() {
  if osslsigncode verify "$@" >/dev/null 2>&1; then
    echo "osslsigncode accepted $*" >&2
    exit 1
  fi
}
refuse -CAfile ca.crt -in tampered-tool.exe
refuse -CAfile ca.crt -CRLfile ca.crl -in revoked-signed-tool.exe
refuse -CAfile ca.crt -in rogue-signed.exe

# The independent digests.
authenticode() {
  rm -f ad.der
  osslsigncode extract-data -h sha256 -in "$1" -out ad.der >/dev/null 2>&1 || { echo "-"; return; }
  openssl asn1parse -inform DER -in ad.der | awk -F: '/OCTET STRING/ {v=$NF} END {print tolower(v)}'
}
echo "# file sha256 sha1 md5 authenticode_sha256"
for f in unsigned/*.bin ./*.exe ./*.cat; do
  printf '%s %s %s %s %s\n' "$(basename "$f")" \
    "$(shasum -a 256 "$f" | cut -d' ' -f1)" \
    "$(shasum -a 1 "$f" | cut -d' ' -f1)" \
    "$(openssl dgst -md5 -r "$f" | cut -d' ' -f1)" \
    "$(authenticode "$f")"
done
# Signer certificate thumbprints, from the signatures themselves.
for f in signed-tool signed-powershell; do
  osslsigncode extract-signature -in "$f.exe" -out "$f.p7" >/dev/null
  openssl pkcs7 -inform DER -in "$f.p7" -print_certs 2>/dev/null |
    awk '/BEGIN CERT/{n++} n==1' > "$f.leaf.pem"
  printf '%s signer sha1 thumbprint: %s\n' "$f" \
    "$(openssl x509 -in "$f.leaf.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')"
done
echo "corpus files checked"
