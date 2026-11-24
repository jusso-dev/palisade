#!/bin/sh
# Regenerates the page hash signature fixtures in this directory (#47).
#
# Each fixture is a PKCS#7 SignedData (DER) with a page hash table, made by
# osslsigncode (`-ph`) over one of the synthetic images that
# `fixture_images()` in tests/page_hash.rs builds. Only the signatures are
# committed, never a PE file: the tests rebuild each image and attach the
# signature. The signer key and certificate are throwaway test material,
# made here by a test-only CA and trusted by nothing; the private key is
# deleted on exit.
#
# osslsigncode writes a SHA-1 (version 1) table with `-h sha1` and a SHA-256
# (version 2) table with `-h sha256`.
#
# Needs: openssl (3.x), osslsigncode (2.x), cargo. Run from anywhere:
#   sh crates/palisade-fileid/tests/fixtures/page_hash/generate.sh
#
# Keys and serials are random, so a rerun changes every file; the tests
# depend only on the page hash tables, which are a function of the images.
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_PAGE_HASH_IMAGES="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test page_hash -- \
  --ignored --exact write_page_hash_images --quiet
for image in default multi pe32; do test -s "$image.exe"; done

cat > leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
CNF
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=Palisade Test Root/O=Palisade Tests" -days 3650 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signer.key 2>/dev/null
openssl req -new -key signer.key -out signer.csr \
  -subj "/CN=Palisade Test Signer page-hash/O=Palisade Tests" 2>/dev/null
openssl x509 -req -in signer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out signer.crt -days 3650 -extfile leaf.cnf 2>/dev/null
cat signer.crt ca.crt > signer.chain

# sign IMAGE DIGEST: signs IMAGE.exe with page hashes, writes IMAGE-DIGEST.p7.
sign() {
  osslsigncode sign -certs signer.chain -key signer.key -time 1700000000 \
    -h "$2" -ph -in "$1.exe" -out "$1-$2.signed.exe" >/dev/null
  osslsigncode verify -CAfile ca.crt -in "$1-$2.signed.exe" >/dev/null
  rm -f "$out/$1-$2.p7"
  osslsigncode extract-signature -in "$1-$2.signed.exe" -out "$out/$1-$2.p7" >/dev/null
}

sign default sha1
sign multi sha256
sign multi sha1
sign pe32 sha256

ls -l "$out"
