#!/bin/sh
# Regenerates the catalog fixtures in this directory.
#
# Every catalog here is made from scratch, never copied from an OS:
#
# 1. `tests/catalog.rs` builds each unsigned catalog byte by byte (a
#    SignedData with no signer around a certificate trust list), the way a
#    catalog tool writes one before signing. Its members are the synthetic
#    PE image `PeBuilder::default()` from `tests/common` (by its
#    Authenticode hash) and a short text file (by its flat hash), both
#    built by the tests, so no member file is committed either.
# 2. osslsigncode signs each one with throwaway keys made here, by two
#    test-only CAs that nothing trusts.
#
# Files:
#   v1-sha1.cat     v1 catalog: SHA-1 member digests, SHA-1 signature.
#   v2-sha256.cat   v2 catalog: SHA-256 member digests and signature.
#   org-sha256.cat  An organisation catalog: v2, signed under org-ca.
#   ca.der          Root of the catalog signer of v1 and v2.
#   org-ca.der      Root of the organisation catalog signer.
#
# The tests check that each catalog signs exactly the trust list the
# builder makes (`fixture_ctls_are_the_builder_output`).
#
# Needs: openssl (3.x or later), osslsigncode (2.x), cargo. Run from
# anywhere:
#   sh crates/palisade-fileid/tests/fixtures/catalog/generate.sh
#
# Keys and serials are random, so a rerun changes every signed file; the
# tests depend only on their structure and validity. No private key is
# kept.
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_CATALOG_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test catalog -- \
  --ignored --exact write_unsigned_catalogs --quiet
for n in v1-sha1 v2-sha256 org-sha256; do test -s "$n.unsigned.cat"; done

cat > ca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CNF
cat > leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF

# ca NAME SUBJECT: a self-signed test root.
ca() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -signkey "$1.key" -out "$1.crt" -days 3650 \
    -extfile ca.cnf 2>/dev/null
  openssl x509 -in "$1.crt" -outform DER -out "$out/$1.der"
}

# leaf NAME CA SUBJECT: a code-signing certificate issued by CA, and
# NAME.chain = leaf + CA.
leaf() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$3" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -out "$1.crt" -days 3650 -extfile leaf.cnf 2>/dev/null
  cat "$1.crt" "$2.crt" > "$1.chain"
}

ca ca "/CN=Palisade Test Catalog Root/O=Palisade Tests"
ca org-ca "/CN=Palisade Test Organisation Root/O=Palisade Tests"
leaf signer ca "/CN=Palisade Test Catalog Signer/O=Palisade Tests"
leaf org-signer org-ca "/CN=Palisade Test Organisation Signer/O=Palisade Tests"

# sign NAME CHAIN KEY DIGEST: signs NAME.unsigned.cat into NAME.cat.
sign() {
  rm -f "$out/$1.cat"
  osslsigncode sign -certs "$2" -key "$3" -h "$4" -time 1700000000 \
    -in "$1.unsigned.cat" -out "$out/$1.cat" >/dev/null
}

sign v1-sha1 signer.chain signer.key sha1
sign v2-sha256 signer.chain signer.key sha256
sign org-sha256 org-signer.chain org-signer.key sha256

echo "catalog fixtures written to $out"
