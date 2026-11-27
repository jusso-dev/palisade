#!/bin/sh
# Regenerates the app package fixtures in this directory.
#
# Every package here is made from scratch, never copied from a vendor:
#
# 1. `tests/package.rs` builds the unsigned test package and bundle byte by
#    byte with `tests/common/appx.rs`, in the shape the OS packaging tool
#    writes (a ZIP archive with a schema-valid manifest, an executable, a
#    multi-block deflated file with a full flush after each block and an
#    empty final block, a block map with real block hashes and compressed
#    block sizes, and content types; a bundle holds two real packages,
#    stored, at the offsets its bundle manifest gives, and its block map
#    lists only the bundle manifest).
# 2. osslsigncode signs them with a throwaway key from a test-only CA that
#    nothing trusts. The signer's subject is the manifests' publisher, so
#    the publisher check passes; `other-publisher.msix` is signed by a
#    second signer whose subject is not.
#
# Files:
#   app.msix                the unsigned package.
#   app-signed.msix         signed (SHA-256, as its block map says).
#   bundle.msixbundle       the unsigned bundle.
#   bundle-signed.msixbundle  signed.
#   other-publisher.msix    the package signed by another publisher.
#   app-sha384.msix         the package signed with a SHA-384 signer
#                           digest (for nesting, in the tests).
#   app-desc(-unsigned).msix   the package with data descriptors, as
#                           packaging tools write it, and signed.
#   app-zip64(-unsigned).msix  the package with data descriptors and ZIP64
#                           records and extra fields, and signed.
#   ca.der                  the test root.
#
# Needs: openssl (3.x or later), osslsigncode (2.x), cargo. Run from
# anywhere:
#   sh crates/palisade-fileid/tests/fixtures/package/generate.sh
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

PALISADE_PACKAGE_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test package -- \
  --ignored --exact write_unsigned_packages --quiet
test -s app.msix && test -s bundle.msixbundle
cp app.msix bundle.msixbundle app-desc-unsigned.msix app-zip64-unsigned.msix "$out/"

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

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
openssl req -new -key ca.key -out ca.csr -subj "/CN=Palisade Test Package Root/O=Palisade Tests" 2>/dev/null
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt -days 3650 -extfile ca.cnf 2>/dev/null
openssl x509 -in ca.crt -outform DER -out "$out/ca.der"

# leaf NAME SUBJECT: a code-signing certificate issued by the root.
leaf() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$1.crt" -days 3650 -extfile leaf.cnf 2>/dev/null
  cat "$1.crt" ca.crt > "$1.chain"
}
# Encoded O then CN, so it renders as "CN=..., O=...", the manifests'
# publisher string.
leaf signer "/O=Palisade Tests/CN=Palisade Test Package Signer"
leaf other "/O=Palisade Tests/CN=Someone Else"

# sign SIGNER IN OUT
sign() {
  rm -f "$out/$3"
  osslsigncode sign -certs "$1.chain" -key "$1.key" -time 1700000000 \
    -in "$2" -out "$out/$3" >/dev/null
  osslsigncode verify -CAfile ca.crt -in "$out/$3" >/dev/null
}
sign signer app.msix app-signed.msix
sign signer bundle.msixbundle bundle-signed.msixbundle
sign other app.msix other-publisher.msix
# The same package signed again, with a SHA-384 signer digest. The tests
# nest each signature inside app-signed.msix's (osslsigncode does not nest
# on packages): other-publisher.msix gives a nested signer from another
# publisher, app-sha384.msix one from the same publisher.
rm -f "$out/app-sha384.msix"
osslsigncode sign -h sha384 -certs signer.chain -key signer.key -time 1700000000 \
  -in app.msix -out "$out/app-sha384.msix" >/dev/null
sign signer app-desc-unsigned.msix app-desc.msix
sign signer app-zip64-unsigned.msix app-zip64.msix

echo "package fixtures written to $out"
