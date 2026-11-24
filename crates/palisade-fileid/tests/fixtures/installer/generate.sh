#!/bin/sh
# Regenerates the installer package fixtures in this directory.
#
# Every package here is made from scratch, never copied from a vendor:
#
# 1. `tests/installer.rs` builds the unsigned test product byte by byte
#    with `tests/common/msi.rs` (a compound file with a string pool,
#    `_Tables`, `_Columns`, `Property`, `Binary`, `CustomAction`, `Media`,
#    an embedded cabinet stream and summary information).
# 2. osslsigncode signs it with a throwaway key from a test-only CA that
#    nothing trusts.
# 3. `normalised.py` computes the package's normalised hash independently
#    of the crate, from the unsigned package, into
#    product.normalised.txt.
#
# Files:
#   product.msi         the unsigned test product (the Windows test signs
#                       it with the OS signing cmdlet at test time).
#   product-sha256.msi  signed with SHA-256.
#   product-sha1.msi    signed with SHA-1.
#   product-dse.msi     signed with SHA-256 and MsiDigitalSignatureEx
#                       (the metadata hash).
#   ca.der              the test root.
#   product.normalised.txt  the normalised SHA-256 of the product.
#
# Needs: openssl (3.x or later), osslsigncode (2.16 or later, which hashes
# MsiDigitalSignatureEx at its sorted position), python3, cargo. Run from
# anywhere:
#   sh crates/palisade-fileid/tests/fixtures/installer/generate.sh
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

PALISADE_INSTALLER_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test installer -- \
  --ignored --exact write_unsigned_installers --quiet
test -s product.msi

cp product.msi "$out/product.msi"
python3 -I "$out/normalised.py" product.msi > "$out/product.normalised.txt"

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
openssl req -new -key ca.key -out ca.csr -subj "/CN=Palisade Test Installer Root/O=Palisade Tests" 2>/dev/null
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt -days 3650 -extfile ca.cnf 2>/dev/null
openssl x509 -in ca.crt -outform DER -out "$out/ca.der"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signer.key 2>/dev/null
openssl req -new -key signer.key -out signer.csr -subj "/CN=Palisade Test Installer Signer/O=Palisade Tests" 2>/dev/null
openssl x509 -req -in signer.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out signer.crt -days 3650 -extfile leaf.cnf 2>/dev/null
cat signer.crt ca.crt > signer.chain

# sign OUT DIGEST [EXTRA]: signs product.msi into OUT.
sign() {
  name=$1 digest=$2
  shift 2
  rm -f "$out/$name"
  osslsigncode sign -certs signer.chain -key signer.key -h "$digest" -time 1700000000 \
    "$@" -in product.msi -out "$out/$name" >/dev/null
  osslsigncode verify -CAfile ca.crt -in "$out/$name" >/dev/null
}

sign product-sha256.msi sha256
sign product-sha1.msi sha1
sign product-dse.msi sha256 -add-msi-dse

echo "installer fixtures written to $out"
