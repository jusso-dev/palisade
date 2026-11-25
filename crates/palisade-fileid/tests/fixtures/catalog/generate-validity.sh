#!/bin/sh
# Regenerates the catalog validity fixtures in this directory (#50, #51):
# the v2 trust list of `v2-sha256.cat` (from `write_unsigned_catalogs` in
# tests/catalog.rs), signed by a signer whose certificate has expired, with
# and without an RFC 3161 timestamp. Dates are fixed, so the tests can judge
# them against any "now" they choose. Throwaway test CAs, trusted by
# nothing; no private key is kept. (generate.sh makes the other fixtures.)
#
#   validity-root.der   Palisade Catalog Validity Root  2018-01-01 .. 2045-01-01
#   validity-tsa-root.der  Palisade Catalog TSA Root    2018-01-01 .. 2045-01-01
#   v2-expired-timestamped.cat  signer valid 2020-01-01 .. 2022-01-01, signed
#                       with SHA-256 and timestamped at 2021-01-01 by a TSA
#                       (Time Stamping EKU, 2019 .. 2040) under the TSA root
#   v2-expired.cat      the same signer, no timestamp
#
# Needs: openssl 3.4 or later, osslsigncode (2.x), cargo.
#   sh crates/palisade-fileid/tests/fixtures/catalog/generate-validity.sh
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_CATALOG_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test catalog -- \
  --ignored --exact write_unsigned_catalogs --quiet
test -s v2-sha256.unsigned.cat

cat > leaf.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > tsa.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF

rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null; }
root() {
  openssl req -x509 -new -key "$1.key" -subj "$2" -sha256 \
    -not_before 20180101000000Z -not_after 20450101000000Z \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -addext subjectKeyIdentifier=hash -out "$1.pem" 2>/dev/null
}
# issue NAME SUBJECT CA EXTFILE SERIAL FROM TO
issue() {
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -set_serial "0x$5" \
    -not_before "$6" -not_after "$7" -sha256 -extfile "$4" -out "$1.pem" 2>/dev/null
}

rsa root; root root "/O=Palisade Tests/CN=Palisade Catalog Validity Root"
rsa tsaroot; root tsaroot "/O=Palisade Tests/CN=Palisade Catalog TSA Root"
rsa signer; issue signer "/O=Palisade Tests/CN=Palisade Expired Catalog Signer" root leaf.cnf 1001 \
  20200101000000Z 20220101000000Z
rsa tsa; issue tsa "/O=Palisade Tests/CN=Palisade Catalog TSA" tsaroot tsa.cnf 2001 \
  20190101000000Z 20400101000000Z
cat signer.pem root.pem > signer.chain
cat tsa.pem tsaroot.pem > tsa.chain
openssl x509 -in root.pem -outform DER -out "$out/validity-root.der"
openssl x509 -in tsaroot.pem -outform DER -out "$out/validity-tsa-root.der"

rm -f "$out/v2-expired-timestamped.cat" "$out/v2-expired.cat"
osslsigncode sign -certs signer.chain -key signer.key -h sha256 -time 1609459200 \
  -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time 1609459200 \
  -in v2-sha256.unsigned.cat -out "$out/v2-expired-timestamped.cat" >/dev/null
osslsigncode sign -certs signer.chain -key signer.key -h sha256 -time 1609459200 \
  -in v2-sha256.unsigned.cat -out "$out/v2-expired.cat" >/dev/null
echo "catalog validity fixtures written to $out"
