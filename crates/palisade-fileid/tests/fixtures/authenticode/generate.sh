#!/bin/sh
# Regenerates the Authenticode signature fixtures in this directory.
#
# Every fixture is a PKCS#7 SignedData (DER) made by osslsigncode over the
# synthetic image `PeBuilder::default()` from `tests/common`. Only the
# signatures are committed, never a PE file: the tests rebuild the image and
# attach each signature to it. Keys and certificates are throwaway test
# material made here, by a test-only CA, and trusted by nothing.
#
# Needs: openssl (3.x), osslsigncode (2.x), cargo. Run from anywhere:
#   sh crates/palisade-fileid/tests/fixtures/authenticode/generate.sh
#
# Keys, serials and ECDSA signatures are random, so a rerun changes every
# file; the tests only depend on their structure and validity.
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

# The unsigned image the tests build.
PALISADE_AUTHENTICODE_BASE="$work/base.exe" \
  cargo test --manifest-path "$crate/Cargo.toml" --test signature -- \
  --ignored --exact write_fixture_base_image --quiet
test -s base.exe

cat > leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > tsa.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping
CNF

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=Palisade Test Root/O=Palisade Tests" -days 3650 2>/dev/null

# leaf NAME KEYFILE [EXTFILE]: a certificate for KEYFILE issued by the test CA,
# then NAME.chain = leaf + CA.
leaf() {
  openssl req -new -key "$2" -out "$1.csr" \
    -subj "/CN=Palisade Test Signer $1/O=Palisade Tests" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$1.crt" -days 3650 -extfile "${3:-leaf.cnf}" 2>/dev/null
  cat "$1.crt" ca.crt > "$1.chain"
}
rsa() { openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$1.key" 2>/dev/null; leaf "$1" "$1.key"; }
ec() { openssl ecparam -name "$2" -genkey -noout -out "$1.key"; leaf "$1" "$1.key"; }

rsa rsa2048 2048
rsa rsa4096 4096
rsa rsa8192 8192
ec p256 prime256v1
ec p384 secp384r1
ec p521 secp521r1
rsa tsa 2048
leaf tsa tsa.key tsa.cnf
# An Ed25519 signer certificate. osslsigncode cannot sign with it; the tests
# splice it into a SignedData to check that Ed25519 is reported, not trusted.
openssl genpkey -algorithm ed25519 -out ed25519.key
leaf ed25519 ed25519.key
openssl x509 -in ed25519.crt -outform DER -out "$out/ed25519-leaf.der"

# sign NAME CHAIN KEY [osslsigncode options...]: signs base.exe and writes
# the bare PKCS#7 to NAME.p7.
sign() {
  name=$1 chain=$2 key=$3
  shift 3
  osslsigncode sign -certs "$chain" -key "$key" -time 1700000000 "$@" \
    -in base.exe -out "$name.exe" >/dev/null
  rm -f "$out/$name.p7"
  osslsigncode extract-signature -in "$name.exe" -out "$out/$name.p7" >/dev/null
}

sign rsa2048-sha256 rsa2048.chain rsa2048.key -h sha256 \
  -n "Palisade Test App" -i "https://example.test/app"
sign rsa2048-sha384-commercial rsa2048.chain rsa2048.key -h sha384 -comm
sign rsa2048-sha512 rsa2048.chain rsa2048.key -h sha512
sign rsa2048-md5 rsa2048.chain rsa2048.key -h md5
sign rsa2048-page-hashes rsa2048.chain rsa2048.key -h sha256 -ph
sign rsa2048-timestamp rsa2048.chain rsa2048.key -h sha256 \
  -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time 1700000000
sign rsa4096-sha256 rsa4096.chain rsa4096.key -h sha256
sign rsa8192-sha256 rsa8192.chain rsa8192.key -h sha256
sign p256-sha256 p256.chain p256.key -h sha256
sign p384-sha384 p384.chain p384.key -h sha384
sign p521-sha512 p521.chain p521.key -h sha512

# Dual signed: SHA-1 first, then a nested SHA-256 signature.
osslsigncode sign -certs rsa2048.chain -key rsa2048.key -time 1700000000 -h sha1 \
  -in base.exe -out sha1.exe >/dev/null
osslsigncode sign -nest -certs rsa2048.chain -key rsa2048.key -time 1700000000 -h sha256 \
  -in sha1.exe -out dual.exe >/dev/null
rm -f "$out/rsa2048-sha1-nested-sha256.p7"
osslsigncode extract-signature -in dual.exe -out "$out/rsa2048-sha1-nested-sha256.p7" >/dev/null

# Sanity check with osslsigncode itself: every signature but the P-521 and
# MD5 ones must verify against the test CA. (Timestamp chains are not
# checked; the TSA certificate is newer than the timestamp.)
for f in rsa2048-sha256 rsa2048-sha384-commercial rsa2048-sha512 rsa2048-page-hashes \
  rsa4096-sha256 rsa8192-sha256 p256-sha256 p384-sha384 dual; do
  osslsigncode verify -CAfile ca.crt -in "$f.exe" >/dev/null
done

# An RSA-PSS signature (SHA-256, MGF1-SHA-256, salt 32) by the rsa2048
# signer over the authenticated attributes of rsa2048-sha256.p7. The tests
# splice it into that SignerInfo. (osslsigncode cannot make RSA-PSS
# signatures, and no private key is committed.)
python3 -I - "$out/rsa2048-sha256.p7" signed-attrs.der <<'PY'
import sys
def tlv(b, i):
    tag = b[i]; n = b[i + 1]; h = 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); h = 2 + k
    return tag, i + h, i + h + n
def children(b, start, end):
    out = []
    while start < end:
        t, c, e = tlv(b, start); out.append((t, start, c, e)); start = e
    return out
d = open(sys.argv[1], "rb").read()
_, c, e = tlv(d, 0)                       # ContentInfo
_, _, c, e = children(d, c, e)[1]        # [0]
_, c, e = tlv(d, c)                       # SignedData
signer_infos = children(d, c, e)[-1]
_, si_c, si_e = tlv(d, signer_infos[2])   # the SignerInfo
attrs = [x for x in children(d, si_c, si_e) if x[0] == 0xa0][0]
raw = bytearray(d[attrs[1]:attrs[3]]); raw[0] = 0x31
open(sys.argv[2], "wb").write(raw)
PY
openssl dgst -sha256 -sign rsa2048.key -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest -sigopt rsa_mgf1_md:sha256 \
  -out "$out/rsa2048-sha256.pss-signature" signed-attrs.der
openssl x509 -in rsa2048.crt -pubkey -noout > rsa2048.pub
openssl dgst -sha256 -verify rsa2048.pub -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest -signature "$out/rsa2048-sha256.pss-signature" \
  signed-attrs.der

ls -l "$out"
