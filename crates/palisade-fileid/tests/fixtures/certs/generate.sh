#!/bin/sh
# Regenerates the certificate extraction fixtures in this directory (#49).
#
#   signed.cab  A one-file cabinet ("hello.txt"), built here byte by byte
#               (uncompressed, one folder), then signed by osslsigncode with
#               a throwaway leaf under a throwaway root. The signature
#               carries the leaf and the root.
#   root.der    That root.
#   leaf.der    That leaf.
#
# Nothing here is trusted by anything, and no private key is kept. Keys and
# serials are random, so a rerun changes every file; the tests depend only
# on the structure (which certificates the cabinet carries).
#
# Needs: openssl (3.x or later), osslsigncode (2.x), python3.
#   sh crates/palisade-fileid/tests/fixtures/certs/generate.sh
set -eu

out=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

python3 -I - unsigned.cab <<'PY'
import struct, sys
data = b"hello catalog world\n"
name = b"hello.txt\x00"
files_at = 36 + 8                       # CFHEADER, then one CFFOLDER
data_at = files_at + 16 + len(name)     # then one CFFILE
cfdata = struct.pack("<IHH", 0, len(data), len(data)) + data
total = data_at + len(cfdata)
header = b"MSCF" + struct.pack("<IIIIIBBHHHHH", 0, total, 0, files_at, 0, 3, 1, 1, 1, 0, 0x1234, 0)
folder = struct.pack("<IHH", data_at, 1, 0)
cffile = struct.pack("<IIHHHH", len(data), 0, 0, 0x5a21, 0x6000, 0x20) + name
open(sys.argv[1], "wb").write(header + folder + cffile + cfdata)
PY

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
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out root.key 2>/dev/null
openssl req -new -key root.key -subj "/O=Palisade Tests/CN=Palisade Cabinet Test Root" -out root.csr 2>/dev/null
openssl x509 -req -in root.csr -signkey root.key -days 3650 -extfile ca.cnf -out root.pem 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out leaf.key 2>/dev/null
openssl req -new -key leaf.key -subj "/O=Palisade Tests/CN=Palisade Cabinet Test Signer" -out leaf.csr 2>/dev/null
openssl x509 -req -in leaf.csr -CA root.pem -CAkey root.key -CAcreateserial -days 3650 \
  -extfile leaf.cnf -out leaf.pem 2>/dev/null
cat leaf.pem root.pem > chain.pem
openssl x509 -in root.pem -outform DER -out "$out/root.der"
openssl x509 -in leaf.pem -outform DER -out "$out/leaf.der"
rm -f "$out/signed.cab"
osslsigncode sign -certs chain.pem -key leaf.key -h sha256 -time 1700000000 \
  -in unsigned.cab -out "$out/signed.cab" >/dev/null
echo "certificate extraction fixtures written to $out"
