#!/bin/sh
# Regenerates the OCSP fixtures in this directory (#50).
#
# Throwaway test CAs, trusted by nothing; no private key is kept. openssl
# makes every response, so their thisUpdate is the time of the run and
# their nextUpdate ten years later; the tests read those times from the
# responses rather than assuming them.
#
#   root.der         Palisade OCSP Test Root
#   leaf.der         code signing, serial 1001, OCSP URL http://ocsp.test/
#   other.der        code signing, serial 1002 (revoked in the index)
#   responder.der    a delegated responder: OCSP Signing EKU, issued by root
#   rogue.der        a would-be responder without the OCSP Signing EKU
#   old-responder.der a delegated responder valid only during 2021
#   leaf.p7          a SHA-256 Authenticode signature by leaf (with root)
#                    over the synthetic image `PeBuilder::default()`
#
#   good-by-root.der        leaf good, signed by root itself, SHA-1 CertID
#   good-by-root-sha256.der leaf good, signed by root, SHA-256 CertID
#   good-by-key.der         leaf good, signed by root, responder ID by key
#   good-delegated.der      leaf good, signed by responder
#   good-rogue.der          leaf good, signed by rogue (no OCSP Signing EKU)
#   good-old-responder.der  leaf good, signed by old-responder, produced
#                           long after it expired
#   crl-responder-revoked.der  root's CRL (2024 to 2034) revoking responder
#                           (serial 2001, keyCompromise)
#   revoked-responder-by-root.der  root's own OCSP answer: responder
#                           revoked (keyCompromise)
#   revoked-delegated.der   other revoked (keyCompromise), signed by responder
#   unknown-by-root.der     a serial the index does not know, signed by root
#   good-expired.der        leaf good, nextUpdate in the past (-ndays 0 is
#                           not allowed, so -nmin 1 and the tests look later)
#
# Needs: openssl 3.4 or later, osslsigncode (2.x), cargo.
#   sh crates/palisade-fileid/tests/fixtures/ocsp/generate.sh
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_AUTHENTICODE_BASE="$work/base.exe" \
  cargo test --manifest-path "$crate/Cargo.toml" --test signature -- \
  --ignored --exact write_fixture_base_image --quiet
test -s base.exe

cat > leaf.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=OCSP;URI:http://ocsp.test/
CNF
cat > responder.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > rogue.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF

rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null; }
rsa root
openssl req -x509 -new -key root.key -subj "/O=Palisade Tests/CN=Palisade OCSP Test Root" -sha256 \
  -not_before 20180101000000Z -not_after 20450101000000Z \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
  -addext subjectKeyIdentifier=hash -out root.pem 2>/dev/null
# issue NAME SUBJECT EXTFILE SERIAL [FROM TO]
issue() {
  rsa "$1"
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA root.pem -CAkey root.key -set_serial "0x$4" \
    -not_before "${5:-20200101000000Z}" -not_after "${6:-20400101000000Z}" -sha256 \
    -extfile "$3" -out "$1.pem" 2>/dev/null
}
issue leaf "/O=Palisade Tests/CN=Palisade OCSP Leaf" leaf.cnf 1001
issue other "/O=Palisade Tests/CN=Palisade OCSP Revoked Leaf" leaf.cnf 1002
issue responder "/O=Palisade Tests/CN=Palisade OCSP Responder" responder.cnf 2001
issue rogue "/O=Palisade Tests/CN=Palisade Rogue Responder" rogue.cnf 2002
issue old-responder "/O=Palisade Tests/CN=Palisade Old Responder" responder.cnf 2003 \
  20210101000000Z 20220101000000Z
for c in root leaf other responder rogue old-responder; do openssl x509 -in "$c.pem" -outform DER -out "$out/$c.der"; done

# The CA database: 1001 valid, 1002 revoked for keyCompromise.
{
  printf 'V\t400101000000Z\t\t1001\tunknown\t/O=Palisade Tests/CN=Palisade OCSP Leaf\n'
  printf 'R\t400101000000Z\t210601000000Z,keyCompromise\t1002\tunknown\t/O=Palisade Tests/CN=Palisade OCSP Revoked Leaf\n'
} > index.txt

req() { openssl ocsp -issuer root.pem -no_nonce "$@" >/dev/null; }
# respond OUT REQ SIGNER [options...]
respond() {
  o=$1 r=$2 s=$3
  shift 3
  openssl ocsp -index index.txt -CA root.pem -rsigner "$s.pem" -rkey "$s.key" \
    -reqin "$r" -respout "$out/$o" -ndays 3650 "$@" >/dev/null
}
req -cert leaf.pem -reqout leaf.req
req -sha256 -cert leaf.pem -reqout leaf256.req
req -cert other.pem -reqout other.req
req -serial 0x7777 -reqout unknown.req
respond good-by-root.der leaf.req root
respond good-by-root-sha256.der leaf256.req root
respond good-by-key.der leaf.req root -resp_key_id
respond good-delegated.der leaf.req responder
respond good-rogue.der leaf.req rogue
respond good-old-responder.der leaf.req old-responder
respond revoked-delegated.der other.req responder
respond unknown-by-root.der unknown.req root
openssl ocsp -index index.txt -CA root.pem -rsigner root.pem -rkey root.key \
  -reqin leaf.req -respout "$out/good-expired.der" -nmin 1 >/dev/null

# root's CRL revoking the delegated responder.
cat > crl.cnf <<'CNF'
[ca]
default_ca = d
[d]
database = crl.idx
crlnumber = crl.num
default_md = sha256
crl_extensions = ext
[ext]
authorityKeyIdentifier = keyid
CNF
printf 'R\t400101000000Z\t210601000000Z,keyCompromise\t2001\tunknown\t/O=Palisade Tests/CN=Palisade OCSP Responder\n' > crl.idx
echo 01 > crl.num
openssl ca -config crl.cnf -gencrl -cert root.pem -keyfile root.key \
  -crl_lastupdate 20240101000000Z -crl_nextupdate 20340101000000Z -out crl.pem 2>/dev/null
openssl crl -in crl.pem -outform DER -out "$out/crl-responder-revoked.der"
# root's own OCSP answer about the responder.
printf 'R\t400101000000Z\t210601000000Z,keyCompromise\t2001\tunknown\t/O=Palisade Tests/CN=Palisade OCSP Responder\n' > rindex.txt
req -cert responder.pem -reqout responder.req
openssl ocsp -index rindex.txt -CA root.pem -rsigner root.pem -rkey root.key \
  -reqin responder.req -respout "$out/revoked-responder-by-root.der" -ndays 3650 >/dev/null

cat leaf.pem root.pem > leaf.chain
osslsigncode sign -certs leaf.chain -key leaf.key -h sha256 -time 1609459200 \
  -in base.exe -out leaf.exe >/dev/null
rm -f "$out/leaf.p7"
osslsigncode extract-signature -in leaf.exe -out "$out/leaf.p7" >/dev/null
echo "OCSP fixtures written to $out"
