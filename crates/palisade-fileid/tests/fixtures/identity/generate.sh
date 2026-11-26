#!/bin/sh
# Regenerates the generated files of the file identity corpus (#55), and
# prints the independent digests of every corpus file for manifest.yaml.
#
# 1. `tests/identity_corpus.rs` writes every synthetic corpus file
#    (`write_corpus_unsigned`): PE images built byte by byte, and a few
#    non-PE files. No third-party binary is used.
# 2. A throwaway test CA, made here and trusted by nothing outside the
#    tests, signs copies of some of them with osslsigncode, and signs a
#    catalog that lists two of them.
# 3. The digests are computed by tools independent of palisade-fileid:
#    shasum for the flat hashes, osslsigncode `extract-data` for the
#    Authenticode SHA-256, openssl for the signer thumbprint.
#
# Needs: openssl (3.x or later), osslsigncode (2.x), shasum, cargo. Run from
# anywhere:
#   sh crates/palisade-fileid/tests/fixtures/identity/generate.sh
#
# Keys and serials are random, so a rerun changes every signed file and
# its digests; copy the printed values into manifest.yaml. No private key
# is kept. Certificates are dated 2020-01-01 to 2050-01-01 so the corpus
# does not expire; the tests judge validity at a fixed time.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out="$here/files"
crate=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

PALISADE_CORPUS_OUT="$work/unsigned" \
  cargo test --manifest-path "$crate/Cargo.toml" --test identity_corpus -- \
  --ignored --exact write_corpus_unsigned --quiet
test -s unsigned/plain.bin

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
dates="-not_before 20200101000000Z -not_after 20500101000000Z"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
openssl req -new -key ca.key -out ca.csr \
  -subj "/CN=Palisade Corpus Root/O=Palisade Tests" 2>/dev/null
# shellcheck disable=SC2086
openssl x509 -req -in ca.csr -signkey ca.key -out ca.crt $dates -extfile ca.cnf 2>/dev/null

# leaf NAME SUBJECT: a code-signing certificate from the corpus CA.
leaf() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "$2" 2>/dev/null
  # shellcheck disable=SC2086
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$1.crt" $dates -extfile "${LEAF_EXT:-leaf.cnf}" 2>/dev/null
  cat "$1.crt" ca.crt > "$1.chain"
}
leaf vendor "/CN=Palisade Corpus Vendor/O=Palisade Tests"
# The OS signer names a CRL distribution point (never fetched), so a
# policy that requires revocation answers asks about it.
cp leaf.cnf leaf-os.cnf
echo 'crlDistributionPoints=URI:http://crl.example.test/corpus.crl' >> leaf-os.cnf
LEAF_EXT=leaf-os.cnf leaf os "/CN=Palisade Corpus OS Signer/O=Palisade Tests"

# A self-signed signer nothing trusts.
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt \
  -subj "/CN=Palisade Corpus Rogue/O=Palisade Tests" $dates 2>/dev/null

# sign IN OUT CHAIN KEY: signs unsigned/IN.bin into files/OUT.
sign() {
  rm -f "$out/$2"
  osslsigncode sign -certs "$3" -key "$4" -h sha256 -time 1700000000 \
    -n "Palisade corpus" -in "unsigned/$1.bin" -out "$out/$2" >/dev/null
}

mkdir -p "$out"
sign tool signed-tool.exe vendor.chain vendor.key
sign tool-v2 signed-tool-v2.exe vendor.chain vendor.key
sign powershell signed-powershell.exe os.chain os.key
sign plain rogue-signed.exe rogue.crt rogue.key
# A signed file changed after signing: one byte of its code.
cp "$out/signed-tool.exe" tampered.exe
printf '\220' | dd of=tampered.exe bs=1 seek=1025 conv=notrunc 2>/dev/null
mv tampered.exe "$out/tampered-tool.exe"
openssl x509 -in ca.crt -outform DER -out "$out/ca.der"

# An empty CRL from the corpus CA, current from 2025 to 2027 only, for the
# test that revocation is judged at the clock floor.
: > index.txt
echo 01 > crlnumber
cat > crl.cnf <<'CNF'
[ ca ]
default_ca = d
[ d ]
database = index.txt
crlnumber = crlnumber
default_md = sha256
CNF
openssl ca -config crl.cnf -gencrl -keyfile ca.key -cert ca.crt \
  -crl_lastupdate 20250101000000Z -crl_nextupdate 20270101000000Z -out ca.crl 2>/dev/null
openssl crl -in ca.crl -outform DER -out "$out/ca-2025-2027.crl"

# The catalog: the unsigned `plain` image by its Authenticode SHA-256, and
# the `flat-member` text by its flat SHA-256, signed by the OS signer.
PALISADE_CATALOG_OUT="$work" \
  cargo test --manifest-path "$crate/Cargo.toml" --test catalog -- \
  --ignored --exact write_unsigned_catalogs --quiet
rm -f "$out/corpus.cat"
osslsigncode sign -certs os.chain -key os.key -h sha256 -time 1700000000 \
  -in v2-sha256.unsigned.cat -out "$out/corpus.cat" >/dev/null

# Sanity check with osslsigncode itself.
# The OS signer's CRL distribution point is never fetched: the empty CRL
# made above is given instead.
for f in signed-tool signed-tool-v2 signed-powershell; do
  osslsigncode verify -CAfile ca.crt -CRLfile ca.crl -in "$out/$f.exe" >/dev/null
done

# The independent digests.
authenticode() {
  rm -f ad.der
  osslsigncode extract-data -h sha256 -in "$1" -out ad.der >/dev/null 2>&1 || { echo "-"; return; }
  openssl asn1parse -inform DER -in ad.der | awk -F: '/OCTET STRING/ {v=$NF} END {print tolower(v)}'
}
echo "# file sha256 sha1 md5 authenticode_sha256"
for f in "$work"/unsigned/*.bin "$out"/*.exe; do
  printf '%s %s %s %s %s\n' "$(basename "$f")" \
    "$(shasum -a 256 "$f" | cut -d' ' -f1)" \
    "$(shasum -a 1 "$f" | cut -d' ' -f1)" \
    "$(openssl dgst -md5 -r "$f" | cut -d' ' -f1)" \
    "$(authenticode "$f")"
done
for c in vendor os; do
  printf '%s signer sha1 thumbprint: %s\n' "$c" \
    "$(openssl x509 -in "$c.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')"
done
echo "corpus files written to $out"
