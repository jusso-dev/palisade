#!/bin/sh
# Regenerates the certificate chain fixtures in this directory (#49).
#
# Every `.der` file is one X.509 certificate made here by throwaway test CAs
# and trusted by nothing. No private key is committed. `expected.txt` holds
# reference values for every certificate (thumbprints, TBS hashes, serial),
# computed here by Python's hashlib from the DER, independently of the Rust
# parser, which the tests compare against. `leaf.pem.txt` is openssl's PEM form
# of `leaf.der`, for the PEM export test.
#
# The `.p7` files are PKCS#7 SignedData over the synthetic image
# `PeBuilder::default()` (see ../authenticode/generate.sh):
# `dual-a-sha1-b-sha256.p7` is a SHA-1 signature by chain A with a nested
# SHA-256 signature by chain B, and `leaf-inter-root.p7` a SHA-256
# signature by `leaf.der` that embeds `root.der` and `inter.der` too.
#
# Needs: openssl 3.4 or later (for `x509 -not_before`/`-not_after`),
# osslsigncode (2.x), python3, cargo.
#   sh crates/palisade-fileid/tests/fixtures/chain/generate.sh
#
# Keys, serials and ECDSA signatures are random, so a rerun changes every
# file and `expected.txt`; the tests depend only on structure and on
# `expected.txt` matching the files.
set -eu

out=$(cd "$(dirname "$0")" && pwd)
crate=$(cd "$out/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

rsa() { openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${2:-2048}" -out "$1.key" 2>/dev/null; }
ec() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1.key" 2>/dev/null; }

cat > ca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > ca0.cnf <<'CNF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > leaf.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > rich.cnf <<'CNF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=codeSigning,1.3.6.1.4.1.311.10.3.13,1.3.6.1.4.1.311.61.1.1,1.2.3.4.5.6
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
certificatePolicies=1.2.3.4,2.23.140.1.3
crlDistributionPoints=URI:http://crl.example.test/ca.crl
authorityInfoAccess=OCSP;URI:http://ocsp.example.test,caIssuers;URI:http://ca.example.test/ca.crt
CNF
cat > tls.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > tlsca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > noca.cnf <<'CNF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,keyCertSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > nc.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign
nameConstraints=critical,permitted;DNS:example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
# No key identifiers, so only the signature check can tell issuers apart.
cat > bare-ca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign
subjectKeyIdentifier=none
authorityKeyIdentifier=none
CNF
cat > bare-leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=none
authorityKeyIdentifier=none
CNF
cat > self-leaf.cnf <<'CNF'
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
CNF

# root NAME SUBJECT [DIGEST]: a self-signed CA for NAME.key.
root() {
  openssl req -x509 -new -key "$1.key" -subj "$2" -days 3650 "-${3:-sha256}" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
    -out "$1.pem" 2>/dev/null
}
# issue NAME SUBJECT ISSUER EXTFILE [DIGEST [x509 options...]]: a certificate
# for NAME.key issued by ISSUER.pem with ISSUER.key.
issue() {
  name=$1 subj=$2 ca=$3 ext=$4 md=${5:-sha256}
  if [ $# -ge 5 ]; then shift 5; else shift $#; fi
  openssl req -new -key "$name.key" -subj "$subj" -utf8 -out "$name.csr" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA "$ca.pem" -CAkey "$ca.key" -CAcreateserial \
    -days 3650 "-$md" -extfile "$ext" "$@" -out "$name.pem" 2>/dev/null
}
# selfsign NAME SUBJECT EXTFILE: a self-issued certificate for NAME.key.
selfsign() {
  openssl req -new -key "$1.key" -subj "$2" -utf8 -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -key "$1.key" -days 3650 -sha256 -extfile "$3" \
    -out "$1.pem" 2>/dev/null
}

rich="/C=AU/ST=Victoria/L=Melbourne/O=Palisade Tests, Pty/OU=Signing/CN=Palisade Test Publisher/emailAddress=signing@example.test/serialNumber=12345/businessCategory=Private Organization/jurisdictionC=AU"

rsa root; root root "/O=Palisade Tests/CN=Palisade Chain Root"
rsa inter; issue inter "/O=Palisade Tests/CN=Palisade Chain CA" root ca0.cnf
rsa leaf
for md in sha1 sha384 sha512; do
  issue leaf "/O=Palisade Tests/CN=Palisade Test $md" inter leaf.cnf "$md"
  cp leaf.pem "leaf-$md.pem"
done
issue leaf "$rich" inter rich.cnf
rsa onlyo; issue onlyo "/C=AU/O=Palisade Tésts" inter leaf.cnf
rsa tls; issue tls "/O=Palisade Tests/CN=Palisade TLS Server" inter tls.cnf
rsa tlsca; issue tlsca "/O=Palisade Tests/CN=Palisade TLS CA" root tlsca.cnf
rsa tlsleaf; issue tlsleaf "/O=Palisade Tests/CN=Palisade Signer Under TLS CA" tlsca leaf.cnf

# A second root that cross-signs the first: same subject and key as `root`.
rsa root2; root root2 "/O=Palisade Tests/CN=Palisade Second Root"
cp root.key cross.key; issue cross "/O=Palisade Tests/CN=Palisade Chain Root" root2 ca.cnf

# An expired intermediate and a leaf under it.
rsa expca; issue expca "/O=Palisade Tests/CN=Palisade Expired CA" root ca.cnf sha256 \
  -not_before 20010101000000Z -not_after 20020101000000Z
rsa expleaf; issue expleaf "/O=Palisade Tests/CN=Palisade Expired Chain Signer" expca leaf.cnf

# A self-signed signer.
rsa self; selfsign self "/O=Palisade Tests/CN=Palisade Self Signer" self-leaf.cnf

# ECC: a P-384 root and intermediate, and a P-256 leaf.
ec eroot P-384; root eroot "/O=Palisade Tests/CN=Palisade ECC Root" sha384
ec einter P-384; issue einter "/O=Palisade Tests/CN=Palisade ECC CA" eroot ca.cnf sha384
ec eleaf P-256; issue eleaf "/O=Palisade Tests/CN=Palisade ECC Signer" einter leaf.cnf sha384

# A forged issuer: a CA with the real intermediate's name but another key,
# and a leaf it signed. Without key identifiers, only the signature check
# can reject the real intermediate as this leaf's issuer.
rsa forged; selfsign forged "/O=Palisade Tests/CN=Palisade Chain CA" bare-ca.cnf
rsa fleaf; issue fleaf "/O=Palisade Tests/CN=Palisade Forged Signer" forged bare-leaf.cnf

# A re-keyed intermediate: the real intermediate's name, another key and
# so another subject key identifier, properly issued by the root.
rsa rekey; issue rekey "/O=Palisade Tests/CN=Palisade Chain CA" root ca.cnf

# An issuer that is not a CA, and one with a critical name constraint.
rsa noca; issue noca "/O=Palisade Tests/CN=Palisade Not A CA" root noca.cnf
rsa nocaleaf; issue nocaleaf "/O=Palisade Tests/CN=Palisade Under Not A CA" noca leaf.cnf
rsa ncca; issue ncca "/O=Palisade Tests/CN=Palisade Constrained CA" root nc.cnf
rsa ncleaf; issue ncleaf "/O=Palisade Tests/CN=Palisade Under Constrained CA" ncca leaf.cnf

# Path length: `inter` has pathlen 0, so no CA may sit between it and a leaf.
rsa sub; issue sub "/O=Palisade Tests/CN=Palisade Sub CA" inter ca.cnf
rsa deep; issue deep "/O=Palisade Tests/CN=Palisade Too Deep Signer" sub leaf.cnf

# A loop: A is issued by B and B by A.
rsa loopa; rsa loopb
selfsign loopa "/O=Palisade Tests/CN=Palisade Loop A" bare-ca.cnf
issue loopb "/O=Palisade Tests/CN=Palisade Loop B" loopa bare-ca.cnf
issue loopa "/O=Palisade Tests/CN=Palisade Loop A" loopb bare-ca.cnf
rsa loopleaf; issue loopleaf "/O=Palisade Tests/CN=Palisade Loop Signer" loopa bare-leaf.cnf

# Depth: a root, eleven intermediates and a leaf, 13 certificates in all.
rsa d00; root d00 "/O=Palisade Tests/CN=Palisade Depth 00"
prev=d00
for i in 01 02 03 04 05 06 07 08 09 10 11; do
  rsa "d$i"; issue "d$i" "/O=Palisade Tests/CN=Palisade Depth $i" "$prev" ca.cnf
  prev="d$i"
done
rsa d12; issue d12 "/O=Palisade Tests/CN=Palisade Depth Signer" "$prev" leaf.cnf

# Anchors that must not issue: a self-signed end-entity signer (CA:FALSE,
# no keyCertSign) and a leaf signed with its key; and a v3 root with a key
# usage that lacks keyCertSign, and a leaf under it.
cat > ee.cnf <<'CNF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
subjectKeyIdentifier=hash
CNF
cat > noku-root.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
CNF
rsa pinned; selfsign pinned "/O=Palisade Tests/CN=Palisade Pinned Signer" ee.cnf
rsa evil; issue evil "/O=Palisade Tests/CN=Palisade Impersonated Publisher" pinned leaf.cnf
rsa nokuroot; selfsign nokuroot "/O=Palisade Tests/CN=Palisade No Cert Sign Root" noku-root.cnf
rsa nokuleaf; issue nokuleaf "/O=Palisade Tests/CN=Palisade Under No Cert Sign Root" nokuroot leaf.cnf

# Version 1 and 2 certificates, which openssl no longer makes: the TBS is
# built here and signed with openssl. A v1 root, a v1 leaf it issued, and a
# v2 leaf with issuer and subject unique identifiers.
rsa v1root; rsa v1leaf; rsa v2leaf
for k in v1root v1leaf v2leaf; do openssl pkey -in "$k.key" -pubout -outform DER -out "$k.spki"; done
python3 -I - "$work" <<'PY'
import pathlib, subprocess, sys
w = pathlib.Path(sys.argv[1])
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + head + body
def oid(b): return tlv(0x06, bytes.fromhex(b))
def name(*parts):
    rdns = b""
    for o, v in parts:
        rdns += tlv(0x31, tlv(0x30, oid(o) + tlv(0x0c, v.encode())))
    return tlv(0x30, rdns)
O, CN = "55040a", "550403"
ALG = tlv(0x30, oid("2a864886f70d01010b") + b"\x05\x00")  # sha256WithRSAEncryption
VALID = tlv(0x30, tlv(0x17, b"250101000000Z") + tlv(0x17, b"350101000000Z"))
root = name((O, "Palisade Tests"), (CN, "Palisade V1 Root"))
def cert(version, serial, issuer, subject, key, signer, unique=b""):
    spki = (w / f"{key}.spki").read_bytes()
    v = b"" if version == 1 else tlv(0xa0, tlv(0x02, bytes([version - 1])))
    tbs = tlv(0x30, v + tlv(0x02, bytes([serial])) + ALG + issuer + VALID + subject + spki + unique)
    (w / "tbs.der").write_bytes(tbs)
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(w / f"{signer}.key"),
                          str(w / "tbs.der")], check=True, capture_output=True).stdout
    return tlv(0x30, tbs + ALG + tlv(0x03, b"\x00" + sig))
(w / "v1root.der").write_bytes(cert(1, 1, root, root, "v1root", "v1root"))
(w / "v1leaf.der").write_bytes(cert(1, 2, root, name((O, "Palisade Tests"), (CN, "Palisade V1 Signer")), "v1leaf", "v1root"))
uids = tlv(0x81, b"\x00\x01\x02") + tlv(0x82, b"\x04\xf0")
(w / "v2leaf.der").write_bytes(cert(2, 3, root, name((O, "Palisade Tests"), (CN, "Palisade V2 Signer")), "v2leaf", "v1root", uids))
PY
for c in v1root v1leaf v2leaf; do openssl x509 -inform DER -in "$c.der" -out "$c.pem"; done
openssl verify -CAfile v1root.pem v1leaf.pem >/dev/null
openssl verify -CAfile v1root.pem v2leaf.pem >/dev/null

# Sanity checks with openssl itself.
openssl verify -CAfile root.pem -untrusted inter.pem leaf.pem >/dev/null
openssl verify -CAfile root.pem -untrusted inter.pem onlyo.pem >/dev/null
openssl verify -CAfile root2.pem -untrusted cross.pem -untrusted inter.pem leaf.pem >/dev/null
openssl verify -CAfile eroot.pem -untrusted einter.pem eleaf.pem >/dev/null
for bad in "inter fleaf" "noca nocaleaf" "sub deep"; do
  set -- $bad
  if openssl verify -CAfile root.pem -untrusted inter.pem -untrusted "$1.pem" "$2.pem" >/dev/null 2>&1; then
    echo "$2 unexpectedly verifies" >&2; exit 1
  fi
done

find "$out" -maxdepth 1 -name '*.der' -exec rm -f {} +
der() { openssl x509 -in "$1.pem" -outform DER -out "$out/$2.der"; }
der root root; der inter inter; der leaf leaf; der onlyo leaf-o-only
for md in sha1 sha384 sha512; do der "leaf-$md" "leaf-$md"; done
der tls leaf-tls; der tlsca inter-tls; der tlsleaf leaf-under-tls-ca
der root2 root2; der cross cross-root
der expca inter-expired; der expleaf leaf-expired-ca
der self leaf-self-signed
der eroot ecc-root; der einter ecc-inter; der eleaf ecc-leaf
der fleaf leaf-forged; der rekey inter-rekeyed
der noca inter-not-ca; der nocaleaf leaf-under-not-ca
der ncca inter-name-constraints; der ncleaf leaf-under-name-constraints
der sub inter-sub; der deep leaf-too-deep
der loopa loop-a; der loopb loop-b; der loopleaf leaf-loop
for i in 00 01 02 03 04 05 06 07 08 09 10 11 12; do der "d$i" "depth-$i"; done
der pinned leaf-pinned; der evil leaf-issued-by-pinned
der nokuroot root-no-cert-sign; der nokuleaf leaf-under-no-cert-sign
der v1root root-v1; der v1leaf leaf-v1; der v2leaf leaf-v2
# Named .txt: the repository ignores *.pem, to keep keys out.
openssl x509 -in leaf.pem -out "$out/leaf.pem.txt"

# Dual signature: SHA-1 by chain A (leaf A and root A) first, then a nested
# SHA-256 signature by chain B (leaf B and root B).
PALISADE_AUTHENTICODE_BASE="$work/base.exe" \
  cargo test --manifest-path "$crate/Cargo.toml" --test signature -- \
  --ignored --exact write_fixture_base_image --quiet
test -s base.exe
rsa ra; root ra "/O=Palisade Tests/CN=Palisade Root A"
rsa la; issue la "/O=Palisade Tests/CN=Palisade Signer A" ra leaf.cnf
rsa rb; root rb "/O=Palisade Tests/CN=Palisade Root B"
rsa lb; issue lb "/O=Palisade Tests/CN=Palisade Signer B" rb leaf.cnf
cat la.pem ra.pem > a.chain; cat lb.pem rb.pem > b.chain
osslsigncode sign -certs a.chain -key la.key -time 1700000000 -h sha1 \
  -in base.exe -out a.exe >/dev/null
osslsigncode sign -nest -certs b.chain -key lb.key -time 1700000000 -h sha256 \
  -in a.exe -out ab.exe >/dev/null
rm -f "$out/dual-a-sha1-b-sha256.p7"
osslsigncode extract-signature -in ab.exe -out "$out/dual-a-sha1-b-sha256.p7" >/dev/null
der ra root-a; der rb root-b
# The rich leaf, with its intermediate and root embedded (leaf, root,
# intermediate: not in chain order, so ordering is the parser's job).
cat leaf.pem root.pem inter.pem > full.chain
osslsigncode sign -certs full.chain -key leaf.key -time 1700000000 -h sha256 \
  -in base.exe -out full.exe >/dev/null
rm -f "$out/leaf-inter-root.p7"
osslsigncode extract-signature -in full.exe -out "$out/leaf-inter-root.p7" >/dev/null
# (osslsigncode's own verify rejects this leaf for its Lifetime Signing
# EKU without a timestamp, so the tests check the signature instead.)

# Reference values, one line per certificate:
#   name sha1 sha256 tbs-under-own-digest tbs-sha256 serial-octets
python3 -I - "$out" > "$out/expected.txt" <<'PY'
import hashlib, pathlib, sys
def tlv(b, i):
    n = b[i + 1]; h = 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); h = 2 + k
    return i + h, i + h + n
DIGESTS = {  # signatureAlgorithm OID content octets -> digest
    "2a864886f70d010105": "sha1", "2a864886f70d01010b": "sha256",
    "2a864886f70d01010c": "sha384", "2a864886f70d01010d": "sha512",
    "2a8648ce3d040302": "sha256", "2a8648ce3d040303": "sha384",
}
for p in sorted(pathlib.Path(sys.argv[1]).glob("*.der")):
    d = p.read_bytes()
    c, _ = tlv(d, 0)                  # Certificate
    tc, te = tlv(d, c)                # tbsCertificate
    tbs = d[c:te]
    i = tc
    if d[i] == 0xa0:                  # [0] version
        i = tlv(d, i)[1]
    sc, se = tlv(d, i)                # serialNumber
    ac, _ = tlv(d, te)                # signatureAlgorithm
    oc, oe = tlv(d, ac)
    alg = DIGESTS[d[oc:oe].hex()]
    print(p.stem, hashlib.sha1(d).hexdigest(), hashlib.sha256(d).hexdigest(),
          hashlib.new(alg, tbs).hexdigest(), hashlib.sha256(tbs).hexdigest(),
          d[sc:se].hex())
PY
ls -l "$out"
