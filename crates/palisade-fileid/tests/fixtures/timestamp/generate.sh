#!/bin/sh
# Regenerates the timestamp, expiry and revocation fixtures in this
# directory (#50).
#
# Every `.p7` is a PKCS#7 SignedData made by osslsigncode over the synthetic
# image `PeBuilder::default()` (see ../authenticode/generate.sh). Every
# `.der` is a certificate or a CRL made here by throwaway test CAs, trusted
# by nothing. No private key is committed. Dates are fixed, so the tests
# can judge them against any "now" they choose:
#
#   root      Palisade Timestamp Test Root     2018-01-01 .. 2045-01-01
#   leaf      code signing, serial 1001         2020-01-01 .. 2022-01-01 (expired)
#   lifetime  code signing + Lifetime Signing   2020-01-01 .. 2022-01-01, serial 1002
#   current   code signing, serial 1003         2020-01-01 .. 2040-01-01
#   tsa-root  Palisade TSA Test Root            2018-01-01 .. 2045-01-01
#   tsa       Time Stamping only, serial 2001   2019-01-01 .. 2040-01-01
#   tsa-ca-cs a TSA CA restricted to code signing (EKU), under tsa-root
#   tsa-under-cs-ca  Time Stamping, serial 2002, issued by tsa-ca-cs
#
# Every signature has signingTime 2021-01-01T00:00:00Z. RSA PKCS #1 v1.5
# signatures are deterministic, so signatures by one key over the same
# attributes have the same value and their timestamps are interchangeable.
#
#   leaf-rfc3161.p7          leaf, SHA-256, RFC 3161 at 2021-01-01
#   leaf-rfc3161-2023.p7     leaf, SHA-256, RFC 3161 at 2023-01-01 (after expiry)
#   leaf-rfc3161-sha1.p7     leaf, SHA-1, RFC 3161 (SHA-1 imprint) at 2021-01-01
#   leaf-rfc3161-aa.p7       leaf-rfc3161 with its token under the standard
#                            id-aa-timeStampToken attribute (unsigned, so the
#                            rewrite keeps every signature valid)
#   leaf-untimestamped.p7    leaf, SHA-256, no timestamp
#   leaf-rfc3161-2018.p7     leaf, SHA-256, RFC 3161 at 2018-06-01, before the
#                            TSA certificate's validity
#   leaf-legacy.p7           leaf-untimestamped plus a legacy countersignature
#                            by tsa at 2021-01-01, and the TSA certificates
#   lifetime-rfc3161.p7      lifetime, SHA-256, RFC 3161 at 2021-01-01
#   current-rfc3161.p7       current, SHA-256, RFC 3161 at 2021-01-01
#   current-rfc3161-cs-ca.p7 current, SHA-256, RFC 3161 by tsa-under-cs-ca, whose
#                            issuer restricts the Time Stamping EKU away
#
# CRLs (thisUpdate 2024-01-01, nextUpdate 2034-01-01):
#
#   crl-leaf-superseded-after.der  root: leaf revoked 2021-06-01, superseded
#   crl-leaf-compromise-after.der  root: leaf revoked 2021-06-01, keyCompromise
#   crl-leaf-before.der            root: leaf revoked 2020-06-01, unspecified
#   crl-empty.der                  root: nothing revoked
#   crl-forged.der                 root's name, another key: leaf revoked 2020-06-01
#   crl-tsa-before.der             tsa-root: tsa revoked 2020-06-01, keyCompromise
#   crl-tsa-empty.der              tsa-root: nothing revoked
#   crl-leaf-twice.der             root: leaf listed twice, certificateHold on
#                                  2021-06-01 and keyCompromise on 2021-09-01
#
# tsa-reissued.der is the TSA certificate re-issued with the same key, issuer
# and serial but other dates: a token's signature still verifies with it, but
# its ESS signingCertificate hash names the original.
#
# Needs: openssl 3.4 or later, osslsigncode (2.x), python3, cargo.
#   sh crates/palisade-fileid/tests/fixtures/timestamp/generate.sh
#
# Keys are random, so a rerun changes every file; the tests depend only on
# the structure and the dates above.
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
CNF
cat > lifetime.cnf <<'CNF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning,1.3.6.1.4.1.311.10.3.13
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > cs-ca.cnf <<'CNF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
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
# root NAME SUBJECT: a self-signed CA, 2018 to 2045.
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

rsa root; root root "/O=Palisade Tests/CN=Palisade Timestamp Test Root"
rsa tsaroot; root tsaroot "/O=Palisade Tests/CN=Palisade TSA Test Root"
rsa leaf; issue leaf "/O=Palisade Tests/CN=Palisade Expired Signer" root leaf.cnf 1001 20200101000000Z 20220101000000Z
rsa lifetime; issue lifetime "/O=Palisade Tests/CN=Palisade Lifetime Signer" root lifetime.cnf 1002 20200101000000Z 20220101000000Z
rsa current; issue current "/O=Palisade Tests/CN=Palisade Current Signer" root leaf.cnf 1003 20200101000000Z 20400101000000Z
rsa tsa; issue tsa "/O=Palisade Tests/CN=Palisade Test TSA" tsaroot tsa.cnf 2001 20190101000000Z 20400101000000Z
rsa tsacsca; issue tsacsca "/O=Palisade Tests/CN=Palisade Code Signing Only CA" tsaroot cs-ca.cnf 3001 20190101000000Z 20400101000000Z
rsa tsaundercs; issue tsaundercs "/O=Palisade Tests/CN=Palisade TSA Under Code Signing CA" tsacsca tsa.cnf 2002 20190101000000Z 20400101000000Z
for n in leaf lifetime current; do cat "$n.pem" root.pem > "$n.chain"; done
cat tsa.pem tsaroot.pem > tsa.chain
cat tsaundercs.pem tsacsca.pem tsaroot.pem > tsaundercs.chain

T2021=1609459200
T2023=1672531200
# sign NAME SIGNER [osslsigncode options...]
sign() {
  name=$1 signer=$2
  shift 2
  osslsigncode sign -certs "$signer.chain" -key "$signer.key" -time "$T2021" "$@" \
    -in base.exe -out "$name.exe" >/dev/null
  osslsigncode extract-signature -in "$name.exe" -out "$name.p7" >/dev/null
}
sign leaf-rfc3161 leaf -h sha256 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time "$T2021"
sign leaf-rfc3161-2023 leaf -h sha256 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time "$T2023"
sign leaf-rfc3161-sha1 leaf -h sha1 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time "$T2021"
sign leaf-untimestamped leaf -h sha256
sign leaf-rfc3161-2018 leaf -h sha256 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time 1527811200
sign lifetime-rfc3161 lifetime -h sha256 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time "$T2021"
sign current-rfc3161 current -h sha256 -TSA-certs tsa.chain -TSA-key tsa.key -TSA-time "$T2021"
sign current-rfc3161-cs-ca current -h sha256 -TSA-certs tsaundercs.chain -TSA-key tsaundercs.key -TSA-time "$T2021"

# A legacy Authenticode timestamp: a PKCS #9 countersignature by `tsa` over
# leaf-untimestamped's signature value, added as an unauthenticated
# attribute, with the TSA certificates added to the SignedData.
for c in tsa tsaroot; do openssl x509 -in "$c.pem" -outform DER -out "$c.der"; done
python3 -I - leaf-untimestamped.p7 tsa.der tsaroot.der leaf-legacy.p7 "$work" <<'PY'
import hashlib, pathlib, subprocess, sys
src, tsa_der, tsaroot_der, dst, work = sys.argv[1:6]
w = pathlib.Path(work)

def parse(b, i=0):
    """One TLV at i: (tag, header length, end, content start)."""
    tag = b[i]; n = b[i + 1]; h = 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); h = 2 + k
    return tag, i + h, i + h + n
def children(b, start, end):
    out = []
    while start < end:
        t, c, e = parse(b, start); out.append(b[start:e]); start = e
    return out
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        nb = n.to_bytes((n.bit_length() + 7) // 8, "big"); head = bytes([0x80 | len(nb)]) + nb
    return bytes([tag]) + head + body
def content(el):
    _, c, e = parse(el); return el[c:e]
def oid(h): return tlv(0x06, bytes.fromhex(h))

d = open(src, "rb").read()
ci = children(d, *parse(d)[1:])                  # [OID signedData, [0]]
sd = content(ci[1])                              # SignedData SEQUENCE
sd_items = children(sd, *parse(sd)[1:])
# version, digestAlgorithms, contentInfo, [0] certificates, signerInfos
certs = sd_items[3]
assert certs[0] == 0xa0
signer_infos = sd_items[-1]
si = children(signer_infos, *parse(signer_infos)[1:])[0]
si_items = children(si, *parse(si)[1:])
# version, sid, digestAlg, [0] attrs, sigAlg, signature
sig_value = content(si_items[5])
assert len(si_items) == 6, "the source signature must have no unauthenticated attributes"

tsa = open(tsa_der, "rb").read()
tbs = children(tsa, *parse(tsa)[1:])[0]
tbs_items = children(tbs, *parse(tbs)[1:])
# [0] version, serial, sigAlg, issuer, ...
serial, issuer = tbs_items[1], tbs_items[3]

attrs = sorted([
    tlv(0x30, oid("2a864886f70d010903") + tlv(0x31, oid("2a864886f70d010701"))),
    tlv(0x30, oid("2a864886f70d010905") + tlv(0x31, tlv(0x17, b"210101000000Z"))),
    tlv(0x30, oid("2a864886f70d010904") + tlv(0x31, tlv(0x04, hashlib.sha256(sig_value).digest()))),
])
signed = tlv(0x31, b"".join(attrs))
(w / "cs-attrs.der").write_bytes(signed)
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(w / "tsa.key"),
                      str(w / "cs-attrs.der")], check=True, capture_output=True).stdout
counter = tlv(0x30,
    tlv(0x02, b"\x01")
    + tlv(0x30, issuer + serial)
    + tlv(0x30, oid("608648016503040201") + b"\x05\x00")
    + b"\xa0" + signed[1:]
    + tlv(0x30, oid("2a864886f70d010101") + b"\x05\x00")
    + tlv(0x04, sig))
unsigned = tlv(0xa1, tlv(0x30, oid("2a864886f70d010906") + tlv(0x31, counter)))
new_si = tlv(0x30, b"".join(si_items) + unsigned)
new_certs = tlv(0xa0, content(certs) + tsa + open(tsaroot_der, "rb").read())
new_sd = tlv(0x30, b"".join(sd_items[:3]) + new_certs + b"".join(sd_items[4:-1])
             + tlv(0x31, new_si))
open(dst, "wb").write(tlv(0x30, ci[0] + tlv(0xa0, new_sd)))
PY

# CRLs. `openssl ca` reads its revocations from an index file.
crl() { # NAME CA-CERT CA-KEY INDEX-LINES
  : > "$1.idx"
  printf '%b' "$4" > "$1.idx"
  cat > "$1.cnf" <<CNF
[ca]
default_ca = d
[d]
database = $1.idx
crlnumber = $1.num
default_md = sha256
crl_extensions = ext
[ext]
authorityKeyIdentifier = keyid
CNF
  echo 01 > "$1.num"
  openssl ca -config "$1.cnf" -gencrl -cert "$2" -keyfile "$3" \
    -crl_lastupdate 20240101000000Z -crl_nextupdate 20340101000000Z -out "$1.pem" 2>/dev/null
  openssl crl -in "$1.pem" -outform DER -out "$1.der"
}
leaf_subject="/O=Palisade Tests/CN=Palisade Expired Signer"
tsa_subject="/O=Palisade Tests/CN=Palisade Test TSA"
crl crl-leaf-superseded-after root.pem root.key "R\t220101000000Z\t210601000000Z,superseded\t1001\tunknown\t$leaf_subject\n"
crl crl-leaf-compromise-after root.pem root.key "R\t220101000000Z\t210601000000Z,keyCompromise\t1001\tunknown\t$leaf_subject\n"
crl crl-leaf-before root.pem root.key "R\t220101000000Z\t200601000000Z\t1001\tunknown\t$leaf_subject\n"
crl crl-empty root.pem root.key ""
rsa forged; root forged "/O=Palisade Tests/CN=Palisade Timestamp Test Root"
crl crl-forged forged.pem forged.key "R\t220101000000Z\t200601000000Z\t1001\tunknown\t$leaf_subject\n"
crl crl-tsa-empty tsaroot.pem tsaroot.key ""
crl crl-tsa-before tsaroot.pem tsaroot.key "R\t400101000000Z\t200601000000Z,keyCompromise\t2001\tunknown\t$tsa_subject\n"
# `openssl ca` will not list a serial twice, so build that CRL here: two
# entries for the leaf (certificateHold, then keyCompromise), signed by root.
python3 -I - crl-leaf-superseded-after.der "$work" crl-leaf-twice.der <<'PY'
import pathlib, subprocess, sys
src, work, dst = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
def parse(b, i=0):
    n = b[i + 1]; h = 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); h = 2 + k
    return i + h, i + h + n
def children(b, start, end):
    out = []
    while start < end:
        _, e = parse(b, start); out.append(b[start:e]); start = e
    return out
def tlv(tag, body):
    n = len(body)
    head = bytes([n]) if n < 0x80 else (lambda nb: bytes([0x80 | len(nb)]) + nb)(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + head + body
def entry(date, reason):
    ext = tlv(0x30, tlv(0x30, tlv(0x06, bytes.fromhex("551d15")) + tlv(0x04, tlv(0x0a, bytes([reason])))))
    return tlv(0x30, tlv(0x02, bytes.fromhex("1001")) + tlv(0x17, date) + ext)
d = open(src, "rb").read()
outer = children(d, *parse(d))            # tbs, alg, signature
tbs = outer[0]
items = children(tbs, *parse(tbs))        # version, alg, issuer, this, next, revoked, [0] ext
assert items[5][0] == 0x30 and items[6][0] == 0xa0
revoked = tlv(0x30, entry(b"210601000000Z", 6) + entry(b"210901000000Z", 1))
new_tbs = tlv(0x30, b"".join(items[:5]) + revoked + items[6])
(work / "twice-tbs.der").write_bytes(new_tbs)
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(work / "root.key"),
                      str(work / "twice-tbs.der")], check=True, capture_output=True).stdout
open(dst, "wb").write(tlv(0x30, new_tbs + outer[1] + tlv(0x03, b"\x00" + sig)))
PY
openssl crl -inform DER -in crl-leaf-twice.der -out crl-leaf-twice.pem
python3 -I - leaf-rfc3161.p7 leaf-rfc3161-aa.p7 <<'PY'
import sys
d = bytearray(open(sys.argv[1], "rb").read())
def parse(b, i=0):
    n = b[i + 1]; h = 2
    if n & 0x80:
        k = n & 0x7f; n = int.from_bytes(b[i + 2:i + 2 + k], "big"); h = 2 + k
    return i + h, i + h + n
def children(b, start, end):
    out = []
    while start < end:
        _, e = parse(b, start); out.append(bytes(b[start:e])); start = e
    return out
def content(el):
    c, e = parse(el); return el[c:e]
def tlv(tag, body):
    n = len(body)
    head = bytes([n]) if n < 0x80 else (lambda nb: bytes([0x80 | len(nb)]) + nb)(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    return bytes([tag]) + head + body
ci = children(d, *parse(d))
sd = content(ci[1]); items = children(sd, *parse(sd))
si = children(items[-1], *parse(items[-1]))[0]
si_items = children(si, *parse(si))
unsigned = si_items[-1]; assert unsigned[0] == 0xa1
attr = children(unsigned, *parse(unsigned))[0]
oid, values = children(attr, *parse(attr))
assert oid == tlv(0x06, bytes.fromhex("2b0601040182370303 01".replace(" ", "")))
new_attr = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010910020e")) + values)
new_si = tlv(0x30, b"".join(si_items[:-1]) + tlv(0xa1, new_attr))
new_sd = tlv(0x30, b"".join(items[:-1]) + tlv(0x31, new_si))
open(sys.argv[2], "wb").write(tlv(0x30, ci[0] + tlv(0xa0, new_sd)))
PY
test "$(openssl crl -in crl-leaf-twice.pem -noout -text | grep -c 'Serial Number: 1001')" = 2
openssl req -new -key tsa.key -subj "$tsa_subject" -out tsa2.csr 2>/dev/null
openssl x509 -req -in tsa2.csr -CA tsaroot.pem -CAkey tsaroot.key -set_serial 0x2001 \
  -not_before 20190601000000Z -not_after 20400101000000Z -sha256 -extfile tsa.cnf -out tsa-reissued.pem 2>/dev/null

# Sanity checks with openssl itself.
openssl verify -CAfile tsaroot.pem tsa.pem >/dev/null
openssl verify -attime "$T2021" -CAfile root.pem leaf.pem >/dev/null
for c in crl-leaf-superseded-after crl-leaf-compromise-after crl-leaf-before crl-empty crl-leaf-twice; do
  openssl crl -in "$c.pem" -CAfile root.pem -noout 2>/dev/null
done
if openssl crl -in crl-forged.pem -CAfile root.pem -noout 2>/dev/null; then
  echo "the forged CRL unexpectedly verifies" >&2; exit 1
fi
osslsigncode verify -CAfile root.pem -TSA-CAfile tsaroot.pem -in current-rfc3161.exe >/dev/null

find "$out" -maxdepth 1 \( -name '*.der' -o -name '*.p7' \) -exec rm -f {} +
for c in root leaf lifetime current tsa tsa-reissued; do
  openssl x509 -in "$c.pem" -outform DER -out "$out/$c.der"
done
openssl x509 -in tsaroot.pem -outform DER -out "$out/tsa-root.der"
for p in leaf-rfc3161 leaf-rfc3161-aa leaf-rfc3161-2023 leaf-rfc3161-2018 leaf-rfc3161-sha1 leaf-untimestamped leaf-legacy \
  lifetime-rfc3161 current-rfc3161 current-rfc3161-cs-ca; do
  cp "$p.p7" "$out/$p.p7"
done
for c in crl-leaf-superseded-after crl-leaf-compromise-after crl-leaf-before crl-empty \
  crl-forged crl-tsa-before crl-tsa-empty crl-leaf-twice; do
  cp "$c.der" "$out/$c.der"
done
ls -l "$out"
