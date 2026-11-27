"""Writes publisher_ids.txt: publisher DN strings and their package
publisher IDs, computed independently of the crate it tests (#53).

The ID is the first 8 bytes of the SHA-256 of the UTF-16LE publisher
string, read as a big-endian 64-bit number, padded with one zero bit to 65
bits, as 13 characters of Crockford base32 in lowercase. It first checks
the computation against the publisher IDs the OS itself reports for two
well-known publishers (os_publisher_ids.txt); the vectors it writes
exercise ordering, quoting, non-ASCII and length. Standard library only.
Usage: python3 -I publisher_ids.py > publisher_ids.txt
"""

import hashlib
import os
import sys

ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
# Publisher IDs the OS itself reports for two well-known publishers, kept
# in their own file (the only one here that names a vendor, as the
# publisher strings do).
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "os_publisher_ids.txt"),
          encoding="utf-8") as f:
    OS_REPORTED = dict(line.rstrip("\n").split("\t") for line in f if line.strip())


def publisher_id(publisher):
    digest = hashlib.sha256(publisher.encode("utf-16-le")).digest()[:8]
    value = int.from_bytes(digest, "big") << 1
    return "".join(ALPHABET[(value >> (5 * (12 - i))) & 31] for i in range(13))


def vectors():
    yield "CN=Palisade Test Package Signer, O=Palisade Tests"
    yield "CN=Palisade Tests"
    yield "CN=a"
    yield "O=Palisade Tests, CN=Palisade Test Package Signer"
    yield 'CN="Palisade, Tests", O=Palisade'
    yield "CN=Café Logiciel, O=Exemple SARL, L=Lyon, C=FR"
    yield "CN=日本の発行元, C=JP"
    yield "CN=Emoji \U0001F600 Publisher"
    yield "CN=" + "x" * 200
    yield "cn=palisade tests"
    yield "CN=Palisade Tests "
    for i in range(45):
        yield f"CN=Test Publisher {i}, O=Example Org {i % 7}, L=City {i % 3}, C=AU"


def main():
    for p, pid in OS_REPORTED.items():
        assert publisher_id(p) == pid, (p, pid)
    out = []
    for p in vectors():
        pid = publisher_id(p)
        out.append(f"{p}\t{pid}\n")
    # UTF-8 bytes, whatever the console's code page: the vectors include
    # characters a legacy code page cannot encode.
    sys.stdout.buffer.write("".join(out).encode("utf-8"))


if __name__ == "__main__":
    main()
