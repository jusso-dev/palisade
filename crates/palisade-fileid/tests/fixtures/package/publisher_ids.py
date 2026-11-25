"""Writes publisher_ids.txt: publisher DN strings and their package
publisher IDs, computed independently of the crate it tests (#53).

The ID is the first 8 bytes of the SHA-256 of the UTF-16LE publisher
string, read as a big-endian 64-bit number, padded with one zero bit to 65
bits, as 13 characters of Crockford base32 in lowercase. The first two
vectors are publisher IDs the OS itself reports for well-known publishers;
the rest exercise ordering, quoting, non-ASCII and length. Standard library
only. Usage: python3 -I publisher_ids.py > publisher_ids.txt
"""

import hashlib
import sys

ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
OS_REPORTED = {
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US":
        "8wekyb3d8bbwe",
    "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US":
        "cw5n1h2txyewy",
}


def publisher_id(publisher):
    digest = hashlib.sha256(publisher.encode("utf-16-le")).digest()[:8]
    value = int.from_bytes(digest, "big") << 1
    return "".join(ALPHABET[(value >> (5 * (12 - i))) & 31] for i in range(13))


def vectors():
    yield from OS_REPORTED
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
    out = []
    for p in vectors():
        pid = publisher_id(p)
        if p in OS_REPORTED:
            assert pid == OS_REPORTED[p], (p, pid)
        out.append(f"{p}\t{pid}\n")
    sys.stdout.write("".join(out))


if __name__ == "__main__":
    main()
