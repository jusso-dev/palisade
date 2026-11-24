"""Computes the Palisade normalised installer hash of a package.

An independent implementation of the algorithm documented in
`src/installer/mod.rs`, with its own minimal compound-file reader, so the
pinned value in `product.normalised.txt` does not come from the crate it
tests. Standard library only. Usage: python3 -I normalised.py FILE
"""

import hashlib
import struct
import sys

TAG = b"palisade-msi-normalised-v1\0"
SKIP = {"\x05DigitalSignature", "\x05MsiDigitalSignatureEx",
        "\x05SummaryInformation", "\x05DocumentSummaryInformation"}
TIMES = {10, 11, 12, 13}


def read_cfb(data):
    sector = 1 << struct.unpack_from("<H", data, 0x1E)[0]
    nfat = struct.unpack_from("<I", data, 0x2C)[0]
    difat = list(struct.unpack_from("<109I", data, 0x4C))[:nfat]
    fat = []
    for s in difat:
        off = (s + 1) * sector
        fat += struct.unpack_from("<%dI" % (sector // 4), data, off)

    def chain(start):
        out = []
        while start < 0xFFFFFFFA:
            out.append(start)
            start = fat[start]
        return out

    def read(start, size):
        buf = b"".join(data[(s + 1) * sector:(s + 2) * sector] for s in chain(start))
        return buf[:size]

    dirbuf = read(struct.unpack_from("<I", data, 0x30)[0], 1 << 30)
    entries = []
    for i in range(len(dirbuf) // 128):
        e = dirbuf[i * 128:(i + 1) * 128]
        nlen = struct.unpack_from("<H", e, 0x40)[0]
        name = e[:max(nlen - 2, 0)].decode("utf-16-le", "surrogatepass")
        kind = e[0x42]
        left, right, child = struct.unpack_from("<III", e, 0x44)
        clsid = e[0x50:0x60]
        start = struct.unpack_from("<I", e, 0x74)[0]
        size = struct.unpack_from("<Q", e, 0x78)[0] & 0xFFFFFFFF
        entries.append(dict(name=name, raw=e[:max(nlen - 2, 0)], kind=kind, left=left,
                            right=right, child=child, clsid=clsid, start=start, size=size))
    root = entries[0]
    mini = read(root["start"], root["size"])
    nmf = struct.unpack_from("<I", data, 0x40)[0]
    minifat = []
    if nmf:
        mf = read(struct.unpack_from("<I", data, 0x3C)[0], nmf * sector)
        minifat = list(struct.unpack_from("<%dI" % (len(mf) // 4), mf))

    def content(e):
        if e["size"] == 0:
            return b""
        if e["size"] < 4096:
            out, s = b"", e["start"]
            while s < 0xFFFFFFFA:
                out += mini[s * 64:(s + 1) * 64]
                s = minifat[s]
            return out[:e["size"]]
        return read(e["start"], e["size"])

    def children(e):
        out, stack = [], [e["child"]]
        while stack:
            i = stack.pop()
            if i == 0xFFFFFFFF:
                continue
            c = entries[i]
            out.append(c)
            stack += [c["left"], c["right"]]
        return out

    return root, children, content


def summary_canonical(stream):
    start = struct.unpack_from("<I", stream, 44)[0]
    count = struct.unpack_from("<I", stream, start + 4)[0]
    sec = stream[start:]
    props = {}
    for i in range(count):
        pid, off = struct.unpack_from("<II", sec, 8 + 8 * i)
        ty = struct.unpack_from("<I", sec, off)[0]
        if ty == 2:
            props[pid] = (ty, sec[off + 4:off + 6])
        elif ty == 3:
            props[pid] = (ty, sec[off + 4:off + 8])
        elif ty == 30:
            n = struct.unpack_from("<I", sec, off + 4)[0]
            raw = sec[off + 8:off + 8 + n].split(b"\0", 1)[0]
            props[pid] = (ty, struct.pack("<I", len(raw)) + raw)
        elif ty == 64:
            props[pid] = (ty, sec[off + 4:off + 12])
    out = b""
    for pid in sorted(props):
        if pid in TIMES:
            continue
        ty, body = props[pid]
        out += struct.pack("<II", pid, ty) + body
    return out


def fold(name):
    return name.upper()


def main(path):
    data = open(path, "rb").read()
    root, children, content = read_cfb(data)
    h = hashlib.sha256()
    h.update(TAG)
    h.update(root["clsid"])

    def units(raw):
        return [raw[i] | raw[i + 1] << 8 for i in range(0, len(raw), 2)]

    def walk(storage, is_root, path):
        for c in sorted(children(storage), key=lambda c: units(c["raw"])):
            if is_root and fold(c["name"]) in {fold(n) for n in SKIP}:
                continue
            p = path + ("/".encode("utf-16-le") if path else b"") + c["raw"]
            if c["kind"] == 1:
                h.update(b"S" + struct.pack("<I", len(p)) + p + c["clsid"])
                walk(c, False, p)
            else:
                h.update(b"F" + struct.pack("<I", len(p)) + p + struct.pack("<Q", c["size"]))
                h.update(content(c))

    walk(root, True, b"")
    summary = [c for c in children(root) if fold(c["name"]) == fold("\x05SummaryInformation")]
    if summary:
        # Fixtures always have a well-formed summary; a malformed one is
        # hashed raw under the tag "R" (not needed here).
        canon = summary_canonical(content(summary[0]))
        h.update(b"I" + struct.pack("<Q", len(canon)) + canon)
    else:
        h.update(b"N")
    sys.stdout.write(h.hexdigest())


if __name__ == "__main__":
    main(sys.argv[1])
