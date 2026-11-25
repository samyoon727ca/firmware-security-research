#!/usr/bin/env python3
"""graft_node.py SEED DONOR PATH OUT: copy node PATH (with subnodes) from the
DONOR FIT into the signed SEED as the first subnode of its parent, changing no
byte a config signature covers: the node is in no hashed node, and its property
names reuse SEED's strings (a missing name is appended after hashed-strings).
Standard library only; run it with python3 -I."""
import struct
import sys

HDR = struct.Struct(">10I")  # FDT v17 header
BEGIN, END, PROP, NOP, FIN = 1, 2, 3, 4, 9


def align(n):
    return (n + 3) & ~3


def tokens(blob):
    """Yield (token, start, end, path, name, value) over the struct block."""
    magic, _, off_st, off_str, _, ver, _, _, _, size_st = HDR.unpack_from(blob)
    if magic != 0xD00DFEED or ver < 17:
        sys.exit("graft_node.py: not a version 17 FDT")
    path, pos = [], off_st
    while pos < off_st + size_st:
        tok, start, name, value = struct.unpack_from(">I", blob, pos)[0], pos, None, None
        pos += 4
        if tok == BEGIN:
            name = blob[pos:blob.index(b"\0", pos)].decode()
            pos = align(pos + len(name) + 1)
            path.append(name)
        elif tok == PROP:
            size, nameoff = struct.unpack_from(">II", blob, pos)
            name = blob[off_str + nameoff:blob.index(b"\0", off_str + nameoff)].decode()
            value, pos = blob[pos + 8:pos + 8 + size], align(pos + 8 + size)
        elif tok == FIN:
            return
        elif tok not in (END, NOP):
            sys.exit("graft_node.py: bad struct token %d" % tok)
        yield tok, start, pos, "/" + "/".join(path[1:]), name, value
        if tok == END:
            path.pop()


def main(seed_file, donor_file, path, out_file):
    seed, donor = open(seed_file, "rb").read(), open(donor_file, "rb").read()
    hdr = list(HDR.unpack_from(seed))
    off_st, off_str, off_rsv, size_str, size_st = hdr[2], hdr[3], hdr[4], hdr[8], hdr[9]
    if not off_rsv < off_st <= off_st + size_st <= off_str:
        sys.exit("graft_node.py: seed blocks are not in the usual order")
    strings = bytearray(seed[off_str:off_str + size_str])

    def nameoff(name):
        key = name.encode() + b"\0"
        if strings.find(key) < 0:  # a suffix of a longer name also matches
            strings.extend(key)
        return strings.find(key)

    node, depth = bytearray(), 0  # the donor node, against the seed's strings
    for tok, start, end, p, name, value in tokens(donor):
        if tok == BEGIN and (p == path or depth):
            depth += 1
        if depth and tok == PROP:
            node += struct.pack(">III", PROP, len(value), nameoff(name))
            node += value + b"\0" * (align(len(value)) - len(value))
        elif depth and tok != NOP:
            node += donor[start:end]
        if depth and tok == END:
            depth -= 1
            if not depth:
                break
    if not node:
        sys.exit("graft_node.py: no %s in %s" % (path, donor_file))

    def up(p):
        return p.rsplit("/", 1)[0] or "/"

    at = None  # after the parent's properties, before its first subnode
    for tok, start, _, p, _, _ in tokens(seed):
        if tok == BEGIN and p == path:
            sys.exit("graft_node.py: %s already has %s" % (seed_file, path))
        if at is None and ((tok == BEGIN and p != up(path) and up(p) == up(path))
                           or (tok == END and p == up(path))):
            at = start - off_st
    if at is None:
        sys.exit("graft_node.py: no %s in %s" % (up(path), seed_file))
    st = seed[off_st:at + off_st] + bytes(node) + seed[at + off_st:off_st + size_st]
    hdr[1], hdr[3] = off_st + len(st) + len(strings), off_st + len(st)
    hdr[8], hdr[9] = len(strings), len(st)
    with open(out_file, "wb") as f:
        f.write(HDR.pack(*hdr) + seed[HDR.size:off_st] + st + bytes(strings))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
