#!/usr/bin/env python3
"""Frost-ledger Bay 07 offline solver -- faithful reconstruction.
Same struct layouts/offsets as the parser used in the CTF (superblock +
FNV1a-64 slots, v1 backwards-packed cells, overflow chains with
total_len = stored len). Usage: python3 solve.py registry.fvr"""
import re, struct, sys, zlib
TARGET = b"bay/07/thaw-authority"
TOKEN_RE = re.compile(rb"isfcr\{[^}]+\}")
RV_RE = re.compile(rb"record-version:\s*(\d+)")
EP_RE = re.compile(rb"epoch:\s*(\d+)")
def fnv1a64(d):
    h = 0xCBF29CE484222325
    for b in d:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h
def parse_sb(data):
    if data[0:3] != b"FVR":
        raise ValueError("bad magic")
    ps, pc, fmt = struct.unpack_from("<III", data, 4)
    slots = []
    for i in range(8):
        off = 16 + i * 32
        epoch, root, wal, res, fnv = struct.unpack_from("<QIIQQ", data, off)
        slots.append((i, epoch, root, fnv1a64(data[off:off + 24]) == fnv))
    return ps, pc, fmt, slots
def page_hdr(data, pgid, ps):
    pg = data[pgid * ps:(pgid + 1) * ps]
    _, epoch, kind, _, cc, _, _ = struct.unpack_from("<IQBBHII", pg, 0)
    return pg, epoch, kind, cc
def cell_at(body, bl, i):
    koff, ksz, vsz, voff, fl = struct.unpack_from("<IHHII", body, i * 16)
    return bytes(body[bl - koff:bl - koff + ksz]), bytes(body[bl - voff:bl - voff + vsz]), voff, fl
def btree_lookup(data, root, ps, target):
    bl = ps - 24
    cur = root
    while True:
        pg, _, kind, cc = page_hdr(data, cur, ps)
        body = pg[24:ps]
        if kind == 2:
            for i in range(cc):
                k, v, voff, fl = cell_at(body, bl, i)
                if k == target:
                    return cur, v, fl, voff, body
            raise KeyError(f"{target!r} missing on data page {cur}")
        if kind != 1:
            raise ValueError(f"page {cur} kind {kind}")
        child = None
        for i in range(cc):
            sep, v, _, _ = cell_at(body, bl, i)
            (cpg,) = struct.unpack("<I", v)
            if target < sep:
                child = cpg
                break
        if child is None:
            (child,) = struct.unpack_from("<I", body, len(body) - 4)
        cur = child
def reassemble(data, head, total, ps):
    buf = bytearray()
    chain = []
    cur = head
    while cur:
        pg, _, kind, _ = page_hdr(data, cur, ps)
        if kind != 3:
            raise ValueError(f"chain page {cur} kind {kind}")
        nxt, used = struct.unpack_from("<II", pg, 24)
        buf += pg[32:32 + used]
        chain.append(cur)
        cur = nxt
    if len(buf) != total:
        raise ValueError(f"reassembled {len(buf)} != total_len {total}")
    return bytes(buf), chain
def decode_value(raw):
    try:
        return zlib.decompress(raw)
    except Exception:
        return raw  # pre-rv4 plaintext CoW history is verbatim
def token_of(p):
    m = TOKEN_RE.search(p)
    return m.group(0).decode() if m else None
def scan_chains(data, ps, pc):
    info = {}
    for pgid in range(pc):
        pg, epoch, kind, _ = page_hdr(data, pgid, ps)
        if kind == 3:
            nxt, used = struct.unpack_from("<II", pg, 24)
            info[pgid] = (epoch, nxt, used)
    pointed = {n for _, n, _ in info.values() if n}
    out = []
    for h in sorted(p for p in info if p not in pointed):
        buf = bytearray()
        cur, seen, ok = h, set(), True
        while cur:
            if cur in seen or cur not in info:
                ok = False
                break
            seen.add(cur)
            _, nxt, used = info[cur]
            buf += data[cur * ps + 32:cur * ps + 32 + used]
            cur = nxt
        if not ok:
            continue
        dec = decode_value(bytes(buf))
        tok = token_of(dec)
        if tok:
            rv = RV_RE.search(dec)
            ep = EP_RE.search(dec)
            out.append((h, len(buf), tok, rv.group(1).decode() if rv else "?",
                        ep.group(1).decode() if ep else "?"))
    return out
def main():
    data = open(sys.argv[1] if len(sys.argv) > 1 else "registry.fvr", "rb").read()
    ps, pc, fmt, slots = parse_sb(data)
    print(f"FVR v{fmt} {pc}x{ps}")
    for i, epoch, root, ok in slots:
        print(f"slot{i} epoch={epoch} root={root} {'OK' if ok else 'TORN'}")
    live = max((s for s in slots if s[3] and s[1]), key=lambda s: s[1])
    torn_max = max([s[1] for s in slots if not s[3]] or [-1])
    print(f"live: slot{live[0]} epoch={live[1]} root={live[2]}")
    try:
        pgid, val, fl, voff, body = btree_lookup(data, live[2], ps, TARGET)
        if not fl & 0x2:
            print(token_of(val) or val)
            return
        head, total = struct.unpack_from("<QI", body, (ps - 24) - voff)
        print(f"cell: data={pgid} head={head} stored-len={total}")
        raw, chain = reassemble(data, head, total, ps)
        print("chain " + "->".join(map(str, chain)))
        print(token_of(decode_value(raw)) or "(no token)")
        return
    except Exception as e:
        print(f"live walk failed ({e}); falling back to chain scan")
    for h, stored, tok, rv, ep in scan_chains(data, ps, pc):
        verdict = "STALE (orphan, no slot)"
        if ep == str(live[1]):
            verdict = "LIVE"
        elif ep == str(torn_max):
            verdict = "STALE (torn slot, fnv fail)"
        elif rv == "3":
            verdict = "STALE (superseded CoW history)"
        print(f"head={h} rv={rv} epoch={ep} stored={stored} {tok} [{verdict}]")
if __name__ == "__main__":
    main()
