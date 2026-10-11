# Palimpest -- Reverse

**Flag:** `isfcr{p4p3r_r3m3mb3rs_wh4t_1nk_f0rg3ts}`
**Points:** 475
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A tiny static, stripped Zig/LLD x86-64 ELF (~4200 bytes) runs a 160-instruction self-decrypting VM over the 32-byte seal body. Code cannot be read forward (each instruction's decryption depends on your input and prior register state), but every opcode is invertible — so you run the VM **backwards** from the known final state to recover the seal.

## Solution

### Step 1: Reverse the format and VM

Input is exactly 39 chars: `isfcr{` + **32 bytes** + `}`; the 32 bytes load into eight 32-bit registers. The VM runs 160 eight-byte instructions at `0x10003d0`. Each instruction byte is decrypted by a rolling state `s = rol5(s + byte + pc + 0x9e3779b9 + j) ^ 0xa5a5f00d`, and the next instruction's starting state mixes in current register values — so the stream is not statically readable. Register indices are relative to a rotating pointer (starts at 3); opcode `0xa6` moves it. Opcodes: XOR-imm (`0x13`), add-imm (`0x27`), ROL (`0x39`), multiply by odd imm (`0x4d`), XOR rotated reg (`0x78`), sub rotated reg (`0x62`), swap (`0x8b`), ptr-move (`0xa6`) — all invertible. Final check: pointer ends at 1, chaining value + 160 == `0xf7f77ddb`, and the eight registers equal a 32-byte constant at `0x1000120`/`0x1000130`.

### Step 2: Run it backwards ("restoration starts at the last impression")

From the known final registers/pointer/chaining value, rebuild each instruction's full decryption state, decode it, undo it, recover the previous chaining value, and repeat 160×. The backward run lands exactly on the real start values (pointer 3, chaining value `0x6d2b79f5`), confirming consistency; the recovered 32 bytes are the seal body. Feeding `isfcr{<body>}` to the binary prints `Seal accepted. Job 04 restored.`

```python
import struct, sys
d = open(sys.argv[1], 'rb').read()           # python3 solve.py palimpsest
base = 0x1000000
rd = lambda a, n: d[a-base:a-base+n]
code = rd(0x10003d0, 0x500)
tgt_hi = struct.unpack('<4I', rd(0x1000120, 16))
tgt_lo = struct.unpack('<4I', rd(0x1000130, 16))
R = list(tgt_lo + tgt_hi)
M = 0xffffffff
rol = lambda x, n: ((x << n) | (x >> (32-n))) & M if n % 32 else x
ror = lambda x, n: rol(x, (32-n) % 32)
r15 = 1
ecx = (0xf7f77ddb - 160) & M
for i in range(159, -1, -1):
    edx = 8*i; b = code[edx:edx+8]
    t = ror(ecx, 7) ^ 0xa5a5f00d ^ R[(r15+i) & 7] ^ rol(R[(r15+i+3) & 7], 11)
    s = [0]*9; s[8] = t
    s[7] = (ror(s[8], 5) - edx - b[7] - 0x9e3779c0) & M
    for j in range(6, -1, -1):
        s[j] = (ror(s[j+1] ^ 0xa5a5f00d, 5) - b[j] - edx - (0x9e3779b9+j)) & M
    dd = [(s[j] >> 24) ^ b[j] for j in range(8)]
    op = dd[0]; imm = struct.unpack('<I', bytes(dd[4:8]))[0]; cl = dd[3]
    assert dd[1] <= 7 and dd[2] <= 7 and 1 <= cl <= 0x1f, (i, dd)
    if op == 0xa6: r15 = (r15 - dd[4]) & 7
    dst = (dd[1] + r15) & 7; src = (dd[2] + r15) & 7
    if op == 0x13: R[dst] ^= imm
    elif op == 0x27: R[dst] = (R[dst] - imm) & M
    elif op == 0x39: R[dst] = ror(R[dst], cl)
    elif op == 0x4d: assert imm & 1; R[dst] = R[dst] * pow(imm, -1, 1 << 32) & M
    elif op == 0x78: assert dst != src; R[dst] ^= rol(R[src], cl)
    elif op == 0x62: assert dst != src; R[dst] = (R[dst] - rol(R[src], cl)) & M
    elif op == 0x8b: assert dst != src; R[dst], R[src] = R[src], R[dst]
    elif op == 0xa6: pass
    else: raise Exception(('badop', i, op))
    r9 = s[0]
    ecx = (r9 - (i-1) - 0x7f4a7c15) & M
print('r15', r15, 'r9_0', hex(r9))
body = struct.pack('<8I', *R)
print('isfcr{' + body.decode('latin1') + '}')
```
