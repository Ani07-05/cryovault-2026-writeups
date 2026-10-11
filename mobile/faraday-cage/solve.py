from vm import *

T = INIT[0:16]
K = [INIT[0x10 + 16 * r:0x20 + 16 * r] for r in range(4)]
P = INIT[0x50:0x60]
print('T', T.hex(), 'P', list(P))
[print('K', k.hex()) for k in K]

# f52c0 is linear over GF(2): column j = f(1 << j). Recover its 32x32
# bit-matrix by probing the native routine, then verify linearity.
cols = [f52c0(1 << j) for j in range(32)]
assert f52c0(0) == 0
import random
for _ in range(5):
    x = random.getrandbits(32); y = 0
    for j in range(32):
        if x >> j & 1:
            y ^= cols[j]
    assert y == f52c0(x)

def apply(m, x):
    y = 0
    for j in range(32):
        if x >> j & 1:
            y ^= m[j]
    return y

# invert the 32x32 GF(2) matrix via Gauss-Jordan elimination
rows = [[cols[j] >> i & 1 for j in range(32)] for i in range(32)]
A = [rows[i][:] + [1 if i == k else 0 for k in range(32)] for i in range(32)]
for c in range(32):
    p = next(r for r in range(c, 32) if A[r][c]); A[c], A[p] = A[p], A[c]
    for r in range(32):
        if r != c and A[r][c]:
            A[r] = [x ^ y for x, y in zip(A[r], A[c])]
invm = [sum(A[i][32 + j] << i for i in range(32)) for j in range(32)]

def mcinv(s):
    out = b''
    for i in range(0, 16, 4):
        w = int.from_bytes(s[i:i + 4], 'little')
        out += apply(invm, w).to_bytes(4, 'little')
    return out

def forward(inp):
    s = list(inp)
    for r in range(4):
        s = [SBOX_INV[b] for b in s]
        s = [s[P[i]] for i in range(16)]
        w = b''.join(f52c0(int.from_bytes(bytes(s[i:i + 4]), 'little')).to_bytes(4, 'little') for i in range(0, 16, 4))
        s = [w[i] ^ K[r][i] for i in range(16)]
    return bytes(s)

# invert the 4 rounds (reverse order) to recover the 16-byte unlock input
# that forward() maps onto the fixed target block T.
s = bytes(T)
for r in range(3, -1, -1):
    s = bytes(a ^ b for a, b in zip(s, K[r]))
    s = mcinv(s)
    u = [0] * 16
    for i in range(16):
        u[P[i]] = s[i]
    s = bytes(SBOX[b] for b in u)

print('input', s.hex())
assert forward(s) == T
open('sol.txt', 'w').write(s.hex())
