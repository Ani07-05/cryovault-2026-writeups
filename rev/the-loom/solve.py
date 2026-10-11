import struct
b = open('loom/chall', 'rb').read()
A = struct.pack('<4Q', 0x3e9d1e0e41ab9680, 0xae5c2dba59ecec09,
                0xc0a1574c6494a721, 0x5b8c9c0974ee8ed2)
B = b[0x1340:0x1360]
M = (1 << 256) - 1
rl = lambda x, k: ((x << k) | (x >> (256-k))) & M
rr = lambda x, k: rl(x, 256-k)
def f(x):
    c = rl(x, 2); s = rl(x, 1); e = x; b1 = rr(x, 1); r = rr(x, 2)
    return (e & c) ^ s ^ b1 ^ (s & b1) ^ (e & r) ^ (c & r)
hi = int.from_bytes(A, 'little')    # x_N
lo = int.from_bytes(B, 'little')    # x_{N-1}
for _ in range(1000003):
    hi, lo = lo, f(lo) ^ hi
print(hex(lo))                       # -> 0x0
print(hi.to_bytes(32, 'little'))     # -> flag bytes
