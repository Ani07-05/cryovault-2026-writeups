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
