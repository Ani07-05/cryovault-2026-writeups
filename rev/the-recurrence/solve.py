from sympy import factorint, isprime, legendre_symbol
from sympy.ntheory import discrete_log
from sympy import sqrt_mod, n_order

b = open('chall/chall', 'rb').read()
# locate .rodata by scanning for the marker that precedes T at 0x4012e0
def rd(addr):
    o = b.rfind(bytes.fromhex("003110f1659975bb"))
    return o + (addr - 0x4012e0)
T = int.from_bytes(b[rd(0x4012e0):rd(0x4012e0)+32], 'little')
P = int.from_bytes(b[rd(0x401300):rd(0x401300)+32], 'little')
p = int.from_bytes(b[rd(0x401320):rd(0x401320)+32], 'little')
print(hex(T), hex(P), hex(p), isprime(p))
print('legendre', legendre_symbol((P*P-4) % p, p))
print('p-1', factorint(p-1, limit=10**7))

def roots(S):
    d = sqrt_mod((S*S-4) % p, p); i2 = pow(2, -1, p)
    return [(S+d)*i2 % p, (S-d)*i2 % p]
a = roots(P)[0]; o = n_order(a, p)
for bt in roots(T):
    n = discrete_log(p, bt, a)
    for m in (n, (o-n) % o):
        bs = m.to_bytes(28, 'little') if m.bit_length() <= 224 else None
        print(m.bit_length(), bs)   # yields: 223 b'isfcr{p0hlig_h3llman_sm00th}'
