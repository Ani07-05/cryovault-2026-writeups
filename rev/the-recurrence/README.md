# The Recurrence -- Reverse

**Flag:** `isfcr{p0hlig_h3llman_sm00th}`
**Points:** 500
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A stripped x86-64 ELF reads 28 bytes as a 224-bit integer `n`, computes the n-th term of a Lucas sequence `Vₙ(P,1) mod p` via a Montgomery ladder, and compares to a stored target `T`. Recovering `n` is a discrete log in `F_p`; because `p−1` is smooth, Pohlig–Hellman solves it instantly and the 28 little-endian bytes of `n` are the flag.

## Solution

### Step 1: Recognise the Lucas-sequence DLP

The binary computes `Vₙ`: `V₀=2, V₁=P`, each next term from the previous two, all mod a 247-bit prime `p` (`P`, `p`, `T` are 256-bit constants in `.rodata` at `0x401260`). Closed form: `Vₙ = αⁿ + α⁻ⁿ` where `α` is a root of `x² − Px + 1 mod p`. So recovering `n` is a discrete log `αⁿ = β`, with `β` a root of `x² − Tx + 1`.

### Step 2: Pohlig–Hellman

`(P²−4)` is a QR mod p (Legendre = 1), so `α` lives in `F_p`; and `p−1` factors into only small primes (all < 60k), so Pohlig–Hellman solves the DLP instantly. Of the candidate exponents, only the one fitting in 224 bits is valid; its little-endian bytes are the flag. Piping into `./chall` prints `CORRECT -- the flag is the input you just gave me.`

```python
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
```
