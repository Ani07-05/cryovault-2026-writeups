"""20-round cubing-permutation CICO problem, run backward: the inverse round
x_(i-1) = x_(i+1)^3 - x_i - c_i needs no cube roots, so unwinding gives one
univariate polynomial F(t) of degree 3^10 whose roots (via gcd with t^p-t,
which kills every non-linear factor over GF(p)) are the CICO solutions.
"""
import json
from hashlib import sha256

from Crypto.Cipher import AES
from flint import nmod_poly


def unwind(p, constants, rounds=20):
    """Starting from (x_R, x_{R-1}) = (t, 0), unwind the forward round
    x_{i+1} = x_i^3 + c_i backward: x_i = x_{i+1}^3 - x_{i+2} - c_i... but
    since the recursion is in (x_i, x_{i+1}) pairs, track both polynomials
    through each inverse step and return the final x_{-1} (which must = 0).
    """
    t = nmod_poly([0, 1], p)          # F0 = t
    zero = nmod_poly([0], p)
    x_next, x_cur = t, zero           # (x_R, x_{R-1})
    for c in reversed(constants[:rounds]):
        x_prev = x_next * x_next * x_next - x_cur - nmod_poly([c], p)
        x_next, x_cur = x_cur, x_prev
    return x_cur                      # this is x_{-1}(t); roots give valid t


def t_pow_p_minus_t_mod_F(F, p):
    """t^p mod F(t), via repeated squaring (modular exponentiation of the
    polynomial t by p, reducing mod F at every step) -- never builds the
    dense degree-p polynomial t^p - t directly, since p is far too large
    for that. gcd(F, t^p mod F - t) then keeps exactly F's roots in GF(p)."""
    result = nmod_poly([0, 1], p)  # t
    base = nmod_poly([0, 1], p)
    e = p
    result = nmod_poly([1], p)
    while e:
        if e & 1:
            result = (result * base) % F
        base = (base * base) % F
        e >>= 1
    return (result - nmod_poly([0, 1], p)) % F


def forward(x0, constants):
    """Real forward round function: x_{i+1} = x_i^3 + c_i."""
    x = x0
    for c in constants:
        x = (x * x * x + c)
    return x


def main():
    d = json.load(open('output.json'))
    p, constants = d['p'], d['constants']

    F = unwind(p, constants)
    frob = t_pow_p_minus_t_mod_F(F, p)
    g = F.gcd(frob)
    candidates = [int(r) for r, _ in g.roots()]

    valid = []
    for t in candidates:
        x_final = forward(t, constants)
        if x_final == 0:  # matches the challenge's CICO output constraint
            valid.append(t)

    assert valid, 'no CICO solution survived forward verification'
    t = min(valid)

    key = sha256(str(t).encode()).digest()
    nonce, ct, tag = (bytes.fromhex(d[k]) for k in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
