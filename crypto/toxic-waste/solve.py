"""Cheon's attack on a KZG-style trusted setup: q-1 = 2^E1 * m (m prime)
splits Z_q* into an order-2^E1 and an order-m subgroup, so the discrete log
of tau is recovered in two ~sqrt(max(2^E1,m))-size baby-step-giant-step
stages instead of one full-size one, then CRT-combined into tau mod (q-1).

CAVEAT: this file sketches the two-BSGS-stage *structure* of the real
attack (confirmed against the session's own write-up of the method), but
the exact group-theoretic correspondence between B=g^(tau^d) and an
order-m element -- which depends on d's relationship to 2^E1 under the
Z_(q-1) ~= Z_m x Z_(2^E1) CRT isomorphism -- was re-derived from scratch
here and only checked structurally, not against a toy group. The original
ephemeral solve script (which worked against the real challenge output)
no longer exists on disk. Treat the stage-1/stage-2 BSGS calls below as
illustrative of the approach, not a drop-in verified solver.
"""
import json
from hashlib import sha256
from math import gcd

import gmpy2
from Crypto.Cipher import AES

E1 = 44  # q - 1 = 2^E1 * m


def bsgs(g, h, order, q):
    """Discrete log of h base g inside a subgroup of the given order, mod q."""
    m = int(gmpy2.isqrt(order)) + 1
    table = {}
    e = gmpy2.mpz(1)
    for j in range(m):
        table[int(e)] = j
        e = (e * g) % q
    factor = gmpy2.powmod(gmpy2.invert(g, q), m, q)
    e = gmpy2.mpz(h)
    for i in range(m):
        if int(e) in table:
            return i * m + table[int(e)]
        e = (e * factor) % q
    raise ValueError('bsgs failed to find a match')


def crt(r1, m1, r2, m2):
    """Combine x = r1 (mod m1), x = r2 (mod m2) into x mod m1*m2 (gcd(m1,m2)=1)."""
    assert gcd(m1, m2) == 1
    m1_inv = pow(m1, -1, m2)
    x = r1 + m1 * (((r2 - r1) * m1_inv) % m2)
    return x % (m1 * m2)


def main():
    d = json.load(open('output.json'))
    q, g = d['q'], d['g']
    A, B, dexp = d['A'], d['B'], d['d']  # A = g^tau, B = g^(tau^d)
    order_small = 1 << E1
    order_m = (q - 1) // order_small

    # Stage 1: on the order-m subgroup, B = g^(tau^d) = (g^tau)^(tau^(d-1))...
    # concretely: let beta = g^d (order m); B = beta^k where tau = zeta^k.
    beta = gmpy2.powmod(g, dexp, q)
    k_mod_m = bsgs(beta, B, order_m, q)

    # Stage 2: dividing the order-m component out of A = g^tau leaves the
    # order-2^E1 component; a second BSGS on that recovers k mod 2^E1.
    omega = gmpy2.powmod(g, order_m, q)
    g_k_mod_m_component = gmpy2.powmod(g, k_mod_m, q)
    A_reduced = (gmpy2.mpz(A) * gmpy2.invert(g_k_mod_m_component, q)) % q
    k_mod_small = bsgs(omega, A_reduced, order_small, q)

    k = crt(k_mod_small, order_small, k_mod_m, order_m)
    tau = gmpy2.powmod(g, k, q)  # not needed for the key -- sha256 uses k directly below
    assert gmpy2.powmod(g, k, q) == int(A) % q, 'recovered k does not reproduce A = g^tau'

    key = sha256(str(k).encode()).digest()
    nonce, ct, tag = (bytes.fromhex(d[kk]) for kk in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
