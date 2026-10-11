"""Sudan list decoding for Shamir shares with far more liars than the
Johnson bound allows for unique decoding: interpolate a bivariate Q(x,y) of
weighted degree (1, k-1) that every honest share must satisfy, then run
Roth-Ruckenstein to recover f(x) directly.

k = 40 (polynomial degree 39), weighted-degree bound W = 184, y-degree <= 4.
535 monomials x^i y^j (i + 39*j <= 184, 0<=j<=4) against 512 linear
constraints -- guaranteed a nontrivial null-space vector.
"""
import json
from hashlib import sha256
from math import comb

from Crypto.Cipher import AES
from flint import nmod_poly

K = 40          # polynomial has k=40 coefficients (degree 39)
W = 184         # weighted-degree bound: i + (K-1)*j <= W
DY = 4          # y-degree bound


def monomials():
    mons = []
    for j in range(DY + 1):
        i_max = W - (K - 1) * j
        for i in range(i_max + 1):
            mons.append((i, j))
    return mons


def rref_mod(matrix, p):
    """In-place modular row reduction. Returns (rref, pivot_cols)."""
    rows, cols = len(matrix), len(matrix[0])
    pivot_cols = []
    r = 0
    for c in range(cols):
        piv = next((i for i in range(r, rows) if matrix[i][c] % p != 0), None)
        if piv is None:
            continue
        matrix[r], matrix[piv] = matrix[piv], matrix[r]
        inv = pow(matrix[r][c], -1, p)
        matrix[r] = [(x * inv) % p for x in matrix[r]]
        for i in range(rows):
            if i != r and matrix[i][c] % p != 0:
                f = matrix[i][c]
                matrix[i] = [(matrix[i][k] - f * matrix[r][k]) % p for k in range(cols)]
        pivot_cols.append(c)
        r += 1
        if r == rows:
            break
    return matrix, pivot_cols


def null_space_vector(matrix, p):
    """One nontrivial null-space vector of `matrix` over GF(p)."""
    rows, cols = len(matrix), len(matrix[0])
    rref, pivots = rref_mod([row[:] for row in matrix], p)
    pivot_set = set(pivots)
    free_cols = [c for c in range(cols) if c not in pivot_set]
    assert free_cols, 'matrix has full column rank -- no nontrivial solution'
    free = free_cols[0]

    vec = [0] * cols
    vec[free] = 1
    for r, pc in enumerate(pivots):
        vec[pc] = (-rref[r][free]) % p
    return vec


def interpolate_Q(shares, p):
    mons = monomials()
    matrix = [[pow(x, i, p) * pow(y, j, p) % p for (i, j) in mons] for (x, y) in shares]
    coeffs = null_space_vector(matrix, p)
    Q = {mon: c for mon, c in zip(mons, coeffs) if c % p != 0}
    return Q


def shift_and_divide(Q, r, p):
    """Substitute y -> r + x*y1 into Q, then divide the result by x (valid
    because r is a root of Q(0, y), which forces the x^0 term to vanish)."""
    new = {}
    for (i, j), c in Q.items():
        for t in range(j + 1):
            ct = (c * comb(j, t) * pow(r, j - t, p)) % p
            key = (i + t, t)
            new[key] = (new.get(key, 0) + ct) % p

    assert new.get((0, 0), 0) % p == 0, 'r is not a root of Q(0, y)'
    divided = {(i - 1, j): c for (i, j), c in new.items() if i > 0 and c % p != 0}
    return divided


def roots_in_y(Q, p):
    max_j = max((j for (_, j) in Q), default=0)
    coeffs = [Q.get((0, j), 0) % p for j in range(max_j + 1)]
    if all(c == 0 for c in coeffs):
        return []
    poly = nmod_poly(coeffs, p)
    return [int(r) for r, _ in poly.roots()]


def roth_ruckenstein(Q, p, max_degree):
    results = []

    def recurse(Q, prefix):
        if len(prefix) == max_degree:
            # f is fully determined; the remaining y stands for coefficients
            # beyond the degree bound, implicitly fixed at 0 -- so only the
            # j=0 (pure-x) slice of Q has to vanish identically, not all of Q.
            if all(c % p == 0 for (i, j), c in Q.items() if j == 0):
                results.append(prefix)
            return
        for r in roots_in_y(Q, p):
            try:
                Q2 = shift_and_divide(Q, r, p)
            except AssertionError:
                continue
            recurse(Q2, prefix + [r])

    recurse(Q, [])
    return results


def main():
    d = json.load(open('output.json'))
    p, shares = d['p'], [(s['x'], s['y']) for s in d['shares']]

    Q = interpolate_Q(shares, p)
    candidates = roth_ruckenstein(Q, p, K)

    def agreement(f_coeffs):
        f = nmod_poly(f_coeffs, p)
        return sum(1 for x, y in shares if int(f(x)) == y % p)

    best = max(candidates, key=agreement)
    assert agreement(best) >= 185, 'best candidate does not match enough shares'

    key = sha256(b''.join(c.to_bytes(4, 'big') for c in best)).digest()
    nonce, ct, tag = (bytes.fromhex(d[k]) for k in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
