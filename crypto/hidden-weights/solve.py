"""Nguyen-Stern attack on a hidden-subset-sum style knapsack: LLL on the
kernel lattice of v.h=0 (mod M) surfaces vectors orthogonal to every hidden
0/1 row of X; LLL+enumeration on their integer kernel recovers the rows
themselves.
"""
import json
from hashlib import sha256

import numpy as np
from Crypto.Cipher import AES
from fpylll import GSO, IntegerMatrix, LLL, Enumeration, EvaluatorStrategy


def kernel_lattice(h, M):
    """Basis for {v in Z^(n+1) : v[:n].h = 0 (mod M)}, as the standard
    (n+1)-dim lattice [[I_n | h^T], [0 | M]]. LLL on this surfaces the
    short vectors orthogonal to h mod M."""
    n = len(h)
    B = IntegerMatrix(n + 1, n + 1)
    for i in range(n):
        B[i, i] = 1
        B[i, n] = h[i]
    B[n, n] = M
    return B


def solve_linear_mod(rows, rhs, M):
    """Solve alpha . rows = rhs (mod M) by rational least squares then
    rounding -- valid here because alpha is known to be small/integer and
    the system is overdetermined (50 columns, 10 unknown rows)."""
    A = np.array(rows, dtype=float)
    b = np.array(rhs, dtype=float)
    sol, *_ = np.linalg.lstsq(A.T, b, rcond=None)
    return [round(x) % M for x in sol]


def main():
    d = json.load(open('output.json'))
    h, M = d['h'], d['M']
    n = len(h)

    B = kernel_lattice(h, M)
    LLL.reduction(B)
    # rows with a zero in the last column are exactly the v with v.h = 0 mod M
    kernel_vectors = [list(B[i])[:-1] for i in range(n + 1) if list(B[i])[-1] == 0]

    orth = IntegerMatrix.from_matrix(kernel_vectors)
    LLL.reduction(orth)

    G = GSO.Mat(orth)
    G.update_gso()
    en = Enumeration(G, strategy=EvaluatorStrategy.BEST_N_SOLUTIONS)
    candidates = en.enumerate(0, orth.nrows, n, 0)  # squared-norm bound <= n

    X_rows, seen = [], set()
    for _, v in candidates:
        v = list(v)
        for w in (v, [-x for x in v]):
            key = tuple(w)
            if all(x in (0, 1) for x in w) and any(w) and key not in seen:
                seen.add(key)
                X_rows.append(w)
    X_rows = X_rows[:10]
    assert len(X_rows) == 10, f'only recovered {len(X_rows)}/10 rows'

    alpha = solve_linear_mod(X_rows, h, M)

    key = sha256(bytes(sorted(alpha))).digest()
    nonce, ct, tag = (bytes.fromhex(d[k]) for k in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
