"""Negacyclic ring-LWE 'leaky-eval': each decryption query leaks one exact
error coefficient e[idx]. 72 samples >= 64 unknowns -> solve for s by plain
Gaussian elimination mod Q (no lattice reduction needed, leak is exact).
"""
import json
from hashlib import sha256

import numpy as np
from Crypto.Cipher import AES

N = 64


def row_for(a, idx, Q):
    row = np.zeros(N, dtype=object)
    for j in range(N):
        if j <= idx:
            row[j] = a[idx - j] % Q
        else:
            row[j] = (-a[idx - j + N]) % Q
    return row


def solve_mod(A, b, Q):
    A = [row[:] for row in A]
    b = b[:]
    n = len(A[0])
    for col in range(n):
        piv = next(r for r in range(col, len(A)) if A[r][col] % Q != 0)
        A[col], A[piv] = A[piv], A[col]
        b[col], b[piv] = b[piv], b[col]
        inv = pow(int(A[col][col]), -1, Q)
        A[col] = [(x * inv) % Q for x in A[col]]
        b[col] = (b[col] * inv) % Q
        for r in range(len(A)):
            if r != col and A[r][col] % Q != 0:
                f = A[r][col]
                A[r] = [(A[r][c] - f * A[col][c]) % Q for c in range(n)]
                b[r] = (b[r] - f * b[col]) % Q
    return [b[i] for i in range(n)]


def main():
    d = json.load(open('output.json'))
    Q = d['Q']
    rows, rhs = [], []
    for s in d['samples']:
        rows.append(list(row_for(s['a'], s['idx'], Q)))
        rhs.append((s['b'][s['idx']] - s['leak']) % Q)

    s_coeffs = solve_mod(rows, rhs, Q)
    s_signed = [c if c <= Q // 2 else c - Q for c in s_coeffs]  # recenter to ternary
    key = sha256(bytes((c + 1) for c in s_signed)).digest()

    nonce, ct, tag = (bytes.fromhex(d[k]) for k in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
