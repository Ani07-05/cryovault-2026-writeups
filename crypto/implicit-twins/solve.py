"""Implicit factoring (May-Ritzenhofen): p1, p2 share their low 530 bits,
so (q1, q2) sit in a 2D lattice of determinant 2^530 -- small enough for
plain Gauss (Lagrange) lattice reduction to recover directly.
"""
import json

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

SHARED_BITS = 530
M = 1 << SHARED_BITS


def gauss_reduce(u, v):
    while True:
        if dot(u, u) < dot(v, v):
            u, v = v, u
        mu = round(dot(u, v) / dot(v, v))
        if mu == 0:
            return u, v
        u = sub(u, scal(mu, v))


def dot(a, b):
    return a[0] * b[0] + a[1] * b[1]


def sub(a, b):
    return (a[0] - b[0], a[1] - b[1])


def scal(k, a):
    return (k * a[0], k * a[1])


def main():
    d = json.load(open('output.json'))
    N1, N2, e, ct = d['N1'], d['N2'], 65537, bytes.fromhex(d['ct'])

    c = (N1 * pow(N2, -1, M)) % M
    u, v = (c, 1), (M, 0)
    u, v = gauss_reduce(u, v)

    for cand in (u, v, (abs(u[0]), abs(u[1])), (abs(v[0]), abs(v[1]))):
        q1 = cand[0]
        if q1 > 1 and N1 % q1 == 0:
            break
    else:
        raise RuntimeError('lattice reduction did not surface q1')

    p1 = N1 // q1
    phi = (p1 - 1) * (q1 - 1)
    priv = RSA.construct((N1, e, pow(e, -1, phi)))
    pt = PKCS1_OAEP.new(priv).decrypt(ct)
    print(pt.decode())


if __name__ == '__main__':
    main()
