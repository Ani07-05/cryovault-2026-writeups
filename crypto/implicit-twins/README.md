# implicit-twins -- Crypto

**Flag:** `isfcr{1mpl1c1t_f4ct0r1ng_0f_tw1ns}`
**Tools:** Python 3 (plain integer arithmetic, no external lattice library needed)
**Scripts:** `solve.py` is a reconstruction of the original `t.py` (same attack).

## Enumeration

Two 1280-bit RSA public keys `N1, N2` (`e=65537`) and one ciphertext, framed as "two keys separated at
birth. Neither of them will talk alone."

## Analysis

Classic implicit factoring (May-Ritzenhofen): `p1` and `p2` share their low 530 bits (`low`), so
`N1 = low*q1 (mod 2^530)` and `N2 = low*q2 (mod 2^530)`, giving `N2*q1 = N1*q2 (mod 2^530)`. That places
`(q1, q2)` in a rank-2 lattice `{(x,y): x = N1*N2^-1*y mod 2^530}` of determinant `2^530`, whose shortest
vector (~`2^265`) comfortably bounds the 256-bit `q1`/`q2` -- small enough for plain 2D Gauss (Lagrange)
reduction, no `fpylll` needed.

## Exploit

```
$ python3 solve.py
```

Reduced the `(c,1)`/`(M,0)` basis with Gauss reduction and checked the short vector against
`N1 % q1 == 0`. Got `q1` directly, `p1 = N1/q1`, derived the RSA private exponent `d`, and decrypted the
ciphertext -- clean ASCII output confirmed the factoring was correct.

## Flag

`isfcr{1mpl1c1t_f4ct0r1ng_0f_tw1ns}`
