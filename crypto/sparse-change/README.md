# Sparse-Change -- Crypto

**Tools:** Python, sympy (Berlekamp-Massey, GF(p) factoring, Pohlig-Hellman), pycryptodome (AES-GCM)
**Scripts:** Original scripts recovered from the session scratchpad: `solve.py`.
**Flag:** `isfcr{pr0ny_kn3w_1t_1n_1795}` (see note below)

## Enumeration

Given chall.py and output.json: a machine's "sweep log" is 48 numbers, log[0..47] = F(g^j) for j = 0..47 over a field GF(p), plus an AES-GCM-encrypted blob that only opens with the correct secret term list.

## Analysis

log[j] = F(g^j) = sum_i c_i * (g^{e_i})^j. That is a sparse exponential sum, i.e. a linear recurrence of order 24 whose characteristic-polynomial roots are x_i = g^{e_i}. This is exactly Prony's method (1795) for sparse polynomial interpolation.

## Exploit

Recovery pipeline (solve.py, using sympy + pycryptodome):
1. Berlekamp-Massey on the 48 samples -> order-24 connection polynomial over GF(p).
2. Factor that polynomial into 24 linear factors -> the 24 roots x_i = g^{e_i}.
3. p-1 is built from small prime factors, so Pohlig-Hellman (base g) recovers each    discrete-log exponent e_i from x_i.
4. The first 24 log entries form a Vandermonde system in the unknown coefficients c_i;    solved it directly for the sparse term list.
5. AES key = SHA-256(";".join(f"{e}:{c}" for e,c sorted by exponent)), per the    challenge's own note; used it to AES-GCM-decrypt output.json's blob.

## Verification

AES-GCM authentication tag verified on decryption, confirming the recovered term list was exactly right.
