# hidden-weights -- Crypto

**Flag:** `isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}`
**Tools:** Python 3, fpylll (LLL + enumeration), cysignals, pycryptodome, run via `uv run --with`
**Scripts:** `solve.py` is a reconstruction of the original `h.py` (same attack).

## Enumeration

A hidden subset-sum problem: 50 secret 0/1 weight vectors (rows of a matrix `X`) combined by an unknown
integer recipe `alpha` into one public total vector `h`, modulo `M`. Only `h`, `M` (and the row/column
dimensions) are public.

## Analysis

Nguyen-Stern attack on the hidden subset-sum / dense-knapsack problem:

1. Build the kernel lattice of all integer `v in Z^50` with `v.h = 0 (mod M)`.
2. LLL-reduce it -- yields the `m-n=40` shortest vectors (norm <= 3), each orthogonal to every hidden
   0/1 row of `X`, with a clean gap before the next-shortest vector (~2.5e5).

## Exploit

```
$ uv run --with fpylll --with cysignals --with pycryptodome --with numpy python3 solve.py
```

Took the integer kernel of those 40 orthogonal vectors (a 10-dimensional lattice containing the rows of
`X`), LLL-reduced again, then used fpylll's GSO/Enumeration to list short vectors (squared norm <= 50).
Enumeration returns a vector or its negation, so both signs were tested per candidate. With all 10 rows
of `X` recovered, solved `h = alpha.X (mod M)` as a linear system for the integer weights. Hashed the
sorted weights with SHA-256 for the AES-GCM key; the tag verified on decrypt.

## Flag

`isfcr{0rth0g0n4l_l4tt1c3_1s_th3_tr1ck}`
