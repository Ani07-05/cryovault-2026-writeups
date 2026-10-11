# leaky-eval -- Crypto

**Flag:** `isfcr{n3g4cycl1c_n01s3_l34k}`
**Tools:** Python 3, numpy
**Scripts:** `solve.py` is a reconstruction of the original `s.py` (same attack, same inputs).

## Enumeration

Ring-LWE style decryption oracle (`b = a*s + e` under negacyclic polynomial multiplication mod `Q`,
`N=64`). On decrypting an attacker-chosen ciphertext it returns the plaintext plus a "little something
extra": one coefficient of the error polynomial `e`, `leak = e[idx]`, with `idx` also disclosed.

## Analysis

The leak is exact, not rounded. Since `e = b - a*s`, each `(a, b, idx, leak)` sample gives one exact
linear equation mod `Q` in the 64 unknown coefficients of `s`. 72 recorded samples for 64 unknowns is
already enough for plain Gaussian elimination -- no lattice reduction or noise handling needed.

Row for sample `idx`: `c_j = a[idx-j]` for `j<=idx`, else `-a[idx-j+N]` (mod `Q`), RHS `b[idx]-leak`.

## Exploit

```
$ python3 solve.py
```

Solved the 72x64 linear system mod `Q` directly; `s` came back ternary (`{-1,0,1}` coefficients), exactly
as key-generation would produce. `sha256(s)` is the AES-GCM key; the tag verified on decrypt.

## Flag

`isfcr{n3g4cycl1c_n01s3_l34k}`
