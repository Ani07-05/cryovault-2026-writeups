# free-lunch -- Crypto

**Flag:** `isfcr{b4ckw4rds_1s_h4lf_th3_d3gr33}`
**Tools:** Python 3, python-flint (finite-field polynomial gcd/roots), pycryptodome
**Scripts:** `solve.py` is a reconstruction of the original `f.py` (same attack).

## Enumeration

A 20-round CICO (constrained-input constrained-output) permutation over a prime field `GF(p)` built from
a degree-3 S-box per round ("there is no free lunch, but there is a cube root -- twenty of them"). The
forward relation is degree `3^20` in the unknown input -- far too large to invert directly.

## Analysis

Ran the permutation backward instead of forward: the inverse round
`x_(i-1) = x_(i+1)^3 - x_i - c_i` needs no cube roots (unlike the forward direction). Starting from
`(x_R, x_(R-1)) = (t, 0)` with free variable `t` and unwinding all 20 rounds gives one polynomial `F(t)`
of degree `3^10 = 59049`, after forcing the final value `x_(-1) = 0`.

## Exploit

```
$ python3 solve.py
```

Computed `gcd(F(t), t^p - t)` to isolate `F`'s linear factors over `GF(p)`, split them with
`python-flint`'s `roots()`, and verified each candidate by re-running the real (forward) permutation.
Got exactly 2 valid CICO solutions; took the smaller, `1093395384440720767`, hashed its decimal string
with SHA-256 for the AES-GCM key. The tag verified.

## Flag

`isfcr{b4ckw4rds_1s_h4lf_th3_d3gr33}`
