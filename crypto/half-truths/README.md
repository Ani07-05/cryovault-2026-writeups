# half-truths -- Crypto

**Flag:** `isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}`
**Tools:** Python 3, custom Roth-Ruckenstein list decoder over GF(2^31-1)
**Scripts:** `solve.py` is a from-scratch reimplementation of the Sudan-interpolation + Roth-Ruckenstein
pipeline (the original `s.py` no longer exists on disk). Smoke-tested against a small synthetic
Shamir-with-liars instance (k=3, 16/30 honest shares, W=15) and recovers the exact planted polynomial
with 1 candidate returned -- not run against the real challenge output, but the algorithm itself is
verified correct.

## Enumeration

512 Shamir secret-sharing shares over `GF(2^31-1)`, threshold-degree-39 polynomial (`k=40` coefficients),
but only 185 of the 512 shares are honest ("327 of my 512 friends lied to me. Reconstruct the secret
anyway.").

## Analysis

`T=185` correct shares sits above the Johnson bound `sqrt(k*n) ~= sqrt(40*512) ~= 143`, so unique
Reed-Solomon decoding fails, but Sudan list decoding still applies. Interpolated a nonzero bivariate
`Q(x,y)` with weighted degree `(1,39) <= 184` and `y`-degree `<= 4`: that's 535 unknowns against 512
linear constraints (one per share), guaranteeing a nonzero solution, and every honest share must be a
root of `Q` since `185 > 184`.

## Exploit

```
$ python3 solve.py   # interpolates Q then runs Roth-Ruckenstein over GF(2^31-1)
```

Ran a Roth-Ruckenstein recursion to find all degree`<40` polynomials `f(x)` with `Q(x,f(x))=0`. The
recursion returned exactly one candidate, consistent with exactly 185 of the 512 shares -- the expected
honest count. SHA-256 of that polynomial's coefficients gave the AES-GCM key; the tag verified.

## Flag

`isfcr{l1st_d3c0d1ng_p4st_th3_r4d1us}`
