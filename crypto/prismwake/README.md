# Prismwake -- Crypto

**Flag:** `isfcr{pr0j3ct1v3_sh4d0ws_c0nc34l_gr0up_l4w}`
**Tools:** Python 3, sympy, custom Mersenne Twister state-recovery/rewind code
**Scripts:** `solve.py` is a structural sketch of the real attack -- the full MT state-recovery and EC
ladder code ran across several scratchpad files (`mt.py`, `ec.py`, `clone_helpers.py`, `rewind*.py`)
that no longer exist on disk. The steps below are the actual method used.

## Enumeration

Given `model.py` and `observations.json`: 6000 observed `x`-coordinates `Y[i]` on a curve
`E: Y^2 = X^3 + curve_b` over `F_p`, each claimed to be `x([multiplier[i]] * K)` for a fixed hidden
point `K` and 6000 public integer multipliers. "Its instruments agree on the motion, but the
coordinate marks do not belong to the sky they describe" -- the multipliers are not what they look like.

```
$ cat "model (2).py"; head -c 1500 "observations (2).json"
```

## Analysis

1. **Curve check.** `p = 2 mod 3` and `p+1 = 6n` -- the curve is supersingular. Tried every direct
   algebraic relation between multipliers (sums, ratios, products, squares) looking for a linear
   dependency to exploit -- nothing usable.
2. **The weak point was the RNG, not the curve.** Subtracting 1 from each multiplier and splitting it
   into 32-bit words satisfies the Mersenne Twister (`MT19937`) recurrence 234 times in a row. The
   multipliers are not random integers -- they're the raw output stream of Python's
   `random.randrange(1, n)`.
3. **Rebuilt the generator's internal state.** Placed each multiplier at its position in the output
   stream, recovered the (partially-masked) third 32-bit word of each draw, and filled every gap with
   the MT recurrence. That gave ~18k consecutive known state words with no contradictions. 70
   multipliers didn't fit the stream directly -- their draws happened but the *values* were swapped
   out; they still satisfy the curve relation, so they're a trap against naive brute-forcing rather than
   genuine stream output.
4. **Rewound the generator** past its 624-word seed window to the three draws made just before the
   first multiplier -- these are the coefficients of a Mobius map `L(y) = (u*y + v) / (w*y + 1)` used to
   mask the real x-coordinates:
   - `u = 34559716604220687612953322102`
   - `v = 48772199007751653754816185446`
   - `w = 22589791273467761145953217267`

## Exploit

`x_K = x([m0^-1] * L(y0))`, where `y0 = Y[0]` and `m0 = multiplier[0]`. Computed via the EC
Montgomery-ladder `x`-only scalar multiplication (works even on the supersingular curve, no need for
full point arithmetic):

```
$ v/bin/python - <<'EOF'
from ec import *
Lx = lambda y: (u*y + v) * pow((w*y + 1) % p, -1, p) % p
xK = aff(ladder(pow(M[0], -1, n), Lx(Y[0])))
good = [aff(ladder(M[i], xK)) == Lx(Y[i]) for i in range(6000)]
print('xK', xK, 'match', sum(good))
EOF
```

`xK = 32469388776030518256910525566` and all 6000 readings matched `x([m_i] * K)` under the recovered
map, including the 70 planted ones (confirming they really do sit on the curve relation, they just
weren't part of the exploitable RNG stream). Fed `xK` into `open_seal()` from the provided model file,
which returned the flag.

## Flag

`isfcr{pr0j3ct1v3_sh4d0ws_c0nc34l_gr0up_l4w}`
