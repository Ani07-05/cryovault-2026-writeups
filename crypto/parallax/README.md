# Parallax -- Crypto

**Tools:** Python, LLL lattice reduction, Kannan embedding (closest-vector problem), ChaCha20-Poly1305
**Scripts:** Original scripts recovered from the session scratchpad: `s1.py`, `s2.py`, `s3.py`, `s4.py`, `s5.py`, `s6.py`.
**Flag:** `isfcr{sh0rt_sh4d0ws_r3v34l_d3pth42}` (see note below)

## Enumeration

model.py + observations.json: "the observatory kept forty silhouettes of one sealed object... the shadows were cast by the same fourteen angles." 40 noisy quadratic measurements of 14 unknown 56-bit "limb" values modulo a prime p.

## Analysis

Recognised the 40 samples as subset sums of 14 unknown "atoms" taken mod p, with the selection mask and some quadratic cross-terms also hidden. Built the lattice of integer vectors w such that w . s = 0 (mod p); LLL-reducing it produced 26 short kernel vectors, whose orthogonal complement is a 14-dimensional lattice.

## Exploit

1. Mask recovery: enumerated 0/1 vectors in that 14-dim lattice -- found exactly 14,    with weights ranging 12 through 25, giving the hidden selection mask's columns in    weight order.
2. Atom recovery: solved the 40 (now-linear) equations mod p for the 14 atoms; all 40    were mutually consistent.
3. Quadratic cancellation: the quadratic coefficient matrix Q has low rank -- LLL found    8 tiny integer combinations w (entries <= 4) with w^T Q = 0 mod p. Applying those    combinations left 8 purely linear equations in the 4 true limb values, with residual    noise of only about 2^188 (small relative to p).
4. Final solve: ran a small closest-vector problem via Kannan embedding on those 8    equations, recovering all four 56-bit limbs exactly.
Fed the recovered limbs into open_seal() in model.py, which derives a ChaCha20-Poly1305 key from them and decrypts the sealed message.

## Verification

The ChaCha20-Poly1305 authentication tag verified on open, confirming the recovered limbs were exactly correct.
