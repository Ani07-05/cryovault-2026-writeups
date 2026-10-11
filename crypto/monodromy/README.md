# Monodromy -- Crypto

**Tools:** Python, C (baby-step giant-step), WSL, Argon2 (seal.py harness)
**Scripts:** Original scripts recovered from the session scratchpad: `bsgs.c`, `seal.py`, `build.py`, `an.py`, `red.py`.
**Flag:** `isfcr{m0n0dr0my_r3v34ls_th3_h1dd3n_0rd3r}` (see note below)

## Enumeration

monodromy (Linux x86-64 ELF) + capsule.bin: "two instruments crossed the same loop, yet their readings no longer align." The recovery terminal (seal.py) accepts one rotation index recovered from the instrument's sealed tape; the archive forces a local restoration computation before revealing the record.

## Analysis

monodromy reads capsule.bin and replays each of two 600,064-entry tapes into an 8x8 matrix over F_p (p ~ 5.19e37), then checks A^k = B for the typed index k. Rebuilt A and B independently in Python and matched the binary's own memory byte for byte. A's characteristic polynomial splits into six linear factors and one irreducible quadratic; the quadratic has norm 1, and its root has prime order q = 714595551230081, which divides p+1 -- reducing the whole problem to a discrete log in a group of only ~7.1e14 elements.

## Exploit

Solved that discrete log with a baby-step/giant-step search written in C (~33 seconds runtime), recovering rotation index 323320369822980. Ran ./monodromy with that index, which printed "Index accepted. Derive the work seed and open the capsule." Then ran:
  python3 -I seal.py 323320369822980 capsule.bin
which performs an Argon2 key-derivation step (CPU/RAM heavy, took roughly 30+ minutes) and, on success, decrypts and prints the flag directly; a wrong index would instead fail with a decryption error rather than printing isfcr{...}.

## Verification

seal.py's own decrypt-or-fail behaviour confirmed correctness: it printed the flag rather than erroring out.
