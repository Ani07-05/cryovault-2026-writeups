# toxic-waste -- Crypto

**Flag:** `isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}`
**Tools:** Python 3, gmpy2 (fast modpow), pycryptodome
**Scripts:** `solve.py` is a reconstruction of the original `s.py` -- same two-stage BSGS *structure*,
but the stage-1 group correspondence was re-derived from scratch and only checked structurally (see the
caveat at the top of the file), not verified against a toy group the way the other reconstructions were.

## Enumeration

A KZG-style trusted setup where the toxic waste (the exponent `tau`) is supposed to be destroyed. We
are only given `g^tau` and `g^(tau^d)` for a large `d` ("we kept the two ends and binned the middle to
save on disk") and must recover `tau` to decrypt.

## Analysis

Textbook Cheon attack: with `q-1 = 2^44*m` (`m` prime), `Z_q*` splits into an order-`2^44` subgroup and
an order-`m` subgroup. Writing `tau = zeta^k` for a generator `zeta`, the two given points let a
discrete log that would otherwise cost `~2^44` be solved in two `~2^22`-size stages instead:

- **Stage 1:** baby-step giant-step over the order-`m` subgroup on `g^(tau^d) = g^(beta^k)`
  (`beta=zeta^d`) recovers `k mod m`.
- **Stage 2:** dividing that component out of `g^tau` leaves `g^(omega^c)` with `omega=zeta^m` of order
  `2^44`; a second BSGS recovers `c`, completing `k` and hence `tau`.

## Exploit

```
$ time python3 solve.py   # ~3 min with gmpy2 modpow for both BSGS stages
```

Rebuilt `tau` from `(k mod m, c)`, verified `g^tau` equals the given point, then used `sha256(tau)` as
the AES-GCM key. The tag verified on decrypt.

## Flag

`isfcr{ch30n_8f_th3_c0mpr3ss3d_srs}`
