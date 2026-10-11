# one-more -- Crypto

**Flag:** `isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}`
**Points:** 500
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A blind Schnorr signing service over secp256k1 that answers each session's `sign` exactly once and lets you win if you return more valid signatures than challenges answered. This is the textbook **ROS attack** (Benhamouda et al., Eurocrypt 2021): open 256 parallel sessions and linearly combine them to forge a 257th signature from 256 answers.

## Solution

### Step 1: Understand the win condition

On connect the server sends `X <pubkey>` (fresh key per connection). `open` returns a session id and nonce point `R=rG`; `sign <id> <c>` answers each session **once** with `s = r + c·x mod n`; `submit` then a JSON array of `[msg_hex, Rx, Ry, s]`. A signature `(R,s)` on `m` is valid iff `s·G == R + H(R,m)·X` with `H(R,m)=SHA256(x‖y‖m) mod n`. You win when `good > answered`.

### Step 2: ROS linear-combination forgery

Open `L=256` sessions. For each session `i` prepare two candidate messages with challenges `e⁰ᵢ=H(Rᵢ,m⁰ᵢ)`, `e¹ᵢ=H(Rᵢ,m¹ᵢ)`. Choose `aᵢ = 2^(i-1)·(e¹ᵢ−e⁰ᵢ)⁻¹ mod n` so that picking bit `bᵢ` adds exactly `bᵢ·2^(i-1)` to `Σ aᵢeᵢ`. Set `R* = Σ aᵢRᵢ`, `c* = H(R*, m*)`, and read the 256 bits off `(c* − Σ aᵢe⁰ᵢ) mod n` (which is `< n < 2^256`, so the bit-decomposition is exact). Feed `e^{bᵢ}ᵢ` to each session, collect the 256 `sᵢ`, and the 257th signature is `(R*, s*=Σ aᵢsᵢ)` on a fresh message — valid because the combination lands exactly on the forged challenge. Live service replied `valid 257 answered 256`.

```python
#!/usr/bin/env python3
"""ROS / Benhamouda-et-al. one-more forgery against the blind Schnorr service."""
import sys, json, hashlib, asyncio
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

G = SECP256k1.generator
N = int(SECP256k1.order)
CURVE = SECP256k1.curve
L = 256

def ser(P):
    return int(P.x()).to_bytes(32, "big") + int(P.y()).to_bytes(32, "big")

def H(Rpt, m):
    return int.from_bytes(hashlib.sha256(ser(Rpt) + m).digest(), "big") % N

def parse_R(hexstr):
    b = bytes.fromhex(hexstr)
    return Point(CURVE, int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big"))

def build(X, Rs):
    """Given pubkey point X and L nonce points Rs, return challenges to send and
    a finalize(s_list) -> submission payload."""
    m0 = [b"reg0-%d" % i for i in range(L)]
    m1 = [b"reg1-%d" % i for i in range(L)]
    e0 = [H(Rs[i], m0[i]) for i in range(L)]
    e1 = [H(Rs[i], m1[i]) for i in range(L)]
    a  = [pow((e1[i]-e0[i]) % N, -1, N) * pow(2, i, N) % N for i in range(L)]
    Rstar = Rs[0] * a[0]
    for i in range(1, L):
        Rstar = Rstar + Rs[i] * a[i]
    mstar = b"EXTRA-one-more"
    cstar = H(Rstar, mstar)
    C0 = sum(a[i]*e0[i] for i in range(L)) % N
    target = (cstar - C0) % N            # equals sum b_i 2^(i-1) exactly (target<N<2^256)
    bits = [(target >> i) & 1 for i in range(L)]
    chals = [e1[i] if bits[i] else e0[i] for i in range(L)]
    msgs  = [m1[i] if bits[i] else m0[i] for i in range(L)]

    def finalize(s_list):
        sigs = []
        for i in range(L):
            sigs.append([msgs[i].hex(), int(Rs[i].x()), int(Rs[i].y()), int(s_list[i]) % N])
        sstar = sum(a[i]*s_list[i] for i in range(L)) % N
        sigs.append([mstar.hex(), int(Rstar.x()), int(Rstar.y()), sstar])
        assert G*(sstar % N) == Rstar + X*cstar, "extra sig fails local check"
        return sigs
    return chals, finalize

async def live(url):
    from websockets.asyncio.client import connect
    async with connect(url, max_size=None, ping_interval=20, open_timeout=60) as ws:
        X = parse_R((await ws.recv()).split()[1])
        Rs = []
        for i in range(L):
            await ws.send("open")
            Rs.append(parse_R((await ws.recv()).split()[3]))
        chals, finalize = build(X, Rs)
        s_list = []
        for i in range(L):
            await ws.send(f"sign {i} {chals[i]}")
            s_list.append(int((await ws.recv()).split()[1]))
        sigs = finalize(s_list)
        await ws.send("submit")
        await ws.send(json.dumps(sigs))
        print("LIVE:", await ws.recv())
        try:
            print("LIVE:", await asyncio.wait_for(ws.recv(), 5))
        except Exception:
            pass

if __name__ == "__main__":
    asyncio.run(live(sys.argv[1]))   # python3 onemore.py wss://one-more.isfcr.xyz
```
