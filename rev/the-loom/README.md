# The Loom -- Reverse

**Flag:** `isfcr{2nd_0rd3r_r3v_c3ll_aut0m8}`
**Points:** 498
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A stripped x86-64 ELF reads 32 bytes and runs a **second-order reversible cellular automaton** over them for 1,000,003 steps, comparing the final two states to stored constants. Because each step XORs in the state from two steps back, the recurrence is exactly invertible — load the final states and step backwards to recover the flag.

## Solution

### Step 1: Model the automaton

The 32 input bytes become a 256-bit ring `x₀` with `x₋₁ = 0`. Each step is `x_{t+1}[i] = f(x_t[i−2..i+2]) XOR x_{t−1}[i]`, where `f` is a fixed AND/XOR boolean mix of the five neighbour cells, iterated 1,000,003×. The binary stores the two final states (one in `.text` immediates, one in `.rodata` at `0x1340`).

### Step 2: Step backwards

Since `x_{t−1} = f(x_t) XOR x_{t+1}`, treat each 256-bit ring as one big integer with bit rotations and iterate backwards. The run lands on `x₋₁ = 0` (confirming correctness) and recovers `x₀` = the flag (~5 s). Piping it into `./chall` prints `CORRECT -- the flag is the input you just gave me.`

```python
import struct
b = open('loom/chall', 'rb').read()
A = struct.pack('<4Q', 0x3e9d1e0e41ab9680, 0xae5c2dba59ecec09,
                0xc0a1574c6494a721, 0x5b8c9c0974ee8ed2)
B = b[0x1340:0x1360]
M = (1 << 256) - 1
rl = lambda x, k: ((x << k) | (x >> (256-k))) & M
rr = lambda x, k: rl(x, 256-k)
def f(x):
    c = rl(x, 2); s = rl(x, 1); e = x; b1 = rr(x, 1); r = rr(x, 2)
    return (e & c) ^ s ^ b1 ^ (s & b1) ^ (e & r) ^ (c & r)
hi = int.from_bytes(A, 'little')    # x_N
lo = int.from_bytes(B, 'little')    # x_{N-1}
for _ in range(1000003):
    hi, lo = lo, f(lo) ^ hi
print(hex(lo))                       # -> 0x0
print(hi.to_bytes(32, 'little'))     # -> flag bytes
```

> Note: do not confuse with **the recurrence** (`isfcr{p0hlig_h3llman_sm00th}`) — that is a 28-byte Lucas-sequence DLP, a different challenge.
