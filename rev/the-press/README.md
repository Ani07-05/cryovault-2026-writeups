# the-press -- Reverse

**Flag:** `isfcr{r4ng3_c0d3r_b1t_3x4ct_y0!}`
**Points:** 496
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A stripped x86-64 ELF reads 32 bytes, delta-codes them, runs them through an LZMA-style adaptive binary range coder, and compares the 36-byte output to a `.rodata` constant. Write the matching range *decoder* with the identical probability model, decode the stored target back to the delta bytes, and undo the delta XOR to get the flag.

## Solution

### Step 1: Identify the range coder

Input is first **delta-coded** (each byte XORed with the previous). Then each byte emits 8 MSB-first binary decisions; each decision has its own 12-bit probability indexed by `(prev_delta_byte << 8) + node` (a 256×256 table, all starting at `0x800`). Updates are asymmetric: a 0-bit moves `p += (0x1000−p)>>4`, a 1-bit `p -= p>>5`. The coder flushes and compares its 36-byte output to the constant at `0x4012e0`.

### Step 2: Run the mirror decoder

Writing the decoder with the same probability/adaptation rules, running it over the stored 36 bytes, then undoing the delta XOR recovers the flag. `printf '%s' '<flag>' | ./press/chall` prints `CORRECT`.

```python
b = open('press/chall', 'rb').read()
out = b[0x12e0:0x12e0+36] + b'\0'*8        # file offset 0x12e0 maps to vaddr 0x4012e0
probs = [0x800]*(256*256)
rng = 0xffffffff; code = int.from_bytes(out[1:5], 'big'); pos = 5
prev = 0; res = []; last = 0
for i in range(32):
    node = 1
    for _ in range(8):
        idx = (prev << 8) + node; p = probs[idx]
        bound = (rng >> 12) * p
        if code < bound:
            rng = bound; probs[idx] = p + ((0x1000-p) >> 4); bit = 0
        else:
            code -= bound; rng -= bound; probs[idx] = p - (p >> 5); bit = 1
        while rng < 1 << 24:
            rng = (rng << 8) & 0xffffffff
            code = ((code << 8) | out[pos]) & 0xffffffff; pos += 1
        node = node*2 + bit
    d = node & 0xff; prev = d
    c = d ^ last if i else d; res.append(c); last = c
print(bytes(res))
```
