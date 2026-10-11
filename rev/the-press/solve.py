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
