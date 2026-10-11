import pickle, sys

with open(sys.argv[1], "rb") as f:
    d = pickle.load(f)
out = d["out"]
tokens = d["tokens"]

N = len(out)

# Build position for each token
ambiguous = []
pos = 0
for ti, t in enumerate(tokens):
    if t[0] == 'L':
        pos += 1
    else:
        _, length, dist = t
        p = pos
        target = bytes(out[p:p+length])
        # find all valid distances d' in [1, p] such that out[p-d':p-d'+length] == target
        valids = []
        start_pos = 0
        while True:
            idx = out.find(target, start_pos, p)
            if idx == -1:
                break
            valids.append(p - idx)
            start_pos = idx + 1
        if len(valids) > 1:
            valids.sort()
            rank = valids.index(dist)
            ambiguous.append((ti, p, length, dist, valids, rank))
        pos += length

print("total matches", sum(1 for t in tokens if t[0]=='M'))
print("ambiguous matches", len(ambiguous))
for a in ambiguous[:40]:
    print(a[0], "pos",a[1],"len",a[2],"dist",a[3],"nvalid",len(a[4]),"rank",a[5], "valids_sample", a[4][:6])

import pickle as pk
with open(sys.argv[2], "wb") as f:
    pk.dump(ambiguous, f)
