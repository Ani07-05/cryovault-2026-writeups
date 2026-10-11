# the aggregate remembers -- Crypto / ML

**Flag:** `isfcr{9b1aa6a53205a859c14cc5e4}`
**Tools:** Python 3, numpy, scipy.optimize.least_squares
**Scripts:** `solve.py` is a reconstruction of the original `a.py`/`b.py` (same attack).

## Enumeration

Provided `data.json`: a federated-learning simulation. A target client's SGD updates to a shared
linear-regression model are mixed with two other clients' updates across 6 checkpoints before the
aggregated deltas are exposed. `lr=1/8`, weight-decay `wd=1/64`.

```
$ python3 -c "import json; d=json.load(open('data.json')); m=d['model']; print([(k,type(v).__name__) for k,v in m.items()], len(m['checkpoints']))"
```

## Analysis

Per round, `delta*(-1/lr) - wd*w` recovers that round's mix-weighted mean gradient. Rounds that share a
checkpoint have different client mixes, so least squares over the three clients across those
shared-checkpoint rounds isolates each individual client's gradient -- keeping only the target client's
row.

Across all 6 checkpoints, the target's recovered gradients have rank 2, meaning exactly 2 underlying
training records were ever mixed in -- the batch that leaked.

## Exploit

```
$ python3 solve.py
```

Solved `g = 1/2 * sum((w.x - 1)*x)` for the two feature vectors with nonlinear least squares from random
starting points. The solution landed on clean integer bytes once the scale/center/permutation the
challenge applied were inverted, recovering the two original 16-byte records:
`07841f68cb73fe5aac5cbf66f113f992` and `ff1247cd40f11a77f9495f7ba9648a20`.

## Flag

`isfcr{9b1aa6a53205a859c14cc5e4}`
