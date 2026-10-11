# the shape of silence -- ML

**Flag:** `isfcr{577027585a0778773aa949d9}`
**Tools:** Python 3 (fractions/json/hashlib), numpy/scipy lstsq, unlock.py oracle, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a reconstruction of the original ephemeral-scratchpad solver (same attack, re-expressed cleanly); needs the handout `data.json` (`python3 solve.py data.json`), pipe its JSON output to `unlock.py`.

## Enumeration

Handout `the_shape_of_silence.zip` -> `data.json` + `unlock.py`: 22 captures of 2 clouds x 7 points in dim 6, plus 16 anchors (`x`/`y`) and 24 targets (`x` only). The answer is the list of 24 target outputs; `unlock.py` checks it via `key = sha256(b'isfcr-ml\0' + json(answer))` AES-GCM decrypt with `challenge_id` as AAD.

```
$ python3 -c "import json; d=json.load(open('data.json')); print(d['model_version'], d['dimension'], len(d['captures']), len(d['anchors']), len(d['targets']))"
```

4 captures are stale `v-41e59d`, 18 are current `v-8fb4ff`. Each cloud's 7 points determine an exact affine plane (`[x 1].[g;b] = y` over `Fractions`); all 44 gradients and intercepts come out exact integers, with each cloud centroid lying exactly on its plane.

## Analysis

Grouping captures by gradient jump `dg = g1-g0, db = b1-b0` splits the set cleanly: the current 18 form 9 pairs with byte-identical `(dg, db)`, while the old 4 are singletons with unique jumps. Within each capture the cloud-to-cloud offset is parallel to its `dg` (cosine ~+-1), and the segment joining the two centroids meets the plane intersection at `t* ~ 0.5` -- each capture straddles one hinge symmetrically.

So each pair flips exactly one hyperplane `h(x) = dg.x + db`, and the model is an integer piecewise-affine ReLU net `f(x) = L(x) + sum c_j ReLU(h_j(x))` with 9 hinges. The two pairs with anti-parallel offsets take `c = -1`; the rest take `c = +1`.

## Exploit

```
$ python3 solve.py data.json
$ python3 unlock.py "$(python3 solve.py data.json)"
```

Free `lstsq` over the 36 current centroids + 16 anchors with columns `[x, 1, ReLU(h_j)]` lands on integers directly: `L(x) = 2x0-6x1+14x2-5x3+20x4+5x5-21`, `c = [1,1,1,1,1,-1,1,1,-1]` (hinges sorted by `(dg, db)`), maxerr `3e-13`. Exact `Fraction` verification passes on all 252 current cloud points plus all anchors. Evaluating the 24 targets as reduced fraction strings:

`["5441/64","909/32","8939/64","1055/32","6041/64","1305/64","4173/32","4559/64","1597/16","1309/64","3015/32","423/4","2145/64","9475/64","26","2777/64","-1437/64","2969/64","983/16","5471/64","4163/64","5835/64","2971/64","2007/64"]`

`unlock.py` accepts it and prints the flag.

## Flag

`isfcr{577027585a0778773aa949d9}`
