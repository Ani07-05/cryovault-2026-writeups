"""the shape of silence -- piecewise-affine ReLU net recovery.

Each capture holds 2 clouds of 7 points in dim 6. Seven points determine
an exact affine plane, so every cloud is solved over Fractions (integer
gradients/intercepts throughout). Captures are grouped by their gradient
jump dg = g1 - g0, db = b1 - b0: the 18 current (v-8fb4ff) captures form
9 pairs with identical (dg, db); the 4 stale (v-41e59d) captures are
singletons. Each pair straddles one ReLU hyperplane h(x) = dg.x + db.

Model: f(x) = L(x) + sum_j c_j * ReLU(h_j(x)) with integer L and c_j = +-1.
L and c are fit by free least squares over the 36 current centroids plus
the 16 anchors, rounded to integers, then verified exactly with Fractions.
Prints the JSON list of 24 target outputs (reduced fraction strings).
"""
import json
import sys
from collections import defaultdict
from fractions import Fraction

import numpy as np


def plane_fit(pts):
    """Exact affine fit of 7 points (x in Q^6, y in Q): [x 1].[g;b] = y."""
    n = len(pts)
    mat = [[Fraction(v) for v in p["x"]] + [Fraction(1), Fraction(p["y"])]
           for p in pts]
    for col in range(7):
        piv = next(r for r in range(col, n) if mat[r][col] != 0)
        mat[col], mat[piv] = mat[piv], mat[col]
        pv = mat[col][col]
        for r in range(n):
            if r != col and mat[r][col] != 0:
                f = mat[r][col] / pv
                for c in range(col, 8):
                    mat[r][c] -= f * mat[col][c]
    sol = [mat[i][7] / mat[i][i] for i in range(7)]
    return tuple(sol[:6]), sol[6]


def centroid(cloud):
    dim = len(cloud[0]["x"])
    cx = [sum(Fraction(p["x"][j]) for p in cloud) / len(cloud)
          for j in range(dim)]
    cy = sum(Fraction(p["y"]) for p in cloud) / len(cloud)
    return cx, cy


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "data.json"
    d = json.load(open(path))
    cur = "v-8fb4ff"

    # 1. Exact planes per cloud, jumps per capture.
    jumps = {}
    for i, cap in enumerate(d["captures"]):
        g0, b0 = plane_fit(cap["clouds"][0])
        g1, b1 = plane_fit(cap["clouds"][1])
        dg = tuple(a - b for a, b in zip(g1, g0))
        jumps[i] = (dg, b1 - b0)

    # 2. Group captures by byte-identical (dg, db); keep current pairs.
    groups = defaultdict(list)
    for i, cap in enumerate(d["captures"]):
        groups[jumps[i]].append(i)
    pairs = sorted(
        (dg_db for dg_db, members in groups.items()
         if len(members) == 2
         and all(d["captures"][m]["model_version"] == cur
                 for m in members)),
        key=lambda t: ([int(v) for v in t[0]], int(t[1])),
    )
    hinges = [(dg, db) for (dg, db) in pairs]
    assert len(hinges) == 9, f"expected 9 hinges, got {len(hinges)}"

    # 3. Free least squares over 36 centroids + 16 anchors.
    fx, fy = [], []
    for i, cap in enumerate(d["captures"]):
        if cap["model_version"] != cur:
            continue
        for cloud in cap["clouds"]:
            cx, cy = centroid(cloud)
            fx.append([float(v) for v in cx])
            fy.append(float(cy))
    for a in d["anchors"]:
        fx.append([float(Fraction(v)) for v in a["x"]])
        fy.append(float(Fraction(a["y"])))
    X = np.array(fx)
    y = np.array(fy)
    H = np.array([[[float(sum(dg[j] * Fraction(str(row[j]))
                              for j in range(6)) + db)
                    for dg, db in hinges] for row in fx]])
    H = H.reshape(len(fx), len(hinges))
    A = np.column_stack([X, np.ones(len(X)), np.maximum(H, 0)])
    sol, *_ = np.linalg.lstsq(A, y, rcond=None)
    lw = [int(round(v)) for v in sol[:6]]
    lb = int(round(sol[6]))
    c = [int(round(v)) for v in sol[7:]]

    # 4. Exact Fraction verification on every current point + anchor.
    def f_exact(x):
        v = sum(Fraction(w) * xi for w, xi in zip(lw, x)) + Fraction(lb)
        for (dg, db), cj in zip(hinges, c):
            h = sum(dgi * xi for dgi, xi in zip(dg, x)) + db
            if h > 0:
                v += Fraction(cj) * h
        return v

    for i, cap in enumerate(d["captures"]):
        if cap["model_version"] != cur:
            continue
        for cloud in cap["clouds"]:
            for p in cloud:
                x = [Fraction(v) for v in p["x"]]
                assert f_exact(x) == Fraction(p["y"]), f"mismatch cap{i}"
    for a in d["anchors"]:
        x = [Fraction(v) for v in a["x"]]
        assert f_exact(x) == Fraction(a["y"]), "anchor mismatch"

    # 5. Targets as reduced fraction strings.
    ans = [str(f_exact([Fraction(v) for v in t])) for t in d["targets"]]
    print(json.dumps(ans))


if __name__ == "__main__":
    main()
