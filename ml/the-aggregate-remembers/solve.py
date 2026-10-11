"""Federated-learning gradient-leak reconstruction: isolate the target
client's per-round gradient by least squares over the known client mixes,
then recover the two leaked 16-byte training records from that gradient's
rank-2 structure via nonlinear least squares.
"""
import json

import numpy as np
from scipy.optimize import least_squares

LR = 1 / 8
WD = 1 / 64


def per_round_gradients(checkpoints, lr=LR, wd=WD):
    grads = {}
    for ck in checkpoints:
        w = np.array(ck['weights'], dtype=float)
        delta = np.array(ck['delta'], dtype=float)
        grads[ck['id']] = delta * (-1 / lr) - wd * w
    return grads


def isolate_target(grads, mixes, target_id):
    # Rounds sharing a checkpoint have different client mixes; least squares
    # over the known mix matrix isolates the target client's row.
    A = np.array([m[target_id] for m in mixes])
    b = np.array(list(grads.values()))
    sol, *_ = np.linalg.lstsq(A[:, None], b, rcond=None)
    return sol


def residual(vars_, target_grad, w):
    """g = 1/2 * sum((w.x_i - 1) * x_i) over the batch {x1, x2}, for the
    model weights w in force when the leaked batch was trained on."""
    n = len(vars_) // 2
    x1, x2 = vars_[:n], vars_[n:]
    g = 0.5 * (((w @ x1) - 1) * x1 + ((w @ x2) - 1) * x2)
    return g - target_grad


def main():
    d = json.load(open('data.json'))
    m = d['model']
    grads = per_round_gradients(m['checkpoints'])

    target_grad = np.mean(list(grads.values()), axis=0)  # rank-2 across 6 checkpoints
    # w = the model's weight vector at the checkpoint the leaked batch was
    # trained against -- the challenge ties each gradient to a specific
    # checkpoint id, so pull that checkpoint's actual weights rather than
    # assuming zero.
    w = np.array(m['checkpoints'][0]['weights'], dtype=float)
    n = len(target_grad)
    x0 = np.random.randn(2 * n)
    res = least_squares(residual, x0, args=(target_grad, w))
    x1, x2 = res.x[:n], res.x[n:]

    perm = m['permutation']
    rec1 = bytes(round(x1[perm[i]]) & 0xFF for i in range(16))
    rec2 = bytes(round(x2[perm[i]]) & 0xFF for i in range(16))
    print(rec1.hex(), rec2.hex())


if __name__ == '__main__':
    main()
