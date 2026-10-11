# The Deletion Echo -- ML

**Tools:** Python, numpy (linear least squares / integer programming), unlock.py (challenge harness)
**Scripts:** Original scripts recovered from the session scratchpad: `fit.py`, `an.py`, `st.py`, `st2.py`, `ilp.py`.
**Flag:** `isfcr{763c8479fac095a9e471ad3d}` (see note below)

## Enumeration

safe_alone.zip -> data.json: six gate-telemetry snapshots of a model's Hessian-like statistics (each from 240 queries), where some records had been deleted between snapshots. Had to submit the exact deleted-record id:value list to unlock.py.

## Analysis

Fit each snapshot's 240 queries: the means give theta, the variances give the noise variance and H^-1, recovering H and b = H*theta almost exactly per snapshot. Two snapshots (d170 and e21c) were identical, so one was a stale redeploy and could be ignored. The remaining four formed a clear chain: 2ee9 -> d170 -> e385 -> 9ccb, where the first and last steps are pure ingest batches (5798d74d, 578b7698) matching with no residual.

## Exploit

The middle step added batch e0449f2a and also deleted records. Fit the leftover H change to non-negative combinations of candidate rank-one terms -> exactly 26 candidates, each weight 1. The b change equals the batch's labelled sum minus the deleted records' labelled sum -> 12 equations in 36 unknown labels in {0,1,2,3}; an integer program solved it with max error ~0.005. Submitted:
python3 unlock.py '["record-0730706150:0","record-28c0bbf813:2","record-2e6662ecc6:3",
  "record-3de105d25d:3","record-3ee76f33c8:2","record-46126dd779:0","record-473e486afd:0",
  "record-49aa7c51a4:2","record-507645d5d9:2","record-58fad90382:2","record-5bc7d8554c:1",
  "record-66f65f5026:0","record-71fb3e266c:2","record-7796490f27:1","record-77a4509144:1",
  "record-8f4b4073f9:1","record-90769aad7a:1","record-978b124800:1","record-9cddf7a4fb:0",
  "record-9cfdc74744:3","record-b9e67b6811:2","record-cf44aec78a:2","record-cf4fee237a:0",
  "record-d32fd7d5d5:1","record-ebfb2ad09e:0","record-ee9e7ec4d8:1"]'

## Verification

unlock.py accepted the 26-record answer directly and returned the flag.
