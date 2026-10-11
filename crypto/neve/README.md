# NEVE -- Crypto

**Tools:** Python, C (hidden-state maximum-likelihood fitting), live query-budgeted oracle probing
**Scripts:** Original scripts recovered from the session scratchpad: `solver2.py`, `emfit.py`, `fb.c`, `solve.py`.
**Flag:** `isfcr{neve_e60e_jacket_67de9384_loop}` (see note below)

## Enumeration

"A NEVE sounding head watches the outer jacket loop: hand it a symbol and it answers with one bit." The live head (NV-4.2.1, 32 rows) enforced a strict 1.25M-query budget, with an older vendor bench model (NV-3.4.2) provided as a reference for expected behaviour.

## Analysis

Naive per-symbol frequency estimates (which worked against the bench model) gave grades that didn't land cleanly on the live head's 0-7 grid. Diagnosed three real differences from the bench model: (1) each flip probability is looked up against a symbol seen a few steps back, not the previous one -- the lag resets to 2 only on a flip that originates from the table cell itself, otherwise growing by one per step up to a per-row cap; (2) that cap varies by row (measured values of 3, 4, 5, 6 or 8); (3) the head tracks a running output-bit balance clamped to +-7, adding a forced-flip chance that rises from about 8% to 100% as the balance builds up.

## Exploit

Wrote a C solver fitting a hidden-state model (lag + cap + disparity feedback) to random symbols sent to each row via maximum likelihood, picking the per-row cap by likelihood score. Stopped once every cell's grade settled to within 0.3 of an integer with likelihood ~1-2e-5, which took 20k-45k symbols per row. Validated the approach on disposable throwaway sessions first (confirming four rows correctly there) before running it for real: all 32 rows of the live head were confirmed with zero wrong checkpoints, so nothing was charged against the query budget on the real session (finishing with ~160k of the 1.25M budget left). Used the fully recovered 32-row calibration table to decrypt the sealed recovery bundle.

## Verification

The bundle decrypted successfully on the first attempt using the recovered calibration table.
