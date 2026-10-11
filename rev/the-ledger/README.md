# The Ledger -- Rev

**Tools:** Python, sympy (ELF parsing), fpylll (BKZ lattice reduction), WSL
**Scripts:** No original script survived the session's ephemeral scratchpad; the method below is a faithful reconstruction from the session transcript, not a recovered file.
**Flag:** `isfcr{lll_dense}` (see note below)

## Enumeration

chall (4): "Hand it 16 bytes. It will tell you nope." A single stripped Linux ELF binary.

## Analysis

The binary reads 16 bytes (128 bits) and treats each bit as a yes/no choice: it sums the 128 table entries (each 400 bits) whose corresponding input bit is set, then compares the resulting 512-bit total against a fixed target -- a textbook subset-sum problem. Measured density (~0.32) is low enough that a lattice attack (rather than brute force over 2^128 subsets) applies directly: this is the classic CJLOSS low-density subset-sum construction.

## Exploit

Pulled the 128-entry table and the target out of the ELF's data section, built the CJLOSS lattice basis from them. sympy's built-in LLL did not find the short vector, but fpylll's BKZ (block size 20) did, run under WSL's Ubuntu (the binary and its data section are x86-64 ELF; fpylll needed a real Linux environment). The recovered 128-bit vector sums exactly to the 512-bit target. The binary's own success message states that the flag is literally the 16-byte input you give it, so the recovered bits (packed back into 16 bytes) are the flag text directly, with no further decoding step.

## Verification

Recovered bit vector sums exactly to the fixed 512-bit target in the verification script; the binary's success path requires nothing else.
