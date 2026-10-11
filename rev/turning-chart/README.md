# Turning Chart -- Rev

**Tools:** Python, WSL (native Linux binary execution), manual 320-round cipher inversion
**Scripts:** No original script survived the session's ephemeral scratchpad; the method below is a faithful reconstruction from the session transcript, not a recovered file.
**Flag:** `isfcr{3v3ry_r0ut3_r3m3mb3rs_1ts_0r1g1n}` (see note below)

## Enumeration

"The survey ship's last chart was sealed by a navigation instrument whose needle never stays put. The crew kept the instrument, but lost the course." A 39-byte "course" binary (chall) that validates a candidate flag of the form isfcr{<32 chars from [a-z0-9_]>}.

## Analysis

The program hashes the fixed string "a chart is a record of motion, not of place" with FNV-1a, uses that hash to seed a xorshift PRNG, and uses the PRNG to shuffle a 10-entry "dial" and a 256-byte S-box. The 32 inner characters then go through 320 rounds; each round applies one of 10 fixed operations to the 32-byte state (S-box lookups, swaps, adds, rotations, row/column shuffles, and two control-state-only ops), chosen by the dial. Because the operation sequence never depends on the input itself, the full 320-step sequence can be computed ahead of time and inverted exactly. The dial the binary prints at runtime ("4 1 7 0 9 2 5 3 8 6") is explicitly flagged by the challenge as a decoy.

## Exploit

Derived the real dial -- 4 1 0 5 7 8 2 6 9 3 -- by fitting against the known per-round operation behaviour, then applied the inverse of each of the 320 operations in reverse order to the binary's fixed target state, recovering the original 32-character input.

## Verification

Verified by running the recovered course string through the actual binary under WSL, which printed "Chart opened. Course restored."
