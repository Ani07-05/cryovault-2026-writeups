# Faraday Cage (LumoWise LW-7 / Faraday.apk) -- Mobile

**Flag:** `isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}`
**Tools:** Python, Unicorn (ARM64 emulation), objdump/readelf
**Scripts:** `vm.py`, `solve.py`, `final.py` are verbatim from the session scratchpad -- a
full, runnable pipeline (recovered from the session transcript, not a reconstruction).

Verbatim from the session transcript (Unicorn-emulated ARM64 native lib).

Prereqs: `pip install unicorn`, `readelf`/`objdump` on PATH, and the extracted
APK's native lib at `../apk/lib/arm64-v8a/libbulb.so` relative to this folder
(i.e. extract `Faraday.apk` and point `apk/` at its contents).

Run in order:

```bash
python3 vm.py      # emulates libbulb.so's init, recovers the shuffled
                    # opcode table, disassembles the 60-instr VM program
python3 solve.py    # inverts the 4-round AES-like cipher (inverse S-box,
                    # byte permutation, GF(2)-linear MixColumns via its
                    # recovered 32x32 bit-matrix, round-key XOR) to
                    # recover the 16-byte unlock input -> writes sol.txt
python3 final.py    # feeds the recovered input back through the real
                    # native submit() routine, which derives a SHA-256
                    # key and decrypts the flag
```

Output: `isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}`

The unlock response typed into the app itself is the ASCII decode of the
recovered bytes: `LumosFaradCage01` (hex `4c756d6f734661726164436167653031`).

Note: the constant-pool address `0x32a` in an earlier draft of `vm.py` was
wrong — the real `init` block lives at `0x132a` (an `adrp 0x1000` base is
added before the literal offset). The version here already has the fix.
