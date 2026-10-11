# Oatmeal -- Mobile

**Tools:** unzip, androguard, Python (manual ARM64 disassembly reading / VM emulation)
**Scripts:** Original scripts recovered from the session scratchpad: `findoff.py`, `hdr.py`, `sgdump.py`, `stroff.py`, `xorscan.py`, `ic.py`, `entropy.py`, `png.py`, `cs1.py`, `str.py`, `hexdump.py`.
**Flag:** `isfcr{5958fbb07efd243b}` (see note below)

## Enumeration

silvergate.apk + base.odex, from an imaged device running an in-house vault app, SilverGate. Unpacked the APK, decompiled classes.dex with androguard, and pulled strings from both files.

## Analysis

Several things were decoys placed to catch naive extraction: LockActivity.checkFlag() SHA-256-hashes the typed input and compares it to a hardcoded digest, then deriveFlag() XORs that same input with 0x55 and hex-encodes it into isfcr{...} -- a dead end, since assets/notes.txt points at a secrets/vault_dev.yaml that isn't part of this image. The odex also has a fake embedded "dex" magic at offset 0x890 (invalid header fields, bait for naive dex-extractors) plus two cooked-up strings (isfcr{dev_overlay_do_not_submit_18ca3b}, isfcr{preprod_token_v3_40df11a0ce9c}) next to a "isfcr{%016llx}" format string -- also bait. The real logic is a tiny ARM64 bytecode VM (checkFlag_v1_LEGACY) starting at file offset 0x4b0, interpreting 265 two-byte instructions stored at 0x290.

## Exploit

Each VM block reads one input byte, mixes it with three embedded 24-byte lookup tables via add -> xor -> rotate-left-3, then asserts the result against a table-derived constant -- fully invertible, no brute force needed. Solved all 24 byte positions against that chain to recover the exact string the VM accepts:
  art_image_took_the_cake!
Fed that into the neighbouring native finalizeFlag routine: a 64-bit FNV-1a hash over those 24 bytes (offset-basis 0xcbf29ce484222325, prime 0x100000001b3), XORed with a hardcoded constant (0xa55a96693c3cd2ad), printed via "isfcr{%016llx}" -> the flag.

## Verification

Verified three ways: the recovered 24-byte string satisfies every ASSERT in a full VM emulation, and finalizeFlag's math was reproduced instruction-for-instruction from the disassembly.
