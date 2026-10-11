# Mirror Garden -- Mobile

**Tools:** androguard, Unicorn (native-code emulation), Z3 (SMT solving), Python
**Scripts:** Original scripts recovered from the session scratchpad: `disasm.py`, `dump.py`, `emu.py`, `leaf.py`, `solve.py`, `final.py`, `elfinfo.py`, `dump2.py`.
**Flag:** `isfcr{m1rr0r_g4rden_bl00ms_@t_m1dn1ght_7f3a}` (see note below)

## Enumeration

mirror-garden.apk: "something is growing in the mirror garden, and only one leaf remembers." The dex ships 1024 decoy classes (leaf/L0000 .. L1023), each implementing its own verify(byte[16]); MainActivity forwards the 16-byte input text field to a native bloom() in libgarden.so.

## Analysis

The native code ignores the actual input when choosing which leaf to use -- it runs a fixed internal routine (emulated with Unicorn rather than reverse-engineered by hand) that always selects leaf 357. verify() on leaf 357 only passes if 8 obfuscated arithmetic checks on the 16 input bytes all hold simultaneously.

## Exploit

Translated those 8 arithmetic constraints into Z3; the solver returned a unique 16-byte input: L.]^ooq(LlU^(a]#. Reverse-engineered the rest of the native pipeline: on a successful verify, the leaf returns 48 bytes which are XORed with internal native state to build a key; that key is hashed with SHA-256 using the domain-separation labels "garden/e/v1" and "garden/m/v1" to derive an encryption key and a MAC key. The library checks an HMAC-SHA256 tag with the MAC key, then decrypts a 44-byte blob using SHA-256(key || counter) as a keystream (a SHA-256-CTR construction). Reimplemented that whole chain offline in Python with the solved 16-byte input.

## Verification

Re-ran the app's own check offline: the HMAC tag computed from the recovered input matched the one stored in the library exactly, confirming the decryption (and the flag) were correct.
