# mirage -- Pwn

**Tools:** netcat / raw sockets, manual blind format-string exploitation (no binary provided)
**Scripts:** Original scripts recovered from the session scratchpad: `mirage.py`, `t1.py`, `t2.py`, `t3.py`, `t4.py`, `t5.py`, `t6.py`, `scan.py`, `probe.sh`, `probe2.sh`.
**Flag:** `isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}` (see note below)

## Enumeration

nc 0.cloud.chals.io 23023 -- "an echo that repeats back a little more than you said." No binary or source was given; everything had to be inferred live over the wire.

## Analysis

Confirmed mirage echoes input through something like printf(buf) directly: %x chains leaked raw stack values (first 5 vararg slots observed: 0x48725b, 0, 0x71, 0, 0; slot 6+ was our own input), and %1$s leaked the literal string "quit" from memory -- a hardcoded comparison string. Banner strings ("[chall] mirage..." at 0x489448, __vdso_getrandom at 0x487c1b) confirmed the target is a statically-linked, non-PIE binary, and stack addresses stayed stable across reconnects (ASLR effectively absent on the stack) -- making blind exploitation tractable with no binary in hand.

## Exploit

Built a self-referencing arbitrary-read primitive: place a %N$s positional specifier early in the sent buffer, and put an 8-byte little-endian candidate address in a later, aligned vararg "slot" of the same buffer, so printf treats our own injected bytes as a pointer and dereferences it. Swept roughly 160 vararg stack slots with %p to collect candidate pointers, then ran the arbitrary-read trick against the heap-looking ones (0x4a3xxx / 0x4bxxxx range). 0x4b6ac0 resolved to the flag string; read a few bytes immediately before that address and found a null terminator right at the start, confirming the string was complete and not truncated.

## Verification

Boundary check (null terminator immediately before the string's start address) confirmed the flag text was intact end-to-end.
