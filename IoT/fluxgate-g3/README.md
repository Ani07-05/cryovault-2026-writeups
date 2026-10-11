# Fluxgate G3 -- IoT

**Tools:** Python, custom binary protocol client (socket), firmware-bundle diffing
**Scripts:** Original scripts recovered from the session scratchpad: `exploit.py`, `net.py`.
**Flag:** `isfcr{s1gn3d_p4rts_uns1gn3d_whole_ab84f1}` (see note below)

## Enumeration

fluxgate-g3.zip: "a small industrial controller sits on the lab network, its factory service mode is meant to stay locked." Bundle contains multiple firmware/policy/radio builds (pol-v3, pol-v3rc, tab-v2, tab-v3, rad-v2) and an update-and-unlock protocol.

## Analysis

Diffed every firmware payload against its predecessor. tab-v3.fw quietly downgrades the capability required for opcode 0x70 from SERVICE (0x8000, factory-only hardware) to BASIC_READ (0x0001, a bit every operator token -- including a low-tier one -- already has). pol-v3rc.fw is the only policy build that still wires opcode 0x70 to action 0x07 (UNLOCK); the shipped pol-v3.fw dropped that handler entirely. Each individual firmware/policy artifact is validly signed on its own ("signed parts"), but installing both together reconstructs a combined state the vendor never signed off on ("unsigned whole") -- the flag's own wording.

## Exploit

From the installed baseline pol@v3 / tab@v2 / rad@v2, found a fully legal update path needing no RESET:
1. UPDATE pol-v3rc -- a same-counter sidegrade (counter 3 >= 3) whose deps (tab:1-3,    rad:1-2) are already met by the installed tab@v2 / rad@v2.
2. UPDATE tab-v3 -- counter 3 >= 2, with its only dependency (pol:3-3) now satisfied    since pol-v3rc reports version 3.
Booted the resulting state, pulled a genuine low-privilege TOKEN (user_id 42, caps 0x0003), and crafted a SEND frame by hand:
  "FG" + frame_version(2 bytes) + opcode(0x70) + payload_len(0) + token(24 bytes)
The loader checked the frame against installed tab@v3, saw opcode 0x70 only needs BASIC_READ (which the low-tier token already has), and let it through to pol@v3rc's UNLOCK handler, which emitted the factory service blob containing the flag.

## Verification

Captured live against the target service; working exploit script at Downloads\fluxgate_work\exploit.py.
