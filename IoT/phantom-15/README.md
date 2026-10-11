# PHANTOM-15 -- IoT

**Flag:** `isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}`
**Tools:** Python 3 + numpy/scipy/scapy/cryptography, custom CPA/CCM\*/GF-RS code, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a faithful reconstruction of the method actually used (same primitives/formats), re-expressed as a single script; needs the handout files.

## Enumeration

Handout (`phantom15-participant.zip`, not in repo, referenced by name) ships three text briefs --
`description.txt`, `field_service_excerpt.txt`, `incident_report.txt` -- that pin the link layer down:
802.15.4 PAN `0x4f21`, security level ENC-MIC-64 with key mode 1, nonce layout `src8|counter4LE|0x06`,
an HS15 sync preamble, and a hop sequence over channels `[15, 20, 25]`.

Side-channel scope comes as NPZ files: `traces` arrays of shape `(4400, 344)` float32 with
`sample_period 2ns`, plus a `meta` dict (`P15Q`, little-endian) tagging session 49 / key-index 43 and
session 50 / key-index 100. A CSV capture maps over-the-air frames to the AES inputs used in the CPA,
and the briefs define the P15 shard format, the Reed-Solomon layout `V[i,j] = (i+1)^j` over
`GF(0x11d)`, and the DG15 record envelope (payload + CRC32 + 16-byte BLAKE2s tag).

PCAP triage splits the capture into `alpha` (ch 15), `beta` (ch 20), `gamma` (ch 25): windows 0-19
ticking at +79 ms, with the secured data frames a uniform 74 bytes -- a 21-byte header plus 51 bytes
of encrypted payload (43 plaintext bytes + 8-byte MIC).

## Analysis

The traces show a trigger pulse around samples 49-65, jittered about +-8 samples, with scope
saturation near +-2.5 units; a clipped pre-filter leaves the S-box leakage intact. Aligning each
trace by its `argmax` over samples 45-70 removes the jitter, then a standard Hamming-weight CPA --
model `HW[SBOX[pt ^ guess]]` against byte `i` at sample `120 + 11*i` -- recovers both session keys,
each byte peaking at correlation 0.18-0.24 with a clean gap to the next-best guess.

The two keys diverge on decrypt: key-index 43 opens frames of type `P15`/`ver01`/`kindD1` with valid
MICs, while key-index 100 decrypts to well-formed but wrong-context `MEA` records -- a decoy
key/session the challenge plants to punish CPA-only solvers who stop at the first hit.

## Exploit

```
$ python3 solve.py phantom15-participant/   # pcap parse -> CPA -> CCM* -> RS decode -> flag
```

Decryption is CCM\* with `M=8, L=2`, built on the `cryptography` AES-ECB primitive:
`B0 = 0x59 | nonce | mlenBE` for the CBC-MAC, counter blocks for the keystream, nonce assembled as
`src8 | counter4LE | 0x06` per the briefs. Continuity comes from `msgid 00004a31`, with the flag
shard set keyed by emergency `msgid a17c4a31`. Reed-Solomon decoding over `GF(0x11d)` treats any 8 of
the 9 authentic shards as an 8x8 Vandermonde solve, reassembling the 188-byte DG15 record; its CRC32
and BLAKE2s-16 both verify, and the record's note field holds the flag.

## Flag

`isfcr{phantom15_6b4cf2a16a3ffc72c9420983dec02be1}`
