# Ghosts in the Bulb -- Forensics / IoT

**Flag:** `isfcr{when_photons_and_seconds_both_carry_secrets_a7c3}`
**Tools:** Python 3, scapy, pycryptodome
**Scripts:** `decode.py` is a reconstruction of the ephemeral solve script -- method and framing match exactly.

## Enumeration

`capture.pcap`: several hours of smart-home traffic from a suspected insider's home network, where a smart
bulb, a robovac and other gadgets talk to a local hub (`192.168.1.40`, `.60`, `.70`).

```
$ python3 -c "from scapy.all import *; p=rdpcap('capture.pcap'); ..."   # per-device inter-arrival timing pass
```

## Analysis

Two separate covert channels, hidden in otherwise-plausible telemetry:

**Channel 1 (data)** -- the bedroom bulb's reported brightness (`bri`) LSB carries a bitstream framed by
start marker `A55AA55A`, a length field (109), base85-encoded payload, end marker `F00DCAFE`. Decoding it
gives a `GITB` tag + 12-byte nonce + AES-GCM ciphertext + 16-byte tag.

**Channel 2 (key)** -- the robovac normally reports every 60+-2s. After one 137s gap it switches to
irregular intervals of ~30/45/60/75s before returning to the normal 60s rhythm; each irregular interval
is one 2-bit symbol (`30->00, 45->01, 60->10, 75->11`). These interval anomalies were initially dismissed
as generator/runtime-counter noise -- that cost real time before a per-device `dt` histogram caught the
off-grid intervals.

## Exploit

```
$ python3 -c "from scapy.all import *; v=[float(x.time) for x in p if x[IP].src=='192.168.1.40' ...]; dt=[b-a for a,b in zip(v,v[1:])]"
```

Decoded the robovac's interval symbols into bytes: sync byte `A5`, then the 12-character key material
`KZ7WMQR3XB2H`, then `AA` marking the return to normal cadence. `sha256(b"KZ7WMQR3XB2H")` is the AES-GCM
key, the 12 bytes after the `GITB` tag in the bulb stream are the nonce. Decryption succeeded and the
tag verified.

## Flag

`isfcr{when_photons_and_seconds_both_carry_secrets_a7c3}`
