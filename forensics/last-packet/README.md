# Last Packet -- Forensics

**Flag:** `isfcr{l33t_c0d3_tw0_sum_f0und}`
**Tools:** tcpdump, Python 3 + scapy, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a faithful reconstruction of the parser actually used (same scapy
extraction + hex/base64/XOR path), re-expressed as a single offline script; needs the handout pcap.

## Enumeration

50-pt forensics. Handout `challenge2.pcap` (13 KB, 112 packets): DNS A-only queries plus
9 HTTP flows.

```
$ tcpdump -r challenge2.pcap -n | head
$ python3 solve.py challenge2.pcap
```

The last flow is `10.0.1.50:65080 > 10.0.1.100:8080`, `GET /internal/next-step`, which
returns a `hint-status: continue` header and a `hello-darling` body pointing at a Reddit
OSINT branch. That branch was followed to a Reddit 403 and is documented here as
unresolved -- it is not needed for the flag.

## Analysis

Packet 56 is the interesting request: `POST /api/v1/twosum/solve` against
`twosum-api.internal.corp:9090` with `X-Debug-Mode` enabled and body
`{"nums":[24,42,7,15],"target":66}`.

Packet 58 is its `200` reply: `{"result":[0,1],"debug":{"internal_key":"4b7a...","enc":"xor"}}`.
The `internal_key` value is hex-encoded base64, 30 bytes once decoded -- the XOR-encrypted
flag sitting inside the pcap's debug output.

The rest of the capture was ruled out as a carrier: no padding/trailing bytes on frames,
DNS is A-records only, no ICMP/ARP traffic at all, and TCP sequence numbers are unique
(no retransmission-hiding or overlapping-segment tricks).

## Exploit

```
$ python3 solve.py challenge2.pcap
```

Decode the key hex -> base64 -> 30 ciphertext bytes, then single-byte XOR brute-force all
256 keys. Only key 66 (`B` -- the same value as the two-sum `target`) yields printable
`isfcr{...}` output, verified against the flag format.

Honest note: the pcap-embedded XOR flag is the solve; the `/internal/next-step`
hello-darling Reddit OSINT branch was left unresolved (Reddit 403) and is not part of
the flag path.

## Flag

`isfcr{l33t_c0d3_tw0_sum_f0und}`
