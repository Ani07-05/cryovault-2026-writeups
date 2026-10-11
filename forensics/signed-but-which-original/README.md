# signed, but which original? -- Forensics

**Flag:** `isfcr{29336738f5f44f4d2d1e3ac2}`
**Points:** unknown
**Solved by:** vikas1337
**Tools:** see script below
**Scripts:** `solve.py` is vikas1337's original solve script, included verbatim.

## Summary

An append-only transparency log (`entries.bin`) plus a policy (`case.json`). You must apply a layered validity filter — verify the Merkle log, pick the largest *valid* checkpoint, and follow the one admissible provenance chain — then reconstruct the exact evidence array that keys an AES-GCM seal. The GCM tag verifying is the proof the chain is right.

## Solution

### Step 1: Parse the log and filter checkpoints

`entries.bin` = `ISFCRLOG` header + 55 length-prefixed records; each body = `[1-byte type][TLV]`. Leaf `= SHA256(0x00 || body)`, node `= SHA256(0x01 || L || R)` (RFC 6962). Recomputed roots match checkpoints at ts=55, 52, 46, 33 but not ts=50 (forged root). Apply `largest_valid_checkpoint`: ts=55 root matches but its **signature is forged**; ts=52 is signed by a fork/secondary key → excluded; ts=50 root forged; **ts=46 (primary key, valid sig + valid root) wins** → only leaves 0–45 are admissible.

### Step 2: Resolve the unique chain and decrypt

The one valid chain (capture `capture-north`, parent-linked, intermediates exactly `crop,resize`, final `redact`, tied to `incident-d7be9442cb`, manifests verified over RFC 8785 canonical JSON): idx 6 capture `mf-326c47df321e` → idx 12 crop `mf-95efb978da36` → idx 17 resize `mf-57d2452e846e` → idx 41 redact `mf-ee2392778137`. The key decoy is redact #48 `mf-a9260fd9b062` — validly signed but leaf index 48 > tree_size 46, so excluded. The seal: `key = scrypt("isfcr-forensics\0" + compact-JSON(evidence), salt, n=131072, r=8, p=1)` then `AES-GCM(nonce, ct, aad="signed-but-which-original")`. The evidence array is `[final_asset, final_mid, "mid>mid>mid>mid" ancestry, capture_asset, incident_id, str(tree_size)]`.

```python
import json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE = bytes.fromhex("d2705557b11d25f6a1607cfd")
CT = bytes.fromhex("7bad7e996d62c88b017ef105997ca1235e513b8b24a724eb88a5204d1771614af735db56d5d02cc8177133b8d79101")
AAD = b"signed-but-which-original"
SALT = bytes.fromhex("df2fd39adb32a812294cfe264c4a0ddc")

def try_ev(ev):
    E = json.dumps(ev, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    key = hashlib.scrypt(b"isfcr-forensics\x00" + E, salt=SALT, n=131072, r=8, p=1,
                         maxmem=2**28, dklen=32)
    try:
        return AESGCM(key).decrypt(NONCE, CT, AAD)
    except Exception:
        return None

cap_asset = "5fe33137c48b34086ca6c2c19723b4916fb13732e465759be10b96dcef825bcf"
cap_mid = "mf-326c47df321e"; crop_mid = "mf-95efb978da36"; resize_mid = "mf-57d2452e846e"
INC = "incident-d7be9442cb"

candidates = [
    ("c40ac4a3268f0b30aac5a1e344e1e4016b82fbfb1171e86330a64c69e73d6cff", "mf-ee2392778137"),  # #41
    ("668ee29ce200c5abe03275f7449805810f9ba60ca630feaab7d9d5db27fb26e4", "mf-a9260fd9b062"),  # #48 decoy
]
for ts in ["52", "46", "50", "55", "33"]:
    for dasset, dmid in candidates:
        anc = ">".join([cap_mid, crop_mid, resize_mid, dmid])
        ev = [dasset, dmid, anc, cap_asset, INC, ts]
        r = try_ev(ev)
        if r is not None:
            print("SUCCESS ts=", ts, "deriv_mid=", dmid)
            print("evidence=", ev)
            print("FLAG=", r.decode())
            raise SystemExit
print("no match")
```

Winning evidence (GCM tag validated): `["c40ac4a3...e73d6cff", "mf-ee2392778137", "mf-326c47df321e>mf-95efb978da36>mf-57d2452e846e>mf-ee2392778137", "5fe33137...825bcf", "incident-d7be9442cb", "46"]`.
