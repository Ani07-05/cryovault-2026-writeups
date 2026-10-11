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
