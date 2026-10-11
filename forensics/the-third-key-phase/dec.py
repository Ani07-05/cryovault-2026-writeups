import sys, json, hmac, hashlib, struct, pickle
from scapy.all import rdpcap, UDP, IP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

P = sys.argv[1]
CHA = 'cha' in sys.argv[5:]
V2 = 'v2' in sys.argv[5:]
LK,LI,LH,LU=((b'quicv2 key',b'quicv2 iv',b'quicv2 hp',b'quicv2 ku') if V2 else (b'quic key',b'quic iv',b'quic hp',b'quic ku'))
secrets = {}
for l in open(sys.argv[2]):
    p = l.split()
    if len(p) == 3:
        secrets.setdefault(p[1], {})[p[0]] = bytes.fromhex(p[2])
hints = json.loads(sys.argv[3])

def hkdf_exp(h, prk, info, n):
    out = b""; t = b""; i = 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), h).digest(); out += t; i += 1
    return out[:n]
def label(h, sec, lab, n):
    full = b"tls13 " + lab
    info = struct.pack(">H", n) + bytes([len(full)]) + full + b"\x00"
    return hkdf_exp(h, sec, info, n)


def keys(sec):
    h = hashlib.sha256 if len(sec) == 32 else hashlib.sha384
    kl = 16 if (len(sec) == 32 and not CHA) else 32
    return (label(h, sec, LK, kl), label(h, sec, LI, 12), label(h, sec, LH, kl))

def mask(hp, sample):
    if len(hp) == 32 and CHA:
        c = Cipher(algorithms.ChaCha20(hp, sample), None, ).encryptor()
        return c.update(bytes(5))
    c = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return c.update(sample)[:5]

pkts = rdpcap(P)
res = []
for idx, pk in enumerate(pkts, 1):
    d = bytes(pk[UDP].payload)
    if not d or d[0] & 0x80: continue
    done = False
    for cr, s in secrets.items():
        for dirn in ("CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"):
          sec0 = s[dirn]
          h_ = hashlib.sha256 if len(sec0) == 32 else hashlib.sha384
          sec = sec0
          for gen in range(8):
            key, iv, _ = keys(sec)
            hp = keys(sec0)[2]
            sec = label(h_, sec, LU, len(sec))
            for dl in range(0, 21):
                po = 1 + dl
                if len(d) < po + 20: continue
                m = mask(hp, d[po+4:po+20])
                fb = d[0] ^ (m[0] & 0x1f)
                pnl = (fb & 3) + 1
                pn_t = bytes(a ^ b for a, b in zip(d[po:po+pnl], m[1:1+pnl]))
                tr = int.from_bytes(pn_t, "big")
                hdr = bytes([fb]) + d[1:po] + pn_t
                lp = hints[cr]["largest_client_pn" if dirn.startswith("CLIENT") else "largest_server_pn"]
                win = 1 << (8 * pnl)
                base = (lp & ~(win - 1)) | tr
                for cand in (base, base - win, base + win):
                    if cand < 0: continue
                    nonce = bytes(a ^ b for a, b in zip(iv, cand.to_bytes(12, "big")))
                    try:
                        pt = (ChaCha20Poly1305 if CHA else AESGCM)(key).decrypt(nonce, d[po+pnl:], hdr)
                    except Exception:
                        continue
                    res.append((idx, pk[IP].src, pk[UDP].sport, cr, dirn[:6], d[1:po].hex(), cand, pt))
                    done = True; break
                if done: break
            if done: break
        if done: break
    if not done: print("undecrypted", idx, len(d))
pickle.dump(res, open(sys.argv[4], "wb"))
print(len(res), "decrypted")
