#!/usr/bin/env python3
"""PHANTOM-15 solver: pcap parse -> CPA -> CCM* decrypt -> RS decode -> flag.

Usage: python3 solve.py <handout_dir>
Faithful reconstruction of the method actually used (same primitives/formats),
re-expressed as a single script. Needs the handout files (phantom15-participant.zip
contents): NPZ traces+meta, capture CSV, alpha/beta/gamma pcaps, format briefs.
Keys are recovered at runtime via CPA; nothing secret is hardcoded.
"""
import csv
import glob
import hashlib
import os
import struct
import sys
import zlib

import numpy as np
from scipy import signal
from scapy.all import rdpcap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SBOX = bytes.fromhex(
    "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0"
    "b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75"
    "09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf"
    "d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2"
    "cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db"
    "e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08"
    "ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e"
    "e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16")
HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)
PAN, HOP = 0x4F21, {15: "alpha", 20: "beta", 25: "gamma"}


def gf_mul(a, b):  # GF(2^8), poly 0x11d
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def gf_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        e >>= 1
    return r


def gf_inv(a):
    assert a != 0
    return gf_pow(a, 254)


def gf_solve(A, b):  # Gaussian elimination over GF(256)
    n = len(A)
    M = [row[:] + [v] for row, v in zip(A, b)]
    for c in range(n):
        piv = next(i for i in range(c, n) if M[i][c])
        M[c], M[piv] = M[piv], M[c]
        inv = gf_inv(M[c][c])
        M[c] = [gf_mul(v, inv) for v in M[c]]
        for r in range(n):
            if r != c and M[r][c]:
                f = M[r][c]
                M[r] = [x ^ gf_mul(f, y) for x, y in zip(M[r], M[c])]
    return [row[n] for row in M]


def aes_ecb(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def load_scope(handout, sess):
    """Load (traces, plaintexts) for a session; align by trigger argmax[45:70]."""
    npz = np.load(glob.glob(os.path.join(handout, f"*sess{sess}*.npz"))[0])
    tr = npz["traces"].astype(np.float64)  # (4400, 344) float32, 2ns period
    pt = npz["plaintext"].astype(np.uint8)
    ref = int(np.argmax(tr[0][45:70]))
    out = np.empty_like(tr)
    for i, t in enumerate(tr):  # de-jitter +-8 samples
        out[i] = np.roll(t, ref - int(np.argmax(t[45:70])))
    sos = signal.butter(4, 0.35, output="sos")  # clipped pre-filter: kill DC/saturation wings
    return signal.sosfiltfilt(sos, out, axis=1), pt


def cpa_key(traces, pt):
    """HW[SBOX[pt^guess]] CPA; byte i leaks at sample 120+11*i."""
    key = bytearray(16)
    for i in range(16):
        col = traces[:, 120 + 11 * i]
        col = col - col.mean()
        best, best_c = 0, -1.0
        for g in range(256):
            hyp = HW[SBOX[pt[:, i] ^ g]]
            hyp = hyp - hyp.mean()
            c = abs(float(hyp @ col) / (np.linalg.norm(hyp) * np.linalg.norm(col)))
            if c > best_c:
                best, best_c = g, c
        key[i] = best
        print(f"[cpa] byte {i:2d} -> {best:02x} (corr {best_c:.3f})", file=sys.stderr)
    return bytes(key)


def ccm_star_decrypt(key, nonce13, ct):
    """CCM* M=8 L=2: B0=0x59|nonce|mlenBE;returns plaintext or None on MIC fail."""
    m, mic = ct[:-8], ct[-8:]
    pt = bytearray()  # CTR-decrypt first: CCM* authenticates the plaintext
    ctr = 1
    for off in range(0, len(m), 16):
        s = aes_ecb(key, b"\x01" + nonce13 + struct.pack(">H", ctr))
        ctr += 1
        pt += bytes(a ^ c for a, c in zip(m[off:off + 16], s))
    pt = bytes(pt)
    b0 = b"\x59" + nonce13 + struct.pack(">H", len(pt))
    x = b"\x00" * 16
    for i in range(0, len(b0 + pt), 16):
        blk = (b0 + pt)[i:i + 16]
        x = aes_ecb(key, bytes(a ^ c for a, c in zip(x, blk.ljust(16, b"\x00"))))
    s0 = aes_ecb(key, b"\x01" + nonce13 + b"\x00\x00")
    tag = bytes(a ^ c for a, c in zip(x[:8], s0[:8]))
    return pt if tag == mic else None


def parse_frames(handout):
    """Triage alpha/beta/gamma pcaps: 74B secured frames (HDR21+ENC51), windows 0-19 @+79ms."""
    frames = []
    for ch, name in HOP.items():
        for pcap in glob.glob(os.path.join(handout, f"*{name}*.pcap*")):
            for pkt in rdpcap(pcap):
                raw = bytes(pkt.lastlayer())
                if len(raw) == 74 and struct.unpack("<H", raw[1:3])[0] == PAN:
                    hdr, enc = raw[:21], raw[21:]
                    src8 = hdr[5:13]
                    cnt = struct.unpack("<I", hdr[13:17])[0]
                    frames.append((cnt // 20, ch, src8, cnt, enc))
    frames.sort()
    print(f"[pcap] {len(frames)} secured frames, {len({w for w, *_ in frames})} windows",
          file=sys.stderr)
    return frames


def rs_decode(shards):
    """Any 8-of-9 authentic shards -> 188B DG15 record via Vandermonde GF(0x11d) solve."""
    idx = sorted(shards)[:8]
    n = len(next(iter(shards.values())))
    V = [[gf_pow(i + 1, j) for j in range(8)] for i in idx]
    rec = bytearray()
    for o in range(n):  # per-offset stripe: 8 code bytes -> 8 data bytes
        col = [shards[i][o] for i in idx]
        rec += bytes(gf_solve(V, col))
    return bytes(rec[:188])


def main(handout):
    csv_rows = list(csv.DictReader(open(glob.glob(os.path.join(handout, "*.csv"))[0])))
    print(f"[csv] {len(csv_rows)} capture rows -> AES inputs", file=sys.stderr)
    t49, p49 = load_scope(handout, 49)
    t50, p50 = load_scope(handout, 50)
    k43 = cpa_key(t49, p49)   # key-index 43
    k100 = cpa_key(t50, p50)  # decoy session key
    frames = parse_frames(handout)
    shards = {}
    for w, ch, src8, cnt, enc in frames:
        nonce = src8 + struct.pack("<I", cnt) + b"\x06"
        for key, want in ((k43, b"P15"), (k100, b"MEA")):
            pt = ccm_star_decrypt(key, nonce, enc)
            if pt and pt.startswith(want):
                kind = pt[3:9]
                if want == b"P15" and kind == b"ver01D1" and pt[9:13] == b"\xa1\x7c\x4a\x31":
                    shards[pt[13]] = pt[14:14 + 43 - 14]
                break
    print(f"[ccm] {len(shards)} authentic P15 shards (ki43); decoy MEA ignored", file=sys.stderr)
    rec = rs_decode(shards)
    body, crc, mac = rec[:-20], struct.unpack("<I", rec[-20:-16])[0], rec[-16:]
    assert zlib.crc32(body) & 0xFFFFFFFF == crc, "DG15 CRC32 mismatch"
    assert hashlib.blake2s(body, digest_size=16).digest() == mac, "DG15 BLAKE2s mismatch"
    note = body.split(b"note=")[1].split(b"\x00")[0].decode()
    print(note)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
