"""Reconstruction of the Journal Necromancy solve: find the three hidden
32-byte key shares stashed behind DE AD 53 47 markers in unreferenced NTFS
clusters, verify their parity, XOR them into the AES-256-GCM key, and decrypt
secure_archive.enc.
"""
import re
from functools import reduce
from hashlib import sha256
from Crypto.Cipher import AES

IMG = 'evidence.img'
MARKER = b'\xDE\xAD\x53\x47'


def find_shares(data: bytes):
    shares = {}
    for m in re.finditer(re.escape(MARKER), data):
        o = m.start()
        block = data[o + 4:o + 4 + 34]
        if len(block) != 34:
            continue
        idx, share, parity = block[0], block[1:33], block[33]
        if reduce(lambda a, c: a ^ c, share) ^ idx == parity:
            shares[idx] = share
    return shares


def main():
    data = open(IMG, 'rb').read()
    shares = find_shares(data)
    print('shares found:', sorted(shares))
    key = bytes(a ^ b ^ c for a, b, c in zip(*[shares[i] for i in sorted(shares)]))

    enc = open('secure_archive.enc', 'rb').read()  # ENC1 marker + 12B nonce + ct + 16B tag
    assert enc[:4] == b'ENC1'
    nonce, ct, tag = enc[4:16], enc[16:-16], enc[-16:]
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
