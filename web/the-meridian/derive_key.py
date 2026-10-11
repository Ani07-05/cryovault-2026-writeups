"""Offline re-derivation of The Meridian's vault key, once curators/rounds
are known from source review (see README) -- no need to drive the actual
prototype-pollution PoC through a browser session.
"""
import hashlib
import json

from Crypto.Cipher import AES

CURATORS = ['E. Vantar', 'R. Oikawa', 'H. Delacroix', 'K. Adeyemi', 'S. Marchetti']
PEPPER = 'meridian::provenance::v3::do-not-share'


def derive_key(bsalt: str, curators: list[str], rounds: int) -> bytes:
    material = f"{bsalt}:{'|'.join(curators)}".encode()
    digest = hashlib.sha256(material).digest()
    for _ in range(rounds - 1):
        digest = hashlib.sha256(digest).digest()
    return digest


def main():
    d = json.load(open('vault_blob.json'))
    bsalt = d['bsalt']
    rounds = 1000 + (sum(d['exhibit_years']) % 4096)

    key = derive_key(bsalt, CURATORS, rounds)
    nonce, ct, tag = (bytes.fromhex(d[k]) for k in ('nonce', 'ct', 'tag'))
    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
