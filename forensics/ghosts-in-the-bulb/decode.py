"""Reconstruction: extract the bulb's LSB-steganographed ciphertext and the
robovac's interval-coded key, then AES-GCM decrypt.
"""
import base64
import hashlib
import json
import struct
from itertools import pairwise

from scapy.all import IP, TCP, rdpcap
from Crypto.Cipher import AES

PCAP = 'capture.pcap'
BULB_IP = '192.168.1.70'
ROBOVAC_IP = '192.168.1.40'

START, END = bytes.fromhex('A55AA55A'), bytes.fromhex('F00DCAFE')
INTERVAL_SYMBOL = {30: 0b00, 45: 0b01, 60: 0b10, 75: 0b11}


def extract_bulb_stream(packets):
    bits = []
    for pkt in packets:
        if pkt[IP].src != BULB_IP or not pkt.haslayer(TCP):
            continue
        payload = json.loads(bytes(pkt[TCP].payload))
        bits.append(payload['bri'] & 1)
    raw = bytes(int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits) - 7, 8))
    start = raw.find(START) + len(START)
    length = raw[start]
    end = raw.find(END, start)
    b85 = raw[start + 1:end]
    return base64.b85decode(b85)[:length]


def extract_key_bits(packets):
    times = [float(p.time) for p in packets if p[IP].src == ROBOVAC_IP and p.haslayer(TCP)]
    dts = [round(b - a) for a, b in pairwise(times)]
    bits = []
    for dt in dts:
        nearest = min(INTERVAL_SYMBOL, key=lambda k: abs(k - dt))
        if abs(nearest - dt) <= 3 and nearest != 60:
            bits.append(INTERVAL_SYMBOL[nearest])
    sym_bytes = bytes(int(f'{bits[i]:02b}{bits[i+1]:02b}{bits[i+2]:02b}{bits[i+3]:02b}', 2)
                       for i in range(0, len(bits) - 3, 4))
    assert sym_bytes[0] == 0xA5  # sync
    return sym_bytes[1:-1]  # drop sync + trailing 0xAA


def main():
    packets = rdpcap(PCAP)
    frame = extract_bulb_stream(packets)
    assert frame[:4] == b'GITB'
    nonce, ct, tag = frame[4:16], frame[16:-16], frame[-16:]

    key_material = extract_key_bits(packets)
    key = hashlib.sha256(key_material).digest()

    pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    print(pt.decode())


if __name__ == '__main__':
    main()
