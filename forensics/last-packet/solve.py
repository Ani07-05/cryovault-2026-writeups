#!/usr/bin/env python3
"""last-packet solve: extract debug XOR key from pcap, brute-force it.
Usage: python3 solve.py challenge2.pcap (needs the handout pcap)"""
import base64, json, re, sys
from scapy.all import rdpcap, Raw

def extract_bodies(pcap_path):
    bodies = []
    for p in rdpcap(pcap_path):
        if not p.haslayer(Raw):
            continue
        data = bytes(p[Raw].load).decode("utf-8", errors="ignore")
        if "\r\n\r\n" in data:
            bodies.append(data.split("\r\n\r\n", 1)[1])
        bodies.append(data)
    return bodies

def find_debug_key(bodies):
    for b in bodies:
        for m in re.finditer(r"\{[^{}]*internal_key[^{}]*\}", b):
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                continue
            dbg = obj.get("debug", obj)
            if isinstance(dbg, dict) and "internal_key" in dbg:
                return dbg["internal_key"], dbg.get("enc", "")
    for b in bodies:  # fallback: raw hex string
        m = re.search(r'"internal_key"\s*:\s*"([0-9a-fA-F]+)"', b)
        if m:
            return m.group(1), "xor"
    raise SystemExit("debug internal_key not found in pcap")

def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} challenge2.pcap")
    hex_key, enc = find_debug_key(extract_bodies(sys.argv[1]))
    print(f"[+] internal_key hex len={len(hex_key)} enc={enc}")
    ct = base64.b64decode(bytes.fromhex(hex_key))
    print(f"[+] ciphertext {len(ct)} bytes")
    for k in range(256):
        try:
            s = bytes(c ^ k for c in ct).decode()
        except UnicodeDecodeError:
            continue
        if s.startswith("isfcr{") and s.endswith("}") and s.isprintable():
            print(f"[+] single-byte XOR key={k} ({chr(k)!r})")
            print(s)
            return
    print("[-] no single-byte XOR key yielded a flag")

if __name__ == "__main__":
    main()
