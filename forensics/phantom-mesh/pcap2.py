import sys
from scapy.all import rdpcap
pkts = rdpcap(sys.argv[1])
for i,p in enumerate(pkts):
    raw=bytes(p)
    h=raw.hex()
    idx=h.find("1c03")
    if idx>=0:
        cmd=h[idx+4:idx+6]
        print(i,cmd,h[idx:])
