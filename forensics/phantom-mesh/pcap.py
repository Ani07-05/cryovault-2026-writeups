import sys
from scapy.all import rdpcap, Dot15d4
pkts = rdpcap(sys.argv[1])
print(len(pkts))
for i,p in enumerate(pkts):
    raw=bytes(p)
    print(i,len(raw),raw.hex())
