import sys,json,hmac,hashlib,struct
sys.argv=['x','/c/Users/Aniruddh/Downloads/cryovaultpes/h4/the-third-key-phase/capture.pcapng']
from scapy.all import rdpcap,UDP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
pk=rdpcap('C:/Users/Aniruddh/Downloads/cryovaultpes/h4/the-third-key-phase/capture.pcapng')
d=bytes(pk[0][UDP].payload); print(len(d),d[:12].hex())
for i in (0,2,51,60,61,100,200,264):
    d=bytes(pk[i][UDP].payload);print(i+1,d[0]>>6&1,d[0]>>7,d[:12].hex())
