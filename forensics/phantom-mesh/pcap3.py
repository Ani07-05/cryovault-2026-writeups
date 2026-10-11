import sys
from scapy.all import rdpcap
pkts = rdpcap(sys.argv[1])
for i,p in enumerate(pkts):
    raw=bytes(p)
    h=raw.hex()
    idx=h.find("1c03")
    if idx<0: continue
    body=bytes.fromhex(h[idx:])
    cmd=body[2]
    if cmd==0x21:
        sec=body[3]; fc=int.from_bytes(body[4:8],"little"); eui=body[8:16].hex()
        rest=body[16:-2]  # drop trailing FCS 2 bytes? actually FCS may be 2 bytes at very end of frame not of LMP; need check
        mic=rest[-4:].hex(); ct=rest[:-4].hex()
        print(i,"REPORT fc",fc,"eui",eui,"ctlen",len(rest)-4,"ct",ct,"mic",mic)
    elif cmd==0x11:
        sec=body[3]; fc=int.from_bytes(body[4:8],"little"); eui=body[8:16].hex()
        rest=body[16:-2]
        mic=rest[-4:].hex(); ct=rest[:-4].hex()
        print(i,"TRANSPORT_KEY fc",fc,"eui",eui,"ct",ct,"mic",mic,"ctlen",len(rest)-4)
    elif cmd==0x12:
        nonce=body[3:19].hex(); tag=body[19:27].hex()
        print(i,"KEY_CONFIRM nonce",nonce,"tag",tag,"full",body.hex())
    elif cmd==0x30:
        print(i,"BEACON",body.hex())
