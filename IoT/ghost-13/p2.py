import struct,pickle,hashlib,zlib
exec(open(r'C:\Users\Aniruddh\AppData\Local\Temp\claude\C--Users-Aniruddh-Downloads-cryovaultpes\02bfe440-d5c8-48fe-843a-35da13a99aa2\scratchpad\p1.py').read().split("for port")[0])
st={}
for sp,seq,pl in segs:
    if sp==49152 and pl: st[seq]=pl
buf=b''.join(st[k] for k in sorted(st))
def crc16(b):
    c=0xFFFF
    for x in b:
        c^=x<<8
        for _ in range(8): c=((c<<1)^0x1021)&0xFFFF if c&0x8000 else (c<<1)&0xFFFF
    return c
pos=0; frags={}
while pos<len(buf):
    tid,pid,ln,uid=struct.unpack('>HHHB',buf[pos:pos+7]); pdu=buf[pos+7:pos+6+ln]; pos+=6+ln
    if pdu[0]!=16: continue
    addr,qty,bc=struct.unpack('>HHB',pdu[1:6]); f=pdu[6:]
    magic,sid,idx,dc,fl,par,res=struct.unpack('<4sHBBHBB',f[:12]); pay=f[12:52]; crc=struct.unpack('<H',f[52:54])[0]
    ok=crc16(f[:52])==crc; aok=addr==(0x4200+20*idx if idx<3 else 0x4300)
    print(tid,hex(addr),sid,idx,dc,fl,par,'crc',ok,'addr',aok)
    if ok and aok: frags.setdefault(sid,{})[idx]=pay
out={}
for sid,fr in frags.items():
    idxs=sorted(fr); print(hex(sid),idxs)
    if 3 in fr and len(fr)==3:
        miss=[i for i in range(3) if i not in fr][0]
        x=bytes(a^b^c for a,b,c in zip(*[fr[i] for i in range(4) if i!=miss])); fr[miss]=x
    frame=b''.join(fr[i] for i in range(3))
    fl=[f for f in [struct.unpack('>H',b'\x00\x76')]][0][0]
    out[sid]=frame[:118]; print(frame[:118].hex())
pickle.dump(out,open('frames.pkl','wb'))
