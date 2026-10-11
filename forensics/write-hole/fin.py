import re,struct,zlib,hashlib,json
from dissect.extfs import ExtFS
import raid
raid.LEN=16<<20
D=raid.D;OFF=raid.OFF;CH=32768
v=open('vol.img','rb').read()
# gather KSLT candidates from every raw disk page and xor combos
cands=set()
def scan(buf):
    for m in re.finditer(b'KSLT\x01',buf):
        b=buf[m.start():m.start()+64]
        if len(b)==64:
            cands.add(b[:52])
for dsk in D:scan(dsk)
scan(v)
# also pairwise xors of chunks per stripe (reconstruction)
ns=raid.LEN//CH
for s in range(ns):
    ch=[D[i][OFF+s*CH:OFF+(s+1)*CH] for i in range(3)]
    for a,b,c in ((0,1,2),(0,2,1),(1,2,0)):
        x=bytes(p^q for p,q in zip(ch[a],ch[b]))
        scan(x)
print(len(cands))
want='b5125b19a47d9d61'
keys={}
for b in cands:
    magic,ver,job=struct.unpack('>4sB3xQ',b[:16]);key=b[16:48];crc=struct.unpack('>I',b[48:52])[0]
    ok=zlib.crc32(b[:48])==crc
    kid=hashlib.sha256(key).hexdigest()[:16]
    print(job,ok,kid,kid==want)
    if kid==want:keys[job]=key
json.dump({k:v.hex() for k,v in keys.items()},open('keys.json','w'))
