import json,hashlib,struct
from dissect.extfs import ExtFS
import raid
raid.LEN=16<<20
D=raid.D;OFF=raid.OFF;CH=32768
fs=ExtFS(open('vol.img','rb'))
n=fs.get('/stage/payload.bin')
print(n.dataruns() if callable(n.dataruns) else n.dataruns)
intent=json.loads(fs.get('/stage/job-0007.intent').open().read())
key=bytes.fromhex(json.load(open('keys.json'))['7'])
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
runs=list(n.dataruns())
blocks=[]
for r in runs:
    # dataruns tuple (lblk, pblk, len) guess
    print(r)
perm=(1,2,0)
def disks(k):
    s,idx=divmod(k,2);p=(2-s)%3
    dd=(p+1+idx)%3
    other=(p+1+(1-idx))%3
    return s,perm[dd],perm[other],perm[p]
def chunk(disk,s):return D[disk][OFF+s*CH:OFF+(s+1)*CH]
xor=lambda a,b:bytes(x^y for x,y in zip(a,b))
base=1160*4096//CH
out=b''
for i,h in enumerate(intent['records']):
    s,dd,od,pd=disks(base+i)
    vers={'data':chunk(dd,s),'recon':xor(chunk(od,s),chunk(pd,s))}
    res=None
    for nm,c in vers.items():
        ok=hashlib.sha256(c).hexdigest()==h
        dec=None
        try:
            nonce=c[:12];aad=b"payload.bin|%d|%d"%(7,i)
            dec=AESGCM(key).decrypt(nonce,c[12:],aad)
        except Exception as e:pass
        print(i,'stripe',s,nm,'hash',ok,'dec',dec is not None)
        if ok and dec is not None and res is None:res=dec
    out+=res if res else b'[MISSING %d]'%i
print(out[:200])
open('plain.bin','wb').write(out)
