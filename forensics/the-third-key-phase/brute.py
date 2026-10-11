import pickle,hashlib,json,itertools
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
r=pickle.load(open('asm.pkl','rb'));g=lambda s:r[('87566b',s)]
full='87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3'
U=119
def inter(parts):
    out=bytearray();i=0
    while True:
        a=False
        for p in parts:
            c=p[i*U:(i+1)*U]
            if c: out+=c;a=True
        if not a:break
        i+=1
    return bytes(out)
def tryf(f,tag):
    h=hashlib.sha256(f).hexdigest()
    E=json.dumps(["6e26102a48d71fe1d7f68231",full,h],separators=(",",":")).encode()
    key=hashlib.scrypt(b"isfcr-forensics\x00"+E,salt=bytes.fromhex("55cfbdc7a31326404d59e133d991dc88"),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
    try:
        print('FOUND',tag,AESGCM(key).decrypt(bytes.fromhex("f684f2db484cdd8e6f38b16e"),bytes.fromhex("c4805539a3db8bc0bba5f5fb6ad76c1125d889aab86af18041007f8f49e30d2b5822be5cf8d26d21ddb576b25d06bc"),b"the-third-key-phase"),flush=True);return True
    except Exception: return False
seen=set()
for s4 in (4,20):
  for s8 in (8,16,24):
    P={0:g(0),4:g(s4),8:g(s8),12:g(12)}
    for perm in itertools.permutations([0,4,8,12]):
      for mode in('i','c'):
        parts=[P[k] for k in perm]
        f=inter(parts) if mode=='i' else b''.join(parts)
        if f in seen:continue
        seen.add(f)
        if tryf(f,(s4,s8,perm,mode)):raise SystemExit
print('none',len(seen))
