import pickle,hashlib,json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
r=pickle.load(open('asm.pkl','rb'))
cr='87566b'
g=lambda s:r[(cr,s)]
print(g(8)==g(16),g(16)==g(24),g(4)==g(20)[:len(g(4))])
U=119
def inter(parts):
    out=bytearray();i=0
    while True:
        any_=False
        for p in parts:
            c=p[i*U:(i+1)*U]
            if c: out+=c;any_=True
        if not any_:break
        i+=1
    return bytes(out)
full='87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3'
cands={'inter':inter([g(0),g(20),g(16),g(12)]),'inter24':inter([g(0),g(20),g(24),g(12)]),'concat':g(0)+g(20)+g(16)+g(12)}
for n,f in cands.items():
    print(n,len(f),f[:16].hex(),hashlib.sha256(f).hexdigest())
    ev=["6e26102a48d71fe1d7f68231",full,hashlib.sha256(f).hexdigest()]
    E=json.dumps(ev,ensure_ascii=True,separators=(",",":")).encode()
    key=hashlib.scrypt(b"isfcr-forensics\x00"+E,salt=bytes.fromhex("55cfbdc7a31326404d59e133d991dc88"),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
    try:
        print(AESGCM(key).decrypt(bytes.fromhex("f684f2db484cdd8e6f38b16e"),bytes.fromhex("c4805539a3db8bc0bba5f5fb6ad76c1125d889aab86af18041007f8f49e30d2b5822be5cf8d26d21ddb576b25d06bc"),b"the-third-key-phase"))
    except Exception as e: print('fail')
open('cand_inter.bin','wb').write(cands['inter'])
