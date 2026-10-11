import pickle,hashlib,json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
r=pickle.load(open('asm.pkl','rb'))
crs=[l.split()[1] for l in open('C:/Users/Aniruddh/AppData/Local/Temp/keys.txt') if l.startswith('CLIENT')]
def inter(parts,U):
    out=bytearray();i=0
    while True:
        a=False
        for p in parts:
            c=p[i*U:(i+1)*U]
            if c: out+=c;a=True
        if not a:break
        i+=1
    return bytes(out)
def tryf(f,cr):
    h=hashlib.sha256(f).hexdigest()
    E=json.dumps(["6e26102a48d71fe1d7f68231",cr,h],separators=(",",":")).encode()
    key=hashlib.scrypt(b"isfcr-forensics\x00"+E,salt=bytes.fromhex("55cfbdc7a31326404d59e133d991dc88"),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
    try:
        print('FOUND',cr,AESGCM(key).decrypt(bytes.fromhex("f684f2db484cdd8e6f38b16e"),bytes.fromhex("c4805539a3db8bc0bba5f5fb6ad76c1125d889aab86af18041007f8f49e30d2b5822be5cf8d26d21ddb576b25d06bc"),b"the-third-key-phase"),flush=True);return True
    except Exception: return False
g=lambda c,s:r[(c[:6],s)]
c8=[c for c in crs if c.startswith('87566b')][0]
cb=[c for c in crs if c.startswith('bfa624')][0]
# bfa6 candidates: streams 0,4 + partial 8 (unit 90)
f1=inter([g(cb,0),g(cb,4),g(cb,8)],90)
f2=inter([g(cb,0),g(cb,4)],90)
fs=[('b_i3',f1),('b_i2',f2),('b_c',g(cb,0)+g(cb,4)+g(cb,8))]
f8=inter([g(c8,0),g(c8,20),g(c8,16),g(c8,12)],119)
fs.append(('8',f8))
for n,f in fs:
    for cr in crs:
        if tryf(f,cr):print(n);raise SystemExit
print('none')
