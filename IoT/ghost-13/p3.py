import struct,pickle,hashlib,zlib
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
fr=pickle.load(open('frames.pkl','rb'))
fw=open('plc_firmware.bin','rb').read(); pg=open('plc_program.bin','rb').read()
print('KDFD',fw[8400:8478].hex()); print('PUBK',fw[8480:8548].hex())
const=fw[8400+4:8400+4+32]  # after G13K
print(fw[8400:8404])
slots=[pg[64+128*i:64+128*i+128] for i in range(8)]
for sid,f in fr.items():
    print(hex(sid),'crc32',zlib.crc32(f[:114])==struct.unpack('<I',f[114:118])[0])
    for i,s in enumerate(slots):
        ID=s[8:24]; salt=s[24:40]
        key=hashlib.sha256(b'G13/link/v2'+const+ID+salt).digest()
        c=Cipher(algorithms.AES(key),modes.CTR(f[10:26])).decryptor()
        body=c.update(f[26:114])
        print(' slot',i,body[:24].hex())
print('=====')
from cryptography.hazmat.primitives.asymmetric import ec
s5=slots[5]; ID=s5[8:24]; salt=s5[24:40]
key=lambda: hashlib.sha256(b'G13/link/v2'+const+ID+salt).digest()
n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
info={}
for sid,f in fr.items():
    body=Cipher(algorithms.AES(key()),modes.CTR(f[10:26])).decryptor().update(f[26:114])
    state=body[:24]; r=int.from_bytes(body[24:56],'big'); s=int.from_bytes(body[56:88],'big')
    z=int.from_bytes(hashlib.sha256(b'G13/sign/v2'+f[:26]+state+ID+salt[:8]).digest(),'big')
    info[sid]=(r,s,z); print(hex(sid),state,hex(r)[:20])
x=int.from_bytes(fw[8484:8516],'big'); y=int.from_bytes(fw[8516:8548],'big')
pub=ec.EllipticCurvePublicNumbers(x,y,ec.SECP256R1()).public_key()
ks=list(info)
for i in ks:
  for j in ks:
    if i<j and info[i][0]==info[j][0]:
        r,s1,z1=info[i]; _,s2,z2=info[j]
        k=(z1-z2)*pow(s1-s2,-1,n)%n; d=(s1*k-z1)*pow(r,-1,n)%n
        pn=ec.derive_private_key(d,ec.SECP256R1()).public_key().public_numbers()
        print('pair',hex(i),hex(j),'d',hex(d),'pub match',pn.x==x and pn.y==y)
        open('d.txt','w').write(hex(d))
