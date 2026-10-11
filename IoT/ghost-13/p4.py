import struct,zlib,hashlib,json,itertools
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
o=open('maintenance_update (1).ota','rb').read()
fw=open('plc_firmware.bin','rb').read(); pg=open('plc_program.bin','rb').read()
sl,=struct.unpack('<I',o[8:12]); ml,pl=struct.unpack('<HH',o[56:60])
man=o[64:64+ml]; dl=o[64+ml:64+ml+pl]; sealed=o[64+ml+pl:]
assert zlib.crc32(dl[:-4])==struct.unpack('<I',dl[-4:])[0]
mg,ver,hc,osz,tsz,ocrc,tcrc=struct.unpack('<4sHHIIII',dl[:24]); print(mg,ver,hc,osz,tsz,hex(ocrc),hex(tcrc),zlib.crc32(fw)==ocrc)
img=bytearray(fw); pos=32
for _ in range(hc):
    off,ln,mode=struct.unpack('<IHH',dl[pos:pos+8]); rep=dl[pos+8:pos+8+ln]; pos+=8+ln
    print('hunk',off,ln,mode); img[off:off+ln]=rep
img=bytes(img); print(len(img),zlib.crc32(img)==tcrc, hashlib.sha256(img).digest()[:16].hex(), o[24:40].hex())
# section CRCs
for i in range(64,64+24*4,24):
    t=img[i:i+4]; offs,ln,crc=struct.unpack('<III',img[i+4:i+16]); print(t,zlib.crc32(img[offs:offs+ln])==crc)
print(img[:64].hex())
d=int(open('d.txt').read(),16)
s5=pg[64+128*5:64+128*6]; ID=s5[8:24]; salt=s5[24:40]
trim=s5[84:92]
wire='64658003'
digits=''.join(str((int(c)+t)%10) for c,t in zip(wire,trim)); print('digits',digits)
# target KDF constant
kd=None
for i in range(64,64+24*8,24):
    if img[i:i+4]==b'KDFD':
        offs,ln=struct.unpack('<II',img[i+4:i+12]); kd=img[offs:offs+ln]
const=kd[4:36]; print(hex(int.from_bytes(const,'big')))
nonce=digits.encode()+o[12:16]
aad=o[:60]+man+dl
ikm=d.to_bytes(32,'big')+ID+salt
salt_h=hashlib.sha256(const+salt).digest()
for fv in [struct.unpack('<H',img[i:i+2])[0] for i in (4,6,8)]+[4,3,2,1]:
    info=b'G13/diagnostic/v4'+ID+struct.pack('<H',fv)+digits.encode()+hashlib.sha256(img).digest()+hashlib.sha256(man).digest()+hashlib.sha256(dl).digest()
    key=HKDF(hashes.SHA256(),32,salt_h,info).derive(ikm)
    try:
        pt=AESGCM(key).decrypt(nonce,sealed,aad); print('OK fv',fv); print(pt[:4],zlib.decompress(pt[4:])); break
    except Exception as e: print('fail',fv)
