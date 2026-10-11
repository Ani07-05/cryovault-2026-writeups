import hmac,hashlib,struct
from scapy.all import rdpcap,UDP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
p=rdpcap('C:/Users/Aniruddh/Downloads/cryovaultpes/h4/the-third-key-phase/capture.pcapng')
def hk(h,prk,info,n):
    out=b"";t=b"";i=1
    while len(out)<n:
        t=hmac.new(prk,t+info+bytes([i]),h).digest();out+=t;i+=1
    return out[:n]
def lab(h,s,l,n):
    f=b"tls13 "+l;return hk(h,s,struct.pack(">H",n)+bytes([len(f)])+f+b"\0",n)
def run(idx,sec0,v2,cha):
    L=(b'quicv2 key',b'quicv2 iv',b'quicv2 hp',b'quicv2 ku') if v2 else (b'quic key',b'quic iv',b'quic hp',b'quic ku')
    h=hashlib.sha256 if len(sec0)==32 else hashlib.sha384
    kl=32 if (cha or len(sec0)==48) else 16
    d=bytes(p[idx-1][UDP].payload);po=9
    hp=lab(h,sec0,L[2],kl)
    smp=d[po+4:po+20]
    m=(Cipher(algorithms.ChaCha20(hp,smp),None).encryptor().update(bytes(5))) if cha else Cipher(algorithms.AES(hp),modes.ECB()).encryptor().update(smp)[:5]
    fb=d[0]^(m[0]&0x1f);pnl=(fb&3)+1
    pt_=bytes(a^b for a,b in zip(d[po:po+pnl],m[1:1+pnl]));tr=int.from_bytes(pt_,'big')
    hdr=bytes([fb])+d[1:po]+pt_
    print(idx,'pnl',pnl,'tr',tr,'kp',(fb>>2)&1)
    sec=sec0
    for gen in range(12):
        key=lab(h,sec,L[0],kl);iv=lab(h,sec,L[1],12);sec=lab(h,sec,L[3],len(sec))
        A=ChaCha20Poly1305(key) if cha else AESGCM(key)
        w=1<<(8*pnl)
        for cand in range(tr,1<<24,w):
            n=bytes(a^b for a,b in zip(iv,cand.to_bytes(12,'big')))
            try: pl=A.decrypt(n,d[po+pnl:],hdr);print('OK gen',gen,'pn',cand,pl.hex());return
            except Exception:pass
    print('fail')
run(244,bytes.fromhex('7ba4f71ae308f585347d9e36721736e7457aaca5790399598ff3db07032bff5f'),0,0) if False else None
s=bytes.fromhex('04b677c66f748997dddc125b6670949d9c48f4f0c6f0556eca6513ab3bb5d539')
for i in(244,245,246): run(i,s,1,1)
c=bytes.fromhex('da98965225e39a1235448314faa050282a12734b61036621fd7bb6b43ac096c7')
sv=bytes.fromhex('c63e6208ab33322bda0c128b29593b4e6c453dbff44491ee78f3627214b9f9d2')
run(182,sv,0,0)
