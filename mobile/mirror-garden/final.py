import hashlib,hmac
ro=open(r'C:/Users/Aniruddh/Downloads/mg_extract/lib/arm64-v8a/libgarden.so','rb').read()
B=open('state.bin','rb').read()[:48]
inp=bytes.fromhex('4c2e5d5e6f6f71284c6c555e28615d23')
payload=bytes.fromhex('c9fd8c81c3b9da820eff4ac45347ea1525f0921ec88b554f85fabc6f92cd33ae20cbb21d9d44baf903c3ea9d1e6a05b8')
R=bytes(payload[i]^inp[i%16] for i in range(48))
K=bytes(a^b for a,b in zip(B,R))
h=hashlib.sha256(K).digest()
Ke=hashlib.sha256(h+b'garden/e/v1').digest(); Km=hashlib.sha256(h+b'garden/m/v1').digest()
nonce=ro[0x5b0:0x5c0]; ct=ro[0x700:0x72c]
tag=hmac.new(Km,nonce+ct,'sha256').digest()
print('tag',tag[:16].hex(),'expect',ro[0x5d0:0x5e0].hex(), tag[:16]==ro[0x5d0:0x5e0])
ks=hashlib.sha256(Ke+(0).to_bytes(4,'little')).digest()+hashlib.sha256(Ke+(1).to_bytes(4,'little')).digest()
print(bytes(a^b for a,b in zip(ct,ks)))
