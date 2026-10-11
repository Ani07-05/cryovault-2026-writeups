exec(open('fin2.py').read().split("out=b''")[0])
i=3
s,dd,od,pd=disks(base+i)
rec=bytearray(xor(chunk(od,s),chunk(pd,s)))
target=intent['records'][i]
def test(r):return hashlib.sha256(r).hexdigest()==target
# positions of differences vs data chunk? try first near shard line
start=12+8833
for pos in list(range(start,start+60))+list(range(len(rec)-16,len(rec))):
    orig=rec[pos]
    for v in range(256):
        rec[pos]=v
        if test(rec):
          print('FOUND pos',pos,'orig',orig,'new',v)
          from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
          pt=Cipher(algorithms.AES(key),modes.CTR(bytes(rec[:12])+struct.pack('>I',2))).decryptor().update(bytes(rec[12:-16]))
          print(pt[8833:8880]);print(rec[-16:].hex())
          try:AESGCM(key).decrypt(bytes(rec[:12]),bytes(rec[12:]),b"payload.bin|7|3");print('gcm ok')
          except Exception as e:print('gcm bad')
          raise SystemExit
    rec[pos]=orig
print('no single-byte fix near')
