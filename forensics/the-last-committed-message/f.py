import sqlite3,sys,json,hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
d=sys.argv[1]
c=sqlite3.connect(d+"/vA.db")
n,r,dest,a,o,sha=c.execute("select n.note_id,n.revision,n.destination,n.attachment_id,n.operation_id,a.sha256 from notes n join attachments a using(attachment_id) where n.operation_id='op-09e0d79b4b14'").fetchone()
print(repr(dest[-80:]),len(dest),dest.isascii())
E=json.dumps([n,str(r),dest,sha],ensure_ascii=True,separators=(",",":")).encode("ascii")
key=hashlib.scrypt(b"isfcr-forensics\x00"+E,salt=bytes.fromhex("a3845b1a904c5ee73abe7329b5d735d7"),n=131072,r=8,p=1,maxmem=2**28,dklen=32)
print(AESGCM(key).decrypt(bytes.fromhex("ca98cff993b27fd3bb352436"),bytes.fromhex("3fa8b9049b01fb8d12df130b404352f9c678c272cccb7e6c034554c902f1ca4d574fc04db8892fead1ad394735e021"),b"the-last-committed-message"))
