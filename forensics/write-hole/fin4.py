exec(open('fin2.py').read().split("out=b''")[0])
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
import re
i=3
s,dd,od,pd=disks(base+i)
rec=xor(chunk(od,s),chunk(pd,s))
nonce=rec[:12]
ct=rec[12:-16]
# CTR with counter starting at 2
c=Cipher(algorithms.AES(key),modes.CTR(nonce+struct.pack('>I',2))).decryptor()
pt=c.update(ct)
open('rec3.txt','wb').write(pt)
print(pt[:300])
bad=[j for j in range(0,len(pt),512) if not re.fullmatch(rb'[\x20-\x7e\n]*',pt[j:j+512])]
print('nonprintable sectors', len(bad), bad[:70])
print(re.findall(rb'shard[^\n]*',pt))
