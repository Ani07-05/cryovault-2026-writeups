b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
blob=b[0x2a0:0x890]
print(len(blob))
open(r"C:\Users\Aniruddh\AppData\Local\Temp\claude\C--Users-Aniruddh-Downloads-cryovaultpes\a4ff2c31-9d0f-4050-ba50-09bc8e2d4496\scratchpad\blob.bin",'wb').write(blob)
best=[]
for k in range(256):
    x=bytes(c^k for c in blob)
    printable=sum(1 for c in x if 32<=c<127 or c in (9,10,13))
    best.append((printable,k))
best.sort(reverse=True)
for p,k in best[:10]:
    print(k,hex(k),p,len(blob))
