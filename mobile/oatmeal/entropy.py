import math,collections,zlib
b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
blob=b[0x290:0x1899]
print('len',len(blob))
cnt=collections.Counter(blob)
ent=-sum((c/len(blob))*math.log2(c/len(blob)) for c in cnt.values())
print('entropy bits/byte', ent)
# look for gzip/zlib magic
for i in range(len(blob)-1):
    if blob[i]==0x1f and blob[i+1]==0x8b: print('gzip magic at',hex(0x290+i))
    if blob[i]==0x78 and blob[i+1] in (0x01,0x9c,0xda): print('zlib magic at',hex(0x290+i), hex(blob[i+1]))
try:
    d=zlib.decompressobj()
    out=d.decompress(blob)
    print('zlib decompress worked, len',len(out))
except Exception as e:
    print('zlib fail',e)
