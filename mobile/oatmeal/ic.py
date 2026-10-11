b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
blob=b[0x290:0x1899]
def ic_for_keylen(data,klen):
    total=0; count=0
    for off in range(klen):
        col=data[off::klen]
        n=len(col)
        if n<2: continue
        from collections import Counter
        c=Counter(col)
        s=sum(v*(v-1) for v in c.values())
        total += s/(n*(n-1))
        count+=1
    return total/count if count else 0

for klen in range(1,41):
    print(klen, round(ic_for_keylen(blob,klen),4))
