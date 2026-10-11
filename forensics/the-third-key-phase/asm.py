import pickle,collections,math,zlib
o=pickle.load(open('frames.pkl','rb'))
st=collections.defaultdict(lambda:collections.defaultdict(dict))
fin={}
for r in o:
    if r[2]!='CLI': continue
    for f in r[7]:
        if isinstance(f,tuple) and f[0]=='S':
            _,sid,off,l,fn,d=f
            st[r[1]][sid][off]=d
            if fn: fin[(r[1],sid)]=off+l
def asm(cr,sid):
    ch=st[cr][sid];buf=bytearray();pos=0;gaps=[]
    for off in sorted(ch):
        if off>pos: gaps.append((pos,off)); buf+=bytes(off-pos); pos=off
        d=ch[off]
        buf[off:off+len(d)]=d; pos=max(pos,off+len(d))
    return bytes(buf),gaps
def ent(b):
    c=collections.Counter(b);n=len(b);return -sum(v/n*math.log2(v/n) for v in c.values())
res={}
for cr in st:
    for sid in sorted(st[cr]):
        b,g=asm(cr,sid);res[(cr,sid)]=b
        print(cr,sid,len(b),'fin',fin.get((cr,sid)),'gaps',g,'ent%.2f'%ent(b),b[:8].hex())
pickle.dump(res,open('asm.pkl','wb'))
