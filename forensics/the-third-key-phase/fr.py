import pickle,collections
allr=[]
for f in('res.pkl','res2.pkl','res_v2.pkl','res_v2_cha.pkl'):
    allr+=pickle.load(open(f,'rb'))
seen={}
for x in allr: seen[x[0]]=x
print(len(seen),"pkts; missing",[i for i in range(1,266) if i not in seen])
def vi(b,p):
    f=b[p]>>6;n=1<<f;v=b[p]&0x3f
    for i in range(1,n):v=v<<8|b[p+i]
    return v,p+n
streams=collections.defaultdict(dict)  # (cr,dir)-> (sid)->{off:data}
other=[]
for idx,x in sorted(seen.items()):
    pt=x[7];p=0;cr=x[3][:6];dr=x[4]
    while p<len(pt):
        t,p=vi(pt,p)
        if t==0:continue
        if t==1: other.append((idx,'PING'));continue
        if t in(2,3):
            la,p=vi(pt,p);dl,p=vi(pt,p);rc,p=vi(pt,p);fr,p=vi(pt,p)
            for _ in range(rc):_,p=vi(pt,p);_,p=vi(pt,p)
            if t==3:
                for _ in range(3):_,p=vi(pt,p)
            continue
        if 8<=t<=15:
            sid,p=vi(pt,p);off=0
            if t&4:off,p=vi(pt,p)
            if t&2:l,p=vi(pt,p)
            else:l=len(pt)-p
            d=pt[p:p+l];p+=l
            streams[(cr,dr,x[1],x[2])].setdefault((sid),[]).append((off,d,idx,t&1))
            continue
        other.append((idx,hex(t),pt[p:p+40].hex()));break
pickle.dump(dict(streams),open('streams.pkl','wb'))
for k,v in streams.items():
    for sid,ch in v.items():
        print(k,sid,len(ch),sum(len(c[1]) for c in ch),"fin" if any(c[3] for c in ch) else "")
print(other[:30])
