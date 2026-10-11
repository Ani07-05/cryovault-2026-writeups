import pickle,collections
allr=[]
for f in('res.pkl','res2.pkl','res_v2.pkl','res_v2_cha.pkl'):
    allr+=pickle.load(open(f,'rb'))
seen={x[0]:x for x in allr}
def vi(b,p):
    f=b[p]>>6;n=1<<f;v=b[p]&0x3f
    for i in range(1,n):v=v<<8|b[p+i]
    return v,p+n
out=[]
for idx,x in sorted(seen.items()):
    pt=x[7];p=0
    fr=[]
    while p<len(pt):
        t,p=vi(pt,p)
        if t==0:continue
        if t==1:fr.append('PING');continue
        if t in(2,3):
            la,p=vi(pt,p);dl,p=vi(pt,p);rc,p=vi(pt,p);f0,p=vi(pt,p)
            for _ in range(rc):_,p=vi(pt,p);_,p=vi(pt,p)
            if t==3:
                for _ in range(3):_,p=vi(pt,p)
            fr.append(('ACK',la));continue
        if 8<=t<=15:
            sid,p=vi(pt,p);off=0
            if t&4:off,p=vi(pt,p)
            if t&2:l,p=vi(pt,p)
            else:l=len(pt)-p
            d=pt[p:p+l];p+=l;fr.append(('S',sid,off,len(d),t&1,d));continue
        if t==4: a=[vi(pt,p)];sid,p=a[0];e,p=vi(pt,p);fs,p=vi(pt,p);fr.append(('RESET',sid,e,fs));continue
        if t==5: sid,p=vi(pt,p);e,p=vi(pt,p);fr.append(('STOPSEND',sid,e));continue
        if t in(0x10,0x12,0x13,0x16,0x17,0x14,0x19):
            v,p=vi(pt,p);fr.append((hex(t),v));continue
        if t in(0x11,0x15):
            a,p=vi(pt,p);b,p=vi(pt,p);fr.append((hex(t),a,b));continue
        if t==0x18:
            sq,p=vi(pt,p);rp,p=vi(pt,p);l=pt[p];p+=1;c=pt[p:p+l];p+=l+16;fr.append(('NEWCID',sq,rp,c.hex()));continue
        if t in(0x1a,0x1b):
            fr.append((hex(t),pt[p:p+8].hex()));p+=8;continue
        if t in(0x1c,0x1d):
            e,p=vi(pt,p)
            if t==0x1c:_,p=vi(pt,p)
            l,p=vi(pt,p);fr.append(('CLOSE',e,pt[p:p+l]));p+=l;continue
        if t==0x1e:fr.append('HSDONE');continue
        if t in(0x30,0x31):
            if t==0x31:l,p=vi(pt,p)
            else:l=len(pt)-p
            fr.append(('DGRAM',pt[p:p+l].hex()[:60],l));p+=l;continue
        fr.append(('UNK',hex(t),pt[p:p+30].hex()));break
    out.append((idx,x[3][:6],x[4][:3],x[1],x[2],x[5],x[6],fr))
pickle.dump(out,open('frames.pkl','wb'))
