import sqlite3,sys,struct,os,shutil
d=sys.argv[1]
w=open(d+"/case.db-wal","rb").read()
base=open(d+"/case.db","rb").read()
ps=512
hdr=struct.unpack(">8I",w[:32]); salt=hdr[4:6]
print("header salt",salt, "dbsize base pages",len(base)/ps)
# checksum validation
def ck(data,s0,s1,be=True):
    f=">%dI" if be else "<%dI"
    v=struct.unpack(f%(len(data)//4),data)
    for i in range(0,len(v),2):
        s0=(s0+v[i]+s1)&0xffffffff; s1=(s1+v[i+1]+s0)&0xffffffff
    return s0,s1
be = (hdr[0]&1)==1
s0,s1=ck(w[:24],0,0,be)
pages=bytearray(base); commits=[]
cur={}
n=(len(w)-32)//(24+ps)
valid=0
for i in range(n):
    o=32+i*(24+ps); fh=w[o:o+24]; data=w[o+24:o+24+ps]
    pg,cm,sa,sb,c0,c1=struct.unpack(">6I",fh)
    if (sa,sb)!=tuple(salt): print("salt mismatch at",i); break
    s0,s1=ck(fh[:8],s0,s1,be); s0,s1=ck(data,s0,s1,be)
    if (s0,s1)!=(c0,c1): print("checksum fail at",i); break
    cur[pg]=data
    if cm:
        commits.append((i,cm,dict(cur))); cur={}
print("commits",len(commits))
state=bytearray(base)
os.makedirs(d+"/st",exist_ok=True)
prev=None
for k,(i,cm,fr) in enumerate(commits):
    need=cm*ps
    if len(state)<need: state.extend(b"\0"*(need-len(state)))
    for pg,data in fr.items(): state[(pg-1)*ps:pg*ps]=data
    p=d+"/st/s.db"
    open(p,"wb").write(state[:need])
    c=sqlite3.connect(p)
    try:
        ops=[r[0] for r in c.execute("select operation_id from operations order by rowid")]
        nn=c.execute("select count(*) from notes").fetchone()[0]
    except Exception as e: ops=str(e);nn=-1
    c.close()
    print(k,i,cm,nn,ops)
    open(d+f"/st/s{k}.db","wb").write(state[:need])
