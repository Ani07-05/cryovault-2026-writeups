import sys,re,struct
d=sys.argv[1]
w=open(d+"/case.db-wal","rb").read(); ps=512
def fr(i): o=32+i*(24+ps); return struct.unpack(">6I",w[o:o+24]), w[o+24:o+24+ps]
t="op-09e0d79b4b14".encode("utf-16le")
for i in (440,441,449,454):
    h,p=fr(i); print(i,h[:4],"page type",p[0] if h[1]!=1 else p[100])
    print(repr(p.replace(b"\0",b"")[:300]))
