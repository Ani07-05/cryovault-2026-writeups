import sqlite3,sys,struct
d=sys.argv[1]
w=open(d+"/case.db-wal","rb").read()
print(w[:32].hex(), len(w))
magic,ver,ps,seq,s1,s2=struct.unpack(">IIIIII"[:0] or ">IIIIII",w[:24]) if False else struct.unpack(">6I",w[:24])
print(hex(magic),ps,seq)
n=(len(w)-32)//(24+ps);print("frames",n)
for i in range(n):
    o=32+i*(24+ps); pg,commit,sa,sb=struct.unpack(">4I",w[o:o+16]); print(i,pg,commit,hex(sa)[:6])
