import sqlite3,sys,struct,os
d=sys.argv[1]
w=open(d+"/case.db-wal","rb").read(); base=open(d+"/case.db","rb").read(); ps=512
def fr(i): o=32+i*(24+ps); return struct.unpack(">6I",w[o:o+24]), w[o+24:o+24+ps]
def build(layers,nm,size):
    st=bytearray(base)
    if len(st)<size*ps: st.extend(b"\0"*(size*ps-len(st)))
    for a,b in layers:
        for i in range(a,b):
            h,p=fr(i); st[(h[0]-1)*ps:h[0]*ps]=p
    fn=d+"/"+nm; open(fn,"wb").write(st[:size*ps]); return fn
def show(fn):
    c=sqlite3.connect(fn)
    try:
        print(c.execute("pragma integrity_check").fetchall()[:3])
        print([r[0][3:] for r in c.execute("select operation_id from operations order by rowid")])
        for r in c.execute("select n.note_id,n.revision,n.destination,n.attachment_id,n.operation_id,a.sha256 from notes n left join attachments a using(attachment_id) where n.note_id='note-7211098c21a6'"): print(r)
    except Exception as e: print(e)
for name,layers in {"A":[(725,1538),(108,455)],"B":[(108,455)],"C":[(725,1538),(0,108),(108,455)]}.items():
    print(name); show(build(layers,f"v{name}.db",208))
