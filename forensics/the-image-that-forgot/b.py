import tarfile,io,sys,os,json
B=sys.argv[1]; m=sys.argv[2]
def blob(d): return open(os.path.join(B,'blobs','sha256',d.split(':')[1]),'rb').read()
mf=json.loads(blob(m))
fs={}  # path -> (type,data,link)
for l in mf['layers']:
    t=tarfile.open(fileobj=io.BytesIO(blob(l['digest'])))
    print('--- layer',l['digest'][7:19])
    for ti in t:
        print('  ',ti.name,ti.type,ti.linkname,ti.size)
        n=ti.name.rstrip('/'); base=os.path.basename(n); dn=os.path.dirname(n)
        if base=='.wh..wh..opq':
            for k in [k for k in fs if k.startswith(dn+'/')]: del fs[k]
            continue
        if base.startswith('.wh.'):
            tgt=(dn+'/' if dn else '')+base[4:]
            for k in [k for k in fs if k==tgt or k.startswith(tgt+'/')]: del fs[k]
            continue
        if ti.isfile(): fs[n]=t.extractfile(ti).read()
        elif ti.islnk(): fs[n]=('LINK',ti.linkname.rstrip('/'))
        elif ti.issym(): fs[n]=('SYM',ti.linkname)
        elif ti.isdir(): fs[n]=None
def res(p,d=0):
    v=fs.get(p)
    if isinstance(v,tuple): return res(v[1],d+1) if v[0]=='LINK' else v
    return v
print('FINAL')
for k,v in sorted(fs.items()):
    if v is not None: print(k, res(k))
