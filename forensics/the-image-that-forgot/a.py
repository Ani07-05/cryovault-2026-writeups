import json,sys,os,datetime
B=sys.argv[1]
def blob(d): return open(os.path.join(B,'blobs','sha256',d.split(':')[1]),'rb').read()
idx=json.load(open(B+'/index.json'))
for m in idx['manifests']:
    d=m['digest']; i=json.loads(blob(d))
    print(d[:19], [ (x['platform']['architecture'],x['platform'].get('variant'),x['digest'][7:19],x.get('annotations')) for x in i['manifests']], i.get('annotations'))
    for x in i['manifests']:
        mf=json.loads(blob(x['digest']))
        print('   ',x['digest'][7:19], mf['config']['digest'][7:19], [l['digest'][7:19] for l in mf['layers']])
        c=json.loads(blob(mf['config']['digest'])); print('      cfg',json.dumps(c)[:400])
