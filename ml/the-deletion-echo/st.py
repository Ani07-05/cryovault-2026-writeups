import pickle,json,numpy as np,itertools
H,B=pickle.load(open('HB.pkl','rb'))
d=json.load(open('C:/Users/Aniruddh/Downloads/cryovaultpes/h5/data.json'))
c=d['contract'];P=c['permutation'];C=np.array(c['center'],float);S=np.array(c['scale'],float)
feat=lambda r:(np.array(r,float)[P]-C)/S
names=['snapshot-2ee90f53b5c2','snapshot-d1f54facd170','snapshot-e385b6f3720a','snapshot-9ccbadef83c2']
Bt={b['batch_id']:np.array([feat(r['raw']) for r in b['records']]) for b in d['ingest']}
for u in names:
  for w in names:
    if u==w:continue
    for bid,X in Bt.items():
        D=H[w]-H[u]-X.T@X
        print(u[-4:],w[-4:],bid[-4:],'fro %.1f'%np.linalg.norm(D),'trace %.0f'%np.trace(D))
