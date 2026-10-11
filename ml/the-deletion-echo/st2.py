import pickle,json,numpy as np
from scipy.optimize import nnls
H,B=pickle.load(open('HB.pkl','rb'))
d=json.load(open('C:/Users/Aniruddh/Downloads/cryovaultpes/h5/data.json'))
c=d['contract'];P=c['permutation'];C=np.array(c['center'],float);S=np.array(c['scale'],float)
feat=lambda r:(np.array(r,float)[P]-C)/S
N={'a':'snapshot-2ee90f53b5c2','d':'snapshot-d1f54facd170','e':'snapshot-e385b6f3720a','c':'snapshot-9ccbadef83c2'}
Bt={b['batch_id']:np.array([feat(r['raw']) for r in b['records']]) for b in d['ingest']}
cand=d['candidates'];XC=np.array([feat(r['raw']) for r in cand])
iu=np.triu_indices(12)
def labels(X,db):
    sol=np.linalg.lstsq(X.T,db,rcond=None)[0];return sol
for (u,w,bid) in((N['a'],N['d'],'ingest-5798d74d'),(N['e'],N['c'],'ingest-578b7698')):
    pass
for bid in Bt: print(bid)
ids=list(Bt)
d74=[b for b in ids if b.endswith('d74d')]; print(d74)
X9=Bt['ingest-e0449f2a']
for u,w in((N['c'],N['a']),(N['d'],N['e']),(N['a'],N['c']),(N['e'],N['d'])):
    D=-(H[w]-H[u]-X9.T@X9)   # = sum deleted xx^T if right
    A=np.array([np.outer(x,x)[iu] for x in XC]).T
    sol,rn=nnls(A,D[iu])
    nz=np.where(sol>0.05)[0]
    print(u[-4:],w[-4:],'resid',rn,'nnz',len(nz),'sum',sol[nz].round(2), 'norm D',np.linalg.norm(D[iu]))
