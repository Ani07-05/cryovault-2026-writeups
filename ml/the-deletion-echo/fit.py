import json,numpy as np,pickle
d=json.load(open('C:/Users/Aniruddh/Downloads/cryovaultpes/h5/data.json'))
c=d['contract'];P=c['permutation'];C=np.array(c['center'],float);S=np.array(c['scale'],float)
def feat(raw): r=np.array(raw,float);return (r[P]-C)/S
iu=np.triu_indices(12)
out={}
for s in d['snapshots']:
    sid=s['id'];Q=[q for q in d['queries'] if q['snapshot_id']==sid]
    X=np.array([feat(q['raw']) for q in Q]);m=np.array([float(q['mean']) for q in Q]);v=np.array([float(q['predictive_variance']) for q in Q])
    th,res,_,_=np.linalg.lstsq(X,m,rcond=None)
    # variance: sigma2 + q^T M q
    F=np.array([np.r_[1,[(x[i]*x[j])*(1 if i==j else 2) for i,j in zip(*iu)]] for x in X])
    w=1/v  # relative noise
    sol=np.linalg.lstsq(F*w[:,None],v*w,rcond=None)[0]
    M=np.zeros((12,12));M[iu]=sol[1:];M=M+M.T-np.diag(np.diag(M))
    print(sid,'mean resid std',np.std(m-X@th),'sigma2',sol[0],'var relres',np.std((F@sol-v)/v))
    out[sid]=(th,sol[0],M,X)
pickle.dump(out,open('fit.pkl','wb'))
