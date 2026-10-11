import pickle,json,numpy as np
from scipy.optimize import nnls,milp,LinearConstraint,Bounds
exec(open('st2.py').read().split("for (u,w,bid)")[0])
X9=Bt['ingest-e0449f2a']
D=-(H[N['e']]-H[N['d']]-X9.T@X9)
A=np.array([np.outer(x,x)[iu] for x in XC]).T
sol,rn=nnls(A,D[iu]);Dl=np.where(sol>0.5)[0];print(len(Dl),rn,sol[Dl].round(3))
db=B[N['e']]-B[N['d']]
M=np.hstack([X9.T,-XC[Dl].T])
n=M.shape[1]
res=milp(c=np.zeros(n),constraints=LinearConstraint(M,db-0.03,db+0.03),integrality=np.ones(n),bounds=Bounds(0,3),options={'time_limit':300})
print(res.status,res.message)
if res.x is not None:
    y=np.round(res.x).astype(int);print('batch y',y[:10]);print('del',[(cand[i]['id'],int(y[10+k])) for k,i in enumerate(Dl)]);print(np.abs(M@y-db).max())
    pickle.dump((Dl,y),open('sol.pkl','wb'))
