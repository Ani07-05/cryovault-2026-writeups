import pickle
from sympy import ZZ
from sympy.polys.galoistools import gf_factor
exec(open('/mnt/c/Users/Aniruddh/Downloads/cryovaultpes/scripts/an.py').read().split('for name,M')[0])
cp=charpoly(A)
lc,fs=gf_factor(cp,p,ZZ)
f=[f for f,m in fs if len(f)==3][0]; a,b=f[1],f[2]
print('quad',a,b)
def matvec(M,v): return [sum(M[i][k]*v[k] for k in range(n))%p for i in range(n)]
def polyA(M,coef): # f(M) = M^2 + a M + b I
    M2=mm(M,M); return [[(M2[i][j]+a*M[i][j]+(b if i==j else 0))%p for j in range(n)] for i in range(n)]
F=polyA(A,f)
def nullspace(M):
    rows=[r[:] for r in M]; piv=[]; r=0
    for c in range(n):
        pr=next((i for i in range(r,n) if rows[i][c]),None)
        if pr is None: continue
        rows[r],rows[pr]=rows[pr],rows[r]
        inv=pow(rows[r][c],-1,p); rows[r]=[x*inv%p for x in rows[r]]
        for i in range(n):
            if i!=r and rows[i][c]:
                m=rows[i][c]; rows[i]=[(x-m*y)%p for x,y in zip(rows[i],rows[r])]
        piv.append(c); r+=1
    free=[c for c in range(n) if c not in piv]; basis=[]
    for fc in free:
        v=[0]*n; v[fc]=1
        for i,pc in enumerate(piv): v[pc]=(-rows[i][fc])%p
        basis.append(v)
    return basis
ns=nullspace(F); print('nullity',len(ns))
v=ns[0]; Av=matvec(A,v); Bv=matvec(B,v)
# solve Bv = x v + y Av
# pick two coordinates with nonzero det
for i in range(n):
    for j in range(i+1,n):
        det=(v[i]*Av[j]-v[j]*Av[i])%p
        if det: break
    if det: break
di=pow(det,-1,p)
x=(Bv[i]*Av[j]-Bv[j]*Av[i])*di%p
y=(v[i]*Bv[j]-v[j]*Bv[i])*di%p
assert all((x*v[t]+y*Av[t]-Bv[t])%p==0 for t in range(n))
print('xy',x,y)
open('/mnt/c/Users/Aniruddh/Downloads/cryovaultpes/work/params.txt','w').write(f"{p}\n{a}\n{b}\n{x}\n{y}\n{o}\n")
