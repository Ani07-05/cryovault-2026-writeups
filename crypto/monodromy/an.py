import pickle
from sympy import Poly, GF, symbols, factorint
from sympy.polys.galoistools import gf_factor, gf_from_int_poly
p,o,A,B=pickle.load(open('/mnt/c/Users/Aniruddh/Downloads/cryovaultpes/work/AB.pkl','rb'))
n=8
def mm(X,Y): return [[sum(X[i][k]*Y[k][j] for k in range(n))%p for j in range(n)] for i in range(n)]
def charpoly(M):
    # Faddeev-LeVerrier
    I=[[int(i==j) for j in range(n)] for i in range(n)]
    c=[1]; Mk=[[0]*n for _ in range(n)]
    for k in range(1,n+1):
        Mk=mm(M,[[Mk[i][j]+c[-1]*I[i][j] for j in range(n)] for i in range(n)]) if k>1 else M
        tr=sum(Mk[i][i] for i in range(n))%p
        c.append((-tr*pow(k,-1,p))%p)
    return c  # x^n + c1 x^{n-1}+...
for name,M in (('A',A),('B',B)):
    cp=charpoly(M); print(name,'charpoly',cp)
    lc,fs=gf_factor(cp,p,__import__('sympy').ZZ)
    print(' factors degs',[(len(f)-1,m) for f,m in fs])
print(factorint(o), factorint(p-1), factorint(p+1))
