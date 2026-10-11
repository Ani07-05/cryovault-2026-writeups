import pickle, numpy as np, math
L=np.array(pickle.load(open('lat.pkl','rb')),dtype=float)
n=14
# Gram-Schmidt
Bs=np.zeros_like(L); mu=np.zeros((n,n))
for i in range(n):
    Bs[i]=L[i]
    for j in range(i):
        mu[i,j]=L[i]@Bs[j]/(Bs[j]@Bs[j]); Bs[i]-=mu[i,j]*Bs[j]
nb=[Bs[i]@Bs[i] for i in range(n)]
R2=25.0+1e-6
found=[]
def rec(k,c,partial_center_sum):
    pass
sol=[]
c=[0]*n
def enum(k, rem):
    # choose c[k], given c[k+1..]
    ctr=-sum(c[j]*mu[j,k] for j in range(k+1,n))
    r=math.sqrt(max(rem,0)/nb[k])
    lo=math.ceil(ctr-r); hi=math.floor(ctr+r)
    for x in range(lo,hi+1):
        c[k]=x
        nr=rem-(x-ctr)**2*nb[k]
        if nr<-1e-9: continue
        if k==0:
            v=np.rint(sum(c[i]*L[i] for i in range(n))).astype(int)
            if set(v.tolist())<= {0,1} and v.sum()>0: sol.append(v)
        else: enum(k-1,nr)
    c[k]=0
enum(n-1,R2)
print(len(sol))
sol.sort(key=lambda v:v.sum())
print([int(v.sum()) for v in sol])
pickle.dump([v.tolist() for v in sol],open('cols.pkl','wb'))
