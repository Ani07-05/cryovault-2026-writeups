import pickle, flint
K=pickle.load(open('ker.pkl','rb'))[:26]
n=40; W=2**30
rows=[[1 if i==j else 0 for j in range(n)]+[W*K[r][i] for r in range(26)] for i in range(n)]
B=flint.fmpz_mat(rows).lll()
R=[[int(B[i,j]) for j in range(n+26)] for i in range(n)]
L=[r[:n] for r in R if all(x==0 for x in r[n:])]
print(len(L))
for r in L: print(r, sum(x*x for x in r))
pickle.dump(L,open('lat.pkl','wb'))
