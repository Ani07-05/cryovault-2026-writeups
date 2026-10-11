import json, flint
d=json.load(open(r'C:\Users\Aniruddh\Downloads\observations.json'))
p=int(d['prime']); s=[int(x) for x in d['samples']]
n=40; W=2**60
rows=[[1 if i==j else 0 for j in range(n)]+[W*s[i]] for i in range(n)]
rows.append([0]*n+[W*p])
B=flint.fmpz_mat(rows).lll()
R=[[int(B[i,j]) for j in range(n+1)] for i in range(n+1)]
ker=[r[:n] for r in R if r[n]==0]
print(len(ker), max(max(abs(x) for x in r) for r in ker))
import pickle; pickle.dump(ker,open('ker.pkl','wb'))
