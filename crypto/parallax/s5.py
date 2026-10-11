import json, flint, math
d=json.load(open(r'C:\Users\Aniruddh\Downloads\observations.json'))
p=int(d['prime'])
Q=[[int(x)%p for x in r] for r in d['quad']]
Lm=[[int(x)%p for x in r] for r in d['linear']]
c=[int(x)%p for x in d['constant']]
print(math.log2(int(d['error_limit'])), math.log2(p))
# coefficient bit sizes
print([[int(x).bit_length() for x in r] for r in d['quad']][:3])
# lattice: w in Z^14 with w^T Q small mod p ; columns 10
n=14
def run(cols, W):
    rows=[]
    for i in range(n):
        rows.append([1 if i==j else 0 for j in range(n)]+[W*cols[k][i] for k in range(len(cols))])
    for k in range(len(cols)):
        rows.append([0]*n+[W*p if kk==k else 0 for kk in range(len(cols))])
    B=flint.fmpz_mat(rows).lll()
    return [[int(B[i,j]) for j in range(n+len(cols))] for i in range(B.nrows())]
qc=[[Q[i][k] for i in range(n)] for k in range(10)]
R=run(qc,1)
for r in R[:6]:
    print(math.log2(max(abs(x) for x in r[:n])+1), [round(math.log2(abs(x)+1)) for x in r[n:]])
print('----')
for r in R:
    print([x for x in r[:n]], [round(math.log2(abs(x)+1)) for x in r[n:n+10]])
