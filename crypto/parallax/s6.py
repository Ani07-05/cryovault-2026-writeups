import json, flint, math, pickle, sys
sys.path.insert(0,r'C:\Users\Aniruddh\Downloads')
import model
d=json.load(open(r'C:\Users\Aniruddh\Downloads\observations.json'))
p=int(d['prime']); n=14
Q=[[int(x)%p for x in r] for r in d['quad']]
Lm=[[int(x)%p for x in r] for r in d['linear']]
c=[int(x)%p for x in d['constant']]
a=pickle.load(open('atoms.pkl','rb'))
# kernel vectors
def kernel():
    cols=[[Q[i][k] for i in range(n)] for k in range(10)]
    rows=[[1 if i==j else 0 for j in range(n)]+[cols[k][i] for k in range(10)] for i in range(n)]
    for k in range(10): rows.append([0]*n+[p if kk==k else 0 for kk in range(10)])
    B=flint.fmpz_mat(rows).lll()
    R=[[int(B[i,j]) for j in range(n+10)] for i in range(B.nrows())]
    return [r[:n] for r in R if all(x==0 for x in r[n:]) and max(abs(x) for x in r[:n])<100]
W=kernel(); print(len(W))
m=len(W)
H=2**55
# eq: sum_i A[k][i]*x_i + noise_k = T[k] mod p ; x=x'+H
A=[[sum(W[k][j]*Lm[j][i] for j in range(n))%p for i in range(4)] for k in range(m)]
T=[sum(W[k][j]*(a[j]-c[j]) for j in range(n))%p for k in range(m)]
T=[(T[k]-sum(A[k][i]*H for i in range(4)))%p for k in range(m)]
S=2**132; E=2**188
rows=[]
for i in range(4):
    rows.append([S if ii==i else 0 for ii in range(4)]+[A[k][i] for k in range(m)]+[0])
for k in range(m):
    rows.append([0]*4+[p if kk==k else 0 for kk in range(m)]+[0])
rows.append([0]*4+T+[E])
B=flint.fmpz_mat(rows).lll()
for i in range(B.nrows()):
    r=[int(B[i,j]) for j in range(4+m+1)]
    if abs(r[-1])==E:
        sg=1 if r[-1]==E else -1
        # row = (x'*S, T - ..., E)?  row = target - lattice => sign
        xs=[ (-sg*r[ii])//S + H for ii in range(4)]
        for cand in (xs,[ (sg*r[ii])//S + H for ii in range(4)]):
            print(cand)
            if all(0<=v<2**56 for v in cand):
                try: print(model.open_seal(d,cand))
                except Exception as e: print('fail',type(e).__name__)
