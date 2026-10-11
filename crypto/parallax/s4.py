import pickle, json, sympy
d=json.load(open(r'C:\Users\Aniruddh\Downloads\observations.json'))
p=int(d['prime']); s=[int(x) for x in d['samples']]
cols=pickle.load(open('cols.pkl','rb'))
M=[[cols[j][i] for j in range(14)] for i in range(40)]
# gaussian elimination mod p on augmented 40x15
A=[M[i][:]+[s[i]] for i in range(40)]
r=0; piv=[]
for c in range(14):
    pr=next(i for i in range(r,40) if A[i][c]%p)
    A[r],A[pr]=A[pr],A[r]
    inv=pow(A[r][c],-1,p); A[r]=[x*inv%p for x in A[r]]
    for i in range(40):
        if i!=r and A[i][c]%p:
            f=A[i][c]; A[i]=[(x-f*y)%p for x,y in zip(A[i],A[r])]
    r+=1
a=[A[i][14] for i in range(14)]
print([A[i][14] for i in range(14,40)][:3])  # should be 0 (consistent)
print(all(A[i][14]==0 for i in range(14,40)))
pickle.dump(a,open('atoms.pkl','wb'))
print([x.bit_length() for x in a])
