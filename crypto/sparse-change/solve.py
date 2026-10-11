import json
from hashlib import sha256
from sympy import Poly, symbols, GF
from sympy.ntheory import discrete_log
from Crypto.Cipher import AES
d=json.load(open(r"C:\Users\Aniruddh\Downloads\output.json"))
p,g,T,s=d["p"],d["g"],d["t"],d["log"]
# Berlekamp-Massey
def bm(s,p):
    C=[1];B=[1];L=0;m=1;b=1
    for n in range(len(s)):
        dd=s[n]
        for i in range(1,L+1): dd=(dd+C[i]*s[n-i])%p
        if dd==0: m+=1; continue
        Tt=C[:]
        coef=dd*pow(b,-1,p)%p
        C=C+[0]*(len(B)+m-len(C))
        for i,v in enumerate(B): C[i+m]=(C[i+m]-coef*v)%p
        if 2*L<=n: L=n+1-L;B=Tt;b=dd;m=1
        else: m+=1
    return C[:L+1],L
C,L=bm(s,p);print("L",L)
x=symbols('x')
# roots r satisfy r^L + C1 r^(L-1)+...+CL=0
poly=Poly(list(C),x,modulus=p)
fl=poly.factor_list()[1]
roots=[]
for f,_ in fl:
    assert f.degree()==1, f.degree()
    a,b=f.all_coeffs(); roots.append((-b*pow(a,-1,p))%p)
print(len(roots))
es=[discrete_log(p,r,g) for r in roots]
assert all(pow(g,e,p)==r for e,r in zip(es,roots))
# solve coefficients: s[j]=sum c_i r_i^j  (Gaussian elim mod p)
n=len(roots)
M=[[pow(r,j,p) for r in roots]+[s[j]] for j in range(n)]
for i in range(n):
    pv=next(k for k in range(i,n) if M[k][i]); M[i],M[pv]=M[pv],M[i]
    iv=pow(M[i][i],-1,p); M[i]=[v*iv%p for v in M[i]]
    for k in range(n):
        if k!=i and M[k][i]:
            f=M[k][i]; M[k]=[(a-f*b)%p for a,b in zip(M[k],M[i])]
cs=[M[i][n] for i in range(n)]
terms=sorted(zip(es,cs))
key=sha256(";".join(f"{e}:{c}" for e,c in terms).encode()).digest()
c=AES.new(key,AES.MODE_GCM,nonce=bytes.fromhex(d["flag_nonce"]))
print(c.decrypt_and_verify(bytes.fromhex(d["flag_ct"]),bytes.fromhex(d["flag_tag"])))
