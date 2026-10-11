import json,numpy as np,pickle
out=pickle.load(open('fit.pkl','rb'))
H={};B={}
for k,(th,s2,M,X) in out.items():
    h=s2*np.linalg.inv(M);H[k]=h;B[k]=h@th
    print(k,'H dev from 1/16 grid',np.abs(h*16-np.round(h*16)).max(),'trace',np.trace(h),'eig min',np.linalg.eigvalsh(h)[0])
ks=list(H)
for a in ks:
    for b in ks:
        if a<b:
            D=H[a]-H[b];print(a[-4:],b[-4:],'rank-ish',np.sum(np.abs(np.linalg.eigvalsh(D))>0.05),'diag mean',np.trace(D)/12, 'fro',np.linalg.norm(D))
pickle.dump((H,B),open('HB.pkl','wb'))
