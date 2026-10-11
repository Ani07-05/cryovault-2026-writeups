import numpy as np, csv, sys, pickle
p=sys.argv[1]; out=sys.argv[2]
iq = np.load(p+r"\traces\iq.npz")["iq"]
print("iq shape",iq.shape,iq.dtype)
nonces=[]
with open(p+r"\traces\nonces.csv") as f:
    r=csv.reader(f); next(r)
    for row in r:
        nonces.append(bytes.fromhex(row[1]))
print(len(nonces), nonces[0].hex())
np.save(out+r"\iqabs.npy", np.abs(iq).astype(np.float32))
with open(out+r"\nonces.pkl","wb") as f: pickle.dump(nonces,f)
