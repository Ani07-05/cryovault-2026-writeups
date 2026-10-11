import ctypes,json,numpy as np,os
lib=ctypes.CDLL(os.path.abspath('fb.dll'))
lib.fb.restype=ctypes.c_double
P=ctypes.POINTER
dp=P(ctypes.c_double);ip=P(ctypes.c_int)
lib.fb.argtypes=[ctypes.c_int,ctypes.c_int,ip,ip,ip,dp,dp,ctypes.c_int,dp,dp]
GP=np.array([0.18+i*0.64/7 for i in range(8)])
Hd=np.array([0,.08,.173,.258,.356,.509,.715,1.0])
def fbrun(s,f,z,C,H,cap,t0=10):
    n=len(s);n1=np.zeros(16);n0=np.zeros(16)
    s=np.ascontiguousarray(s,dtype=np.int32);f=np.ascontiguousarray(f,dtype=np.int32);z=np.ascontiguousarray(z,dtype=np.int32)
    C=np.ascontiguousarray(C,dtype=np.float64);H=np.ascontiguousarray(H,dtype=np.float64)
    ll=lib.fb(n,cap-1,s.ctypes.data_as(ip),f.ctypes.data_as(ip),z.ctypes.data_as(ip),C.ctypes.data_as(dp),H.ctypes.data_as(dp),t0,n1.ctypes.data_as(dp),n0.ctypes.data_as(dp))
    return ll,n1,n0
def em(s,f,z,cap,H=Hd,iters=30,C0=None,t0=10,verbose=False):
    C=np.full(16,.5) if C0 is None else C0.copy()
    for it in range(iters):
        ll,n1,n0=fbrun(s,f,z,C,H,cap,t0)
        C=np.clip(n1/np.maximum(n1+n0,1e-9),0.02,0.98)
        if verbose: print(it,ll)
    ll,n1,n0=fbrun(s,f,z,C,H,cap,t0)
    return ll,C,n1,n0
def gradepost(n1,n0):
    LL=n1[:,None]*np.log(GP)[None]+n0[:,None]*np.log(1-GP)[None]
    P=np.exp(LL-LL.max(1,keepdims=True));return P/P.sum(1,keepdims=True)
if __name__=='__main__':
    import sys
    from model import hist,zprime
    d=json.load(open(sys.argv[1]));n=int(sys.argv[2])
    s=np.array(d['syms'][:n]);f,b,D=hist(d['syms'][:n],d['fl'][:n]);z=np.clip(zprime(f,b,D),0,7)
    for cap in range(3,9):
        ll,C,n1,n0=em(s,f,z,cap,iters=25)
        g=(C-.18)/(.64/7)
        print(cap,round(ll,1),np.round(g,2).tolist())
