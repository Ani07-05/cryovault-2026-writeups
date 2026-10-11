import json,os,sys,time,random
import numpy as np
from neve_bench import Link
from emfit import fbrun,em,gradepost,GP
URL='wss://isfcrpesu-neve.chals.io/'
HD=np.array([0,.08,.173,.258,.356,.509,.715,0.99])
class Run:
    def __init__(s,logpath,session=None):
        s.logpath=logpath; s.syms=[]; s.bits=[]; s.rows=[]   # rows[i] = row used for step i
        s.l=Link(URL,session=session) if session else Link(URL)
        s.cap=None; s.confirmed={}
        if session is None:
            r=s.l.open(); s.bit0=r['bit']; s.budget=r['budget']
            s.log({'kind':'open','session':s.l.session,'r':r})
        else:
            s.reload()
    def log(s,o):
        with open(s.logpath,'a') as fh: fh.write(json.dumps(o)+'\n')
    def reload(s):
        s.bit0=0
        for line in open(s.logpath):
            o=json.loads(line)
            if o['kind']=='open': s.bit0=o['r']['bit']
            elif o['kind']=='sound': s.syms+=o['syms']; s.bits+=o['bits']; s.rows+=[o['row']]*len(o['syms'])
            elif o['kind']=='confirm': s.confirmed[o['row']]=o['grades']
            elif o['kind']=='cap': s.cap=o['cap']
        h=s.l.hello(); s.budget=h['budget']
        assert h['t']==len(s.syms),(h['t'],len(s.syms))
    def send(s,row,syms):
        r=s.l.sound(row,syms)
        if not r.get('ok'): raise Exception(r)
        bits=[int(c) for c in r['bits']]
        s.syms+=syms; s.bits+=bits; s.rows+=[row]*len(syms); s.budget=r['budget']
        s.log({'kind':'sound','row':row,'syms':syms,'bits':bits})
    def arrays(s):
        b=np.array(s.bits,int); prevb=np.concatenate([[s.bit0],b[:-1]])
        f=(b!=prevb).astype(int)
        D=np.cumsum(2*b-1)
        z=np.zeros(len(b),int); z[1:]=(2*b[:-1]-1)*D[:-1]
        z=np.clip(z,0,7)
        return np.array(s.syms,int),f,z
    def seg(s,row):
        idx=[i for i,r in enumerate(s.rows) if r==row]
        start,end=idx[0],idx[-1]+1
        S,F,Z=s.arrays()
        lo=max(0,start-12)
        t0=(start-lo)+8 if start>0 else 12
        return S[lo:end],F[lo:end],Z[lo:end],t0
    def fit(s,row,cap,iters=25):
        S,F,Z,t0=s.seg(row)
        return em(S,F,Z,cap,H=HD,iters=iters,t0=t0)
    def select_cap(s,row,caps=range(3,10)):
        res={}
        for c in caps:
            ll,C,n1,n0=s.fit(row,c,iters=15); res[c]=ll
        best=max(res,key=res.get)
        return best,res
    def rand_batch(s,row,n=4096):
        s.send(row,[random.randrange(16) for _ in range(n)])
