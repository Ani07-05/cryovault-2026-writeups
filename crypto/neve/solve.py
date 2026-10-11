import sys
from solver2 import *
def solve_row(run,row,tol=2e-5,dev=0.3,maxsyms=90000,first=20480,step=4096,verbose=True):
    n=0
    k=first
    while True:
        while k>0:
            m=min(4096,k); run.rand_batch(row,m); k-=m; n+=m
        cap,res=run.select_cap(row)
        ll,C,n1,n0=run.fit(row,cap)
        P=gradepost(n1,n0); g=P.argmax(1); mx=P.max(1)
        gh=(C-.18)/(.64/7); dv=np.abs(gh-np.round(gh))
        bad=[i for i in range(16) if mx[i]<1-tol or dv[i]>dev]
        if verbose: print(f'row {row} n={n} cap={cap} undecided={len(bad)} minpost={mx.min():.5f} maxdev={dv.max():.2f} budget={run.budget}',flush=True)
        if not bad: return g,cap,n
        if n>=maxsyms: return None,cap,n
        k=step
def do_rows(run,rows):
    for row in rows:
        g,cap,n=solve_row(run,row)
        if g is None: print('row',row,'unresolved'); return
        r=run.l.checkpoint(row,g.tolist())
        print('checkpoint',row,g.tolist(),r,flush=True)
        run.log({'kind':'checkpoint','row':row,'grades':g.tolist(),'resp':r})
        if not r.get('ok'): return
        run.log({'kind':'confirm','row':row,'grades':g.tolist()})
if __name__=='__main__':
    run=Run(sys.argv[1],session=sys.argv[2] if len(sys.argv)>2 and sys.argv[2]!='-' else None)
    rows=list(range(int(sys.argv[3]),int(sys.argv[4])+1))
    do_rows(run,rows)
