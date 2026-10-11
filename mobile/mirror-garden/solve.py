import sys,re
from z3 import *
lines=[l.rstrip('\n') for l in open(sys.argv[1])]
start=lines.index('M verify')+1
inp=[BitVec('b%d'%i,8) for i in range(16)]
R={}
def val(r): return R[r]
cons=[]
M=(1<<64)-1
for l in lines[start:]:
    if l.startswith(('fill-array-data','new-array','return')): break
    parts=l.split(' ',1); op=parts[0]; args=[a.strip() for a in parts[1].split(',')] if len(parts)>1 else []
    if op in('move-object/from16','if-eqz','if-eq','goto/16','array-length','if-nez','goto') : continue
    def lit(s): return int(s)
    if op.startswith('const'):
        R[args[0]]=BitVecVal(int(args[1])&M,64)
    elif op=='aget-byte':
        # index register holds constant
        idx=simplify(R[args[2]]).as_long()
        R[args[0]]=SignExt(56,inp[idx])
    elif op=='int-to-long':
        R[args[0]]=R[args[1]]  # already sign-extended 64
    elif op.startswith('move-wide'):
        R[args[0]]=R[args[1]]
    elif op=='cmp-long':
        cons.append((R[args[1]],R[args[2]]))
    else:
        m=re.match(r'(and|or|xor|add|sub|mul|shl|ushr)-long(/2addr)?$',op)
        assert m,op
        if m.group(2): a,b=args[0],args[1]; dst=args[0]
        else: dst,a,b=args
        x,y=R[a],R[b]
        f=m.group(1)
        R[dst]={'and':lambda:x&y,'or':lambda:x|y,'xor':lambda:x^y,'add':lambda:x+y,'sub':lambda:x-y,'mul':lambda:x*y,'shl':lambda:x<<(y&63),'ushr':lambda:LShR(x,y&63)}[f]()
print(len(cons),'constraints')
s=Solver()
for a,b in cons: s.add(a==b)
print(s.check())
if s.check()==sat:
    m=s.model(); bs=bytes(m.eval(b,model_completion=True).as_long() for b in inp)
    print(bs, bs.hex())
    # uniqueness
    s.add(Or([b!=m.eval(b,model_completion=True) for b in inp])); print('other',s.check())
