import struct,sys,pickle
blob=open(sys.argv[1],'rb').read()
p=int.from_bytes(blob[8:24],'little'); order=struct.unpack_from('<Q',blob,24)[0]
n0,n1,s0,s1=struct.unpack_from('<IIII',blob,32)
i0,i1=blob[48],blob[49]
sl=struct.unpack_from('<I',blob,80)[0]
ts=84+sl
M32=0xffffffff
def build(off,n,seed,init):
    M=[[int(r==c) for c in range(8)] for r in range(8)]
    h=(seed^0xa5d931c7)&M32; d=init&0xff
    for i in range(n):
        e=blob[off+19*i:off+19*i+19]
        K=(19*i+0x9e3779b9)&M32
        eax=(29*d+17*i)&M32
        dec=bytearray(19)
        for j in range(19):
            top=h>>24
            h=(h+K+j)&M32
            x=(e[j]^eax^top)&0xff
            eax=(eax+7)&M32
            dec[j]=x
            h=(h+x)&M32
            h^=(h<<13)&M32; h^=h>>17; h^=(h<<5)&M32
        t=i>>12
        op=(dec[0]^((7*d)&M32)^((11*t)&M32))&7
        A=(dec[1]+d)&M32; B=(dec[2]+2*d)&M32
        c=int.from_bytes(dec[3:19],'little')
        if op==0:
            a,b=A&7,B&7
            M[a]=[(M[a][k]+c*M[b][k])%p for k in range(8)]
        elif op==1:
            a=A&7; M[a]=[c*x%p for x in M[a]]
        elif op==2:
            a,b=A&7,B&7; M[a],M[b]=M[b],M[a]
        d=((dec[3]&3)+t+A+1)&7
    return M
A=build(ts,n0,s0,i0); B=build(ts+19*n0,n1,s1,i1)
pickle.dump((p,order,A,B),open(sys.argv[2],'wb'))
print(p,order,s0,s1,i0,i1)
print(A[0][:2],B[0][:2])
