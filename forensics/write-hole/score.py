import struct,itertools,sys
import raid
raid.LEN=16<<20
def inode(v,tab,n,isz):
    o=tab*4096+(n-1)*isz
    return v[o:o+isz]
def firstblock(ino):
    flags=struct.unpack_from('<I',ino,32)[0]
    if flags&0x80000:
        # extent: header at 40, entry at 52
        if struct.unpack_from('<H',ino,40)[0]!=0xF30A:return None
        depth=struct.unpack_from('<H',ino,46)[0]
        if depth:return None
        lo=struct.unpack_from('<I',ino,40+12+8)[0];hi=struct.unpack_from('<H',ino,40+12+6)[0]
        return (hi<<32)|lo
    return struct.unpack_from('<I',ino,40)[0]
def test(v):
    sb=v[1024:2048]
    if struct.unpack_from('<H',sb,56)[0]!=0xEF53:return 0,'nosb'
    isz=struct.unpack_from('<H',sb,88)[0] or 128
    gd=v[4096:4096+64]
    bb,ib,it=struct.unpack_from('<III',gd,0)
    if it*4096+isz*512>len(v) or it==0:return 0,'baditab'
    root=inode(v,it,2,isz)
    mode=struct.unpack_from('<H',root,0)[0]
    if mode&0xF000!=0x4000:return 1,'rootnotdir %x it=%d'%(mode,it)
    fb=firstblock(root)
    if fb is None or fb*4096+12>len(v):return 2,'badextent'
    blk=v[fb*4096:fb*4096+24]
    ino1,rl,nl,ty=struct.unpack_from('<IHBB',blk,0)
    if ino1==2 and nl==1 and blk[8]==0x2e:return 10,'ROOT OK'
    return 3,'rootdirblock bad'
if __name__=='__main__':
    best=[]
    for chunk in [4096<<i for i in range(0,8)]:
        for layout in('ls','la','rs','ra'):
            for perm in itertools.permutations(range(3)):
                v=raid.build(chunk,layout,perm)
                sc,msg=test(v)
                best.append((sc,chunk,layout,perm,msg))
    best.sort(reverse=True)
    for b in best[:25]:print(b)
