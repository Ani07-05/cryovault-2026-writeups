import itertools,sys
D=[open(f'/Users/anirudh/ctf/cryovault/wh/write-hole/bay{i}.img','rb').read() for i in range(3)]
OFF=1<<20; LEN=15<<20
def build(chunk,layout,perm,limit=None):
    n=3;out=bytearray()
    ns=(LEN//chunk)//(n-1)
    if limit: ns=min(ns,limit)
    for s in range(ns):
        if layout in('ls','la'): p=(n-1-s)%n
        else: p=s%n
        for k in range(n-1):
            if layout in('ls','rs'): dd=(p+1+k)%n
            else: dd=[x for x in range(n) if x!=p][k]
            disk=perm[dd]
            o=OFF+s*chunk
            out+=D[disk][o:o+chunk]
    return bytes(out)
if __name__=='__main__':
    for chunk in [4096<<i for i in range(0,8)]:
        for layout in('ls','la','rs','ra'):
            for perm in itertools.permutations(range(3)):
                v=build(chunk,layout,perm,limit=max(4,(4<<20)//chunk))
                if v[1080:1082]==b'\x53\xef':print('EXT sb',chunk,layout,perm)
