from dissect.extfs import ExtFS
import sys
fs=ExtFS(open(sys.argv[1] if len(sys.argv)>1 else 'vol.img','rb'))
def walk(n,p,d=0):
    for name,c in n.listdir().items():
        if name in('.','..'):continue
        isd=c.filetype==16384
        print(' '*d+name, c.inum, 'dir' if isd else c.size)
        if isd and name!='lost+found':walk(c,p+'/'+name,d+2)
        elif c.size<400:
            try:print(' '*d+'   >',c.open().read()[:300])
            except Exception as e:print('   err',e)
walk(fs.get('/'),'')
