import sys
from androguard.core.dex import DEX
d=DEX(open(sys.argv[1],'rb').read())
for c in d.get_classes():
    n=c.get_name()
    if n.startswith(('Landroid','Ljava','Lkotlin')): continue
    print(n, len(c.get_methods()))
