import sys
from androguard.core.dex import DEX
d=DEX(open(sys.argv[1],'rb').read())
for c in d.get_classes():
    if 'R$' in c.get_name(): continue
    print("###",c.get_name())
    for m in c.get_methods():
        print("--",m.get_name(),m.get_descriptor())
        co=m.get_code()
        if co:
            for i in co.get_bc().get_instructions(): print("  ",i.get_name(),i.get_output())
