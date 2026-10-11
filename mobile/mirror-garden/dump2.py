import sys
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
d=DEX(open(sys.argv[1],'rb').read())
cs=[c for c in d.get_classes() if c.get_name().startswith('Lone/sr/garden')]
print(len(cs),'classes;', sum(1 for c in cs if '/leaf/' in c.get_name()),'leaves')
for c in cs:
    n=c.get_name()
    if '/leaf/' in n and n not in ('Lone/sr/garden/leaf/L0000;','Lone/sr/garden/leaf/L0001;'): continue
    if '/R' in n: continue
    print('==',n)
    for f in c.get_fields(): print(' F',f.get_name(),f.get_descriptor(),f.get_init_value() if hasattr(f,'get_init_value') else '')
    for m in c.get_methods():
        print(' M',m.get_name(),m.get_descriptor())
        if m.get_code():
            for i in m.get_code().get_bc().get_instructions(): print('    ',i.get_name(),i.get_output())
