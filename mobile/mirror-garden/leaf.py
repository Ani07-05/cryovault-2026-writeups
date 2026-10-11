import sys
from loguru import logger
logger.remove()
from androguard.core.dex import DEX
d=DEX(open(r'C:/Users/Aniruddh/Downloads/mg_extract/classes.dex','rb').read())
k=int(sys.argv[1])
for c in d.get_classes():
    if c.get_name()=='Lone/sr/garden/leaf/L%04d;'%k:
        for m in c.get_methods():
            print('M',m.get_name())
            if m.get_code():
                for i in m.get_code().get_bc().get_instructions(): print(i.get_name(),i.get_output())
