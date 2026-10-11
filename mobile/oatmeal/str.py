import re,sys
for f in sys.argv[1:]:
    b=open(f,'rb').read()
    print("==",f,b[:8])
    for m in re.finditer(rb'[\x20-\x7e]{4,}',b): print(m.group().decode())
