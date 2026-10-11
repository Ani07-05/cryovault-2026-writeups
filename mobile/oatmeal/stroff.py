import re
b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
for m in re.finditer(rb'[\x20-\x7e]{4,}',b):
    print(hex(m.start()), len(m.group()), m.group())
