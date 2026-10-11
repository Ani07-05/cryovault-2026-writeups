import sys
b=open(r"C:\Users\Aniruddh\Downloads\base.odex",'rb').read()
off=2192
chunk=b[off:off+112]
for i in range(0,len(chunk),16):
    row=chunk[i:i+16]
    hexs=" ".join(f"{x:02x}" for x in row)
    asc="".join(chr(x) if 32<=x<127 else "." for x in row)
    print(f"{off+i:06x}  {hexs:<48}  {asc}")
