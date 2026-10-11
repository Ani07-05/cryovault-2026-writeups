from capstone import *
from elftools.elf.elffile import ELFFile
p=r'C:/Users/Aniruddh/Downloads/mg_extract/lib/arm64-v8a/libgarden.so'
e=ELFFile(open(p,'rb')); d=open(p,'rb').read()
t=e.get_section_by_name('.text'); print(hex(t['sh_offset']),hex(t['sh_addr']))
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
off=t['sh_offset']; 
for i in md.disasm(d[off:off+t['sh_size']],t['sh_addr']): print(hex(i.address),i.mnemonic,i.op_str)
