from elftools.elf.elffile import ELFFile
from capstone import *
f=open(r'C:/Users/Aniruddh/Downloads/mg_extract/lib/arm64-v8a/libgarden.so','rb')
e=ELFFile(f)
for s in e.iter_sections(): print(s.name,hex(s['sh_addr']),hex(s['sh_size']))
sym=e.get_section_by_name('.dynsym')
for s in sym.iter_symbols(): print(s.name,hex(s['st_value']),s['st_size'])
