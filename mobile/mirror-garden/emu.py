from unicorn import *
from unicorn.arm64_const import *
from elftools.elf.elffile import ELFFile
p=r'C:/Users/Aniruddh/Downloads/mg_extract/lib/arm64-v8a/libgarden.so'
raw=open(p,'rb').read(); e=ELFFile(open(p,'rb'))
mu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
mu.mem_map(0,0x10000)
for s in e.iter_segments():
    if s['p_type']=='PT_LOAD':
        mu.mem_write(s['p_vaddr'], raw[s['p_offset']:s['p_offset']+s['p_filesz']])
# enable fp/simd
mu.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
mu.mem_map(0x100000,0x10000)
sp=0x108000; out=0x101000
mu.reg_write(UC_ARM64_REG_SP,sp); mu.reg_write(UC_ARM64_REG_X0,out)
mu.reg_write(UC_ARM64_REG_X30,0x9000)
mu.emu_start(0x2374,0x9000)
b=bytes(mu.mem_read(out,0x40))
print(b.hex()); import struct
w=struct.unpack('<16I',b); print([hex(x) for x in w]); print('leaf',w[0]&0x3ff)
open('state.bin','wb').write(b)
