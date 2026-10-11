import struct, sys
from unicorn import *
from unicorn.arm64_const import *

SO = '../apk/lib/arm64-v8a/libbulb.so'
data = open(SO, 'rb').read()
BASE = 0x10000000
STACK = 0x20000000
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(BASE, 0x10000)
# map LOAD segments
for off, va, fs, ms in [(0, 0, 0x2120, 0x2120), (0x2120, 0x3120, 0x2510, 0x2510), (0x4630, 0x6630, 0x4e0, 0x4e0)]:
    mu.mem_write(BASE + va, data[off:off + fs])
# relocations: RELATIVE
import subprocess, re
rel = subprocess.run(['readelf', '-rW', SO], capture_output=True, text=True).stdout
for l in rel.splitlines():
    p = l.split()
    if len(p) >= 3 and p[2] == 'R_AARCH64_RELATIVE':
        off = int(p[0], 16); add = int(p[3], 16)
        mu.mem_write(BASE + off, struct.pack('<Q', BASE + add))
# PLT: find JUMP_SLOT entries
STUB = BASE + 0xe000
mu.mem_write(STUB, b'\xc0\x03\x5f\xd6' * 64)  # ret
hooks = {}
for l in rel.splitlines():
    p = l.split()
    if len(p) >= 5 and p[2] == 'R_AARCH64_JUMP_SLOT':
        off = int(p[0], 16); name = p[4].split('@')[0]
        a = STUB + 4 * len(hooks)
        hooks[a] = name
        mu.mem_write(BASE + off, struct.pack('<Q', a))

def hook(uc, addr, size, ud):
    n = hooks.get(addr)
    if n == 'memcpy':
        d = uc.reg_read(UC_ARM64_REG_X0); s = uc.reg_read(UC_ARM64_REG_X1); c = uc.reg_read(UC_ARM64_REG_X2)
        uc.mem_write(d, bytes(uc.mem_read(s, c)))
    elif n == 'memset':
        d = uc.reg_read(UC_ARM64_REG_X0); v = uc.reg_read(UC_ARM64_REG_X1) & 0xff; c = uc.reg_read(UC_ARM64_REG_X2)
        uc.mem_write(d, bytes([v]) * c)

mu.hook_add(UC_HOOK_CODE, hook, begin=STUB, end=STUB + 0x400)
# enable FP/SIMD
mu.reg_write(UC_ARM64_REG_CPACR_EL1, 0x300000)
mu.mem_map(STACK, 0x100000)

def call(fn, args=(), stop=BASE + 0xf000):
    mu.mem_write(stop, b'\xc0\x03\x5f\xd6')
    for i, a in enumerate(args):
        mu.reg_write(UC_ARM64_REG_X0 + i, a)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0xf0000)
    mu.reg_write(UC_ARM64_REG_X30, stop)
    mu.emu_start(BASE + fn, stop, count=50000000)
    return mu.reg_read(UC_ARM64_REG_X0)
