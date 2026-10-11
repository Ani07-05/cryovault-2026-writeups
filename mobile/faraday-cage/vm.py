from emu import *

call(0x5058)  # run libbulb.so's init routine, which shuffles the opcode table

# recover the real opcode -> handler permutation by diffing the shuffled
# table (0x7e78) against the original, unshuffled table (0x67b8)
tab = struct.unpack('<48Q', bytes(mu.mem_read(BASE + 0x7e78, 48 * 8)))
orig = struct.unpack('<48Q', bytes(mu.mem_read(BASE + 0x67b8, 48 * 8)))
PERM = [orig.index(t) for t in tab]

CODE = bytes(mu.mem_read(BASE + 0x138a, 0xf0))        # 60-instruction VM program (4 bytes/instr)
INIT = bytes(mu.mem_read(BASE + 0x132a, 0x60))         # target block, round keys, permutation table
SBOX_INV = bytes(mu.mem_read(BASE + 0x147a, 256))
SBOX = bytes(mu.mem_read(BASE + 0x7ff8, 256))

def gfmul(a, b):
    return call(0x51b8, (a & 0xffffffff, b & 0xffffffff)) & 0xffffffff

def f52c0(x):
    """The VM's custom MixColumns step: a GF(2^8)-ish linear map over a
    32-bit word, implemented natively at 0x52c0. Treated as a black-box
    linear function and inverted via its 32x32 GF(2) matrix in solve.py."""
    return call(0x52c0, (x & 0xffffffff,)) & 0xffffffff

NAMES = ['add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'shr', 'rol', 'ror', 'addi', 'xori', 'andi', 'ori',
         'movi', 'movhi', 'ldb', 'ldw', 'stb', 'stw', 'ldbx', 'isbox', 'sbox', 'gfmul', 'f52c0', 'jmp', 'beq',
         'bne', 'blt', 'bge', 'jz', 'jnz', 'push', 'pop', 'call', 'ret', 'nop', 'nop', 'mov', 'neg', 'not',
         'clz', 'rbit', 'rev16', 'inb', 'outb', 'halt', 'haltc']

def sx(v):
    return v - 256 if v >= 128 else v

def dis():
    for pc in range(len(CODE) // 4):
        op, a, b, c = CODE[pc * 4:pc * 4 + 4]
        print("%02x: %-6s r%d r%d r%d   (%02x %02x %02x %02x) h=%d" % (pc, NAMES[PERM[op]], a, b, c, op, a, b, c, PERM[op]))

if __name__ == '__main__':
    print(PERM)
    dis()
