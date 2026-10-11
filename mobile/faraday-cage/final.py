from emu import *

# sol.txt (written by solve.py) holds the recovered 16-byte unlock input,
# hex-encoded -> ASCII "LumosFaradCage01". Run the real native submit()
# routine on it: on success it SHA-256-hashes the input to derive a key
# and decrypts the embedded 53-byte flag blob.
inp = bytes.fromhex(open('sol.txt').read())
IN = STACK + 0x1000
OUT = STACK + 0x2000
LEN = STACK + 0x3000
mu.mem_write(IN, inp)
r = call(0x43dc, (IN, len(inp), OUT, 0x80, LEN))
n = struct.unpack('<I', bytes(mu.mem_read(LEN, 4)))[0]
print(r, n, bytes(mu.mem_read(OUT, n)))
# -> 1 53 b'isfcr{p3rmut3d_h4ndl3rs_v5_cust0m_ch4ch4_1n_th3_c4g3}'
