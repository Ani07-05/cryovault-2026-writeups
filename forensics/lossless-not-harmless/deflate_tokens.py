import sys

LEN_BASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEN_EXTRA = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
DIST_BASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DIST_EXTRA = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]

class BitReader:
    def __init__(self, data):
        self.data = data
        self.bytepos = 0
        self.bitpos = 0
    def bit(self):
        b = (self.data[self.bytepos] >> self.bitpos) & 1
        self.bitpos += 1
        if self.bitpos == 8:
            self.bitpos = 0
            self.bytepos += 1
        return b
    def bits(self, n):
        v = 0
        for i in range(n):
            v |= self.bit() << i
        return v
    def align(self):
        if self.bitpos != 0:
            self.bitpos = 0
            self.bytepos += 1

class Huffman:
    def __init__(self, lengths):
        self.max_len = max(lengths) if lengths else 0
        bl_count = [0]*(self.max_len+1)
        for l in lengths:
            if l>0: bl_count[l]+=1
        code = 0
        next_code=[0]*(self.max_len+2)
        for bits in range(1,self.max_len+1):
            code = (code+bl_count[bits-1])<<1
            next_code[bits]=code
        self.codes={}
        for n,l in enumerate(lengths):
            if l>0:
                self.codes[(l,next_code[l])]=n
                next_code[l]+=1
    def decode(self, br):
        code=0
        for l in range(1,self.max_len+1):
            code = (code<<1) | br.bit()
            if (l,code) in self.codes:
                return self.codes[(l,code)]
        raise ValueError('bad huffman code')

FIXED_LIT_LENGTHS = [8]*144 + [9]*112 + [7]*24 + [8]*8
FIXED_DIST_LENGTHS = [5]*30

def decode_deflate(data):
    br = BitReader(data)
    out = bytearray()
    tokens = []  # (kind, outpos, *args)
    while True:
        bfinal = br.bit()
        btype = br.bits(2)
        if btype == 0:
            br.align()
            ln = br.data[br.bytepos] | (br.data[br.bytepos+1]<<8)
            nlen = br.data[br.bytepos+2] | (br.data[br.bytepos+3]<<8)
            br.bytepos += 4
            chunk = br.data[br.bytepos:br.bytepos+ln]
            tokens.append(('stored', len(out), ln))
            out.extend(chunk)
            br.bytepos += ln
        elif btype in (1,2):
            if btype==1:
                lit_huff = Huffman(FIXED_LIT_LENGTHS)
                dist_huff = Huffman(FIXED_DIST_LENGTHS)
            else:
                hlit = br.bits(5)+257
                hdist = br.bits(5)+1
                hclen = br.bits(4)+4
                order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
                cl_lengths = [0]*19
                for i in range(hclen):
                    cl_lengths[order[i]] = br.bits(3)
                cl_huff = Huffman(cl_lengths)
                lengths = []
                while len(lengths) < hlit+hdist:
                    sym = cl_huff.decode(br)
                    if sym < 16:
                        lengths.append(sym)
                    elif sym == 16:
                        rep = br.bits(2)+3
                        lengths.extend([lengths[-1]]*rep)
                    elif sym == 17:
                        rep = br.bits(3)+3
                        lengths.extend([0]*rep)
                    else:
                        rep = br.bits(7)+11
                        lengths.extend([0]*rep)
                lit_lengths = lengths[:hlit]
                dist_lengths = lengths[hlit:hlit+hdist]
                lit_huff = Huffman(lit_lengths)
                dist_huff = Huffman(dist_lengths)
            while True:
                sym = lit_huff.decode(br)
                if sym < 256:
                    tokens.append(('lit', len(out), sym))
                    out.append(sym)
                elif sym == 256:
                    break
                else:
                    idx = sym-257
                    length = LEN_BASE[idx] + br.bits(LEN_EXTRA[idx])
                    dsym = dist_huff.decode(br)
                    distance = DIST_BASE[dsym] + br.bits(DIST_EXTRA[dsym])
                    tokens.append(('match', len(out), length, distance))
                    for _ in range(length):
                        out.append(out[-distance])
        else:
            raise ValueError('bad btype')
        if bfinal:
            break
    return bytes(out), tokens

if __name__ == '__main__':
    import zlib
    png = open(sys.argv[1],'rb').read()
    i=8; idat=b''
    while i < len(png):
        ln = int.from_bytes(png[i:i+4],'big')
        typ = png[i+4:i+8].decode('ascii',errors='replace')
        data = png[i+8:i+8+ln]
        if typ=='IDAT': idat+=data
        i += 8+ln+4
        if typ=='IEND': break
    raw_deflate = idat[2:]  # strip 2-byte zlib header
    out, tokens = decode_deflate(raw_deflate)
    ref = zlib.decompress(idat)
    print('match output vs zlib:', out == ref, len(out), len(ref))
    print('num tokens', len(tokens))
    kinds = {}
    for t in tokens:
        kinds[t[0]] = kinds.get(t[0],0)+1
    print(kinds)
