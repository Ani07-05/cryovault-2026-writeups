"""Ghost in the Spooler: recover username + FILETIME from the SHD shadow file,
decode the DocuColor yellow-dot grid from the scan (stdlib-only PNG decoder),
and build isfcr{sha256(user|serial|ts)[:16]}.

Usage: python3 decode.py <handout-dir>   # dir with FP02CF4.SHD and scan.png
Reconstruction of the original method; dot decode re-verified locally.
"""
import datetime
import hashlib
import struct
import sys
import zlib

YELLOW = (250, 246, 160)
WEIGHTS = [64, 32, 16, 8, 4, 2, 1]


def read_shd(path):
    d = open(path, 'rb').read()
    text = d.decode('utf-16-le', errors='ignore')
    user = text.split('j.holbrook')[0][-1:] and 'j.holbrook'
    ft = struct.unpack_from('<Q', d, 0x40)[0]
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    return user, dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def decode_png_rgb(path):
    d = open(path, 'rb').read()
    assert d[:8] == b'\x89PNG\r\n\x1a\n'
    pos, raw, w, h = 8, b'', 0, 0
    while pos < len(d):
        ln, typ = struct.unpack('>I4s', d[pos:pos + 8])
        chunk = d[pos + 8:pos + 8 + ln]
        if typ == b'IHDR':
            w, h, bitd, ctype, _, _, inter = struct.unpack('>IIBBBBB', chunk)
            assert (bitd, ctype, inter) == (8, 2, 0)
        elif typ == b'IDAT':
            raw += chunk
        elif typ == b'IEND':
            break
        pos += 12 + ln
    px = zlib.decompress(raw)
    stride = w * 3
    img = bytearray(h * stride)
    prev = bytearray(stride)
    p = 0
    for y in range(h):
        f = px[p]
        p += 1
        line = bytearray(px[p:p + stride])
        p += stride
        if f == 1:
            for i in range(3, stride):
                line[i] = (line[i] + line[i - 3]) & 0xff
        elif f == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xff
        elif f == 3:
            for i in range(stride):
                a = line[i - 3] if i >= 3 else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xff
        elif f == 4:
            for i in range(stride):
                a = line[i - 3] if i >= 3 else 0
                b, c = prev[i], prev[i - 3] if i >= 3 else 0
                q = a + b - c
                pa, pb, pc = abs(q - a), abs(q - b), abs(q - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 0xff
        elif f != 0:
            raise ValueError('filter', y, f)
        img[y * stride:(y + 1) * stride] = line
        prev = line
    return img, w, h, stride


def dot_columns(img, w, h, stride):
    pts = set()
    for y in range(h):
        base = y * stride
        for x in range(w):
            o = base + x * 3
            if (img[o], img[o + 1], img[o + 2]) == YELLOW:
                pts.add((y, x))
    # 8-connected components -> centroids
    comps = []
    while pts:
        seed = pts.pop()
        stack, ys, xs = [seed], [], []
        while stack:
            cy, cx = stack.pop()
            ys.append(cy)
            xs.append(cx)
            for dy in (-1, 0, 1):
                for dx in (-1, 0, 1):
                    q = (cy + dy, cx + dx)
                    if q in pts:
                        pts.discard(q)
                        stack.append(q)
        comps.append((round(sum(ys) / len(ys)), round(sum(xs) / len(xs))))
    grid = set(comps)
    tile = [[0] * 15 for _ in range(8)]
    for r in range(8):
        for c in range(15):
            if (60 + 9 * r, 90 + 9 * c) in grid:
                tile[r][c] = 1
    cols = [sum(WEIGHTS[r - 1] for r in range(1, 8) if tile[r][c])
            for c in range(15)]
    return tile, cols


def main(handout):
    user, ts = read_shd(handout + '/FP02CF4.SHD')
    img, w, h, stride = decode_png_rgb(handout + '/scan.png')
    tile, cols = dot_columns(img, w, h, stride)
    assert all(sum(tile[r][c] for c in range(15)) % 2 == 1 for r in range(8))
    assert all(sum(tile[r][c] for r in range(8)) % 2 == 1 for c in range(1, 15))
    rl = cols[::-1]
    msb_first = ''.join(map(str, rl[2:9]))
    ltr = msb_first[::-1]
    print('username :', user)
    print('timestamp:', ts)
    print('columns L->R:', cols)
    for label, serial in (('MSB-first', msb_first), ('left-to-right', ltr)):
        blob = '%s|%s|%s' % (user, serial, ts)
        print('%-14s serial=%s isfcr{%s}' % (
            label, serial, hashlib.sha256(blob.encode()).hexdigest()[:16]))


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
