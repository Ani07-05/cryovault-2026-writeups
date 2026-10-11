import sys, json, hashlib
sys.path.insert(0, '/tmp/w/s')
from solve import *  # NOTE: not recovered verbatim -- see README.md
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CASE = "9697624543591457a15dc6d9a4797c45"  # CaseID of the orphaned/unreferenced PDF revision

def tryg(grid):
    """Derive an AES-GCM key from [CASE, grid] via scrypt and attempt the decrypt."""
    E = json.dumps([CASE, grid], ensure_ascii=True, separators=(",", ":")).encode()
    key = hashlib.scrypt(
        b"isfcr-forensics\x00" + E,
        salt=bytes.fromhex("8a251a8101ffa67ed383a445a05e77f2"),
        n=131072, r=8, p=1, maxmem=2**28, dklen=32,
    )
    try:
        return AESGCM(key).decrypt(
            bytes.fromhex("cf5d90d20b821db4c5bf1b73"),                           # nonce
            bytes.fromhex("27b4469da3cc30f3ec487d60be3053aa2d5aa00c9f4da69fe54e7d51da8463883b4aa1b0a10a69c45c4e974171133f"),  # ciphertext+tag
            b"the-alphabet-that-wasnt-there",                                     # AAD
        )
    except Exception:
        return None

def grid_of(doc, R, thr=0.99):
    """Keep only glyphs that are >=thr covered by the topmost drawn pixels
    (i.e. actually visible after clipping/overlays), match each to the
    labelled reference alphabet by rotation-normalised bitmap comparison."""
    rm = refmap()
    ids, counts = np.unique(R.buf, return_counts=True)
    cnt = dict(zip(ids.tolist(), counts.tolist()))
    units = {}
    vis = []
    for i, g in enumerate(R.glyphs):
        if not g['area'] or cnt.get(i + 1, 0) < thr * g['area']:
            continue
        fn = g['font']
        if fn not in units:
            units[fn] = font_unit(doc, doc.obj[fn])
        g['sym'] = rm.get(canon(bitmap(glyph_rects(doc.stm[g['cp']]), units[fn])), '?')
        vis.append(g)
    return vis

def rows_to_str(vis, tol=8):
    """Sort visible glyphs into the 16x16 reading order (top-to-bottom rows,
    left-to-right within a row) and flatten to a symbol string."""
    vis = sorted(vis, key=lambda g: -g['y'])
    rows = []
    for g in vis:
        if rows and abs(rows[-1][0] - g['y']) < tol:
            rows[-1][1].append(g)
        else:
            rows.append([g['y'], [g]])
    return ''.join(''.join(g['sym'] for g in sorted(r, key=lambda g: g['x'])) for _, r in rows), [len(r) for _, r in rows]

def flat(n, maxoff=None):
    """Render Form XObject `n` from the orphaned revision of damaged.pdf."""
    doc = Doc(P + 'damaged.pdf', maxoff)
    R = Renderer(doc, (-40, -30, 320, 450), 6)
    gs = GS()
    gs.clips = [(I, (-40, -30, 360, 480))]
    R.run(b'/X0 Do', {'XObject': {'X0': Ref(n)}}, gs)
    return doc, R

if __name__ == '__main__':
    for n in (109, 110, 111):           # candidate page/revision XObjects
        doc, R = flat(n)
        vis = grid_of(doc, R)           # <-- the version here reads glyphs
                                         #     WITHOUT the 14 white-patch
                                         #     overlays applied, which is
                                         #     the combination that decrypts
        s, l = rows_to_str(vis)
        print(n, len(vis), l, s[:40], tryg(s))
