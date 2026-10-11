"""Collect every 'equivalent match' (an LZ77 match whose chosen distance
has at least one alternative distance that would reproduce the identical
`length` bytes at the same output position), and try a couple of readings
of the tie-break choice as a hidden bitstream. Neither reading below
produced the flag -- kept for whoever picks this back up. See README.
"""
import bisect
import pickle
import sys

from deflate_tokens import DIST_BASE, decode_deflate


def load_idat(png_path):
    png = open(png_path, 'rb').read()
    i = 8
    idat = b''
    while i < len(png):
        ln = int.from_bytes(png[i:i + 4], 'big')
        typ = png[i + 4:i + 8].decode('ascii', errors='replace')
        data = png[i + 8:i + 8 + ln]
        if typ == 'IDAT':
            idat += data
        i += 8 + ln + 4
        if typ == 'IEND':
            break
    return idat


def find_ambiguous_matches(out, matches, max_ties=6):
    ambiguous = []
    for kind, pos, length, dist in matches:
        target = out[pos:pos + length]
        maxd = min(pos, 32768)
        ties = []
        for d in range(1, maxd + 1):
            if d >= length:
                cand = out[pos - d:pos - d + length]
            else:
                reps = (length // d) + 1
                cand = (out[pos - d:pos] * reps)[:length]
            if cand == target:
                ties.append(d)
                if len(ties) >= max_ties:
                    break
        if len(ties) > 1:
            ambiguous.append((pos, length, dist, ties))
    return ambiguous


def dist_bucket(d):
    return bisect.bisect_right(DIST_BASE, d) - 1


def main():
    png_path = sys.argv[1] if len(sys.argv) > 1 else 'mosaic_0417.png'
    idat = load_idat(png_path)
    out, tokens = decode_deflate(idat[2:])
    matches = [t for t in tokens if t[0] == 'match']

    ambiguous = find_ambiguous_matches(out, matches)
    pickle.dump(ambiguous, open('ambiguous.pkl', 'wb'))
    print('ambiguous matches:', len(ambiguous), '/', len(matches))

    # Reading 1: nearest-vs-not over every ambiguous match.
    binary_all = [0 if dist == min(ties) else 1 for _, _, dist, ties in ambiguous]
    print('reading 1 (all ties, nearest=0):', bytes(
        sum(b << (7 - j) for j, b in enumerate(binary_all[i:i + 8]))
        for i in range(0, len(binary_all) - 7, 8)
    ))

    # Reading 2: only ties within the same distance Huffman bucket (truly
    # zero extra-bit-cost substitutions -- the strict reading of
    # "equivalent").
    filtered = []
    for pos, length, dist, ties in ambiguous:
        b = dist_bucket(dist)
        same = [t for t in ties if dist_bucket(t) == b]
        if len(same) > 1:
            filtered.append((dist, sorted(same)))
    binary_bucket = [0 if d == same[0] else 1 for d, same in filtered]
    print('reading 2 (same-bucket ties, nearest=0):', bytes(
        sum(b << (7 - j) for j, b in enumerate(binary_bucket[i:i + 8]))
        for i in range(0, len(binary_bucket) - 7, 8)
    ))


if __name__ == '__main__':
    main()
