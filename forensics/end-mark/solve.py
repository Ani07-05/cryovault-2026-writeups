"""End Mark: reconstruct the 24 FETCH payloads each reader connection saw,
by reading WAL frames directly (full page images, no diffing needed) at the
exact transaction each reader's snapshot was actually pinned at -- which is
each connection's first real read of the *main* database, not its labeled
'heartbeat' (three of those are decoys that touch no main-db page).
"""
import hashlib
import struct

# slot -> trace transaction number the reader that fetched it had its
# snapshot pinned at (see README for the decoy-heartbeat / tx-mapping
# derivation from trace.ndjson).
SLOT_SNAPSHOT_TX = {}
for tx, slots in {
    38: [15, 20, 13, 23],
    42: [9, 3, 11, 16],
    44: [17, 8, 10, 0],
    65: [18, 12, 14, 7],
    67: [22, 5, 21, 19],
    71: [6, 1, 4, 2],
}.items():
    for s in slots:
        SLOT_SNAPSHOT_TX[s] = tx


def read_varint(b, o):
    result = 0
    for i in range(9):
        c = b[o]
        o += 1
        if i == 8:
            result = (result << 8) | c
            break
        result = (result << 7) | (c & 0x7F)
        if not (c & 0x80):
            break
    return result, o


def parse_record(payload):
    hdr_len, p = read_varint(payload, 0)
    serials = []
    while p < hdr_len:
        st, p = read_varint(payload, p)
        serials.append(st)
    bo = hdr_len
    cols = []
    for st in serials:
        if st == 0:
            val, ln = None, 0
        elif st == 1:
            val, ln = payload[bo], 1
        elif st == 8:
            val, ln = 0, 0
        elif st == 9:
            val, ln = 1, 0
        elif st >= 12 and st % 2 == 0:
            ln = (st - 12) // 2
            val = payload[bo:bo + ln]
        elif st >= 13:
            ln = (st - 13) // 2
            val = payload[bo:bo + ln].decode('utf8', errors='replace')
        else:
            val, ln = None, 0
        cols.append(val)
        bo += ln
    return cols


def parse_fragments_page(page):
    """Leaf table b-tree page -> {slot: 24-byte payload}."""
    ncell = struct.unpack('>H', page[3:5])[0]
    rows = {}
    for i in range(ncell):
        cp = struct.unpack('>H', page[8 + 2 * i:10 + 2 * i])[0]
        o = cp
        plen, o = read_varint(page, o)
        rowid, o = read_varint(page, o)
        cols = parse_record(page[o:o + plen])
        rows[rowid] = cols[1]  # column 1 = payload BLOB
    return rows


def load_wal_frames(path, page_size=1024):
    d = open(path, 'rb').read()
    off = 32  # skip 32-byte WAL header
    frames = []
    while off + 24 + page_size <= len(d):
        pgno, dbsize = struct.unpack('>II', d[off:off + 8])
        page = d[off + 24:off + 24 + page_size]
        frames.append((pgno, dbsize, page))
        off += 24 + page_size
    return frames


def fragments_at_tx(frames, tx):
    """Map a trace transaction number to its WAL frame-pair index and parse
    the resulting fragments-table page. See README for the derivation of
    this tx<->frame mapping (two WAL generations concatenated in one file)."""
    if 61 <= tx <= 90:
        k = tx - 61
    elif 31 <= tx <= 60:
        k = tx - 1
    else:
        raise ValueError(f'tx {tx} outside recoverable WAL range')
    pgno, dbsize, page = frames[2 * k]
    assert pgno == 2, 'expected the fragments-table page'
    return parse_fragments_page(page)


def main():
    frames = load_wal_frames('ledger.db-wal')

    payloads = {}
    for tx in set(SLOT_SNAPSHOT_TX.values()):
        rows = fragments_at_tx(frames, tx)
        for slot, snap_tx in SLOT_SNAPSHOT_TX.items():
            if snap_tx == tx:
                payloads[slot] = rows[slot]

    concat = b''.join(payloads[s] for s in range(24))
    digest = hashlib.sha256(concat).hexdigest()
    print('flag:', f'isfcr{{{digest[:32]}}}')


if __name__ == '__main__':
    main()
