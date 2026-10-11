# Write Hole -- Forensics

**Flag:** `isfar{p4r1ty_n3v3r_l13s_wr1t3_h0l3_r3m3mb3rs}`
**Tools:** Python 3, dissect.extfs, pycryptodome
**Scripts:** original, as run during the CTF (`raid.py`, `score.py`, `walk.py`, `fin.py`-`fin5.py`)

## Enumeration

Given three 18 MiB disk images (`bay0.img`, `bay1.img`, `bay2.img`) from a 3-drive software RAID that lost
power mid-write (the "write hole"), with no saved layout. A sealed report, believed to be an ext4
filesystem striped across the three disks, is somewhere in there -- stripe geometry (chunk size, layout,
disk order) all unknown.

## Analysis

`raid.py` rebuilds a candidate linear volume for every combination of:

- chunk size in `{4096, 8192, 16384, ..., 512K}`
- layout in `{left-symmetric, left-asymmetric, right-symmetric, right-asymmetric}`
- disk permutation (all `3! = 6` orderings)

`score.py` scores each candidate by (a) the ext4 magic `0xEF53` at byte offset 1024, and (b) decoding the
root inode's extent header and confirming the root directory's first dirent is self-referential
(inode 2, name `.`).

```
$ python3 score.py   # prints (score, chunk, layout, perm, msg) sorted descending
```

One combination scored 10/10 ("ROOT OK"), giving the exact chunk size, layout and disk permutation.

## Exploit

Rebuilt the volume with that layout, mounted it with `dissect.extfs`, and walked it (`walk.py`) to find
`/stage/payload.bin` and `/stage/job-0007.intent` -- a manifest listing the expected `sha256` of every
stripe chunk.

Recovered the per-job AES-256 key by scanning every raw disk page for the `KSLT\x01` key-slot magic,
CRC32-checking each 52-byte candidate, and keeping the one whose `sha256[:16]` matched the known key id
(`fin.py`).

For every record in the intent manifest, computed two candidate plaintexts per stripe -- straight from the
data chunk, and reconstructed via parity XOR of the other two disks -- and kept whichever matched the
manifest hash *and* decrypted cleanly under AES-GCM (`fin2.py`). Record #3 sat exactly on the write-hole:
neither candidate matched.

For that one inconsistent stripe, brute-forced a single-byte correction near the point where the AES-CTR
decrypt stopped being valid ASCII, until the corrected buffer's `sha256` matched the manifest (`fin5.py`),
then re-ran AES-CTR with the corrected stripe (`fin4.py`) to get the clean plaintext: `rec3.txt`, a
2000+ line evidence-custody log.

## Flag

The custody token was split into 3 shards hidden inline in the log:

```
$ grep -n shard rec3.txt
```

```
[custody-token] shard 1/3 = isfar{p4r1ty_n3
[custody-token] shard 2/3 = v3r_l13s_wr1t3_
[custody-token] shard 3/3 = h0l3_r3m3mb3rs}
```

Concatenated in order, no separators: `isfar{p4r1ty_n3v3r_l13s_wr1t3_h0l3_r3m3mb3rs}`
