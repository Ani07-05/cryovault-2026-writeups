# Frost-ledger Bay 07 -- Forensics

**Flag:** `isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}`
**Tools:** fvrctl info/stat/lsroot, docker --platform linux/amd64, Python 3 struct/zlib/re, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a faithful reconstruction of the parser actually used (same struct layouts/offsets), re-expressed as a single offline script; needs the handout registry.fvr.

## Enumeration

492-pt forensics. Handout `frost-ledger.tar.gz` unpacks to `registry.fvr`, a linux/amd64
`fvrctl`, and docs (`ONDISK-NOTES.txt`, `RELEASE-NOTES.txt`, `fvr_format.h`, `fvregd.log`).
Target is the record `bay/07/thaw-authority`; its authority-token is the flag.

```
$ tar xzf frost-ledger.tar.gz
$ docker run --platform linux/amd64 -v $PWD:/m frost terrain:fvrctl info /m/registry.fvr
```

`ONDISK-NOTES.txt` is explicitly v0-only (12-byte descriptors, forward offsets from body
start). `RELEASE-NOTES.txt` carries the rest: 1.3.0 moves v0->v1 (16-byte descriptor plus
flags, not backward readable); 1.4.0 starts record-versioning and stores rv4+ payloads
encoded rather than verbatim, with `total_len` as the *stored* length; 1.4.2 removes the
`get`/`walk` subcommands, so offline inspection goes through a hand-rolled reader. `fvrctl`
(`info`/`stat`/`lsroot`) reports FVR v1, 3072 pages of 4096 bytes, with slots 284-290
verifying and slot 291 reading TORN.

## Analysis

The superblock holds 8 root slots (`<QIIQQ`: epoch, root pgid, wal_head, reserved, FNV1a-64
over the first 24 bytes). Recomputing the checksum discards the epoch-291 slot, leaving slot 2
(epoch 290, root 3039) as the live generation -- max epoch among *valid*-fnv slots. Liveness is
tree reachability plus fnv plus epoch consistency; it is never the record name or the raw
maximum epoch.

v1 packing is undocumented (`fvr_cell_key()`/`fvr_cell_value()` live in the unshipped libfvr),
so it was learned empirically: the target key hits 101 times, always at page-offset 4075, i.e.
ending exactly at the page end. Body length is 4072, descriptors are 16 bytes (`<IHHII`:
koff/ksize/vsize/voff/flags), and key/value payloads pack *backwards* from the page end
(`key = page[4096-koff:4096-koff+ksize]`). An overflow value sets `flags & 0x2`, and its inline
bytes are `<Q head +I total`.

## Exploit

```
$ python3 solve.py registry.fvr
```

Walk live root 3039 (INDEX, 8 separators, all `seg/...` so `bay/...` takes the first child)
to DATA page 3030, whose first cell is the target with head 966 and stored-len 2372. Reassemble
the overflow chain 966->2675->184->355 via each page's `next_pgid`/`bytes_used` header, assert
the 2372 bytes against `total_len`, then `zlib.decompress` -- record-version 4, epoch 290 --
and read off the authority-token (the `stale` in its name is a decoy).

Decoys: the rv3/epoch-6 plaintext CoW history
(`isfcr{thaw_authority_superseded_at_epoch_6}`), the epoch-291 revision behind the torn root
(`isfcr{superseded_authority_rev1_8ce67c}`, fnv fail), the epoch-326 orphan with no slot
(`isfcr{superseded_authority_rev6_0fa710}`), plus orphans rev2_0ad5eb@298, rev3_fc69e1@305,
rev4_1b0dc1@312, rev5_6ad752@319 -- all reachable only by ignoring fnv/slot liveness.

## Flag

`isfcr{stale_cow_67c1_root_fc8fe97f_backwards_heap}`
