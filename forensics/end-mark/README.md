# End Mark -- Forensics

**Flag:** `isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}`
**Tools:** Python 3 (from-scratch SQLite WAL frame parser + b-tree leaf-page record decoder)
**Scripts:** `solve.py` -- the actual script that produced the flag.

## Enumeration

Given `ledger.db`, `ledger.db-wal` and `trace.ndjson`: a SQLite WAL-mode database with a sole writer
`W` and six reader connections `C1`-`C6`, each doing `BEGIN DEFERRED` then a `READ heartbeat` query
then 4 `FETCH`es (`SELECT payload FROM fragments WHERE slot=?`) then `END`. The trace records every
operation's order (`seq`) and timestamp (`tick`), but never the bytes a `FETCH` actually returned.
Task: recover the exact 24-byte `payload` each of the 24 `FETCH` calls (one per slot, 0-23) saw,
concatenate in slot order, and submit `sha256(...)` truncated to 32 hex chars.

## Analysis

**Which read establishes a reader's snapshot.** Under SQLite WAL snapshot isolation with
`isolation_level=None` (autocommit) and an explicit `BEGIN DEFERRED`, the read snapshot is pinned at
the connection's *first actual read of the main database*, not at `BEGIN` itself. Each reader's
`READ heartbeat` statement was designed to look like that first read, but three of the six are decoys
that touch nothing in `main`:
- C2: `SELECT 1` -- a constant, no table access.
- C4: `SELECT marker FROM temp.pulse WHERE id=1` -- a `TEMP` table (separate temp database, not `main`).
- C6: `SELECT sqlite_version()` -- a scalar function, no database access.

For those three, the real snapshot is pinned at their first *FETCH* instead. C1 (`SELECT marker FROM
heartbeat WHERE id=1`), C3 (`PRAGMA user_version`, reads the main db header) and C5 (`SELECT count(*)
FROM sqlite_schema`) are genuine main-db reads and pin the snapshot right there.

Walking `trace.ndjson` for the last `W` commit strictly before each reader's real snapshot event gives
six target transaction numbers: **C1->tx38, C2->tx42, C3->tx44, C4->tx65, C5->tx67, C6->tx71.**

**Reconstructing state at an arbitrary past transaction.** SQLite WAL frames store full page images
(not diffs), so the state after any committed transaction can be read directly off its frame, with no
need to replay deltas. Parsing `ledger.db-wal`'s 32-byte header + 24-byte-per-frame headers (page
size 1024) gives 120 frames = 60 two-page commit transactions (page 2 = the 24-row `fragments` table,
one b-tree leaf page; page 3 = a 1-row `heartbeat` table). The file holds **two WAL salt generations**
concatenated: the current one (salt matching the file header) and a stale leftover generation whose
frames were never physically overwritten. Cross-checking against the base `ledger.db` (which matches
the *last* frame of the stale generation exactly) and the single `CHECKPOINT` event in the trace
(`PRAGMA wal_checkpoint(RESTART)`, landing right between trace tx60 and tx61) pins the mapping:

- Physical frames 0-119 split into two 60-frame (30-tx) halves.
- The stale/first-in-file half = the tail of the pre-checkpoint WAL lifetime = **trace tx31-60**.
- The current/second-in-file half = the post-checkpoint lifetime = **trace tx61-90**.

**Validation.** Every row's record carries a 3rd column (an update-revision counter). Walking all 60
reconstructed states in this inferred chronological order (tx31->90), that counter is strictly
non-decreasing for every one of the 24 slots, and *exactly one* slot's value changes per transaction
(for 59/60 transitions; the first sampled point has nothing to compare against) -- zero violations.
That's independent confirmation the tx-to-frame mapping is correct.

## Exploit

```
$ python3 solve.py
```

For each of the 6 target transactions, locate its WAL frame pair, parse page 2's b-tree leaf cells
(varint cell pointers -> payload-length/rowid varints -> sqlite record header/serial-type decoding) to
read all 24 rows' `payload` BLOBs, and pull out the specific slot(s) that reader fetched. Concatenate
all 24 payloads in slot order 0-23, SHA-256 the 576-byte result, take the first 32 hex characters.

## Flag

`isfcr{28bc454d9b8fc1b73ff97a0d7db31a76}`
