# The Last Committed Message -- Forensics

**Tools:** Python, sqlite3 CLI, manual SQLite WAL frame replay, cryptography (AES-GCM)
**Scripts:** Original scripts recovered from the session scratchpad: `p.py`, `q.py`, `r.py`, `v.py`, `w.py`, `f.py`, `g.py`.
**Flag:** `isfcr{a03a410f1b87dbc115dd1ef6}` (see note below)

## Enumeration

case.db / case.db-wal: had to recover a note and its attachment record exactly as they stood when export export-07abca69cd99 was acknowledged, using an export log that ties export ids to operation ids and statuses.

## Analysis

export-07abca69cd99 appears twice in the export log: once against op-c46dc0e04bdd (status: timeout -- a decoy, since a timed-out operation never describes real post-commit state) and once against op-09e0d79b4b14 (status: acknowledged -- the real one). The live database and the newest WAL generation only retain the latest few operations; an older WAL generation with stale salt 1049188690 sits after the valid frames and had to be replayed separately.

## Exploit

Replayed that older WAL generation frame-by-frame up to frame 454 (database size 208 pages), the exact frame that committed the operation record for op-09e0d79b4b14. Because the older generation doesn't sit on a clean base, tried three different ways of layering its pages over the live database file and the oldest generation; all three agreed on the same note row and attachment hash:
  Note id:      note-7211098c21a6, revision "5"
  Destination:  sftp://drop-edef61bb364d.example.invalid/inbox/.../5ec4921ffe4835a0.bin
                ?ticket=a638d0e59bf0b87a8d34c22020f0555d
  Attachment:   blob-72346f69c681,
                sha256 b89d5c5695803071522614060828e31e9bb4bc25813fdbc5d516db06ac4c2d58
Used sqlite3 directly on a scratch copy of the handout (never touching the original extracted files) to cross-check page contents, then fed this evidence into the challenge's AES-GCM flag decryption.

## Verification

AES-GCM decryption succeeded on the recovered state, confirming it was correct.
