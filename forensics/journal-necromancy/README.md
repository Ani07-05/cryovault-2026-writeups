# Journal Necromancy -- Forensics

**Flag:** `isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}`
**Tools:** Python 3, pycryptodome, xxd
**Scripts:** `mft_scan.py` is a reconstruction -- the actual solve ran a from-scratch MFT parser in an
ephemeral session scratchpad that no longer exists on disk. Logic/offsets below match the real solve.

## Enumeration

Given `evidence.img` (64 MiB raw NTFS image) and `$LogFile`, from a workstation wiped before being
handed back. `secure_archive.enc`, an 85-byte MFT-resident file under `Personal/vault`, holds an `ENC1`
marker + 12-byte nonce + ciphertext + 16-byte GCM tag. `reminders.txt` documents that the real key is a
3-way XOR of three 32-byte shares, each carrying a 1-byte index and a 1-byte parity byte.

## Analysis

Dead ends checked first:

- `$LogFile` is entirely `0xFF` -- no NTFS transaction journal survives.
- 120 deleted `Cache/_c/c*_NNNN.tmp` files (80 random bytes each) are decoys, no valid carrier inside.

Wrote a from-scratch MFT record parser (not a directory walk -- the relevant records had already been
deleted) and iterated every record, including ones no live directory entry points to. This surfaced
three unreferenced data clusters whose content looked like plausible filler text but wasn't referenced
by any MFT entry:

- cluster `10420` -- a fake log
- cluster `12133` -- a random 4K block
- cluster `13848` -- scratch notes

## Exploit

```
$ xxd -s $((10420*4096+2630)) -l 140 evidence.img
$ xxd -s $((13848*4096+1975)) -l 140 evidence.img
```

Each hidden share sits behind a `DE AD 53 47` marker, followed by a 1-byte index, a 32-byte share and a
1-byte parity (`index XOR share-bytes`). Scanned the whole image for the marker and validated parity
(`mft_scan.py`). All three validated. XORed the three shares together to get the AES-256-GCM key, then
decrypted `secure_archive.enc`. The tag verified and the plaintext was the flag.

## Flag

`isfcr{mft_slack_dies_but_data_clusters_remember_1a2f}`
