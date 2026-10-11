# Ghost in the Spooler -- Forensics

**Flag:** `isfcr{e24d16be9d731cba}`
**Tools:** Python 3 (stdlib only: struct/datetime/hashlib/zlib PNG decoder), EFF DocuColor decoding guide
**Scripts:** `decode.py` is a reconstruction of the method in the original solve transcript (which ran on
another device); the dot-grid decode, SHD fields, and final hash were all independently re-verified
locally against the handout with a dependency-free script. Needs the handout files
(`FP02CF4.SHD`, `FP02CF4.SPL`, `scan.png`).

## Enumeration

Handout: `FP02CF4.SHD` (520 B Windows spooler shadow file), `FP02CF4.SPL` (1,872 B spool data),
`scan.png` (2550x3300 RGB scan of the printed page). The flag is not in any file -- it is built as
`isfcr{sha256(username|serial|timestamp)[:16]}` from three recovered values: the lowercase username
owning the print job, the printer's 7-digit serial, and the print's UTC timestamp as
`YYYY-MM-DDTHH:MM:SSZ`.

## Analysis

The SHD is a raw shadow file: UTF-16LE strings give `j.holbrook` printing
`Q3-Compensation-Adjustments.docx` from workstation `FIN-WKS-014` to
`\\PRINT01\HR-DocuColor-12` (Xerox DocuColor 12 PS driver, `NT EMF 1.008`), and the FILETIME
at offset `0x40` (`0x01DB090F0DE78E00`) converts to `2024-09-17T14:37:00Z`.

The DocuColor is the classic yellow-tracking-dot (MIC) printer. The scan carries 51,744
yellow `(250,246,160)` pixels forming 2,464 identical 21 px components on a 9 px pitch grid
(120 distinct x-positions, 88 y-positions) -- 88 repeats of one 15-wide x 8-tall tile.
Decoded per the EFF layout (column 1 = row parity, top row = column parity, data rows weigh
64/32/16/8/4/2/1 top to bottom; all rows and data columns check odd parity), the columns read
left to right as `[80,37,14,17,9,24,8,8,4,2,0,1,3,0,0]`, i.e. right to left
`[0,0] [3,1,0,2,4,8,8] [24,9,17,14,37]`: two pad columns, a 7-digit serial, then
year/month/day/hour/minute. The dot timestamp (2024-09-17 14:37) exactly matches the SHD
FILETIME -- proving the scanned page came off that machine for that job.

## Exploit

```
$ python3 decode.py ghost-spooler/
username : j.holbrook
timestamp: 2024-09-17T14:37:00Z
serial   : 8842013          # left-to-right digit order (see pitfall)
flag     : isfcr{e24d16be9d731cba}
```

Pitfall: the EFF example reads the serial most-significant-digit-first from the highest column
(`3102488`, giving decoy `isfcr{3b0d7740fdd8896f}`); this challenge's author laid the digits out
left to right (`8842013`), which is the confirmed flag.

## Flag

`isfcr{e24d16be9d731cba}`
