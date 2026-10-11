# Draftpad -- Web

**Flag:** `isfcr{merge_shifts_the_wall_not_the_window}`
**Tools:** curl, jq, browser devtools, manual document/op-log analysis (isfcrpesu-draftpad.chals.io)
**Scripts:** `exploit.py` (needs `requests`) is a reconstruction of the method described below; requires the live service.

Note: this was previously misfiled under the name `ouroboros` in this repo -- `ouroboros` is actually
a separate, unsolved pwn/misc challenge ("hand it 32 bytes. It will tell you nope.") that got
sidelined mid-session in favor of Draftpad. Corrected here.

## Enumeration

Service at `isfcrpesu-draftpad.chals.io`: "Draftpad is a tiny shared editor. Every document has a
public part that anyone can read and a private part." -- an operational-transform style shared
document.

```
$ curl -s https://isfcrpesu-draftpad.chals.io/ -o index.html -w "HTTP %{http_code}\n"
$ curl -s https://isfcrpesu-draftpad.chals.io/app.js -o app.js -w "HTTP %{http_code}\n"
$ curl -s https://isfcrpesu-draftpad.chals.io/api/document | jq .
$ curl -s https://isfcrpesu-draftpad.chals.io/api/export/public | jq .
$ curl -s https://isfcrpesu-draftpad.chals.io/api/log | jq .
```

## Analysis

`/api/export/public` is meant to redact a private range of blocks before export, marked by two pin
indices (`start=6, end=8`) into the flattened, linearly-ordered block list. The redaction logic keys off
numeric *position* in that flattened list, not block id or logical-clock range.

## Exploit

Inserted a new block (`probe-a`) as a child of `blk_pstart` -- earlier in tree order than the hidden
`blk_flag` -- via the document's own insert API. That shifted every downstream block's linear index by
one, but the pins kept their old numeric positions, so the redaction boundary slid past `blk_flag`.

Re-fetched `/api/export/public`: it printed the whole `--- confidential (do not export) ---` section,
including `blk_flag`'s content, in full and unredacted -- the flag above, handed back directly in the
export response.

## Flag

`isfcr{merge_shifts_the_wall_not_the_window}`
