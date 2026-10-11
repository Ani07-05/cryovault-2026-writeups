# One pound fish -- OSINT

**Flag:** `isfcr{russell_market}`
**Tools:** Google Lens (reverse image search)

## Enumeration

Given a single photo of an open-air fish/seafood market street -- stalls of trays with fresh catch,
narrow lane, mixed old/new building facades, overcast sky.

## Analysis

Reverse image search (Google Lens) on the photo directly matched it to the fish and seafood section
of **Russell Market** in Shivajinagar, Bengaluru -- a well-known century-old market, identifiable from
the characteristic building facades, stall layout and tray arrangement visible in the shot.

## Exploit

No further pivoting needed -- the market name itself, normalized to the flag format, is the answer.

## Flag

`isfcr{russell_market}`
