# Sanity Check -- Misc

**Flag:** `isfcr{n0_d1sc0rd_n0_gl0ry}`
**Tools:** Discord client (hover inspection), browser

## Enumeration

No handout files -- the challenge lived entirely in the event's own Discord server.

## Analysis

In the `#announcements` channel, the pinned `CRYOVAULT 2026` event-details message used a custom
server emoji (`:cryovaultlogo:`) as part of its header. Hovering over that custom emoji in Discord's
client shows its underlying asset tooltip -- which here was a direct link:
`https://pastebin.com/ksDVcMpT`, tucked into the emoji rather than posted as visible text.

## Exploit

Opened the pastebin link. It's a short, unlisted paste titled `CRYOVAULT 2026`, posted by a guest,
containing the flag in plaintext.

## Flag

`isfcr{n0_d1sc0rd_n0_gl0ry}`
