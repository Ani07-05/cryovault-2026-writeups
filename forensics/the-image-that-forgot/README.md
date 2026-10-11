# The Image That Forgot -- Forensics

**Flag:** `isfcr{57cfd556fca281af64d920ef}`
**Tools:** Python 3, hashlib (scrypt), cryptography (AESGCM)
**Scripts:** `a.py`, `b.py`, `c.py` are the original scripts recovered from the session
scratchpad, verbatim.

## Enumeration

`handout (6).zip` -> `the-image-that-forgot/` with `events.jsonl`, `images.tar` (an OCI image
layout: `index.json` + content-addressed `blobs/sha256/*`), and `vault.json`. Task: "Recover the
incident token of the container instance that was serving `dispatch-ac1af5608a` at
`2026-08-14T10:10:08.555+05:30`." `a.py` walks `index.json` -> every OCI image index -> its
per-platform manifests -> each manifest's config/layers, to map every digest mentioned in
`events.jsonl` down to an actual filesystem.

## Analysis

`events.jsonl` mixes two kinds of records: service lifecycle events (`activate` / `restart` /
`rollback` / `migrate`, each with an `event_id` and, for `activate`, a `ref` that's either a raw
`sha256:` digest or a tag like `dispatch:stable`) and tag-resolution records (`{"tag":...,
"digest":..., "time_ms":...}`) that say what a tag pointed to at a given moment. Converting every
`dispatch-ac1af5608a` event to UTC and replaying the tag's history over time: the instance running
at the query time was started by the **migrate** event at `04:36:41Z`, `deploy-9d1a1fd93d`, onto an
amd64 node -- a prior failed activation attempt doesn't count as a start. The image it was running
had been set by the **rollback** at `04:25:54Z`, reverting to `sha256:30062144...`, which is a
multi-platform OCI index; on the amd64 node that resolves to the single-platform manifest
`sha256:154d6f1fa75464d02b6245a4e536f6efb187af4bf7266aff8ac9e2e21d4538f8`.

The hard part is `key_version`: it isn't a small integer, it's a string baked into that specific
image's filesystem. `b.py` extracts the full layered filesystem for that manifest (handling
whiteouts, opaque-whiteout directory resets, hardlinks and symlinks across layers). The expected
path `/etc/service/key-version.json` doesn't exist in the final filesystem -- it was deleted by an
opaque whiteout in a later layer. But it had originally been a **hardlink** to
`/opt/dispatch/.state/b97e8564`, which survives untouched and resolves to `key-e52be7cc57`. A
second, decoy copy at `/etc/service.bak` (`key-90a623d0c2`) also exists and also decrypts *some*
note under the vault's AAD scheme, but that token never satisfies the final flag derivation.

## Exploit

`c.py` brute-forces the vault: for each candidate `key_version` string, each of the 4 vault keys,
and each of the 203 notes, build the AAD `[service_id, key_version, manifest_digest, event_id]`
(ASCII compact JSON) and try `AESGCM(key).decrypt(nonce, data, aad)`. Exactly one combination
authenticates: `key_version="key-e52be7cc57"`, vault key index 2, note 92, decrypting to the token
`e411af706f77101364ccdf6b0cb59e75eb8b3cc34342a94c`.

With the full evidence list `["deploy-9d1a1fd93d", "sha256:154d6f1f...e4538f8",
"dispatch-ac1af5608a", "key-e52be7cc57", "e411af70...cc34342a94c"]`, derive the flag key with
`hashlib.scrypt(b"isfcr-forensics\x00" + compact_json(evidence), salt=..., n=131072, r=8, p=1,
dklen=32)` and `AESGCM(key).decrypt(...)` the challenge's own ciphertext with AAD
`b"the-image-that-forgot"`.

## Verification

The decoy key version (`key-90a623d0c2`, the surviving `.bak` copy) also decrypts a note under the
vault, but the resulting token fails to unlock the final flag blob -- only `key-e52be7cc57` (the
hardlink-recovered value) produces a scrypt key whose AES-GCM decrypt of the final ciphertext
authenticates.
