# Attestation -- Web

**Flag:** `isfcr{attest_5d60_notary_41a34ce7_laundered}`
**Tools:** curl -sk, Python 3 (hashlib/json/tarfile), OCI registry API, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** solve.py is the original script that ran (recovered from the session scratchpad).

## Enumeration

Service at `https://isfcrpesu-attestation.chals.io` (489 pts), a per-team OCI-style evidence vault. `POST /session` mints a per-team registry base for all later paths.

```
$ curl -sk -X POST https://isfcrpesu-attestation.chals.io/session
$ curl -sk $BASE/catalog.json
$ curl -sk $BASE/policy.json
$ curl -sk $BASE/v2/cryovault/tags/list
```

`catalog.json` gives the `case`, `platform`, and the `retired_manifest` (digest + size); `policy.json` gives the `live_layer` release path/record and the referrers claim/annotation names. `tags/list` shows only `archived-case`. Pulling that retired manifest and its evidence layer yields three decoy flags, retired-custody only: `isfcr{archival_c26b516c766ae89451650c8cb04441aa}`, `isfcr{archival_ef7c619d92a445b574c1b99e5e106e14}`, `isfcr{archival_4c3d298a7ed042eed7637241a133e5a4}`.

`POST /api/notarize {"digest": retired_digest}` returns a notary attestation digest for the retired manifest; `GET /v2/cryovault/referrers/<retired_digest>` then lists it (size 210) alongside the claim annotation the opener will demand.

## Analysis

`POST /api/open` only honors a reviewed index: the `reference` needs a matching `ticket` from `POST /api/review`, and review only stamps an index holding both the retired and a live manifest on identical platforms.

Two quirks combine. First, the live layer tar member path is checked against a protected prefix -- writing the ustar header with `release_path` split at its last `/` into `prefix`/`name` passes intake while still extracting to the release location. Second, when both index entries tie on platform, selection follows entry order, so one of `idx-lr` / `idx-rl` selects live and fails review while the other selects the retired digest and returns a usable ticket.

The last gate is a legacy fallback: a tag named `sha256-<live_hex>` whose index body relabels the retired-custody attestation with the required live claim annotation. The opener resolves that tag subject without a seal check, so the retired notary satisfies the live claim.

## Exploit

`solve.py` (132 lines) shells out to `curl -sk`, canonicalizes every JSON body with `separators=(',',':')`, and computes exact `sha256:` digests and byte sizes over the raw PUT bytes:

```
$ python3 solve.py   # session, build, review both orders, fallback, open
```

1. `POST /session`, read `catalog.json` / `policy.json`.
2. Fetch the retired manifest + evidence (archival flags only).
3. `POST /api/notarize` the retired digest; resolve the attestation size (210) via the referrers API.
4. Build the prefix-split tar, plus evidence/config blobs and the live manifest, PUTting each blob and manifest with its exact digest/size.
5. PUT index `idx-lr` (live, retired) and `idx-rl` (retired, live); `POST /api/review` both, keep the ticket whose `selected == retired_digest`.
6. PUT the `sha256-<live_hex>` fallback index relabeling the attestation claim.
7. `POST /api/open` with the winning reference + ticket -- returns the live flag. Verified on fresh sessions.

## Flag

`isfcr{attest_5d60_notary_41a34ce7_laundered}`
