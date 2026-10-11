# Cassandra -- Web

**Flag:** `isfcr{h2_continuation_smuggling_is_the_new_black}`
**Tools:** curl --http2, openssl s_client -ALPN h2, Python 3 + python-h2/hpack/hyperframe, OpenCode AI pair-solver (Muse Spark 1.3)
**Scripts:** `solve.py` is a faithful reconstruction of the method actually used (same primitives/endpoints), re-expressed as a single script; requires the live service.

475 pts. Target `0.cloud.chals.io:30152` -- H2 over TLS with a self-signed cert (`CN=cassandra.local`),
`server: cassandra-edge/2.3.1`.

## Enumeration

```
$ openssl s_client -connect 0.cloud.chals.io:30152 -ALPN h2 -servername cassandra.local | openssl x509 -noout -subject -issuer
$ curl -k --http2 -v https://0.cloud.chals.io:30152/
$ curl -k --http2 https://0.cloud.chals.io:30152/api/openapi.json
$ curl -k --http2 https://0.cloud.chals.io:30152/api/changelog
$ curl -k --http2 https://0.cloud.chals.io:30152/api/status
$ curl -k --http2 https://0.cloud.chals.io:30152/api/notes
$ curl -k --http2 https://0.cloud.chals.io:30152/api/notes/201
$ curl -k --http2 https://0.cloud.chals.io:30152/admin/flag   # -> 401
```

`/api/changelog` is the roadmap: it documents a CONTINUATION fast-path bug (only the primary
HEADERS frame is checked for restricted headers), a signer that refuses any literal-`/admin` path,
an admin verifier that `unquote()`s + `normpath()`s before comparing, a 4 KiB notes cap, and a
monitor that hits the backend every ~3 s with a bot bearer token.

## Analysis

Setting `max_outbound_frame_size=20` on a python-h2 connection splits every header block into
HEADERS + CONTINUATIONs. The frontend's restricted-header check only inspects the first HEADERS
frame, so anything smuggled in a CONTINUATION (`Content-Length`, `X-Signed-Path`, `X-Admin-Ts`,
`X-Admin-Sig`) sails through.

The backend is an H2 front over a shared H1 connection pool. A `POST /api/notes` carrying a
smuggled `Content-Length` desyncs that H1 layer: the leftover bytes (the monitor's own pipelined
H1 request, including its `Authorization: Bearer ...` header) get stored as a note body of exactly
`len=CL`, readable back at `GET /api/notes/201`.

## Exploit

1. **CONTINUATION bypass primitive.** Fresh H2 connection, `max_outbound_frame_size=20`, clean
primary HEADERS, restricted headers in CONTINUATION frames. Confirmed the 401 path accepted
smuggled headers.
2. **Bearer capture.** Fresh connection per try: `POST /api/notes` with smuggled `Content-Length`
600-4000 and a short prefix body, then poll `GET /api/notes/201` during a request lull until a
stored note matches `Authorization: Bearer ...`. Timing matters -- hit the gap between monitor
ticks so the desync swallows the monitor's request rather than a stranger's.
3. **Sign.** `POST /internal/sign` with that bearer to sign a path. The signer blocks literal
`/admin`, so sign `/api/../%61dmin/flag` instead -- the admin verifier `unquote()`s +
`normpath()`s it back to `/admin/flag` after the signature check.
4. **Flag.** Fresh connection, fresh `ts` each try (`+-30 s` window): `GET` with request path
`/admin/flag` plus smuggled `X-Signed-Path` / `X-Admin-Ts` / `X-Admin-Sig` via CONTINUATION ->
flag body.

Pitfalls: the instance is shared, so other players overwrite note 201 -- re-capture when the
content changes. A poisoned H1 pool connection keeps desyncing, so use a fresh connection (and
fresh timestamp) for every attempt.

## Flag

`isfcr{h2_continuation_smuggling_is_the_new_black}`
