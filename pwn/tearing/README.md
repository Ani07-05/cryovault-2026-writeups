# tearing -- Pwn

**Flag:** `isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}`
**Tools:** netcat (`/dev/tcp`), manual protocol probing
**Scripts:** `exploit.py` is a reconstruction of the method described below (both the intended thread-race path and the `claim_only` path that actually worked); requires the live service.

## Enumeration

Service: `nc 0.cloud.chals.io 26166` -- a ticket-vault TCP service ("one ticket in the drawer. Leave
with two.") with `redeem`/`status`/`claim`/`quit` commands over a shared counter.

```
$ which nc ncat socat
$ timeout 5 bash -c 'exec 3<>/dev/tcp/0.cloud.chals.io/26166; cat <&3'
$ ( sleep 1; echo status; sleep 1; echo redeem; sleep 1; echo claim; sleep 1; echo quit; sleep 1 ) | nc -w8 0.cloud.chals.io 26166
```

## Analysis

The intended bug is a classic TOCTOU: `redeem` has a check-then-act window on the shared ticket counter,
so two concurrent `redeem` calls can both pass the check before either decrements it, letting a single
ticket be double-spent into two -- "the window only opens concurrently."

## Exploit

Vault state is global across connections, not per-session. By the time this connection hit the service,
the counter was already negative from the TOCTOU window (left over from the intended race), so a single
`claim` succeeded immediately without needing to drive the race myself on this run. The service handed
back the flag directly on `claim`.

## Flag

`isfcr{t0ct0u_w1nd0w_0nly_0p3ns_c0ncurr3ntly}`
