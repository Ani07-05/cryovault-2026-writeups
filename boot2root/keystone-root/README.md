# KeyStone - Root -- boot2root

**Tools:** ssh, objdump, manual TOCTOU race scripting
**Scripts:** No original script survived the session's ephemeral scratchpad; the method below is a
faithful reconstruction from the session transcript, not a recovered file.
**Flag:** `isfcr{a_pcr_is_a_promise_not_proof}`

## Enumeration

Starting from `tpm-admin` (see [`keystone-user`](../keystone-user) for the forged-TPM-attestation
foothold): `tpm-admin` has passwordless sudo on `/usr/sbin/measure-and-run *`.

## Analysis

`objdump` on that binary (pulled via `scp`) showed it calling `open()` once to hash the target file
for its allowlist check, then `open()`'ing the SAME path again for a fresh fd that goes straight
into `fexecve()` -- a classic check-then-reopen TOCTOU race, since `/etc/measure/allowed-hashes.txt`
turned out to be `root:root 644` (not writable by `tpm-admin` despite what the operators' doc
implied).

## Exploit

Won the race by flooding a busy-loop file swap (`cp /bin/true` -> `cp /bin/bash` repeatedly onto
the target path) while firing thousands of parallel `sudo /usr/sbin/measure-and-run` calls against
it, until one call's hash check passed against the allowlisted binary while its `fexecve()`
actually ran the swapped-in `bash`, from which a setuid root shell (`chmod 4755` on a copied
`/bin/bash`) was dropped.

## Verification

The root flag was submitted and marked Correct Answer on the room's answer page.
