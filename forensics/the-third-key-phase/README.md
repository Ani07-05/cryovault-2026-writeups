# The Third Key Phase -- Forensics

**Tools:** Python, Wireshark/tshark, custom QUIC/TLS-1.3 record decryptor, hashlib.scrypt
**Scripts:** Original scripts recovered from the session scratchpad: `asm.py`, `b2.py`, `brute.py`, `dec.py`, `fin.py`, `fr.py`, `fr2.py`, `miss.py`, `t.py`.
**Flag:** `isfcr{7d6bae9970a1173284046064}` (see note below)

## Enumeration

capture.pcapng: a QUIC/UDP-443 capture of 5 connections, no visible TLS handshake packets in Wireshark. Had to recover the exact bytes of the file accepted by the intake service for request id 6e26102a48d71fe1d7f68231, then derive a key from [request_id, client_random, sha256(file)].

## Analysis

Wireshark couldn't decode the capture because the handshake packets weren't present; the embedded TLS secrets were keyed by client_random. The 5 connections use different cipher/QUIC-version combinations (AES-128-GCM and AES-256-GCM on QUICv1, AES-GCM and ChaCha20 on QUICv2), and some packets needed a TLS 1.3 key-update ("key phase" — the challenge's title) to decrypt. Wrote a custom decryptor instead of relying on tshark's built-in QUIC support; it decrypted 261/265 packets (the remaining 4 were tiny, treated as noise).

## Exploit

The request id appeared on two connections: bfa624... (client cancelled it, stream 8 reset) and 87566bdc... (the one that actually delivered the file, resending the failed parts: stream 4 -> stream 20, stream 8 -> stream 16; the server rejected a later stream 24 with status 26). Rebuilt the file by interleaving streams 0, 20, 16 and 12 (data striped in 119-byte units), which produced a clean raw-DEFLATE stream decompressing to 16,456 bytes (a CSV starting "# transfer 6e26102a..."). Computed SHA-256 of the decompressed bytes (not the compressed bytes, which don't match), then ran:
evidence = ["6e26102a48d71fe1d7f68231",
            "87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3",
            "43669914701c2add27583d67043e96c02f44d622a78116f10fea5fac66e233dd"]
through hashlib.scrypt(b"isfcr-forensics\x00" + E, salt=...) exactly as specified to derive the AES key, then AES-GCM-decrypted the flag blob.

## Verification

Key derivation matched and the flag decrypted cleanly from the derived AES-GCM key.
