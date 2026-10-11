# Phantom Mesh -- Forensics

**Tools:** Python, Scapy/Zigbee (802.15.4) parsing, Correlation Power Analysis (CPA) against SDR IQ traces, AES-CCM*
**Scripts:** Original scripts recovered from the session scratchpad: `cpa.py`, `pcap.py`, `pcap2.py`, `pcap3.py`, `dec1.py`, `dec2.py`, `load.py`, `extract.py`.
**Flag:** `isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}` (see note below)

## Enumeration

phantom-mesh.zip: mesh.pcap (Zigbee capture), traces/iq.npz (2500 SDR captures of KEY_CONFIRM exchanges), traces/nonces.csv, plus LMP-protocol.md / sdr-capture.md. A rogue device on the mesh (LUMETA-NET fabric) sent a daily diagnostics report that needed decrypting.

## Analysis

All SECURE_REPORT (cmd 0x21) frames had sequential frame counters (1-95) from devices whose EUI64 low byte clustered tightly -- except one frame with frame_counter=3501, a distinct EUI64 ending ...40:00, and a much longer ciphertext: the uninvited device's report (frame 80).

## Exploit

1. CPA attack on the 2500 KEY_CONFIRM SDR traces: used the known 16-byte nonce per    trace as plaintext against |I+jQ| envelope power (the vendor notes hinted at    unstable PA bias causing data-dependent AM -- the side channel), correlating    Hamming weight of AES SubBytes(nonce_byte XOR key_byte) per byte position. All 16    key bytes recovered independently with clean correlation peaks:
   TC Link Key = 7cf8b0b78be9f36a225c1e70692e1e1c
   Verified exactly against two KEY_CONFIRM tags (confirm_tag = AES-ECB(key, nonce)[:8]).
2. Decrypted TRANSPORT_KEY (frame 39) with the TC Link Key under AES-CCM* (nonce/AAD    built per the byte-order quirk in LMP-protocol.md) -> MIC verified ->
   NWK Key = ffa0be732cd8f56eae8caa21359baf06
3. Decrypted the rogue SECURE_REPORT (frame 80) with the NWK Key -> MIC verified ->    ZCL-like report, cluster_id=0xfc01, attribute_id=0x42, 52-byte value decoding    directly to ASCII containing the flag.

## Verification

MIC verified at every decryption stage (KEY_CONFIRM, TRANSPORT_KEY, SECURE_REPORT), confirming each recovered key.
