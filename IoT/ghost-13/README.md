# GHOST-13 -- IoT

**Tools:** Python, Wireshark/Modbus-TCP stream reassembly, ECDSA nonce-reuse key recovery, AES-GCM, HKDF
**Scripts:** Original scripts recovered from the session scratchpad: `p1.py`, `p2.py`, `p3.py`, `p4.py`.
**Flag:** `isfcr{ghost13_dc8f84a256fa64108b6c75a151a1474d}` (see note below)

## Enumeration

plc_firmware.bin, plc_program.bin, plc_traffic.pcap, alarm_buzzer.wav, maintenance_update (1).ota, uart_log.txt, field_service_excerpt.txt: a line controller's maintenance gateway received two diagnostic writes after a brief power failure "that should never have looked alike."

## Analysis

The program dump has 8 redundancy slots; slot 6's journal fails its CRC, slot 7's own CRC and commit word are bad (though its journal checks out), and slots 0-5 are valid with the last valid journal pointing at slot 5 (sequence 2, epoch 7, trim 09 09 03 02 09 09 09 04; the 16-bit journal sequence rolls over 65535->0 between slots 2 and 3). Reassembled the Modbus/TCP stream and read the FC16 writes as three diagnostic fragment streams tagged 0x41, 0x42 and 0x43: 0x41 sits before the brownout restart in the UART log, 0x42 after it, and 0x43 is never mentioned there at all.

## Exploit

Each fragment stream was missing one data slice, restored from an accompanying XOR parity fragment. Decrypted all three frames using slot 5's ID and salt, recovering the same state string (PLC-G13/STATE/...) in all three -- and crucially, streams 0x41 and 0x42 carried ECDSA signatures sharing the same nonce-derived r value, i.e. the power-restoration restart reused a signing nonce (the challenge's own "two diagnostic writes that should never have looked alike"). Reusing that nonce let me solve directly for the P-256 private scalar, which matched the public key embedded in the firmware image. The alarm buzzer recording decoded to two DTMF digit groups (70372720 = power-on self-check, 64658003 = wire code); adding the slot-5 trim bytes mod 10 to the wire code gave the real update digits (53977997). That update patch applied cleanly to the factory firmware image (CRC and SHA-256 both matched), and an HKDF over the recovered P-256 scalar (with firmware version 3, read from the image header) produced the AES-GCM key for maintenance_update (1).ota.

## Verification

The AES-GCM tag on the maintenance update verified, and the decrypted diagnostic JSON read {"diagnostic":"power-restoration", ...} containing the flag.
