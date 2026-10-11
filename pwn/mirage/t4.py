import socket, time
from mirage import HOST, PORT

s = socket.create_connection((HOST, PORT), timeout=5)
s.settimeout(2)
buf = b""
try:
    while True:
        chunk = s.recv(8192)
        if not chunk:
            break
        buf += chunk
except socket.timeout:
    pass
print("INITIAL BANNER:", repr(buf))

for cmd in [b"help", b"flag", b"quit", b"echo test", b"secret", b"cat flag.txt", b"ls"]:
    s.sendall(cmd + b"\n")
    time.sleep(0.4)
    resp = b""
    try:
        s.settimeout(1)
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    print(cmd, "->", repr(resp))
s.close()
