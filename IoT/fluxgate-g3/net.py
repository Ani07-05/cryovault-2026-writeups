import socket, sys, time

HOST="0.cloud.chals.io"; PORT=25537

s = socket.create_connection((HOST, PORT), timeout=10)
s.settimeout(1.5)

def recv_all():
    buf=b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            buf += chunk
    except socket.timeout:
        pass
    return buf.decode(errors="replace")

def cmd(line):
    s.sendall((line+"\n").encode())
    time.sleep(0.3)
    out = recv_all()
    print(f">>> {line}\n{out}")
    return out

print(recv_all())
cmd("HELLO")
cmd("STATUS")
cmd("TOKEN")
