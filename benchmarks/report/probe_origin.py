"""A small HTTP/1.1 origin for conformance checks.

nginx cannot be told to send a response with both Content-Length and Transfer-Encoding,
to truncate a body, or to say what it was sent. This origin does, because it is a few
dozen lines of sockets rather than a server: it reads requests the way a strict origin
would, remembers every request it received (so a test can tell whether a proxy forwarded
one request or two), and answers according to the path it was asked for.

    /p/echo            200, the body is the request as received (line, headers, body digest)
    /p/resp-hop        200 with hop-by-hop response headers a proxy must not pass on
    /p/resp-cl-te      200 with both Content-Length and Transfer-Encoding: chunked
    /p/resp-short      Content-Length: 100, 10 bytes, then the connection closes
    /p/resp-garbage    a header line without a colon
    /p/resp-100        a 100 Continue before the final 200
    /p/resp-304        304 with an ETag and no body
    /p/resp-bighdr     200 with a 60 KB header value
    /p/smuggled        200 (what an attacker wants to reach; tests check it is never asked for)

The admin side (a second port): GET /seen returns the requests received since the last
GET /reset, as JSON.
"""
from __future__ import annotations

import hashlib
import json
import socket
import threading


class ProbeOrigin:
    def __init__(self, port: int, admin_port: int):
        self.port, self.admin_port = port, admin_port
        self.seen: list[dict] = []
        self.lock = threading.Lock()
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        for port, handler in ((self.port, self._serve), (self.admin_port, self._admin)):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(128)
            self._socks.append(s)
            t = threading.Thread(target=self._accept, args=(s, handler), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass

    def _accept(self, srv: socket.socket, handler) -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    # ── reading a request the way a strict origin would ──────────────────────
    @staticmethod
    def _read_request(conn: socket.socket, buf: bytearray):
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buf += chunk
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        del buf[:]
        buf += rest
        lines = head.split(b"\r\n")
        method, target, _ver = (lines[0].decode("latin-1").split(" ", 2) + ["", ""])[:3]
        headers = []
        for ln in lines[1:]:
            k, _, v = ln.decode("latin-1").partition(":")
            headers.append((k, v.strip()))
        names = {k.lower(): v for k, v in headers}
        body = b""
        if "chunked" in names.get("transfer-encoding", "").lower():
            while True:
                while b"\r\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return dict(method=method, target=target, headers=headers, body=body)
                    buf += chunk
                size_line, _, rest = bytes(buf).partition(b"\r\n")
                try:
                    size = int(size_line.split(b";")[0], 16)
                except ValueError:
                    return dict(method=method, target=target, headers=headers, body=body, bad_chunk=True)
                del buf[:]
                buf += rest
                while len(buf) < size + 2:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                body += bytes(buf[:size])
                del buf[: size + 2]
                if size == 0:
                    break
        else:
            try:
                n = int(names.get("content-length", "0").split(",")[0])
            except ValueError:
                n = 0
            while len(buf) < n:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            body = bytes(buf[:n])
            del buf[:n]
        return dict(method=method, target=target, headers=headers, body=body)

    # ── origin ────────────────────────────────────────────────────────────────
    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(2)
        buf = bytearray()
        try:
            while True:
                req = self._read_request(conn, buf)
                if req is None:
                    return
                with self.lock:
                    self.seen.append(dict(method=req["method"], target=req["target"], headers=req["headers"],
                                          body_len=len(req["body"])))
                if self._respond(conn, req):
                    return
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _respond(self, conn: socket.socket, req: dict) -> bool:
        """Answer one request; True means close the connection afterwards."""
        what = req["target"].split("?")[0].rsplit("/", 1)[-1]
        send = conn.sendall
        if what == "resp-hop":
            body = b"ok"
            send(b"HTTP/1.1 200 OK\r\nConnection: X-Resp-Hop, keep-alive\r\nX-Resp-Hop: 1\r\nKeep-Alive: timeout=5\r\n"
                 b"Content-Length: 2\r\n\r\n" + body)
        elif what == "resp-cl-te":
            send(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
            return True
        elif what == "resp-short":
            send(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
            return True
        elif what == "resp-garbage":
            send(b"HTTP/1.1 200 OK\r\ngarbage-without-a-colon\r\nContent-Length: 2\r\n\r\nok")
        elif what == "resp-100":
            send(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        elif what == "resp-304":
            send(b'HTTP/1.1 304 Not Modified\r\nETag: "probe-1"\r\n\r\n')
        elif what == "resp-bighdr":
            send(b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 60000 + b"\r\nContent-Length: 2\r\n\r\nok")
        else:   # echo, smuggled, anything else
            lines = [f"{req['method']} {req['target']}"]
            lines += [f"{k}: {v}" for k, v in req["headers"]]
            lines.append(f"BODY-LEN {len(req['body'])}")
            lines.append(f"BODY-SHA256 {hashlib.sha256(req['body']).hexdigest()}")
            body = ("\n".join(lines) + "\n").encode("latin-1", "replace")
            send(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode()
                 + b"\r\n\r\n" + body)
        return False

    # ── admin ─────────────────────────────────────────────────────────────────
    def _admin(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            data = conn.recv(8192).decode("latin-1")
            path = data.split(" ", 2)[1] if " " in data else "/"
            with self.lock:
                if path.startswith("/reset"):
                    self.seen.clear()
                    body = b"{}"
                else:
                    body = json.dumps(self.seen).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        except (OSError, socket.timeout):
            pass
        finally:
            conn.close()
