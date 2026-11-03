#!/usr/bin/env python3
"""A bare HTTP/1.1 server simulating a middleware-bypass vulnerability, for testing run.py
itself (tests/lab/run.py) against a real zion binary without Docker or a real CVE.

    python3 fake_upstream.py PORT vulnerable|fixed

/            -> 200 "home"
/protected   -> 401 "denied", UNLESS:
                 - vulnerable: the X-Bypass-Auth header is present -> 200 "CANARY"
                 - fixed:      that header is never honored
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep test output quiet

    def _reply(self, status: int, body: str):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        if self.path == "/":
            self._reply(200, "home")
            return
        if self.path == "/protected":
            bypass = self.headers.get("X-Bypass-Auth")
            if MODE == "vulnerable" and bypass == "1":
                self._reply(200, "CANARY")
            else:
                self._reply(401, "denied")
            return
        self._reply(404, "not found")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._handle()


if __name__ == "__main__":
    port, MODE = int(sys.argv[1]), sys.argv[2]
    assert MODE in ("vulnerable", "fixed")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
