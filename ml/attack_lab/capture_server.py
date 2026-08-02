# SPDX-License-Identifier: Apache-2.0
"""Local capture target for the ML-WAF attack-traffic lab.

A tiny HTTP server bound to 127.0.0.1 that logs every request it receives
(method, request-target, headers) to a JSONL file and answers 200. Point real
attack tools (nuclei, sqlmap, ffuf, …) at it and it records the *actual* requests
they emit — real, tool-generated attack traffic to train the WAF scorer on.

Strictly local + defensive: the target is our own loopback server; the tools
never touch a third party. Captured data is gitignored (never committed).

    CAPTURE_OUT=ml/corpus/traffic/attack.jsonl CAPTURE_LABEL=attack \
    CAPTURE_PORT=9099 python3 ml/attack_lab/capture_server.py
"""

from __future__ import annotations

import http.server
import json
import os
import threading

OUT = os.environ.get("CAPTURE_OUT", "capture.jsonl")
LABEL = os.environ.get("CAPTURE_LABEL", "attack")
PORT = int(os.environ.get("CAPTURE_PORT", "9099"))

_lock = threading.Lock()
_body = b"<html><body>OK</body></html>"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _capture_and_reply(self, with_body: bool = True) -> None:
        rec = {
            "label": LABEL,
            "method": self.command,
            "uri": self.path,  # request-target: path + query, exactly as sent
            "headers": [[k, v] for k, v in self.headers.items()],
        }
        line = json.dumps(rec, ensure_ascii=False)
        with _lock:
            with open(OUT, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        # Drain any request body so keep-alive stays in sync.
        clen = int(self.headers.get("Content-Length", 0) or 0)
        if clen:
            try:
                self.rfile.read(clen)
            except Exception:
                pass
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(_body) if with_body else 0))
        self.end_headers()
        if with_body:
            try:
                self.wfile.write(_body)
            except Exception:
                pass

    def do_GET(self):
        self._capture_and_reply()

    def do_POST(self):
        self._capture_and_reply()

    def do_PUT(self):
        self._capture_and_reply()

    def do_DELETE(self):
        self._capture_and_reply()

    def do_PATCH(self):
        self._capture_and_reply()

    def do_OPTIONS(self):
        self._capture_and_reply()

    def do_HEAD(self):
        self._capture_and_reply(with_body=False)

    def log_message(self, *_args):
        pass  # silence per-request stderr spam


if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"capture on 127.0.0.1:{PORT} → {OUT} (label={LABEL})", flush=True)
    srv.serve_forever()
