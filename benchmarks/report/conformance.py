#!/usr/bin/env python3
"""HTTP conformance of a proxy, check by check, with the RFC section each one comes from.

    conformance.py --zion BIN --out DIR [--only h1,...]

It starts the same rig as bench.py (nginx origin, zion, nginx as the reference) plus a
probe origin that can send the malformed and edge-case responses a real origin never
will (probe_origin.py). Every check is run against zion and against nginx, so a column of
"fail" for both usually means the check asks for something the RFC leaves optional, and
a check zion fails and nginx passes is the one to read first.

Verdicts:  pass  fail  info (behaviour recorded, no requirement)  n/a (could not be run).
Levels:    MUST / SHOULD / SECURITY (hardening the RFC implies but does not word as MUST)
           / INFO. Only a failed MUST or SECURITY check is a defect; a failed SHOULD is a
           deviation to read; INFO never fails.

The checks are deterministic: fixed bytes in, fixed expectations out, no timing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import bench
from bench import NGX_HTTPS, ORIGIN_PORT, PROBE_ADMIN_PORT, PROBE_PORT, ZION_HTTPS
from probe_origin import ProbeOrigin

HOST = "localhost"


# ── a tiny HTTP/1.1 client that does not fix anything for us ────────────────────

@dataclass
class Resp:
    status: int | None = None
    headers: list = field(default_factory=list)
    body: bytes = b""
    complete: bool = False       # the framing said the message ended and it did
    closed: bool = False         # the peer closed (EOF) before our deadline
    interim: list = field(default_factory=list)
    raw: bytes = b""

    def h(self, name: str) -> str | None:
        v = [x for k, x in self.headers if k.lower() == name.lower()]
        return ", ".join(v) if v else None

    def names(self) -> set:
        return {k.lower() for k, _ in self.headers}


def parse_one(raw: bytes, method: str = "GET"):
    """Parse one response from the start of raw. Returns (Resp, consumed) or (None, 0)."""
    pos, interim = 0, []
    while True:
        end = raw.find(b"\r\n\r\n", pos)
        if end < 0:
            return None, 0
        lines = raw[pos:end].split(b"\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", lines[0])
        if not m:
            return Resp(status=None, raw=raw), len(raw)
        status = int(m.group(1))
        headers = []
        for ln in lines[1:]:
            k, _, v = ln.decode("latin-1").partition(":")
            headers.append((k, v.strip()))
        pos = end + 4
        if 100 <= status < 200 and status != 101:
            interim.append(status)
            continue
        break
    r = Resp(status=status, headers=headers, interim=interim, raw=raw)
    names = {k.lower(): v for k, v in headers}
    if method == "HEAD" or status in (204, 304):
        r.complete = True
        return r, pos
    if "chunked" in names.get("transfer-encoding", "").lower():
        body = b""
        while True:
            e = raw.find(b"\r\n", pos)
            if e < 0:
                return r, len(raw)
            try:
                size = int(raw[pos:e].split(b";")[0], 16)
            except ValueError:
                return r, len(raw)
            pos = e + 2
            if size == 0:
                t = raw.find(b"\r\n\r\n", pos - 2)
                r.body, r.complete = body, t >= 0
                return r, (t + 4 if t >= 0 else len(raw))
            if len(raw) < pos + size + 2:
                r.body = body + raw[pos:pos + size]
                return r, len(raw)
            body += raw[pos:pos + size]
            pos += size + 2
    if "content-length" in names:
        try:
            n = int(names["content-length"].split(",")[0])
        except ValueError:
            n = 0
        r.body = raw[pos:pos + n]
        r.complete = len(raw) >= pos + n
        return r, min(len(raw), pos + n)
    r.body = raw[pos:]            # delimited by close
    return r, len(raw)


def exchange(port: int, payload: bytes | list, *, methods=("GET",), expect_close=False, timeout=4.0,
             alpn=("http/1.1",), tls=True, wait_between: float = 0.0) -> list[Resp]:
    """Send payload (bytes, or a list of bytes sent with a pause between) and return the
    responses read. Stops when len(methods) complete responses arrived, unless
    expect_close, in which case it reads to EOF so `closed` is meaningful."""
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(list(alpn))
        sock = ctx.wrap_socket(raw, server_hostname=HOST)
    else:
        sock = raw
    deadline = time.time() + timeout
    buf, closed = b"", False
    try:
        for part in (payload if isinstance(payload, list) else [payload]):
            try:
                sock.sendall(part)
            except (ConnectionError, ssl.SSLError, OSError):
                closed = True        # the peer hung up on us while we were still sending
                break
            if wait_between:
                sock.settimeout(wait_between)
                try:
                    chunk = sock.recv(65536)
                    buf += chunk
                    closed = closed or not chunk
                except (socket.timeout, ssl.SSLError):
                    pass
        sock.settimeout(0.7)
        while time.time() < deadline and not closed:
            resps, off = [], 0
            for m in methods:
                r, used = parse_one(buf[off:], m)
                if r is None:
                    break
                resps.append(r)
                off += used
            if len(resps) == len(methods) and all(r.complete for r in resps) and not expect_close:
                break
            try:
                chunk = sock.recv(262144)
            except socket.timeout:
                if buf and not expect_close and resps:
                    break
                continue
            except (ConnectionError, ssl.SSLError, OSError):
                closed = True
                break
            if not chunk:
                closed = True
                break
            buf += chunk
    finally:
        try:
            sock.close()
        except OSError:
            pass
    out, off = [], 0
    for m in methods:
        r, used = parse_one(buf[off:], m)
        if r is None:
            break
        out.append(r)
        off += used
    if not out:
        out = [Resp(raw=buf)]
    out[-1].closed = closed
    return out


def req(method, target, headers=(), body=b"", ver="HTTP/1.1", host=HOST) -> bytes:
    lines = [f"{method} {target} {ver}"]
    if host is not None:
        lines.append(f"Host: {host}")
    lines += list(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


# ── check registry ───────────────────────────────────────────────────────────────

CHECKS: list[dict] = []


def check(cid, group, rfc, level, title):
    def deco(fn):
        CHECKS.append(dict(id=cid, group=group, rfc=rfc, level=level, title=title, fn=fn))
        return fn
    return deco


class Ctx:
    """What a check may use: the port under test, the probe origin's memory, the nginx origin."""

    def __init__(self, name: str, port: int, probe: ProbeOrigin):
        self.name, self.port, self.probe = name, port, probe

    def x(self, payload, **kw) -> Resp:
        return exchange(self.port, payload, **kw)[-1]

    def xs(self, payload, **kw) -> list[Resp]:
        return exchange(self.port, payload, **kw)

    def reset(self) -> None:
        with self.probe.lock:
            self.probe.seen.clear()

    def seen(self) -> list[dict]:
        time.sleep(0.15)          # the proxy may still be forwarding when the client has its answer
        with self.probe.lock:
            return [dict(s, names={k.lower(): v for k, v in s["headers"]}) for s in self.probe.seen]


def P(ok, detail=""):
    return ("pass" if ok else "fail", detail.replace("status None", "no response (connection closed)"))


def rejected(r: Resp) -> bool:
    return r.status is not None and 400 <= r.status < 500 or (r.status is None and r.closed)


# ── A. request framing and smuggling (RFC 9112) ───────────────────────────────────

@check("cl-te", "Framing", "RFC 9112 §6.1", "MUST", "Content-Length and Transfer-Encoding together: not forwarded as both, and the connection is closed")
def _(c):
    c.reset()
    r = c.x(req("POST", "/p/echo", ["Content-Length: 5", "Transfer-Encoding: chunked"], b"0\r\n\r\n"), expect_close=True)
    if rejected(r):
        return P(True, f"rejected with {r.status}")
    s = c.seen()
    if s and "content-length" in s[0]["names"] and "transfer-encoding" in s[0]["names"]:
        return P(False, "origin received both headers")
    return P(r.closed, "answered and closed" if r.closed else "answered but kept the connection open (must close)")


@check("dup-cl", "Framing", "RFC 9110 §8.6", "MUST", "Two different Content-Length values: rejected, not forwarded")
def _(c):
    c.reset()
    r = c.x(req("POST", "/p/echo", ["Content-Length: 5", "Content-Length: 6"], b"hello!"))
    return P(rejected(r) and not c.seen(), f"status {r.status}, forwarded {len(c.seen())}")


@check("cl-invalid", "Framing", "RFC 9110 §8.6", "MUST", "Malformed Content-Length (+5, '5 5', 0x5, -1, 5abc): rejected, not forwarded")
def _(c):
    bad = []
    for v in ("+5", "5 5", "0x5", "-1", "5abc"):
        c.reset()
        r = c.x(req("POST", "/p/echo", [f"Content-Length: {v}"], b"hello"))
        if not (rejected(r) and not c.seen()):
            bad.append(f"{v!r}→{r.status}")
    return P(not bad, "; ".join(bad) or "all five rejected")


@check("te-unknown", "Framing", "RFC 9112 §6.1", "MUST", "Unknown transfer coding (xchunked): 400 or 501, not forwarded")
def _(c):
    c.reset()
    r = c.x(req("POST", "/p/echo", ["Transfer-Encoding: xchunked"], b"5\r\nhello\r\n0\r\n\r\n"))
    return P(r.status in (400, 501) and not c.seen(), f"status {r.status}, forwarded {len(c.seen())}")


@check("te-not-final", "Framing", "RFC 9112 §6.3", "MUST", "Transfer-Encoding: chunked, gzip (chunked not last): 400")
def _(c):
    c.reset()
    r = c.x(req("POST", "/p/echo", ["Transfer-Encoding: chunked, gzip"], b"5\r\nhello\r\n0\r\n\r\n"))
    return P(r.status == 400 and not c.seen(), f"status {r.status}, forwarded {len(c.seen())}")


@check("ws-colon", "Framing", "RFC 9112 §5.1", "MUST", "Whitespace before the colon in a field name: 400")
def _(c):
    c.reset()
    r = c.x(req("POST", "/p/echo", ["Transfer-Encoding : chunked"], b"5\r\nhello\r\n0\r\n\r\n"))
    return P(r.status == 400 and not c.seen(), f"status {r.status}, forwarded {len(c.seen())}")


@check("obs-fold", "Framing", "RFC 9112 §5.2", "MUST", "Obsolete line folding: rejected or replaced by a space")
def _(c):
    c.reset()
    r = c.x(b"GET /p/echo HTTP/1.1\r\nHost: localhost\r\nX-Fold: a\r\n b\r\n\r\n")
    if rejected(r):
        return P(True, f"rejected with {r.status}")
    s = c.seen()
    folded = any(k[:1] in (" ", "\t") for k, _ in (s[0]["headers"] if s else []))
    return P(not folded, "origin saw a folded line" if folded else "unfolded before forwarding")


@check("bare-cr", "Framing", "RFC 9112 §2.2", "MUST", "Bare CR in a field value: rejected or replaced")
def _(c):
    c.reset()
    r = c.x(b"GET /p/echo HTTP/1.1\r\nHost: localhost\r\nX-A: a\rb\r\n\r\n")
    if rejected(r):
        return P(True, f"rejected with {r.status}")
    return P(not any("\r" in v for _, v in (c.seen() or [dict(headers=[])])[0]["headers"]), f"status {r.status}")


@check("nul-value", "Framing", "RFC 9110 §5.5", "MUST", "NUL in a field value: rejected or replaced")
def _(c):
    c.reset()
    r = c.x(b"GET /p/echo HTTP/1.1\r\nHost: localhost\r\nX-A: a\x00b\r\n\r\n")
    if rejected(r):
        return P(True, f"rejected with {r.status}")
    return P(not any("\x00" in v for _, v in (c.seen() or [dict(headers=[])])[0]["headers"]), f"status {r.status}")


@check("no-host", "Framing", "RFC 9112 §3.2", "MUST", "HTTP/1.1 request without Host: 400")
def _(c):
    c.reset()
    r = c.x(req("GET", "/p/echo", host=None))
    return P(r.status == 400 and not c.seen(), f"status {r.status}")


@check("two-hosts", "Framing", "RFC 9112 §3.2", "MUST", "Two Host header lines: 400")
def _(c):
    c.reset()
    r = c.x(req("GET", "/p/echo", ["Host: other.example"]))
    return P(r.status == 400 and not c.seen(), f"status {r.status}")


@check("bad-host", "Framing", "RFC 9112 §3.2", "MUST", "Host with a space in it: 400")
def _(c):
    c.reset()
    r = c.x(req("GET", "/p/echo", host="exa mple.com"))
    return P(r.status == 400 and not c.seen(), f"status {r.status}")


@check("method-case", "Framing", "RFC 9110 §9.1", "MUST", "Lower-case method name is not a method: not served")
def _(c):
    c.reset()
    r = c.x(b"get /p/echo HTTP/1.1\r\nHost: localhost\r\n\r\n")
    return P(r.status in (400, 405, 501) or (r.status is None and r.closed), f"status {r.status}")


@check("target-8000", "Framing", "RFC 9112 §3", "SHOULD", "A request line of 8000 octets is accepted")
def _(c):
    r = c.x(req("GET", "/p/echo?" + "a" * 7900))
    return P(r.status == 200, f"status {r.status}")


@check("target-70000", "Framing", "RFC 9110 §15.5.15", "SHOULD", "A 70,000-octet request target gets 414 (or another 4xx), not a crash")
def _(c):
    r = c.x(req("GET", "/p/echo?" + "a" * 70000))
    return P(r.status is not None and (r.status == 200 or 400 <= r.status < 500), f"status {r.status}")


@check("headers-huge", "Framing", "RFC 9110 §15.5.32", "SHOULD", "200 KB of request headers: 431 (or another 4xx), not a 5xx or a hang")
def _(c):
    hs = [f"X-{i}: " + "a" * 1000 for i in range(200)]
    r = c.x(req("GET", "/p/echo", hs))
    return P(r.status is not None and (r.status == 200 or 400 <= r.status < 500), f"status {r.status}")


@check("chunk-bad-size", "Framing", "RFC 9112 §7.1", "MUST", "Malformed chunk size: not accepted")
def _(c):
    r = c.x(req("POST", "/p/echo", ["Transfer-Encoding: chunked"], b"ZZ\r\nabc\r\n0\r\n\r\n"))
    return P(not (r.status and 200 <= r.status < 300), f"status {r.status}")


@check("chunked-forward", "Framing", "RFC 9112 §7.1", "MUST", "A chunked request body arrives at the origin byte for byte")
def _(c):
    c.reset()
    body = b"5\r\nhello\r\n1\r\n \r\n5\r\nworld\r\n0\r\n\r\n"
    r = c.x(req("POST", "/p/echo", ["Transfer-Encoding: chunked"], body))
    want = hashlib.sha256(b"hello world").hexdigest()
    return P(r.status == 200 and want.encode() in r.body, f"status {r.status}")


@check("pipelining", "Framing", "RFC 9112 §9.3.2", "MUST", "Two pipelined requests are answered in order")
def _(c):
    rs = c.xs(req("GET", "/p/echo?first") + req("GET", "/p/echo?second"), methods=("GET", "GET"))
    ok = len(rs) == 2 and rs[0].status == 200 and rs[1].status == 200 and b"first" in rs[0].body and b"second" in rs[1].body
    return P(ok, f"{len(rs)} responses")


@check("conn-close", "Framing", "RFC 9112 §9.6", "MUST", "Connection: close is honoured")
def _(c):
    r = c.x(req("GET", "/p/echo", ["Connection: close"]), expect_close=True)
    return P(r.status == 200 and r.closed, f"status {r.status}, closed {r.closed}")


@check("expect-100", "Framing", "RFC 9110 §10.1.1", "SHOULD", "Expect: 100-continue: the body is delivered and answered")
def _(c):
    c.reset()
    head = req("POST", "/p/echo", ["Expect: 100-continue", "Content-Length: 5"])
    rs = c.xs([head, b"hello"], wait_between=1.2)
    r = rs[-1]
    return P(r.status == 200 and hashlib.sha256(b"hello").hexdigest().encode() in r.body,
             f"status {r.status}, interim {r.interim}")


@check("http10", "Framing", "RFC 9112 §3.2", "INFO", "HTTP/1.0 request without Host")
def _(c):
    r = c.x(req("GET", "/p/echo", ver="HTTP/1.0", host=None), expect_close=True)
    return ("info", f"status {r.status}")


@check("abs-form", "Framing", "RFC 9112 §3.2.2", "INFO", "Absolute-form target with a different Host header")
def _(c):
    c.reset()
    r = c.x(req("GET", "http://evil.example/p/echo"))
    s = c.seen()
    return ("info", f"status {r.status}; origin saw Host {s[0]['names'].get('host') if s else None!r}")


@check("options-star", "Framing", "RFC 9110 §9.3.7", "INFO", "OPTIONS *")
def _(c):
    r = c.x(req("OPTIONS", "*"))
    return ("info", f"status {r.status}")


@check("trace", "Hardening", "RFC 9110 §9.3.8", "SECURITY", "TRACE is not forwarded to the origin")
def _(c):
    c.reset()
    r = c.x(req("TRACE", "/p/echo", ["Cookie: session=secret"]))
    return P(r.status in (400, 403, 404, 405, 501) and not c.seen(), f"status {r.status}, forwarded {len(c.seen())}")


@check("connect", "Hardening", "RFC 9110 §9.3.6", "SECURITY", "CONNECT does not open a tunnel")
def _(c):
    c.reset()
    r = c.x(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % (PROBE_PORT, PROBE_PORT))
    return P(not (r.status and 200 <= r.status < 300) and not c.seen(), f"status {r.status}")


# ── B. proxy behaviour (RFC 9110 §7) ──────────────────────────────────────────────

@check("hop-request", "Proxy", "RFC 9110 §7.6.1", "MUST", "Hop-by-hop request headers (Connection-listed, Keep-Alive, Proxy-Connection) are not forwarded")
def _(c):
    c.reset()
    c.x(req("GET", "/p/echo", ["Connection: keep-alive, X-Remove-Me", "X-Remove-Me: 1", "Keep-Alive: timeout=9", "Proxy-Connection: keep-alive"]))
    s = c.seen()
    if not s:
        return ("fail", "origin never saw the request")
    leaked = [n for n in ("x-remove-me", "keep-alive", "proxy-connection") if n in s[0]["names"]]
    return P(not leaked, "leaked: " + ", ".join(leaked) if leaked else "none leaked")


@check("hop-response", "Proxy", "RFC 9110 §7.6.1", "MUST", "Hop-by-hop response headers (Connection-listed, Keep-Alive) are not passed on")
def _(c):
    r = c.x(req("GET", "/p/resp-hop"))
    leaked = [n for n in ("x-resp-hop", "keep-alive") if n in r.names()]
    return P(r.status == 200 and not leaked, "leaked: " + ", ".join(leaked) if leaked else f"status {r.status}, none leaked")


@check("via-request", "Proxy", "RFC 9110 §7.6.3", "SHOULD", "A Via header is added to the forwarded request")
def _(c):
    c.reset()
    c.x(req("GET", "/p/echo"))
    s = c.seen()
    v = s[0]["names"].get("via") if s else None
    return P(bool(v), f"Via: {v}" if v else "no Via")


@check("xff", "Proxy", "(not an RFC)", "INFO", "X-Forwarded-For from the client: what the origin sees")
def _(c):
    c.reset()
    c.x(req("GET", "/p/echo", ["X-Forwarded-For: 6.6.6.6"]))
    s = c.seen()
    return ("info", f"origin saw X-Forwarded-For: {s[0]['names'].get('x-forwarded-for') if s else None!r}")


@check("max-forwards", "Proxy", "RFC 9110 §7.6.2", "INFO", "OPTIONS with Max-Forwards: 0")
def _(c):
    c.reset()
    r = c.x(req("OPTIONS", "/p/echo", ["Max-Forwards: 0"]))
    return ("info", f"status {r.status}; forwarded {len(c.seen())}")


@check("resp-cl-te", "Proxy", "RFC 9112 §6.1", "MUST", "An origin response with both Content-Length and Transfer-Encoding is not relayed as both")
def _(c):
    r = c.x(req("GET", "/p/resp-cl-te"), expect_close=True)
    both = {"content-length", "transfer-encoding"} <= r.names()
    return P(r.status in (502, 503) or (not both and r.body == b"hello"), f"status {r.status}, both headers {both}, body {r.body[:12]!r}")


@check("resp-truncated", "Proxy", "RFC 9112 §8", "MUST", "A response cut short by the origin is not delivered as complete")
def _(c):
    r = c.x(req("GET", "/p/resp-short"), expect_close=True)
    return P(r.status in (502, 503, 504) or not r.complete, f"status {r.status}, complete {r.complete}, body {len(r.body)} bytes")


@check("resp-garbage", "Proxy", "RFC 9110 §5.5", "SHOULD", "A response header line without a colon is not relayed")
def _(c):
    r = c.x(req("GET", "/p/resp-garbage"))
    relayed = any("garbage" in k.lower() for k, _ in r.headers)
    return P(r.status in (502, 503) or not relayed, f"status {r.status}, relayed {relayed}")


@check("resp-100", "Proxy", "RFC 9110 §15.2", "MUST", "A 100 Continue before the final response does not confuse the client")
def _(c):
    r = c.x(req("GET", "/p/resp-100"))
    return P(r.status == 200 and r.body == b"ok", f"status {r.status}, body {r.body[:8]!r}")


@check("resp-bighdr", "Proxy", "RFC 9110 §5.4", "INFO", "A 60 KB response header")
def _(c):
    r = c.x(req("GET", "/p/resp-bighdr"))
    return ("info", f"status {r.status}")


@check("upstream-down", "Proxy", "RFC 9110 §15.6.3", "SHOULD", "An unreachable origin gives 502/503/504 promptly")
def _(c):
    t0 = time.time()
    r = c.x(req("GET", "/dead/x"), timeout=8)
    return P(r.status in (502, 503, 504) and time.time() - t0 < 6, f"status {r.status} after {time.time() - t0:.1f}s")


# ── C. representations, validators, ranges, static files ─────────────────────────

JSON_URL, IMG_URL, STATIC_URL = "/api/item-042.json", "/img/photo-01.jpg", "/static/docs/page-07.html"


def prime(c, url):
    r = c.x(req("GET", url))
    time.sleep(0.2)
    return r


@check("age-on-hit", "Representations", "RFC 9111 §4", "MUST", "A response served from cache carries Age")
def _(c):
    prime(c, JSON_URL)
    r = c.x(req("GET", JSON_URL))
    return P(r.h("age") is not None, f"Age: {r.h('age')}")


@check("etag-304", "Representations", "RFC 9110 §13.1.2", "MUST", "If-None-Match with the current ETag: 304, no body, validator kept")
def _(c):
    r0 = prime(c, JSON_URL)
    et = r0.h("etag")
    if not et:
        return ("fail", "no ETag on the response")
    r = c.x(req("GET", JSON_URL, [f"If-None-Match: {et}"]))
    return P(r.status == 304 and not r.body and r.h("etag") == et, f"status {r.status}, ETag {r.h('etag')}")


@check("ims-304", "Representations", "RFC 9110 §13.1.3", "MUST", "If-Modified-Since with Last-Modified: 304")
def _(c):
    r0 = prime(c, JSON_URL)
    lm = r0.h("last-modified")
    if not lm:
        return ("fail", "no Last-Modified on the response")
    r = c.x(req("GET", JSON_URL, [f"If-Modified-Since: {lm}"]))
    return P(r.status == 304 and not r.body, f"status {r.status}")


@check("inm-mismatch", "Representations", "RFC 9110 §13.1.2", "MUST", "If-None-Match with a different ETag: full 200")
def _(c):
    prime(c, JSON_URL)
    r = c.x(req("GET", JSON_URL, ['If-None-Match: "nope"']))
    return P(r.status == 200 and len(r.body) > 0, f"status {r.status}")


@check("head", "Representations", "RFC 9110 §9.3.2", "MUST", "HEAD: same status and Content-Length as GET, no body")
def _(c):
    g = prime(c, JSON_URL)
    h = c.x(req("HEAD", JSON_URL), methods=("HEAD",))
    return P(h.status == g.status and not h.body and h.h("content-length") == g.h("content-length"),
             f"HEAD {h.status} CL {h.h('content-length')} vs GET {g.status} CL {g.h('content-length')}")


@check("range-206", "Representations", "RFC 9110 §14", "MUST", "Range: bytes=0-99: a correct 206, or the whole 200 (both allowed)")
def _(c):
    g = prime(c, IMG_URL)
    n = len(g.body)
    r = c.x(req("GET", IMG_URL, ["Range: bytes=0-99"]))
    if r.status == 200:
        return P(len(r.body) == n, "Range ignored, full 200 (allowed)")
    ok = r.status == 206 and len(r.body) == 100 and r.h("content-range") == f"bytes 0-99/{n}" and r.body == g.body[:100]
    return P(ok, f"status {r.status}, Content-Range {r.h('content-range')}, {len(r.body)} bytes")


@check("range-416", "Representations", "RFC 9110 §15.5.17", "SHOULD", "An unsatisfiable range: 416 with Content-Range: bytes */N")
def _(c):
    g = prime(c, IMG_URL)
    r = c.x(req("GET", IMG_URL, ["Range: bytes=99999999-"]))
    if r.status == 200:
        return ("pass", "Range ignored, full 200 (allowed)")
    return P(r.status == 416 and r.h("content-range") == f"bytes */{len(g.body)}", f"status {r.status}, Content-Range {r.h('content-range')}")


@check("content-type", "Representations", "RFC 9110 §8.3", "SHOULD", "The origin's Content-Type is preserved")
def _(c):
    r = prime(c, JSON_URL)
    return P((r.h("content-type") or "").startswith("application/json"), f"Content-Type: {r.h('content-type')}")


@check("unsafe-method", "Representations", "RFC 9111 §4.4", "MUST", "POST to a cached URL is not answered from the cache")
def _(c):
    prime(c, JSON_URL)
    r = c.x(req("POST", JSON_URL, ["Content-Length: 2"], b"{}"))
    o = exchange(ORIGIN_PORT, req("POST", JSON_URL, ["Content-Length: 2"], b"{}"), tls=False)[-1]
    return P(r.status == o.status and r.h("age") is None, f"status {r.status} (origin says {o.status}), Age {r.h('age')}")


@check("accept-ranges", "Representations", "RFC 9110 §14.3", "SHOULD", "Static files advertise Accept-Ranges: bytes")
def _(c):
    r = c.x(req("GET", STATIC_URL))
    return P(r.status == 200 and (r.h("accept-ranges") or "").lower() == "bytes", f"status {r.status}, Accept-Ranges {r.h('accept-ranges')}")


@check("static-range", "Representations", "RFC 9110 §14", "SHOULD", "Static files honour Range")
def _(c):
    g = c.x(req("GET", STATIC_URL))
    r = c.x(req("GET", STATIC_URL, ["Range: bytes=10-19"]))
    ok = r.status == 206 and r.body == g.body[10:20]
    return P(ok, f"status {r.status}, {len(r.body)} bytes")


@check("static-conditional", "Representations", "RFC 9110 §13", "MUST", "Static files answer If-None-Match with 304")
def _(c):
    g = c.x(req("GET", STATIC_URL))
    et = g.h("etag")
    if not et:
        return ("fail", "no ETag on a static file")
    r = c.x(req("GET", STATIC_URL, [f"If-None-Match: {et}"]))
    return P(r.status == 304 and not r.body, f"status {r.status}")


@check("traversal", "Hardening", "RFC 3986 §6", "SECURITY", "Path traversal out of the static directory never reaches a file outside it")
def _(c):
    leaks = []
    for p in ("/static/../secret.txt", "/static/%2e%2e/secret.txt", "/static/%2e%2e%2fsecret.txt", "/static/..%2fsecret.txt",
              "/static/..%5csecret.txt", "/static/%252e%252e/secret.txt", "/static//..//secret.txt",
              "/static/./../secret.txt", "/static/%c0%ae%c0%ae/secret.txt", "/static/docs/../../secret.txt",
              "/static/..;/secret.txt", "/static/%2e%2e%00/secret.txt"):
        r = c.x(req("GET", p))
        if b"TOPSECRET-CANARY" in r.body:
            leaks.append(p)
    return P(not leaks, "leaked via " + ", ".join(leaks) if leaks else "12 encodings, none reached the file")


@check("static-methods", "Hardening", "RFC 9110 §9.3", "SECURITY", "PUT and DELETE on the static directory do not succeed")
def _(c):
    bad = []
    for m in ("PUT", "DELETE", "PATCH"):
        r = c.x(req(m, "/static/docs/page-07.html", ["Content-Length: 0"]))
        if r.status and 200 <= r.status < 300:
            bad.append(f"{m}→{r.status}")
    return P(not bad, ", ".join(bad) or "all refused")


# ── D. TLS ────────────────────────────────────────────────────────────────────────

def tls_connect(port, *, alpn=("http/1.1",), vmin=None, vmax=None, session=None, ctx=None):
    ctx = ctx or ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_alpn_protocols(list(alpn))
    if vmin:
        ctx.minimum_version = vmin
    if vmax:
        ctx.maximum_version = vmax
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=4), server_hostname=HOST, session=session)
    return s


@check("tls13", "TLS", "RFC 8446", "SHOULD", "TLS 1.3 is negotiated")
def _(c):
    s = tls_connect(c.port)
    v = s.version()
    s.close()
    return P(v == "TLSv1.3", v)


@check("tls12", "TLS", "RFC 5246", "INFO", "Whether TLS 1.2 is still accepted (a configured floor, not a requirement)")
def _(c):
    try:
        s = tls_connect(c.port, vmin=ssl.TLSVersion.TLSv1_2, vmax=ssl.TLSVersion.TLSv1_2)
        v = s.version()
        s.close()
        return ("info", f"accepted, {v}")
    except (ssl.SSLError, OSError) as e:
        return ("info", f"refused ({str(e).split(']')[-1].strip()})")


@check("alpn", "TLS", "RFC 7301", "INFO", "ALPN selection when the client offers h2 and http/1.1")
def _(c):
    s = tls_connect(c.port, alpn=("h2", "http/1.1"))
    a = s.selected_alpn_protocol()
    s.close()
    return ("info", f"selected {a}")


@check("resumption", "TLS", "RFC 8446 §4.6.1", "SHOULD", "A session is resumed with a ticket")
def _(c):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    s = tls_connect(c.port, ctx=ctx)
    s.sendall(req("GET", "/p/echo"))
    s.settimeout(2)
    try:
        s.recv(4096)
    except (socket.timeout, ssl.SSLError):
        pass
    sess = s.session
    s.close()
    s2 = tls_connect(c.port, session=sess, ctx=ctx)
    reused = s2.session_reused
    s2.close()
    return P(bool(reused), f"session_reused={reused}")


# ── runner ────────────────────────────────────────────────────────────────────────

def run_all(rig, probe, only=None):
    results = {}
    for name, port in (("zion", ZION_HTTPS), ("nginx", NGX_HTTPS)):
        rig.start_target(name)
        c = Ctx(name, port, probe)
        for ck in CHECKS:
            if only and ck["group"].lower() not in only and ck["id"] not in only:
                continue
            time.sleep(0.5)          # let the last check's stragglers reach the origin,
            c.reset()                # then forget them: a check sees only its own requests
            try:
                verdict, detail = ck["fn"](c)
            except Exception as e:      # a check that cannot run says so; it never passes silently
                verdict, detail = "n/a", f"{type(e).__name__}: {e}"
            results.setdefault(ck["id"], dict({k: ck[k] for k in ("group", "rfc", "level", "title")}, results={}))["results"][name] = dict(verdict=verdict, detail=detail)
        rig.stop(name)
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--zion", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--work", type=Path, default=Path("/dev/shm/zion-report-conf"))
    ap.add_argument("--only", default="", help="comma-separated group names or check ids")
    a = ap.parse_args()
    bench.ensure_ports_free()
    probe = ProbeOrigin(PROBE_PORT, PROBE_ADMIN_PORT)
    probe.start()
    rig = bench.Rig(a.zion.resolve(), a.work)
    rig.prepare(conformance=True)
    rig.start()
    try:
        res = run_all(rig, probe, {x.strip().lower() for x in a.only.split(",") if x.strip()})
    finally:
        rig.stop_all()
        probe.stop()
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "conformance.json").write_text(json.dumps(dict(schema=1, zion_version=bench.sh(a.zion, "--version").stdout.strip(),
                                                           checks=res), indent=1, sort_keys=True) + "\n")
    for cid, r in res.items():
        z, n = r["results"].get("zion", {}), r["results"].get("nginx", {})
        mark = lambda v: {"pass": "ok ", "fail": "FAIL", "info": "info", "n/a": "n/a"}[v["verdict"]]  # noqa: E731
        print(f"{cid:18s} {r['level']:8s} zion {mark(z):4s} nginx {mark(n):4s}  {z.get('detail', '')}", file=sys.stderr)


if __name__ == "__main__":
    main()
