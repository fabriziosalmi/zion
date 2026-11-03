#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CVE lab runner (#699): real stacks behind real zion, one request-shape probe per CVE.

    python3 tests/lab/run.py STACK --zion-bin target/release/zion [--out DIR] [--no-compose]

For each probe of `tests/lab/stacks/STACK/probes.toml` four observations are made, and the
probe counts as covered only if all four came out as expected:

  baseline        the request WITHOUT the vector, straight to the vulnerable variant:
                  the oracle must say "not vulnerable" (the stack does protect the resource)
  vulnerable      the request WITH the vector, straight to the vulnerable variant:
                  the oracle must say "vulnerable" (the vector works on this version)
  fixed           the same request, straight to the patched variant:
                  the oracle must say "not vulnerable" (the oracle tells the versions apart)
  zion            the same request through zion in front of the vulnerable variant:
                  the oracle must say "not vulnerable" (zion neutralizes it)

If the vector works through zion the verdict is `bypass` and the run fails. If the vector does
not work on the vulnerable variant (or the baseline already looks vulnerable) the verdict is
`inconclusive`: such a probe proves nothing and is not counted as coverage.

A `[[benign]]` session (normal use of the stack) runs through zion and straight to the stack;
a step that passes straight and fails through zion is a false positive and fails the run.

Stdlib only; Python 3.11 or later (tomllib). Probes are request SHAPES from public advisories,
not exploits: each one names the advisory it comes from.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_VERSION = 1


# ── raw HTTP/1.1 ─────────────────────────────────────────────────────────────
# http.client normalizes what a probe must be able to send verbatim (duplicate headers, odd
# targets), so the request is built by hand, one connection per request.


def build_request(req: dict, host_header: str) -> bytes:
    method = req.get("method", "GET")
    target = req.get("target", "/")
    headers = [(str(k), str(v)) for k, v in req.get("headers", [])]
    body = req.get("body", "").encode()
    names = {k.lower() for k, _ in headers}
    lines = [f"{method} {target} HTTP/1.1"]
    if "host" not in names:
        lines.append(f"Host: {host_header}")
    lines += [f"{k}: {v}" for k, v in headers]
    if body and "content-length" not in names:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def _dechunk(raw: bytes) -> bytes:
    """Decode a chunked body. Raises ValueError if the 0-size terminator chunk is never
    reached — an incomplete chunked body must not be returned as if it were the whole thing:
    `judge()` would then compare a partial, truncated body against the oracle."""
    out, i = b"", 0
    while True:
        eol = raw.find(b"\r\n", i)
        if eol < 0:
            raise ValueError("chunked body ends mid-chunk-header: incomplete response")
        size = int(raw[i:eol].split(b";")[0] or b"0", 16)
        if size == 0:
            return out
        chunk_end = eol + 2 + size
        if len(raw) < chunk_end + 2:
            raise ValueError("chunked body ends mid-chunk: incomplete response")
        out += raw[eol + 2 : chunk_end]
        i = chunk_end + 2


def parse_response(raw: bytes) -> dict:
    """Raises ValueError on a response that is not actually complete (truncated by a reset,
    a timeout, or a server that closed early): `observe()` must see this as a connection
    error, not as a 200 with a shorter-than-declared or otherwise wrong body that could
    accidentally satisfy (or fail to satisfy) the oracle."""
    head, _, body = raw.partition(b"\r\n\r\n")
    if not _:
        raise ValueError(f"no header/body separator in {raw[:80]!r}: incomplete response")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise ValueError(f"no status line in {raw[:80]!r}")
    headers = [tuple(line.split(":", 1)) for line in lines[1:] if ":" in line]
    headers = [(k.strip().lower(), v.strip()) for k, v in headers]
    is_chunked = any(k == "transfer-encoding" and "chunked" in v.lower() for k, v in headers)
    if is_chunked:
        body = _dechunk(body)  # raises on an incomplete chunked body
    else:
        declared = next((v for k, v in headers if k == "content-length"), None)
        if declared is not None:
            want = int(declared)
            if len(body) < want:
                raise ValueError(f"body is {len(body)} bytes, Content-Length declared {want}: incomplete response")
            body = body[:want]  # a pipelined/trailing byte past a non-close connection would stay here otherwise
    return {"status": status, "headers": headers, "body": body.decode("utf-8", "replace")}


def send(addr: tuple[str, int], tls: bool, req: dict, timeout: float = 15.0, ca: Path | None = None) -> dict:
    """One request on a fresh connection. With `tls`, `ca` is the one certificate trusted: the
    throwaway one the runner made for its own zion, verified against the name `localhost`."""
    data = build_request(req, f"{addr[0]}:{addr[1]}")
    sock = socket.create_connection(addr, timeout=timeout)
    try:
        if tls:
            ctx = ssl.create_default_context(cafile=str(ca))
            sock = ctx.wrap_socket(sock, server_hostname="localhost")
        sock.sendall(data)
        raw = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (ssl.SSLError, ConnectionResetError):
                break
            if not chunk:
                break
            raw += chunk
    finally:
        sock.close()
    return parse_response(raw)


# ── oracle ───────────────────────────────────────────────────────────────────


def matches(resp: dict, cond: dict) -> bool:
    """True when every condition present holds. `status` is an int or a list of ints."""
    if "status" in cond:
        want = cond["status"] if isinstance(cond["status"], list) else [cond["status"]]
        if resp["status"] not in want:
            return False
    if "body_contains" in cond and cond["body_contains"] not in resp["body"]:
        return False
    if "body_not_contains" in cond and cond["body_not_contains"] in resp["body"]:
        return False
    if "header_present" in cond and not any(k == cond["header_present"].lower() for k, _ in resp["headers"]):
        return False
    return True


def observe(label: str, addr, tls: bool, req: dict, vulnerable_if: dict, ca: Path | None = None) -> dict:
    try:
        resp = send(addr, tls, req, ca=ca)
    except (OSError, ValueError) as e:
        return {"at": label, "error": f"{type(e).__name__}: {e}", "vulnerable": None}
    return {
        "at": label,
        "status": resp["status"],
        "body_sha256_12": hashlib.sha256(resp["body"].encode()).hexdigest()[:12],
        "vulnerable": matches(resp, vulnerable_if),
    }


def judge(obs: dict[str, dict]) -> tuple[str, str]:
    """(verdict, why). `bypass` wins over everything, checked FIRST: a confirmed bypass
    through zion must stay a `bypass` even if another observation (baseline/vulnerable/fixed)
    happened to error out -- a demonstrated hole is never allowed to hide behind an unrelated
    connection problem reported as `error` instead."""
    if obs["zion"].get("vulnerable") is True:
        return "bypass", "the vector works through zion"
    if any(o.get("vulnerable") is None for o in obs.values()):
        bad = [k for k, o in obs.items() if o.get("vulnerable") is None]
        return "error", f"no answer at: {', '.join(bad)}"
    problems = []
    if obs["baseline"]["vulnerable"]:
        problems.append("the baseline (no vector) already looks vulnerable: the oracle or the stack is wrong")
    if not obs["vulnerable"]["vulnerable"]:
        problems.append("the vector does not work on the vulnerable variant: nothing to neutralize")
    if obs["fixed"]["vulnerable"]:
        problems.append("the vector also works on the patched variant: the oracle cannot tell versions apart")
    if problems:
        return "inconclusive", "; ".join(problems)
    return "covered", "the vector works on the vulnerable version and not on the patched one nor through zion"


def strip_vector(req: dict, baseline: dict) -> dict:
    """The request without the vector: `baseline` overrides the fields that differ."""
    return {**req, **baseline}


def validate_probes(probes: dict) -> None:
    """Every probe MUST declare `[probe.baseline]`. There is no generic way for this runner
    to know which part of a request IS "the vector" (a header, a cookie, a path segment, a
    body field) — only the probe's own author does. Without an explicit baseline, an earlier
    version of this runner silently fell back to the UNCHANGED request (vector still present),
    which makes the baseline observation meaningless and can turn a real bypass into a false
    `inconclusive` instead of the `bypass` it should be. Fail at load time, loudly, rather than
    report a wrong verdict."""
    # Presence, not truthiness: an explicit but empty `[probe.baseline]` parses to `{}`,
    # which is falsy in Python even though the author did declare it.
    missing = [p["id"] for p in probes.get("probe", []) if "baseline" not in p]
    if missing:
        raise ValueError(
            f"probe(s) {missing} have no [probe.baseline]: every probe must state what the "
            "request without its vector looks like (e.g. `[probe.baseline]\\nheaders = []`)"
        )


# ── lifecycle ────────────────────────────────────────────────────────────────


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(addr, tls: bool, path: str, seconds: float, ok=(200, 301, 302, 401, 404), ca: Path | None = None) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if send(addr, tls, {"target": path}, timeout=3, ca=ca)["status"] in ok:
                return True
        except (OSError, ValueError):
            pass
        time.sleep(0.5)
    return False


class Zion:
    """A real zion process in front of one upstream, on a throwaway certificate."""

    def __init__(self, binary: Path, upstream: str, extra: str = ""):
        self.dir = Path(tempfile.mkdtemp(prefix="zion-lab-"))
        self.http, self.https = free_port(), free_port()
        key, crt = self.dir / "tls.key", self.dir / "tls.crt"
        self.ca = crt
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
             "-keyout", str(key), "-out", str(crt)],
            check=True, stderr=subprocess.DEVNULL)
        cfg = self.dir / "zion.toml"
        cfg.write_text(
            f'[server]\nlisten_http = "127.0.0.1:{self.http}"\nlisten_https = "127.0.0.1:{self.https}"\n'
            f'{extra}\n[tls]\ncert_path = "{crt}"\nkey_path = "{key}"\nhot_reload = false\n'
            f'[upstreams]\nstack = "{upstream}"\n[[route]]\npath = "/{{*rest}}"\nupstream = "stack"\n')
        self.log_path = self.dir / "zion.log"
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [str(binary)], env={**os.environ, "ZION_CONFIG": str(cfg), "ZION_BOOT_FAST": "1",
                                "ZION_LAST_GASP_PATH": str(self.dir / "gasp.jsonl")},
            stdout=subprocess.DEVNULL, stderr=self.log)
        if not wait_for(("127.0.0.1", self.https), True, "/healthz", 30, ca=self.ca):
            # Read the log BEFORE stop(), which deletes self.dir: reading it afterwards would
            # raise FileNotFoundError and lose the one diagnostic that explains the failure
            # (a bad config, a port already bound, a crash on startup).
            self.log.flush()
            tail = self.log_path.read_text()[-600:] if self.log_path.exists() else "(no log file)"
            self.stop()
            raise RuntimeError(f"zion did not come up; log: {tail}")

    @property
    def addr(self):
        return ("127.0.0.1", self.https)

    def version(self, binary: Path) -> str:
        out = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
        return (out.stdout or out.stderr).strip()

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.log.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def compose(stack_dir: Path, project: str, *args: str, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-p", project, "-f", str(stack_dir / "compose.yml"), *args],
        check=check, capture_output=True, text=True)


def addr_of(url: str) -> tuple[str, int]:
    host, _, port = url.removeprefix("http://").partition(":")
    return host, int(port)


# ── one stack ────────────────────────────────────────────────────────────────


def run_stack(name: str, zion_bin: Path, out_dir: Path, use_compose: bool, stacks_dir: Path = HERE / "stacks") -> int:
    stack_dir = stacks_dir / name
    meta = tomllib.loads((stack_dir / "stack.toml").read_text())
    probes = tomllib.loads((stack_dir / "probes.toml").read_text())
    validate_probes(probes)
    variants = {v["name"]: v for v in meta["variant"]}
    project = f"zlab-{name}"
    images: dict = {}
    versions: dict = {}

    try:
        if use_compose:
            print(f"[{name}] building and starting the stack", flush=True)
            # Inside the try: a failed/unhealthy `up --wait` (check=True raises) must still
            # reach the `finally` below, or containers are left running and holding ports and
            # memory with no KEEP set and nothing telling the operator they are still up.
            compose(stack_dir, project, "up", "-d", "--build", "--wait", "--wait-timeout", "300")
        for vname, v in variants.items():
            if not wait_for(addr_of(v["upstream"]), False, meta["stack"].get("ready_path", "/"), 120):
                raise RuntimeError(f"variant {vname} did not answer at {v['upstream']}")
            if use_compose and v.get("service"):
                cid = compose(stack_dir, project, "ps", "-q", v["service"]).stdout.strip()
                images[vname] = subprocess.run(
                    ["docker", "inspect", "--format", "{{.Image}}", cid], capture_output=True, text=True).stdout.strip()
                if v.get("version_cmd"):
                    versions[vname] = compose(stack_dir, project, "exec", "-T", v["service"], *v["version_cmd"],
                                              check=False).stdout.strip()
            versions.setdefault(vname, v.get("version", "unknown"))

        guarded = variants[meta["stack"]["guarded_variant"]]
        # `{stack_dir}` in server_extra expands to this stack's own absolute directory, so a
        # stack can point zion at a file that lives beside it (e.g. a virtual-patch rules_file,
        # #698) without baking a checkout-specific absolute path into the committed stack.toml
        # (zion itself resolves a *relative* rules_file against zion.toml's directory, a throwaway
        # tmpdir this runner invents per run, not the stack's own directory -- see docs/config).
        server_extra = meta.get("zion", {}).get("server_extra", "").replace("{stack_dir}", str(stack_dir.resolve()))
        zion = Zion(zion_bin, guarded["upstream"], server_extra)
        try:
            return finish(name, meta, probes, variants, guarded, zion, zion_bin, images, versions, out_dir)
        finally:
            zion.stop()
    finally:
        if use_compose and not os.environ.get("KEEP"):
            compose(stack_dir, project, "down", "-v", "--remove-orphans", check=False)


def finish(name, meta, probes, variants, guarded, zion, zion_bin, images, versions, out_dir) -> int:
    vuln_addr = addr_of(guarded["upstream"])
    fixed_addr = addr_of(variants[meta["stack"]["fixed_variant"]]["upstream"])
    results = []
    for p in probes.get("probe", []):
        req, cond = p["request"], p["oracle"]["vulnerable_if"]
        obs = {
            "baseline": observe("vulnerable variant, no vector", vuln_addr, False, strip_vector(req, p.get("baseline")), cond),
            "vulnerable": observe("vulnerable variant", vuln_addr, False, req, cond),
            "fixed": observe("patched variant", fixed_addr, False, req, cond),
            "zion": observe("through zion", zion.addr, True, req, cond, zion.ca),
        }
        verdict, why = judge(obs)
        results.append({
            "id": p["id"], "cve": p["cve"], "advisory": p["advisory"], "affects": p["affects"],
            "mechanism": p.get("mechanism", ""),
            # Whether a human has confirmed the `mechanism` text by a break-test (disable the
            # named defense, see the probe flip from `covered` to `bypass`) rather than only
            # by reading the code. The probe itself declares it; this runner cannot infer it
            # generically -- `covered` only says SOMETHING in the path stopped the vector, not
            # that it was the specific mechanism named in prose.
            "mechanism_verified": p.get("mechanism_verified", False),
            "observations": obs, "verdict": verdict, "why": why,
        })
        print(f"[{name}] {p['id']}: {verdict}  ({why})", flush=True)

    benign = []
    for b in probes.get("benign", []):
        direct = observe("direct", vuln_addr, False, b["request"], b["expect"])
        via = observe("through zion", zion.addr, True, b["request"], b["expect"], zion.ca)
        # for a benign step the oracle is "expected", so `vulnerable` reads as "as expected"
        ok_direct, ok_zion = direct.get("vulnerable"), via.get("vulnerable")
        if ok_direct is None or ok_zion is None:
            outcome = "error"  # a connection failed outright; neither "false_positive" nor
            # "broken_step" would be an honest label for that
        elif ok_direct and ok_zion:
            outcome = "ok"
        elif ok_direct and not ok_zion:
            outcome = "false_positive"
        else:
            outcome = "broken_step"  # not even the direct request behaved as expected
        benign.append({"id": b["id"], "direct": direct, "zion": via, "outcome": outcome})
        print(f"[{name}] benign {b['id']}: {outcome}", flush=True)

    count = lambda xs, key, val: sum(1 for x in xs if x[key] == val)
    summary = {
        "probes": len(results),
        "covered": count(results, "verdict", "covered"),
        "inconclusive": count(results, "verdict", "inconclusive"),
        "bypass": count(results, "verdict", "bypass"),
        "error": count(results, "verdict", "error"),
        "benign_steps": len(benign),
        "false_positives": count(benign, "outcome", "false_positive"),
        "broken_steps": count(benign, "outcome", "broken_step"),
        "benign_errors": count(benign, "outcome", "error"),
    }
    doc = {
        "schema_version": SCHEMA_VERSION,
        "stack": name,
        "ran_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "zion": zion.version(zion_bin),
        "variants": {k: {"version": versions.get(k), "image": images.get(k)} for k in variants},
        "summary": summary,
        "probes": results,
        "benign": benign,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.json").write_text(json.dumps(doc, indent=2) + "\n")
    print(f"[{name}] {summary}", flush=True)
    failed = (summary["bypass"] or summary["error"] or summary["false_positives"]
              or summary["broken_steps"] or summary["benign_errors"])
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stack")
    ap.add_argument("--zion-bin", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=HERE / "results")
    ap.add_argument("--no-compose", action="store_true", help="the variants are already running")
    ap.add_argument(
        "--stacks-dir", type=Path, default=HERE / "stacks",
        help="where the stack definitions are (tests use a temporary one)",
    )
    ap.add_argument("--strict", action="store_true", help="an inconclusive probe also fails the run")
    a = ap.parse_args()
    if not a.zion_bin.exists():
        print(f"no zion binary at {a.zion_bin}", file=sys.stderr)
        return 2
    rc = run_stack(a.stack, a.zion_bin.resolve(), a.out, not a.no_compose, a.stacks_dir)
    if a.strict and rc == 0:
        doc = json.loads((a.out / f"{a.stack}.json").read_text())
        if doc["summary"]["inconclusive"]:
            return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
