#!/usr/bin/env python3
"""The conformance legs that use other people's tools, and the byte-exact crawl.

    external.py --zion BIN --out DIR [--only h2spec,cachetests,crawl]

h2spec            HTTP/2 against RFC 9113 and RFC 7541, zion and nginx.
cache-tests       Mark Nottingham's HTTP cache behaviour survey (RFC 9111), a reverse proxy in
                  front of its own test origin, zion and nginx. It calls itself "not a
                  conformance test suite"; the report says so too.
crawl             every file of the example site fetched twice through each proxy and compared
                  by SHA-256 with the manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import bench
from bench import NGX_HTTPS, TOOLS, ZION_HTTPS, pin

CT_PORT = 8000


def kill_tree(p) -> None:
    for pid in bench.tree_pids(p.pid):
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    p.wait()
    time.sleep(0.3)


def parse_junit(xml: Path):
    """h2spec's JUnit: the test's description is the testcase's `classname`, its spec section the
    `package`, and a failure is an <error> (or <failure>) whose text says what the server did."""
    tests = passed = failed = skipped = 0
    failures = []
    for tc in ET.parse(xml).getroot().iter("testcase"):
        tests += 1
        bad = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
        if tc.find("skipped") is not None:
            skipped += 1
        elif bad is not None:
            failed += 1
            why = next((ln.strip() for ln in ((bad.text or "") + "\n" + (bad.get("message") or "")).splitlines() if ln.strip()), "")
            failures.append(f"[{tc.get('package')}] {tc.get('classname')}" + (f" — {why[:110]}" if why else ""))
        else:
            passed += 1
    return tests, passed, failed, skipped, failures


def run_h2spec(rig, out: Path) -> dict:
    res = {}
    for name, port in (("zion", ZION_HTTPS), ("nginx", NGX_HTTPS)):
        proc = None
        if name == "zion":
            # h2spec 2.6.0 is built with a Go that cannot speak TLS 1.3, and zion's default floor is
            # 1.3: for this leg only, zion's floor is 1.2 (what the production profile also sets).
            conf = rig.d / "zion-h2spec.toml"
            conf.write_text((rig.d / "zion.toml").read_text().replace("hot_reload = false", 'hot_reload = false\nmin_version = "1.2"', 1))
            proc = subprocess.Popen(pin(bench.SERVER_CPU) + [str(rig.zion)], env=dict(os.environ, ZION_CONFIG=str(conf), ZION_BOOT_FAST="1"),
                                    stdout=subprocess.DEVNULL, stderr=(rig.d / "zion-h2spec.log").open("wb"))
            bench.wait_port(port, "zion")
            time.sleep(0.5)
        else:
            rig.start_target(name)
        xml = out / f"h2spec-{name}.xml"
        subprocess.run(pin(bench.LOAD_CPUS) + [str(TOOLS / "bin" / "h2spec"), "-t", "-k", "-h", "127.0.0.1", "-p", str(port),
                                               "--junit-report", str(xml)], capture_output=True, text=True, timeout=600)
        if proc:
            kill_tree(proc)
        else:
            rig.stop(name)
        if not xml.exists():
            res[name] = None
            continue
        tests, passed, failed, skipped, failures = parse_junit(xml)
        res[name] = dict(tests=tests, passed=passed, failed=failed, skipped=skipped, failures=failures)
    return res


def wait_http(port: int, secs: float = 15.0) -> None:
    end = time.time() + secs
    while time.time() < end:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            c.request("GET", "/")
            c.getresponse().read()
            return
        except OSError:
            time.sleep(0.2)
    sys.exit(f"cache-tests server did not come up on {CT_PORT}")


CT_ZION = """\
[server]
listen_http = "127.0.0.1:{http}"
listen_https = "127.0.0.1:{https}"
[tls]
cert_path = "{d}/tls.crt"
key_path = "{d}/tls.key"
hot_reload = false
[access_log]
enabled = false
[upstreams]
ct = "http://127.0.0.1:{ct}"
[cache_profile.ct]
mode = "memory"
max_entries = 10000
ttl_seconds = 3600
[[route]]
path = "/{{*rest}}"
upstream = "ct"
mode = "static_cache"
cache_profile = "ct"
waf = false
"""
CT_NGINX = """\
worker_processes 1; daemon off; pid {d}/ct-nginx.pid; error_log {d}/ct-nginx.err warn;
events {{ worker_connections 1024; }}
http {{
  access_log off; client_body_temp_path {d}/tmp/cb; proxy_temp_path {d}/tmp/cp; fastcgi_temp_path {d}/tmp/cf;
  uwsgi_temp_path {d}/tmp/cu; scgi_temp_path {d}/tmp/cs;
  proxy_cache_path {d}/ctcache levels=1:2 keys_zone=ct:10m max_size=256m inactive=1h;
  server {{
    listen 127.0.0.1:{port} ssl http2;
    ssl_certificate {d}/tls.crt; ssl_certificate_key {d}/tls.key;
    location / {{ proxy_pass http://127.0.0.1:{ct}; proxy_http_version 1.1; proxy_set_header Connection ""; proxy_cache ct; }}
  }}
}}
"""


def run_cache_tests(rig, out: Path) -> dict:
    d = rig.d
    (d / "ct-zion.toml").write_text(CT_ZION.format(http=bench.ZION_HTTP, https=ZION_HTTPS, d=d, ct=CT_PORT))
    (d / "ct-nginx.conf").write_text(CT_NGINX.format(d=d, port=NGX_HTTPS, ct=CT_PORT))
    ctdir = TOOLS / "cache-tests"
    res = {}
    for name, port in (("zion", ZION_HTTPS), ("nginx", NGX_HTTPS)):
        # The test server remembers the ids it has configured, so each target gets a fresh one.
        server = subprocess.Popen(["node", "--no-warnings", "test-engine/server/server.mjs"], cwd=ctdir,
                                  stdout=(d / "ct-server.log").open("wb"), stderr=subprocess.STDOUT,
                                  env=dict(os.environ, npm_package_config_port=str(CT_PORT), npm_package_config_protocol="http",
                                           npm_package_config_pidfile=str(d / "ct.pid")))
        p = None
        try:
            wait_http(CT_PORT)
            if name == "zion":
                p = subprocess.Popen(pin(bench.SERVER_CPU) + [str(rig.zion)], env=dict(os.environ, ZION_CONFIG=str(d / "ct-zion.toml"), ZION_BOOT_FAST="1"),
                                     stdout=subprocess.DEVNULL, stderr=(d / "ct-zion.log").open("wb"))
            else:
                p = subprocess.Popen(pin(bench.SERVER_CPU) + ["nginx", "-e", str(d / "ct-nginx.err"), "-p", str(d), "-c", str(d / "ct-nginx.conf")],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            bench.wait_port(port, name)
            time.sleep(0.5)
            env = dict(os.environ, NODE_TLS_REJECT_UNAUTHORIZED="0", npm_config_base=f"https://127.0.0.1:{port}",
                       npm_config_id="", npm_package_config_base="", npm_package_config_id="")
            r = subprocess.run(["node", "--no-warnings", "test-engine/cli.mjs"], cwd=ctdir, env=env, capture_output=True,
                               text=True, timeout=1200)
            raw = r.stdout[r.stdout.index("\n{") + 1:] if "\n{" in r.stdout else r.stdout
            (out / f"cachetests-{name}.json").write_text(raw)
            sm = subprocess.run(["node", str(bench.HERE / "ct-summary.mjs"), str(ctdir), str(out / f"cachetests-{name}.json")],
                                capture_output=True, text=True, check=True)
            j = json.loads(sm.stdout)
            res[name] = dict(tests=j["tests"], passed=j["passed"], failed=j["failed_count"], outcomes=j["outcomes"],
                             suites=j["suites"], failed_ids=j["failed"][:80])
        finally:
            if p:
                kill_tree(p)
            server.kill()
            server.wait()
    return res


def crawl(rig, manifest: list[dict]) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    out = {}
    for name, port in (("zion", ZION_HTTPS), ("nginx", NGX_HTTPS)):
        rig.start_target(name)
        bad, n = [], 0
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
        for m in manifest:
            path = "/nc" + m["path"] if m["path"].startswith("/download/") else m["path"]
            for rnd in ("cold", "warm"):
                n += 1
                try:
                    c.request("GET", path, headers={"Host": "localhost"})
                    r = c.getresponse()
                    body = r.read()
                except (OSError, http.client.HTTPException) as e:
                    bad.append(f"{m['path']} ({rnd}): {type(e).__name__}")
                    c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=15)
                    continue
                if r.status != 200 or hashlib.sha256(body).hexdigest() != m["sha256"] or len(body) != m["bytes"]:
                    bad.append(f"{m['path']} ({rnd}): status {r.status}, {len(body)} bytes")
            time.sleep(0)
        rig.stop(name)
        out[name] = dict(files=len(manifest), requests=n, mismatches=len(bad), mismatch_paths=bad[:20])
    z = out["zion"]
    return dict(files=z["files"], mismatches=z["mismatches"], mismatch_paths=z["mismatch_paths"], nginx_mismatches=out["nginx"]["mismatches"])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--zion", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--work", type=Path, default=Path("/dev/shm/zion-report-ext"))
    ap.add_argument("--only", default="h2spec,cachetests,crawl")
    a = ap.parse_args()
    only = set(a.only.split(","))
    bench.ensure_ports_free()
    rig = bench.Rig(a.zion.resolve(), a.work)
    rig.prepare()
    manifest = json.loads((rig.site / "manifest.json").read_text())["files"]
    rig.start()
    a.out.mkdir(parents=True, exist_ok=True)
    try:
        if "crawl" in only:
            (a.out / "crawl.json").write_text(json.dumps(crawl(rig, manifest), indent=1) + "\n")
        if "h2spec" in only:
            (a.out / "h2spec.json").write_text(json.dumps(run_h2spec(rig, a.out), indent=1, sort_keys=True) + "\n")
        if "cachetests" in only:
            (a.out / "cachetests.json").write_text(json.dumps(run_cache_tests(rig, a.out), indent=1, sort_keys=True) + "\n")
    finally:
        rig.stop_all()


if __name__ == "__main__":
    main()
