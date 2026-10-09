#!/usr/bin/env python3
"""Measure one zion binary the way the release report describes, and write result.json.

    bench.py --zion BIN --out DIR [--label v0.11.0] [--quick] [--only a,b]

What a run is: an example site (gen_site.py, fixed seed) served by a real nginx origin;
zion in front of it; a real nginx proxy_cache in front of the same origin as a
reference; and the same site read directly from the origin as the floor. Each scenario
is driven by wrk (HTTP/1.1), h2load (HTTP/2) or oha (fixed arrival rate, corrected for
coordinated omission) and repeated in trials. Trials are interleaved across the targets
(zion, nginx, origin, zion, nginx, origin, ...) so a slow drift of the host lands on all
of them alike instead of on whoever ran last.

Determinism, said exactly: the bytes served, the request sequence, the tool versions,
the core layout and the order of every step are fixed and recorded. The numbers are not
bit-identical from one run to the next, because a CPU is not; what is fixed is the size
of the noise. Every scenario reports a median over trials with its spread, a canary
(a fixed CPU workload) brackets the run to show whether the host itself moved, and a run
whose canary drifts more than CANARY_TOLERANCE is marked noisy instead of being trusted.

Core layout (4 CPUs, the ci-zion LXC): origin 0, server under test 1, load generators 2-3.
Every proxy under test gets exactly one core, so req/s is per core and nginx
(worker_processes 1) is compared on equal terms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "regress"))
from run import CLK_TCK, cpu_ticks, mad, parse_h2load, vm_hwm_mib, wait_port  # noqa: E402

import gen_site  # noqa: E402

TOOLS = Path(os.environ.get("TOOLS", "/opt/zion-bench"))
ORIGIN_CPU, SERVER_CPU, LOAD_CPUS = "0", "1", "2,3"
ZION_HTTPS, ZION_HTTP, NGX_HTTPS, ORIGIN_PORT = 14432, 14480, 14433, 14490
PROCEDURE = 2                    # bump when scenarios, parameters or layout change: reports of different procedures do not compare
CANARY_TOLERANCE = 0.03
IDLE_MIN_PCT = 97.0              # the host must be this idle for 5 s before anything is timed
VARIANTS: dict = {}               # --variants name=path,...: several zion builds as interleaved targets
NGX_WORKERS = 1                  # follows the number of server cores (--server-cpus)
SERVER_BOUND_MIN_PCT = 80.0     # below this the load generator was the limit

TARGETS = {
    "zion": dict(base=f"https://127.0.0.1:{ZION_HTTPS}"),
    "nginx": dict(base=f"https://127.0.0.1:{NGX_HTTPS}"),
    "origin": dict(base=f"http://127.0.0.1:{ORIGIN_PORT}"),
}
ALL, PROXIES = ["zion", "nginx", "origin"], ["zion", "nginx"]

# One small cacheable document, one ~200 KB image: chosen from the manifest at start.
SMALL, IMAGE = "/api/item-042.json", None
SCENARIOS = {
    "cache_hit_small": dict(tool="wrk", conns=64, targets=ALL, cache=True,
                            what="GET a 5 KB cached JSON document, TLS, HTTP/1.1, 64 keep-alive connections"),
    "cache_hit_doc": dict(tool="wrk", conns=64, targets=ALL, cache=True, path="/docs/page-07.html",
                          what="GET a 28 KB cached HTML page: the same bytes as static_files, from the cache"),
    "cache_hit_h2": dict(tool="h2load", conns=16, streams=10, targets=PROXIES, cache=True,
                         what="the same document over HTTP/2, 16 connections x 10 streams"),
    "cache_hit_image": dict(tool="wrk", conns=64, targets=ALL, cache=True, image=True,
                            what="GET a ~200 KB cached image: copy and TLS cost, not request cost"),
    "site_mix": dict(tool="wrk", conns=64, targets=ALL, cache=True, mix=True,
                     what="the whole example site, Zipf-popular paths, hot cache"),
    "proxy_nocache": dict(tool="wrk", conns=64, targets=ALL, path="/nc" + SMALL,
                          what="no cache: every request goes to the origin (origin: no-store)"),
    "static_files": dict(tool="wrk", conns=64, targets=ALL, path="/static/docs/page-07.html",
                         what="zion `static` mode and nginx `alias` serving the files from disk"),
    "tls_handshake": dict(tool="wrk", conns=64, targets=PROXIES, close=True, cache=True,
                          what="Connection: close, so every request is a new TLS handshake"),
    "download_10m": dict(tool="wrk", conns=8, targets=ALL, path="/nc/download/archive-10m.bin",
                         what="a 10 MiB body streamed through the proxy, 8 connections"),
}
for _r in (5000, 15000):
    SCENARIOS[f"latency_{_r // 1000}k"] = dict(
        tool="oha", conns=50, rate=_r, targets=ALL, cache=True,
        what=f"a fixed {_r} req/s on the cached document, latency corrected for coordinated omission")
SCENARIOS["cache_hit_small_logs"] = dict(SCENARIOS["cache_hit_small"], logs=True, targets=PROXIES,
    what="cache_hit_small with the access log on in both: zion's default, nginx's combined format")
SCENARIOS["site_mix_logs"] = dict(SCENARIOS["site_mix"], logs=True, targets=PROXIES,
    what="site_mix with the access log on in both")
for _c in (1, 8, 256, 1024):
    SCENARIOS[f"sweep_c{_c}"] = dict(tool="wrk", conns=_c, targets=PROXIES, cache=True,
                                     what=f"the cached document at {_c} connections")


def sh(*cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(list(map(str, cmd)), check=True, capture_output=True, text=True, **kw)


def pin(cpus: str) -> list[str]:
    return ["taskset", "-c", cpus]


def raise_nofile() -> None:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536), hard))


def tree_pids(root: int) -> list[int]:
    """root and all its descendants (nginx does its work in a worker, not the master)."""
    parent: dict[int, int] = {}
    for p in Path("/proc").iterdir():
        if p.name.isdigit():
            try:
                parent[int(p.name)] = int(p.joinpath("stat").read_text().rsplit(")", 1)[1].split()[1])
            except (OSError, IndexError, ValueError):
                pass
    out, todo = [], [root]
    while todo:
        pid = todo.pop()
        out.append(pid)
        todo += [c for c, pp in parent.items() if pp == pid]
    return out


def tree_ticks(root: int) -> int:
    t = 0
    for pid in tree_pids(root):
        try:
            t += cpu_ticks(pid)
        except OSError:
            pass
    return t


def tree_hwm(root: int) -> float:
    return sum(vm_hwm_mib(p) for p in tree_pids(root) if Path(f"/proc/{p}").exists())


# ── environment ────────────────────────────────────────────────────────────────

def canary(seconds: float = 2.0) -> float:
    """MB/s of SHA-256 on one pinned core: a fixed workload, so a change means the host moved."""
    code = ("import hashlib,time;b=bytes(1<<20);n=0;h=hashlib.sha256();t=time.perf_counter()\n"
            f"while time.perf_counter()-t<{seconds}:\n h.update(b);n+=1\n"
            "print(n/(time.perf_counter()-t))")
    return float(sh(*pin(SERVER_CPU), sys.executable, "-c", code).stdout)


def host_idle_pct(window: float) -> float:
    """Share of all CPU time spent idle (or in iowait) over `window` seconds, from /proc/stat."""
    def snap():
        f = [int(x) for x in read("/proc/stat").splitlines()[0].split()[1:]]
        return f[3] + f[4], sum(f)
    i0, t0 = snap()
    time.sleep(window)
    i1, t1 = snap()
    return 100.0 * (i1 - i0) / max(1, t1 - t0)


def read(p: str) -> str:
    try:
        return Path(p).read_text().strip()
    except OSError:
        return ""


def tls_probe(rig: "Rig") -> dict:
    """What each proxy actually negotiates with the load generators: a 'TLS-heavy' number is
    only comparable if both ends picked the same protocol and cipher."""
    out = {}
    for t, port in (("zion", ZION_HTTPS), ("nginx", NGX_HTTPS)):
        rig.start_target(t)
        r = subprocess.run(f"echo | openssl s_client -connect 127.0.0.1:{port} -brief 2>&1", shell=True,
                           capture_output=True, text=True).stdout
        pick = lambda k: next((ln.split(":", 1)[1].strip() for ln in r.splitlines() if ln.startswith(k)), "?")  # noqa: E731
        out[t] = dict(protocol=pick("Protocol version"), cipher=pick("Ciphersuite"), group=pick("Negotiated TLS1.3 group"))
        rig.stop(t)
    return out


def environment(zion: Path, label: str) -> dict:
    lock = read(str(TOOLS / "tools.lock"))
    cpu = next((ln.split(":", 1)[1].strip() for ln in read("/proc/cpuinfo").splitlines() if ln.startswith("model name")), "")
    mhz = [float(ln.split(":")[1]) for ln in read("/proc/cpuinfo").splitlines() if ln.startswith("cpu MHz")]
    st = read("/proc/stat").splitlines()[0].split()
    ver = sh(zion, "--version").stdout.strip()
    return dict(
        label=label, zion_version=ver, zion_sha256=hashlib.sha256(zion.read_bytes()).hexdigest(),
        date_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        cpu=cpu, cpus=os.cpu_count(), kernel=platform.release(), mem_mib=int(read("/proc/meminfo").split()[1]) // 1024,
        governor=read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        cpu_mhz_at_start=mhz, load_avg=os.getloadavg(), steal_ticks=int(st[8]) if len(st) > 8 else None,
        layout=dict(origin=ORIGIN_CPU, server=SERVER_CPU, load=LOAD_CPUS),
        tools=dict(ln.split("=", 1) for ln in lock.splitlines() if "=" in ln),
        somaxconn=read("/proc/sys/net/core/somaxconn"),
        ip_local_port_range=read("/proc/sys/net/ipv4/ip_local_port_range"),
    )


# ── the rig ────────────────────────────────────────────────────────────────────

ZION_CONF = """\
[server]
listen_http = "127.0.0.1:{http}"
listen_https = "127.0.0.1:{https}"

[tls]
cert_path = "{d}/tls.crt"
key_path = "{d}/tls.key"
hot_reload = false

[access_log]
enabled = {logs}

[upstreams]
origin = "http://127.0.0.1:{origin}"
{extra_upstreams}
[cache_profile.site]
mode = "memory"
max_entries = 10000
ttl_seconds = 3600

{routes}{extra_routes}[[route]]
path = "/nc/{{*rest}}"
upstream = "origin"
mode = "standard"
waf = false

[[route]]
path = "/static/{{*rest}}"
mode = "static"
serve_dir = "{site}"
"""
CACHED_PREFIXES = ["docs", "assets", "img", "fonts", "api"]
CACHED_EXACT = ["/index.html", "/favicon.ico", "/robots.txt"]

# Added only for the conformance run: a crafted-response origin and an origin that is down.
PROBE_PORT, PROBE_ADMIN_PORT, DEAD_PORT = 14491, 14492, 14499
CONF_UPSTREAMS = f'probe = "http://127.0.0.1:{PROBE_PORT}"\ndead = "http://127.0.0.1:{DEAD_PORT}"\n'
CONF_ROUTES = (
    '[[route]]\npath = "/p/{*rest}"\nupstream = "probe"\nmode = "standard"\nwaf = false\n\n'
    '[[route]]\npath = "/dead/{*rest}"\nupstream = "dead"\nmode = "standard"\nwaf = false\n\n')
CONF_NGINX = (
    f'    location /p/    {{ proxy_pass http://127.0.0.1:{PROBE_PORT}; proxy_http_version 1.1; proxy_set_header Connection ""; }}\n'
    f'    location /dead/ {{ proxy_pass http://127.0.0.1:{DEAD_PORT}; proxy_http_version 1.1; proxy_set_header Connection ""; }}\n')

ORIGIN_CONF = """\
worker_processes 1; daemon off; pid {d}/origin.pid; error_log {d}/origin.err warn;
events {{ worker_connections 8192; }}
http {{
  include /etc/nginx/mime.types; default_type application/octet-stream;
  access_log off; sendfile on; tcp_nopush on; keepalive_timeout 75; keepalive_requests 1000000;
  open_file_cache max=2000 inactive=60s; open_file_cache_valid 60s;
  client_body_temp_path {d}/tmp/ob; proxy_temp_path {d}/tmp/op; fastcgi_temp_path {d}/tmp/of;
  uwsgi_temp_path {d}/tmp/ou; scgi_temp_path {d}/tmp/os;
  server {{
    listen 127.0.0.1:{port} backlog=4096;
    root {site};
    location = /_status {{ stub_status; }}
    location /nc/     {{ alias {site}/; add_header Cache-Control "no-store" always; }}
    location /static/ {{ alias {site}/; add_header Cache-Control "public, max-age=3600"; }}
    location /        {{ add_header Cache-Control "public, max-age=3600"; }}
  }}
}}
"""
NGINX_CONF = """\
worker_processes {workers}; daemon off; pid {d}/nginx.pid; error_log {d}/nginx.err warn;
events {{ worker_connections 8192; }}
http {{
  include /etc/nginx/mime.types; default_type application/octet-stream;
  {access_log}; sendfile on; tcp_nopush on; keepalive_timeout 75; keepalive_requests 1000000;
  open_file_cache max=2000 inactive=60s; open_file_cache_valid 60s;
  client_body_temp_path {d}/tmp/nb; proxy_temp_path {d}/tmp/np; fastcgi_temp_path {d}/tmp/nf;
  uwsgi_temp_path {d}/tmp/nu; scgi_temp_path {d}/tmp/ns;
  proxy_cache_path {d}/ngxcache levels=1:2 keys_zone=z:20m max_size=512m inactive=1h;
  upstream origin {{ server 127.0.0.1:{origin}; keepalive 128; }}
  server {{
    listen 127.0.0.1:{port} ssl http2 backlog=4096;
    ssl_certificate {d}/tls.crt; ssl_certificate_key {d}/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_cache shared:S:10m;
    proxy_http_version 1.1; proxy_set_header Connection ""; proxy_set_header Host $host;
{extra_locations}    location /nc/     {{ proxy_pass http://origin; }}
    location /static/ {{ alias {site}/; add_header Cache-Control "public, max-age=3600"; }}
    location /        {{ proxy_pass http://origin; proxy_cache z; add_header X-Cache-Status $upstream_cache_status; }}
  }}
}}
"""


class Rig:
    def __init__(self, zion: Path, work: Path):
        self.zion, self.d, self.procs = zion, work, {}
        self.site = work / "site"

    def prepare(self, conformance: bool = False) -> str:
        d = self.d
        shutil.rmtree(d, ignore_errors=True)
        (d / "tmp").mkdir(parents=True)
        gen_site.build(self.site, gen_site.SEED)
        site_hash = hashlib.sha256((self.site / "manifest.json").read_bytes()).hexdigest()
        if conformance:
            (d / "secret.txt").write_text("TOPSECRET-CANARY\n")   # one level above the served directory
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
           "-days", "2", "-subj", "/CN=localhost", "-keyout", d / "tls.key", "-out", d / "tls.crt")
        routes = "".join(
            f'[[route]]\npath = "/{p}/{{*rest}}"\nupstream = "origin"\nmode = "static_cache"\n'
            'cache_profile = "site"\nwaf = false\n\n' for p in CACHED_PREFIXES)
        routes += "".join(
            f'[[route]]\npath = "{p}"\nupstream = "origin"\nmode = "static_cache"\n'
            'cache_profile = "site"\nwaf = false\n\n' for p in CACHED_EXACT)
        for suffix, on in (("", False), ("-logs", True)):
            (d / f"zion{suffix}.toml").write_text(ZION_CONF.format(
                http=ZION_HTTP, https=ZION_HTTPS, d=d, origin=ORIGIN_PORT, routes=routes, site=self.site,
                logs="true" if on else "false",
                extra_upstreams=CONF_UPSTREAMS if conformance else "", extra_routes=CONF_ROUTES if conformance else ""))
        (d / "origin.conf").write_text(ORIGIN_CONF.format(d=d, port=ORIGIN_PORT, site=self.site))
        for suffix, on in (("", False), ("-logs", True)):
            (d / f"nginx{suffix}.conf").write_text(NGINX_CONF.format(
                d=d, port=NGX_HTTPS, origin=ORIGIN_PORT, site=self.site,
                workers=NGX_WORKERS,
                access_log=f"access_log {d}/nginx-access.log" if on else "access_log off",
                extra_locations=CONF_NGINX if conformance else ""))
        return site_hash

    def _spawn(self, name: str, cpus: str, cmd: list, env=None) -> int:
        log = (self.d / f"{name}.log").open("wb")
        self.procs[name] = subprocess.Popen(pin(cpus) + list(map(str, cmd)), env=env or os.environ.copy(),
                                            stdout=log, stderr=log, preexec_fn=raise_nofile)
        return self.procs[name].pid

    def start(self) -> int:
        """The origin lives for the whole run, alone on its core. The proxies under test
        are started around their own trials, so only one of them is ever resident."""
        d = self.d
        pid = self._spawn("origin", ORIGIN_CPU, ["nginx", "-e", d / "origin.err", "-p", d, "-c", d / "origin.conf"])
        wait_port(ORIGIN_PORT, "origin")
        return pid

    def start_target(self, t: str, logs: bool = False) -> int:
        d = self.d
        sfx = "-logs" if logs else ""
        for f in ("zion.log", "nginx-access.log"):
            (d / f).write_bytes(b"")     # one trial never inherits the last one's log
        if t == "origin":
            return self.procs["origin"].pid
        if t == "nginx":
            pid = self._spawn("nginx", SERVER_CPU, ["nginx", "-e", d / "nginx.err", "-p", d, "-c", d / f"nginx{sfx}.conf"])
            wait_port(NGX_HTTPS, "nginx")
        else:
            refuse_if_listening(ZION_HTTPS, t)
            env = dict(os.environ, ZION_CONFIG=str(d / f"zion{sfx}.toml"), ZION_BOOT_FAST="1")
            pid = self._spawn("zion", SERVER_CPU, [VARIANTS.get(t, self.zion)], env=env)
            wait_port(ZION_HTTPS, "zion")
        time.sleep(0.5)
        return pid

    def stop(self, name: str) -> None:
        """Kill the whole process tree: killing only nginx's master leaves its workers
        alive, still listening, and answering the next scenario's requests."""
        p = self.procs.pop("zion" if name in VARIANTS else name, None)
        if p:
            for pid in tree_pids(p.pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            p.wait()
            time.sleep(0.2)

    def stop_all(self) -> None:
        for n in list(self.procs):
            self.stop(n)


def refuse_if_listening(port: int, who: str) -> None:
    """zion binds with SO_REUSEPORT, so a second instance on the same port starts without error and
    the kernel splits the connections between the two: the measured process then sees only a share
    of the traffic. A leftover from an earlier trial must stop the run, not hide in it."""
    import socket
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
    except OSError:
        return
    sys.exit(f"something already listens on port {port} before {who} was started (a process left behind?)")


def ensure_ports_free() -> None:
    import socket
    for port in (ZION_HTTPS, ZION_HTTP, NGX_HTTPS, ORIGIN_PORT):
        with socket.socket() as sk:
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sk.bind(("127.0.0.1", port))
            except OSError:
                sys.exit(f"port {port} is already in use: a previous run left a process behind; refusing to measure")


# ── drivers ────────────────────────────────────────────────────────────────────

def drive_wrk(url_base: str, sc: dict, paths: list[str], seconds: float, workdir: Path) -> dict:
    pf = workdir / "paths.txt"
    pf.write_text("\n".join(paths) + "\n")
    env = dict(os.environ, PATHS_FILE=str(pf), CLOSE="1" if sc.get("close") else "0")
    cmd = pin(LOAD_CPUS) + ["wrk", f"-t{min(2, sc['conns'])}", f"-c{sc['conns']}", f"-d{seconds:g}s", "--timeout", "5s",
                            "-s", str(HERE / "wrk.lua"), url_base]
    out = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=seconds + 60, preexec_fn=raise_nofile)
    m = re.search(r"^ZRES (\{.*\})$", out.stdout, re.M)
    if out.returncode != 0 or not m:
        raise RuntimeError(f"wrk failed ({out.returncode}): {out.stdout[-400:]} {out.stderr[-400:]}")
    r = json.loads(m.group(1))
    e = r["errors"]
    bad = sum(e.values())
    if bad:
        raise RuntimeError(f"invalid trial, errors {e}")
    secs = r["duration_us"] / 1e6
    return dict(requests=r["requests"], rps=r["requests"] / secs, mbps=r["bytes"] / secs / 1e6,
                lat_us=r["lat_us"])


def drive_h2load(url_base: str, sc: dict, paths: list[str], seconds: float, workdir: Path) -> dict:
    cmd = pin(LOAD_CPUS) + ["h2load", "-c", str(sc["conns"]), "-m", str(sc["streams"]), "-t", "2",
                            "-D", f"{seconds:g}", url_base + paths[0]]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60, preexec_fn=raise_nofile)
    if out.returncode != 0:
        raise RuntimeError(f"h2load failed ({out.returncode}): {out.stdout[-400:]}")
    r = parse_h2load(out.stdout)
    return r


def drive_oha(url_base: str, sc: dict, paths: list[str], seconds: float, workdir: Path) -> dict:
    """A fixed arrival rate (-q), latencies corrected for coordinated omission: a request
    that was due while the server stalled is charged the wait, as a user would feel it."""
    cmd = pin(LOAD_CPUS) + [str(TOOLS / "bin" / "oha"), "-z", f"{seconds:g}s", "-q", str(sc["rate"]),
                            "-c", str(sc["conns"]), "--latency-correction", "--no-tui", "--insecure",
                            "--output-format", "json", url_base + paths[0]]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=seconds + 60, preexec_fn=raise_nofile)
    if out.returncode != 0:
        raise RuntimeError(f"oha failed ({out.returncode}): {out.stderr[-300:]}")
    d = json.loads(out.stdout)
    codes, errs = d["statusCodeDistribution"], d.get("errorDistribution", {})
    n = sum(codes.values())
    bad = sum(v for k, v in codes.items() if not k.startswith("2"))
    stray = {k: v for k, v in errs.items() if k != "aborted due to deadline"}
    if n == 0 or bad or stray:
        raise RuntimeError(f"invalid trial: statuses {codes}, errors {errs}")
    p = d["latencyPercentiles"]
    return dict(requests=n, rps=d["summary"]["requestsPerSec"], mbps=d["summary"]["sizePerSec"] / 1e6,
                lat_us=dict(mean=d["summary"]["average"] * 1e6, p50=p["p50"] * 1e6, p90=p["p90"] * 1e6,
                            p99=p["p99"] * 1e6, p999=p["p99.9"] * 1e6, max=d["summary"]["slowest"] * 1e6))


def origin_requests() -> int:
    """Requests the origin has handled so far (stub_status), the tool-independent evidence of
    how many requests a proxy answered by itself. The scrape counts itself once."""
    out = subprocess.run(["curl", "-s", "-m", "5", "--fail", f"http://127.0.0.1:{ORIGIN_PORT}/_status"],
                         capture_output=True, text=True)
    m = re.search(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", out.stdout, re.M)
    if not m:
        raise RuntimeError("origin /_status not readable")
    return int(m.group(3))


def scenario_paths(sc: dict, manifest: list[dict], image: str) -> list[str]:
    if sc.get("mix"):
        rng = gen_site.Rng(0x5EED)
        pop = [m["path"] for m in manifest if m["path"] not in ("/download/archive-10m.bin", "/manifest.json")]
        for i in range(len(pop) - 1, 0, -1):    # seeded Fisher-Yates: the popularity order
            j = rng.below(i + 1)
            pop[i], pop[j] = pop[j], pop[i]
        return pop
    if sc.get("image"):
        return [image]
    return [sc.get("path", SMALL)]


def summarise(trials: list[dict]) -> dict:
    def med(k):
        v = [t[k] for t in trials if k in t]
        return statistics.median(v) if v else None
    rps = [t["rps"] for t in trials]
    s = dict(trials=len(trials), rps=statistics.median(rps), rps_min=min(rps), rps_max=max(rps),
             rps_mad_pct=100 * mad(rps) / statistics.median(rps) if statistics.median(rps) else 0,
             mbps=med("mbps"), cpu_us_per_req=med("cpu_us_per_req"), server_cpu_pct=med("server_cpu_pct"))
    for k in ("p50", "p90", "p99", "p999"):
        v = [t["lat_us"][k] for t in trials if "lat_us" in t]
        if v:
            s[f"lat_{k}_us"] = statistics.median(v)
    s["server_bound"] = (s["server_cpu_pct"] or 0) >= SERVER_BOUND_MIN_PCT
    return s


def run_scenario(rig: Rig, name: str, sc: dict, manifest, image, trials: int, secs: float, warm: float) -> dict:
    paths = scenario_paths(sc, manifest, image)
    drive = dict(wrk=drive_wrk, h2load=drive_h2load, oha=drive_oha)[sc["tool"]]
    res: dict[str, dict] = {t: dict(trials=[], invalid=[]) for t in sc["targets"]}
    # Every trial starts the proxy afresh (cold cache, no carry-over from the last trial),
    # fills the cache in a warm-up that is not timed, then measures.
    for k in range(trials):
        for t in sc["targets"]:
            pid = rig.start_target(t, sc.get("logs", False))
            try:
                drive(TARGETS[t]["base"], dict(sc, close=False), paths, warm, rig.d)
            except RuntimeError as e:
                res[t]["invalid"].append(f"warm-up: {e}")
            o0 = origin_requests() if sc.get("cache") else 0
            t0, w0 = tree_ticks(pid), time.time()
            try:
                r = drive(TARGETS[t]["base"], sc, paths, secs, rig.d)
                w1 = time.time()
                cpu_s = (tree_ticks(pid) - t0) / CLK_TCK
                n = r.get("requests") or r.get("total") or 0
                r["cpu_us_per_req"] = cpu_s * 1e6 / n if n else None
                r["server_cpu_pct"] = 100.0 * cpu_s / (w1 - w0)
                if sc.get("cache") and t != "origin":
                    # all requests that reached the origin, minus the one status scrape itself
                    reached = origin_requests() - o0 - 1
                    r["cache_hit_ratio"] = max(0.0, 1.0 - reached / n) if n else None
                res[t]["trials"].append(r)
                res[t]["rss_hwm_mib"] = tree_hwm(pid)
            except RuntimeError as e:
                res[t]["invalid"].append(str(e))
            finally:
                if t != "origin":
                    rig.stop(t)
    for t, r in res.items():
        r["summary"] = summarise(r["trials"]) if r["trials"] else None
    return res


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--zion", type=Path, help="the binary under test (or use --variants)")
    ap.add_argument("--variants", default="", help="name=path,name=path: several zion builds measured as interleaved targets, trial by trial, so drift of the host lands on all of them alike")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--label", default="")
    ap.add_argument("--work", type=Path, default=Path("/dev/shm/zion-report-work"))
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--warm", type=float, default=3.0)
    ap.add_argument("--quick", action="store_true", help="1 trial x 2 s: checks the harness, measures nothing")
    ap.add_argument("--only", default="")
    ap.add_argument("--server-cpus", default="", help="CPUs of the proxy under test, e.g. 1,2 (default 1); nginx gets one worker per CPU")
    ap.add_argument("--load-cpus", default="", help="CPUs of the load generators (default 2,3)")
    ap.add_argument("--targets", default="", help="comma-separated subset of zion,nginx,origin (an A/B of two zion builds needs only zion)")
    a = ap.parse_args()
    if a.quick:
        a.trials, a.duration, a.warm = 1, 2.0, 1.0
    global SERVER_CPU, LOAD_CPUS, NGX_WORKERS
    if a.variants:
        for item in a.variants.split(","):
            name, _, path = item.partition("=")
            VARIANTS[name] = Path(path).resolve()
            TARGETS[name] = dict(base=TARGETS["zion"]["base"])
        a.zion = next(iter(VARIANTS.values()))
    if not a.zion:
        sys.exit("give --zion BIN or --variants name=path,...")
    if a.server_cpus:
        SERVER_CPU = a.server_cpus
        NGX_WORKERS = len(a.server_cpus.split(","))
    if a.load_cpus:
        LOAD_CPUS = a.load_cpus
    if (os.cpu_count() or 0) < 4:
        sys.exit("needs 4 CPUs: origin, server and two for the load generators")

    deadline, idle = time.time() + 180, 0.0
    while time.time() < deadline:
        idle = host_idle_pct(5.0)
        if idle >= IDLE_MIN_PCT:
            break
    if idle < IDLE_MIN_PCT:
        sys.exit(f"host is not idle ({idle:.1f}% idle over 5 s, need {IDLE_MIN_PCT}%); refusing to measure")

    ensure_ports_free()
    rig = Rig(a.zion.resolve(), a.work)
    env = environment(a.zion, a.label)
    site_hash = rig.prepare()
    manifest = json.loads((rig.site / "manifest.json").read_text())["files"]
    image = min((m for m in manifest if m["path"].startswith("/img/")), key=lambda m: abs(m["bytes"] - 200_000))["path"]
    env["site_sha256"], env["image_path"], env["idle_pct_at_start"] = site_hash, image, round(idle, 2)
    env["procedure"] = PROCEDURE
    env["harness_sha256"] = hashlib.sha256(b"".join((HERE / f).read_bytes() for f in ("bench.py", "wrk.lua", "gen_site.py"))).hexdigest()
    env["params"] = dict(trials=a.trials, duration_s=a.duration, warm_s=a.warm, quick=a.quick)

    names = [n for n in SCENARIOS if not a.only or n in a.only.split(",")]
    if VARIANTS:
        for n in names:
            SCENARIOS[n] = dict(SCENARIOS[n], targets=list(VARIANTS))
        env["variants"] = {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in VARIANTS.items()}
    if a.targets:
        keep = set(a.targets.split(","))
        for n in names:
            SCENARIOS[n] = dict(SCENARIOS[n], targets=[t for t in SCENARIOS[n]["targets"] if t in keep])
        env["params"]["targets"] = sorted(keep)
    rig.start()
    env["tls"] = tls_probe(rig)
    canaries = [canary()]
    out = dict(schema=1, env=env, scenarios={})
    try:
        for i, n in enumerate(names):
            print(f"[{i + 1}/{len(names)}] {n}: {SCENARIOS[n]['what']}", file=sys.stderr, flush=True)
            out["scenarios"][n] = dict(what=SCENARIOS[n]["what"], tool=SCENARIOS[n]["tool"], conns=SCENARIOS[n]["conns"],
                                       targets=run_scenario(rig, n, SCENARIOS[n], manifest, image, a.trials, a.duration, a.warm))
            if i % 4 == 3:
                canaries.append(canary())
    finally:
        rig.stop_all()
    canaries.append(canary())
    drift = (max(canaries) - min(canaries)) / statistics.median(canaries)
    out["canary"] = dict(mb_s=canaries, drift=drift, tolerance=CANARY_TOLERANCE, noisy=drift > CANARY_TOLERANCE)
    env["load_avg_at_end"] = os.getloadavg()
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "result.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"canary drift {drift * 100:.2f}% ({'NOISY' if out['canary']['noisy'] else 'ok'}); wrote {a.out}/result.json",
          file=sys.stderr)


if __name__ == "__main__":
    main()
