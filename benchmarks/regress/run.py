#!/usr/bin/env python3
"""Performance regression harness: one release binary, a fixed set of data paths,
the numbers that do not depend on how busy the box is.

    python3 benchmarks/regress/run.py --zion target/release/zion --out result.json
    python3 benchmarks/regress/compare.py base.json result.json

Why this exists: a refactor of the request pipeline, or a change to the cache, the
static server or the upstream pool, must be able to say "performance unchanged" or
"X % better" with numbers that were measured the same way before and after. The
canonical `benchmarks/baseline/` harness is a release-level report (nginx comparison,
conformance, PDF); this one answers a narrower question, fast, and fails loudly when
a trial is not valid.

What it measures, per scenario (restarting zion for each, so memory and cache state
do not leak between them):

  * rps            requests per second (h2load, HTTP/2 over TLS 1.3, the real pipeline)
  * cpu_us_per_req CPU time zion spent per request, from /proc/<pid>/stat around the
                   measured window. This is the number to trust: it barely moves
                   with the box's load or the load generator's speed.
  * mean_ms        mean request latency (h2load does not report percentiles)
  * server_cpu_pct how busy the server's cores were. Below ~80 % the load generator
                   was the limit and `rps` says nothing about zion (cpu_us_per_req
                   still holds).
  * rss_hwm_mib    peak resident memory of zion over the scenario (VmHWM)

Each scenario runs TRIALS times; the summary is the median with the spread (MAD).
A trial with any non-2xx status, failed or errored request aborts the run: a
benchmark of an error path is not a benchmark.

Linux only (it reads /proc). It pins zion and the load generator to separate CPUs
when the box has at least 4, and says so in the result when it does not.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CLK_TCK = os.sysconf("SC_CLK_TCK")

HTTPS_PORT = 14432
HTTP_PORT = 14480
BACKEND_PORT = 9090  # fixed by benchmarks/backend/main.go

# ── Scenarios ────────────────────────────────────────────────────────────────
# `uris` is a list of request targets; one entry means a single hot URL, many
# entries are cycled by h2load (-i). `post` is a body file name written by setup().
# `warm` is the number of requests that fill the cache before measuring.


def _uri_variety(n: int) -> list[str]:
    """Paths that exercise the normaliser: dot segments, doubled slashes and
    percent-encodings of unreserved characters, all of which zion accepts and
    rewrites before routing."""
    forms = [
        "/api/a/./b/../c{i}",
        "/api//a//b{i}",
        "/api/%61bc/%7Euser{i}",
        "/api/a/b/../../x/y{i}",
        "/api/./a/./b{i}/.",
    ]
    return [forms[i % len(forms)].format(i=i) + f"?v={i}" for i in range(n)]


SCENARIOS: dict[str, dict] = {
    # The cache hit path: routing, gates, cache lookup, response, TLS and HTTP/2.
    "cache_hit_1k": dict(
        conns=16, streams=10,
        uris=["/_next/static/blob?bytes=1024"], warm=1,
    ),
    # The same with 2,000 distinct keys: the shared tier, not one hot entry.
    "cache_hit_2000_keys": dict(
        conns=16, streams=10,
        uris=[f"/_next/static/blob?bytes=1024&k={i}" for i in range(2000)], warm=2000,
    ),
    # No cache: the pipeline plus one upstream round trip.
    "proxy_1k": dict(
        conns=16, streams=10,
        uris=["/api/blob?bytes=1024"], warm=1,
    ),
    # The pipeline with the WAF scanning a JSON body.
    "waf_post_json": dict(
        conns=16, streams=10,
        uris=["/w/v1/data"], warm=1, post="body.json",
    ),
    # URI normalisation on every request (the audit's most security-relevant parser).
    "uri_normalise": dict(
        conns=16, streams=10,
        uris=_uri_variety(500), warm=0,
    ),
    # Static files served from disk: one-shot read up to 576 KiB, streamed above.
    "static_1m": dict(conns=8, streams=5, uris=["/files/1m.bin"], warm=1),
    "static_10m": dict(conns=8, streams=5, uris=["/files/10m.bin"], warm=1),
}

CONFIG = """\
[server]
listen_http = "127.0.0.1:{http}"
listen_https = "127.0.0.1:{https}"

[tls]
cert_path = "{dir}/tls.crt"
key_path = "{dir}/tls.key"
hot_reload = false

[upstreams]
backend = "http://127.0.0.1:{backend}"

[cache_profile.bench]
mode = "memory"
max_entries = 10000
ttl_seconds = 3600

[[route]]
path = "/_next/static/{{*rest}}"
upstream = "backend"
mode = "static_cache"
cache_profile = "bench"
waf = false

[[route]]
path = "/w/{{*rest}}"
upstream = "backend"
mode = "standard"
waf = true

[[route]]
path = "/api/{{*rest}}"
upstream = "backend"
mode = "standard"
waf = false

[[route]]
path = "/files/{{*rest}}"
mode = "static"
serve_dir = "{dir}/www"
"""


def sh(*cmd: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def cpu_ticks(pid: int) -> int:
    """utime + stime of a process, in clock ticks."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])  # fields 14 and 15 of the full line


def vm_hwm_mib(pid: int) -> float:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1]) / 1024
    return 0.0


def wait_port(port: int, what: str, timeout: float = 20.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    sys.exit(f"{what} did not open port {port} in {timeout:.0f} s")


def mad(values: list[float]) -> float:
    m = statistics.median(values)
    return statistics.median(abs(v - m) for v in values)


def parse_h2load(out: str) -> dict:
    """The numbers of one h2load run; raises when the run is not a valid trial."""
    done = re.search(
        r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, "
        r"(\d+) failed, (\d+) errored, (\d+) timeout", out)
    status = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", out)
    rate = re.search(r"finished in ([\d.]+)(m?s), ([\d.]+) req/s", out)
    lat = re.search(r"time for request:\s+([\d.]+)(us|ms|s)\s+([\d.]+)(us|ms|s)\s+"
                    r"([\d.]+)(us|ms|s)", out)
    if not (done and status and rate and lat):
        raise RuntimeError("h2load output not understood:\n" + out[-800:])
    n_done, ok, failed, errored, timeout = (int(done.group(i)) for i in (3, 4, 5, 6, 7))
    s2, s3, s4, s5 = (int(status.group(i)) for i in (1, 2, 3, 4))
    # Status codes count responses whose headers arrived, so streams still open when the
    # window ends make `2xx` exceed `done` for large bodies; they must never fall short.
    if n_done == 0 or failed or errored or timeout or s3 or s4 or s5 or s2 < n_done:
        raise RuntimeError(
            f"not a valid trial: {n_done} done, {s2} 2xx, {s3} 3xx, {s4} 4xx, {s5} 5xx, "
            f"{failed} failed, {errored} errored, {timeout} timeout")
    unit = {"us": 1e-3, "ms": 1.0, "s": 1e3}
    return dict(
        requests=n_done,
        rps=float(rate.group(3)),
        mean_ms=float(lat.group(5)) * unit[lat.group(6)],
        max_ms=float(lat.group(3)) * unit[lat.group(4)],
    )


class Rig:
    """Everything one session needs: certificate, files, backend, config."""

    def __init__(self, zion: Path, workdir: Path, cpus_server: str | None, cpus_load: str | None):
        self.zion, self.dir = zion, workdir
        self.cpus_server, self.cpus_load = cpus_server, cpus_load
        self.backend: subprocess.Popen | None = None
        self.proc: subprocess.Popen | None = None

    def pin(self, cpus: str | None) -> list[str]:
        return ["taskset", "-c", cpus] if cpus else []

    def setup(self) -> None:
        d = self.dir
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-nodes", "-days", "2", "-subj", "/CN=localhost",
           "-keyout", str(d / "tls.key"), "-out", str(d / "tls.crt"))
        (d / "www").mkdir()
        for name, size in (("1m.bin", 1 << 20), ("10m.bin", 10 << 20)):
            # Deterministic bytes that do not compress.
            seed, out = 0x9E3779B97F4A7C15, bytearray()
            while len(out) < size:
                seed = (seed * 6364136223846793005 + 1442695040888963407) & (2**64 - 1)
                out += seed.to_bytes(8, "little")
            (d / "www" / name).write_bytes(bytes(out[:size]))
        (d / "body.json").write_text(
            '{"user":"alice","items":[1,2,3,4,5],"note":"a short, ordinary sentence","ok":true}')
        (d / "zion.toml").write_text(CONFIG.format(
            dir=d, http=HTTP_PORT, https=HTTPS_PORT, backend=BACKEND_PORT))
        sh("go", "build", "-o", str(d / "backend"), str(REPO / "benchmarks" / "backend" / "main.go"))
        self.backend = subprocess.Popen(
            self.pin(self.cpus_load) + [str(d / "backend")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_port(BACKEND_PORT, "backend")

    def start_zion(self) -> int:
        env = dict(os.environ, ZION_CONFIG=str(self.dir / "zion.toml"), ZION_BOOT_FAST="1")
        self.proc = subprocess.Popen(
            self.pin(self.cpus_server) + [str(self.zion)],
            env=env, stdout=subprocess.DEVNULL, stderr=(self.dir / "zion.log").open("ab"))
        wait_port(HTTPS_PORT, "zion")
        time.sleep(0.5)
        # `taskset` execs zion, so the pid is the process's own.
        return self.proc.pid

    def stop_zion(self) -> None:
        if self.proc:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()
            self.proc = None

    def teardown(self) -> None:
        self.stop_zion()
        if self.backend:
            self.backend.kill()
            self.backend.wait()

    def h2load(self, sc: dict, duration: float | None, requests: int | None) -> str:
        d = self.dir
        cmd = self.pin(self.cpus_load) + ["h2load", "-c", str(sc["conns"]), "-m", str(sc["streams"]),
                                          "-t", str(min(2, sc["conns"]))]
        if duration is not None:
            cmd += ["-D", f"{duration:g}"]  # h2load rejects "2.0"
        else:
            cmd += ["-n", str(requests)]
        if sc.get("post"):
            cmd += ["-d", str(d / sc["post"]), "-H", "content-type: application/json"]
        uris = sc["uris"]
        base = f"https://127.0.0.1:{HTTPS_PORT}"
        if len(uris) == 1:
            cmd.append(base + uris[0])
        else:
            (d / "uris.txt").write_text("\n".join(base + u for u in uris) + "\n")
            cmd += ["-i", str(d / "uris.txt")]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=(duration or 60) + 60)
        if out.returncode != 0:
            raise RuntimeError(f"h2load exited {out.returncode}:\n{out.stdout[-600:]}\n{out.stderr[-600:]}")
        return out.stdout

    def scenario(self, name: str, trials: int, duration: float, cores: int) -> dict:
        sc = SCENARIOS[name]
        pid = self.start_zion()
        try:
            if sc["warm"]:
                self.h2load(dict(sc, conns=min(4, sc["warm"]), streams=1), None, sc["warm"])
            self.h2load(sc, 2.0, None)  # settle: connections, pools, caches
            results = []
            for _ in range(trials):
                t0, w0 = cpu_ticks(pid), time.time()
                run = parse_h2load(self.h2load(sc, duration, None))
                t1, w1 = cpu_ticks(pid), time.time()
                cpu_s = (t1 - t0) / CLK_TCK
                run["cpu_us_per_req"] = cpu_s * 1e6 / run["requests"]
                run["server_cpu_pct"] = 100.0 * cpu_s / ((w1 - w0) * cores)
                results.append(run)
            return dict(trials=results, rss_hwm_mib=vm_hwm_mib(pid),
                        summary=summarise(results))
        finally:
            self.stop_zion()


def summarise(results: list[dict]) -> dict:
    out = {}
    for metric in ("rps", "cpu_us_per_req", "mean_ms", "server_cpu_pct"):
        vals = [r[metric] for r in results]
        out[metric] = dict(median=statistics.median(vals), min=min(vals), max=max(vals),
                           mad=mad(vals))
    return out


def host_meta(zion: Path, args: argparse.Namespace, pinned: bool) -> dict:
    cpu = next((l.split(":", 1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines()
                if l.startswith("model name")), "?")
    return dict(
        label=args.label,
        zion=sh(str(zion), "--version").stdout.strip(),
        zion_sha256=sh("sha256sum", str(zion)).stdout.split()[0],
        host=platform.node(), kernel=platform.release(), cpu=cpu, cpus=os.cpu_count(),
        pinned=pinned, cpus_server=args.cpus_server, cpus_load=args.cpus_load,
        load_avg_at_start=os.getloadavg(),
        h2load=sh("h2load", "--version").stdout.strip(),
        trials=args.trials, duration_s=args.duration,
        date=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--zion", required=True, type=Path, help="release binary to measure")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--label", default="", help="free text stored in the result (e.g. the version)")
    p.add_argument("--trials", type=int, default=7)
    p.add_argument("--duration", type=float, default=10.0, help="seconds per trial")
    p.add_argument("--only", default="", help="comma-separated scenario names")
    p.add_argument("--cpus-server", default=None, help="taskset list for zion (default: first half)")
    p.add_argument("--cpus-load", default=None, help="taskset list for load + backend (default: second half)")
    p.add_argument("--quick", action="store_true", help="2 trials of 3 s: a check of the harness, not a measurement")
    args = p.parse_args()
    if args.quick:
        args.trials, args.duration = 2, 3.0
    if platform.system() != "Linux":
        sys.exit("this harness reads /proc: run it on Linux")
    for tool in ("h2load", "openssl", "go", "taskset"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is required")
    n = os.cpu_count() or 1
    if n >= 4 and not (args.cpus_server or args.cpus_load):
        half = n // 2
        args.cpus_server = ",".join(str(i) for i in range(half))
        args.cpus_load = ",".join(str(i) for i in range(half, n))
    pinned = bool(args.cpus_server and args.cpus_load)
    cores = len(args.cpus_server.split(",")) if args.cpus_server else n
    names = [s for s in args.only.split(",") if s] or list(SCENARIOS)
    unknown = [s for s in names if s not in SCENARIOS]
    if unknown:
        sys.exit(f"unknown scenario(s): {', '.join(unknown)}; known: {', '.join(SCENARIOS)}")
    zion = args.zion.resolve()

    result = dict(meta=host_meta(zion, args, pinned), scenarios={})
    with tempfile.TemporaryDirectory(prefix="zion-regress-") as tmp:
        rig = Rig(zion, Path(tmp), args.cpus_server, args.cpus_load)
        rig.setup()
        try:
            for name in names:
                print(f"{name:22} ", end="", flush=True)
                res = rig.scenario(name, args.trials, args.duration, cores)
                result["scenarios"][name] = res
                s = res["summary"]
                print(f"{s['rps']['median']:>10,.0f} req/s   {s['cpu_us_per_req']['median']:>7.1f} us cpu/req"
                      f"   {s['mean_ms']['median']:>6.2f} ms   server cpu {s['server_cpu_pct']['median']:>3.0f} %"
                      f"   rss {res['rss_hwm_mib']:>6.0f} MiB", flush=True)
        finally:
            rig.teardown()
    result["meta"]["load_avg_at_end"] = os.getloadavg()
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"written {args.out}")


if __name__ == "__main__":
    main()
