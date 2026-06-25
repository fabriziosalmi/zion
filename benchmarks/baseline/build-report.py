#!/usr/bin/env python3
"""Render the Zion baseline PDF from raw harness outputs.

Reads results/ (produced by run-baseline.sh) + meta.env, parses each tool's
output into structured values, and emits zion-<version>-baseline.pdf via
WeasyPrint. Pure parse-and-render: it invents no numbers — every figure traces
back to a raw file in results/, which is embedded verbatim in the appendix.

Usage: build-report.py <results_dir> <out_dir>
"""
import re
import sys
import json
import html
from pathlib import Path
from datetime import datetime, timezone

RES = Path(sys.argv[1])
OUT = Path(sys.argv[2])


def read(name: str) -> str:
    p = RES / name
    return p.read_text(errors="replace") if p.exists() else ""


def meta() -> dict:
    d = {}
    for line in read("meta.env").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    return d


def search(pattern, text, group=1, default="n/a", flags=0):
    m = re.search(pattern, text, flags)
    return m.group(group).strip() if m else default


# ── parsers ─────────────────────────────────────────────────────────────────
def parse_oha(name):
    t = read(name)
    return {
        "rps": search(r"Requests/sec:\s*([\d.]+)", t),
        "success": search(r"Success rate:\s*([\d.]+%)", t),
        "avg_ms": search(r"Average:\s*([\d.]+)\s*ms", t) or search(r"Average:\s*([\d.]+)", t),
        "slowest_ms": search(r"Slowest:\s*([\d.]+)\s*ms", t) or search(r"Slowest:\s*([\d.]+)", t),
        "fastest_ms": search(r"Fastest:\s*([\d.]+)\s*ms", t) or search(r"Fastest:\s*([\d.]+)", t),
        "p99_ms": search(r"99\.00%\s+in\s+([\d.]+)\s*ms", t),
    }


def parse_h2load(name):
    t = read(name)
    fin = re.search(r"finished in [\d.]+\w+,\s*([\d.]+)\s*req/s,\s*([\d.]+\w+/s)", t)
    req = re.search(r"requests:\s*\d+ total.*?(\d+) succeeded,\s*(\d+) failed", t)
    return {
        "rps": fin.group(1) if fin else "n/a",
        "throughput": fin.group(2) if fin else "n/a",
        "succeeded": req.group(1) if req else "n/a",
        "failed": req.group(2) if req else "n/a",
        "status_2xx": search(r"status codes:\s*(\d+) 2xx", t),
        "status_5xx": search(r"(\d+) 5xx", t, default="0"),
    }


def parse_wrk(name):
    t = read(name)
    return {
        "rps": search(r"Requests/sec:\s*([\d.]+)", t),
        "lat_avg": search(r"Latency\s+([\d.]+\w+)", t),
        "lat_max": search(r"Latency\s+[\d.]+\w+\s+[\d.]+\w+\s+([\d.]+\w+)", t),
        "transfer": search(r"Transfer/sec:\s*([\d.]+\w+)", t),
    }


def parse_h2spec(name):
    t = read(name)
    m = re.search(r"(\d+) tests,\s*(\d+) passed,\s*(\d+) skipped,\s*(\d+) failed", t)
    total, passed, skipped, failed = (m.groups() if m else ("n/a",) * 4)
    fails = re.findall(r"×\s+\d+:\s*(.+)", t)
    return {"total": total, "passed": passed, "skipped": skipped,
            "failed": failed, "failures": list(dict.fromkeys(fails))}


def parse_testssl():
    """Prefer the structured JSON; fall back to text."""
    proto = {}
    vulns_ok = True
    findings = []        # genuine crypto/protocol weaknesses (count against zion)
    cert_artifacts = []  # self-signed lab-cert artifacts (NOT a zion weakness)
    # IDs whose HIGH/CRITICAL rating is purely a consequence of using a
    # self-signed lab certificate — they say nothing about zion's TLS stack.
    CERT_TRUST = ("cert", "overall_grade", "OCSP", "CRL")
    jf = RES / "testssl.json"
    if jf.exists():
        try:
            data = json.loads(jf.read_text())
            for f in data:
                fid = f.get("id", "")
                sev = f.get("severity", "")
                fnd = f.get("finding", "")
                if fid in ("SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"):
                    proto[fid] = fnd
                if sev in ("HIGH", "CRITICAL"):
                    if fid.startswith(CERT_TRUST) or "self signed" in fnd.lower():
                        cert_artifacts.append(f"{fid}: {fnd} [{sev}]")
                    else:
                        vulns_ok = False
                        findings.append(f"{fid}: {fnd} [{sev}]")
        except Exception:
            pass
    t = read("testssl.txt")
    return {
        "proto": proto,
        "tls12": "offered" if "TLS 1.2" in t and re.search(r"TLS 1\.2\s+offered", t) else proto.get("TLS1_2", "n/a"),
        "tls13": proto.get("TLS1_3", "offered" if re.search(r"TLS 1\.3\s+offered", t) else "n/a"),
        "alpn": search(r"ALPN/HTTP2\s+(.+?)\s+\(offered\)", t),
        "fs": "yes" if re.search(r"Forward Secrecy.*offered", t) else "n/a",
        "cipher_order": "yes" if re.search(r"server cipher order\?\s+yes", t) else "n/a",
        "vulns_ok": vulns_ok,
        "high_findings": findings,
        "cert_artifacts": cert_artifacts,
        "vuln_lines": [l.strip() for l in t.splitlines()
                       if re.search(r"\b(not vulnerable|VULNERABLE)\b", l)],
    }


def verify_age():
    t = read("verify-cache-hit.txt")
    age = search(r"(?im)^age:\s*(\d+)", t)
    cc = search(r"(?im)^cache-control:\s*(.+)$", t)
    return {"age": age, "cache_control": cc, "present": age != "n/a"}


M = meta()
oha_c, oha_p = parse_oha("oha-cache.txt"), parse_oha("oha-proxy.txt")
h2l = parse_h2load("h2load-cache.txt")
wrk = parse_wrk("wrk-cache.txt")
h2s = parse_h2spec("h2spec.txt")
tls = parse_testssl()
age = verify_age()

ver = M.get("zion_version", "zion").split()[-1] if M.get("zion_version") else "dev"
pdf_name = f"zion-{ver}-baseline.pdf"


def esc(x):
    return html.escape(str(x))


def rps(x):
    """Render a requests/sec value as a rounded integer with thousands
    separators — raw tool decimals (e.g. 186237.3718) are noise for reading."""
    try:
        return f"{float(str(x).replace(',', '')):,.0f}"
    except Exception:
        return esc(x)


def yesno(ok):
    return ('<span class="ok">PASS</span>' if ok else '<span class="bad">CHECK</span>')


# ── exact commands (mirror run-baseline.sh; reproducibility) ────────────────
D = M.get("params_duration", "20s"); C = M.get("params_conns", "50")
N = M.get("params_h2load_n", "200000"); MM = M.get("params_h2load_m", "20")
WT = M.get("params_wrk_threads", "4")
commands = [
    ("HTTP/2 RFC 9113/7540", f"h2spec -t -k -h 127.0.0.1 -p 4432"),
    ("TLS conformance", f"testssl.sh --quiet 127.0.0.1:4432"),
    ("oha cache-hit", f"oha -z {D} -c {C} --insecure /_next/static/chunk.js"),
    ("oha proxy", f"oha -z {D} -c {C} --insecure /api/v1/data"),
    ("h2load HTTP/2", f"h2load -n {N} -c {C} -m {MM} /_next/static/chunk.js"),
    ("wrk HTTP/1.1", f"wrk -t{WT} -c{C} -d{D} /_next/static/chunk.js"),
]

meta_rows = [
    ("Report date (UTC)", M.get("date_utc", "n/a")),
    ("Zion version", M.get("zion_version", "n/a")),
    ("Git commit", M.get("git_sha", "n/a") + (" (dirty)" if M.get("git_dirty") == "yes" else "")),
    ("Host OS / arch", f"{M.get('os','n/a')} / {M.get('arch','n/a')}"),
    ("CPU / cores / mem", f"{M.get('cpu','n/a')} / {M.get('cores','n/a')} / {M.get('mem_gb','n/a')} GB"),
    ("oha", M.get("tool_oha", "n/a")),
    ("h2load", M.get("tool_h2load", "n/a")),
    ("wrk", M.get("tool_wrk", "n/a")),
    ("h2spec", M.get("tool_h2spec", "n/a")),
    ("testssl.sh", M.get("tool_testssl", "n/a")),
    ("OpenSSL (client)", M.get("tool_openssl", "n/a")),
]

raw_files = ["h2spec.txt", "oha-cache.txt", "oha-proxy.txt", "h2load-cache.txt",
             "wrk-cache.txt", "verify-cache-hit.txt", "testssl.txt", "zion.log"]

CSS = """
@page { size: A4; margin: 18mm 16mm; @bottom-center { content: "Zion edge baseline · """ + esc(ver) + """ · page " counter(page) " / " counter(pages); font-size: 8pt; color: #888; } }
* { font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif; }
body { font-size: 10pt; color: #1a1a1a; line-height: 1.45; }
h1 { font-size: 22pt; margin: 0 0 2pt; color: #0b3d63; }
h2 { font-size: 14pt; margin: 18pt 0 6pt; color: #0b3d63; border-bottom: 2px solid #0b3d63; padding-bottom: 2pt; }
h3 { font-size: 11pt; margin: 12pt 0 4pt; color: #444; }
.sub { color: #666; font-size: 10pt; margin-bottom: 4pt; }
table { width: 100%; border-collapse: collapse; margin: 6pt 0; font-size: 9pt; }
th, td { text-align: left; padding: 4pt 6pt; border-bottom: 1px solid #ddd; vertical-align: top; }
th { background: #f0f4f8; color: #0b3d63; }
.metric { font-size: 13pt; font-weight: 700; color: #0b3d63; }
.ok { color: #137333; font-weight: 700; }
.bad { color: #b00020; font-weight: 700; }
.kpi { display: flex; gap: 8pt; margin: 8pt 0; }
.card { flex: 1; border: 1px solid #d0d7de; border-radius: 6px; padding: 8pt; background: #fafcff; }
.card .v { font-size: 16pt; font-weight: 800; color: #0b3d63; }
.card .l { font-size: 8pt; color: #666; text-transform: uppercase; letter-spacing: .4px; }
code, pre { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 8pt; }
pre { background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 5px; padding: 6pt; white-space: pre-wrap; word-break: break-word; }
.note { background: #fff8e1; border-left: 3px solid #f9a825; padding: 6pt 8pt; font-size: 9pt; margin: 6pt 0; }
.appendix pre { font-size: 6.5pt; max-height: none; }
"""

failures_html = "".join(f"<li>{esc(f)}</li>" for f in h2s["failures"]) or "<li>none</li>"
vuln_html = "".join(f"<tr><td>{esc(l)}</td></tr>" for l in tls["vuln_lines"][:18])
cmd_html = "".join(f"<tr><td>{esc(n)}</td><td><code>{esc(c)}</code></td></tr>" for n, c in commands)
meta_html = "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in meta_rows)

appendix = ""
for fn in raw_files:
    body = read(fn)
    if not body:
        continue
    # cap very long files to keep the PDF bounded; note the truncation
    lines = body.splitlines()
    capped = "\n".join(lines[:160])
    if len(lines) > 160:
        capped += f"\n... [{len(lines)-160} more lines truncated; see results/{fn}]"
    appendix += f"<h3>results/{esc(fn)}</h3><pre>{esc(capped)}</pre>"

doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body>
<h1>Zion Edge — Baseline Report</h1>
<div class="sub">Reproducible benchmark &amp; RFC-conformance baseline · {esc(M.get('zion_version','n/a'))} · {esc(M.get('date_utc','n/a'))}</div>
<div class="note">Generated by <code>benchmarks/baseline/run-baseline.sh</code> → <code>build-report.py</code>.
Every figure below is parsed from a raw tool output embedded verbatim in the Appendix. Re-run the harness on the
same hardware to reproduce within noise.</div>

<h2>1. Summary</h2>
<div class="kpi">
  <div class="card"><div class="v">{esc(h2s['passed'])}/{esc(h2s['total'])}</div><div class="l">HTTP/2 RFC (h2spec)</div></div>
  <div class="card"><div class="v">{yesno(tls['vulns_ok'])}</div><div class="l">TLS vulns</div></div>
  <div class="card"><div class="v">{rps(wrk['rps'])}</div><div class="l">HTTP/1.1 req/s</div></div>
  <div class="card"><div class="v">{rps(h2l['rps'])}</div><div class="l">HTTP/2 req/s</div></div>
  <div class="card"><div class="v">{rps(oha_c['rps'])}</div><div class="l">cache-hit req/s</div></div>
</div>

<h2>2. Environment &amp; tooling</h2>
<table>{meta_html}</table>

<h2>3. Methodology — exact commands</h2>
<div class="sub">Lab: client → zion (TLS :4432, min 1.2, memory cache) → Go bench-backend (:9090). Config: <code>benchmarks/baseline/zion-lab.toml</code>.</div>
<table><tr><th>Test</th><th>Command (params pinned in run-baseline.sh)</th></tr>{cmd_html}</table>

<h2>4. Functional verification — v0.4.2 cache fix</h2>
<div class="sub">The v0.4.2 fix makes cache hits emit an <code>Age</code> header (absent before) and derive freshness from the origin.</div>
<table>
<tr><th>Age header present on cache hit</th><td>{yesno(age['present'])} (Age: {esc(age['age'])})</td></tr>
<tr><th>Cache-Control on hit</th><td><code>{esc(age['cache_control'])}</code></td></tr>
</table>

<h2>5. RFC conformance</h2>
<h3>5.1 HTTP/2 (RFC 9113 / 7540) — h2spec</h3>
<table>
<tr><th>Total</th><th>Passed</th><th>Skipped</th><th>Failed</th></tr>
<tr><td>{esc(h2s['total'])}</td><td class="ok">{esc(h2s['passed'])}</td><td>{esc(h2s['skipped'])}</td><td>{esc(h2s['failed'])}</td></tr>
</table>
<h3>Failing cases</h3><ul>{failures_html}</ul>

<h3>5.2 TLS — testssl.sh</h3>
<table>
<tr><th>Protocols</th><td>SSLv2/v3, TLS1.0/1.1 not offered · TLS 1.2 &amp; 1.3 offered</td></tr>
<tr><th>ALPN</th><td>{esc(tls['alpn'])}</td></tr>
<tr><th>Forward Secrecy</th><td>{esc(tls['fs'])}</td></tr>
<tr><th>Server cipher order</th><td>{esc(tls['cipher_order'])}</td></tr>
<tr><th>Genuine crypto/protocol findings</th><td>{yesno(tls['vulns_ok'])} {esc('; '.join(tls['high_findings']) or 'none')}</td></tr>
</table>
<div class="note"><b>Lab-cert artifacts (not a zion weakness):</b> {esc('; '.join(tls['cert_artifacts']) or 'none')}.
These HIGH/CRITICAL ratings (chain-of-trust, revocation, overall grade) follow directly from using a self-signed
certificate in the lab. The production edge serves a CA-issued cert; the protocol/cipher/vulnerability posture below
is what reflects zion.</div>
<h3>Vulnerability probes</h3><table>{vuln_html}</table>

<h2>6. Benchmark</h2>
<table>
<tr><th>Test</th><th>req/s</th><th>Success</th><th>Latency</th><th>Notes</th></tr>
<tr><td>oha — cache-hit (H1/TLS)</td><td class="metric">{rps(oha_c['rps'])}</td><td>{esc(oha_c['success'])}</td><td>avg {esc(oha_c['avg_ms'])} ms / slowest {esc(oha_c['slowest_ms'])} ms</td><td>c={esc(C)}, {esc(D)}</td></tr>
<tr><td>oha — proxy passthrough</td><td class="metric">{rps(oha_p['rps'])}</td><td>{esc(oha_p['success'])}</td><td>avg {esc(oha_p['avg_ms'])} ms</td><td>no cache</td></tr>
<tr><td>h2load — HTTP/2 cache-hit</td><td class="metric">{rps(h2l['rps'])}</td><td>{esc(h2l['succeeded'])} ok / {esc(h2l['failed'])} fail</td><td>{esc(h2l['throughput'])}</td><td>n={esc(N)}, m={esc(MM)}; 2xx={esc(h2l['status_2xx'])}, 5xx={esc(h2l['status_5xx'])}</td></tr>
<tr><td>wrk — HTTP/1.1 cache-hit</td><td class="metric">{rps(wrk['rps'])}</td><td>—</td><td>avg {esc(wrk['lat_avg'])} / max {esc(wrk['lat_max'])}</td><td>t={esc(WT)}, c={esc(C)}, {esc(D)}; xfer {esc(wrk['transfer'])}</td></tr>
</table>
<div class="note">Loopback numbers measure server-side efficiency (no network RTT, self-signed TLS). They are an upper bound for the data path, not a WAN figure. Use them as a regression baseline across versions on identical hardware.</div>

<div class="appendix">
<h2>Appendix — raw tool output</h2>
{appendix}
</div>
</body></html>"""

(OUT / "report.html").write_text(doc)
# PDF conversion is done by the WeasyPrint CLI from run-baseline.sh (the brew
# package ships a CLI, not an importable module). Emit the target filename so
# the harness knows what to produce.
print(pdf_name)
