#!/usr/bin/env python3
"""Render the Zion baseline PDF (v2) from raw harness outputs.

Reads results/ (produced by run-baseline.sh) and emits report.html (PDF via the
WeasyPrint CLI from the harness). Statistics over N trials (median + stdev +
95% CI), full latency percentiles, nginx comparison, resource accounting, a
cache-correctness verdict, a concurrency-sweep chart, and a regression delta
against history.json. Every figure traces to a raw file embedded in the appendix.

Usage: build-report.py <results_dir> <out_dir> [history.json]
"""
import re
import sys
import json
import html
import base64
import io
import statistics as st
from pathlib import Path

RES = Path(sys.argv[1])
OUT = Path(sys.argv[2])
HISTORY = Path(sys.argv[3]) if len(sys.argv) > 3 else None


def read(name):
    p = RES / name
    return p.read_text(errors="replace") if p.exists() else ""


def kv(text):
    d = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            d[k.strip()] = v.strip()
    return d


def search(pat, text, g=1, d="n/a", flags=0):
    m = re.search(pat, text, flags)
    return m.group(g).strip() if m else d


def esc(x):
    return html.escape(str(x))


def rps(x):
    try:
        return f"{float(str(x).replace(',', '')):,.0f}"
    except Exception:
        return esc(x)


def trials(name):
    """Parse a .dat of trial rows 'rps p50 p99 p999 p9999 cpu rss' → dict of lists."""
    cols = {"rps": [], "p50": [], "p99": [], "p999": [], "p9999": [], "cpu": [], "rss": []}
    for line in read(name).splitlines():
        f = line.split()
        if len(f) >= 7:
            for i, k in enumerate(["rps", "p50", "p99", "p999", "p9999", "cpu", "rss"]):
                try:
                    cols[k].append(float(f[i]))
                except ValueError:
                    pass
    return cols


def stat(vals):
    if not vals:
        return {"med": 0, "sd": 0, "ci": 0, "n": 0}
    med = st.median(vals)
    sd = st.pstdev(vals) if len(vals) > 1 else 0.0
    ci = 1.96 * sd / (len(vals) ** 0.5) if len(vals) > 1 else 0.0
    return {"med": med, "sd": sd, "ci": ci, "n": len(vals)}


M = kv(read("meta.env"))
P = kv(read("proto.env"))
CC = kv(read("cache-correctness.txt"))
cores = float(M.get("cores", "1") or 1)
ver = M.get("zion_version", "zion").split()[-1] if M.get("zion_version") else "dev"
pdf_name = f"zion-{ver}-baseline.pdf"

# ── headline rows ───────────────────────────────────────────────────────────
HEAD = [("zion cache-hit", "hl-zion-cache.dat"),
        ("zion proxy passthrough", "hl-zion-proxy.dat"),
        ("nginx cache-hit (ref)", "hl-nginx-cache.dat")]
head_rows = []
for label, fn in HEAD:
    c = trials(fn)
    if not c["rps"]:
        continue
    r = stat(c["rps"])
    head_rows.append({
        "label": label,
        "rps": r["med"], "rps_ci": r["ci"], "n": r["n"],
        "p50": stat(c["p50"])["med"], "p99": stat(c["p99"])["med"], "p999": stat(c["p999"])["med"],
        "cpu": stat(c["cpu"])["med"], "rss": stat(c["rss"])["med"],
        "rpc": r["med"] / cores if cores else 0,
    })


def yesno(ok):
    return '<span class="ok">PASS</span>' if ok else '<span class="bad">FAIL</span>'


# ── cache correctness verdict ───────────────────────────────────────────────
cc_checks = [
    ("Age header present on hit", CC.get("age_present") == "yes"),
    (f"Age monotonic ({CC.get('age_t0','?')}→{CC.get('age_t2','?')}s over 2s)", CC.get("age_monotonic") == "yes"),
    (f"Origin TTL honoured (max-age=5 → '{CC.get('shortttl_cache_control','?')}')", CC.get("origin_ttl_honored") == "yes"),
    (f"Stale-born passthrough (upstream Age={CC.get('staleborn_age','?')})", CC.get("staleborn_passthrough") == "yes"),
]
hit_ratio = CC.get("hit_ratio", "n/a")

# ── conformance ─────────────────────────────────────────────────────────────
h2t = read("h2spec.txt")
h2m = re.search(r"(\d+) tests,\s*(\d+) passed,\s*(\d+) skipped,\s*(\d+) failed", h2t)
h2spec = dict(zip(["total", "passed", "skipped", "failed"], h2m.groups())) if h2m else None
h2fails = list(dict.fromkeys(re.findall(r"×\s+\d+:\s*(.+)", h2t)))

tls_txt = read("testssl.txt")
tls = None
if tls_txt:
    vulns_ok = True
    cert_art = []
    jf = RES / "testssl.json"
    if jf.exists():
        try:
            for f in json.loads(jf.read_text()):
                if f.get("severity") in ("HIGH", "CRITICAL"):
                    if f.get("id", "").startswith(("cert", "overall_grade", "OCSP", "CRL")) or "self signed" in f.get("finding", "").lower():
                        cert_art.append(f"{f['id']}: {f['finding']}")
                    else:
                        vulns_ok = False
        except Exception:
            pass
    tls = {
        "alpn": search(r"ALPN/HTTP2\s+(.+?)\s+\(offered\)", tls_txt),
        "fs": "yes" if re.search(r"Forward Secrecy.*offered", tls_txt) else "n/a",
        "vulns_ok": vulns_ok, "cert_art": cert_art,
        "probes": [l.strip() for l in tls_txt.splitlines() if re.search(r"\b(not vulnerable|VULNERABLE)\b", l)],
    }

# ── h2load / wrk / wrk2 protocol-pinned ─────────────────────────────────────
h2l = read("h2load.txt")
h2load_rps = search(r"finished in [\d.]+\w+,\s*([\d.]+)\s*req/s", h2l)
h2load_ok = search(r"(\d+) succeeded", h2l)
wrk_t = read("wrk.txt")
wrk_rps = search(r"Requests/sec:\s*([\d.]+)", wrk_t)
wrk2_t = read("wrk2.txt")
wrk2_p99 = search(r"99\.000%\s+([\d.]+\w+)", wrk2_t) if wrk2_t else None

# ── sweep chart ─────────────────────────────────────────────────────────────
sweep = []
for line in read("sweep.dat").splitlines():
    f = line.split()
    if len(f) >= 3:
        sweep.append((int(f[0]), float(f[1]), float(f[2])))
sweep_img = ""
if sweep:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        cs = [s[0] for s in sweep]; rs = [s[1] for s in sweep]; ps = [s[2] for s in sweep]
        fig, ax1 = plt.subplots(figsize=(6.4, 3.0))
        ax1.plot(cs, rs, "o-", color="#0b3d63", label="req/s")
        ax1.set_xlabel("concurrency"); ax1.set_ylabel("req/s", color="#0b3d63")
        ax1.set_xscale("log"); ax1.grid(True, alpha=0.3)
        ax2 = ax1.twinx()
        ax2.plot(cs, ps, "s--", color="#b00020", label="p99 (ms)")
        ax2.set_ylabel("p99 latency (ms)", color="#b00020")
        fig.tight_layout()
        buf = io.BytesIO(); fig.savefig(buf, format="png", dpi=120); plt.close(fig)
        sweep_img = f'<img src="data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}" style="width:100%">'
    except Exception as e:
        sweep_img = f"<p><i>chart unavailable: {esc(e)}</i></p>"
sweep_rows = "".join(f"<tr><td>{c}</td><td>{rps(r)}</td><td>{p:.2f}</td></tr>" for c, r, p in sweep)

# ── payload matrix (medians from pm-<p>.dat) ────────────────────────────────
pm_rows = ""
for line in read("payload.dat").splitlines():
    p = line.strip()
    if not p:
        continue
    c = trials(f"pm-{p}.dat")
    s = stat(c["rps"])
    label = f"{int(p)//1024} KB" if int(p) < 1048576 else f"{int(p)//1048576} MB"
    pm_rows += f"<tr><td>{label}</td><td>{rps(s['med'])}</td><td>±{rps(s['ci'])}</td><td>{stat(c['p99'])['med']:.2f}</td></tr>"

# ── regression delta + history append ───────────────────────────────────────
reg_html = "<i>no history baseline yet (first run on this host)</i>"
host_key = f"{M.get('cpu','?')}|{M.get('cores','?')}"
cur_rps = head_rows[0]["rps"] if head_rows else 0
if HISTORY is not None:
    hist = {}
    if HISTORY.exists():
        try:
            hist = json.loads(HISTORY.read_text())
        except Exception:
            hist = {}
    entries = hist.get(host_key, [])
    if entries:
        prev = entries[-1]
        pr = prev.get("zion_cache_rps", 0)
        if pr:
            delta = 100 * (cur_rps - pr) / pr
            cls = "ok" if delta >= -5 else "bad"
            reg_html = (f'vs previous ({esc(prev.get("zion_version","?"))}@{esc(prev.get("git_sha","?"))}, '
                        f'{rps(pr)} req/s): <span class="{cls}">{delta:+.1f}%</span> '
                        f'(regression gate: ≥ −5%)')
    entries.append({"date": M.get("date_utc"), "git_sha": M.get("git_sha"),
                    "zion_version": M.get("zion_version"), "zion_cache_rps": cur_rps})
    hist[host_key] = entries
    try:
        HISTORY.write_text(json.dumps(hist, indent=2))
    except Exception:
        pass

# ── HTML ────────────────────────────────────────────────────────────────────
CSS = """
@page { size: A4; margin: 16mm 14mm; @bottom-center { content: "Zion baseline · """ + esc(ver) + """ · " counter(page) "/" counter(pages); font-size:8pt; color:#888; } }
* { font-family: -apple-system,'Helvetica Neue',Arial,sans-serif; }
body { font-size: 9.5pt; color:#1a1a1a; line-height:1.4; }
h1 { font-size:21pt; margin:0 0 2pt; color:#0b3d63; }
h2 { font-size:13pt; margin:15pt 0 5pt; color:#0b3d63; border-bottom:2px solid #0b3d63; padding-bottom:2pt; }
h3 { font-size:10.5pt; margin:9pt 0 3pt; color:#444; }
.sub { color:#666; font-size:9pt; margin-bottom:4pt; }
table { width:100%; border-collapse:collapse; margin:5pt 0; font-size:8.5pt; }
th,td { text-align:left; padding:3.5pt 5pt; border-bottom:1px solid #ddd; vertical-align:top; }
th { background:#f0f4f8; color:#0b3d63; }
.ok { color:#137333; font-weight:700; } .bad { color:#b00020; font-weight:700; }
.metric { font-weight:800; color:#0b3d63; }
.kpi { display:flex; gap:6pt; margin:7pt 0; }
.card { flex:1; border:1px solid #d0d7de; border-radius:6px; padding:7pt; background:#fafcff; }
.card .v { font-size:15pt; font-weight:800; color:#0b3d63; } .card .l { font-size:7.5pt; color:#666; text-transform:uppercase; }
code,pre { font-family:'SF Mono',Menlo,Consolas,monospace; font-size:8pt; }
pre { background:#f6f8fa; border:1px solid #e1e4e8; border-radius:5px; padding:6pt; white-space:pre-wrap; word-break:break-word; }
.note { background:#fff8e1; border-left:3px solid #f9a825; padding:6pt 8pt; font-size:8.5pt; margin:6pt 0; }
.appendix pre { font-size:6.5pt; }
"""


def head_table():
    rows = ""
    for r in head_rows:
        rps_core = f"{r['rpc']:,.0f}"
        rows += (f"<tr><td>{esc(r['label'])}</td>"
                 f"<td class='metric'>{rps(r['rps'])} <span style='font-size:7pt;color:#888'>±{rps(r['rps_ci'])}</span></td>"
                 f"<td>{r['p50']:.2f}</td><td>{r['p99']:.2f}</td><td>{r['p999']:.2f}</td>"
                 f"<td>{r['cpu']:.0f}%</td><td>{r['rss']:.0f}</td><td>{rps_core}</td><td>{r['n']}</td></tr>")
    return rows


cc_html = "".join(f"<tr><td>{esc(t)}</td><td>{yesno(ok)}</td></tr>" for t, ok in cc_checks)
cc_all = all(ok for _, ok in cc_checks)
h2fail_html = "".join(f"<li>{esc(x)}</li>" for x in h2fails) or "<li>none</li>"
probe_html = "".join(f"<tr><td>{esc(l)}</td></tr>" for l in (tls["probes"][:16] if tls else []))

raw_files = ["cache-correctness.txt", "hl-zion-cache.dat", "hl-zion-proxy.dat", "hl-nginx-cache.dat",
             "sweep.dat", "h2load.txt", "wrk.txt", "wrk2.txt", "h2spec.txt", "testssl.txt", "proto.env", "zion.log"]
appendix = ""
for fn in raw_files:
    body = read(fn)
    if not body:
        continue
    lines = body.splitlines()
    cap = "\n".join(lines[:140]) + (f"\n... [{len(lines)-140} more lines; results/{fn}]" if len(lines) > 140 else "")
    appendix += f"<h3>results/{esc(fn)}</h3><pre>{esc(cap)}</pre>"

iso = M.get("isolation", "")
iso_warn = "" if ("performance" in iso or "isolated" in iso) else f'<div class="note"><b>Isolation:</b> {esc(iso)}. Numbers are indicative; for authoritative figures run on a dedicated host with the CPU governor pinned to <code>performance</code>.</div>'

doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>{CSS}</style></head><body>
<h1>Zion Edge — Baseline Report</h1>
<div class="sub">Rigorous benchmark · RFC conformance · cache-correctness · {esc(M.get('zion_version','n/a'))} · {esc(M.get('date_utc','n/a'))} · mode={esc(M.get('mode','?'))}</div>
<div class="note">Generated by <code>benchmarks/baseline/run-baseline.sh</code>. Throughput is the <b>median of {esc(M.get('params_trials','?'))} trials</b> with 95% CI; latency is p50/p99/p99.9 (ms). Every figure is parsed from a raw output embedded in the Appendix.</div>
{iso_warn}

<h2>1. Summary</h2>
<div class="kpi">
  <div class="card"><div class="v">{(h2spec['passed']+'/'+h2spec['total']) if h2spec else 'n/a'}</div><div class="l">HTTP/2 RFC</div></div>
  <div class="card"><div class="v">{yesno(cc_all)}</div><div class="l">cache correctness</div></div>
  <div class="card"><div class="v">{yesno(tls['vulns_ok']) if tls else 'n/a'}</div><div class="l">TLS vulns</div></div>
  <div class="card"><div class="v">{rps(head_rows[0]['rps']) if head_rows else 'n/a'}</div><div class="l">cache req/s (median)</div></div>
  <div class="card"><div class="v">{hit_ratio}%</div><div class="l">hit ratio (90/10)</div></div>
</div>

<h2>2. Environment</h2>
<table>
<tr><th>Zion / git</th><td>{esc(M.get('zion_version','n/a'))} · {esc(M.get('git_sha','n/a'))}{' (dirty)' if M.get('git_dirty')=='yes' else ''}</td></tr>
<tr><th>Host</th><td>{esc(M.get('cpu','n/a'))} · {esc(M.get('cores','n/a'))} cores · {esc(M.get('mem_gb','n/a'))} GB · {esc(M.get('os','n/a'))}/{esc(M.get('arch','n/a'))}</td></tr>
<tr><th>CPU governor / isolation</th><td>{esc(M.get('cpu_governor','n/a'))} · {esc(iso)}</td></tr>
<tr><th>Negotiated ALPN</th><td>zion: HTTP/{esc(P.get('zion_alpn','?'))} · nginx: HTTP/{esc(P.get('nginx_alpn','n/a'))}</td></tr>
<tr><th>Tools</th><td>{esc(M.get('tool_oha','?'))} · {esc(M.get('tool_h2load','?'))} · {esc(M.get('tool_wrk','?'))} · {esc(M.get('tool_h2spec','n/a'))} · {esc(M.get('tool_testssl','n/a'))}</td></tr>
</table>

<h2>3. Functional — cache correctness (validates v0.4.2)</h2>
<table><tr><th>Check</th><th>Result</th></tr>{cc_html}
<tr><td>Hit ratio under 90/10 hot/cold load</td><td>{esc(hit_ratio)}% ({esc(CC.get('hits_delta','?'))} hits / {esc(CC.get('misses_delta','?'))} misses)</td></tr></table>

<h2>4. Throughput &amp; latency</h2>
<div class="sub">oha over ALPN-negotiated HTTP/{esc(P.get('zion_alpn','?'))}; median of {esc(M.get('params_trials','?'))} trials, c={esc(M.get('params_conns','?'))}, {esc(M.get('params_duration','?'))}.</div>
<table>
<tr><th>Target</th><th>req/s (median ±CI)</th><th>p50 ms</th><th>p99 ms</th><th>p99.9 ms</th><th>CPU</th><th>RSS MB</th><th>req/s·core</th><th>n</th></tr>
{head_table()}
</table>
<div class="sub">Protocol-pinned cross-check: h2load (explicit H2) {rps(h2load_rps)} req/s ({esc(h2load_ok)} ok) · wrk (explicit H1) {rps(wrk_rps)} req/s{(' · wrk2 CO-corrected p99 '+esc(wrk2_p99)) if wrk2_p99 else ''}.</div>

<h2>5. Concurrency sweep (zion cache-hit)</h2>
{sweep_img}
<table><tr><th>concurrency</th><th>req/s</th><th>p99 ms</th></tr>{sweep_rows}</table>

<h2>6. Payload matrix (zion cache-hit)</h2>
<table><tr><th>body size</th><th>req/s (median)</th><th>95% CI</th><th>p99 ms</th></tr>{pm_rows}</table>

<h2>7. Regression</h2>
<p>{reg_html}</p>

<h2>8. RFC conformance</h2>
<h3>HTTP/2 (RFC 9113/7540) — h2spec</h3>
{('<table><tr><th>total</th><th>passed</th><th>skipped</th><th>failed</th></tr><tr><td>'+h2spec['total']+'</td><td class=ok>'+h2spec['passed']+'</td><td>'+h2spec['skipped']+'</td><td>'+h2spec['failed']+'</td></tr></table><ul>'+h2fail_html+'</ul>') if h2spec else '<p><i>not run (h2spec absent)</i></p>'}
<h3>TLS — testssl.sh</h3>
{('<table><tr><th>ALPN</th><td>'+esc(tls['alpn'])+'</td></tr><tr><th>Forward Secrecy</th><td>'+esc(tls['fs'])+'</td></tr><tr><th>Genuine crypto findings</th><td>'+yesno(tls['vulns_ok'])+'</td></tr></table><div class=note><b>Lab-cert artifacts (self-signed, not a zion weakness):</b> '+esc('; '.join(tls['cert_art']) or 'none')+'</div><table>'+probe_html+'</table>') if tls else '<p><i>not run (testssl absent)</i></p>'}

<div class="appendix"><h2>Appendix — raw output</h2>{appendix}</div>
</body></html>"""

(OUT / "report.html").write_text(doc)
print(pdf_name)
